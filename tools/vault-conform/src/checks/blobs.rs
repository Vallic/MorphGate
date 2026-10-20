//! Blobs: sealed attachments and session logs, named by the SHA-256 of their bytes.

use mg_sync::Error;
use reqwest::Method;
use sha2::{Digest, Sha256};

use super::auth::outcome;
use crate::fake::{self, ulid, vault_req};
use crate::report::{ensure, shown};
use crate::{Ctx, Report};

const G: &str = "blobs";

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub async fn run(ctx: &Ctx, r: &mut Report) {
    let endpoints = [
        ("PUT /vaults/{vault_id}/blobs/{hash}", "stores a blob"),
        ("GET /vaults/{vault_id}/blobs/{hash}", "returns its bytes"),
        ("GET /vaults/{vault_id}/blobs", "lists blobs"),
        ("DELETE /vaults/{vault_id}/blobs/{hash}", "deletes a blob"),
    ];
    let Some(limits) = ctx.caps.as_ref().and_then(|c| c.features.blobs.clone()) else {
        for (e, w) in endpoints {
            r.skip(G, e, w, "the server doesn't store blobs (features.blobs)");
        }
        return;
    };
    if let Err(why) = ctx.accounts() {
        for (e, w) in endpoints {
            r.skip(G, e, w, why);
        }
        return;
    }
    let Some(c) = r
        .check(
            G,
            "POST /auth/register",
            "an account for the blob checks",
            ctx.shared(),
        )
        .await
    else {
        return;
    };
    let vault = ulid();
    if r.check(G, "POST /vaults", "a vault for the blobs", async {
        c.create_vault(&vault_req(&vault))
            .await
            .map_err(shown)
            .map(drop)
    })
    .await
    .is_none()
    {
        return;
    }
    let bytes: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let name = hash(&bytes);
    let kind = if limits.kinds.iter().any(|k| k == "attachment") {
        "attachment"
    } else {
        limits.kinds.first().map_or("attachment", String::as_str)
    };
    r.check(
        G,
        endpoints[0].0,
        "stores a new blob (201), and the same bytes again (200)",
        async {
            let (info, created) = c
                .put_blob(&vault, &name, kind, bytes.clone())
                .await
                .map_err(shown)?;
            ensure(created, "the first upload wasn't 201 Created")?;
            ensure(
                info.hash == name && info.size == bytes.len() as u64 && info.kind == kind,
                format!("metadata {info:?}"),
            )?;
            let (_, again) = c
                .put_blob(&vault, &name, kind, bytes.clone())
                .await
                .map_err(shown)?;
            ensure(!again, "the same bytes again weren't 200")
        },
    )
    .await;
    r.check(
        G,
        endpoints[0].0,
        "refuses bytes that don't match the name (400 hash_mismatch)",
        async {
            let wrong = hash(b"something else");
            match c.put_blob(&vault, &wrong, kind, bytes.clone()).await {
                Err(Error::Api {
                    status: 400, code, ..
                }) if code == "hash_mismatch" => Ok(()),
                other => Err(format!(
                    "expected 400 hash_mismatch, got {}",
                    outcome(other)
                )),
            }
        },
    )
    .await;
    if limits.max_blob_bytes <= 32 * 1024 * 1024 {
        r.check(
            G,
            endpoints[0].0,
            "refuses a blob over max_blob_bytes (413)",
            async {
                let big = vec![0u8; limits.max_blob_bytes as usize + 1];
                match c.put_blob(&vault, &hash(&big), kind, big).await {
                    Err(Error::Api { status: 413, .. }) => Ok(()),
                    other => Err(format!("expected 413, got {}", outcome(other))),
                }
            },
        )
        .await;
    } else {
        r.skip(
            G,
            endpoints[0].0,
            "refuses a blob over max_blob_bytes (413)",
            "max_blob_bytes is over 32 MiB: too big to send for a check",
        );
    }
    r.check(G, endpoints[1].0, "returns the bytes as stored", async {
        let back = c.blob(&vault, &name).await.map_err(shown)?;
        ensure(back == bytes, "other bytes came back")
    })
    .await;
    r.check(
        G,
        "HEAD /vaults/{vault_id}/blobs/{hash}",
        "answers HEAD with the blob's kind",
        async {
            let token = fake::token(&c)?;
            let raw = ctx
                .raw(
                    Method::HEAD,
                    &format!("vaults/{vault}/blobs/{name}"),
                    Some(&token),
                    None,
                )
                .await?;
            ensure(raw.status == 200, format!("status {}", raw.status))?;
            let k = raw
                .headers
                .get("x-blob-kind")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            ensure(k == kind, format!("X-Blob-Kind {k:?}, expected {kind:?}"))
        },
    )
    .await;
    r.check(
        G,
        endpoints[2].0,
        "lists the vault's blobs (and filters by kind)",
        async {
            let all = c.blobs(&vault, None).await.map_err(shown)?;
            ensure(all.iter().any(|b| b.hash == name), "the blob isn't listed")?;
            let other = if kind == "attachment" {
                "session_log"
            } else {
                "attachment"
            };
            let filtered = c.blobs(&vault, Some(other)).await.map_err(shown)?;
            ensure(
                filtered.iter().all(|b| b.hash != name),
                "filtering by another kind still lists it",
            )
        },
    )
    .await;
    r.check(
        G,
        endpoints[3].0,
        "deletes a blob; it's gone afterwards",
        async {
            c.delete_blob(&vault, &name).await.map_err(shown)?;
            match c.blob(&vault, &name).await {
                Err(Error::Api { status: 404, .. }) => Ok(()),
                other => Err(format!(
                    "fetching it again: expected 404, got {}",
                    outcome(other)
                )),
            }
        },
    )
    .await;
    r.check(
        G,
        endpoints[1].0,
        "keeps blobs private to the vault's account (404)",
        async {
            c.put_blob(&vault, &name, kind, bytes.clone())
                .await
                .map_err(shown)?;
            let m = ctx.outsider().await?;
            match m.blob(&vault, &name).await {
                Err(Error::Api {
                    status: 404 | 403, ..
                }) => Ok(()),
                other => Err(format!(
                    "another account fetching it: expected 404, got {}",
                    outcome(other)
                )),
            }
        },
    )
    .await;
}
