//! Vaults and their items: create, list, push, pull, conflicts, tombstones, privacy.

use mg_sync::{B64, Error, MAX_DELETION_ENVELOPE, PushItem, PushStatus};
use reqwest::Method;

use super::auth::outcome;
use crate::fake::{self, bytes, envelope, put, ulid, vault_req};
use crate::report::{ensure, shown};
use crate::{Ctx, Report};

const G: &str = "vaults";

pub async fn run(ctx: &Ctx, r: &mut Report) {
    if let Err(why) = ctx.accounts() {
        for (e, w) in [
            ("POST /vaults", "creates a vault"),
            ("GET /vaults", "lists the account's vaults"),
            ("POST /vaults/{vault_id}/changes", "pushes items"),
            ("GET /vaults/{vault_id}/changes", "pulls items"),
            ("DELETE /vaults/{vault_id}", "deletes a vault"),
        ] {
            r.skip(G, e, w, why);
        }
        return;
    }
    let Some(c) = r
        .check(
            G,
            "POST /auth/register",
            "an account for the vault checks",
            ctx.shared(),
        )
        .await
    else {
        return;
    };
    let vault = ulid();
    if r.check(G, "POST /vaults", "creates a vault", async {
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
    r.check(
        G,
        "POST /vaults",
        "refuses the same id again (409)",
        async {
            match c.create_vault(&vault_req(&vault)).await {
                Err(Error::Api { status: 409, .. }) => Ok(()),
                other => Err(format!("expected 409, got {}", outcome(other))),
            }
        },
    )
    .await;
    let (a, b) = (ulid(), ulid());
    r.check(
        G,
        "POST /vaults/{vault_id}/changes",
        "accepts new items and moves the head",
        async {
            let resp = c
                .push(&vault, vec![put(&a, 0, 1), put(&b, 0, 2)])
                .await
                .map_err(shown)?;
            ensure(
                resp.results
                    .iter()
                    .all(|x| x.status == PushStatus::Accepted),
                format!("not all accepted: {:?}", resp.results),
            )?;
            ensure(
                resp.head_rev == 2,
                format!("head_rev {}, expected 2", resp.head_rev),
            )
        },
    )
    .await;
    r.check(
        G,
        "GET /vaults/{vault_id}/changes",
        "returns the items with their envelopes",
        async {
            let page = c.pull(&vault, 0, 500).await.map_err(shown)?;
            ensure(
                page.items.len() == 2 && page.head_rev == 2 && !page.has_more,
                format!(
                    "{} items, head {}, has_more {}",
                    page.items.len(),
                    page.head_rev,
                    page.has_more
                ),
            )?;
            let item = page
                .items
                .iter()
                .find(|i| i.id == a)
                .ok_or("an item is missing")?;
            ensure(
                item.envelope == Some(envelope(1)),
                "an envelope came back changed",
            )
        },
    )
    .await;
    r.check(
        G,
        "POST /vaults/{vault_id}/changes",
        "answers a stale base_rev with a conflict and the server's copy",
        async {
            let resp = c.push(&vault, vec![put(&a, 0, 9)]).await.map_err(shown)?;
            let x = resp.results.first().ok_or("no result")?;
            ensure(
                x.status == PushStatus::Conflict,
                format!("status {:?}, expected conflict", x.status),
            )?;
            ensure(
                x.current.as_ref().and_then(|i| i.envelope.clone()) == Some(envelope(1)),
                "the conflict doesn't carry the server's copy",
            )
        },
    )
    .await;
    r.check(
        G,
        "POST /vaults/{vault_id}/changes",
        "takes an update at the right base_rev, and a deletion",
        async {
            let delete = PushItem {
                id: b.clone(),
                base_rev: 2,
                deleted: true,
                envelope: None,
            };
            let resp = c
                .push(&vault, vec![put(&a, 1, 3), delete])
                .await
                .map_err(shown)?;
            ensure(
                resp.results
                    .iter()
                    .all(|x| x.status == PushStatus::Accepted),
                format!("not all accepted: {:?}", resp.results),
            )?;
            ensure(
                resp.head_rev == 4,
                format!("head_rev {}, expected 4", resp.head_rev),
            )
        },
    )
    .await;
    r.check(
        G,
        "GET /vaults/{vault_id}/changes",
        "returns changes since a revision, tombstones included",
        async {
            let page = c.pull(&vault, 2, 500).await.map_err(shown)?;
            ensure(
                page.items.len() == 2,
                format!("{} items since 2, expected 2", page.items.len()),
            )?;
            let tomb = page
                .items
                .iter()
                .find(|i| i.id == b)
                .ok_or("the tombstone is missing")?;
            ensure(
                tomb.deleted && tomb.envelope.is_none(),
                "the tombstone isn't marked deleted without an envelope",
            )
        },
    )
    .await;
    r.check(
        G,
        "GET /vaults/{vault_id}/changes",
        "pages with limit and has_more",
        async {
            let page = c.pull(&vault, 0, 1).await.map_err(shown)?;
            ensure(
                page.has_more && page.items.len() == 1,
                format!("{} items, has_more {}", page.items.len(), page.has_more),
            )
        },
    )
    .await;
    r.check(
        G,
        "POST /vaults/{vault_id}/changes",
        "rejects oversized envelopes and bad ids, per item",
        async {
            let max = ctx
                .caps
                .as_ref()
                .map_or(65_536, |c| c.limits.max_envelope_bytes as usize);
            let big = PushItem {
                id: ulid(),
                base_rev: 0,
                deleted: false,
                envelope: Some(bytes(max + 1024, 0)),
            };
            let bad = PushItem {
                id: "../x".into(),
                base_rev: 0,
                deleted: false,
                envelope: Some(envelope(1)),
            };
            match c.push(&vault, vec![big, bad]).await {
                Ok(resp) => ensure(
                    resp.results
                        .iter()
                        .all(|x| x.status == PushStatus::Rejected),
                    format!("not all rejected: {:?}", resp.results),
                ),
                // Refusing the whole request is allowed too.
                Err(Error::Api {
                    status: 400 | 413, ..
                }) => Ok(()),
                Err(e) => Err(shown(e)),
            }
        },
    )
    .await;
    r.check(
        G,
        "GET /vaults",
        "lists the vault with its head and item count",
        async {
            let list = c.list_vaults().await.map_err(shown)?;
            let v = list
                .iter()
                .find(|v| v.id == vault)
                .ok_or("the vault isn't listed")?;
            ensure(
                v.head_rev == 4,
                format!("head_rev {}, expected 4", v.head_rev),
            )?;
            ensure(
                v.item_count.is_none_or(|n| n == 1),
                format!("item_count {:?}, expected 1", v.item_count),
            )
        },
    )
    .await;
    r.check(G, "GET /vaults/{vault_id}", "shows one vault", async {
        let v = c.vault(&vault).await.map_err(shown)?;
        ensure(
            v.id == vault && v.head_rev == 4,
            "another vault, or another head",
        )
    })
    .await;
    r.check(
        G,
        "GET /vaults/{vault_id}/changes",
        "keeps vaults private to their account (404)",
        async {
            let m = ctx.outsider().await?;
            ensure(
                matches!(
                    m.pull(&vault, 0, 10).await,
                    Err(Error::Api { status: 404, .. })
                ),
                "another account can pull it",
            )?;
            ensure(
                matches!(
                    m.push(&vault, vec![put(&ulid(), 0, 1)]).await,
                    Err(Error::Api { status: 404, .. })
                ),
                "another account can push to it",
            )?;
            ensure(
                matches!(m.vault(&vault).await, Err(Error::Api { status: 404, .. })),
                "another account can see it",
            )?;
            ensure(
                m.list_vaults()
                    .await
                    .map_err(shown)?
                    .iter()
                    .all(|v| v.id != vault),
                "another account lists it",
            )
        },
    )
    .await;

    gone_after_purge(ctx, r, &c).await;
    signed_deletions(ctx, r, &c).await;
    events(ctx, r, &c, &vault).await;

    r.check(
        G,
        "DELETE /vaults/{vault_id}",
        "deletes a vault and its items",
        async {
            c.delete_vault(&vault).await.map_err(shown)?;
            ensure(
                matches!(c.vault(&vault).await, Err(Error::Api { status: 404, .. })),
                "the deleted vault is still there",
            )
        },
    )
    .await;
}

/// A deletion's envelope (its author's signed deletion) kept and returned: where the server
/// offers it.
async fn signed_deletions(ctx: &Ctx, r: &mut Report, c: &mg_sync::SyncClient) {
    const E: (&str, &str) = (
        "POST /vaults/{vault_id}/changes",
        "keeps a deletion's envelope (at most 1 KiB) and returns it with the tombstone",
    );
    if !ctx
        .caps
        .as_ref()
        .is_some_and(|c| c.features.signed_tombstones)
    {
        r.skip(
            G,
            E.0,
            E.1,
            "the server doesn't offer features.signed_tombstones",
        );
        return;
    }
    r.check(G, E.0, E.1, async {
        let vault = ulid();
        c.create_vault(&vault_req(&vault)).await.map_err(shown)?;
        let id = ulid();
        c.push(&vault, vec![put(&id, 0, 1)]).await.map_err(shown)?;
        let deletion = |envelope| PushItem {
            id: id.clone(),
            base_rev: 1,
            deleted: true,
            envelope: Some(envelope),
        };
        let mut big = envelope(2).0;
        big.resize(MAX_DELETION_ENVELOPE + 1, 2);
        match c.push(&vault, vec![deletion(B64(big))]).await {
            Ok(resp) => ensure(
                resp.results
                    .iter()
                    .all(|x| x.status == PushStatus::Rejected),
                "took a deletion's envelope over 1 KiB",
            )?,
            Err(Error::Api {
                status: 400 | 413, ..
            }) => {}
            Err(e) => return Err(shown(e)),
        }
        let resp = c
            .push(&vault, vec![deletion(envelope(3))])
            .await
            .map_err(shown)?;
        ensure(
            resp.results
                .iter()
                .all(|x| x.status == PushStatus::Accepted),
            format!("the deletion wasn't accepted: {:?}", resp.results),
        )?;
        let page = c.pull(&vault, 1, 500).await.map_err(shown)?;
        let tomb = page
            .items
            .iter()
            .find(|i| i.id == id)
            .ok_or("the tombstone is missing")?;
        ensure(
            tomb.deleted && tomb.envelope == Some(envelope(3)),
            "the tombstone came back without the deletion's envelope",
        )?;
        c.delete_vault(&vault).await.map_err(shown)
    })
    .await;
}

/// `410` after tombstones are purged: only with a command that makes the server purge now.
async fn gone_after_purge(ctx: &Ctx, r: &mut Report, c: &mg_sync::SyncClient) {
    const E: (&str, &str) = (
        "GET /vaults/{vault_id}/changes",
        "answers 410 for a since older than purged tombstones",
    );
    let Some(cmd) = &ctx.opts.purge_command else {
        r.skip(
            G,
            E.0,
            E.1,
            "pass --purge-command to make the server purge tombstones now",
        );
        return;
    };
    r.check(G, E.0, E.1, async {
        let vault = ulid();
        c.create_vault(&vault_req(&vault)).await.map_err(shown)?;
        let id = ulid();
        c.push(&vault, vec![put(&id, 0, 1)]).await.map_err(shown)?;
        c.push(
            &vault,
            vec![PushItem {
                id,
                base_rev: 1,
                deleted: true,
                envelope: None,
            }],
        )
        .await
        .map_err(shown)?;
        let status = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status()
            .await
            .map_err(|e| format!("running the purge command: {e}"))?;
        ensure(
            status.success(),
            format!("the purge command failed ({status})"),
        )?;
        match c.pull(&vault, 1, 500).await {
            Err(Error::Gone) => Ok(()),
            other => Err(format!("expected 410, got {}", outcome(other))),
        }
    })
    .await;
}

/// `GET /vaults/{vault_id}/events`: change notifications (server-sent events), where offered.
async fn events(ctx: &Ctx, r: &mut Report, c: &mg_sync::SyncClient, vault: &str) {
    const E: (&str, &str) = (
        "GET /vaults/{vault_id}/events",
        "streams change notifications (text/event-stream)",
    );
    if !ctx.caps.as_ref().is_some_and(|c| c.features.sse) {
        r.skip(G, E.0, E.1, "the server doesn't offer them (features.sse)");
        return;
    }
    r.check(G, E.0, E.1, async {
        let token = fake::token(c)?;
        let resp = reqwest::Client::new()
            .request(
                Method::GET,
                format!("{}/v1/vaults/{vault}/events", ctx.opts.server),
            )
            .bearer_auth(token)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(shown)?;
        let kind = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        ensure(
            resp.status().is_success(),
            format!("status {}", resp.status()),
        )?;
        ensure(
            kind.starts_with("text/event-stream"),
            format!("content-type {kind:?}"),
        )
    })
    .await;
}
