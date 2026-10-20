//! `GET /.well-known/vault-sync`: everything else depends on what it says.

use crate::report::{ensure, shown};
use crate::{Ctx, Report};

const G: &str = "discovery";

pub async fn run(ctx: &mut Ctx, r: &mut Report) {
    let caps = r
        .check(
            G,
            "GET /.well-known/vault-sync",
            "serves the capabilities document",
            async {
                let caps = ctx.client()?.capabilities().await.map_err(shown)?;
                ensure(
                    caps.spec == "vault-sync",
                    format!("spec is {:?}, not \"vault-sync\"", caps.spec),
                )?;
                ensure(
                    caps.versions.iter().any(|v| v == "v1"),
                    format!("versions {:?} lack v1", caps.versions),
                )?;
                ensure(
                    caps.limits.max_push_items > 0 && caps.limits.max_envelope_bytes >= 4096,
                    format!(
                        "limits too small: max_push_items {}, max_envelope_bytes {}",
                        caps.limits.max_push_items, caps.limits.max_envelope_bytes
                    ),
                )?;
                Ok(caps)
            },
        )
        .await;
    ctx.caps = caps;
}
