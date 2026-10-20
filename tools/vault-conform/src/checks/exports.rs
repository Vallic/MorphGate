//! `GET /account/export`: what the server keeps about an account, readable (optional).

use mg_sync::Error;

use crate::report::{ensure, shown};
use crate::{Ctx, Report};

const G: &str = "exports";
const E: (&str, &str) = (
    "GET /account/export",
    "exports what the server keeps, without secrets",
);

pub async fn run(ctx: &Ctx, r: &mut Report) {
    if let Err(why) = ctx.accounts() {
        r.skip(G, E.0, E.1, why);
        return;
    }
    let Some(c) = r
        .check(
            G,
            "POST /auth/register",
            "an account to export",
            ctx.shared(),
        )
        .await
    else {
        return;
    };
    let email = match c.account().await {
        Ok(a) => a.email,
        Err(e) => {
            r.skip(G, E.0, E.1, &format!("the account: {e}"));
            return;
        }
    };
    let data = match c.account_export().await {
        Err(Error::Api { status: 404, .. }) => {
            r.skip(
                G,
                E.0,
                E.1,
                "the server doesn't offer it (404; it's optional)",
            );
            return;
        }
        other => other,
    };
    r.check(G, E.0, E.1, async {
        let data = data.map_err(shown)?;
        ensure(
            data["format"] == "morphgate-account-export/1",
            format!("format {}", data["format"]),
        )?;
        ensure(
            data["account"]["email"]
                .as_str()
                .is_some_and(|e| e.eq_ignore_ascii_case(&email)),
            "another address",
        )?;
        ensure(
            data["devices"].as_array().is_some_and(|d| !d.is_empty()),
            "no devices",
        )?;
        let text = data.to_string();
        for secret in ["auth_hash", "recovery_hash", "wrapped", "envelope"] {
            ensure(!text.contains(secret), format!("{secret} is in the export"))?;
        }
        Ok(())
    })
    .await;
}
