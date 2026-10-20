//! Registration, sign-in, tokens and devices.

use mg_sync::{DeviceUpdate, Error, RegisterRequest};
use reqwest::Method;
use serde_json::json;

use crate::fake::{self, bytes};
use crate::report::{ensure, shown};
use crate::{Ctx, Report};

const G: &str = "auth";

pub async fn run(ctx: &Ctx, r: &mut Report) {
    r.check(
        G,
        "POST /auth/prelogin",
        "answers unknown addresses with stable, distinct parameters",
        async {
            let c = ctx.client()?;
            let nobody = ctx.email("nobody");
            let a = c.prelogin(&nobody).await.map_err(shown)?;
            let again = c.prelogin(&nobody.to_uppercase()).await.map_err(shown)?;
            ensure(
                a == again,
                "the same address (other case) got other parameters",
            )?;
            let other = c.prelogin(&ctx.email("other")).await.map_err(shown)?;
            ensure(
                a.salt != other.salt,
                "two unknown addresses got the same salt",
            )
        },
    )
    .await;

    if let Some(caps) = &ctx.caps
        && caps.features.email_verification
    {
        email_verification(ctx, r).await;
    }
    if let Err(why) = ctx.accounts() {
        for (endpoint, what) in [
            ("POST /auth/register", "creates accounts"),
            ("POST /auth/login", "signs in"),
            ("POST /auth/refresh", "rotates refresh tokens"),
            ("POST /auth/logout", "ends the session"),
            ("GET /devices", "lists devices"),
            ("PATCH /devices/{device_id}", "updates a device"),
            ("DELETE /devices/{device_id}", "signs a device out"),
            ("DELETE /account", "deletes the account"),
        ] {
            r.skip(G, endpoint, what, why);
        }
        return;
    }

    let Some((a, email, session)) = r
        .check(
            G,
            "POST /auth/register",
            "creates an account and returns its session",
            async {
                let (c, email, s) = fake::account(ctx, "auth", 7).await?;
                ensure(
                    s.keys.sign_public_key == bytes(32, 3),
                    "the session's keys aren't the ones registered",
                )?;
                ensure(
                    !s.tokens.access_token.is_empty() && !s.tokens.refresh_token.is_empty(),
                    "tokens missing",
                )?;
                Ok((c, email, s))
            },
        )
        .await
    else {
        return;
    };
    const TAKEN: &str = "refuses an address already taken (409, any case)";
    if ctx
        .caps
        .as_ref()
        .is_some_and(|c| c.features.email_verification)
    {
        // The code step comes first, so a taken address isn't revealed: nothing to check.
        r.skip(
            G,
            "POST /auth/register",
            TAKEN,
            "with email verification, the code is asked before a taken address shows",
        );
    } else {
        r.check(G, "POST /auth/register", TAKEN, async {
            match ctx
                .client()?
                .register(&fake::register_req(&email.to_uppercase(), 7))
                .await
            {
                Err(Error::Api { status: 409, .. }) => Ok(()),
                other => Err(format!("expected 409, got {}", outcome(other.map(|_| ())))),
            }
        })
        .await;
    }
    r.check(
        G,
        "POST /auth/login",
        "refuses a wrong AuthKey (401)",
        async {
            match ctx.client()?.login(&fake::login_req(&email, 8)).await {
                Err(Error::Api { status: 401, .. }) => Ok(()),
                other => Err(format!("expected 401, got {}", outcome(other.map(|_| ())))),
            }
        },
    )
    .await;
    let Some(b) = r
        .check(
            G,
            "POST /auth/login",
            "signs in a second device with the AuthKey",
            async {
                let b = ctx.client()?;
                let s = b.login(&fake::login_req(&email, 7)).await.map_err(shown)?;
                ensure(
                    s.account_id == session.account_id,
                    "signed in to another account",
                )?;
                ensure(
                    b.account()
                        .await
                        .map_err(shown)?
                        .email
                        .eq_ignore_ascii_case(&email),
                    "GET /account shows another address",
                )?;
                Ok(b)
            },
        )
        .await
    else {
        return;
    };
    let b_device = r
        .check(
            G,
            "GET /devices",
            "lists the account's devices, this one marked current",
            async {
                let list = a.devices().await.map_err(shown)?;
                ensure(
                    list.len() == 2,
                    format!("{} devices, expected 2", list.len()),
                )?;
                ensure(
                    list.iter().filter(|d| d.current).count() == 1,
                    "not exactly one device is current",
                )?;
                Ok(list.into_iter().find(|d| !d.current).map(|d| d.info.id))
            },
        )
        .await
        .flatten();

    match &b_device {
        Some(device) => {
            r.check(
                G,
                "PATCH /devices/{device_id}",
                "a device updates its own name, platform and version, not another's",
                async {
                    let update = DeviceUpdate {
                        name: "vault-conform phone".into(),
                        platform: "android".into(),
                        client_version: Some("9.9.9".into()),
                    };
                    b.update_device(device, &update).await.map_err(shown)?;
                    let list = a.devices().await.map_err(shown)?;
                    let shown_now = list
                        .iter()
                        .find(|d| &d.info.id == device)
                        .ok_or("the device left GET /devices")?;
                    ensure(
                        shown_now.info.name == update.name
                            && shown_now.info.platform == update.platform
                            && shown_now.info.client_version == update.client_version,
                        "GET /devices still shows the device's old name, platform or version",
                    )?;
                    let other = list
                        .iter()
                        .find(|d| d.current)
                        .map(|d| d.info.id.clone())
                        .unwrap_or_default();
                    match b.update_device(&other, &update).await {
                        Err(Error::Api { status: 403, .. }) => Ok(()),
                        Ok(()) => Err("a device renamed another".into()),
                        Err(e) => Err(shown(e)),
                    }
                },
            )
            .await;
        }
        None => r.skip(
            G,
            "PATCH /devices/{device_id}",
            "updates a device",
            "no second device",
        ),
    }

    match b_device {
        Some(device) => {
            r.check(
                G,
                "DELETE /devices/{device_id}",
                "signs another device out, which then hears device_revoked",
                async {
                    b.account().await.map_err(shown)?;
                    a.revoke_device(&device).await.map_err(shown)?;
                    match b.account().await {
                        Err(Error::DeviceRevoked) => Ok(()),
                        Err(Error::Unauthorized) => Err(
                            "the signed-out device's refresh gets a plain 401, not device_revoked"
                                .into(),
                        ),
                        Ok(_) => Err("the signed-out device still works".into()),
                        Err(e) => Err(shown(e)),
                    }
                },
            )
            .await;
        }
        None => r.skip(
            G,
            "DELETE /devices/{device_id}",
            "signs another device out",
            "no second device to sign out",
        ),
    }

    // Replaying a refresh token signs the device out: last, since it ends this session.
    r.check(
        G,
        "POST /auth/refresh",
        "rotates the refresh token, and a replayed one signs the device out",
        async {
            let first = session.tokens.refresh_token.clone();
            let resumed = ctx.client()?;
            resumed.resume(first.clone());
            resumed.list_vaults().await.map_err(shown)?;
            let rotated = resumed
                .take_rotated_refresh()
                .ok_or("no new refresh token after refreshing")?;
            ensure(rotated != first, "the refresh token didn't change")?;
            let thief = ctx.client()?;
            thief.resume(first);
            ensure(
                matches!(thief.list_vaults().await, Err(Error::Unauthorized)),
                "a replayed refresh token still works",
            )?;
            ensure(
                matches!(resumed.list_vaults().await, Err(Error::Unauthorized)),
                "after a replay, the device's current token still works (reuse should sign it out)",
            )
        },
    )
    .await;

    // A third session to sign out of, then the account goes.
    let c = ctx.client().ok();
    if let Some(c) = &c
        && c.login(&fake::login_req(&email, 7)).await.is_ok()
    {
        r.check(G, "POST /auth/logout", "ends the session", async {
            c.logout().await.map_err(shown)?;
            ensure(
                matches!(c.account().await, Err(Error::Unauthorized)),
                "the session still works after logout",
            )
        })
        .await;
    } else {
        r.skip(
            G,
            "POST /auth/logout",
            "ends the session",
            "couldn't sign in a third time",
        );
    }
    delete_account(ctx, r, &email, 7).await;
}

/// `DELETE /account`, with a wrong and then the right AuthKey.
async fn delete_account(ctx: &Ctx, r: &mut Report, email: &str, auth: u8) {
    r.check(
        G,
        "DELETE /account",
        "deletes the account after its AuthKey; it can't sign in again, and its other devices hear account_deleted",
        async {
            let c = ctx.client()?;
            c.login(&fake::login_req(email, auth))
                .await
                .map_err(shown)?;
            let other = ctx.client()?;
            other
                .login(&fake::login_req(email, auth))
                .await
                .map_err(shown)?;
            let token = fake::token(&c)?;
            let wrong = ctx
                .raw(
                    Method::DELETE,
                    "account",
                    Some(&token),
                    Some(json!({ "auth_key": bytes(32, 99) })),
                )
                .await?;
            ensure(
                wrong.status == 401 || wrong.status == 403,
                format!("a wrong AuthKey got {}", wrong.status),
            )?;
            let gone = ctx
                .raw(
                    Method::DELETE,
                    "account",
                    Some(&token),
                    Some(json!({ "auth_key": bytes(32, auth) })),
                )
                .await?;
            ensure(
                gone.status == 204,
                format!("expected 204, got {} {}", gone.status, gone.body),
            )?;
            match other.account().await {
                Err(Error::AccountDeleted) => {}
                Err(Error::Unauthorized) => {
                    return Err("another device's refresh gets a plain 401, not account_deleted".into());
                }
                other => {
                    return Err(format!(
                        "another device after the deletion: expected account_deleted, got {}",
                        outcome(other.map(|_| ()))
                    ));
                }
            }
            match ctx.client()?.login(&fake::login_req(email, auth)).await {
                Err(Error::Api { status: 401, .. }) => Ok(()),
                other => Err(format!(
                    "signing in after deletion: expected 401, got {}",
                    outcome(other.map(|_| ()))
                )),
            }
        },
    )
    .await;
}

/// Servers that verify addresses: only the refusals can be checked (the code is in a mailbox).
async fn email_verification(ctx: &Ctx, r: &mut Report) {
    let email = ctx.email("verify");
    r.check(
        G,
        "POST /auth/register",
        "wants the mailed code (400 email_code_required)",
        async {
            match ctx.client()?.register(&fake::register_req(&email, 7)).await {
                Err(Error::Api {
                    status: 400, code, ..
                }) if code == "email_code_required" => Ok(()),
                other => Err(format!(
                    "expected 400 email_code_required, got {}",
                    outcome(other.map(|_| ()))
                )),
            }
        },
    )
    .await;
    r.check(G, "POST /auth/register/start", "mails a code", async {
        let c = ctx.client()?;
        c.start_registration(&email).await.map_err(shown)
    })
    .await;
    r.check(
        G,
        "POST /auth/register",
        "refuses a wrong code (400 invalid_code)",
        async {
            let guess = RegisterRequest {
                email_code: Some("abcdef".into()),
                accepted_terms: None,
                ..fake::register_req(&email, 7)
            };
            match ctx.client()?.register(&guess).await {
                Err(Error::Api {
                    status: 400, code, ..
                }) if code == "invalid_code" => Ok(()),
                other => Err(format!(
                    "expected 400 invalid_code, got {}",
                    outcome(other.map(|_| ()))
                )),
            }
        },
    )
    .await;
}

/// A result as the report says it.
pub fn outcome<T>(r: Result<T, Error>) -> String {
    match r {
        Ok(_) => "success".into(),
        Err(e) => format!("\"{e}\""),
    }
}
