//! The account: its keys, password changes, recovery, two-step verification, email changes.

use mg_sync::{
    EmailChangeRequest, Error, LoginRequest, RecoverRequest, RecoveryMaterial,
    RotateCredentialsRequest, TotpDisableRequest, TotpStartRequest,
};

use super::auth::outcome;
use crate::fake::{self, bytes, kdf};
use crate::report::{ensure, shown};
use crate::{Ctx, Report};

const G: &str = "account";

pub async fn run(ctx: &Ctx, r: &mut Report) {
    if let Err(why) = ctx.accounts() {
        for (endpoint, what) in [
            ("GET /account", "shows the account"),
            ("PUT /account/keys", "changes credentials"),
            ("POST /account/recover", "recovers with the recovery key"),
        ] {
            r.skip(G, endpoint, what, why);
        }
        return;
    }
    let Some((a, email, _)) = r
        .check(
            G,
            "GET /account",
            "shows the account's address, KDF and keys",
            async {
                let (c, email, s) = fake::account(ctx, "acct", 7).await?;
                let acct = c.account().await.map_err(shown)?;
                ensure(acct.email.eq_ignore_ascii_case(&email), "another address")?;
                ensure(acct.id == s.account_id, "another account id")?;
                ensure(acct.kdf == kdf(), "the KDF parameters changed")?;
                ensure(
                    acct.wrapped_private_keys_rk == Some(bytes(104, 5)),
                    "the recovery-wrapped keys are missing",
                )?;
                Ok((c, email, s))
            },
        )
        .await
    else {
        return;
    };
    let Some(b) = r
        .check(
            G,
            "POST /auth/login",
            "signs in a second device (for the next checks)",
            async {
                let b = ctx.client()?;
                b.login(&fake::login_req(&email, 7)).await.map_err(shown)?;
                Ok(b)
            },
        )
        .await
    else {
        return;
    };

    let same_password = RotateCredentialsRequest {
        current_auth_key: Some(bytes(32, 7)),
        new_kdf: kdf(),
        new_auth_key: bytes(32, 7),
        wrapped_private_keys: bytes(104, 4),
        recovery: Some(RecoveryMaterial {
            wrapped_private_keys_rk: bytes(104, 11),
            recovery_proof: bytes(32, 12),
        }),
    };
    r.check(
        G,
        "PUT /account/keys",
        "refuses a wrong current AuthKey",
        async {
            let wrong = RotateCredentialsRequest {
                current_auth_key: Some(bytes(32, 1)),
                ..same_password.clone()
            };
            match a.rotate_credentials(&wrong).await {
                Err(
                    Error::Unauthorized
                    | Error::Api {
                        status: 401 | 403, ..
                    },
                ) => Ok(()),
                other => Err(format!("expected 401, got {}", outcome(other))),
            }
        },
    )
    .await;
    r.check(
        G,
        "PUT /account/keys",
        "a new recovery key keeps other devices signed in",
        async {
            a.rotate_credentials(&same_password).await.map_err(shown)?;
            let acct = b
                .account()
                .await
                .map_err(|e| format!("the other device: {e}"))?;
            ensure(
                acct.wrapped_private_keys_rk == Some(bytes(104, 11)),
                "the new recovery-wrapped keys aren't stored",
            )
        },
    )
    .await;
    r.check(
        G,
        "PUT /account/keys",
        "a new password signs other devices out, not this one",
        async {
            let new_password = RotateCredentialsRequest {
                new_auth_key: bytes(32, 8),
                recovery: None,
                ..same_password.clone()
            };
            a.rotate_credentials(&new_password).await.map_err(shown)?;
            a.account()
                .await
                .map_err(|e| format!("the device that changed it: {e}"))?;
            ensure(
                matches!(b.account().await, Err(Error::Unauthorized)),
                "the other device is still signed in",
            )
        },
    )
    .await;

    // Recovery, with the recovery key set above (proof 12, keys 11).
    r.check(
        G,
        "POST /account/recover",
        "refuses a wrong recovery proof (401)",
        async {
            let bad = RecoverRequest {
                email: email.clone(),
                recovery_proof: bytes(32, 99),
            };
            match ctx.client()?.recover(&bad).await {
                Err(Error::Api { status: 401, .. }) => Ok(()),
                other => Err(format!("expected 401, got {}", outcome(other))),
            }
        },
    )
    .await;
    r.check(
        G,
        "POST /account/recover",
        "gives a narrow, single-use token for new credentials",
        async {
            let c = ctx.client()?;
            let resp = c
                .recover(&RecoverRequest {
                    email: email.clone(),
                    recovery_proof: bytes(32, 12),
                })
                .await
                .map_err(shown)?;
            ensure(
                resp.wrapped_private_keys_rk == bytes(104, 11),
                "other recovery-wrapped keys came back",
            )?;
            ensure(
                matches!(
                    c.list_vaults().await,
                    Err(Error::Unauthorized
                        | Error::Api {
                            status: 401 | 403,
                            ..
                        })
                ),
                "the recovery token opens vaults",
            )?;
            let fresh = ctx.client()?;
            fresh
                .recover(&RecoverRequest {
                    email: email.clone(),
                    recovery_proof: bytes(32, 12),
                })
                .await
                .map_err(shown)?;
            let rotate = RotateCredentialsRequest {
                current_auth_key: None,
                new_kdf: kdf(),
                new_auth_key: bytes(32, 9),
                wrapped_private_keys: bytes(104, 10),
                recovery: None,
            };
            fresh
                .rotate_credentials(&rotate)
                .await
                .map_err(|e| format!("setting new credentials: {e}"))?;
            ensure(
                fresh.rotate_credentials(&rotate).await.is_err(),
                "the recovery token works twice",
            )?;
            ensure(
                matches!(a.account().await, Err(Error::Unauthorized)),
                "devices stay signed in after a recovery",
            )?;
            let s = ctx
                .client()?
                .login(&fake::login_req(&email, 9))
                .await
                .map_err(|e| format!("signing in with the new key: {e}"))?;
            ensure(
                s.keys.wrapped_private_keys == bytes(104, 10),
                "the new wrapped keys aren't stored",
            )
        },
    )
    .await;

    totp(ctx, r).await;
    email_change(ctx, r).await;
    web_session(ctx, r).await;
}

/// RFC 6238 (SHA-1, 6 digits, 30 s).
fn code(secret: &[u8], step: u64) -> String {
    use hmac::{KeyInit, Mac};
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(secret).expect("any key length");
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = (h[19] & 0x0f) as usize;
    let n = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
    format!("{:06}", n % 1_000_000)
}

fn unbase32(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for c in text.trim_end_matches('=').chars() {
        acc = (acc << 5) | ALPHABET.find(c.to_ascii_uppercase())? as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

async fn totp(ctx: &Ctx, r: &mut Report) {
    const E: [(&str, &str); 3] = [
        ("POST /account/totp/start", "starts two-step verification"),
        (
            "POST /account/totp/enable",
            "turns it on with a code; sign-in then needs one",
        ),
        (
            "DELETE /account/totp",
            "turns it off with the AuthKey and a fresh code",
        ),
    ];
    if !ctx.caps.as_ref().is_some_and(|c| c.features.totp) {
        for (e, w) in E {
            r.skip(
                G,
                e,
                w,
                "the server doesn't offer two-step verification (features.totp)",
            );
        }
        return;
    }
    let Some((a, email, _)) = r
        .check(
            G,
            "POST /auth/register",
            "an account for two-step verification",
            fake::account(ctx, "totp", 7),
        )
        .await
    else {
        return;
    };
    let Some(secret) = r
        .check(G, E[0].0, E[0].1, async {
            let setup = a
                .start_totp(&TotpStartRequest {
                    auth_key: bytes(32, 7),
                })
                .await
                .map_err(shown)?;
            ensure(
                setup.uri.starts_with("otpauth://totp/"),
                format!("uri {:?} isn't otpauth://totp/", setup.uri),
            )?;
            unbase32(&setup.secret).ok_or_else(|| format!("secret {:?} isn't base32", setup.secret))
        })
        .await
    else {
        return;
    };
    let step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 30)
        .unwrap_or(0);
    r.check(G, E[1].0, E[1].1, async {
        a.enable_totp(&code(&secret, step - 1))
            .await
            .map_err(shown)?;
        ensure(
            a.account().await.map_err(shown)?.totp_enabled,
            "GET /account says it's off",
        )?;
        let b = ctx.client()?;
        match b.login(&fake::login_req(&email, 7)).await {
            Err(Error::Api { code, .. }) if code == "totp_required" => {}
            other => {
                return Err(format!(
                    "signing in without a code: expected totp_required, got {}",
                    outcome(other)
                ));
            }
        }
        let with = LoginRequest {
            totp: Some(code(&secret, step)),
            ..fake::login_req(&email, 7)
        };
        b.login(&with)
            .await
            .map_err(|e| format!("signing in with a code: {e}"))?;
        Ok(())
    })
    .await;
    r.check(G, E[2].0, E[2].1, async {
        let off = TotpDisableRequest {
            auth_key: bytes(32, 7),
            code: code(&secret, step + 1),
        };
        a.disable_totp(&off).await.map_err(shown)?;
        ensure(
            !a.account().await.map_err(shown)?.totp_enabled,
            "GET /account says it's still on",
        )
    })
    .await;
}

/// Email changes need the code mailed to the new address: only the refusal can be checked.
async fn email_change(ctx: &Ctx, r: &mut Report) {
    if !ctx
        .caps
        .as_ref()
        .is_some_and(|c| c.features.email_verification)
    {
        r.skip(
            G,
            "POST /account/email/start",
            "mails a code to the new address",
            "the server doesn't verify addresses (features.email_verification)",
        );
        r.skip(
            G,
            "PUT /account/email",
            "changes the address with the code",
            "the server doesn't verify addresses (features.email_verification)",
        );
        return;
    }
    if ctx.opts.mailpit.is_none() {
        for (e, w) in [
            (
                "POST /account/email/start",
                "mails a code to the new address",
            ),
            ("PUT /account/email", "changes the address with the code"),
        ] {
            r.skip(
                G,
                e,
                w,
                "the code goes by mail: pass --mailpit URL to read it",
            );
        }
        return;
    }
    let Some(c) = r
        .check(
            G,
            "POST /auth/register",
            "an account whose address changes",
            ctx.shared(),
        )
        .await
    else {
        return;
    };
    let new = ctx.email("moved");
    r.check(
        G,
        "POST /account/email/start",
        "mails a code to the new address",
        async { c.start_email_change(&new).await.map_err(shown) },
    )
    .await;
    r.check(
        G,
        "PUT /account/email",
        "changes the address with the code; a wrong code is refused",
        async {
            let code = ctx.mailed_code(&new, &[]).await?;
            let wrong = EmailChangeRequest {
                new_email: new.clone(),
                code: "000000".into(),
                auth_key: bytes(32, 1),
            };
            match c.change_email(&wrong).await {
                Err(Error::Api { status: 400, .. }) => {}
                other => {
                    return Err(format!(
                        "a wrong code: expected 400, got {}",
                        outcome(other)
                    ));
                }
            }
            let right = EmailChangeRequest {
                new_email: new.clone(),
                code,
                auth_key: bytes(32, 1),
            };
            c.change_email(&right).await.map_err(shown)?;
            let acct = c.account().await.map_err(shown)?;
            ensure(
                acct.email.eq_ignore_ascii_case(&new),
                format!("the address is still {}", acct.email),
            )
        },
    )
    .await;
}

async fn web_session(ctx: &Ctx, r: &mut Report) {
    if !ctx
        .caps
        .as_ref()
        .is_some_and(|c| c.features.billing.as_ref().is_some_and(|b| b.web_session))
    {
        r.skip(
            G,
            "POST /account/web-session",
            "a signed-in link to the account portal",
            "the server has no account portal (features.billing.web_session)",
        );
        return;
    }
    r.check(
        G,
        "POST /account/web-session",
        "a signed-in link to the account portal",
        async {
            let a = ctx.shared().await?;
            let link = a.web_session(None).await.map_err(shown)?;
            ensure(
                link.url.starts_with("https://") || link.url.starts_with("http://"),
                format!("not a link: {:?}", link.url),
            )?;
            ensure(link.expires_in > 0, "expires_in is 0")
        },
    )
    .await;
    r.check(
        G,
        "POST /account/web-session",
        "`next` picks an account page; anything else is 400",
        async {
            let a = ctx.shared().await?;
            let link = a
                .web_session(Some("/account/two-step"))
                .await
                .map_err(shown)?;
            ensure(link.expires_in > 0, "expires_in is 0")?;
            match a.web_session(Some("https://example.com/")).await {
                Err(Error::Api { status: 400, .. }) => Ok(()),
                other => Err(format!(
                    "next outside the account pages: expected 400, got {}",
                    outcome(other.map(|_| ()))
                )),
            }
        },
    )
    .await;
}
