//! `morphgate://` links, from the website ("Open in MorphGate" on an invite, the account page) and
//! from consoles that list servers. A link only opens a screen, filled in: it never joins,
//! connects or changes anything by itself, and passwords or keys in it are ignored.
//!
//! - `morphgate://invite?token=…&server=…` (or `morphgate://invite/<token>`): Teams, joining
//! - `morphgate://sync`, `morphgate://teams`, `morphgate://teams/<org id>`
//! - `morphgate://connect?host=…&port=…&user=…&label=…`: quick connect
//!
//! Dev builds answer `morphgate-dev://` instead. Links that arrive while the vault is locked wait
//! here until the workspace takes them; the first screen looks at a waiting invite (and can add
//! one pasted there) without taking it.

use std::sync::Mutex;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State, Url};

/// What a link opens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Link {
    /// Teams → Join, looking up this invite. `server`: the sync server it's for.
    Invite {
        token: String,
        server: Option<String>,
    },
    Sync,
    /// Teams, or one team's page.
    Teams {
        org_id: Option<String>,
    },
    /// Quick connect, filled in.
    Connect {
        host: String,
        port: Option<u16>,
        user: Option<String>,
        label: Option<String>,
    },
}

/// A received link: what it opens, or why it can't be opened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Received {
    link: Option<Link>,
    error: Option<String>,
}

#[derive(Default)]
pub struct Links(Mutex<Vec<Received>>);

const SCHEMES: [&str; 2] = ["morphgate", "morphgate-dev"];

/// What `url` asks for.
pub fn parse(url: &Url) -> Result<Link, String> {
    if !SCHEMES.contains(&url.scheme()) {
        return Err(format!("not a MorphGate link ({}://)", url.scheme()));
    }
    let action = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let path: Vec<&str> = url
        .path_segments()
        .map(|p| p.filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    let query = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    match action.as_str() {
        "invite" => {
            let token = query("token")
                .or_else(|| path.first().map(|s| (*s).to_owned()))
                .ok_or("the invite link has no code")?;
            if !invite_code(&token) {
                return Err("the invite code in the link isn't valid".into());
            }
            let server = query("server").map(|s| origin(&s)).transpose()?;
            Ok(Link::Invite { token, server })
        }
        "sync" => Ok(Link::Sync),
        "teams" => {
            let org_id = match path.first() {
                Some(id) if id.len() == 26 && id.bytes().all(|b| b.is_ascii_alphanumeric()) => {
                    Some(id.to_ascii_uppercase())
                }
                Some(_) => return Err("the team in the link isn't valid".into()),
                None => None,
            };
            Ok(Link::Teams { org_id })
        }
        "connect" => {
            let host = query("host").ok_or("the link names no host")?;
            let host_ok = host.len() <= 253
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b));
            if !host_ok {
                return Err("the host in the link isn't a host name or address".into());
            }
            let port = match query("port") {
                Some(p) => Some(
                    p.parse::<u16>()
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or("the port in the link isn't valid")?,
                ),
                None => None,
            };
            let user = query("user");
            if let Some(u) = &user
                && (u.len() > 64
                    || !u
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
            {
                return Err("the user in the link isn't valid".into());
            }
            let label = query("label").map(|l| {
                l.chars()
                    .filter(|c| !c.is_control())
                    .take(64)
                    .collect::<String>()
            });
            Ok(Link::Connect {
                host: host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned(),
                port,
                user,
                label,
            })
        }
        "" => Err("the link says nothing to open".into()),
        other => Err(format!(
            "this version of MorphGate doesn't know “{other}” links"
        )),
    }
}

/// What an invite code looks like.
fn invite_code(token: &str) -> bool {
    (16..=256).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// An invite pasted on the first screen: the code, the website's invite page
/// (`https://…/invite/<code>`), or a `morphgate://invite` link.
pub fn pasted_invite(text: &str) -> Result<Link, String> {
    let text = text.trim();
    let not = || "that isn't an invite link or code".to_owned();
    if invite_code(text) {
        return Ok(Link::Invite {
            token: text.into(),
            server: None,
        });
    }
    let url = Url::parse(text).map_err(|_| not())?;
    if SCHEMES.contains(&url.scheme()) {
        return match parse(&url)? {
            link @ Link::Invite { .. } => Ok(link),
            _ => Err(not()),
        };
    }
    let token = match url
        .path_segments()
        .map(|p| p.collect::<Vec<_>>())
        .as_deref()
    {
        Some(["invite", token]) if invite_code(token) => (*token).to_owned(),
        _ => return Err(not()),
    };
    Ok(Link::Invite {
        token,
        server: Some(origin(url.as_str())?),
    })
}

/// `https://host[:port]` (plain `http` only for this computer).
fn origin(server: &str) -> Result<String, String> {
    let bad = || "the server in the link isn't a sync server address".to_owned();
    let url = Url::parse(server).map_err(|_| bad())?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if !(url.scheme() == "https" || (url.scheme() == "http" && local))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(bad());
    }
    Ok(url.origin().ascii_serialization())
}

/// Links from the system (the app opened by one, or one opened while it runs): kept for the
/// workspace, which is told, and the window comes forward.
pub fn received(app: &AppHandle, urls: Vec<Url>) {
    let ours: Vec<Received> = urls
        .iter()
        .filter(|u| SCHEMES.contains(&u.scheme()))
        .map(|u| match parse(u) {
            Ok(link) => Received {
                link: Some(link),
                error: None,
            },
            Err(e) => Received {
                link: None,
                error: Some(format!("MorphGate can't open this link: {e}")),
            },
        })
        .collect();
    if ours.is_empty() {
        return;
    }
    if let Ok(mut pending) = app.state::<Links>().0.lock() {
        pending.extend(ours);
    }
    show(app);
    let _ = app.emit("links-pending", ());
}

/// Brings the window forward (a link, or a second launch). Phones show the app themselves.
pub fn show(_app: &AppHandle) {
    #[cfg(desktop)]
    if let Some(w) = _app.webview_windows().values().next() {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// The links received since the last call (the unlocked workspace takes them).
#[tauri::command]
pub fn links_take(links: State<'_, Links>) -> Vec<Received> {
    links
        .0
        .lock()
        .map(|mut l| std::mem::take(&mut *l))
        .unwrap_or_default()
}

/// The links waiting for the workspace, left waiting (the first screen shows an invite).
#[tauri::command]
pub fn links_peek(links: State<'_, Links>) -> Vec<Received> {
    links.0.lock().map(|l| l.clone()).unwrap_or_default()
}

/// An invite pasted on the first screen: it waits with the other links, so the workspace opens
/// Teams with it once there's an account.
#[tauri::command]
pub fn links_add_invite(
    app: AppHandle,
    links: State<'_, Links>,
    text: String,
) -> Result<(), String> {
    let link = pasted_invite(&text)?;
    let mut pending = links.0.lock().map_err(|_| "links lock poisoned")?;
    // One invite at a time: the newest replaces any waiting.
    pending.retain(|r| !matches!(r.link, Some(Link::Invite { .. })));
    pending.push(Received {
        link: Some(link),
        error: None,
    });
    drop(pending);
    let _ = app.emit("links-pending", ());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(s: &str) -> Result<Link, String> {
        parse(&Url::parse(s).unwrap())
    }

    const TOKEN: &str = "AbCdEfGhIjKlMnOpQrStUv_-0123456789";

    #[test]
    fn pasted_invites() {
        let hosted = Link::Invite {
            token: TOKEN.into(),
            server: Some("https://morphgate.com".into()),
        };
        assert_eq!(
            pasted_invite(&format!(" {TOKEN}\n")),
            Ok(Link::Invite {
                token: TOKEN.into(),
                server: None
            })
        );
        assert_eq!(
            pasted_invite(&format!("https://morphgate.com/invite/{TOKEN}")),
            Ok(hosted.clone())
        );
        assert_eq!(
            pasted_invite(&format!(
                "morphgate://invite?token={TOKEN}&server=https://morphgate.com"
            )),
            Ok(hosted)
        );
        for not in [
            "hello",
            "morphgate://sync",
            "https://morphgate.com/account",
            "http://evil.example/invite/AbCdEfGhIjKlMnOpQrStUv",
        ] {
            assert!(pasted_invite(not).is_err(), "{not}");
        }
    }

    #[test]
    fn invites() {
        let expected = Link::Invite {
            token: TOKEN.into(),
            server: Some("https://morphgate.com".into()),
        };
        assert_eq!(
            link(&format!(
                "morphgate://invite?token={TOKEN}&server=https://morphgate.com/"
            )),
            Ok(expected.clone())
        );
        assert_eq!(
            link(&format!(
                "morphgate://Invite/{TOKEN}?server=https%3A%2F%2Fmorphgate.com"
            )),
            Ok(expected)
        );
        assert!(link("morphgate://invite?token=short").is_err());
        assert!(
            link(&format!(
                "morphgate://invite?token={TOKEN}&server=http://evil.example"
            ))
            .is_err()
        );
        assert!(
            link(&format!(
                "morphgate://invite?token={TOKEN}&server=https://me:pw@morphgate.com"
            ))
            .is_err()
        );
        // The reference server on this computer.
        assert_eq!(
            link(&format!(
                "morphgate://invite?token={TOKEN}&server=http://127.0.0.1:8790"
            )),
            Ok(Link::Invite {
                token: TOKEN.into(),
                server: Some("http://127.0.0.1:8790".into())
            })
        );
    }

    #[test]
    fn pages() {
        assert_eq!(link("morphgate://sync"), Ok(Link::Sync));
        assert_eq!(
            link("morphgate-dev://teams/"),
            Ok(Link::Teams { org_id: None })
        );
        assert_eq!(
            link("morphgate://teams/01j5abcdefghjkmnpqrstvwxyz"),
            Ok(Link::Teams {
                org_id: Some("01J5ABCDEFGHJKMNPQRSTVWXYZ".into())
            })
        );
        assert!(link("morphgate://teams/../../etc").is_err());
        assert!(
            link("morphgate://delete-everything")
                .unwrap_err()
                .contains("delete-everything")
        );
        assert!(link("https://morphgate.com/sync").is_err());
    }

    #[test]
    fn connect_fills_in_and_ignores_secrets() {
        assert_eq!(
            link(
                "morphgate://connect?host=web-1.example.com&port=2222&user=deploy&label=Web%201&password=hunter2"
            ),
            Ok(Link::Connect {
                host: "web-1.example.com".into(),
                port: Some(2222),
                user: Some("deploy".into()),
                label: Some("Web 1".into()),
            })
        );
        assert_eq!(
            link("morphgate://connect?host=[2001:db8::1]"),
            Ok(Link::Connect {
                host: "2001:db8::1".into(),
                port: None,
                user: None,
                label: None
            })
        );
        assert!(link("morphgate://connect?host=a;rm%20-rf").is_err());
        assert!(link("morphgate://connect?host=a&port=0").is_err());
        assert!(link("morphgate://connect?host=a&user=root;id").is_err());
        assert!(link("morphgate://connect").is_err());
    }
}
