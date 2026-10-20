//! The Vallic client against a fake console on loopback: signing in (device flow), refreshing
//! (rotation, a replay refused), and the inventory.

use std::sync::{Arc, Mutex};

use mg_inventory::Error;
use mg_inventory::vallic::{Poll, Session, Vallic};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct Console {
    polls: u32,
    /// The refresh token that still works.
    refresh: String,
}

async fn console() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(Mutex::new(Console {
        refresh: "R1".into(),
        ..Console::default()
    }));
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let state = state.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Head, then the body its Content-Length says.
                let (head, body) = loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).to_string();
                        let len = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        while buf.len() < end + 4 + len {
                            let n = sock.read(&mut chunk).await.unwrap();
                            buf.extend_from_slice(&chunk[..n]);
                        }
                        break (
                            head,
                            String::from_utf8_lossy(&buf[end + 4..end + 4 + len]).to_string(),
                        );
                    }
                };
                let line = head.lines().next().unwrap().to_owned();
                let bearer = head
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("authorization: Bearer ")
                            .or_else(|| l.strip_prefix("Authorization: Bearer "))
                    })
                    .unwrap_or("")
                    .to_owned();
                let (status, json) = route(&line, &body, &bearer, &state);
                let reply = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{json}",
                    json.len()
                );
                sock.write_all(reply.as_bytes()).await.unwrap();
            });
        }
    });
    format!("http://{addr}")
}

fn route(line: &str, body: &str, bearer: &str, state: &Mutex<Console>) -> (&'static str, String) {
    let ok = |v: serde_json::Value| ("200 OK", v.to_string());
    let oauth = |code: &str| {
        (
            "400 Bad Request",
            serde_json::json!({ "error": code }).to_string(),
        )
    };
    let mut s = state.lock().unwrap();
    match line.split_whitespace().nth(1).unwrap_or("") {
        "/oauth/device_authorization" => {
            assert!(
                body.contains("client_id=vallic-cli")
                    && body.contains("device_name=MorphGate+test"),
                "{body}"
            );
            ok(
                serde_json::json!({ "device_code": "D1", "user_code": "ABCD-EFGH", "verification_uri": "https://console.example/device", "expires_in": 600, "interval": 1 }),
            )
        }
        "/oauth/token" if body.contains("device_code=D1") => {
            s.polls += 1;
            if s.polls == 1 {
                oauth("authorization_pending")
            } else {
                ok(
                    serde_json::json!({ "access_token": "A1", "refresh_token": "R1", "expires_in": 900 }),
                )
            }
        }
        "/oauth/token" if body.contains("grant_type=refresh_token") => {
            let given = body
                .split('&')
                .find_map(|kv| kv.strip_prefix("refresh_token="))
                .unwrap_or("");
            if given != s.refresh {
                return oauth("invalid_grant");
            }
            let next = format!("R{}", given[1..].parse::<u32>().unwrap() + 1);
            s.refresh = next.clone();
            ok(
                serde_json::json!({ "access_token": "A2", "refresh_token": next, "expires_in": 900 }),
            )
        }
        _ if bearer != "A2" => ("401 Unauthorized", "{}".into()),
        "/api/vc/v1/projects" => ok(
            serde_json::json!({ "projects": [{ "id": 1, "label": "Shop", "machine_name": "shop" }] }),
        ),
        "/api/vc/v1/environments" => ok(serde_json::json!({ "environments": [
            { "id": 7, "slug": "production", "name": "Production", "project": 1 },
            { "id": 9, "slug": "preview", "name": "Preview", "project": 1 }
        ] })),
        "/api/vc/v1/environments/7" => ok(serde_json::json!({ "environment": {
            "id": 7, "slug": "production", "name": "Production", "project": 1,
            "ssh": { "host": "production.acme.vallic.cloud", "port": 2417, "user": "vc-t-acme" }
        } })),
        "/api/vc/v1/environments/9" => ok(
            serde_json::json!({ "environment": { "id": 9, "slug": "preview", "name": "Preview", "project": 1, "ssh": null } }),
        ),
        _ => ("404 Not Found", "{}".into()),
    }
}

#[tokio::test]
async fn sign_in_refresh_and_list() {
    let v = Vallic::new(Some(&console().await)).unwrap();

    let device = v.sign_in("MorphGate test").await.unwrap();
    assert_eq!(device.user_code, "ABCD-EFGH");
    assert!(matches!(
        v.poll(&device.device_code).await.unwrap(),
        Poll::Pending
    ));
    let Poll::Approved(tokens) = v.poll(&device.device_code).await.unwrap() else {
        panic!("not approved");
    };
    assert_eq!(tokens.refresh, "R1");

    // A session from the stored refresh token: the first call refreshes, and the token rotates.
    let mut session = Session::new(tokens.refresh);
    let access = session.access(&v).await.unwrap();
    assert_eq!((access.as_str(), session.refresh_token()), ("A2", "R2"));
    // The old refresh token is refused now: that sign-in ended for whoever still had it.
    assert!(matches!(v.refresh("R1").await, Err(Error::SignedOut(_))));

    let inventory = v.inventory(&access).await.unwrap();
    assert_eq!(inventory.hosts.len(), 1);
    assert_eq!(inventory.hosts[0].port, 2417);
    assert_eq!(inventory.without_shell, ["Shop · Preview"]);
    // A stale access token: signed out, so the caller refreshes.
    assert!(matches!(v.projects("A1").await, Err(Error::SignedOut(_))));
}
