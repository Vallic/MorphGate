//! The feed client against a fake publisher on loopback: the request it makes, a refused token,
//! a document too large, and one it reads.

use std::sync::{Arc, Mutex};

use mg_inventory::feed;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serves `GET /feed` (with token `T1`), `/big` (over 5 MiB) and `/moved` (a redirect to plain
/// HTTP elsewhere). Returns its address and the request heads it saw.
async fn publisher() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = heads.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let head = loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break String::from_utf8_lossy(&buf[..end]).to_string();
                    }
                };
                seen.lock().unwrap().push(head.clone());
                let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
                let authorized = head
                    .lines()
                    .any(|l| l.eq_ignore_ascii_case("authorization: Bearer T1"));
                let (status, extra, body) = match path.as_str() {
                    _ if !authorized => ("401 Unauthorized", String::new(), "{}".to_owned()),
                    "/feed" => (
                        "200 OK",
                        String::new(),
                        serde_json::json!({
                            "version": 1,
                            "name": "Ops",
                            "hosts": [{ "id": "web-1", "hostname": "10.0.0.1", "user": "ops" }],
                            "snippets": [{ "id": "up", "name": "Uptime", "body": "uptime" }]
                        })
                        .to_string(),
                    ),
                    "/big" => (
                        "200 OK",
                        String::new(),
                        format!(
                            "{{\"version\": 1, \"name\": \"{}\"}}",
                            "x".repeat(feed::MAX_BYTES)
                        ),
                    ),
                    "/moved" => (
                        "302 Found",
                        "location: http://example.com/feed\r\n".to_owned(),
                        String::new(),
                    ),
                    _ => ("404 Not Found", String::new(), String::new()),
                };
                let reply = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(reply.as_bytes()).await;
            });
        }
    });
    (format!("http://{addr}"), heads)
}

#[tokio::test]
async fn reads_a_feed_with_its_token() {
    let (base, heads) = publisher().await;
    let feed = feed::fetch("Ops", &format!("{base}/feed"), "T1")
        .await
        .unwrap();
    assert_eq!(feed.name.as_deref(), Some("Ops"));
    assert_eq!(feed.hosts[0].external_id, "feed:web-1");
    assert_eq!(feed.snippets[0].body, "uptime");
    let head = heads.lock().unwrap()[0].to_lowercase();
    assert!(head.contains("accept: application/json"), "{head}");
    assert!(
        head.contains(&format!(
            "user-agent: morphgate/{}",
            env!("CARGO_PKG_VERSION")
        )),
        "{head}"
    );
}

#[tokio::test]
async fn a_refused_token_too_large_and_elsewhere_are_said() {
    let (base, _) = publisher().await;
    let err = |r: mg_inventory::Result<feed::Feed>| r.unwrap_err().to_string();
    assert_eq!(
        err(feed::fetch("Ops", &format!("{base}/feed"), "wrong").await),
        "Ops refused the token"
    );
    assert_eq!(
        err(feed::fetch("Ops", &format!("{base}/big"), "T1").await),
        "Ops sent more than 5 MiB: a feed is at most that"
    );
    // Not followed to plain HTTP on another host: the redirect itself is the answer.
    assert_eq!(
        err(feed::fetch("Ops", &format!("{base}/moved"), "T1").await),
        "Ops answered 302 Found"
    );
    assert_eq!(
        err(feed::fetch("Ops", &format!("{base}/nothing"), "T1").await),
        "Ops answered 404 Not Found"
    );
}
