//! The tool against the in-process reference server: everything it offers passes.

use vault_conform::{Options, Outcome, run};
use vault_sync_server::{AppState, Config, router};

#[tokio::test]
async fn the_reference_server_conforms() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = AppState::in_memory(Config {
        public_url: url.clone(),
        ..Config::default()
    })
    .unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });

    let report = run(Options::new(&url)).await;
    let failed: Vec<_> = report
        .checks
        .iter()
        .filter(|c| matches!(c.outcome, Outcome::Fail(_)))
        .map(|c| format!("{} {}: {:?}", c.endpoint, c.what, c.outcome))
        .collect();
    assert!(failed.is_empty(), "{}", failed.join("\n"));
    assert!(report.passed() > 60, "{}", report.text(false));
    // It keeps signed deletions, so that check runs.
    assert!(report.checks.iter().any(|c| {
        c.what.starts_with("keeps a deletion's envelope") && matches!(c.outcome, Outcome::Pass)
    }));
    // What the reference server doesn't offer, or this run can't do, is skipped and says why.
    for c in &report.checks {
        if let Outcome::Skip(why) = &c.outcome {
            assert!(!why.is_empty());
        }
    }
}
