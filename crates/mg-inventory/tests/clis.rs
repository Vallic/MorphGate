//! The providers' real CLIs, read only: who's signed in, and what they list. Skipped unless
//! asked for, as each needs an account signed in on this machine:
//!
//! ```sh
//! MG_TEST_AZ=1 cargo test -p mg-inventory --test clis -- --include-ignored --nocapture
//! MG_TEST_AWS=1 [MG_TEST_AWS_PROFILE=…] cargo test -p mg-inventory --test clis -- --include-ignored --nocapture
//! MG_TEST_GCLOUD=1 cargo test -p mg-inventory --test clis -- --include-ignored --nocapture
//! MG_TEST_HCLOUD=1 cargo test -p mg-inventory --test clis -- --include-ignored --nocapture
//! MG_TEST_DOCTL=1 cargo test -p mg-inventory --test clis -- --include-ignored --nocapture
//! ```
//!
//! What they print is counts and states, not names or addresses.

use mg_inventory::cli::Cli;
use mg_inventory::{Listing, aws, azure, digitalocean, gcp, hetzner};

fn summary(listing: &Listing) {
    let running = listing.machines.iter().filter(|m| m.running).count();
    let public = listing
        .machines
        .iter()
        .filter(|m| m.public_address.is_some())
        .count();
    let users = listing.machines.iter().filter(|m| m.user.is_some()).count();
    println!(
        "{} machines ({running} running, {public} with a public address, {users} saying a user); {} skipped",
        listing.machines.len(),
        listing.skipped.len()
    );
    for m in &listing.machines {
        assert!(!m.external_id.is_empty() && !m.name.is_empty() && !m.state.is_empty());
    }
}

#[tokio::test]
#[ignore = "needs MG_TEST_AZ and az signed in"]
async fn azure() {
    if std::env::var_os("MG_TEST_AZ").is_none() {
        return;
    }
    let cli = Cli::find("az", None).unwrap();
    assert!(!azure::whoami(&cli).await.unwrap().is_empty());
    let subscriptions = azure::subscriptions(&cli).await.unwrap();
    println!("{} subscriptions", subscriptions.len());
    summary(&azure::machines(&cli, &[]).await.unwrap());
}

#[tokio::test]
#[ignore = "needs MG_TEST_AWS and aws signed in"]
async fn aws() {
    if std::env::var_os("MG_TEST_AWS").is_none() {
        return;
    }
    let profile = std::env::var("MG_TEST_AWS_PROFILE").ok();
    let cli = Cli::find("aws", None).unwrap();
    assert!(
        !aws::whoami(&cli, profile.as_deref())
            .await
            .unwrap()
            .is_empty()
    );
    summary(&aws::machines(&cli, profile.as_deref(), &[]).await.unwrap());
}

#[tokio::test]
#[ignore = "needs MG_TEST_GCLOUD and gcloud signed in"]
async fn gcloud() {
    if std::env::var_os("MG_TEST_GCLOUD").is_none() {
        return;
    }
    let cli = Cli::find("gcloud", None).unwrap();
    assert!(!gcp::whoami(&cli).await.unwrap().is_empty());
    summary(&gcp::machines(&cli, &[]).await.unwrap());
}

#[tokio::test]
#[ignore = "needs MG_TEST_HCLOUD and an hcloud context"]
async fn hcloud() {
    if std::env::var_os("MG_TEST_HCLOUD").is_none() {
        return;
    }
    let cli = Cli::find("hcloud", None).unwrap();
    assert!(!hetzner::whoami(&cli, None).await.unwrap().is_empty());
    summary(&hetzner::machines(&cli, None).await.unwrap());
}

#[tokio::test]
#[ignore = "needs MG_TEST_DOCTL and doctl signed in"]
async fn doctl() {
    if std::env::var_os("MG_TEST_DOCTL").is_none() {
        return;
    }
    let cli = Cli::find("doctl", None).unwrap();
    assert!(!digitalocean::whoami(&cli, None).await.unwrap().is_empty());
    summary(&digitalocean::machines(&cli, None).await.unwrap());
}
