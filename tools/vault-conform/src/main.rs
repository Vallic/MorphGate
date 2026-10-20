//! `vault-conform URL`: checks a vault-sync/v1 server, endpoint by endpoint.

use std::io::IsTerminal;
use std::process::ExitCode;

use vault_conform::{GROUPS, Options, run};

const USAGE: &str = "vault-conform URL [options]

Checks a vault-sync/v1 server against the spec, endpoint by endpoint, with throwaway accounts.
The server must accept new accounts without a mailed code (or give --mailpit for invites). A full
run registers 8 accounts and signs in about 15 times: a server's per-IP rate limits must allow
that (the hosted backend's default allows 10 registrations an hour).

Options:
  --only GROUP[,GROUP…]    run only these groups: discovery, auth, account, vaults, blobs,
                           sharing, exports, scim (discovery always runs)
  --email-domain DOMAIN    domain of the throwaway addresses (default example.com)
  --purge-command CMD      a shell command that makes the server purge tombstones now, to
                           check 410 Gone (e.g. \"drush vault-sync:purge --all\")
  --scim ORG_ID:TOKEN      an organization's SCIM token, to check provisioning
  --mailpit URL            a Mailpit that receives the server's mail (e.g. ddev's, on port
                           8026), to read invites a server mails instead of returning
  --json                   the report as JSON
  --no-color               plain text
  -h, --help               this help

Exits 0 when nothing failed (skips are fine), 1 when something did, 2 on a usage error.";

fn parse() -> Result<(Options, bool, bool), String> {
    let mut args = std::env::args().skip(1);
    let mut server = None;
    let mut opts_json = false;
    let mut color = std::io::stdout().is_terminal();
    let mut only = Vec::new();
    let mut domain = None;
    let mut purge = None;
    let mut scim = None;
    let mut mailpit = None;
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "--json" => opts_json = true,
            "--no-color" => color = false,
            "--only" => {
                for g in value()?.split(',').map(str::trim).filter(|g| !g.is_empty()) {
                    if !GROUPS.contains(&g) {
                        return Err(format!("unknown group {g}; groups: {}", GROUPS.join(", ")));
                    }
                    only.push(g.to_owned());
                }
            }
            "--email-domain" => domain = Some(value()?),
            "--mailpit" => mailpit = Some(value()?),
            "--purge-command" => purge = Some(value()?),
            "--scim" => {
                let v = value()?;
                let (org, token) = v.split_once(':').ok_or("--scim takes ORG_ID:TOKEN")?;
                scim = Some((org.to_owned(), token.to_owned()));
            }
            other if other.starts_with('-') => return Err(format!("unknown option {other}")),
            url if server.is_none() => server = Some(url.to_owned()),
            extra => return Err(format!("unexpected argument {extra}")),
        }
    }
    let server = server.ok_or("which server? vault-conform URL")?;
    if !server.starts_with("https://") && !server.starts_with("http://") {
        return Err(format!("{server} isn't an http(s) URL"));
    }
    let mut opts = Options::new(&server);
    opts.only = only;
    if let Some(d) = domain {
        opts.email_domain = d;
    }
    opts.purge_command = purge;
    opts.scim = scim;
    opts.mailpit = mailpit;
    Ok((opts, opts_json, color))
}

#[tokio::main]
async fn main() -> ExitCode {
    let (opts, json, color) = match parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vault-conform: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let report = run(opts).await;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serializable")
        );
    } else {
        print!("{}", report.text(color));
    }
    if report.failed() > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
