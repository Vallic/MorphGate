//! What the checks found: one line per check, grouped by endpoint, as text or JSON.

use std::future::Future;
use std::time::Instant;

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", content = "detail", rename_all = "lowercase")]
pub enum Outcome {
    Pass,
    /// What went wrong: the server's answer, or what was expected instead.
    Fail(String),
    /// Why it didn't run: the server doesn't offer it, or it needs something this run lacks.
    Skip(String),
}

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    /// The group of checks (`auth`, `sharing`, …).
    pub group: &'static str,
    /// `METHOD /path` as the spec names it.
    pub endpoint: String,
    pub what: String,
    #[serde(flatten)]
    pub outcome: Outcome,
    pub ms: u128,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub server: String,
    pub checks: Vec<Check>,
}

impl Report {
    /// Runs one check; `Ok` passes, `Err` fails with its text. Returns the value on success,
    /// so later checks can build on it.
    pub async fn check<T>(
        &mut self,
        group: &'static str,
        endpoint: &str,
        what: &str,
        f: impl Future<Output = Result<T, String>>,
    ) -> Option<T> {
        let started = Instant::now();
        let result = f.await;
        let ms = started.elapsed().as_millis();
        let (outcome, value) = match result {
            Ok(v) => (Outcome::Pass, Some(v)),
            Err(e) => (Outcome::Fail(e), None),
        };
        self.checks.push(Check {
            group,
            endpoint: endpoint.to_owned(),
            what: what.to_owned(),
            outcome,
            ms,
        });
        value
    }

    pub fn skip(&mut self, group: &'static str, endpoint: &str, what: &str, why: &str) {
        self.checks.push(Check {
            group,
            endpoint: endpoint.to_owned(),
            what: what.to_owned(),
            outcome: Outcome::Skip(why.to_owned()),
            ms: 0,
        });
    }

    pub fn passed(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Pass))
    }

    pub fn failed(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Fail(_)))
    }

    pub fn skipped(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Skip(_)))
    }

    fn count(&self, f: impl Fn(&Outcome) -> bool) -> usize {
        self.checks.iter().filter(|c| f(&c.outcome)).count()
    }

    /// The report for people: endpoints in order, one line per check, then the totals.
    pub fn text(&self, color: bool) -> String {
        let paint = |code: &str, s: &str| {
            if color {
                format!("\x1b[{code}m{s}\x1b[0m")
            } else {
                s.to_owned()
            }
        };
        let mut out = format!("vault-conform: {}\n", self.server);
        let mut group = "";
        for c in &self.checks {
            if c.group != group {
                group = c.group;
                out.push_str(&format!("\n{}\n", paint("1", group)));
            }
            let (tag, detail) = match &c.outcome {
                Outcome::Pass => (paint("32", "PASS"), String::new()),
                Outcome::Fail(e) => (paint("31", "FAIL"), format!("\n        {}", paint("31", e))),
                Outcome::Skip(why) => (paint("33", "SKIP"), format!(" ({why})")),
            };
            out.push_str(&format!("  {tag}  {:<52} {}{detail}\n", c.endpoint, c.what));
        }
        out.push_str(&format!(
            "\n{} passed, {} failed, {} skipped\n",
            self.passed(),
            self.failed(),
            self.skipped()
        ));
        out
    }
}

/// `Err(msg)` unless `ok`.
pub fn ensure(ok: bool, msg: impl Into<String>) -> Result<(), String> {
    if ok { Ok(()) } else { Err(msg.into()) }
}

/// An error as the report shows it.
pub fn shown(e: impl std::fmt::Display) -> String {
    e.to_string()
}
