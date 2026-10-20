//! polkit: `CheckAuthorization` for MorphGate's own action, which allows the active user after
//! they authenticate (`auth_self`). The desktop's polkit agent shows the dialog and PAM decides
//! what it accepts: a fingerprint where fprintd is set up, otherwise the login password.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::Value;

use crate::{Availability, Error, Kind, Parent, Status};

pub const ACTION_ID: &str = "com.morphgate.desktop.unlock";
pub const POLICY_PATH: &str = "/usr/share/polkit-1/actions/com.morphgate.desktop.policy";
pub const POLICY: &str = include_str!("../polkit/com.morphgate.desktop.policy");

/// `CheckAuthorization` flag: polkit may show an authentication dialog.
const ALLOW_USER_INTERACTION: u32 = 1;

/// `(action_id, description, message, vendor_name, vendor_url, icon_name, implicit_any,
/// implicit_inactive, implicit_active, annotations)`
pub(crate) type ActionDescription = (
    String,
    String,
    String,
    String,
    String,
    String,
    u32,
    u32,
    u32,
    HashMap<String, String>,
);

fn authority(conn: &Connection) -> zbus::Result<Proxy<'static>> {
    Proxy::new(
        conn,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
}

fn describe(e: zbus::Error) -> String {
    match &e {
        zbus::Error::MethodError(name, ..)
            if name.as_str() == "org.freedesktop.DBus.Error.ServiceUnknown"
                || name.as_str() == "org.freedesktop.DBus.Error.NameHasNoOwner" =>
        {
            "polkit is not running".into()
        }
        _ => format!("polkit: {e}"),
    }
}

/// Whether MorphGate's action is installed.
pub(crate) fn registered(conn: &Connection) -> zbus::Result<bool> {
    let actions: Vec<ActionDescription> = authority(conn)?.call("EnumerateActions", &("",))?;
    Ok(actions.iter().any(|a| a.0 == ACTION_ID))
}

pub(crate) struct Answer {
    pub authorized: bool,
    /// The user closed the dialog.
    pub dismissed: bool,
}

/// Asks polkit about this process (by its bus name, which can't be raced like a PID).
pub(crate) fn check(conn: &Connection, action: &str, interactive: bool) -> zbus::Result<Answer> {
    let name = conn
        .unique_name()
        .ok_or_else(|| zbus::Error::Failure("no unique name on the system bus".into()))?
        .to_string();
    let subject = (
        "system-bus-name",
        HashMap::from([("name", Value::from(name.as_str()))]),
    );
    let details: HashMap<&str, &str> = HashMap::new();
    let flags = if interactive {
        ALLOW_USER_INTERACTION
    } else {
        0
    };
    let (authorized, _challenge, details): (bool, bool, HashMap<String, String>) =
        authority(conn)?.call("CheckAuthorization", &(subject, action, details, flags, ""))?;
    Ok(Answer {
        authorized,
        dismissed: details.get("polkit.dismissed").is_some_and(|v| v == "true"),
    })
}

pub(crate) fn status(conn: &Connection) -> Status {
    match registered(conn) {
        Ok(true) => Status::Ready,
        Ok(false) => Status::NeedsSetup,
        Err(e) => Status::Unavailable(describe(e)),
    }
}

pub fn availability() -> Availability {
    let status = match Connection::system() {
        Ok(conn) => status(&conn),
        Err(e) => Status::Unavailable(format!("can't reach the system bus: {e}")),
    };
    Availability {
        kind: Kind::System,
        status,
    }
}

/// polkit shows the message from the installed action; `reason` has nowhere to go.
pub fn verify(_reason: &str, _parent: Parent) -> Result<(), Error> {
    let conn = Connection::system()
        .map_err(|e| Error::Unavailable(format!("can't reach the system bus: {e}")))?;
    verify_on(&conn)
}

pub(crate) fn verify_on(conn: &Connection) -> Result<(), Error> {
    match status(conn) {
        Status::Ready => {}
        Status::NeedsSetup => {
            return Err(Error::Unavailable(
                "MorphGate's polkit action isn't installed".into(),
            ));
        }
        Status::Unavailable(reason) => return Err(Error::Unavailable(reason)),
    }
    let answer = check(conn, ACTION_ID, true).map_err(|e| Error::Failed(describe(e)))?;
    if answer.authorized {
        Ok(())
    } else if answer.dismissed {
        Err(Error::Cancelled)
    } else {
        Err(Error::Failed("authentication failed".into()))
    }
}

pub fn setup() -> Result<(), Error> {
    install(&["pkexec"], Path::new(POLICY_PATH))
}

/// Writes the policy as root, through `pkexec` (tests pass a stand-in command). The content goes
/// through a pipe, never a file the user could swap in between: a policy can grant `pkexec`
/// rights to anything.
pub(crate) fn install(pkexec: &[&str], target: &Path) -> Result<(), Error> {
    let mut child = Command::new(pkexec[0])
        .args(&pkexec[1..])
        // polkitd reads actions as its own user: the file must be world-readable whatever our
        // umask is.
        .args(["/bin/sh", "-c", "umask 022 && exec tee \"$0\" >/dev/null"])
        .arg(target)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::Unavailable("pkexec is not installed".into()),
            _ => Error::Failed(format!("can't run pkexec: {e}")),
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        // Fits in the pipe buffer, so this doesn't wait for the password prompt. A dismissed
        // prompt closes the pipe; the exit status says so.
        let _ = stdin.write_all(POLICY.as_bytes());
    }
    let out = child
        .wait_with_output()
        .map_err(|e| Error::Failed(format!("pkexec: {e}")))?;
    match out.status.code() {
        Some(0) => Ok(()),
        Some(126) => Err(Error::Cancelled),
        Some(127) => Err(Error::Failed(
            "not authorized to install MorphGate's polkit action".into(),
        )),
        _ => Err(Error::Failed(format!(
            "installing MorphGate's polkit action failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::PermissionsExt;
    use std::process::Child;
    use std::sync::{Arc, Mutex};

    use zbus::zvariant::OwnedValue;

    use super::*;

    /// A private bus (`dbus-daemon`), killed on drop.
    struct Bus {
        daemon: Child,
        address: String,
        _dir: tempfile::TempDir,
    }

    impl Bus {
        fn start() -> Option<Self> {
            let dir = tempfile::tempdir().unwrap();
            let mut daemon = Command::new("dbus-daemon")
                .args(["--session", "--nofork", "--nosyslog", "--print-address=1"])
                .arg(format!("--address=unix:dir={}", dir.path().display()))
                .stdout(Stdio::piped())
                .spawn()
                .ok()?;
            let mut line = String::new();
            BufReader::new(daemon.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            Some(Bus {
                daemon,
                address: line.trim().to_owned(),
                _dir: dir,
            })
        }

        fn connect(&self) -> Connection {
            zbus::blocking::connection::Builder::address(self.address.as_str())
                .unwrap()
                .build()
                .unwrap()
        }
    }

    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.daemon.kill();
            let _ = self.daemon.wait();
        }
    }

    #[derive(Default)]
    struct Mock {
        registered: bool,
        /// What CheckAuthorization answers.
        authorized: bool,
        dismissed: bool,
        /// (subject kind, subject name, sender, action, flags) of each check.
        checks: Vec<(String, String, String, String, u32)>,
    }

    struct Authority(Arc<Mutex<Mock>>);

    #[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
    impl Authority {
        fn enumerate_actions(&self, _locale: &str) -> Vec<ActionDescription> {
            let mut actions = vec![action("org.example.other")];
            if self.0.lock().unwrap().registered {
                actions.push(action(ACTION_ID));
            }
            actions
        }

        fn check_authorization(
            &self,
            #[zbus(header)] header: zbus::message::Header<'_>,
            subject: (String, HashMap<String, OwnedValue>),
            action_id: String,
            _details: HashMap<String, String>,
            flags: u32,
            _cancellation_id: String,
        ) -> (bool, bool, HashMap<String, String>) {
            let mut mock = self.0.lock().unwrap();
            let name = subject
                .1
                .get("name")
                .and_then(|v| String::try_from(v.clone()).ok())
                .unwrap_or_default();
            let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();
            mock.checks
                .push((subject.0, name, sender, action_id, flags));
            let mut details = HashMap::new();
            if mock.dismissed {
                details.insert("polkit.dismissed".to_owned(), "true".to_owned());
            }
            (mock.authorized, false, details)
        }
    }

    fn action(id: &str) -> ActionDescription {
        (
            id.into(),
            "description".into(),
            "message".into(),
            "vendor".into(),
            String::new(),
            String::new(),
            0,
            0,
            2,
            HashMap::new(),
        )
    }

    #[test]
    fn polkit_conversation() {
        let Some(bus) = Bus::start() else {
            eprintln!("skipped: dbus-daemon is not installed");
            return;
        };
        let client = bus.connect();
        assert_eq!(
            status(&client),
            Status::Unavailable("polkit is not running".into())
        );

        let mock = Arc::new(Mutex::new(Mock::default()));
        let _polkitd = zbus::blocking::connection::Builder::address(bus.address.as_str())
            .unwrap()
            .name("org.freedesktop.PolicyKit1")
            .unwrap()
            .serve_at(
                "/org/freedesktop/PolicyKit1/Authority",
                Authority(mock.clone()),
            )
            .unwrap()
            .build()
            .unwrap();

        // Not installed: no dialog is even attempted.
        assert_eq!(status(&client), Status::NeedsSetup);
        assert!(matches!(verify_on(&client), Err(Error::Unavailable(_))));
        assert!(mock.lock().unwrap().checks.is_empty());

        mock.lock().unwrap().registered = true;
        assert_eq!(status(&client), Status::Ready);

        mock.lock().unwrap().authorized = true;
        assert_eq!(verify_on(&client), Ok(()));
        let me = client.unique_name().unwrap().to_string();
        assert_eq!(
            mock.lock().unwrap().checks,
            [(
                "system-bus-name".to_owned(),
                me.clone(),
                me,
                ACTION_ID.to_owned(),
                ALLOW_USER_INTERACTION
            )]
        );

        mock.lock().unwrap().authorized = false;
        mock.lock().unwrap().dismissed = true;
        assert_eq!(verify_on(&client), Err(Error::Cancelled));

        mock.lock().unwrap().dismissed = false;
        assert_eq!(
            verify_on(&client),
            Err(Error::Failed("authentication failed".into()))
        );
    }

    /// Stands in for `pkexec`: runs the rest of the command line after `script` (no executable
    /// file of our own: writing one races with other tests' forks, "text file busy").
    fn fake_pkexec(script: &str) -> [&str; 4] {
        ["/bin/sh", "-c", script, "pkexec"]
    }

    #[test]
    fn setup_writes_a_readable_policy() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("com.morphgate.desktop.policy");
        // Even with a strict umask, polkitd (another user) must be able to read it.
        install(&fake_pkexec("umask 077 && exec \"$@\""), &target).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), POLICY);
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);

        assert_eq!(
            install(&fake_pkexec("exit 126"), &target),
            Err(Error::Cancelled)
        );
        assert!(matches!(
            install(&fake_pkexec("exit 127"), &target),
            Err(Error::Failed(_))
        ));
        let missing = dir.path().join("pkexec");
        assert!(matches!(
            install(&[missing.to_str().unwrap()], &target),
            Err(Error::Unavailable(_))
        ));
    }

    #[test]
    fn policy_declares_the_action() {
        assert!(POLICY.contains(&format!("<action id=\"{ACTION_ID}\">")));
        assert!(POLICY.contains("<allow_active>auth_self</allow_active>"));
    }

    /// Talks to the real polkitd without ever prompting (no interaction allowed): checks that it
    /// understands our requests.
    #[test]
    #[ignore = "set MG_TEST_POLKIT=1 to query the system's polkitd"]
    fn real_polkitd_understands_us() {
        if std::env::var_os("MG_TEST_POLKIT").is_none() {
            return;
        }
        let conn = Connection::system().unwrap();
        println!("registered: {}", registered(&conn).unwrap());
        let answer = check(&conn, "org.freedesktop.policykit.exec", false).unwrap();
        // pkexec's action needs an administrator: never granted without a dialog.
        assert!(!answer.authorized && !answer.dismissed);
    }
}
