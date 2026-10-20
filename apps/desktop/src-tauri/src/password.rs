//! The master password's strength: at least 10 characters, and not easy to guess the way cracking
//! tools guess (zxcvbn's estimate: at least 10^10 guesses).
//!
//! It's stretched with Argon2id (256 MiB, 3 passes) before anything leaves the device, so every
//! guess costs an attacker that much memory-hard work, and 10^10 guesses is months for a rig of
//! GPUs. What's refused is what people predictably choose ("Summer2024!", "P@ssw0rd1"), not
//! passwords missing a kind of character: rules like "one digit, one symbol" produce exactly
//! those choices (NIST SP 800-63B). Passwords set before this keep working; it applies when one
//! is set.

use serde::Serialize;

/// The store's floor (mg-store refuses shorter too).
pub const MIN_CHARS: usize = mg_store::MIN_PASSWORD_CHARS;
/// zxcvbn's estimate of the guesses it takes, as a power of ten.
pub const MIN_GUESSES_LOG10: f64 = 10.0;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    /// Long enough and hard enough to guess.
    ok: bool,
    /// zxcvbn's estimate of the guesses it takes, as a power of ten.
    guesses_log10: f64,
    /// Why it's guessable ("This is similar to a commonly used password.").
    warning: Option<String>,
    /// What would make it stronger.
    suggestions: Vec<String>,
}

pub(crate) fn strength(password: &str) -> Strength {
    let estimate = zxcvbn::zxcvbn(password, &[]);
    let feedback = estimate.feedback();
    let guesses_log10 = estimate.guesses_log10();
    Strength {
        ok: password.chars().count() >= MIN_CHARS && guesses_log10 >= MIN_GUESSES_LOG10,
        guesses_log10,
        warning: feedback.and_then(|f| f.warning()).map(|w| w.to_string()),
        suggestions: feedback
            .map(|f| f.suggestions().iter().map(|s| s.to_string()).collect())
            .unwrap_or_default(),
    }
}

/// Refuses a master password that's too short or too easy to guess, saying why.
pub(crate) fn check(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_CHARS {
        return Err(format!(
            "the master password needs at least {MIN_CHARS} characters"
        ));
    }
    let s = strength(password);
    if s.ok {
        return Ok(());
    }
    let why = s
        .warning
        .unwrap_or_else(|| "it follows a pattern cracking tools try early".into());
    Err(format!(
        "that master password is too easy to guess: {why} A few unrelated words make a strong one."
    ))
}

/// How strong a master password would be, for the form to show while it's typed.
#[tauri::command]
pub fn password_strength(password: String) -> Strength {
    strength(&password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predictable_ones_are_refused_and_passphrases_pass() {
        for weak in ["P@ssw0rd123", "Summer2024!", "qwertyuiop12", "morphgate!"] {
            assert!(check(weak).is_err(), "{weak} passed");
        }
        assert!(
            check("short")
                .unwrap_err()
                .contains("at least 10 characters")
        );
        for strong in [
            "correct horse battery staple",
            "purple tiger jumps fence",
            "kT9#mQ2vLx",
            "MyDogRex2019!",
        ] {
            assert!(check(strong).is_ok(), "{strong} was refused");
        }
        let s = strength("P@ssw0rd123");
        assert!(!s.ok && s.warning.is_some());
    }
}
