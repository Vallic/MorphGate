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

/// EFF's long wordlist (`wordlist/README.md`): dice numbers, a tab, a word.
const WORDLIST: &str = include_str!("../wordlist/eff_large_wordlist.txt");
/// Words in a suggestion: about 64 bits from the 7772 used.
const SUGGESTED_WORDS: usize = 5;

/// The list's words, but for the four with a hyphen (the separator).
fn words() -> Vec<&'static str> {
    WORDLIST
        .lines()
        .filter_map(|l| l.split_once('\t').map(|(_, w)| w.trim()))
        .filter(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase()))
        .collect()
}

/// A number below `n`, every one as likely (no modulo bias).
fn below(n: u32) -> Result<u32, String> {
    let zone = u32::MAX - u32::MAX % n;
    loop {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).map_err(|e| format!("no randomness from the system: {e}"))?;
        let x = u32::from_le_bytes(b);
        if x < zone {
            return Ok(x % n);
        }
    }
}

/// Five words at random, joined by hyphens: easy to write down and type, hard to guess. Ones the
/// strength check would refuse (rarely: a run of very common words) are drawn again.
pub(crate) fn suggest() -> Result<String, String> {
    let list = words();
    let n = u32::try_from(list.len()).map_err(|_| "the wordlist is too long")?;
    for _ in 0..16 {
        let mut picked = Vec::with_capacity(SUGGESTED_WORDS);
        for _ in 0..SUGGESTED_WORDS {
            picked.push(list[below(n)? as usize]);
        }
        let password = picked.join("-");
        if strength(&password).ok {
            return Ok(password);
        }
    }
    Err("couldn't come up with a strong password; type one instead".into())
}

/// A master password to suggest.
#[tauri::command]
pub fn password_suggest() -> Result<String, String> {
    suggest()
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

    #[test]
    fn suggestions_are_five_listed_words_that_pass() {
        let list = words();
        assert_eq!(
            list.len(),
            7776 - 4,
            "the list as published, but for the hyphenated four"
        );
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            let p = suggest().unwrap();
            let parts: Vec<&str> = p.split('-').collect();
            assert_eq!(parts.len(), SUGGESTED_WORDS, "{p}");
            assert!(parts.iter().all(|w| list.contains(w)), "{p}");
            assert!(check(&p).is_ok(), "{p}");
            seen.insert(p);
        }
        assert_eq!(seen.len(), 50, "suggestions repeat");
    }
}
