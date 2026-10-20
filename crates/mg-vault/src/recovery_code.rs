//! Human-typeable recovery code: Crockford base32 of `key(32) ‖ check(3)`, 56 symbols in groups of 4.
//!
//! `XXXX-XXXX-…-XXXX` (14 groups). Decoding ignores case, spaces and dashes, and maps the
//! look-alikes I/L → 1 and O → 0. The 24-bit check catches typos before any crypto runs.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CHECK_DOMAIN: &[u8] = b"morphgate/v1/recovery-check";
const RAW_LEN: usize = 35;
const SYMBOLS: usize = RAW_LEN * 8 / 5;
const GROUP: usize = 4;

fn check(key: &[u8; 32]) -> [u8; 3] {
    let digest = Sha256::new()
        .chain_update(CHECK_DOMAIN)
        .chain_update(key)
        .finalize();
    [digest[0], digest[1], digest[2]]
}

pub(crate) fn encode(key: &[u8; 32]) -> Zeroizing<String> {
    let mut raw = Zeroizing::new([0u8; RAW_LEN]);
    raw[..32].copy_from_slice(key);
    raw[32..].copy_from_slice(&check(key));

    let mut out = Zeroizing::new(String::with_capacity(SYMBOLS + SYMBOLS / GROUP));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &byte in raw.iter() {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            if !out.is_empty() && (out.len() + 1).is_multiple_of(GROUP + 1) {
                out.push('-');
            }
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
    }
    out
}

pub(crate) fn decode(code: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut raw = Zeroizing::new([0u8; RAW_LEN]);
    let (mut acc, mut bits, mut n, mut symbols) = (0u32, 0u32, 0usize, 0usize);
    for c in code.chars() {
        let value = match c.to_ascii_uppercase() {
            '-' | ' ' | '\t' | '\n' | '\r' => continue,
            'I' | 'L' => 1,
            'O' => 0,
            u => ALPHABET
                .iter()
                .position(|&a| char::from(a) == u)
                .ok_or(Error::Malformed("invalid character in recovery code"))?
                as u32,
        };
        symbols += 1;
        if symbols > SYMBOLS {
            return Err(Error::Malformed("recovery code is too long"));
        }
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            raw[n] = (acc >> bits) as u8;
            n += 1;
        }
    }
    if symbols != SYMBOLS {
        return Err(Error::Malformed("recovery code is too short"));
    }
    let key: [u8; 32] = raw[..32].try_into().expect("fixed length");
    let key = Zeroizing::new(key);
    if raw[32..] != check(&key) {
        return Err(Error::Malformed(
            "recovery code has a typo (checksum mismatch)",
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_shape() {
        let key = [0xA5u8; 32];
        let code = encode(&key);
        assert_eq!(code.len(), SYMBOLS + SYMBOLS / GROUP - 1);
        assert_eq!(code.split('-').count(), SYMBOLS / GROUP);
        assert!(code.split('-').all(|g| g.len() == GROUP));
        assert_eq!(*decode(&code).unwrap(), key);
    }

    #[test]
    fn decoding_is_forgiving_about_formatting() {
        let key = [7u8; 32];
        let code = encode(&key)
            .to_lowercase()
            .replace('-', " ")
            .replace('1', "l")
            .replace('0', "o");
        assert_eq!(*decode(&code).unwrap(), key);
    }

    #[test]
    fn typos_are_caught() {
        let code = encode(&[3u8; 32]);
        let mut chars: Vec<char> = code.chars().collect();
        chars[5] = if chars[5] == 'Z' { 'Y' } else { 'Z' };
        let typo: String = chars.into_iter().collect();
        assert!(matches!(decode(&typo), Err(Error::Malformed(_))));
        assert!(matches!(
            decode(&code[..code.len() - 1]),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            decode(&format!("{}X", *code)),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(decode("UUUU"), Err(Error::Malformed(_))));
    }
}
