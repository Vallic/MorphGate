//! Key method 2: the messages client and server exchange inside TLS, and how both derive the
//! data channel keys from them (RFC 5705 exporter, or OpenVPN's TLS 1.0 PRF on old servers).

use hmac::{Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

use super::wire::SessionId;

const KEY_METHOD_2: u8 = 2;
pub const EKM_LABEL: &[u8] = b"EXPORTER-OpenVPN-datakeys";

pub type KeyMaterial = Zeroizing<[u8; 256]>;

/// The random material the client contributes.
pub struct ClientRandom {
    pub pre_master: Zeroizing<[u8; 48]>,
    pub random1: [u8; 32],
    pub random2: [u8; 32],
}

impl ClientRandom {
    pub fn generate() -> Self {
        let mut s = Self {
            pre_master: Zeroizing::new([0; 48]),
            random1: [0; 32],
            random2: [0; 32],
        };
        getrandom::fill(&mut *s.pre_master).expect("system RNG");
        getrandom::fill(&mut s.random1).expect("system RNG");
        getrandom::fill(&mut s.random2).expect("system RNG");
        s
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerRandom {
    pub random1: [u8; 32],
    pub random2: [u8; 32],
}

fn write_string(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        // Length includes the trailing NUL.
        Some(s) => {
            out.extend_from_slice(&((s.len() + 1) as u16).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
            out.push(0);
        }
        None => out.extend_from_slice(&0u16.to_be_bytes()),
    }
}

/// The client's key method 2 message.
pub fn client_message(
    random: &ClientRandom,
    options: &str,
    credentials: Option<(&str, &str)>,
    peer_info: &str,
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(512));
    out.extend_from_slice(&0u32.to_be_bytes());
    out.push(KEY_METHOD_2);
    out.extend_from_slice(&*random.pre_master);
    out.extend_from_slice(&random.random1);
    out.extend_from_slice(&random.random2);
    write_string(&mut out, Some(options));
    write_string(&mut out, credentials.map(|c| c.0));
    write_string(&mut out, credentials.map(|c| c.1));
    write_string(&mut out, Some(peer_info));
    out
}

/// Parses the server's key method 2 message at the start of `buf`. Returns the server randoms
/// and how many bytes the message took, or `None` if it isn't complete yet.
pub fn parse_server_message(buf: &[u8]) -> Option<Result<(ServerRandom, usize), &'static str>> {
    if buf.len() < 4 + 1 + 64 + 2 {
        return None;
    }
    if buf[..4] != [0, 0, 0, 0] || buf[4] & 0x0f != KEY_METHOD_2 {
        return Some(Err("the server sent an unexpected key exchange message"));
    }
    let random1 = buf[5..37].try_into().expect("32 bytes");
    let random2 = buf[37..69].try_into().expect("32 bytes");
    let mut pos = 69;
    // Options string, then (optionally) username, password and peer info. Each is a u16 length
    // that includes a trailing NUL; anything that doesn't look like one is the next message.
    let read = |pos: usize| -> Option<usize> {
        let len = usize::from(u16::from_be_bytes(buf.get(pos..pos + 2)?.try_into().ok()?));
        if len == 0 {
            return Some(pos + 2);
        }
        let s = buf.get(pos + 2..pos + 2 + len)?;
        (s[len - 1] == 0).then_some(pos + 2 + len)
    };
    pos = read(pos)?;
    for _ in 0..3 {
        match read(pos) {
            Some(p) => pos = p,
            None => break,
        }
    }
    Some(Ok((ServerRandom { random1, random2 }, pos)))
}

type HmacMd5 = Hmac<md5::Md5>;
type HmacSha1 = Hmac<sha1::Sha1>;

/// TLS 1.0 P_hash.
fn p_hash<M: Mac + KeyInit + Clone>(secret: &[u8], seed: &[u8], out: &mut [u8]) {
    let mac = <M as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    let mut a = {
        let mut m = mac.clone();
        m.update(seed);
        m.finalize().into_bytes().to_vec()
    };
    let mut pos = 0;
    while pos < out.len() {
        let mut m = mac.clone();
        m.update(&a);
        m.update(seed);
        let block = m.finalize().into_bytes();
        let n = block.len().min(out.len() - pos);
        out[pos..pos + n].copy_from_slice(&block[..n]);
        pos += n;
        let mut m = mac.clone();
        m.update(&a);
        a = m.finalize().into_bytes().to_vec();
    }
}

/// The TLS 1.0 PRF: P_MD5 over the first half of the secret XOR P_SHA1 over the second.
fn tls1_prf(secret: &[u8], seed: &[u8], out: &mut [u8]) {
    let half = secret.len() / 2;
    let len = half + (secret.len() & 1);
    let s1 = &secret[..len];
    let s2 = &secret[half..half + len];
    p_hash::<HmacMd5>(s1, seed, out);
    let mut other = Zeroizing::new(vec![0u8; out.len()]);
    p_hash::<HmacSha1>(s2, seed, &mut other);
    for (o, x) in out.iter_mut().zip(other.iter()) {
        *o ^= x;
    }
}

/// OpenVPN's own key expansion, for servers that don't do tls-ekm.
pub fn prf_material(
    client: &ClientRandom,
    server: &ServerRandom,
    client_sid: &SessionId,
    server_sid: &SessionId,
) -> KeyMaterial {
    let mut master = Zeroizing::new([0u8; 48]);
    let mut seed = Vec::with_capacity(128);
    seed.extend_from_slice(b"OpenVPN master secret");
    seed.extend_from_slice(&client.random1);
    seed.extend_from_slice(&server.random1);
    tls1_prf(&*client.pre_master, &seed, &mut *master);

    let mut seed = Vec::with_capacity(128);
    seed.extend_from_slice(b"OpenVPN key expansion");
    seed.extend_from_slice(&client.random2);
    seed.extend_from_slice(&server.random2);
    seed.extend_from_slice(client_sid);
    seed.extend_from_slice(server_sid);
    let mut out = Zeroizing::new([0u8; 256]);
    tls1_prf(&*master, &seed, &mut *out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 2246-era PRF test vector (TLS 1.0, 48-byte secret of 0xab, label + seed of 0xcd),
    /// as used by many TLS test suites.
    #[test]
    fn tls1_prf_known_answer() {
        let secret = [0xabu8; 48];
        let mut seed = b"PRF Testvector".to_vec();
        seed.extend_from_slice(&[0xcd; 64]);
        let mut out = [0u8; 104];
        tls1_prf(&secret, &seed, &mut out);
        let expected = "d3d4d1e349b5d515044666d51de32bab258cb521b6b053463e354832fd976754443bcf9a296519bc289abcbc1187e4ebd31e602353776c408aafb74cbc85eff69255f9788faa184cbb957a9819d84a5d7eb006eb459d3ae8de9810454b8b2d8f1afbc655a8c9a013";
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
    }

    #[test]
    fn server_message_parsing() {
        let mut msg = vec![0, 0, 0, 0, 2];
        msg.extend_from_slice(&[1; 32]);
        msg.extend_from_slice(&[2; 32]);
        write_string(&mut msg, Some("V4,dev-type tun"));
        assert!(parse_server_message(&msg[..20]).is_none(), "incomplete");
        write_string(&mut msg, None);
        write_string(&mut msg, None);
        let len = msg.len();
        msg.extend_from_slice(b"PUSH_REPLY,ping 10\0");
        let (r, used) = parse_server_message(&msg).unwrap().unwrap();
        assert_eq!(r.random1, [1; 32]);
        assert_eq!(used, len, "stops before the next message");

        let c = ClientRandom::generate();
        let m = client_message(&c, "V4", Some(("alice", "pw")), "IV_VER=2.6.0\n");
        assert_eq!(m[4], 2);
        assert!(m.windows(6).any(|w| w == b"alice\0"));
    }
}
