//! LZO1X decompression (what `comp-lzo` servers send), bounds-checked on every step.
//! Follows the classic `lzo1x_decompress_safe` state machine.

/// Decompresses `input`, refusing to produce more than `max` bytes.
pub fn decompress(input: &[u8], max: usize) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 3);
    let mut ip = 0usize;
    let byte = |ip: &mut usize| -> Option<usize> {
        let b = *input.get(*ip)?;
        *ip += 1;
        Some(usize::from(b))
    };
    let le16 = |ip: &mut usize| -> Option<usize> {
        let lo = *input.get(*ip)?;
        let hi = *input.get(*ip + 1)?;
        *ip += 2;
        Some(usize::from(lo) | usize::from(hi) << 8)
    };
    // A run of zero bytes extends a length by 255 each, then a final non-zero byte.
    let extend = |ip: &mut usize, base: usize| -> Option<usize> {
        let mut t = 0usize;
        while *input.get(*ip)? == 0 {
            *ip += 1;
            t = t.checked_add(255)?;
            if t > max {
                return None;
            }
        }
        Some(t + base + byte(ip)?)
    };
    let literals = |out: &mut Vec<u8>, ip: &mut usize, n: usize| -> Option<()> {
        let src = input.get(*ip..*ip + n)?;
        if out.len() + n > max {
            return None;
        }
        out.extend_from_slice(src);
        *ip += n;
        Some(())
    };
    // Back-references may overlap the bytes being written: copy one at a time.
    let copy_match = |out: &mut Vec<u8>, dist: usize, n: usize| -> Option<()> {
        if dist == 0 || dist > out.len() || out.len() + n > max {
            return None;
        }
        let start = out.len() - dist;
        for i in 0..n {
            let b = out[start + i];
            out.push(b);
        }
        Some(())
    };

    if input.len() < 3 {
        return None;
    }
    // `state` = literals copied after the previous match (0..3), or 4 after a literal run.
    let mut state;
    let first = usize::from(input[0]);
    if first > 17 {
        ip = 1;
        let t = first - 17;
        literals(&mut out, &mut ip, t)?;
        state = if t < 4 { t } else { 4 };
    } else {
        state = 0;
    }

    loop {
        let t = byte(&mut ip)?;
        let (dist, len, next);
        if t < 16 {
            if state == 0 {
                let n = if t == 0 { extend(&mut ip, 15)? } else { t } + 3;
                literals(&mut out, &mut ip, n)?;
                state = 4;
                continue;
            } else if state != 4 {
                next = t & 3;
                dist = 1 + (t >> 2) + (byte(&mut ip)? << 2);
                len = 2;
            } else {
                next = t & 3;
                dist = 1 + 0x0800 + (t >> 2) + (byte(&mut ip)? << 2);
                len = 3;
            }
        } else if t >= 64 {
            next = t & 3;
            dist = 1 + ((t >> 2) & 7) + (byte(&mut ip)? << 3);
            len = (t >> 5) + 1;
        } else if t >= 32 {
            let mut n = (t & 31) + 2;
            if n == 2 {
                n = extend(&mut ip, 31)? + 2;
            }
            let v = le16(&mut ip)?;
            next = v & 3;
            dist = 1 + (v >> 2);
            len = n;
        } else {
            let mut n = (t & 7) + 2;
            if n == 2 {
                n = extend(&mut ip, 7)? + 2;
            }
            let v = le16(&mut ip)?;
            next = v & 3;
            let d = ((t & 8) << 11) + (v >> 2);
            if d == 0 {
                // End-of-stream marker.
                return (n == 3 && ip == input.len()).then_some(out);
            }
            dist = d + 0x4000;
            len = n;
        }
        copy_match(&mut out, dist, len)?;
        literals(&mut out, &mut ip, next)?;
        state = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(data: &[u8]) {
        let packed = lzokay_native::compress(data).unwrap();
        let back = decompress(&packed, data.len()).expect("decompress");
        assert_eq!(back, data, "round trip of {} bytes", data.len());
    }

    #[test]
    fn round_trips_against_an_independent_compressor() {
        check(b"hello hello hello hello hello hello hello");
        check(&[0u8; 5000]);
        check(&(0..20_000u32).map(|i| (i % 7) as u8).collect::<Vec<_>>());
        check(
            b"SSH-2.0-OpenSSH_9.6\r\n\x00\x00\x05\xdc\x0a\x14curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512",
        );
        let mut x = 0x1234_5678u32;
        let noise: Vec<u8> = (0..3000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        check(&noise);
        let mut mixed = noise.clone();
        mixed.extend_from_slice(&[b'a'; 70_000]);
        mixed.extend_from_slice(&noise[..100]);
        check(&mixed);
    }

    #[test]
    fn refuses_garbage_and_overflow() {
        let packed = lzokay_native::compress(&[7u8; 4000]).unwrap();
        assert!(decompress(&packed, 100).is_none(), "output cap");
        assert!(
            decompress(&packed[..packed.len() - 2], 4000).is_none(),
            "truncated"
        );
        // Nothing but the end-of-stream marker: empty output.
        assert_eq!(decompress(&[0x11, 0, 0], 10), Some(vec![]));
        for seed in 0..200u8 {
            let junk: Vec<u8> = (0..64)
                .map(|i| seed.wrapping_mul(31).wrapping_add(i))
                .collect();
            let _ = decompress(&junk, 1 << 16);
        }
    }
}
