//! Compression framing on data packets. We never compress (VORACLE, and SSH is encrypted
//! anyway); we speak the framing and decompress whatever a server compresses.

use super::config::Compress;
use super::lzo;

const LZO_COMPRESS_BYTE: u8 = 0x66;
const LZ4_COMPRESS_BYTE: u8 = 0x69;
const NO_COMPRESS_BYTE: u8 = 0xFA;
const NO_COMPRESS_BYTE_SWAP: u8 = 0xFB;
const V2_INDICATOR: u8 = 0x50;
const V2_UNCOMPRESSED: u8 = 0;
const V2_LZ4: u8 = 1;
const V2_LZO: u8 = 2;

/// Largest packet a decompressor may produce.
const MAX_PACKET: usize = 65_535;

pub fn frame(c: Compress, mut packet: Vec<u8>) -> Vec<u8> {
    match c {
        Compress::None => packet,
        Compress::LzoStub | Compress::Lzo => {
            packet.insert(0, NO_COMPRESS_BYTE);
            packet
        }
        Compress::Stub | Compress::Lz4 => {
            // Swap framing: the marker replaces the first byte, which moves to the end.
            if let Some(&first) = packet.first() {
                packet.push(first);
                packet[0] = NO_COMPRESS_BYTE_SWAP;
            }
            packet
        }
        Compress::StubV2 | Compress::Lz4V2 => {
            if packet.first() == Some(&V2_INDICATOR) {
                packet.splice(0..0, [V2_INDICATOR, V2_UNCOMPRESSED]);
            }
            packet
        }
    }
}

fn lz4(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; MAX_PACKET];
    let n = lz4_flex::block::decompress_into(data, &mut out).ok()?;
    out.truncate(n);
    Some(out)
}

pub fn unframe(c: Compress, mut packet: Vec<u8>) -> Option<Vec<u8>> {
    if packet.is_empty() {
        return Some(packet);
    }
    match c {
        Compress::None => Some(packet),
        Compress::LzoStub | Compress::Lzo => match packet[0] {
            NO_COMPRESS_BYTE => {
                packet.remove(0);
                Some(packet)
            }
            LZO_COMPRESS_BYTE => lzo::decompress(&packet[1..], MAX_PACKET),
            _ => None,
        },
        Compress::Stub | Compress::Lz4 => {
            let marker = packet[0];
            let last = packet.pop()?;
            if let Some(first) = packet.first_mut() {
                *first = last;
            }
            match marker {
                NO_COMPRESS_BYTE_SWAP => Some(packet),
                LZ4_COMPRESS_BYTE => lz4(&packet),
                _ => None,
            }
        }
        Compress::StubV2 | Compress::Lz4V2 => {
            if packet[0] != V2_INDICATOR {
                return Some(packet);
            }
            match *packet.get(1)? {
                V2_UNCOMPRESSED => Some(packet.split_off(2)),
                V2_LZ4 => lz4(&packet[2..]),
                V2_LZO => lzo::decompress(&packet[2..], MAX_PACKET),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_round_trips() {
        let ip = vec![0x45, 0, 0, 20, 1, 2, 3, 4];
        for c in [
            Compress::None,
            Compress::LzoStub,
            Compress::Lzo,
            Compress::Stub,
            Compress::StubV2,
            Compress::Lz4,
            Compress::Lz4V2,
        ] {
            assert_eq!(unframe(c, frame(c, ip.clone())), Some(ip.clone()), "{c:?}");
            let escaped = vec![V2_INDICATOR, 9, 9];
            assert_eq!(
                unframe(c, frame(c, escaped.clone())),
                Some(escaped),
                "{c:?}"
            );
        }
        assert_eq!(
            frame(Compress::Stub, vec![1, 2, 3]),
            vec![NO_COMPRESS_BYTE_SWAP, 2, 3, 1]
        );
        assert_eq!(frame(Compress::StubV2, ip.clone()), ip);
    }

    #[test]
    fn decompresses_what_servers_compress() {
        let data = vec![b'x'; 1200];
        let mut lzo = vec![LZO_COMPRESS_BYTE];
        lzo.extend(lzokay_native::compress(&data).unwrap());
        assert_eq!(unframe(Compress::Lzo, lzo), Some(data.clone()));

        let block = lz4_flex::block::compress(&data);
        let mut v2 = vec![V2_INDICATOR, V2_LZ4];
        v2.extend_from_slice(&block);
        assert_eq!(unframe(Compress::Lz4V2, v2), Some(data.clone()));

        // v1 LZ4 with swap: marker first, the block's first byte moved to the end.
        let mut v1 = block.clone();
        v1.push(v1[0]);
        v1[0] = LZ4_COMPRESS_BYTE;
        assert_eq!(unframe(Compress::Lz4, v1), Some(data));

        assert_eq!(unframe(Compress::Lzo, vec![0x42, 1, 2]), None);
    }
}
