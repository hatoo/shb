//! QUIC variable-length integers (RFC 9000 Section 16)
//!
//! The two leading bits give the width, so the same encoding covers a stream
//! ID, a frame type and a packet length. HTTP/3 and QPACK reuse it, which is
//! why it lives here rather than beside either of them.

/// Append a variable-length integer
#[inline]
pub fn put_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=0x3f => out.push(value as u8),
        0x40..=0x3fff => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => {
            out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        _ => out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// Read a variable-length integer, returning it and its length
///
/// None means `buf` does not hold the whole integer yet.
pub fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for &byte in &buf[1..len] {
        value = (value << 8) | byte as u64;
    }
    Some((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(value: u64) -> Vec<u8> {
        let mut v = Vec::new();
        put_varint(&mut v, value);
        v
    }

    #[test]
    fn varints_round_trip_at_every_width() {
        for value in [
            0u64,
            1,
            63,
            64,
            16383,
            16384,
            1 << 29,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let encoded = varint(value);
            assert_eq!(
                get_varint(&encoded),
                Some((value, encoded.len())),
                "{value}"
            );
        }
    }

    #[test]
    fn varints_match_the_spec() {
        let cases: [(&[u8], u64); 5] = [
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
            // The spec's example of 37 in the two-byte form; a decoder has to
            // accept a non-minimal encoding
            (&[0x40, 0x25], 37),
        ];
        for (bytes, value) in cases {
            assert_eq!(
                get_varint(bytes),
                Some((value, bytes.len())),
                "{bytes:02x?}"
            );
        }
        // Our encoder always picks the shortest form
        for (bytes, value) in cases.iter().take(4) {
            assert_eq!(&varint(*value), bytes, "encoding {value}");
        }
    }

    #[test]
    fn a_truncated_varint_is_incomplete() {
        let encoded = varint(16384);
        assert_eq!(get_varint(&encoded[..2]), None);
    }
}
