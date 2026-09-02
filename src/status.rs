//! Reading a `:status`, which HTTP/2 and HTTP/3 encode the same way
//!
//! QPACK reuses HPACK's Huffman code (RFC 9204 Section 5) and a status is
//! always three digits, so both header encodings read one identically. It sits
//! here rather than in each of them.

use anyhow::{Result, bail};

/// Decode a three-digit status value
///
/// Only the ten digit symbols can appear here, and all of them are 5 to 7 bits
/// long, so the Huffman case needs a handful of codes rather than the whole
/// 256-entry table (RFC 7541 Appendix B).
pub fn status_value(s: &[u8], huffman: bool) -> Result<u16> {
    if !huffman {
        if s.len() != 3 || !s.iter().all(|c| c.is_ascii_digit()) {
            bail!("malformed :status");
        }
        return Ok((s[0] - b'0') as u16 * 100 + (s[1] - b'0') as u16 * 10 + (s[2] - b'0') as u16);
    }
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut digits = [0u8; 3];
    let mut n = 0;
    for &byte in s {
        bits = (bits << 8) | byte as u32;
        nbits += 8;
        // Decode while the accumulated bits are enough to identify a symbol.
        // Stopping early is normal: the tail is the all-ones padding, which
        // matches no digit.
        while n < 3 {
            let Some((digit, used)) = huffman_digit(bits, nbits) else {
                break;
            };
            digits[n] = digit;
            n += 1;
            nbits -= used;
            bits &= (1u32 << nbits) - 1;
        }
    }
    if n != 3 {
        bail!("malformed :status");
    }
    Ok(
        (digits[0] - b'0') as u16 * 100
            + (digits[1] - b'0') as u16 * 10
            + (digits[2] - b'0') as u16,
    )
}

/// Match the next Huffman code against the ten digit symbols
///
/// Returns None when the accumulated bits do not (yet) spell a digit, which
/// means either more input is needed or the padding has been reached.
fn huffman_digit(bits: u32, nbits: u32) -> Option<(u8, u32)> {
    if nbits >= 5 {
        // '0' 00000, '1' 00001, '2' 00010
        let top5 = (bits >> (nbits - 5)) & 0x1f;
        if top5 <= 0b00010 {
            return Some((b'0' + top5 as u8, 5));
        }
    }
    if nbits >= 6 {
        // '3' through '9' are 011001 through 011111
        let top6 = (bits >> (nbits - 6)) & 0x3f;
        if (0b011001..=0b011111).contains(&top6) {
            return Some((b'3' + (top6 - 0b011001) as u8, 6));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_status_is_three_digits() {
        assert_eq!(status_value(b"200", false).unwrap(), 200);
        assert_eq!(status_value(b"503", false).unwrap(), 503);
        assert!(status_value(b"20", false).is_err(), "too short");
        assert!(status_value(b"2x0", false).is_err(), "not a digit");
    }

    /// The table is two runs, and the boundary between them is where a wrong
    /// entry would hide (RFC 7541 Appendix B)
    #[test]
    fn the_digit_codes_are_five_bits_then_six() {
        for (digit, code, len) in [
            (b'0', 0b00000, 5),
            (b'1', 0b00001, 5),
            (b'2', 0b00010, 5),
            (b'3', 0b011001, 6),
            (b'9', 0b011111, 6),
        ] {
            assert_eq!(huffman_digit(code, len), Some((digit, len)), "'{digit}'");
        }
        assert_eq!(huffman_digit(0b00011, 5), None, "not a digit");
    }
}
