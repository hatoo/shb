//! QPACK, cut down to what a load generator needs
//!
//! The same trade as the HTTP/2 side. Requests are encoded once at start-up
//! ([`encode_request`]) using static-table references only, so the encoder
//! never inserts and the bytes stay valid for every stream on every
//! connection. The client advertises `QPACK_MAX_TABLE_CAPACITY = 0`, which
//! forbids the peer from inserting either, so decoding needs no dynamic table
//! and never blocks on one.
//!
//! [`find_status`] then walks a field section measuring each field and
//! stepping over it. That matters more here than in HPACK: a profile of a
//! saturated HTTP/3 worker spent 47% of its time Huffman-decoding response
//! header values that a benchmark client never looks at.

use anyhow::{Result, bail};

/// Static entries whose name is `:status`, as (index, code)
const STATUS_ENTRIES: [(u64, u16); 14] = [
    (24, 103),
    (25, 200),
    (26, 304),
    (27, 404),
    (28, 503),
    (61, 100),
    (62, 204),
    (63, 206),
    (64, 302),
    (65, 400),
    (66, 403),
    (67, 421),
    (68, 425),
    (69, 500),
];

/// Static index of `:authority` (name only)
const IDX_AUTHORITY: u64 = 0;
/// Static index of `:path: /`
const IDX_PATH_ROOT: u64 = 1;
/// Static index of `content-length` (name only)
const IDX_CONTENT_LENGTH: u64 = 4;

/// Static index of `:method: <m>` when there is one
fn method_index(method: &str) -> Option<u64> {
    Some(match method {
        "CONNECT" => 15,
        "DELETE" => 16,
        "GET" => 17,
        "HEAD" => 18,
        "OPTIONS" => 19,
        "POST" => 20,
        "PUT" => 21,
        _ => return None,
    })
}

/// Static index of `:scheme: <s>` when there is one
fn scheme_index(scheme: &str) -> Option<u64> {
    Some(match scheme {
        "http" => 22,
        "https" => 23,
        _ => return None,
    })
}

/// Append a prefixed integer (RFC 9204 Section 4.1.1, same as HPACK)
fn encode_int(out: &mut Vec<u8>, prefix_bits: u8, mask: u8, value: u64) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(mask | value as u8);
        return;
    }
    out.push(mask | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest % 128 + 128) as u8);
        rest /= 128;
    }
    out.push(rest as u8);
}

/// Append an uncompressed string literal with a `prefix_bits`-wide length
fn encode_str(out: &mut Vec<u8>, prefix_bits: u8, mask: u8, s: &[u8]) {
    // The Huffman bit sits just above the length field and stays clear
    encode_int(out, prefix_bits, mask, s.len() as u64);
    out.extend_from_slice(s);
}

/// Indexed field line, static table (`1` `T=1` + 6-bit index)
fn indexed(out: &mut Vec<u8>, index: u64) {
    encode_int(out, 6, 0xc0, index);
}

/// Literal field line with a static name reference (`01` `N=0` `T=1` + 4-bit index)
fn literal_named(out: &mut Vec<u8>, name_index: u64, value: &[u8]) {
    encode_int(out, 4, 0x50, name_index);
    encode_str(out, 7, 0x00, value);
}

/// Literal field line with a literal name (`001` `N=0` + 3-bit name length)
fn literal(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    encode_str(out, 3, 0x20, name);
    encode_str(out, 7, 0x00, value);
}

/// Build the field section sent for every request
///
/// Header names must already be lower-cased.
pub fn encode_request(
    method: &str,
    scheme: &str,
    authority: &str,
    path: &str,
    headers: &[(String, String)],
    body_len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + headers.len() * 32);
    // Field section prefix: Required Insert Count 0, Delta Base 0. Nothing in
    // the section references the dynamic table, so both stay zero.
    out.push(0x00);
    out.push(0x00);

    match method_index(method) {
        Some(index) => indexed(&mut out, index),
        None => literal(&mut out, b":method", method.as_bytes()),
    }
    match scheme_index(scheme) {
        Some(index) => indexed(&mut out, index),
        None => literal(&mut out, b":scheme", scheme.as_bytes()),
    }
    literal_named(&mut out, IDX_AUTHORITY, authority.as_bytes());
    if path == "/" {
        indexed(&mut out, IDX_PATH_ROOT);
    } else {
        literal(&mut out, b":path", path.as_bytes());
    }
    for (name, value) in headers {
        literal(&mut out, name.as_bytes(), value.as_bytes());
    }
    if body_len > 0 {
        literal_named(
            &mut out,
            IDX_CONTENT_LENGTH,
            body_len.to_string().as_bytes(),
        );
    }
    out
}

fn short() -> anyhow::Error {
    anyhow::anyhow!("truncated QPACK field section")
}

/// Read a prefixed integer, advancing `pos`
fn decode_int(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> Result<u64> {
    let max = (1u64 << prefix_bits) - 1;
    let first = *buf.get(*pos).ok_or_else(short)? as u64 & max;
    *pos += 1;
    if first < max {
        return Ok(first);
    }
    let mut value = max;
    let mut shift = 0;
    loop {
        let byte = *buf.get(*pos).ok_or_else(short)?;
        *pos += 1;
        value = value
            .checked_add(((byte & 0x7f) as u64) << shift)
            .ok_or_else(|| anyhow::anyhow!("QPACK integer overflow"))?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 56 {
            bail!("QPACK integer too long");
        }
    }
}

/// Step over a string literal, returning its bytes and whether they are
/// Huffman-coded
fn read_str<'a>(buf: &'a [u8], pos: &mut usize, prefix_bits: u8) -> Result<(&'a [u8], bool)> {
    let huffman = *buf.get(*pos).ok_or_else(short)? & (1 << prefix_bits) != 0;
    let len = decode_int(buf, pos, prefix_bits)? as usize;
    let end = pos.checked_add(len).ok_or_else(short)?;
    let s = buf.get(*pos..end).ok_or_else(short)?;
    *pos = end;
    Ok((s, huffman))
}

/// Decode a three-digit status value
///
/// Only digits can appear, and their Huffman codes are 5 to 7 bits, so this
/// needs ten codes rather than the whole 256-entry table (RFC 7541 Appendix B,
/// which QPACK reuses).
fn status_value(s: &[u8], huffman: bool) -> Result<u16> {
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

fn status_for_index(index: u64) -> Option<u16> {
    STATUS_ENTRIES
        .iter()
        .find(|(i, _)| *i == index)
        .map(|(_, code)| *code)
}

fn is_status_index(index: u64) -> bool {
    STATUS_ENTRIES.iter().any(|(i, _)| *i == index)
}

/// Find `:status` in a response field section
///
/// Every other field is measured and stepped over; none of their names or
/// values are decoded, which is what keeps Huffman decoding off the hot path.
pub fn find_status(section: &[u8]) -> Result<u16> {
    let mut pos = 0;
    // Field section prefix. The peer was told not to insert, so the required
    // insert count must be zero and the base cannot be anything else.
    let required_insert_count = decode_int(section, &mut pos, 8)?;
    if required_insert_count != 0 {
        bail!("QPACK dynamic table reference");
    }
    let _delta_base = decode_int(section, &mut pos, 7)?;

    while pos < section.len() {
        let first = section[pos];
        if first & 0x80 != 0 {
            // Indexed field line; T selects static (1) or dynamic (0)
            let static_table = first & 0x40 != 0;
            let index = decode_int(section, &mut pos, 6)?;
            if !static_table {
                bail!("QPACK dynamic table reference");
            }
            if let Some(status) = status_for_index(index) {
                return Ok(status);
            }
        } else if first & 0x40 != 0 {
            // Literal field line with a name reference
            let static_table = first & 0x10 != 0;
            let index = decode_int(section, &mut pos, 4)?;
            if !static_table {
                bail!("QPACK dynamic table reference");
            }
            let named_status = is_status_index(index);
            let (value, huffman) = read_str(section, &mut pos, 7)?;
            if named_status {
                return status_value(value, huffman);
            }
        } else if first & 0x20 != 0 {
            // Literal field line with a literal name
            let (name, name_huffman) = read_str(section, &mut pos, 3)?;
            let named_status = !name_huffman && name == b":status";
            let (value, huffman) = read_str(section, &mut pos, 7)?;
            if named_status {
                return status_value(value, huffman);
            }
        } else {
            // Indexed field line with post-base index: dynamic table only
            bail!("QPACK dynamic table reference");
        }
    }
    bail!("response without :status")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(body: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, 0x00];
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn integers_round_trip_across_the_prefix_boundary() {
        for value in [0u64, 1, 6, 7, 8, 15, 16, 63, 64, 127, 128, 1337, 1 << 40] {
            for bits in [3u8, 4, 5, 6, 7, 8] {
                let mut out = Vec::new();
                encode_int(&mut out, bits, 0, value);
                let mut pos = 0;
                assert_eq!(decode_int(&out, &mut pos, bits).unwrap(), value);
                assert_eq!(pos, out.len(), "value {value} bits {bits}");
            }
        }
    }

    #[test]
    fn get_request_uses_static_entries() {
        let block = encode_request("GET", "https", "example.com", "/", &[], 0);
        assert_eq!(&block[..2], &[0x00, 0x00], "prefix references nothing");
        assert_eq!(block[2], 0xc0 | 17, ":method GET");
        assert_eq!(block[3], 0xc0 | 23, ":scheme https");
        assert_eq!(*block.last().unwrap(), 0xc0 | 1, ":path /");
    }

    /// The field-line representations from RFC 9204 Section 4.5, asserted as
    /// bytes. Without this the encoders are only ever checked against this
    /// file's own decoder, which is how the Huffman table stayed wrong.
    #[test]
    fn representations_match_the_spec() {
        // 4.5.2 indexed field line: 1, T=1 for the static table, 6-bit index
        let mut out = Vec::new();
        indexed(&mut out, 17);
        assert_eq!(out, [0b1100_0000 | 17]);
        // an index that does not fit the prefix continues into another octet
        let mut out = Vec::new();
        indexed(&mut out, 69);
        assert_eq!(out, [0b1111_1111, 69 - 63]);

        // 4.5.4 literal with a name reference: 01, N=0, T=1, 4-bit index
        let mut out = Vec::new();
        literal_named(&mut out, 4, b"12");
        assert_eq!(out, [0b0101_0100, 0b0000_0010, b'1', b'2']);

        // 4.5.6 literal with a literal name: 001, N=0, H=0, 3-bit name length
        let mut out = Vec::new();
        literal(&mut out, b"ab", b"c");
        assert_eq!(out, [0b0010_0010, b'a', b'b', 0b0000_0001, b'c']);

        // 4.5.1 field section prefix: both parts zero, since nothing here
        // references the dynamic table
        let block = encode_request("GET", "https", "h", "/", &[], 0);
        assert_eq!(&block[..2], &[0x00, 0x00]);
    }

    #[test]
    fn indexed_status_is_read() {
        assert_eq!(find_status(&section(&[0xc0 | 25])).unwrap(), 200);
        assert_eq!(find_status(&section(&[0xc0 | 27])).unwrap(), 404);
        // Indices above the 6-bit prefix take the continuation form
        let mut body = Vec::new();
        indexed(&mut body, 69);
        assert_eq!(find_status(&section(&body)).unwrap(), 500);
    }

    #[test]
    fn literal_status_with_a_name_reference_is_read() {
        let mut body = Vec::new();
        literal_named(&mut body, 25, b"201");
        assert_eq!(find_status(&section(&body)).unwrap(), 201);
    }

    #[test]
    fn literal_status_with_a_literal_name_is_read() {
        let mut body = Vec::new();
        literal(&mut body, b":status", b"418");
        assert_eq!(find_status(&section(&body)).unwrap(), 418);
    }

    #[test]
    fn huffman_status_is_read() {
        for status in [200u16, 201, 304, 429, 500, 599, 789] {
            let text = status.to_string();
            let encoded = huffman_encode_digits(&text);
            let mut body = Vec::new();
            // Literal with name reference 25 (:status), Huffman value
            encode_int(&mut body, 4, 0x50, 25);
            encode_int(&mut body, 7, 0x80, encoded.len() as u64);
            body.extend_from_slice(&encoded);
            assert_eq!(find_status(&section(&body)).unwrap(), status, "{status}");
        }
    }

    fn huffman_encode_digits(s: &str) -> Vec<u8> {
        let mut bits = Vec::new();
        for c in s.bytes() {
            let (code, len): (u32, u32) = match c {
                b'0' => (0b00000, 5),
                b'1' => (0b00001, 5),
                b'2' => (0b00010, 5),
                b'3'..=b'9' => (0b011001 + (c - b'3') as u32, 6),
                _ => unreachable!(),
            };
            for i in (0..len).rev() {
                bits.push((code >> i) & 1 == 1);
            }
        }
        while bits.len() % 8 != 0 {
            bits.push(true);
        }
        bits.chunks(8)
            .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | b as u8))
            .collect()
    }

    /// Byte sequences worked out by hand from RFC 7541 Appendix B, so the
    /// decoder is checked against the spec rather than against this file's own
    /// encoder. The 301 is what facebook.com actually sent.
    #[test]
    fn huffman_status_matches_the_spec() {
        for (status, huffman) in [
            (301u16, &[0x64u8, 0x01][..]),
            (200, &[0x10, 0x01]),
            (404, &[0x68, 0x0d, 0x7f]),
            (503, &[0x6c, 0x0c, 0xff]),
            (999, &[0x7d, 0xf7, 0xff]),
        ] {
            // Literal field line, static name reference 25 (:status)
            let mut body = Vec::new();
            encode_int(&mut body, 4, 0x50, 25);
            encode_int(&mut body, 7, 0x80, huffman.len() as u64);
            body.extend_from_slice(huffman);
            assert_eq!(find_status(&section(&body)).unwrap(), status, "{status}");
        }
    }

    #[test]
    fn other_fields_are_stepped_over() {
        let mut body = Vec::new();
        literal(&mut body, b"server", b"nginx");
        // A Huffman-coded value that must not be decoded
        encode_int(&mut body, 3, 0x20, 4);
        body.extend_from_slice(b"date");
        encode_int(&mut body, 7, 0x80, 3);
        body.extend_from_slice(&[0xff, 0xff, 0xff]);
        indexed(&mut body, 25);
        assert_eq!(find_status(&section(&body)).unwrap(), 200);
    }

    #[test]
    fn dynamic_table_references_are_rejected() {
        // Indexed field line with T=0
        assert!(find_status(&section(&[0x80])).is_err());
        // Literal with a dynamic name reference
        assert!(find_status(&section(&[0x40])).is_err());
        // Post-base index
        assert!(find_status(&section(&[0x10])).is_err());
        // A non-zero required insert count
        assert!(find_status(&[0x01, 0x00, 0xc0 | 25]).is_err());
    }

    #[test]
    fn truncated_section_is_rejected() {
        let mut body = Vec::new();
        encode_int(&mut body, 4, 0x50, 25);
        encode_int(&mut body, 7, 0x00, 3);
        body.push(b'2');
        assert!(find_status(&section(&body)).is_err());
    }
}
