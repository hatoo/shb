//! HPACK, cut down to what a load generator needs
//!
//! Requests are identical apart from the stream id, so the whole header block
//! is encoded once at start-up ([`encode_request`]) and then memcpy'd per
//! request. It uses only static-table indices and literals *without* indexing,
//! so it never mutates a dynamic table and the same bytes stay valid forever.
//!
//! Responses go the other way: the client advertises
//! `SETTINGS_HEADER_TABLE_SIZE = 0`, which forbids the peer's encoder from
//! indexing, so decoding needs no dynamic table either. And since the only
//! field worth reading is `:status`, [`find_status`] walks the block measuring
//! fields and steps over every one of them without decoding its contents.

use anyhow::{Result, bail};

/// Static table entries whose name is `:status`, by index
const STATUS_BY_INDEX: [u16; 7] = [200, 204, 206, 304, 400, 404, 500];
/// First and last static index whose name is `:status`
const STATUS_INDEX_LO: u32 = 8;
const STATUS_INDEX_HI: u32 = 14;

/// Append an integer in HPACK's prefix encoding (RFC 7541 Section 5.1)
///
/// `mask` carries the representation bits above the `prefix_bits`-wide field.
fn encode_int(out: &mut Vec<u8>, prefix_bits: u8, mask: u8, value: u32) {
    let max = (1u32 << prefix_bits) - 1;
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

/// Append a string literal, uncompressed
///
/// Huffman coding would shrink the request a little at the cost of a table
/// walk; the block is built once, but the bytes are sent per request, so this
/// trades a few bytes on the wire for no per-request work at all.
fn encode_str(out: &mut Vec<u8>, s: &[u8]) {
    encode_int(out, 7, 0x00, s.len() as u32);
    out.extend_from_slice(s);
}

/// A literal field whose name is in the static table, without indexing
fn literal_indexed_name(out: &mut Vec<u8>, name_index: u32, value: &[u8]) {
    encode_int(out, 4, 0x00, name_index);
    encode_str(out, value);
}

/// A literal field whose name is in the static table, added to the peer's
/// dynamic table as it is decoded
fn literal_indexing(out: &mut Vec<u8>, name_index: u32, value: &[u8]) {
    encode_int(out, 6, 0x40, name_index);
    encode_str(out, value);
}

/// Static index of `:authority`, and the dynamic index its entry lands on
///
/// The dynamic table is addressed from 62 downwards, newest first, and
/// `:authority` is the only field shb ever inserts, so its entry is always 62.
const IDX_AUTHORITY: u32 = 1;
const DYNAMIC_AUTHORITY: u32 = 62;

/// The two header blocks a connection alternates between
pub struct RequestBlocks {
    /// Sent until the peer is known to be keeping a dynamic table. It carries
    /// `:authority` as a literal and asks the peer to remember it.
    pub first: Vec<u8>,
    /// Sent afterwards, with `:authority` as a one-byte reference to that
    /// entry. For a typical authority this is 15 bytes shorter per request.
    pub indexed: Vec<u8>,
    /// What the entry costs in the peer's table (RFC 7541 Section 4.1), so the
    /// caller can check it against SETTINGS_HEADER_TABLE_SIZE
    pub entry_size: u32,
}

/// A literal field with both parts spelled out, without indexing
fn literal(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(0x00);
    encode_str(out, name);
    encode_str(out, value);
}

/// Build the header blocks sent for every request
///
/// Pseudo-headers come first, as RFC 9113 Section 8.3 requires. Header names
/// must already be lower-cased. Only `:authority` is ever indexed: it is the
/// one field long enough to be worth it, and keeping it the sole entry is what
/// makes its dynamic index a constant.
pub fn encode_request(
    method: &str,
    scheme: &str,
    authority: &str,
    path: &str,
    headers: &[(String, String)],
    body_len: usize,
) -> RequestBlocks {
    let build = |index_authority: bool| {
        let mut out = Vec::with_capacity(64 + headers.len() * 32);

        // :method — GET and POST have a static entry of their own
        match method {
            "GET" => out.push(0x82),
            "POST" => out.push(0x83),
            _ => literal_indexed_name(&mut out, 2, method.as_bytes()),
        }
        // :scheme
        match scheme {
            "http" => out.push(0x86),
            "https" => out.push(0x87),
            _ => literal_indexed_name(&mut out, 6, scheme.as_bytes()),
        }
        // :authority
        if index_authority {
            encode_int(&mut out, 7, 0x80, DYNAMIC_AUTHORITY);
        } else {
            literal_indexing(&mut out, IDX_AUTHORITY, authority.as_bytes());
        }
        // :path — "/" has a static entry
        if path == "/" {
            out.push(0x84);
        } else {
            literal_indexed_name(&mut out, 4, path.as_bytes());
        }

        for (name, value) in headers {
            literal(&mut out, name.as_bytes(), value.as_bytes());
        }
        if body_len > 0 {
            // content-length is static index 28
            literal_indexed_name(&mut out, 28, body_len.to_string().as_bytes());
        }
        out
    };
    RequestBlocks {
        first: build(false),
        indexed: build(true),
        // name + value + 32 (RFC 7541 Section 4.1)
        entry_size: (":authority".len() + authority.len() + 32) as u32,
    }
}

/// Read an integer in HPACK's prefix encoding, advancing `pos`
fn decode_int(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> Result<u32> {
    let max = (1u32 << prefix_bits) - 1;
    let first = *buf.get(*pos).ok_or_else(short)? as u32 & max;
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
            .checked_add(((byte & 0x7f) as u32) << shift)
            .ok_or_else(|| anyhow::anyhow!("HPACK integer overflow"))?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 21 {
            bail!("HPACK integer too long");
        }
    }
}

fn short() -> anyhow::Error {
    anyhow::anyhow!("truncated HPACK block")
}

/// Skip over a string literal, returning its bytes and whether they are
/// Huffman-coded
fn read_str<'a>(buf: &'a [u8], pos: &mut usize) -> Result<(&'a [u8], bool)> {
    let huffman = *buf.get(*pos).ok_or_else(short)? & 0x80 != 0;
    let len = decode_int(buf, pos, 7)? as usize;
    let end = pos.checked_add(len).ok_or_else(short)?;
    let s = buf.get(*pos..end).ok_or_else(short)?;
    *pos = end;
    Ok((s, huffman))
}

/// Decode a three-digit status value
///
/// Only the ten digit symbols can appear here, and all of them are 5 to 7 bits
/// long, so the Huffman case needs a handful of codes rather than the whole
/// 256-entry table (RFC 7541 Appendix B).
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

/// Find `:status` in a response header block
///
/// Every other field is measured and stepped over; none of their names or
/// values are decoded.
pub fn find_status(block: &[u8]) -> Result<u16> {
    let mut pos = 0;
    while pos < block.len() {
        let first = block[pos];
        if first & 0x80 != 0 {
            // Fully indexed field
            let index = decode_int(block, &mut pos, 7)?;
            if (STATUS_INDEX_LO..=STATUS_INDEX_HI).contains(&index) {
                return Ok(STATUS_BY_INDEX[(index - STATUS_INDEX_LO) as usize]);
            }
            if index == 0 {
                bail!("HPACK index 0");
            }
            if index > 61 {
                // The peer was told not to index, so it has no dynamic table
                bail!("HPACK dynamic table reference");
            }
            continue;
        }
        // Literal field: incremental (01), size update (001), never (0001) or
        // without indexing (0000)
        let name_index = if first & 0x40 != 0 {
            decode_int(block, &mut pos, 6)?
        } else if first & 0x20 != 0 {
            // Dynamic table size update, no field follows
            decode_int(block, &mut pos, 5)?;
            continue;
        } else {
            decode_int(block, &mut pos, 4)?
        };

        let named_status = if name_index == 0 {
            let (name, huffman) = read_str(block, &mut pos)?;
            !huffman && name == b":status"
        } else {
            if name_index > 61 {
                bail!("HPACK dynamic table reference");
            }
            (STATUS_INDEX_LO..=STATUS_INDEX_HI).contains(&name_index)
        };
        let (value, huffman) = read_str(block, &mut pos)?;
        if named_status {
            return status_value(value, huffman);
        }
    }
    bail!("response without :status")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip_across_the_prefix_boundary() {
        for value in [0u32, 1, 14, 15, 16, 127, 128, 255, 1337, 100000] {
            for bits in [4u8, 5, 6, 7] {
                let mut out = Vec::new();
                encode_int(&mut out, bits, 0, value);
                let mut pos = 0;
                assert_eq!(decode_int(&out, &mut pos, bits).unwrap(), value);
                assert_eq!(pos, out.len(), "value {value} bits {bits}");
            }
        }
    }

    /// The worked examples from RFC 7541 Appendix C.1, so the integer codec is
    /// checked against the spec rather than against itself. QPACK reuses this
    /// encoding unchanged.
    #[test]
    fn integers_match_the_spec() {
        // C.1.1: 10 in a 5-bit prefix fits in the prefix
        let mut out = Vec::new();
        encode_int(&mut out, 5, 0, 10);
        assert_eq!(out, [0x0a]);
        // C.1.2: 1337 in a 5-bit prefix spills into continuation octets
        let mut out = Vec::new();
        encode_int(&mut out, 5, 0, 1337);
        assert_eq!(out, [0x1f, 0x9a, 0x0a]);
        // C.1.3: 42 in an 8-bit prefix
        let mut out = Vec::new();
        encode_int(&mut out, 8, 0, 42);
        assert_eq!(out, [0x2a]);

        for (bytes, prefix, value) in [
            (&[0x0a][..], 5u8, 10u32),
            (&[0x1f, 0x9a, 0x0a], 5, 1337),
            (&[0x2a], 8, 42),
        ] {
            let mut pos = 0;
            assert_eq!(decode_int(bytes, &mut pos, prefix).unwrap(), value);
            assert_eq!(pos, bytes.len());
        }
    }

    #[test]
    fn get_request_uses_static_entries() {
        let blocks = encode_request("GET", "http", "127.0.0.1:80", "/", &[], 0);
        for block in [&blocks.first, &blocks.indexed] {
            // :method GET, :scheme http, :path / are one byte each
            assert_eq!(block[0], 0x82);
            assert_eq!(block[1], 0x86);
            assert_eq!(*block.last().unwrap(), 0x84);
        }
    }

    #[test]
    fn the_short_block_replaces_the_authority_literal() {
        let authority = "127.0.0.1:8080";
        let blocks = encode_request("GET", "http", authority, "/", &[], 0);
        // The first block spells the authority out and asks the peer to keep it
        assert_eq!(
            blocks.first[2],
            0x40 | 1,
            "literal with incremental indexing"
        );
        assert_eq!(&blocks.first[4..4 + authority.len()], authority.as_bytes());
        // The short one is a single reference to the entry that created
        assert_eq!(blocks.indexed[2], 0x80 | 62);
        assert_eq!(
            blocks.first.len() - blocks.indexed.len(),
            authority.len() + 1,
            "the literal's length byte and text are what goes away"
        );
        assert_eq!(blocks.entry_size, (10 + authority.len() + 32) as u32);
    }

    #[test]
    fn a_body_adds_content_length_to_both_blocks() {
        let blocks = encode_request("POST", "https", "h", "/", &[], 1234);
        for block in [&blocks.first, &blocks.indexed] {
            assert!(
                block.windows(4).any(|w| w == b"1234"),
                "content-length is spelled out"
            );
        }
    }

    #[test]
    fn indexed_status_is_read() {
        assert_eq!(find_status(&[0x88]).unwrap(), 200);
        assert_eq!(find_status(&[0x8b]).unwrap(), 304);
        assert_eq!(find_status(&[0x8e]).unwrap(), 500);
    }

    #[test]
    fn literal_status_is_read() {
        // Literal without indexing, name index 8 (:status), value "201"
        let mut block = vec![0x08];
        encode_str(&mut block, b"201");
        assert_eq!(find_status(&block).unwrap(), 201);
    }

    #[test]
    fn huffman_status_is_read() {
        // "201" Huffman: '2'=00010, '0'=00000, '1'=00001, padded with ones
        // 00010 00000 00001 1 -> 0001_0000 0000_0011
        let block = [0x08u8, 0x82, 0x10, 0x03];
        assert_eq!(find_status(&block).unwrap(), 201);
    }

    #[test]
    fn every_huffman_digit_decodes() {
        for status in [200u16, 201, 204, 301, 399, 404, 456, 500, 599, 789] {
            let text = status.to_string();
            let encoded = huffman_encode_digits(&text);
            let mut block = vec![0x08u8];
            encode_int(&mut block, 7, 0x80, encoded.len() as u32);
            block.extend_from_slice(&encoded);
            assert_eq!(find_status(&block).unwrap(), status, "status {status}");
        }
    }

    /// Huffman-encode a run of digits, for the decoder tests
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
        // Pad to a byte boundary with ones, as RFC 7541 Section 5.2 requires
        while bits.len() % 8 != 0 {
            bits.push(true);
        }
        bits.chunks(8)
            .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | b as u8))
            .collect()
    }

    /// Byte sequences worked out by hand from RFC 7541 Appendix B, so the
    /// decoder is checked against the spec rather than against this file's own
    /// encoder
    #[test]
    fn huffman_status_matches_the_spec() {
        for (status, huffman) in [
            (301u16, &[0x64u8, 0x01][..]),
            (200, &[0x10, 0x01]),
            (404, &[0x68, 0x0d, 0x7f]),
            (503, &[0x6c, 0x0c, 0xff]),
            (999, &[0x7d, 0xf7, 0xff]),
        ] {
            // Literal without indexing, name index 8 (:status)
            let mut block = vec![0x08u8];
            encode_int(&mut block, 7, 0x80, huffman.len() as u32);
            block.extend_from_slice(huffman);
            assert_eq!(find_status(&block).unwrap(), status, "{status}");
        }
    }

    #[test]
    fn other_fields_are_stepped_over() {
        let mut block = Vec::new();
        literal(&mut block, b"server", b"nginx");
        block.push(0x88); // :status 200
        literal(&mut block, b"content-type", b"text/plain");
        assert_eq!(find_status(&block).unwrap(), 200);
    }

    #[test]
    fn dynamic_table_reference_is_rejected() {
        // Index 62 is the first dynamic entry, which the peer must not use
        assert!(find_status(&[0xbe]).is_err());
    }

    #[test]
    fn size_update_is_skipped() {
        assert_eq!(find_status(&[0x20, 0x88]).unwrap(), 200);
    }

    #[test]
    fn truncated_block_is_rejected() {
        let mut block = vec![0x08];
        encode_int(&mut block, 7, 0x00, 3);
        block.push(b'2'); // value cut short
        assert!(find_status(&block).is_err());
    }
}
