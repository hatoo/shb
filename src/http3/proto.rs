//! HTTP/3 framing over QUIC streams
//!
//! Enough of RFC 9114 to drive a benchmark: open the control and QPACK
//! streams, put a request on a bidirectional stream, and read the response's
//! `:status` back. Everything the client is allowed to ignore — push, extra
//! settings, unknown frames, unknown unidirectional stream types — is skipped
//! by length rather than modelled.

use anyhow::{Result, bail};

use super::qpack;

// Frame types (RFC 9114 Section 7.2)
const FRAME_DATA: u64 = 0x00;
const FRAME_HEADERS: u64 = 0x01;
const FRAME_SETTINGS: u64 = 0x04;
const FRAME_GOAWAY: u64 = 0x07;

// Unidirectional stream types (RFC 9114 Section 6.2)
pub const STREAM_CONTROL: u64 = 0x00;
pub const STREAM_QPACK_ENCODER: u64 = 0x02;
pub const STREAM_QPACK_DECODER: u64 = 0x03;

// Settings identifiers
const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;

/// Append a QUIC variable-length integer (RFC 9000 Section 16)
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

/// The client's control stream contents: the stream type then SETTINGS
///
/// `QPACK_MAX_TABLE_CAPACITY: 0` is what forbids the peer from inserting into
/// the dynamic table, which in turn lets [`qpack::find_status`] stay stateless
/// and never block on an unreceived insert.
pub fn control_stream_prelude() -> Vec<u8> {
    let mut settings = Vec::new();
    for (id, value) in [
        (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0u64),
        (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        (SETTINGS_MAX_FIELD_SECTION_SIZE, 1 << 20),
    ] {
        put_varint(&mut settings, id);
        put_varint(&mut settings, value);
    }
    let mut out = Vec::with_capacity(settings.len() + 8);
    put_varint(&mut out, STREAM_CONTROL);
    put_varint(&mut out, FRAME_SETTINGS);
    put_varint(&mut out, settings.len() as u64);
    out.extend_from_slice(&settings);
    out
}

/// A request: one HEADERS frame, then a DATA frame when there is a body
pub fn request_bytes(field_section: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field_section.len() + body.len() + 16);
    put_varint(&mut out, FRAME_HEADERS);
    put_varint(&mut out, field_section.len() as u64);
    out.extend_from_slice(field_section);
    if !body.is_empty() {
        put_varint(&mut out, FRAME_DATA);
        put_varint(&mut out, body.len() as u64);
        out.extend_from_slice(body);
    }
    out
}

/// Reader for one response stream
///
/// Frames may be split across QUIC reads, so whatever is left of a partial
/// frame is carried over. Response bodies are skipped by length; only the
/// HEADERS field section is looked at.
#[derive(Default)]
pub struct ResponseReader {
    /// A partial frame header or field section carried over
    pending: Vec<u8>,
    /// Bytes still to skip from the frame being read
    skip: u64,
    /// Status from the first HEADERS frame (0 = not seen yet)
    status: u16,
}

impl ResponseReader {
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Consume stream data
    pub fn feed(&mut self, data: &[u8]) -> Result<()> {
        if self.pending.is_empty() {
            let used = self.run(data)?;
            if used < data.len() {
                self.pending.extend_from_slice(&data[used..]);
            }
            return Ok(());
        }
        let mut buf = std::mem::take(&mut self.pending);
        buf.extend_from_slice(data);
        let result = self.run(&buf);
        match result {
            Ok(used) => {
                buf.drain(..used);
                self.pending = buf;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn run(&mut self, buf: &[u8]) -> Result<usize> {
        let mut pos = 0;
        loop {
            if self.skip > 0 {
                let take = self.skip.min((buf.len() - pos) as u64);
                pos += take as usize;
                self.skip -= take;
                if self.skip > 0 {
                    return Ok(pos);
                }
            }
            let Some((kind, n1)) = get_varint(&buf[pos..]) else {
                return Ok(pos);
            };
            let Some((len, n2)) = get_varint(&buf[pos + n1..]) else {
                return Ok(pos);
            };
            let header_len = n1 + n2;
            if kind == FRAME_HEADERS {
                let end = pos + header_len + len as usize;
                if buf.len() < end {
                    // Wait for the whole field section: decoding it in pieces
                    // would mean keeping QPACK state across reads
                    return Ok(pos);
                }
                let section = &buf[pos + header_len..end];
                // Trailers arrive as a second HEADERS frame and have no status
                if self.status == 0 {
                    self.status = qpack::find_status(section)?;
                }
                pos = end;
                continue;
            }
            if kind == FRAME_GOAWAY && len > 1 << 20 {
                bail!("oversized GOAWAY");
            }
            // DATA and anything else the client may ignore: skip by length
            pos += header_len;
            self.skip = len;
        }
    }
}

/// Reader for a peer-opened unidirectional stream
///
/// The only thing worth acting on is a GOAWAY on the control stream; QPACK
/// encoder and decoder streams stay empty because neither side may insert, and
/// unknown stream types must be discarded.
#[derive(Default)]
pub struct UniReader {
    kind: Option<u64>,
    pending: Vec<u8>,
    skip: u64,
    pub goaway: bool,
}

impl UniReader {
    pub fn feed(&mut self, data: &[u8]) -> Result<()> {
        self.pending.extend_from_slice(data);
        let mut pos = 0;
        if self.kind.is_none() {
            let Some((kind, n)) = get_varint(&self.pending) else {
                return Ok(());
            };
            self.kind = Some(kind);
            pos = n;
        }
        if self.kind != Some(STREAM_CONTROL) {
            // Nothing to interpret; drop what arrived
            self.pending.clear();
            return Ok(());
        }
        loop {
            if self.skip > 0 {
                let take = self.skip.min((self.pending.len() - pos) as u64);
                pos += take as usize;
                self.skip -= take;
                if self.skip > 0 {
                    break;
                }
            }
            let Some((kind, n1)) = get_varint(&self.pending[pos..]) else {
                break;
            };
            let Some((len, n2)) = get_varint(&self.pending[pos + n1..]) else {
                break;
            };
            if kind == FRAME_GOAWAY {
                self.goaway = true;
            }
            pos += n1 + n2;
            self.skip = len;
        }
        self.pending.drain(..pos);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(value: u64) -> Vec<u8> {
        let mut v = Vec::new();
        put_varint(&mut v, value);
        v
    }

    fn frame(kind: u64, payload: &[u8]) -> Vec<u8> {
        let mut v = varint(kind);
        v.extend_from_slice(&varint(payload.len() as u64));
        v.extend_from_slice(payload);
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

    /// The worked examples from RFC 9000 Appendix A.1, so the codec is checked
    /// against the spec rather than against itself
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

    #[test]
    fn control_prelude_disables_the_dynamic_table() {
        let out = control_stream_prelude();
        assert_eq!(out[0], 0x00, "control stream type");
        assert_eq!(out[1], 0x04, "SETTINGS frame");
        // QPACK_MAX_TABLE_CAPACITY = 0 is the first setting
        assert_eq!(&out[3..5], &[0x01, 0x00]);
    }

    #[test]
    fn headers_then_data_yields_the_status() {
        let mut r = ResponseReader::default();
        let mut stream = frame(FRAME_HEADERS, &[0x00, 0x00, 0xc0 | 25]);
        stream.extend_from_slice(&frame(FRAME_DATA, b"hello world!!"));
        r.feed(&stream).unwrap();
        assert_eq!(r.status(), 200);
    }

    #[test]
    fn split_at_every_offset() {
        let mut stream = frame(FRAME_HEADERS, &[0x00, 0x00, 0xc0 | 27]);
        stream.extend_from_slice(&frame(FRAME_DATA, b"body"));
        for split in 1..stream.len() {
            let mut r = ResponseReader::default();
            r.feed(&stream[..split]).unwrap();
            r.feed(&stream[split..]).unwrap();
            assert_eq!(r.status(), 404, "split at {split}");
        }
    }

    #[test]
    fn unknown_frames_are_skipped() {
        let mut r = ResponseReader::default();
        let mut stream = frame(0x21, b"grease");
        stream.extend_from_slice(&frame(FRAME_HEADERS, &[0x00, 0x00, 0xc0 | 25]));
        stream.extend_from_slice(&frame(0x1f * 3 + 0x21, b"more grease"));
        r.feed(&stream).unwrap();
        assert_eq!(r.status(), 200);
    }

    #[test]
    fn trailers_do_not_overwrite_the_status() {
        let mut r = ResponseReader::default();
        let mut stream = frame(FRAME_HEADERS, &[0x00, 0x00, 0xc0 | 25]);
        stream.extend_from_slice(&frame(FRAME_DATA, b"x"));
        // A trailer section with no :status must not be an error
        let mut trailers = vec![0x00u8, 0x00];
        trailers.extend_from_slice(&[0x20 | 3, b'a', b'b', b'c', 0x01, b'1']);
        stream.extend_from_slice(&frame(FRAME_HEADERS, &trailers));
        r.feed(&stream).unwrap();
        assert_eq!(r.status(), 200);
    }

    #[test]
    fn a_large_body_is_skipped_across_reads() {
        let mut r = ResponseReader::default();
        let body = vec![b'x'; 100_000];
        let mut stream = frame(FRAME_HEADERS, &[0x00, 0x00, 0xc0 | 25]);
        stream.extend_from_slice(&frame(FRAME_DATA, &body));
        for chunk in stream.chunks(1500) {
            r.feed(chunk).unwrap();
        }
        assert_eq!(r.status(), 200);
    }

    #[test]
    fn control_stream_goaway_is_noticed() {
        let mut u = UniReader::default();
        let mut data = varint(STREAM_CONTROL);
        data.extend_from_slice(&frame(FRAME_SETTINGS, &[0x01, 0x00]));
        assert!(!u.goaway);
        u.feed(&data).unwrap();
        assert!(!u.goaway);
        u.feed(&frame(FRAME_GOAWAY, &varint(0))).unwrap();
        assert!(u.goaway);
    }

    #[test]
    fn qpack_streams_are_discarded() {
        let mut u = UniReader::default();
        u.feed(&varint(STREAM_QPACK_ENCODER)).unwrap();
        u.feed(b"whatever the peer sends").unwrap();
        assert!(!u.goaway);
        assert!(u.pending.is_empty());
    }
}
