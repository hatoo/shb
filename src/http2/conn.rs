//! HTTP/2 client connection, sized for a load generator
//!
//! Only the parts a benchmark client exercises are implemented: open a stream
//! with a pre-encoded header block, read the response's `:status`, count the
//! body, and keep the flow-control windows out of the way. Priority, push and
//! anything to do with the dynamic HPACK table are declined at the SETTINGS
//! level rather than implemented.

use anyhow::{Result, bail};

use super::hpack::{self, RequestBlocks};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_LEN: usize = 9;

// Frame types
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;

// Frame flags
const FLAG_ACK: u8 = 0x1;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

// Settings identifiers
const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTINGS_ENABLE_PUSH: u16 = 0x2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;

/// Largest window HTTP/2 allows
const MAX_WINDOW: u32 = (1 << 31) - 1;
/// Receive-window credit to hand back in one go, once this much has been used
const WINDOW_REFRESH: u32 = 1 << 30;

/// What the worker needs to hear about
pub enum Event {
    /// The response headers arrived; the stream may still be carrying a body
    Status { stream_id: u32, status: u16 },
    /// The stream is finished
    End { stream_id: u32 },
    /// The peer gave up on this stream
    Reset { stream_id: u32 },
    /// No more streams may be opened on this connection
    Goaway,
}

pub struct Connection {
    /// Bytes waiting to be written to the socket
    out: Vec<u8>,
    /// A partial frame carried over from an earlier receive
    pending: Vec<u8>,
    /// Header block fragments of a HEADERS still awaiting END_HEADERS
    header_block: Vec<u8>,
    /// Stream the pending header block belongs to, and whether it ends the stream
    header_stream: u32,
    header_end_stream: bool,
    /// Next client stream id (odd, ascending)
    next_id: u32,
    /// Streams opened and not yet finished
    open: u32,
    /// The peer's SETTINGS_MAX_CONCURRENT_STREAMS
    max_concurrent: u32,
    /// The peer's SETTINGS_HEADER_TABLE_SIZE, once its SETTINGS have arrived.
    /// Until then nothing may be indexed: the peer might be keeping no table
    /// at all, in which case a reference to one would be a decoding error
    peer_table_size: Option<u32>,
    /// Whether a block that inserts `:authority` has already gone out, so the
    /// peer's table holds the entry the short block refers to
    inserted_authority: bool,
    /// Our remaining connection-level send credit
    send_window: i64,
    /// The peer's SETTINGS_INITIAL_WINDOW_SIZE, the credit each new stream gets
    peer_initial_window: u32,
    /// Bytes received against the connection window since the last update
    recv_consumed: u32,
    /// A GOAWAY has been received
    goaway: bool,
}

impl Connection {
    pub fn new() -> Self {
        Connection {
            out: Vec::with_capacity(4096),
            pending: Vec::new(),
            header_block: Vec::new(),
            header_stream: 0,
            header_end_stream: false,
            next_id: 1,
            open: 0,
            max_concurrent: u32::MAX,
            peer_table_size: None,
            inserted_authority: false,
            send_window: 65535,
            peer_initial_window: 65535,
            recv_consumed: 0,
            goaway: false,
        }
    }

    /// Queue the client preface, our settings and the connection window bump
    pub fn initiate(&mut self) {
        self.out.extend_from_slice(PREFACE);
        // HEADER_TABLE_SIZE 0 forbids the peer's encoder from indexing, which
        // is what lets the response decoder stay stateless
        let settings: [(u16, u32); 3] = [
            (SETTINGS_HEADER_TABLE_SIZE, 0),
            (SETTINGS_ENABLE_PUSH, 0),
            (SETTINGS_INITIAL_WINDOW_SIZE, MAX_WINDOW),
        ];
        self.frame_header(6 * settings.len(), SETTINGS, 0, 0);
        for (id, value) in settings {
            self.out.extend_from_slice(&id.to_be_bytes());
            self.out.extend_from_slice(&value.to_be_bytes());
        }
        // The connection window starts at 65535 whatever SETTINGS say, so
        // raise it once rather than trickling updates back
        self.window_update(0, MAX_WINDOW - 65535);
    }

    /// Whether another stream may be opened right now
    pub fn can_open(&self) -> bool {
        !self.goaway && self.open < self.max_concurrent
    }

    /// Open a stream carrying the request (and `body`), returning its id
    ///
    /// Picks the short header block once the peer has said it keeps a dynamic
    /// table big enough for the entry, and the entry has been sent.
    pub fn start_stream(&mut self, blocks: &RequestBlocks, body: &[u8]) -> Option<u32> {
        if !self.can_open()
            || (body.len() as i64) > self.send_window
            || body.len() as u32 > self.peer_initial_window
        {
            return None;
        }
        let indexed = self.inserted_authority
            && self
                .peer_table_size
                .is_some_and(|size| size >= blocks.entry_size);
        let block: &[u8] = if indexed {
            &blocks.indexed
        } else {
            self.inserted_authority = true;
            &blocks.first
        };
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(2);
        let end_stream = if body.is_empty() { FLAG_END_STREAM } else { 0 };
        self.frame_header(block.len(), HEADERS, FLAG_END_HEADERS | end_stream, id);
        self.out.extend_from_slice(block);
        if !body.is_empty() {
            self.frame_header(body.len(), DATA, FLAG_END_STREAM, id);
            self.out.extend_from_slice(body);
            self.send_window -= body.len() as i64;
        }
        self.open += 1;
        Some(id)
    }

    /// Take everything queued for the socket
    pub fn take_output(&mut self) -> Option<Vec<u8>> {
        if self.out.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.out))
        }
    }

    /// Queue a GOAWAY, so a clean teardown is not logged as an error by the peer
    pub fn send_goaway(&mut self) {
        let last = self.next_id.saturating_sub(2);
        self.frame_header(8, GOAWAY, 0, 0);
        self.out.extend_from_slice(&last.to_be_bytes());
        self.out.extend_from_slice(&0u32.to_be_bytes());
    }

    fn frame_header(&mut self, len: usize, kind: u8, flags: u8, stream: u32) {
        let len = len as u32;
        self.out
            .extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags]);
        self.out.extend_from_slice(&stream.to_be_bytes());
    }

    fn window_update(&mut self, stream: u32, increment: u32) {
        self.frame_header(4, WINDOW_UPDATE, 0, stream);
        self.out.extend_from_slice(&increment.to_be_bytes());
    }

    /// Consume received bytes, appending what happened to `events`
    pub fn feed(&mut self, data: &[u8], events: &mut Vec<Event>) -> Result<()> {
        if self.pending.is_empty() {
            // Fast path: read frames straight out of the receive buffer and
            // keep only a trailing partial frame
            let used = self.run(data, events)?;
            if used < data.len() {
                self.pending.extend_from_slice(&data[used..]);
            }
            return Ok(());
        }
        let mut buf = std::mem::take(&mut self.pending);
        buf.extend_from_slice(data);
        let used = self.run(&buf, events);
        match used {
            Ok(used) => {
                buf.drain(..used);
                self.pending = buf;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Read as many whole frames from `buf` as possible, returning how many
    /// bytes were consumed
    fn run(&mut self, buf: &[u8], events: &mut Vec<Event>) -> Result<usize> {
        let mut pos = 0;
        while buf.len() - pos >= FRAME_HEADER_LEN {
            let h = &buf[pos..pos + FRAME_HEADER_LEN];
            let len = ((h[0] as usize) << 16) | ((h[1] as usize) << 8) | h[2] as usize;
            let kind = h[3];
            let flags = h[4];
            let stream = u32::from_be_bytes([h[5] & 0x7f, h[6], h[7], h[8]]);
            let end = pos + FRAME_HEADER_LEN + len;
            if buf.len() < end {
                break;
            }
            let payload = &buf[pos + FRAME_HEADER_LEN..end];
            pos = end;

            // A HEADERS awaiting END_HEADERS may only be followed by
            // CONTINUATION on the same stream (RFC 9113 Section 6.10)
            if !self.header_block.is_empty() && kind != CONTINUATION {
                bail!("frame interleaved with a header block");
            }

            match kind {
                DATA => self.on_data(stream, flags, payload, events),
                HEADERS => self.on_headers(stream, flags, payload, events)?,
                CONTINUATION => self.on_continuation(stream, flags, payload, events)?,
                SETTINGS => self.on_settings(flags, payload)?,
                WINDOW_UPDATE => self.on_window_update(stream, payload)?,
                PING => self.on_ping(flags, payload),
                RST_STREAM => {
                    if self.finish_stream() {
                        events.push(Event::Reset { stream_id: stream });
                    }
                }
                GOAWAY => {
                    self.goaway = true;
                    events.push(Event::Goaway);
                }
                // PRIORITY and anything unknown are ignored, as the spec allows
                _ => {}
            }
        }
        Ok(pos)
    }

    fn on_data(&mut self, stream: u32, flags: u8, payload: &[u8], events: &mut Vec<Event>) {
        // The whole frame counts against the connection window, padding included
        self.recv_consumed += payload.len() as u32;
        if self.recv_consumed >= WINDOW_REFRESH {
            let credit = self.recv_consumed;
            self.recv_consumed = 0;
            self.window_update(0, credit);
        }
        if flags & FLAG_END_STREAM != 0 && self.finish_stream() {
            events.push(Event::End { stream_id: stream });
        }
    }

    fn on_headers(
        &mut self,
        stream: u32,
        flags: u8,
        payload: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<()> {
        let mut block = payload;
        if flags & FLAG_PADDED != 0 {
            let pad = *block.first().ok_or_else(|| bad("padded HEADERS"))? as usize;
            block = block.get(1..).ok_or_else(|| bad("padded HEADERS"))?;
            block = block
                .get(..block.len().checked_sub(pad).ok_or_else(|| bad("padding"))?)
                .ok_or_else(|| bad("padding"))?;
        }
        if flags & FLAG_PRIORITY != 0 {
            block = block.get(5..).ok_or_else(|| bad("priority in HEADERS"))?;
        }
        if flags & FLAG_END_HEADERS != 0 {
            return self.complete_headers(stream, flags & FLAG_END_STREAM != 0, block, events);
        }
        self.header_block.extend_from_slice(block);
        self.header_stream = stream;
        self.header_end_stream = flags & FLAG_END_STREAM != 0;
        Ok(())
    }

    fn on_continuation(
        &mut self,
        stream: u32,
        flags: u8,
        payload: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<()> {
        if self.header_block.is_empty() || stream != self.header_stream {
            bail!("unexpected CONTINUATION");
        }
        self.header_block.extend_from_slice(payload);
        if flags & FLAG_END_HEADERS == 0 {
            return Ok(());
        }
        let block = std::mem::take(&mut self.header_block);
        let end_stream = self.header_end_stream;
        let result = self.complete_headers(stream, end_stream, &block, events);
        self.header_block = block;
        self.header_block.clear();
        result
    }

    fn complete_headers(
        &mut self,
        stream: u32,
        end_stream: bool,
        block: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<()> {
        events.push(Event::Status {
            stream_id: stream,
            status: hpack::find_status(block)?,
        });
        if end_stream && self.finish_stream() {
            events.push(Event::End { stream_id: stream });
        }
        Ok(())
    }

    fn on_settings(&mut self, flags: u8, payload: &[u8]) -> Result<()> {
        if flags & FLAG_ACK != 0 {
            return Ok(());
        }
        let (entries, rest) = payload.as_chunks::<6>();
        if !rest.is_empty() {
            bail!("malformed SETTINGS");
        }
        // The default when the peer says nothing (RFC 7541 Section 4.2)
        let mut table_size = 4096;
        for entry in entries {
            let id = u16::from_be_bytes([entry[0], entry[1]]);
            let value = u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]);
            match id {
                SETTINGS_MAX_CONCURRENT_STREAMS => self.max_concurrent = value,
                SETTINGS_HEADER_TABLE_SIZE => table_size = value,
                // Our only use for this is deciding whether a request body
                // fits; responses ride on the huge window we advertise
                SETTINGS_INITIAL_WINDOW_SIZE if value <= MAX_WINDOW => {
                    self.peer_initial_window = value
                }
                SETTINGS_INITIAL_WINDOW_SIZE => bail!("SETTINGS_INITIAL_WINDOW_SIZE out of range"),
                _ => {}
            }
        }
        self.peer_table_size = Some(table_size);
        self.frame_header(0, SETTINGS, FLAG_ACK, 0);
        Ok(())
    }

    fn on_window_update(&mut self, stream: u32, payload: &[u8]) -> Result<()> {
        if payload.len() != 4 {
            bail!("malformed WINDOW_UPDATE");
        }
        let increment =
            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & !0x8000_0000;
        if stream == 0 {
            self.send_window += increment as i64;
        }
        Ok(())
    }

    fn on_ping(&mut self, flags: u8, payload: &[u8]) {
        if flags & FLAG_ACK != 0 || payload.len() != 8 {
            return;
        }
        self.frame_header(8, PING, FLAG_ACK, 0);
        self.out.extend_from_slice(payload);
    }

    /// Account for a stream ending, returning false if none was open
    fn finish_stream(&mut self) -> bool {
        if self.open == 0 {
            return false;
        }
        self.open -= 1;
        true
    }
}

fn bad(what: &str) -> anyhow::Error {
    anyhow::anyhow!("malformed frame: {what}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut v = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
        v.extend_from_slice(&stream.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// Two identical one-byte blocks, so tests that only care about framing
    /// do not have to think about which one goes out
    fn blocks() -> RequestBlocks {
        RequestBlocks {
            first: vec![0x82],
            indexed: vec![0x82],
            entry_size: 46,
        }
    }

    fn connected() -> Connection {
        let mut c = Connection::new();
        c.initiate();
        c.take_output();
        c
    }

    #[test]
    fn preface_and_settings_are_queued_first() {
        let mut c = Connection::new();
        c.initiate();
        let out = c.take_output().unwrap();
        assert!(out.starts_with(PREFACE));
        // SETTINGS frame follows, and it turns the peer's dynamic table off
        let settings = &out[PREFACE.len()..];
        assert_eq!(settings[3], SETTINGS);
        assert_eq!(&settings[9..15], &[0, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn stream_ids_are_odd_and_ascending() {
        let mut c = connected();
        assert_eq!(c.start_stream(&blocks(), b""), Some(1));
        assert_eq!(c.start_stream(&blocks(), b""), Some(3));
        assert_eq!(c.start_stream(&blocks(), b""), Some(5));
    }

    #[test]
    fn response_in_one_headers_frame() {
        let mut c = connected();
        let id = c.start_stream(&blocks(), b"").unwrap();
        c.take_output();
        let mut events = Vec::new();
        let data = frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, id, &[0x88]);
        c.feed(&data, &mut events).unwrap();
        assert_eq!(events.len(), 2);
        match events[0] {
            Event::Status { stream_id, status } => {
                assert_eq!(stream_id, id);
                assert_eq!(status, 200);
            }
            _ => panic!("expected a status"),
        }
        assert!(matches!(events[1], Event::End { stream_id } if stream_id == id));
    }

    #[test]
    fn headers_then_data_completes_on_end_stream() {
        let mut c = connected();
        let id = c.start_stream(&blocks(), b"").unwrap();
        c.take_output();
        let mut events = Vec::new();
        let mut data = frame(HEADERS, FLAG_END_HEADERS, id, &[0x88]);
        data.extend_from_slice(&frame(DATA, 0, id, b"hello"));
        data.extend_from_slice(&frame(DATA, FLAG_END_STREAM, id, b" world"));
        c.feed(&data, &mut events).unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], Event::Status { status: 200, .. }));
        assert!(matches!(events[1], Event::End { .. }));
    }

    #[test]
    fn frames_split_at_every_offset() {
        let mut whole = frame(SETTINGS, 0, 0, &[]);
        whole.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &[0x88],
        ));
        for split in 1..whole.len() {
            let mut c = connected();
            c.start_stream(&blocks(), b"").unwrap();
            c.take_output();
            let mut events = Vec::new();
            c.feed(&whole[..split], &mut events).unwrap();
            c.feed(&whole[split..], &mut events).unwrap();
            assert_eq!(events.len(), 2, "split at {split}");
        }
    }

    #[test]
    fn continuation_is_reassembled() {
        let mut c = connected();
        let id = c.start_stream(&blocks(), b"").unwrap();
        c.take_output();
        let mut events = Vec::new();
        // ":status 200" is one byte, so split it around a preceding field
        let block = [0x00u8, 1, b'a', 1, b'b'];
        let mut data = frame(HEADERS, FLAG_END_STREAM, id, &block[..2]);
        data.extend_from_slice(&frame(CONTINUATION, 0, id, &block[2..]));
        data.extend_from_slice(&frame(CONTINUATION, FLAG_END_HEADERS, id, &[0x88]));
        c.feed(&data, &mut events).unwrap();
        assert!(matches!(events[0], Event::Status { status: 200, .. }));
    }

    #[test]
    fn ping_is_acknowledged() {
        let mut c = connected();
        let mut events = Vec::new();
        c.feed(&frame(PING, 0, 0, b"12345678"), &mut events)
            .unwrap();
        let out = c.take_output().unwrap();
        assert_eq!(out[3], PING);
        assert_eq!(out[4], FLAG_ACK);
        assert_eq!(&out[9..17], b"12345678");
    }

    #[test]
    fn settings_are_acknowledged_and_applied() {
        let mut c = connected();
        let mut events = Vec::new();
        let payload = [0, 3, 0, 0, 0, 2]; // MAX_CONCURRENT_STREAMS = 2
        c.feed(&frame(SETTINGS, 0, 0, &payload), &mut events)
            .unwrap();
        let out = c.take_output().unwrap();
        assert_eq!(out[3], SETTINGS);
        assert_eq!(out[4], FLAG_ACK);
        assert!(c.start_stream(&blocks(), b"").is_some());
        assert!(c.start_stream(&blocks(), b"").is_some());
        assert!(c.start_stream(&blocks(), b"").is_none(), "limit applies");
    }

    #[test]
    fn goaway_stops_new_streams() {
        let mut c = connected();
        let mut events = Vec::new();
        c.feed(&frame(GOAWAY, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]), &mut events)
            .unwrap();
        assert!(matches!(events[0], Event::Goaway));
        assert!(c.start_stream(&blocks(), b"").is_none());
    }

    #[test]
    fn padded_headers_are_trimmed() {
        let mut c = connected();
        let id = c.start_stream(&blocks(), b"").unwrap();
        c.take_output();
        let mut events = Vec::new();
        // One pad-length byte, the block, then two padding bytes
        let payload = [1u8, 0x88, 0, 0];
        c.feed(
            &frame(
                HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM | FLAG_PADDED,
                id,
                &payload,
            ),
            &mut events,
        )
        .unwrap();
        assert!(matches!(events[0], Event::Status { status: 200, .. }));
    }

    #[test]
    fn window_update_credit_is_returned_in_bulk() {
        let mut c = connected();
        let id = c.start_stream(&blocks(), b"").unwrap();
        c.take_output();
        let mut events = Vec::new();
        let body = vec![0u8; 16384];
        // Well short of the refresh threshold: no update yet
        for _ in 0..16 {
            c.feed(&frame(DATA, 0, id, &body), &mut events).unwrap();
        }
        assert!(c.take_output().is_none());
        c.recv_consumed = WINDOW_REFRESH - 1;
        c.feed(&frame(DATA, 0, id, &[0]), &mut events).unwrap();
        let out = c.take_output().unwrap();
        assert_eq!(out[3], WINDOW_UPDATE);
    }
}
