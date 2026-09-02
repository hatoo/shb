//! HTTP/2 client connection, sized for a load generator
//!
//! Only the parts a benchmark client exercises are implemented: open a stream
//! with a pre-encoded header block, read the response's `:status`, count the
//! body, and keep the flow-control windows out of the way. Priority, push and
//! anything to do with the dynamic HPACK table are declined at the SETTINGS
//! level rather than implemented.

use crate::inflight::Ring;
use anyhow::{Result, bail};

use super::hpack;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// The largest stream id there is: the field is 31 bits with the top one
/// reserved (RFC 9113 Section 5.1.1). Ours are the odd ones, so a connection
/// runs out after a billion requests - eleven hours at thirty thousand a
/// second, which a long run reaches.
const MAX_STREAM_ID: u32 = 0x7fff_ffff;
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
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
/// The frame size every peer must accept, and what to assume until it says
/// otherwise (RFC 9113 Section 6.5.2)
const DEFAULT_MAX_FRAME: u32 = 16384;
/// The largest a peer may ask for
const MAX_FRAME_CEILING: u32 = (1 << 24) - 1;

/// Largest window HTTP/2 allows
const MAX_WINDOW: u32 = (1 << 31) - 1;
/// How many streams to assume the peer allows until its SETTINGS says
///
/// RFC 9113 Section 6.5.2 makes the initial value unlimited, and taking that
/// literally means opening every stream the run asks for before the peer has
/// said what it will take: the first flight goes out with the client preface,
/// a round trip before its SETTINGS arrives. Servers refuse the excess, and a
/// run of 800 requests at 400 streams came back with 600 of them reset by
/// httpd, h2o and nghttpx alike. Their limit is 100, which is the usual one,
/// and assuming it costs nothing - the real figure arrives a round trip later
/// and the next fill uses it.
const ASSUMED_MAX_CONCURRENT: u32 = 100;
/// Receive-window credit to hand back in one go, once this much has been used
const WINDOW_REFRESH: u32 = 1 << 30;

/// What the worker needs to hear about
#[derive(Debug)]
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

/// A stream we have opened and not yet finished
struct OpenStream {
    id: u32,
    /// How much of the request body has gone out
    sent: usize,
    /// What this stream's flow-control window still allows
    window: i64,
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
    /// The streams opened and not yet finished. Identity matters: a server
    /// that answers without reading the request body follows the response with
    /// RST_STREAM, and that arrives after the stream has already ended.
    /// Retiring by count would take the slot of whichever stream happens to be
    /// open instead, and that stream's own end would then be dropped.
    open: Ring<OpenStream>,
    /// The peer's SETTINGS_MAX_CONCURRENT_STREAMS
    max_concurrent: u32,
    /// Our remaining connection-level send credit
    send_window: i64,
    /// The peer's SETTINGS_INITIAL_WINDOW_SIZE, the credit each new stream gets
    peer_initial_window: u32,
    /// The peer's SETTINGS_MAX_FRAME_SIZE. A header block or body larger than
    /// this has to be split, or the peer answers with FRAME_SIZE_ERROR
    peer_max_frame: u32,
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
            open: Ring::new(2, 1),
            max_concurrent: ASSUMED_MAX_CONCURRENT,
            send_window: 65535,
            peer_initial_window: 65535,
            peer_max_frame: DEFAULT_MAX_FRAME,
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
        !self.goaway
            && !self.stream_ids_exhausted()
            && (self.open.len() as u32) < self.max_concurrent
    }

    /// No id is left to hand out, so this connection cannot carry another
    /// request. RFC 9113 Section 5.1.1: open a new one.
    pub fn stream_ids_exhausted(&self) -> bool {
        self.next_id > MAX_STREAM_ID
    }

    /// Open a stream carrying `block` (and `body`), returning its id
    ///
    /// `block` is the header block built once by [`super::hpack::encode_request`].
    pub fn start_stream(&mut self, block: &[u8], body: &[u8]) -> Option<u32> {
        if !self.can_open() {
            return None;
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(2);
        let end_stream = if body.is_empty() { FLAG_END_STREAM } else { 0 };
        let max = self.peer_max_frame as usize;

        // A header block longer than one frame continues in CONTINUATION, and
        // only the last of them carries END_HEADERS
        let mut chunks = block.chunks(max).peekable();
        let mut first = true;
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none();
            let kind = if first { HEADERS } else { CONTINUATION };
            let mut flags = if last { FLAG_END_HEADERS } else { 0 };
            if first {
                flags |= end_stream;
            }
            self.frame_header(chunk.len(), kind, flags, id);
            self.out.extend_from_slice(chunk);
            first = false;
        }

        self.open.push(
            id as u64,
            OpenStream {
                id,
                sent: 0,
                window: self.peer_initial_window as i64,
            },
        );
        if !body.is_empty() {
            self.write_body(self.open.slot_count() - 1, body);
        }
        Some(id)
    }

    /// Send more of `body` on every stream a window has unblocked
    ///
    /// Called after reading from the socket, since that is where WINDOW_UPDATE
    /// arrives. A body larger than a window used to mean the request was never
    /// started at all, and nothing ever started it later: the run stopped with
    /// no error and no end.
    pub fn pump_bodies(&mut self, body: &[u8]) {
        if body.is_empty() {
            return;
        }
        for pos in 0..self.open.slot_count() {
            self.write_body(pos, body);
        }
    }

    /// Write what the connection window, the stream's window and the frame
    /// size between them allow. END_STREAM rides on the frame that finishes
    /// the body, so a body that leaves in pieces still ends exactly once.
    fn write_body(&mut self, pos: usize, body: &[u8]) {
        let max = self.peer_max_frame as usize;
        loop {
            // A hole: the stream in this slot has already finished
            let Some(s) = self.open.slot(pos) else {
                return;
            };
            let (id, sent, stream_window) = (s.id, s.sent, s.window);
            if sent >= body.len() {
                return;
            }
            let allowed = self.send_window.min(stream_window).max(0) as usize;
            let n = (body.len() - sent).min(max).min(allowed);
            if n == 0 {
                return;
            }
            let flags = if sent + n == body.len() {
                FLAG_END_STREAM
            } else {
                0
            };
            self.frame_header(n, DATA, flags, id);
            self.out.extend_from_slice(&body[sent..sent + n]);
            let Some(s) = self.open.slot_mut(pos) else {
                return;
            };
            s.sent += n;
            s.window -= n as i64;
            self.send_window -= n as i64;
        }
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
                    if self.finish_stream(stream) {
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
        if flags & FLAG_END_STREAM != 0 && self.finish_stream(stream) {
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
        // A section with no `:status` is trailers, and a 1xx is informational
        // and precedes the real response (RFC 9110 Section 15.2); neither is
        // the status this request gets answered with
        if let Some(status) = hpack::find_status(block)?
            && !crate::is_informational(status)
        {
            events.push(Event::Status {
                stream_id: stream,
                status,
            });
        }
        if end_stream && self.finish_stream(stream) {
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
        for entry in entries {
            let id = u16::from_be_bytes([entry[0], entry[1]]);
            let value = u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]);
            match id {
                SETTINGS_MAX_CONCURRENT_STREAMS => self.max_concurrent = value,
                // Our only use for this is deciding whether a request body
                // fits; responses ride on the huge window we advertise
                SETTINGS_INITIAL_WINDOW_SIZE if value <= MAX_WINDOW => {
                    // RFC 9113 Section 6.9.2: the change moves every open
                    // stream's window by the same amount, and may make one
                    // negative
                    let delta = value as i64 - self.peer_initial_window as i64;
                    self.peer_initial_window = value;
                    for s in self.open.iter_mut() {
                        s.window += delta;
                    }
                }
                SETTINGS_INITIAL_WINDOW_SIZE => bail!("SETTINGS_INITIAL_WINDOW_SIZE out of range"),
                SETTINGS_MAX_FRAME_SIZE
                    if (DEFAULT_MAX_FRAME..=MAX_FRAME_CEILING).contains(&value) =>
                {
                    self.peer_max_frame = value
                }
                SETTINGS_MAX_FRAME_SIZE => bail!("SETTINGS_MAX_FRAME_SIZE out of range"),
                _ => {}
            }
        }
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
        } else if let Some(s) = self.open.get_mut(stream as u64) {
            s.window += increment as i64;
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
    /// Retire `stream` if it is still open. False means it had already
    /// finished, which is ordinary: RST_STREAM routinely follows a response
    /// the peer has already ended.
    fn finish_stream(&mut self, stream: u32) -> bool {
        self.open.take(stream as u64).is_some()
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

    /// The frame header from RFC 9113 Section 4.1, asserted as bytes: a
    /// 24-bit length, the type, the flags, then a 31-bit stream id
    #[test]
    fn frame_headers_match_the_spec() {
        let mut c = connected();
        c.take_output();
        c.frame_header(0x010203, 0x7f, 0x2a, 0x0102_0304);
        assert_eq!(
            c.take_output().unwrap(),
            [0x01, 0x02, 0x03, 0x7f, 0x2a, 0x01, 0x02, 0x03, 0x04]
        );

        // A request is one HEADERS frame carrying the block, ending the stream
        let mut c = connected();
        assert_eq!(c.start_stream(&[0x82, 0x86], b""), Some(1));
        assert_eq!(
            c.take_output().unwrap(),
            [
                0,
                0,
                2,
                HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                0,
                0,
                0,
                1,
                0x82,
                0x86
            ]
        );
    }

    #[test]
    fn stream_ids_are_odd_and_ascending() {
        let mut c = connected();
        assert_eq!(c.start_stream(&[0x82], b""), Some(1));
        assert_eq!(c.start_stream(&[0x82], b""), Some(3));
        assert_eq!(c.start_stream(&[0x82], b""), Some(5));
    }

    #[test]
    fn response_in_one_headers_frame() {
        let mut c = connected();
        let id = c.start_stream(&[0x82], b"").unwrap();
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
        let id = c.start_stream(&[0x82], b"").unwrap();
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

    /// HPACK has no static entry for a 1xx, so a 103 arrives as a literal
    /// ":status" (static name index 8) with the value "103"
    #[test]
    fn interim_responses_do_not_become_the_status() {
        let mut c = connected();
        let id = c.start_stream(&[0x82], b"").unwrap();
        c.take_output();
        let mut events = Vec::new();
        let early = [0x08, 0x03, b'1', b'0', b'3'];
        let mut data = frame(HEADERS, FLAG_END_HEADERS, id, &early);
        data.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            id,
            &[0x88],
        ));
        c.feed(&data, &mut events).unwrap();
        // The 103 produces no status event at all, so the only one is the 200
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(matches!(events[0], Event::Status { status: 200, .. }));
        assert!(matches!(events[1], Event::End { .. }));
    }

    /// Trailers are a second HEADERS frame with no ":status"; treating that as
    /// a malformed response would tear down the whole connection
    #[test]
    fn trailers_do_not_overwrite_the_status() {
        let mut c = connected();
        let id = c.start_stream(&[0x82], b"").unwrap();
        c.take_output();
        let mut events = Vec::new();
        let mut data = frame(HEADERS, FLAG_END_HEADERS, id, &[0x88]);
        data.extend_from_slice(&frame(DATA, 0, id, b"hi"));
        // A literal field "abc: 1", with no :status anywhere
        let trailers = [0x00, 0x03, b'a', b'b', b'c', 0x01, b'1'];
        data.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            id,
            &trailers,
        ));
        c.feed(&data, &mut events).unwrap();
        assert_eq!(events.len(), 2, "{events:?}");
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
            c.start_stream(&[0x82], b"").unwrap();
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
        let id = c.start_stream(&[0x82], b"").unwrap();
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
        assert!(c.start_stream(&[0x82], b"").is_some());
        assert!(c.start_stream(&[0x82], b"").is_some());
        assert!(c.start_stream(&[0x82], b"").is_none(), "limit applies");
    }

    /// The id field is 31 bits with the top one reserved, so past the last id
    /// the reserved bit would go on the wire and the peer would see a stream
    /// it cannot have. A connection that has run out has to be replaced, so it
    /// refuses new streams the way one that got a GOAWAY does.
    #[test]
    fn a_connection_that_runs_out_of_stream_ids_opens_no_more() {
        let mut c = connected();
        c.next_id = MAX_STREAM_ID;
        assert_eq!(
            c.start_stream(&[0x82], b""),
            Some(MAX_STREAM_ID),
            "the last id is usable"
        );
        assert!(c.stream_ids_exhausted());
        assert!(!c.can_open());
        assert!(
            c.start_stream(&[0x82], b"").is_none(),
            "and there is no next"
        );
    }

    #[test]
    fn goaway_stops_new_streams() {
        let mut c = connected();
        let mut events = Vec::new();
        c.feed(&frame(GOAWAY, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]), &mut events)
            .unwrap();
        assert!(matches!(events[0], Event::Goaway));
        assert!(c.start_stream(&[0x82], b"").is_none());
    }

    #[test]
    fn padded_headers_are_trimmed() {
        let mut c = connected();
        let id = c.start_stream(&[0x82], b"").unwrap();
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
        let id = c.start_stream(&[0x82], b"").unwrap();
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
    #[test]
    fn a_late_reset_does_not_swallow_another_stream() {
        // A server that answers without reading the request body ends the
        // stream and then resets it. That RST_STREAM lands after the next
        // request has gone out, and retiring streams by count rather than by
        // id let it take the new stream's place: the new stream's own end was
        // then ignored and it never completed.
        let mut c = connected();
        let mut events = Vec::new();

        let first = c.start_stream(&[0x82], b"body").unwrap();
        c.feed(
            &frame(HEADERS, FLAG_END_HEADERS, first, &[0x88]),
            &mut events,
        )
        .unwrap();
        c.feed(&frame(DATA, FLAG_END_STREAM, first, b""), &mut events)
            .unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::End { stream_id } if *stream_id == first))
        );

        let second = c.start_stream(&[0x82], b"body").unwrap();
        // The reset for the finished stream arrives while `second` is open
        c.feed(&frame(RST_STREAM, 0, first, &[0, 0, 0, 0]), &mut events)
            .unwrap();

        events.clear();
        c.feed(
            &frame(HEADERS, FLAG_END_HEADERS, second, &[0x88]),
            &mut events,
        )
        .unwrap();
        c.feed(&frame(DATA, FLAG_END_STREAM, second, b""), &mut events)
            .unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::End { stream_id } if *stream_id == second)),
            "the second stream has to finish too, got {events:?}"
        );
    }
    /// Walk the DATA frames in `out` for `stream`, returning the bytes they
    /// carry and whether one of them ended the stream
    fn data_sent(out: &[u8], stream: u32) -> (usize, bool) {
        let mut pos = 0;
        let (mut bytes, mut ended) = (0, false);
        while pos + FRAME_HEADER_LEN <= out.len() {
            let len = u32::from_be_bytes([0, out[pos], out[pos + 1], out[pos + 2]]) as usize;
            let kind = out[pos + 3];
            let flags = out[pos + 4];
            let id = u32::from_be_bytes([out[pos + 5], out[pos + 6], out[pos + 7], out[pos + 8]]);
            if kind == DATA && id == stream {
                bytes += len;
                ended |= flags & FLAG_END_STREAM != 0;
            }
            pos += FRAME_HEADER_LEN + len;
        }
        (bytes, ended)
    }

    #[test]
    fn a_body_larger_than_the_window_leaves_as_credit_arrives() {
        // Both windows start at 65535. A body bigger than that used to mean
        // the stream was never opened, and nothing opened it later either.
        let mut c = connected();
        let body = vec![b'a'; 100_000];

        let id = c
            .start_stream(&[0x82], &body)
            .expect("the stream opens even though the body does not fit");
        let out = c.take_output().unwrap();
        let (sent, ended) = data_sent(&out, id);
        assert_eq!(sent, 65535, "only what the window allows goes out");
        assert!(!ended, "the stream cannot end with the body unfinished");

        // The peer reads the body and returns credit on both windows
        let mut events = Vec::new();
        let credit = 100_000u32.to_be_bytes();
        c.feed(&frame(WINDOW_UPDATE, 0, 0, &credit), &mut events)
            .unwrap();
        c.feed(&frame(WINDOW_UPDATE, 0, id, &credit), &mut events)
            .unwrap();
        c.pump_bodies(&body);

        let out = c.take_output().unwrap();
        let (rest, ended) = data_sent(&out, id);
        assert_eq!(sent + rest, body.len(), "the whole body goes out");
        assert!(ended, "the last frame ends the stream");
    }

    #[test]
    fn a_stream_window_alone_does_not_release_the_body() {
        // Credit on the stream is not credit on the connection; sending on the
        // strength of one alone would overrun the other
        let mut c = connected();
        let body = vec![b'a'; 100_000];
        let id = c.start_stream(&[0x82], &body).unwrap();
        c.take_output();

        let mut events = Vec::new();
        c.feed(
            &frame(WINDOW_UPDATE, 0, id, &100_000u32.to_be_bytes()),
            &mut events,
        )
        .unwrap();
        c.pump_bodies(&body);
        assert!(
            c.take_output().is_none(),
            "the connection window is still empty"
        );
    }
    #[test]
    fn no_more_streams_are_opened_than_a_silent_peer_is_likely_to_take() {
        // The first flight goes out with the client preface, a round trip
        // before the peer's SETTINGS arrives, so "unlimited until told
        // otherwise" means opening every stream the run asks for and having
        // the excess refused. 800 requests at 400 streams came back with 600
        // of them reset by httpd, h2o and nghttpx.
        let mut c = Connection::new();
        c.initiate();
        let mut opened = 0;
        while c.start_stream(&[0x82], b"").is_some() {
            opened += 1;
            assert!(opened <= 1000, "start_stream never refuses");
        }
        assert_eq!(opened, ASSUMED_MAX_CONCURRENT as usize);

        // And the peer's own figure replaces it as soon as it says
        let mut events = Vec::new();
        let mut payload = Vec::new();
        payload.extend_from_slice(&SETTINGS_MAX_CONCURRENT_STREAMS.to_be_bytes());
        payload.extend_from_slice(&300u32.to_be_bytes());
        c.feed(&frame(SETTINGS, 0, 0, &payload), &mut events)
            .unwrap();
        assert!(c.can_open(), "the peer allows more than we assumed");
    }
}
