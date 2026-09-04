//! HTTP/2 client connection, sized for a load generator
//!
//! Only the parts a benchmark client exercises are implemented: open a stream
//! with a pre-encoded header block, read the response's `:status`, count the
//! body, and keep the flow-control windows out of the way. Priority and push
//! are declined at the SETTINGS level rather than implemented, and the dynamic
//! HPACK table is never written to - though the peer has to be told so when
//! it shrinks its side of it.

use crate::inflight::H2Ring;
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

/// The RST_STREAM code for a stream the peer would not take on at all
/// (RFC 9113 Section 7); every other code is a stream that went wrong
const REFUSED_STREAM: u32 = 0x7;

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
/// The dynamic table size a peer starts out allowing (RFC 9113 Section 6.5.2)
const DEFAULT_HEADER_TABLE_SIZE: u32 = 4096;
/// How many streams to assume the peer allows until its SETTINGS says
///
/// RFC 9113 Section 6.5.2 makes the initial value unlimited, and taking that
/// literally means opening every stream the run asks for before the peer has
/// said what it will take: the first flight goes out with the client preface,
/// a round trip before its SETTINGS arrives. Servers refuse the excess, and a
/// run of 800 requests at 400 streams came back with 600 of them reset by
/// httpd, h2o and nghttpx alike. Their limit is 100, which is the usual one,
/// and assuming it costs nothing - the real figure arrives a round trip later
/// and the next fill uses it. It stands in for the peer's first SETTINGS and
/// no longer: one that arrives without naming a limit has set none, and the
/// assumption gives way to the unlimited the specification starts from.
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
    /// The peer never acted on this stream, so the request is not lost: it
    /// can be sent again as if for the first time (RFC 9113 Section 8.7)
    Unprocessed { stream_id: u32 },
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
    /// The last buffer the sender finished with, waiting to become `out` again
    spare: Vec<u8>,
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
    open: H2Ring<OpenStream>,
    /// The peer's SETTINGS_MAX_CONCURRENT_STREAMS
    max_concurrent: u32,
    /// Whether `max_concurrent` is still the assumption rather than the
    /// peer's word, which its first SETTINGS gives - by naming a figure, or
    /// by naming none
    max_concurrent_assumed: bool,
    /// Our remaining connection-level send credit
    send_window: i64,
    /// The peer's SETTINGS_INITIAL_WINDOW_SIZE, the credit each new stream gets
    peer_initial_window: u32,
    /// The peer's SETTINGS_MAX_FRAME_SIZE. A header block or body larger than
    /// this has to be split, or the peer answers with FRAME_SIZE_ERROR
    peer_max_frame: u32,
    /// Bytes received against the connection window since the last update
    recv_consumed: u32,
    /// The dynamic table our encoder is entitled to, as far as the peer
    /// knows. Nothing is ever put in it, but the peer's decoder cannot know
    /// that: when its SETTINGS_HEADER_TABLE_SIZE drops below this it expects
    /// the next header block to open by shrinking the table to fit (RFC 7541
    /// Section 4.2), and nghttp2 rejects the block if it does not
    table_size: u32,
    /// A shrink the peer is owed, to go at the start of the next header block
    table_size_update: Option<u32>,
    /// A GOAWAY has been received
    goaway: bool,
    /// The peer's preface - its first SETTINGS - has arrived. Until it has,
    /// nothing else may (RFC 9113 Section 3.4).
    peer_preface_seen: bool,
}

impl Connection {
    pub fn new() -> Self {
        Connection {
            out: Vec::with_capacity(4096),
            spare: Vec::new(),
            pending: Vec::new(),
            header_block: Vec::new(),
            header_stream: 0,
            header_end_stream: false,
            next_id: 1,
            open: H2Ring::new(),
            max_concurrent: ASSUMED_MAX_CONCURRENT,
            max_concurrent_assumed: true,
            send_window: 65535,
            peer_initial_window: 65535,
            peer_max_frame: DEFAULT_MAX_FRAME,
            recv_consumed: 0,
            table_size: DEFAULT_HEADER_TABLE_SIZE,
            table_size_update: None,
            goaway: false,
            peer_preface_seen: false,
        }
    }

    /// Queue the client preface, our settings and the connection window bump
    ///
    /// In front of anything already queued. The peer may have spoken first:
    /// TLS 1.3 lets a server send its SETTINGS along with its Finished,
    /// before the client's Finished has reached it, so over TLS the frames
    /// that complete the handshake can carry the server preface too, and its
    /// acknowledgement is queued before this is called. Jetty and AWS's load
    /// balancer both do this, and both closed the connection when the ACK
    /// arrived where the preface should be.
    pub fn initiate(&mut self) {
        let peer_drew = std::mem::take(&mut self.out);
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
        self.out.extend_from_slice(&peer_drew);
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

        // A shrink the peer is owed goes in front of this block and no other,
        // so the join is paid once per SETTINGS change rather than per request
        let shrunk;
        let block = match self.table_size_update.take() {
            Some(size) => {
                let mut joined = Vec::with_capacity(4 + block.len());
                hpack::size_update(&mut joined, size);
                joined.extend_from_slice(block);
                shrunk = joined;
                &shrunk[..]
            }
            None => block,
        };

        if block.len() <= max {
            // What every request the run sends looks like: one HEADERS frame
            // carrying the whole block. Growing the buffer once for the header
            // and the block together keeps it to a single capacity check.
            self.out.reserve(FRAME_HEADER_LEN + block.len());
            self.frame_header(block.len(), HEADERS, FLAG_END_HEADERS | end_stream, id);
            self.out.extend_from_slice(block);
        } else {
            // A header block longer than one frame continues in CONTINUATION,
            // and only the last of them carries END_HEADERS
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
            // Leave whatever came back from the last send in its place, so the
            // requests written between now and the next flush go into a buffer
            // that is already the size they need
            Some(std::mem::replace(
                &mut self.out,
                std::mem::take(&mut self.spare),
            ))
        }
    }

    /// Take back a buffer that has finished sending. Handing it to the sender
    /// left `out` empty, and allocating that back per flush was the largest
    /// single allocation the run made.
    pub fn recycle(&mut self, mut buf: Vec<u8>) {
        if buf.capacity() > self.spare.capacity() {
            buf.clear();
            self.spare = buf;
        }
    }

    /// Queue a GOAWAY, so a clean teardown is not logged as an error by the peer
    ///
    /// The last stream id is the highest one the *peer* opened that we will
    /// still act on (RFC 9113 Section 6.8), not the highest of ours. Push is
    /// off, so the peer never opened one and the field is 0 - what curl and
    /// h2load send. Naming our own last stream put an odd id there, and
    /// nghttp2 logged a protocol error for every session shb closed.
    pub fn send_goaway(&mut self) {
        self.frame_header(8, GOAWAY, 0, 0);
        self.out.extend_from_slice(&0u32.to_be_bytes());
        self.out.extend_from_slice(&0u32.to_be_bytes());
    }

    fn frame_header(&mut self, len: usize, kind: u8, flags: u8, stream: u32) {
        let len = (len as u32).to_be_bytes();
        let stream = stream.to_be_bytes();
        // One append rather than two: the header is nine bytes and splitting it
        // buys a second capacity check and a second copy for no reason
        self.out.extend_from_slice(&[
            len[1], len[2], len[3], kind, flags, stream[0], stream[1], stream[2], stream[3],
        ]);
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
        // What a server that does not speak HTTP/2 sends back to the preface
        // is an HTTP/1.1 status line, and read as a frame that is 4.7 MB of
        // type 0x54 that never finishes arriving: python -m http.server
        // answered with a 501 and the run ended with every request an error
        // and nothing said. It is recognisable from its first five bytes.
        if !self.peer_preface_seen && buf.starts_with(b"HTTP/") {
            bail!("server answered the HTTP/2 preface with HTTP/1.1; is h2c enabled?");
        }
        let mut pos = 0;
        while buf.len() - pos >= FRAME_HEADER_LEN {
            let h = &buf[pos..pos + FRAME_HEADER_LEN];
            // The length is the top three bytes of the frame header and the
            // type is the fourth, so one 32-bit load carries both
            let head = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
            let len = (head >> 8) as usize;
            let kind = head as u8;
            let flags = h[4];
            let stream = u32::from_be_bytes([h[5] & 0x7f, h[6], h[7], h[8]]);

            // The server's preface is a SETTINGS frame, and it MUST be the
            // first frame it sends; anything else is a connection error of
            // type PROTOCOL_ERROR (RFC 9113 Section 3.4). Its ACK of ours
            // does not count, which is how nghttp2 reads it too. Judged from
            // the header rather than the whole frame, since what is not a
            // frame at all tends to claim megabytes that never arrive: this
            // python's http.server answers the preface with an HTML page and
            // no status line.
            if !self.peer_preface_seen {
                if kind != SETTINGS || flags & FLAG_ACK != 0 {
                    bail!(
                        "server's first frame is not SETTINGS (type {kind:#x}); is it speaking HTTP/2?"
                    );
                }
                self.peer_preface_seen = true;
            }

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
                RST_STREAM => self.on_rst_stream(stream, payload, events)?,
                GOAWAY => self.on_goaway(payload, events)?,
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
                // The encoder never grows into a raised limit, so only a cut
                // below what it has is anything to act on; and once it has
                // been cut, a later cut to the same figure owes nothing
                SETTINGS_HEADER_TABLE_SIZE if value < self.table_size => {
                    self.table_size = value;
                    self.table_size_update = Some(value);
                }
                SETTINGS_MAX_CONCURRENT_STREAMS => {
                    self.max_concurrent = value;
                    self.max_concurrent_assumed = false;
                }
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
        // The peer has now said what it will take, and if that said nothing
        // about streams it takes any number: the limit is unlimited until a
        // SETTINGS sets it (RFC 9113 Section 6.5.2), and this one has not.
        // nghttp2 lifts its own guess of 100 the same way. Node's default
        // server sends an empty SETTINGS, and a run at 200 streams a
        // connection was held to 100 of them for its whole length.
        if self.max_concurrent_assumed {
            self.max_concurrent = u32::MAX;
            self.max_concurrent_assumed = false;
        }
        self.frame_header(0, SETTINGS, FLAG_ACK, 0);
        Ok(())
    }

    /// REFUSED_STREAM means the peer never acted on the stream (RFC 9113
    /// Section 8.7), so the request goes back rather than into the error
    /// count. Any other code is a stream that went wrong, and stays an
    /// error.
    ///
    /// A refusal used to lower the stream limit assumed before the peer's
    /// SETTINGS arrived. Nothing can arrive before that SETTINGS now - it
    /// has to be the peer's first frame - so by the time a refusal is read
    /// the peer has said what it takes, or said nothing and takes any
    /// number, and a refusal is then its own to explain.
    fn on_rst_stream(
        &mut self,
        stream: u32,
        payload: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<()> {
        if payload.len() != 4 {
            bail!("malformed RST_STREAM");
        }
        let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if self.finish_stream(stream) {
            events.push(if code == REFUSED_STREAM {
                Event::Unprocessed { stream_id: stream }
            } else {
                Event::Reset { stream_id: stream }
            });
        }
        Ok(())
    }

    /// The last stream id says which of our streams the peer will still
    /// answer: everything above it was never looked at (RFC 9113 Section
    /// 6.8), and nginx sends one for every keepalive_requests-th connection
    /// with a window's worth of streams above the line. Those are retired
    /// here as unprocessed rather than left to be failed when the peer
    /// closes; the ones at or below the line are answered in the ordinary
    /// way, and the connection is replaced once they have been.
    fn on_goaway(&mut self, payload: &[u8], events: &mut Vec<Event>) -> Result<()> {
        if payload.len() < 8 {
            bail!("malformed GOAWAY");
        }
        let last = u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
        // The error code follows; a load generator has no different answer
        // to a GOAWAY that blames it than to one that does not
        self.goaway = true;
        let unprocessed: Vec<u32> = self
            .open
            .iter()
            .filter(|s| s.id > last)
            .map(|s| s.id)
            .collect();
        for id in unprocessed {
            self.open.take(id as u64);
            events.push(Event::Unprocessed { stream_id: id });
        }
        events.push(Event::Goaway);
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

    /// Our preface sent, and nothing heard from the peer yet
    fn preface_sent() -> Connection {
        let mut c = Connection::new();
        c.initiate();
        c.take_output();
        c
    }

    /// Both prefaces exchanged: ours out, the peer's empty SETTINGS in
    fn connected() -> Connection {
        let mut c = preface_sent();
        c.feed(&frame(SETTINGS, 0, 0, &[]), &mut Vec::new())
            .unwrap();
        c.take_output();
        c
    }

    /// python -m http.server answers the preface with "HTTP/1.1 501", which
    /// read as a frame header is 4.7 MB of type 0x54 that never finishes
    /// arriving; the run ended with every request an error and nothing said
    #[test]
    fn an_http1_answer_to_the_preface_is_named() {
        let mut c = preface_sent();
        let mut events = Vec::new();
        let err = c
            .feed(b"HTTP/1.1 501 Unsupported method ('PRI')\r\n", &mut events)
            .unwrap_err();
        assert!(err.to_string().contains("h2c"), "{err}");

        // However it arrives
        let mut c = preface_sent();
        c.feed(b"HT", &mut events).unwrap();
        c.feed(b"TP/1.1 400 Bad Request\r\n", &mut events)
            .unwrap_err();
    }

    /// RFC 9113 Section 3.4: the server's preface is a SETTINGS frame, and
    /// it MUST be the first frame the server sends
    #[test]
    fn the_servers_first_frame_must_be_its_settings() {
        let mut events = Vec::new();
        let mut c = preface_sent();
        assert!(
            c.feed(&frame(PING, 0, 0, b"12345678"), &mut events)
                .is_err()
        );
        // Its ACK of our SETTINGS is not its preface
        let mut c = preface_sent();
        assert!(
            c.feed(&frame(SETTINGS, FLAG_ACK, 0, &[]), &mut events)
                .is_err()
        );
        // After its SETTINGS anything goes
        let mut c = preface_sent();
        let mut data = frame(SETTINGS, 0, 0, &[]);
        data.extend_from_slice(&frame(PING, 0, 0, b"12345678"));
        c.feed(&data, &mut events).unwrap();

        // Judged from the header: an HTML page read as a frame claims 3.9 MB
        // of type 'O', and waiting for the rest of it is waiting for ever
        let mut c = preface_sent();
        assert!(c.feed(b"<!DOCTYPE HTML>\n<html>", &mut events).is_err());
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

    /// Over TLS 1.3 the server's SETTINGS can arrive with the frames that
    /// finish the handshake, before the preface has been queued; the ACK it
    /// draws has to follow the preface, not lead it. Jetty and AWS's load
    /// balancer both send it that early, and both closed the connection.
    #[test]
    fn a_peer_that_speaks_first_is_answered_after_the_preface() {
        let mut c = Connection::new();
        let mut events = Vec::new();
        c.feed(&frame(SETTINGS, 0, 0, &[]), &mut events).unwrap();
        c.initiate();
        let out = c.take_output().unwrap();
        assert!(out.starts_with(PREFACE));
        let ack = &out[out.len() - FRAME_HEADER_LEN..];
        assert_eq!(ack[3], SETTINGS);
        assert_eq!(ack[4], FLAG_ACK);
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

    /// Node with `headerTableSize: 0` answered the first flight and nothing
    /// after it: its SETTINGS cut the table below the 4096 an encoder starts
    /// with, and nghttp2 then demands that the next header block open with a
    /// size update (RFC 7541 Section 4.2), timing out every request whose
    /// block does not.
    #[test]
    fn a_lower_header_table_size_opens_the_next_block_with_a_size_update() {
        let mut c = connected();
        let mut events = Vec::new();
        let mut settings = |c: &mut Connection, size: u32| {
            let mut payload = SETTINGS_HEADER_TABLE_SIZE.to_be_bytes().to_vec();
            payload.extend_from_slice(&size.to_be_bytes());
            c.feed(&frame(SETTINGS, 0, 0, &payload), &mut events)
                .unwrap();
            c.take_output();
        };
        let headers_payload = |c: &mut Connection| {
            let out = c.take_output().unwrap();
            assert_eq!(out[3], HEADERS);
            out[FRAME_HEADER_LEN..].to_vec()
        };

        settings(&mut c, 0);
        c.start_stream(&[0x82, 0x86], b"").unwrap();
        assert_eq!(
            headers_payload(&mut c),
            [0x20, 0x82, 0x86],
            "the block opens with a size update to 0"
        );
        c.start_stream(&[0x82, 0x86], b"").unwrap();
        assert_eq!(
            headers_payload(&mut c),
            [0x82, 0x86],
            "said once, it is not said again"
        );

        // Raising the limit obliges the encoder to nothing, and neither does
        // lowering it back to where the encoder already is
        settings(&mut c, 4096);
        settings(&mut c, 0);
        c.start_stream(&[0x82], b"").unwrap();
        assert_eq!(headers_payload(&mut c), [0x82]);

        // A peer that cuts to something above zero is told that figure
        let mut c = connected();
        settings(&mut c, 2048);
        c.start_stream(&[0x82], b"").unwrap();
        assert_eq!(headers_payload(&mut c), [0x3f, 0xe1, 0x0f, 0x82]);
        // A cut below that is owed again, since the encoder sat at 2048
        settings(&mut c, 1024);
        c.start_stream(&[0x82], b"").unwrap();
        assert_eq!(headers_payload(&mut c), [0x3f, 0xe1, 0x07, 0x82]);
    }

    /// The size update counts towards the frame the block is split over
    #[test]
    fn a_size_update_is_split_with_the_block_it_opens() {
        let mut c = connected();
        let mut events = Vec::new();
        c.feed(&frame(SETTINGS, 0, 0, &[0, 1, 0, 0, 0, 0]), &mut events)
            .unwrap();
        c.take_output();
        c.peer_max_frame = 16;
        let block = [0x00u8; 20];
        c.start_stream(&block, b"").unwrap();
        let out = c.take_output().unwrap();
        // HEADERS carrying 16 bytes, then CONTINUATION with the last 5
        assert_eq!(out[..4], [0, 0, 16, HEADERS]);
        assert_eq!(out[FRAME_HEADER_LEN], 0x20, "the update leads");
        let rest = &out[FRAME_HEADER_LEN + 16..];
        assert_eq!(rest[..5], [0, 0, 5, CONTINUATION, FLAG_END_HEADERS]);
        assert_eq!(rest.len(), FRAME_HEADER_LEN + 5);
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

    /// nginx with keepalive_requests 20 and 32 streams in flight: the GOAWAY
    /// names stream 39, and 1, 3 .. 39 are still answered while 41 onwards
    /// never were. Those come back as unprocessed the moment the GOAWAY is
    /// read, and the answered ones end as they always did.
    #[test]
    fn goaway_gives_back_the_streams_above_its_last_stream_id() {
        let mut c = connected();
        let mut events = Vec::new();
        for _ in 0..4 {
            c.start_stream(&[0x82], b"").unwrap();
        }
        c.take_output();
        // Last stream 3, NO_ERROR
        c.feed(&frame(GOAWAY, 0, 0, &[0, 0, 0, 3, 0, 0, 0, 0]), &mut events)
            .unwrap();
        let unprocessed: Vec<u32> = events
            .iter()
            .filter_map(|e| match e {
                Event::Unprocessed { stream_id } => Some(*stream_id),
                _ => None,
            })
            .collect();
        assert_eq!(unprocessed, [5, 7]);
        assert!(matches!(events.last(), Some(Event::Goaway)));

        // 1 and 3 are still the peer's to answer
        events.clear();
        c.feed(
            &frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, &[0x88]),
            &mut events,
        )
        .unwrap();
        assert!(
            matches!(events[1], Event::End { stream_id: 3 }),
            "{events:?}"
        );
        // And a late answer on a stream given back is not a second ending
        events.clear();
        c.feed(
            &frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 5, &[0x88]),
            &mut events,
        )
        .unwrap();
        assert!(
            !events.iter().any(|e| matches!(e, Event::End { .. })),
            "{events:?}"
        );
    }

    /// Node with maxConcurrentStreams: 8 refused 92 of the 100 streams in
    /// the first flight, and every one was an error. A refusal is not an
    /// answer: the request goes back to be sent again.
    #[test]
    fn a_refused_stream_is_given_back() {
        let mut c = connected();
        let mut events = Vec::new();
        for _ in 0..12 {
            c.start_stream(&[0x82], b"").unwrap();
        }
        c.take_output();
        c.feed(
            &frame(RST_STREAM, 0, 17, &REFUSED_STREAM.to_be_bytes()),
            &mut events,
        )
        .unwrap();
        assert!(
            matches!(events[..], [Event::Unprocessed { stream_id: 17 }]),
            "{events:?}"
        );

        // Any other code is a stream that went wrong
        events.clear();
        c.feed(&frame(RST_STREAM, 0, 21, &[0, 0, 0, 8]), &mut events)
            .unwrap();
        assert!(
            matches!(events[..], [Event::Reset { stream_id: 21 }]),
            "{events:?}"
        );
    }

    #[test]
    fn a_short_rst_stream_is_malformed() {
        let mut c = connected();
        let mut events = Vec::new();
        assert!(
            c.feed(&frame(RST_STREAM, 0, 1, &[0, 0, 7]), &mut events)
                .is_err()
        );
    }

    #[test]
    fn a_short_goaway_is_malformed() {
        let mut c = connected();
        let mut events = Vec::new();
        assert!(
            c.feed(&frame(GOAWAY, 0, 0, &[0, 0, 0, 1]), &mut events)
                .is_err()
        );
    }

    /// A client has no stream of the server's to name, so the field is 0
    /// whatever it has opened itself
    #[test]
    fn our_goaway_names_no_stream() {
        let mut c = connected();
        c.start_stream(&[0x82], b"").unwrap();
        c.start_stream(&[0x82], b"").unwrap();
        c.take_output();
        c.send_goaway();
        let out = c.take_output().unwrap();
        assert_eq!(out[3], GOAWAY);
        assert_eq!(
            &out[FRAME_HEADER_LEN..],
            &[0u8; 8],
            "last stream 0, NO_ERROR"
        );
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
