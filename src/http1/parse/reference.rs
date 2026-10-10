// Frozen production parser from fede6eb (before skipping partial fields).
//! Minimal HTTP/1.1 response scanner
//!
//! A load generator only needs to know where one response ends and the next
//! begins, plus the status code to tally. This scanner therefore reads the
//! status line, `Content-Length` and `Transfer-Encoding`, and skips every
//! other header without looking at it — no field-name validation, no UTF-8
//! checks, no allocation per header line.
//!
//! It does read `Connection` and the HTTP version, because getting connection
//! reuse wrong is not a matter of speed: against an HTTP/1.0 server that closes
//! after every response, assuming keep-alive makes every second request fail.
//! That check costs one extra name comparison on lines starting with `c`.

use anyhow::{Context, Result, bail};
use memchr::memchr;

/// How the body of the response being read is delimited
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Body {
    /// `Content-Length` bytes remain
    Exact(u64),
    /// Reading the hex size line of the next chunk
    ChunkSize,
    /// Bytes remaining in the current chunk, its trailing CRLF included
    ///
    /// Counting the CRLF here rather than adding it on each pass is what lets
    /// a read that stops *inside* that CRLF leave a correct remainder
    Chunk(u64),
    /// Reading trailers after the zero-sized chunk
    Trailers,
    /// Neither framing header was present: the body ends with the connection
    Eof,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Between messages, or partway through a status line / header block
    Head,
    Body(Body),
}

pub struct Parser {
    /// Bytes of one incomplete line carried over from earlier receives.
    /// Empty in the common case, which lets [`Parser::feed`] parse straight
    /// out of the receive buffer with no copy at all.
    pending: Vec<u8>,
    state: State,
    /// Framing metadata is needed only while a header block is incomplete.
    partial_head: Option<Head>,
    /// Status code of the response being read, which is the last completed
    /// one for as long as the caller only asks after one completes
    status: u16,
    /// Whether the connection can be reused after that response
    keep_alive: bool,
    /// Whether the request was a HEAD, whose response never has a body
    /// however it is framed (RFC 9112 Section 6.3)
    head_request: bool,
}

impl Default for Parser {
    fn default() -> Self {
        Parser::new()
    }
}

impl Parser {
    pub fn new() -> Self {
        Parser {
            pending: Vec::new(),
            state: State::Head,
            partial_head: None,
            status: 0,
            keep_alive: true,
            head_request: false,
        }
    }

    /// Forget any partially received message (called when reconnecting)
    pub fn reset(&mut self) {
        self.pending.clear();
        self.partial_head = None;
        self.state = State::Head;
        self.status = 0;
        self.keep_alive = true;
    }

    /// Tell the parser whether responses answer HEAD requests
    pub fn set_head_request(&mut self, head: bool) {
        self.head_request = head;
    }

    /// Status code of the most recently completed response
    ///
    /// Only meaningful once one has: it is filled in from the status line, so
    /// between a response's head arriving and its body finishing it is that
    /// response's rather than the one before it. [`Parser::feed`] returning
    /// non-zero, or [`Parser::mark_eof`] returning true, is what says one has
    /// completed - which is the only place either caller reads this.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Whether the connection may carry another request after the most
    /// recently completed response. Read under the same rule as
    /// [`Parser::status`].
    pub fn keep_alive(&self) -> bool {
        self.keep_alive
    }

    /// Consume received bytes and return how many responses completed
    ///
    /// Whatever is left over is retained for the next call.
    pub fn feed(&mut self, data: &[u8]) -> Result<usize> {
        if self.pending.is_empty() {
            // Fast path: parse in place out of the caller's buffer and copy
            // only a trailing partial message, if there is one
            let (used, done) = self.run(data)?;
            if used < data.len() {
                self.pending.extend_from_slice(&data[used..]);
            }
            return Ok(done);
        }
        // `run` consumes every complete line, so pending contains just one
        // unfinished status, header, chunk-size or trailer line. Search only
        // the newly received bytes: a long line must not be rescanned on every
        // receive. Append only through its newline, then parse the rest of
        // this receive in place (including any response body).
        let Some(nl) = memchr(b'\n', data) else {
            self.pending.extend_from_slice(data);
            return Ok(0);
        };
        let mut line = std::mem::take(&mut self.pending);
        line.extend_from_slice(&data[..=nl]);
        let (used, done) = self.run(&line)?;
        debug_assert_eq!(used, line.len());
        line.clear();
        self.pending = line;
        let (used, more) = self.run(&data[nl + 1..])?;
        self.pending.extend_from_slice(&data[nl + 1 + used..]);
        Ok(done + more)
    }

    /// Signal that the peer closed the connection
    ///
    /// Returns true if that completed a close-delimited response.
    pub fn mark_eof(&mut self) -> bool {
        if self.state == State::Body(Body::Eof) {
            self.state = State::Head;
            self.keep_alive = false;
            true
        } else {
            false
        }
    }

    /// Advance over `buf`, returning (bytes consumed, responses completed)
    fn run(&mut self, buf: &[u8]) -> Result<(usize, usize)> {
        let mut pos = 0;
        let mut done = 0;
        loop {
            match self.state {
                State::Head => {
                    let (used, complete) = scan_head(&buf[pos..], &mut self.partial_head)?;
                    pos += used;
                    let Some(ResponseHead {
                        status,
                        body,
                        keep_alive,
                    }) = complete
                    else {
                        return Ok((pos, done));
                    };
                    if crate::is_informational(status) {
                        if status == 101 {
                            // The connection stops being HTTP/1.1 here, and a
                            // load generator has nothing to switch to
                            bail!("unexpected 101 Switching Protocols");
                        }
                        self.state = State::Head;
                        // An interim response carries no body and does not
                        // finish the message: keep reading for the final one
                        // (RFC 9110 Section 15.2)
                        continue;
                    }
                    self.status = status;
                    let body = if self.head_request || no_body_status(status) {
                        Body::Exact(0)
                    } else {
                        body
                    };
                    // A close-delimited body ends with the connection itself.
                    // Decided on the body as it will actually be read: a 204
                    // or a HEAD response without Content-Length ends at the
                    // empty line, not at the close its headers would imply
                    // (RFC 9112 Section 6.3), and nginx sends its 204s that way
                    self.keep_alive = keep_alive && body != Body::Eof;
                    self.state = State::Body(body);
                }
                State::Body(Body::Exact(0)) => {
                    self.state = State::Head;
                    done += 1;
                }
                State::Body(Body::Exact(n)) => {
                    let avail = (buf.len() - pos) as u64;
                    let take = n.min(avail);
                    pos += take as usize;
                    self.state = State::Body(Body::Exact(n - take));
                    if take == avail && n > take {
                        return Ok((pos, done));
                    }
                }
                State::Body(Body::ChunkSize) => {
                    let Some(nl) = memchr(b'\n', &buf[pos..]) else {
                        return Ok((pos, done));
                    };
                    let size = parse_chunk_size(trim_cr(&buf[pos..pos + nl]))?;
                    pos += nl + 1;
                    self.state = State::Body(if size == 0 {
                        Body::Trailers
                    } else {
                        // The data plus its terminating CRLF
                        let want = size.checked_add(2).context("chunk size overflow")?;
                        Body::Chunk(want)
                    });
                }
                State::Body(Body::Chunk(n)) => {
                    let avail = (buf.len() - pos) as u64;
                    let take = n.min(avail);
                    pos += take as usize;
                    let left = n - take;
                    if left < 2 && take != 0 {
                        // Validate only the terminator bytes in this receive,
                        // including a receive split between CR and LF.
                        let end = (2 - left) as usize;
                        let len = take.min(end as u64) as usize;
                        if buf[pos - len..pos] != b"\r\n"[end - len..end] {
                            bail!("invalid chunk terminator");
                        }
                    }
                    if take < n {
                        self.state = State::Body(Body::Chunk(n - take));
                        return Ok((pos, done));
                    }
                    self.state = State::Body(Body::ChunkSize);
                }
                State::Body(Body::Trailers) => {
                    // Trailer lines, ended by an empty one
                    let Some(nl) = memchr(b'\n', &buf[pos..]) else {
                        return Ok((pos, done));
                    };
                    let line = trim_cr(&buf[pos..pos + nl]);
                    pos += nl + 1;
                    if line.is_empty() {
                        self.state = State::Head;
                        done += 1;
                    }
                }
                State::Body(Body::Eof) => {
                    // Everything received belongs to the body; it ends at EOF
                    return Ok((buf.len(), done));
                }
            }
        }
    }
}

/// Responses that never carry a body, whatever the framing headers say
///
/// 1xx is handled before this: an interim response does not finish the message
/// at all.
fn no_body_status(status: u16) -> bool {
    status == 204 || status == 304
}

/// Metadata from complete header lines. No header bytes are needed again once
/// their framing and connection tokens have been read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Head {
    content_length: Option<u64>,
    status: u16,
    http_1_0: bool,
    te_present: bool,
    te_chunked: bool,
    close: bool,
    keep_alive_token: bool,
}

struct ResponseHead {
    status: u16,
    body: Body,
    keep_alive: bool,
}

/// Consume complete lines, keeping metadata across receives. The unconsumed
/// suffix is at most one incomplete line. Publish status/connection semantics
/// only once the entire header block is complete, just as for a single receive.
fn scan_head(buf: &[u8], partial: &mut Option<Head>) -> Result<(usize, Option<ResponseHead>)> {
    let (mut head, mut pos) = if let Some(head) = partial.take() {
        (head, 0)
    } else {
        let Some(nl) = memchr(b'\n', buf) else {
            return Ok((0, None));
        };
        // "HTTP/1.1 200 OK": HTTP-version SP status-code SP reason-phrase, the
        // version being "HTTP/1." and one digit (RFC 9112 Section 4), so the
        // status code is always at the same offset. The line runs at least to
        // the end of the code, and the newline found above says it is all here.
        if nl < 12 || !buf.starts_with(b"HTTP/1.") {
            bail!("not an HTTP/1.x response");
        }
        let http_1_0 = match buf[7] {
            b'0' => true,
            b'1' => false,
            // "HTTP/1.9", or a two-digit minor that happened to start with a 1
            _ => bail!("unsupported HTTP version"),
        };
        if buf[8] != b' ' {
            bail!("malformed status line");
        }
        let status = parse_status(&buf[9..12])?;
        // A space and the reason phrase follow, but some servers send the code
        // and the line ending alone, and that is readable; a fourth digit is not
        match buf[12] {
            b' ' | b'\r' | b'\n' => {}
            _ => bail!("malformed status line"),
        }
        (
            Head {
                content_length: None,
                status,
                http_1_0,
                te_present: false,
                te_chunked: false,
                close: false,
                keep_alive_token: false,
            },
            nl + 1,
        )
    };
    loop {
        let Some(rel) = memchr(b'\n', &buf[pos..]) else {
            *partial = Some(head);
            return Ok((pos, None));
        };
        let line = trim_cr(&buf[pos..pos + rel]);
        pos += rel + 1;
        if line.is_empty() {
            // Transfer-Encoding overrides Content-Length; its final coding
            // decides whether the body is chunked or close-delimited.
            let body = if head.te_present {
                if head.te_chunked {
                    Body::ChunkSize
                } else {
                    Body::Eof
                }
            } else {
                match head.content_length {
                    Some(n) => Body::Exact(n),
                    None => Body::Eof,
                }
            };
            let keep_alive = if head.http_1_0 {
                head.keep_alive_token && !head.close && !head.te_present
            } else {
                !head.close
            };
            return Ok((
                pos,
                Some(ResponseHead {
                    status: head.status,
                    body,
                    keep_alive,
                }),
            ));
        }
        // One case-insensitive byte decides whether a line is worth reading
        match line[0] | 0x20 {
            b'c' if ci_prefix(line, b"content-length:") => {
                let n = parse_u64(trim_ows(&line[15..]))?;
                // Repeated fields are only allowed to agree; disagreeing ones
                // are a framing attack, not a message (RFC 9112 Section 6.3)
                if head.content_length.is_some_and(|prev| prev != n) {
                    bail!("conflicting Content-Length");
                }
                head.content_length = Some(n);
            }
            b'c' if ci_prefix(line, b"connection:") => {
                for token in line[11..].split(|&b| b == b',') {
                    let token = trim_ows(token);
                    if ci_eq(token, b"close") {
                        head.close = true;
                    } else if ci_eq(token, b"keep-alive") {
                        head.keep_alive_token = true;
                    }
                }
            }
            b't' if ci_prefix(line, b"transfer-encoding:") => {
                // Repeated fields concatenate, so the last one decides whether
                // chunked is the final coding
                head.te_present = true;
                if let Some(chunked) = final_coding(&line[18..])? {
                    head.te_chunked = chunked;
                }
            }
            _ => {}
        }
    }
}

/// Three ASCII digits
fn parse_status(b: &[u8]) -> Result<u16> {
    let (a, c, d) = (b[0], b[1], b[2]);
    if !a.is_ascii_digit() || !c.is_ascii_digit() || !d.is_ascii_digit() {
        bail!("invalid status code");
    }
    Ok((a - b'0') as u16 * 100 + (c - b'0') as u16 * 10 + (d - b'0') as u16)
}

fn parse_u64(b: &[u8]) -> Result<u64> {
    if b.is_empty() {
        bail!("empty Content-Length");
    }
    let mut n: u64 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            bail!("invalid Content-Length");
        }
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add((c - b'0') as u64))
            .ok_or_else(|| anyhow::anyhow!("Content-Length overflow"))?;
    }
    Ok(n)
}

/// Hex chunk size, ignoring any `;ext=...` suffix
fn parse_chunk_size(b: &[u8]) -> Result<u64> {
    let b = match memchr(b';', b) {
        Some(i) => &b[..i],
        None => b,
    };
    let b = trim_ows(b);
    if b.is_empty() {
        bail!("empty chunk size");
    }
    let mut n: u64 = 0;
    for &c in b {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => bail!("invalid chunk size"),
        };
        n = n
            .checked_mul(16)
            .and_then(|n| n.checked_add(d as u64))
            .ok_or_else(|| anyhow::anyhow!("chunk size overflow"))?;
    }
    Ok(n)
}

fn trim_cr(line: &[u8]) -> &[u8] {
    match line.last() {
        Some(b'\r') => &line[..line.len() - 1],
        _ => line,
    }
}

fn trim_ows(mut b: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = b {
        if *first == b' ' || *first == b'\t' {
            b = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = b {
        if *last == b' ' || *last == b'\t' {
            b = rest;
        } else {
            break;
        }
    }
    b
}

/// Case-insensitive equality over ASCII
///
/// `a | 0x20` rather than [`u8::eq_ignore_ascii_case`], which the three of
/// these could otherwise be written with. It only folds case for the letters,
/// and the names compared against here are all lower-case ASCII, so the two
/// agree on everything this is asked. The standard one costs a range check a
/// byte and these run over most of a header line: measured at 1,526
/// instructions a request against 1,387.
fn ci_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x | 0x20 == *y)
}

/// Case-insensitive prefix test over ASCII
fn ci_prefix(line: &[u8], name: &[u8]) -> bool {
    line.len() >= name.len()
        && line[..name.len()]
            .iter()
            .zip(name)
            .all(|(a, b)| a | 0x20 == *b)
}

/// Find the last nonempty coding, honoring quoted commas in parameters.
/// Empty list elements are ignored (RFC 9110 Section 5.6.1.2), including
/// across repeated field lines. Compare whole tokens, not suffixes.
fn final_coding(value: &[u8]) -> Result<Option<bool>> {
    let value = trim_ows(value);
    if ci_eq(value, b"chunked") {
        return Ok(Some(true));
    }
    let mut last = None;
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (i, &byte) in value.iter().enumerate() {
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if !quoted && byte == b',' {
            let coding = trim_ows(&value[start..i]);
            if !coding.is_empty() {
                last = Some(ci_eq(coding, b"chunked"));
            }
            start = i + 1;
        }
    }
    if quoted {
        bail!("unterminated Transfer-Encoding parameter");
    }
    let coding = trim_ows(&value[start..]);
    if !coding.is_empty() {
        last = Some(ci_eq(coding, b"chunked"));
    }
    Ok(last)
}
