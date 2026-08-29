//! Minimal HTTP/1.1 response scanner
//!
//! A load generator only needs to know where one response ends and the next
//! begins, plus the status code to tally. This scanner therefore reads the
//! status line, `Content-Length` and `Transfer-Encoding`, and skips every
//! other header without looking at it — no field-name validation, no UTF-8
//! checks, no allocation per header line.
//!
//! Notably it does **not** interpret `Connection`, so keep-alive is assumed.
//! A server that closes anyway is handled by the worker: the receive returns
//! EOF and the connection is re-established.

use anyhow::{Result, bail};

/// How the body of the response being read is delimited
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Body {
    /// `Content-Length` bytes remain
    Exact(u64),
    /// Reading the hex size line of the next chunk
    ChunkSize,
    /// Bytes remaining in the current chunk, then its trailing CRLF
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
    /// Bytes of an incomplete message carried over from earlier receives.
    /// Empty in the common case, which lets [`Parser::feed`] parse straight
    /// out of the receive buffer with no copy at all.
    pending: Vec<u8>,
    state: State,
    /// Status code of the most recently completed response
    status: u16,
    /// Status code of the response currently being read
    current_status: u16,
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
            status: 0,
            current_status: 0,
            head_request: false,
        }
    }

    /// Forget any partially received message (called when reconnecting)
    pub fn reset(&mut self) {
        self.pending.clear();
        self.state = State::Head;
        self.status = 0;
        self.current_status = 0;
    }

    /// Tell the parser whether responses answer HEAD requests
    pub fn set_head_request(&mut self, head: bool) {
        self.head_request = head;
    }

    /// Status code of the most recently completed response
    pub fn status(&self) -> u16 {
        self.status
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
        // Take the buffer out so `run` can borrow it while holding `&mut self`
        let mut buf = std::mem::take(&mut self.pending);
        buf.extend_from_slice(data);
        let result = self.run(&buf);
        match result {
            Ok((used, done)) => {
                buf.drain(..used);
                self.pending = buf;
                Ok(done)
            }
            Err(e) => Err(e),
        }
    }

    /// Signal that the peer closed the connection
    ///
    /// Returns true if that completed a close-delimited response.
    pub fn mark_eof(&mut self) -> bool {
        if self.state == State::Body(Body::Eof) {
            self.state = State::Head;
            self.status = self.current_status;
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
                    let Some((len, status, body)) = scan_head(&buf[pos..])? else {
                        return Ok((pos, done));
                    };
                    pos += len;
                    self.current_status = status;
                    let body = if self.head_request || no_body_status(status) {
                        Body::Exact(0)
                    } else {
                        body
                    };
                    self.state = State::Body(body);
                }
                State::Body(Body::Exact(0)) => {
                    self.state = State::Head;
                    self.status = self.current_status;
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
                        Body::Chunk(size)
                    });
                }
                State::Body(Body::Chunk(n)) => {
                    // The chunk data plus its terminating CRLF
                    let want = n + 2;
                    let avail = (buf.len() - pos) as u64;
                    let take = want.min(avail);
                    pos += take as usize;
                    if take < want {
                        self.state = State::Body(Body::Chunk(want - take - 2));
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
                        self.status = self.current_status;
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
fn no_body_status(status: u16) -> bool {
    (100..200).contains(&status) || status == 204 || status == 304
}

/// Scan a status line and header block
///
/// Returns None when `buf` does not hold the whole block yet.
fn scan_head(buf: &[u8]) -> Result<Option<(usize, u16, Body)>> {
    let Some(nl) = memchr(b'\n', buf) else {
        return Ok(None);
    };
    // "HTTP/1.1 200 OK" — the status code is always at the same offset
    if buf.len() < 12 || !buf.starts_with(b"HTTP/1.") {
        bail!("not an HTTP/1.x response");
    }
    let status = parse_status(&buf[9..12])?;
    let mut pos = nl + 1;
    let mut body = Body::Eof;
    loop {
        let Some(rel) = memchr(b'\n', &buf[pos..]) else {
            return Ok(None);
        };
        let line = trim_cr(&buf[pos..pos + rel]);
        pos += rel + 1;
        if line.is_empty() {
            return Ok(Some((pos, status, body)));
        }
        // One case-insensitive byte decides whether a line is worth reading
        match line[0] | 0x20 {
            b'c' if ci_prefix(line, b"content-length:") => {
                // Chunked framing wins over Content-Length (RFC 9112 6.3)
                if body != Body::ChunkSize {
                    body = Body::Exact(parse_u64(trim_ows(&line[15..]))?);
                }
            }
            b't' if ci_prefix(line, b"transfer-encoding:")
                && ci_ends_with_chunked(trim_ows(&line[18..])) =>
            {
                body = Body::ChunkSize;
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

/// Case-insensitive prefix test over ASCII
fn ci_prefix(line: &[u8], name: &[u8]) -> bool {
    line.len() >= name.len()
        && line[..name.len()]
            .iter()
            .zip(name)
            .all(|(a, b)| a | 0x20 == *b)
}

/// Whether a Transfer-Encoding value ends in "chunked", which is the only
/// position the token may appear in (RFC 9112 Section 6.1)
fn ci_ends_with_chunked(value: &[u8]) -> bool {
    let tail = match value.len().checked_sub(7) {
        Some(i) => &value[i..],
        None => return false,
    };
    tail.iter().zip(b"chunked").all(|(a, b)| a | 0x20 == *b)
}

fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    memchr::memchr(needle, haystack)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(s: &str) -> Vec<u8> {
        s.replace('\n', "\r\n").into_bytes()
    }

    #[test]
    fn content_length_response() {
        let mut p = Parser::new();
        let data = resp("HTTP/1.1 200 OK\nContent-Length: 5\n\nhello");
        assert_eq!(p.feed(&data).unwrap(), 1);
        assert_eq!(p.status(), 200);
    }

    #[test]
    fn several_responses_in_one_read() {
        let mut p = Parser::new();
        let one = resp("HTTP/1.1 201 Created\nContent-Length: 2\n\nok");
        let mut data = one.clone();
        data.extend_from_slice(&one);
        data.extend_from_slice(&one);
        assert_eq!(p.feed(&data).unwrap(), 3);
        assert_eq!(p.status(), 201);
    }

    #[test]
    fn split_at_every_offset() {
        let data = resp("HTTP/1.1 200 OK\nServer: x\nContent-Length: 11\n\nhello world");
        for split in 1..data.len() {
            let mut p = Parser::new();
            let a = p.feed(&data[..split]).unwrap();
            let b = p.feed(&data[split..]).unwrap();
            assert_eq!(a + b, 1, "split at {split}");
            assert_eq!(p.status(), 200, "split at {split}");
        }
    }

    #[test]
    fn chunked_response() {
        let mut p = Parser::new();
        let data =
            resp("HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n5\nhello\n6\n world\n0\n\n");
        assert_eq!(p.feed(&data).unwrap(), 1);
        assert_eq!(p.status(), 200);
    }

    #[test]
    fn chunked_split_at_every_offset() {
        let data = resp("HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n5\nhello\n0\n\n");
        for split in 1..data.len() {
            let mut p = Parser::new();
            let a = p.feed(&data[..split]).unwrap();
            let b = p.feed(&data[split..]).unwrap();
            assert_eq!(a + b, 1, "split at {split}");
        }
    }

    #[test]
    fn chunked_wins_over_content_length() {
        let mut p = Parser::new();
        let data =
            resp("HTTP/1.1 200 OK\nContent-Length: 99\nTransfer-Encoding: chunked\n\n2\nhi\n0\n\n");
        assert_eq!(p.feed(&data).unwrap(), 1);
    }

    #[test]
    fn header_name_case_is_ignored() {
        let mut p = Parser::new();
        let data = resp("HTTP/1.1 200 OK\ncOnTeNt-LeNgTh:  4 \n\nabcd");
        assert_eq!(p.feed(&data).unwrap(), 1);
    }

    #[test]
    fn head_response_has_no_body() {
        let mut p = Parser::new();
        p.set_head_request(true);
        // Content-Length is present but no body follows
        let data = resp("HTTP/1.1 200 OK\nContent-Length: 11\n\n");
        assert_eq!(p.feed(&data).unwrap(), 1);
    }

    #[test]
    fn status_204_has_no_body() {
        let mut p = Parser::new();
        let data = resp("HTTP/1.1 204 No Content\n\n");
        assert_eq!(p.feed(&data).unwrap(), 1);
        assert_eq!(p.status(), 204);
    }

    #[test]
    fn close_delimited_completes_at_eof() {
        let mut p = Parser::new();
        let data = resp("HTTP/1.1 200 OK\nServer: x\n\npartial body");
        assert_eq!(p.feed(&data).unwrap(), 0);
        assert!(p.mark_eof());
        assert_eq!(p.status(), 200);
    }

    #[test]
    fn eof_without_close_delimited_body_is_not_a_completion() {
        let mut p = Parser::new();
        let data = resp("HTTP/1.1 200 OK\nContent-Length: 5\n\nhel");
        assert_eq!(p.feed(&data).unwrap(), 0);
        assert!(!p.mark_eof());
    }

    #[test]
    fn non_http_response_is_rejected() {
        let mut p = Parser::new();
        assert!(p.feed(b"gibberish that is long enough\r\n\r\n").is_err());
    }

    #[test]
    fn byte_at_a_time() {
        let data = resp("HTTP/1.1 200 OK\nContent-Length: 3\n\nabc");
        let mut p = Parser::new();
        let mut total = 0;
        for b in &data {
            total += p.feed(std::slice::from_ref(b)).unwrap();
        }
        assert_eq!(total, 1);
        assert_eq!(p.status(), 200);
    }
}
