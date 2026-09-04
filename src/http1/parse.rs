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
    /// Bytes of an incomplete message carried over from earlier receives.
    /// Empty in the common case, which lets [`Parser::feed`] parse straight
    /// out of the receive buffer with no copy at all.
    pending: Vec<u8>,
    state: State,
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
            status: 0,
            keep_alive: true,
            head_request: false,
        }
    }

    /// Forget any partially received message (called when reconnecting)
    pub fn reset(&mut self) {
        self.pending.clear();
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
                    let Some((len, status, body, keep_alive)) = scan_head(&buf[pos..])? else {
                        return Ok((pos, done));
                    };
                    pos += len;
                    if crate::is_informational(status) {
                        if status == 101 {
                            // The connection stops being HTTP/1.1 here, and a
                            // load generator has nothing to switch to
                            bail!("unexpected 101 Switching Protocols");
                        }
                        // An interim response carries no body and does not
                        // finish the message: keep reading for the final one
                        // (RFC 9110 Section 15.2)
                        continue;
                    }
                    self.status = status;
                    // A close-delimited body ends with the connection itself
                    self.keep_alive = keep_alive && body != Body::Eof;
                    let body = if self.head_request || no_body_status(status) {
                        Body::Exact(0)
                    } else {
                        body
                    };
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

/// Scan a status line and header block
///
/// Returns None when `buf` does not hold the whole block yet, otherwise the
/// length of the block, the status code, how the body is framed, and whether
/// the connection may be reused.
fn scan_head(buf: &[u8]) -> Result<Option<(usize, u16, Body, bool)>> {
    let Some(nl) = memchr(b'\n', buf) else {
        return Ok(None);
    };
    // "HTTP/1.1 200 OK" — the status code is always at the same offset
    if buf.len() < 12 || !buf.starts_with(b"HTTP/1.") {
        bail!("not an HTTP/1.x response");
    }
    let http_1_0 = buf[7] == b'0';
    let status = parse_status(&buf[9..12])?;
    let mut pos = nl + 1;
    let mut content_length: Option<u64> = None;
    let mut te_present = false;
    let mut te_chunked = false;
    let mut close = false;
    let mut keep_alive_token = false;
    loop {
        let Some(rel) = memchr(b'\n', &buf[pos..]) else {
            return Ok(None);
        };
        let line = trim_cr(&buf[pos..pos + rel]);
        pos += rel + 1;
        if line.is_empty() {
            // Transfer-Encoding overrides Content-Length, and when chunked is
            // not the final coding the body runs to the end of the connection
            // (RFC 9112 Section 6.3)
            let body = if te_present {
                if te_chunked {
                    Body::ChunkSize
                } else {
                    Body::Eof
                }
            } else {
                match content_length {
                    Some(n) => Body::Exact(n),
                    None => Body::Eof,
                }
            };
            // HTTP/1.1 keeps the connection unless told otherwise; HTTP/1.0
            // closes it unless told otherwise (RFC 9112 Section 9.3)
            let keep_alive = if http_1_0 {
                keep_alive_token && !close
            } else {
                !close
            };
            return Ok(Some((pos, status, body, keep_alive)));
        }
        // One case-insensitive byte decides whether a line is worth reading
        match line[0] | 0x20 {
            b'c' if ci_prefix(line, b"content-length:") => {
                let n = parse_u64(trim_ows(&line[15..]))?;
                // Repeated fields are only allowed to agree; disagreeing ones
                // are a framing attack, not a message (RFC 9112 Section 6.3)
                if content_length.is_some_and(|prev| prev != n) {
                    bail!("conflicting Content-Length");
                }
                content_length = Some(n);
            }
            b'c' if ci_prefix(line, b"connection:") => {
                for token in line[11..].split(|&b| b == b',') {
                    let token = trim_ows(token);
                    if ci_eq(token, b"close") {
                        close = true;
                    } else if ci_eq(token, b"keep-alive") {
                        keep_alive_token = true;
                    }
                }
            }
            b't' if ci_prefix(line, b"transfer-encoding:") => {
                // Repeated fields concatenate, so the last one decides whether
                // chunked is the final coding
                te_present = true;
                te_chunked = ci_ends_with_chunked(trim_ows(&line[18..]));
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

    /// Several chunks, split at every offset: a read that stops between the
    /// CR and the LF ending a chunk used to underflow the remaining count
    #[test]
    fn multi_chunk_split_at_every_offset() {
        let data =
            resp("HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n1\na\n2\nbc\n3\ndef\n0\n\n");
        for split in 1..data.len() {
            let mut p = Parser::new();
            let a = p.feed(&data[..split]).unwrap();
            let b = p.feed(&data[split..]).unwrap();
            assert_eq!(a + b, 1, "split at {split}");
        }
    }

    /// A chunk size that leaves no room to add its CRLF must be rejected
    /// rather than wrap around
    #[test]
    fn absurd_chunk_size_is_rejected() {
        let mut p = Parser::new();
        let data = resp("HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\nffffffffffffffff\n");
        assert!(p.feed(&data).is_err());
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
    fn http_1_0_closes_unless_it_says_keep_alive() {
        let mut p = Parser::new();
        assert_eq!(
            p.feed(&resp("HTTP/1.0 200 OK\nContent-Length: 2\n\nok"))
                .unwrap(),
            1
        );
        assert!(!p.keep_alive(), "HTTP/1.0 defaults to closing");

        let mut p = Parser::new();
        let data = resp("HTTP/1.0 200 OK\nConnection: keep-alive\nContent-Length: 2\n\nok");
        assert_eq!(p.feed(&data).unwrap(), 1);
        assert!(p.keep_alive());
    }

    #[test]
    fn http_1_1_keeps_unless_it_says_close() {
        let mut p = Parser::new();
        assert_eq!(
            p.feed(&resp("HTTP/1.1 200 OK\nContent-Length: 2\n\nok"))
                .unwrap(),
            1
        );
        assert!(p.keep_alive());

        let mut p = Parser::new();
        let data = resp("HTTP/1.1 200 OK\nconnection: Close\nContent-Length: 2\n\nok");
        assert_eq!(p.feed(&data).unwrap(), 1);
        assert!(!p.keep_alive(), "Connection: close must be honoured");
    }

    #[test]
    fn connection_token_list_is_split() {
        let mut p = Parser::new();
        let data = resp("HTTP/1.1 200 OK\nConnection: TE, Close\nContent-Length: 2\n\nok");
        assert_eq!(p.feed(&data).unwrap(), 1);
        assert!(!p.keep_alive());
    }

    #[test]
    fn close_delimited_body_never_keeps_alive() {
        let mut p = Parser::new();
        assert_eq!(
            p.feed(&resp("HTTP/1.1 200 OK\nServer: x\n\nbody")).unwrap(),
            0
        );
        assert!(p.mark_eof());
        assert!(!p.keep_alive());
    }

    #[test]
    fn interim_responses_do_not_finish_the_message() {
        // Arriving together
        let mut p = Parser::new();
        let data = resp(
            "HTTP/1.1 103 Early Hints\nLink: </s.css>\n\nHTTP/1.1 200 OK\nContent-Length: 2\n\nok",
        );
        assert_eq!(p.feed(&data).unwrap(), 1);
        assert_eq!(p.status(), 200);

        // And arriving in separate reads, which is how a real early hint comes
        let mut p = Parser::new();
        assert_eq!(
            p.feed(&resp("HTTP/1.1 103 Early Hints\nLink: </s.css>\n\n"))
                .unwrap(),
            0,
            "an interim response must not complete a request"
        );
        assert_eq!(
            p.feed(&resp("HTTP/1.1 200 OK\nContent-Length: 2\n\nok"))
                .unwrap(),
            1
        );
        assert_eq!(p.status(), 200);
    }

    #[test]
    fn a_hundred_continue_is_skipped() {
        let mut p = Parser::new();
        assert_eq!(p.feed(&resp("HTTP/1.1 100 Continue\n\n")).unwrap(), 0);
        assert_eq!(
            p.feed(&resp("HTTP/1.1 201 Created\nContent-Length: 0\n\n"))
                .unwrap(),
            1
        );
        assert_eq!(p.status(), 201);
    }

    #[test]
    fn switching_protocols_is_rejected() {
        let mut p = Parser::new();
        assert!(
            p.feed(&resp("HTTP/1.1 101 Switching Protocols\n\n"))
                .is_err()
        );
    }

    #[test]
    fn disagreeing_content_lengths_are_rejected() {
        let mut p = Parser::new();
        let data = resp("HTTP/1.1 200 OK\nContent-Length: 2\nContent-Length: 9\n\nok");
        assert!(p.feed(&data).is_err());

        // Repeats that agree are allowed
        let mut p = Parser::new();
        let data = resp("HTTP/1.1 200 OK\nContent-Length: 2\nContent-Length: 2\n\nok");
        assert_eq!(p.feed(&data).unwrap(), 1);
    }

    #[test]
    fn transfer_encoding_without_chunked_last_runs_to_eof() {
        // chunked is not the final coding, so Content-Length must be ignored
        // and the body ends with the connection
        let mut p = Parser::new();
        let data = resp(
            "HTTP/1.1 200 OK\nContent-Length: 2\nTransfer-Encoding: chunked, gzip\n\nnot two bytes",
        );
        assert_eq!(p.feed(&data).unwrap(), 0);
        assert!(p.mark_eof());
        assert!(!p.keep_alive());
    }

    #[test]
    fn transfer_encoding_over_two_lines_ends_in_chunked() {
        let mut p = Parser::new();
        let data = resp(
            "HTTP/1.1 200 OK\nTransfer-Encoding: gzip\nTransfer-Encoding: chunked\n\n2\nhi\n0\n\n",
        );
        assert_eq!(p.feed(&data).unwrap(), 1);
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
