//! HTTP/1.1 benchmark worker

use std::net::TcpStream;
use std::os::fd::{FromRawFd, RawFd};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use io_uring::{Submitter, cqueue, squeue, types};
use shiguredo_http11::{BodyKind, BodyProgress, HttpHead, ResponseDecoder};

use crate::buf_ring::BufRing;
use crate::stats::Stats;
use crate::target::Target;
use crate::tls::{TlsSession, TlsSetup};
use crate::uring::{
    self, BUF_GROUP, CONN_IDX_BITS, OP_CONNECT, OP_CONNECT_TIMEOUT, OP_RECV, OP_SEND,
    TIMEOUT_USER_DATA,
};

/// Progress of receiving a response
enum ParseOutcome {
    /// One response completed; keep_alive is true if the connection can be reused
    Complete { keep_alive: bool },
    /// Not enough data; keep receiving
    NeedMoreData,
}

/// Metadata of the current response, extracted from the decoded headers
///
/// The ResponseHead is consumed by decode_headers, so keep only the values
/// needed until the response completes.
struct ResponseMeta {
    body_kind: BodyKind,
    keep_alive: bool,
    /// Status code (tallied on completion)
    status_code: u16,
}

struct Conn {
    fd: RawFd,
    /// Whether the TCP connection is established (true after a successful Connect CQE)
    connected: bool,
    decoder: ResponseDecoder,
    /// TLS session (https URLs only; recreated per TCP connection)
    tls: Option<TlsSession>,
    /// Bytes currently being sent; must stay untouched while a Send is in flight
    out: Vec<u8>,
    out_off: usize,
    /// Whether a Send SQE is in flight for `out`
    sending: bool,
    /// Whether a multishot recv is active (cleared by a CQE without the MORE flag)
    recv_armed: bool,
    /// Reconnect generation. Incremented on every close; CQEs from an old
    /// generation (e.g. a cancelled multishot recv) are identified via
    /// user_data and ignored
    generation: u64,
    /// Metadata of the current response (None = headers not decoded yet)
    resp: Option<ResponseMeta>,
    request_start: Instant,
}

impl Conn {
    fn new() -> Self {
        Conn {
            fd: -1,
            connected: false,
            decoder: ResponseDecoder::new(),
            tls: None,
            out: Vec::new(),
            out_off: 0,
            sending: false,
            recv_armed: false,
            generation: 0,
            resp: None,
            request_start: Instant::now(),
        }
    }

    fn close(&mut self) {
        if self.fd >= 0 {
            // Close by turning the fd back into a TcpStream and dropping it
            drop(unsafe { TcpStream::from_raw_fd(self.fd) });
            self.fd = -1;
        }
        self.connected = false;
        self.recv_armed = false;
        self.sending = false;
        self.tls = None;
        self.out.clear();
        self.out_off = 0;
        // Bump the generation so CQEs of operations on the old connection are ignored
        self.generation += 1;
    }

    /// Advance the decoder state machine after feeding received data
    fn parse(&mut self) -> Result<ParseOutcome> {
        let meta = match &self.resp {
            Some(meta) => meta,
            None => match self
                .decoder
                .decode_headers()
                .map_err(|e| anyhow::anyhow!("decode error: {e:?}"))?
            {
                None => return Ok(ParseOutcome::NeedMoreData),
                Some((head, body_kind)) => &*self.resp.insert(ResponseMeta {
                    body_kind,
                    // A close-delimited body ends with the connection closing,
                    // so keep-alive is impossible regardless of the Connection header
                    keep_alive: head.is_keep_alive()
                        && !matches!(body_kind, BodyKind::CloseDelimited),
                    status_code: head.status_code(),
                }),
            },
        };

        match meta.body_kind {
            BodyKind::None => Ok(ParseOutcome::Complete {
                keep_alive: meta.keep_alive,
            }),
            BodyKind::Tunnel => bail!("unexpected tunnel response"),
            _ => {
                let keep_alive = meta.keep_alive;
                loop {
                    let progress = if let Some(body) = self.decoder.peek_body() {
                        let len = body.len();
                        self.decoder
                            .consume_body(len)
                            .map_err(|e| anyhow::anyhow!("body decode error: {e:?}"))?
                    } else {
                        self.decoder
                            .progress()
                            .map_err(|e| anyhow::anyhow!("body decode error: {e:?}"))?
                    };
                    match progress {
                        BodyProgress::Complete { .. } => {
                            return Ok(ParseOutcome::Complete { keep_alive });
                        }
                        BodyProgress::Advanced => continue,
                        BodyProgress::NeedData => return Ok(ParseOutcome::NeedMoreData),
                    }
                }
            }
        }
    }

    /// Reset per-request state for the next request
    fn begin_request(&mut self) {
        self.resp = None;
        self.request_start = Instant::now();
    }

    fn status_code(&self) -> u16 {
        self.resp.as_ref().map_or(0, |m| m.status_code)
    }
}

/// Queue the request bytes for sending on this connection
fn queue_request(conn: &mut Conn, request: &[u8]) -> Result<()> {
    match &mut conn.tls {
        Some(tls) => tls.write_plaintext(request),
        None => {
            // The previous request was fully sent before its response could
            // complete, so `out` is drained by now
            conn.out.clear();
            conn.out.extend_from_slice(request);
            conn.out_off = 0;
            Ok(())
        }
    }
}

/// Submit pending output unless a send is already in flight
///
/// TLS mode drains the pending ciphertext (handshake messages included)
/// into `out` first.
fn flush(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &mut Conn,
) -> Result<()> {
    if conn.sending {
        return Ok(());
    }
    if let Some(tls) = &mut conn.tls {
        let ciphertext = tls.take_ciphertext()?;
        if !ciphertext.is_empty() {
            conn.out = ciphertext;
            conn.out_off = 0;
            conn.sending = true;
            uring::push_send_slice(submitter, sq, conn_idx, conn.generation, &conn.out)?;
        }
    } else if conn.out_off < conn.out.len() {
        conn.sending = true;
        uring::push_send_slice(
            submitter,
            sq,
            conn_idx,
            conn.generation,
            &conn.out[conn.out_off..],
        )?;
    }
    Ok(())
}

fn push_recv_multi(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &mut Conn,
) -> Result<()> {
    uring::push_recv_multi(submitter, sq, conn_idx, conn.generation)?;
    conn.recv_armed = true;
    Ok(())
}

/// Benchmark loop of a single HTTP/1.1 worker thread
///
/// Owns a dedicated io_uring and set of connections; shares no state with
/// other threads.
pub fn run_worker(
    target: &Target,
    tls_setup: Option<&TlsSetup>,
    connections: usize,
    max_requests: u64,
    duration_limit: Option<Duration>,
    connect_timeout: Duration,
) -> Result<Stats> {
    if connections == 0 || max_requests == 0 {
        return Ok(Stats::default());
    }
    if connections > 1 << CONN_IDX_BITS {
        bail!(
            "too many connections per thread (max {})",
            1u64 << CONN_IDX_BITS
        );
    }

    // Declare buf_ring / conns before the ring. Reverse drop order then
    // destroys the ring first (its teardown waits for in-flight operations to
    // be cancelled), preventing a use-after-free where the kernel writes into
    // buffers that have already been freed.
    let buf_entries = (connections * 2).next_power_of_two().clamp(64, 32768) as u16;
    let mut buf_ring = BufRing::new(buf_entries)?;
    let mut conns: Vec<Conn> = Vec::with_capacity(connections);
    for _ in 0..connections {
        conns.push(Conn::new());
    }

    let entries = (connections * 2).next_power_of_two().max(256) as u32;
    let mut ring = uring::build_ring(entries)?;

    // Keep the Submitter alive so enter can use the registered ring fd
    // (submitter/sq/cq are disjoint borrows of the ring; the ring itself is
    // not touched from here on)
    let (mut submitter, mut sq, mut cq) = ring.split();

    // Skip the ring-fd fdget/fput on every enter (5.18+; behavior is identical
    // if this fails)
    let _ = submitter.register_ring_fd();

    // Reserve a fixed file slot per connection; SQEs refer to fds as
    // types::Fixed(conn_idx), skipping per-op fd refcounting
    submitter
        .register_files_sparse(connections as u32)
        .context("register_files_sparse failed")?;

    // Register the provided buffer ring (kernel 5.19+; RecvMulti needs 6.0+)
    unsafe {
        submitter
            .register_buf_ring_with_flags(buf_ring.ring_ptr as u64, buf_ring.entries, BUF_GROUP, 0)
            .context("register_buf_ring failed")?;
    }

    // The sockaddr / Timespec referenced by Connect SQEs must stay at a stable
    // address until completion
    let raw_addr = Box::new(socket2::SockAddr::from(target.addr));
    let connect_timeout = Box::new(types::Timespec::from(connect_timeout));

    let mut stats = Stats::default();
    if duration_limit.is_none() {
        stats.latencies_ns.reserve(max_requests as usize);
    }
    let mut started: u64 = 0;

    // Duration mode: the deadline is detected solely via the io_uring Timeout CQE
    let timespec = duration_limit.map(|d| Box::new(types::Timespec::from(d)));
    if let Some(ts) = &timespec {
        let entry = io_uring::opcode::Timeout::new(&**ts as *const types::Timespec)
            .build()
            .user_data(TIMEOUT_USER_DATA);
        uring::push_sqe(&submitter, &mut sq, entry)?;
    }

    // Kick off the initial requests (connection setup is async via io_uring too)
    for (i, conn) in conns.iter_mut().enumerate() {
        if started >= max_requests {
            break;
        }
        started += 1;
        conn.begin_request();
        conn.fd = uring::start_connect(
            &submitter,
            &mut sq,
            i,
            conn.generation,
            &target.addr,
            &raw_addr,
            &connect_timeout,
        )?;
    }

    let mut cqe_buf: Vec<(u64, i32, u32)> = Vec::with_capacity(entries as usize * 4);
    // Reusable buffer for decrypted plaintext (TLS mode)
    let mut scratch = vec![0u8; 64 * 1024];
    let mut stop = false;

    'outer: loop {
        if stats.completed + stats.errors >= max_requests {
            break;
        }
        if crate::shutdown::requested() {
            break;
        }
        // Publish the tail of pushed SQEs before submitting
        sq.sync();
        uring::submit_and_wait_timeout(&submitter)?;

        cq.sync();
        cqe_buf.clear();
        for cqe in &mut cq {
            cqe_buf.push((cqe.user_data(), cqe.result(), cqe.flags()));
        }
        // Publish the head of consumed CQEs
        cq.sync();

        for &(ud, res, flags) in &cqe_buf {
            if ud == TIMEOUT_USER_DATA {
                stop = true;
                continue;
            }
            let (op, conn_idx, generation) = uring::decode_user_data(ud);

            // Ignore CQEs of operations from an old generation (a closed
            // connection). If an old multishot recv completed with a buffer
            // attached, just return the buffer.
            if generation != conns[conn_idx].generation {
                if let Some(bid) = cqueue::buffer_select(flags) {
                    buf_ring.recycle(bid);
                }
                continue;
            }

            let mut request_finished = false;
            let mut keep_conn = true;

            match op {
                OP_CONNECT => {
                    if res < 0 {
                        // e.g. ECONNREFUSED, or ECANCELED when the LinkTimeout fired
                        stats.errors += 1;
                        stats.connect_errors += 1;
                        request_finished = true;
                        keep_conn = false;
                    } else {
                        let conn = &mut conns[conn_idx];
                        conn.connected = true;
                        // Arm a connection-lifetime multishot recv right away
                        push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
                        if let Some(setup) = tls_setup {
                            conn.tls = Some(TlsSession::new(setup)?);
                        }
                        // Latency is measured from send start (excludes TCP
                        // connect; the first request on a TLS connection does
                        // include the handshake)
                        conn.request_start = Instant::now();
                        queue_request(conn, &target.request_bytes)?;
                        flush(&submitter, &mut sq, conn_idx, conn)?;
                    }
                }
                OP_CONNECT_TIMEOUT => {
                    // The LinkTimeout CQE arrives whether the connect succeeded
                    // or not (-ECANCELED if the connect finished first, -ETIME
                    // if it fired). Everything is handled on the OP_CONNECT
                    // side, so there is nothing to do here.
                }
                OP_SEND => {
                    if res < 0 {
                        stats.errors += 1;
                        request_finished = true;
                        keep_conn = false;
                    } else {
                        stats.bytes_sent += res as u64;
                        let conn = &mut conns[conn_idx];
                        conn.out_off += res as usize;
                        if conn.out_off < conn.out.len() {
                            uring::push_send_slice(
                                &submitter,
                                &mut sq,
                                conn_idx,
                                conn.generation,
                                &conn.out[conn.out_off..],
                            )?;
                        } else {
                            conn.sending = false;
                            // TLS may have produced more ciphertext meanwhile
                            flush(&submitter, &mut sq, conn_idx, conn)?;
                            if !conn.recv_armed {
                                // Re-arm if the multishot ended (e.g. due to ENOBUFS)
                                push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
                            }
                        }
                    }
                }
                OP_RECV => {
                    let conn = &mut conns[conn_idx];
                    // A CQE without the MORE flag means this multishot recv ended
                    if !cqueue::more(flags) {
                        conn.recv_armed = false;
                    }
                    if res < 0 {
                        // Return the buffer in the unlikely case one is attached
                        if let Some(bid) = cqueue::buffer_select(flags) {
                            buf_ring.recycle(bid);
                        }
                        if res == -libc::ENOBUFS {
                            // The multishot merely stopped because the pool ran
                            // dry; buffers are returned while processing this
                            // batch, so just re-arm
                            push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
                        } else {
                            stats.errors += 1;
                            request_finished = true;
                            keep_conn = false;
                        }
                    } else if res == 0 {
                        if let Some(bid) = cqueue::buffer_select(flags) {
                            buf_ring.recycle(bid);
                        }
                        // EOF: a close-delimited body completes normally here
                        // (is_close_delimited implies the headers were decoded)
                        if conn.decoder.is_close_delimited() {
                            conn.decoder.mark_eof();
                            match conn.parse() {
                                Ok(ParseOutcome::Complete { .. }) => {
                                    stats.record_success(conn.status_code(), conn.request_start);
                                }
                                _ => stats.errors += 1,
                            }
                        } else {
                            stats.errors += 1;
                        }
                        request_finished = true;
                        keep_conn = false;
                    } else {
                        stats.bytes_received += res as u64;
                        let bid =
                            cqueue::buffer_select(flags).context("recv CQE without buffer id")?;
                        // In TLS mode decrypt into scratch and feed the
                        // plaintext; otherwise feed the socket bytes directly
                        let feed_result: Result<()> = match &mut conn.tls {
                            Some(tls) => {
                                tls.feed(buf_ring.data(bid, res as usize)).and_then(|_| {
                                    loop {
                                        let n = tls.read_plaintext(&mut scratch)?;
                                        if n == 0 {
                                            break;
                                        }
                                        conn.decoder
                                            .feed(&scratch[..n])
                                            .map_err(|e| anyhow::anyhow!("decode feed: {e:?}"))?;
                                    }
                                    Ok(())
                                })
                            }
                            None => conn
                                .decoder
                                .feed(buf_ring.data(bid, res as usize))
                                .map_err(|e| anyhow::anyhow!("decode feed: {e:?}")),
                        };
                        buf_ring.recycle(bid);
                        if feed_result.is_err() {
                            stats.errors += 1;
                            request_finished = true;
                            keep_conn = false;
                        } else {
                            match conn.parse() {
                                Ok(ParseOutcome::Complete { keep_alive }) => {
                                    stats.record_success(conn.status_code(), conn.request_start);
                                    request_finished = true;
                                    keep_conn = keep_alive;
                                }
                                Ok(ParseOutcome::NeedMoreData) => {
                                    if !conn.recv_armed {
                                        push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
                                    }
                                }
                                Err(_) => {
                                    stats.errors += 1;
                                    request_finished = true;
                                    keep_conn = false;
                                }
                            }
                            // The TLS handshake may need to send its next
                            // flight even though no request completed
                            flush(&submitter, &mut sq, conn_idx, conn)?;
                        }
                    }
                }
                _ => unreachable!(),
            }

            if request_finished {
                let conn = &mut conns[conn_idx];
                if !stop && started < max_requests {
                    started += 1;
                    conn.begin_request();
                    if keep_conn && conn.connected {
                        if !conn.recv_armed {
                            push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
                        }
                        queue_request(conn, &target.request_bytes)?;
                        flush(&submitter, &mut sq, conn_idx, conn)?;
                    } else {
                        conn.close();
                        conn.decoder.reset();
                        match uring::start_connect(
                            &submitter,
                            &mut sq,
                            conn_idx,
                            conn.generation,
                            &target.addr,
                            &raw_addr,
                            &connect_timeout,
                        ) {
                            Ok(fd) => conn.fd = fd,
                            Err(e) => {
                                eprintln!("reconnect failed: {e}");
                                break 'outer;
                            }
                        }
                    }
                } else if !keep_conn {
                    conn.close();
                }
            }
        }

        if stop {
            break;
        }
    }

    for conn in &mut conns {
        conn.close();
    }

    Ok(stats)
}
