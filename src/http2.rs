//! HTTP/2 benchmark worker (h2c prior knowledge, or ALPN "h2" over TLS)

use std::net::TcpStream;
use std::os::fd::{FromRawFd, RawFd};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use io_uring::{Submitter, cqueue, squeue, types};
use shiguredo_http2::{Connection, ErrorCode, Event, HeaderField, Limits, StreamId, WindowSize};

use crate::buf_ring::BufRing;
use crate::stats::Stats;
use crate::target::Target;
use crate::tls::{TlsSession, TlsSetup};
use crate::uring::{
    self, BUF_GROUP, CONN_IDX_BITS, OP_CONNECT, OP_CONNECT_TIMEOUT, OP_RECV, OP_SEND,
    TIMEOUT_USER_DATA,
};

/// Stream-level receive window advertised via SETTINGS_INITIAL_WINDOW_SIZE.
/// Matches h2load's default of (1 << 30) - 1, effectively disabling
/// flow-control stalls for responses up to 1GB.
const STREAM_WINDOW: u32 = (1 << 30) - 1;
/// Connection-level receive window advertised at connection setup.
/// Matches h2load's default of (1 << 30) - 1.
const CONNECTION_WINDOW: u32 = (1 << 30) - 1;

fn make_limits() -> Result<Limits> {
    Limits::builder()
        .initial_window_size(
            WindowSize::new(STREAM_WINDOW).map_err(|e| anyhow::anyhow!("window size: {e:?}"))?,
        )
        .connection_window_size(
            WindowSize::new(CONNECTION_WINDOW)
                .map_err(|e| anyhow::anyhow!("window size: {e:?}"))?,
        )
        .build()
        .map_err(|e| anyhow::anyhow!("invalid HTTP/2 limits: {e:?}"))
}

/// Request pseudo-headers, built once and cloned per request
///
/// Like h2load's pre-built nva arrays, the template is constructed once with
/// `Cow::Borrowed` contents (`from_static` over intentionally leaked strings),
/// so the per-request clone copies pointers instead of allocating.
fn build_request_headers(target: &Target) -> Vec<HeaderField> {
    // Leaked once per worker; negligible and lives for the whole run anyway.
    // The values already passed parse_target's HTTP/1.1 validation (and DNS
    // resolution for the authority), so from_static's checks cannot fire.
    let authority: &'static [u8] =
        Box::leak(target.authority.clone().into_bytes().into_boxed_slice());
    let path: &'static [u8] = Box::leak(target.path.clone().into_bytes().into_boxed_slice());
    let method: &'static [u8] = Box::leak(target.method.clone().into_bytes().into_boxed_slice());
    let scheme: &'static [u8] = if target.tls { b"https" } else { b"http" };

    vec![
        HeaderField::from_static(b":method", method),
        HeaderField::from_static(b":scheme", scheme),
        HeaderField::from_static(b":authority", authority),
        HeaderField::from_static(b":path", path),
    ]
}

/// An in-flight request (one open stream)
struct InFlight {
    stream_id: StreamId,
    start: Instant,
    /// Status code from :status (0 = not received yet)
    status: u16,
    /// Stream-level receive-window consumption not yet replenished
    window_debt: usize,
}

struct Conn {
    fd: RawFd,
    /// Whether the TCP connection is established (true after a successful Connect CQE)
    connected: bool,
    /// HTTP/2 connection state machine (recreated per TCP connection)
    h2: Option<Connection>,
    /// TLS session (https URLs only; recreated per TCP connection)
    tls: Option<TlsSession>,
    /// Bytes currently being sent; must stay untouched while a Send is in flight
    out: Vec<u8>,
    out_off: usize,
    /// Whether a Send SQE is in flight for `out`
    sending: bool,
    /// Whether a multishot recv is active (cleared by a CQE without the MORE flag)
    recv_armed: bool,
    /// GOAWAY received: no new streams, reconnect once in-flight streams drain
    goaway: bool,
    /// Connection-level receive-window consumption not yet replenished
    window_debt: usize,
    /// Reconnect generation. Incremented on every close; CQEs from an old
    /// generation (e.g. a cancelled multishot recv) are identified via
    /// user_data and ignored
    generation: u64,
    /// In-flight requests, up to the configured parallelism (linear scan;
    /// the list is small)
    streams: Vec<InFlight>,
}

impl Conn {
    fn new() -> Self {
        Conn {
            fd: -1,
            connected: false,
            h2: None,
            tls: None,
            out: Vec::new(),
            out_off: 0,
            sending: false,
            recv_armed: false,
            goaway: false,
            window_debt: 0,
            generation: 0,
            streams: Vec::new(),
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
        self.goaway = false;
        self.window_debt = 0;
        self.out.clear();
        self.out_off = 0;
        self.h2 = None;
        self.tls = None;
        self.streams.clear();
        // Bump the generation so CQEs of operations on the old connection are ignored
        self.generation += 1;
    }

    /// Count all in-flight requests as errors (used when the connection dies)
    fn fail_inflight(&mut self, stats: &mut Stats) {
        stats.errors += self.streams.len() as u64;
        self.streams.clear();
    }
}

/// Open new streams until the parallelism target or the request budget is hit
///
/// Stops early when start_stream refuses (e.g. the peer's
/// SETTINGS_MAX_CONCURRENT_STREAMS limit); filling is retried after
/// completions.
fn fill_streams(
    conn: &mut Conn,
    request_headers: &[HeaderField],
    parallel: usize,
    started: &mut u64,
    max_requests: u64,
    stop: bool,
) {
    if stop || conn.goaway {
        return;
    }
    let Some(h2) = conn.h2.as_mut() else {
        return;
    };
    while conn.streams.len() < parallel && *started < max_requests {
        match h2.start_stream(request_headers.to_vec(), true) {
            Ok(stream_id) => {
                conn.streams.push(InFlight {
                    stream_id,
                    start: Instant::now(),
                    status: 0,
                    window_debt: 0,
                });
                *started += 1;
            }
            Err(_) => break,
        }
    }
}

/// Move pending h2 output into the send buffer and submit it, unless a send
/// is already in flight
fn flush(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &mut Conn,
) -> Result<()> {
    if conn.sending {
        return Ok(());
    }
    let Some(h2) = conn.h2.as_mut() else {
        return Ok(());
    };
    match &mut conn.tls {
        Some(tls) => {
            // Encrypt the h2 output; the ciphertext may also contain pending
            // handshake messages even when h2 has nothing to say
            if let Some(buf) = h2.poll_output() {
                tls.write_plaintext(&buf)?;
            }
            let ciphertext = tls.take_ciphertext()?;
            if !ciphertext.is_empty() {
                conn.out = ciphertext;
                conn.out_off = 0;
                conn.sending = true;
                uring::push_send_slice(submitter, sq, conn_idx, conn.generation, &conn.out)?;
            }
        }
        None => {
            if let Some(buf) = h2.poll_output() {
                conn.out = buf;
                conn.out_off = 0;
                conn.sending = true;
                uring::push_send_slice(submitter, sq, conn_idx, conn.generation, &conn.out)?;
            }
        }
    }
    Ok(())
}

/// Drain h2 events, replenish flow-control windows, and record completed
/// requests. Returns false if the connection is broken (connection error).
fn process_events(conn: &mut Conn, stats: &mut Stats) -> bool {
    let Some(h2) = conn.h2.as_mut() else {
        return false;
    };
    let mut alive = true;
    while let Some(event) = h2.poll_event() {
        match event {
            Event::HeadersReceived {
                stream_id,
                headers,
                end_stream,
                ..
            } => {
                if let Some(inflight) = conn.streams.iter_mut().find(|s| s.stream_id == stream_id) {
                    for field in &headers {
                        if field.name() == b":status" {
                            inflight.status = std::str::from_utf8(field.value())
                                .ok()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                        }
                    }
                    if end_stream {
                        stats.record_success(inflight.status, inflight.start);
                        conn.streams.retain(|s| s.stream_id != stream_id);
                    }
                }
            }
            Event::DataReceived {
                stream_id,
                data,
                end_stream,
            } => {
                conn.window_debt += data.len();
                if let Some(pos) = conn.streams.iter().position(|s| s.stream_id == stream_id) {
                    if end_stream {
                        let inflight = conn.streams.swap_remove(pos);
                        stats.record_success(inflight.status, inflight.start);
                    } else {
                        // Replenish the stream-level window once half of it
                        // has been consumed (like nghttp2's auto updates)
                        let inflight = &mut conn.streams[pos];
                        inflight.window_debt += data.len();
                        if inflight.window_debt >= (STREAM_WINDOW / 2) as usize {
                            let _ = h2.send_window_update(stream_id, inflight.window_debt as u32);
                            inflight.window_debt = 0;
                        }
                    }
                }
            }
            Event::StreamReset {
                stream_id,
                connection_window_consumed,
                ..
            } => {
                conn.window_debt += connection_window_consumed;
                if let Some(pos) = conn.streams.iter().position(|s| s.stream_id == stream_id) {
                    conn.streams.swap_remove(pos);
                    stats.errors += 1;
                }
            }
            Event::DataDiscarded {
                connection_window_consumed,
                ..
            } => {
                conn.window_debt += connection_window_consumed;
            }
            Event::GoawayReceived { .. } => {
                conn.goaway = true;
            }
            Event::ConnectionError { .. } => {
                alive = false;
            }
            _ => {}
        }
    }
    // Replenish the connection-level window once half of it has been consumed
    // (like nghttp2's auto updates)
    if conn.window_debt >= (CONNECTION_WINDOW / 2) as usize {
        let _ = h2.send_window_update(StreamId::Connection, conn.window_debt as u32);
        conn.window_debt = 0;
    }
    alive
}

/// Benchmark loop of a single HTTP/2 worker thread
///
/// On http:// speaks h2c with prior knowledge (no Upgrade dance): the client
/// preface is sent immediately after the TCP connect. On https:// the
/// protocol is negotiated via ALPN "h2". Up to `parallel` streams are kept in
/// flight per connection.
pub fn run_worker(
    target: &Target,
    tls_setup: Option<&TlsSetup>,
    connections: usize,
    max_requests: u64,
    duration_limit: Option<Duration>,
    connect_timeout: Duration,
    parallel: usize,
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

    let limits = make_limits()?;
    let request_headers = build_request_headers(target);

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
    let (mut submitter, mut sq, mut cq) = ring.split();
    let _ = submitter.register_ring_fd();

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
    // Number of streams opened (requests actually begun). Failed connect
    // attempts also consume one unit of the request budget so that -n
    // terminates when the server is unreachable.
    let mut started: u64 = 0;

    // Duration mode: the deadline is detected solely via the io_uring Timeout CQE
    let timespec = duration_limit.map(|d| Box::new(types::Timespec::from(d)));
    if let Some(ts) = &timespec {
        let entry = io_uring::opcode::Timeout::new(&**ts as *const types::Timespec)
            .build()
            .user_data(TIMEOUT_USER_DATA);
        uring::push_sqe(&submitter, &mut sq, entry)?;
    }

    // Kick off the initial connects (streams are opened on connect completion)
    for (i, conn) in conns.iter_mut().enumerate() {
        if (i as u64) >= max_requests {
            break;
        }
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
        uring::submit_and_wait_timeout(&submitter, uring::WAIT_TIMEOUT)?;

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

            // The connection died (or refused); reconnect if budget remains
            let mut conn_broken = false;

            match op {
                OP_CONNECT => {
                    if res < 0 {
                        // e.g. ECONNREFUSED, or ECANCELED when the LinkTimeout fired
                        stats.errors += 1;
                        stats.connect_errors += 1;
                        started += 1;
                        conn_broken = true;
                    } else {
                        let conn = &mut conns[conn_idx];
                        conn.connected = true;
                        // Arm a connection-lifetime multishot recv right away
                        uring::push_recv_multi(&submitter, &mut sq, conn_idx, conn.generation)?;
                        conn.recv_armed = true;
                        if let Some(setup) = tls_setup {
                            conn.tls = Some(TlsSession::new(setup)?);
                        }
                        // Prior knowledge: send the client preface + SETTINGS
                        // and the first requests in a single flush (in TLS mode
                        // they are buffered until the handshake completes)
                        let mut h2 = Connection::client(limits.clone());
                        h2.initiate()
                            .map_err(|e| anyhow::anyhow!("h2 initiate failed: {e:?}"))?;
                        conn.h2 = Some(h2);
                        fill_streams(
                            conn,
                            &request_headers,
                            parallel,
                            &mut started,
                            max_requests,
                            stop,
                        );
                        flush(&submitter, &mut sq, conn_idx, conn)?;
                    }
                }
                OP_CONNECT_TIMEOUT => {
                    // Handled entirely on the OP_CONNECT side
                }
                OP_SEND => {
                    if res < 0 {
                        conns[conn_idx].fail_inflight(&mut stats);
                        conn_broken = true;
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
                            // More output may have accumulated while sending
                            flush(&submitter, &mut sq, conn_idx, conn)?;
                            if !conn.recv_armed {
                                // Re-arm if the multishot ended (e.g. due to ENOBUFS)
                                uring::push_recv_multi(
                                    &submitter,
                                    &mut sq,
                                    conn_idx,
                                    conn.generation,
                                )?;
                                conn.recv_armed = true;
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
                        if let Some(bid) = cqueue::buffer_select(flags) {
                            buf_ring.recycle(bid);
                        }
                        if res == -libc::ENOBUFS {
                            uring::push_recv_multi(&submitter, &mut sq, conn_idx, conn.generation)?;
                            conn.recv_armed = true;
                        } else {
                            conn.fail_inflight(&mut stats);
                            conn_broken = true;
                        }
                    } else if res == 0 {
                        if let Some(bid) = cqueue::buffer_select(flags) {
                            buf_ring.recycle(bid);
                        }
                        // EOF mid-connection: fail whatever is still in flight
                        conn.fail_inflight(&mut stats);
                        conn_broken = true;
                    } else {
                        stats.bytes_received += res as u64;
                        // Keep our ACKs immediate so a Nagle-enabled peer is
                        // never stuck waiting on our delayed ACK
                        uring::set_quickack(conn.fd);
                        let bid =
                            cqueue::buffer_select(flags).context("recv CQE without buffer id")?;
                        // In TLS mode decrypt into scratch and feed the
                        // plaintext; otherwise feed the socket bytes directly
                        let feed_ok = {
                            let h2 = conn.h2.as_mut().context("recv without h2 connection")?;
                            match &mut conn.tls {
                                Some(tls) => tls
                                    .feed(buf_ring.data(bid, res as usize))
                                    .and_then(|_| {
                                        loop {
                                            let n = tls.read_plaintext(&mut scratch)?;
                                            if n == 0 {
                                                break;
                                            }
                                            h2.feed(&scratch[..n])
                                                .map_err(|e| anyhow::anyhow!("h2 feed: {e:?}"))?;
                                        }
                                        Ok(())
                                    })
                                    .is_ok(),
                                None => h2.feed(buf_ring.data(bid, res as usize)).is_ok(),
                            }
                        };
                        buf_ring.recycle(bid);
                        let process_ok =
                            feed_ok && conn.h2.as_mut().is_some_and(|h2| h2.process().is_ok());
                        if !process_ok || !process_events(conn, &mut stats) {
                            conn.fail_inflight(&mut stats);
                            conn_broken = true;
                        } else if conn.goaway && conn.streams.is_empty() {
                            // GOAWAY and every in-flight stream has drained
                            conn_broken = true;
                        } else {
                            fill_streams(
                                conn,
                                &request_headers,
                                parallel,
                                &mut started,
                                max_requests,
                                stop,
                            );
                            // Send window updates / ACKs / new request HEADERS
                            flush(&submitter, &mut sq, conn_idx, conn)?;
                        }
                    }
                }
                _ => unreachable!(),
            }

            if conn_broken {
                let conn = &mut conns[conn_idx];
                conn.close();
                if !stop && started < max_requests {
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
            }
        }

        if stop {
            break;
        }
    }

    // Best-effort GOAWAY before closing so servers do not log our teardown as
    // a connection error. The frame is tiny, so a non-blocking send on the raw
    // fd is enough; if the socket buffer is full we just close as before.
    for conn in &mut conns {
        if conn.connected
            && let Some(h2) = conn.h2.as_mut()
        {
            let _ = h2.send_goaway(ErrorCode::NoError, Vec::new());
            if let Some(buf) = h2.poll_output() {
                let bytes = match &mut conn.tls {
                    Some(tls) => {
                        let _ = tls.write_plaintext(&buf);
                        tls.take_ciphertext().unwrap_or_default()
                    }
                    None => buf,
                };
                if !bytes.is_empty() {
                    unsafe {
                        libc::send(
                            conn.fd,
                            bytes.as_ptr() as *const libc::c_void,
                            bytes.len(),
                            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        );
                    }
                }
            }
        }
        conn.close();
    }

    Ok(stats)
}
