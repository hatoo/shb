//! HTTP/2 benchmark worker (h2c prior knowledge, or ALPN "h2" over TLS)
//!
//! The protocol itself lives in [`conn`] and [`hpack`]; this module moves its
//! bytes with io_uring and turns its events into statistics.

mod conn;
mod hpack;

use std::net::TcpStream;
use std::os::fd::{FromRawFd, RawFd};
use std::time::Duration;

use crate::clock::Instant;

use self::conn::{Connection, Event};
use crate::budget::Budget;
use crate::buf_ring::BufRing;
use crate::inflight::H2Ring;
use crate::stats::Stats;
use crate::target::Target;
use crate::tls::{TlsSession, TlsSetup};
use crate::uring::{
    self, CONN_IDX_BITS, OP_CONNECT, OP_CONNECT_TIMEOUT, OP_RECV, OP_SEND, TIMEOUT_USER_DATA,
};
use anyhow::{Context, Result, bail};
use io_uring::{Submitter, cqueue, squeue, types};

/// Build the HPACK block sent for every request on every connection
///
/// They are encoded once and then memcpy'd per request; nothing in them
/// depends on the stream or the connection.
fn build_header_block(target: &Target) -> Vec<u8> {
    let headers: Vec<(String, String)> = target
        .headers
        .iter()
        .filter(|(name, _)| !crate::target::is_connection_specific(name))
        // HTTP/2 requires lower-case field names (RFC 9113 Section 8.2.1)
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    hpack::encode_request(
        &target.method,
        if target.tls { "https" } else { "http" },
        &target.authority,
        &target.path,
        &headers,
        target.body.len(),
    )
}

/// An in-flight request (one open stream)
struct InFlight {
    start: Instant,
    /// Status code from :status (0 = not received yet)
    status: u16,
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
    /// Output is waiting and has not been submitted yet. Set while completions
    /// are being drained, cleared by the flush pass after them, so requests
    /// generated across a whole batch leave in one send rather than one each.
    needs_flush: bool,
    /// Whether a multishot recv is active (cleared by a CQE without the MORE flag)
    recv_armed: bool,
    /// GOAWAY received: no new streams, reconnect once in-flight streams drain
    goaway: bool,
    /// Reconnect generation. Incremented on every close; CQEs from an old
    /// generation (e.g. a cancelled multishot recv) are identified via
    /// user_data and ignored
    generation: u64,
    /// In-flight requests, up to the configured parallelism
    streams: H2Ring<InFlight>,
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
            needs_flush: false,
            recv_armed: false,
            goaway: false,
            generation: 0,
            streams: H2Ring::new(),
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
        self.out.clear();
        self.out_off = 0;
        self.h2 = None;
        self.tls = None;
        self.streams.clear();
        // Bump the generation so CQEs of operations on the old connection are ignored
        self.generation = (self.generation + 1) & uring::GENERATION_MASK;
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
    header_block: &[u8],
    body: &[u8],
    parallel: usize,
    started: &mut u64,
    budget: Budget,
    stop: bool,
) {
    if stop || conn.goaway {
        return;
    }
    let Some(h2) = conn.h2.as_mut() else {
        return;
    };
    // A body that did not fit the windows when its stream opened leaves as the
    // peer grants credit, which is what has just arrived
    h2.pump_bodies(body);
    while conn.streams.len() < parallel && budget.may_start(*started) {
        let Some(stream_id) = h2.start_stream(header_block, body) else {
            break;
        };
        conn.streams.push(
            stream_id as u64,
            InFlight {
                start: Instant::now(),
                status: 0,
            },
        );
        *started += 1;
    }
    // Out of stream ids: this connection can carry no more requests, which is
    // the state a GOAWAY leaves it in, so it drains and is replaced the same
    // way.
    if h2.stream_ids_exhausted() {
        conn.goaway = true;
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
            if let Some(buf) = h2.take_output() {
                tls.write_plaintext(&buf)?;
                h2.recycle(buf);
            }
            tls.take_ciphertext_into(&mut conn.out)?;
            if !conn.out.is_empty() {
                conn.out_off = 0;
                conn.sending = true;
                uring::push_send_slice(submitter, sq, conn_idx, conn.generation, &conn.out)?;
            }
        }
        None => {
            if let Some(buf) = h2.take_output() {
                conn.out = buf;
                conn.out_off = 0;
                conn.sending = true;
                uring::push_send_slice(submitter, sq, conn_idx, conn.generation, &conn.out)?;
            }
        }
    }
    Ok(())
}

/// Turn the connection's events into statistics
///
/// A request is found by its stream number, which is where its slot is.
fn process_events(conn: &mut Conn, events: &[Event], stats: &mut Stats) {
    for event in events {
        match *event {
            Event::Status { stream_id, status } => {
                if let Some(inflight) = conn.streams.get_mut(stream_id as u64) {
                    inflight.status = status;
                }
            }
            Event::End { stream_id } => {
                if let Some(inflight) = conn.streams.take(stream_id as u64) {
                    if inflight.status == 0 {
                        // Every response begins with HEADERS carrying :status
                        // (RFC 9113 Section 8.1). A stream that ends without
                        // one is not a response, and counting it as a success
                        // would report a request that never got an answer
                        stats.errors += 1;
                    } else {
                        stats.record_success(inflight.status, inflight.start);
                    }
                }
            }
            Event::Reset { stream_id } => {
                if conn.streams.take(stream_id as u64).is_some() {
                    stats.errors += 1;
                }
            }
            Event::Goaway => conn.goaway = true,
        }
    }
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
    budget: Budget,
    connect_timeout: Duration,
    timeout: Option<Duration>,
    parallel: usize,
) -> Result<Stats> {
    if connections == 0 || budget.is_empty() {
        return Ok(Stats::default());
    }
    if connections > 1 << CONN_IDX_BITS {
        bail!(
            "too many connections per thread (max {})",
            1u64 << CONN_IDX_BITS
        );
    }

    let header_block = build_header_block(target);
    // Reused across receives so events never allocate on the hot path
    let mut events: Vec<Event> = Vec::with_capacity(64);

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

    let mut ring = uring::build_worker_ring(connections)?;
    // Kept alive so that enter can use the registered ring fd; submitter, sq
    // and cq are disjoint borrows, and the ring is not touched from here on
    let (mut submitter, mut sq, mut cq) = ring.split();
    uring::register_worker(&mut submitter, connections, &buf_ring)?;

    // The sockaddr / Timespec referenced by Connect SQEs must stay at a stable
    // address until completion
    let raw_addr = Box::new(socket2::SockAddr::from(target.addr));
    let connect_timeout = Box::new(types::Timespec::from(connect_timeout));

    let mut stats = Stats::default();
    if let Some(n) = budget.expected_requests() {
        stats.latencies_ns.reserve(n as usize);
    }
    // Number of streams opened (requests actually begun). Failed connect
    // attempts also consume one unit of the request budget so that -n
    // terminates when the server is unreachable.
    let mut started: u64 = 0;

    // Held for its lifetime: the SQE points at it until the run is over
    let _deadline = uring::arm_deadline(&submitter, &mut sq, budget.deadline())?;

    // Kick off the initial connects (streams are opened on connect completion)
    for (i, conn) in conns.iter_mut().enumerate() {
        if !budget.may_start(i as u64) {
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

    // Reusable buffer for decrypted plaintext (TLS mode)
    let mut scratch = vec![0u8; 64 * 1024];
    let mut stop = false;
    // How many completions one wait should collect before returning
    let batch = uring::batch_size_multiplexed(parallel);

    'outer: loop {
        if budget.is_met(stats.completed + stats.errors) {
            break;
        }
        if crate::shutdown::requested() {
            break;
        }
        // Publish the tail of pushed SQEs before submitting
        sq.sync();
        uring::submit_and_wait_timeout(&submitter, uring::WAIT_TIMEOUT, batch)?;

        cq.sync();

        // A response that never comes would otherwise hold the run open for
        // ever: a wedged server is a result to report, not a reason to wait
        if let Some(limit) = timeout {
            let now = Instant::now();
            for (conn_idx, conn) in conns.iter_mut().enumerate() {
                if !conn
                    .streams
                    .iter()
                    .any(|s| now.duration_since(s.start) >= limit)
                {
                    continue;
                }
                conn.fail_inflight(&mut stats);
                conn.close();
                if !stop && budget.may_start(started) {
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

        for cqe in &mut cq {
            let (ud, res, flags) = (cqe.user_data(), cqe.result(), cqe.flags());
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
                        let mut h2 = Connection::new();
                        h2.initiate();
                        conn.h2 = Some(h2);
                        fill_streams(
                            conn,
                            &header_block,
                            &target.body,
                            parallel,
                            &mut started,
                            budget,
                            stop,
                        );
                        conn.needs_flush = true;
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
                            // Without TLS the buffer just sent is h2's own, and
                            // it goes back to be written into again
                            if conn.tls.is_none()
                                && let Some(h2) = conn.h2.as_mut()
                            {
                                h2.recycle(std::mem::take(&mut conn.out));
                            }
                            // More output may have accumulated while sending
                            conn.needs_flush = true;
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
                        let bid =
                            cqueue::buffer_select(flags).context("recv CQE without buffer id")?;
                        // In TLS mode decrypt into scratch and feed the
                        // plaintext; otherwise feed the socket bytes directly
                        events.clear();
                        let feed_ok = {
                            let h2 = conn.h2.as_mut().context("recv without h2 connection")?;
                            match &mut conn.tls {
                                Some(tls) => tls
                                    .feed_into(
                                        buf_ring.data(bid, res as usize),
                                        &mut scratch,
                                        |plain| h2.feed(plain, &mut events),
                                    )
                                    .is_ok(),
                                None => h2
                                    .feed(buf_ring.data(bid, res as usize), &mut events)
                                    .is_ok(),
                            }
                        };
                        buf_ring.recycle(bid);
                        process_events(conn, &events, &mut stats);
                        if !feed_ok {
                            conn.fail_inflight(&mut stats);
                            conn_broken = true;
                        } else if conn.goaway && conn.streams.is_empty() {
                            // GOAWAY and every in-flight stream has drained
                            conn_broken = true;
                        } else {
                            fill_streams(
                                conn,
                                &header_block,
                                &target.body,
                                parallel,
                                &mut started,
                                budget,
                                stop,
                            );
                            // Window updates / ACKs / new request HEADERS go
                            // out in the flush pass below
                            conn.needs_flush = true;
                        }
                    }
                }
                _ => unreachable!(),
            }

            if conn_broken {
                let conn = &mut conns[conn_idx];
                conn.close();
                if !stop && budget.may_start(started) {
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

        // One send per connection for everything this batch produced. Sending
        // from each completion instead put a request on the wire on its own,
        // and TCP_NODELAY made each one its own segment.
        for (conn_idx, conn) in conns.iter_mut().enumerate() {
            if conn.needs_flush {
                conn.needs_flush = false;
                flush(&submitter, &mut sq, conn_idx, conn)?;
            }
        }

        if stop {
            break;
        }
    }

    // Best-effort GOAWAY before closing so servers do not log our teardown as
    // a connection error. The frame is tiny, so a non-blocking send on the raw
    // fd is enough; if the socket buffer is full we just close as before.
    //
    // It has to follow what the ring is sending rather than land in the
    // middle of it. The sends the last flush pushed were never submitted, and
    // a TCP send completes at submission unless the socket buffer is full, so
    // one submit that does not wait finishes nearly all of them; a connection
    // whose send is still not done gets no GOAWAY and is closed as before.
    sq.sync();
    let _ = uring::submit_and_wait_timeout(&submitter, Duration::ZERO, 1);
    cq.sync();
    for cqe in &mut cq {
        let (ud, res, flags) = (cqe.user_data(), cqe.result(), cqe.flags());
        if let Some(bid) = cqueue::buffer_select(flags) {
            buf_ring.recycle(bid);
        }
        if ud == TIMEOUT_USER_DATA {
            continue;
        }
        let (op, conn_idx, generation) = uring::decode_user_data(ud);
        let conn = &mut conns[conn_idx];
        if op == OP_SEND && generation == conn.generation && res > 0 {
            conn.out_off += res as usize;
            conn.sending = conn.out_off < conn.out.len();
        }
    }
    for conn in &mut conns {
        if conn.connected
            && !conn.sending
            && let Some(h2) = conn.h2.as_mut()
        {
            h2.send_goaway();
            if let Some(buf) = h2.take_output() {
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
