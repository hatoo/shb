//! HTTP/1.1 benchmark worker

mod parse;

use std::net::TcpStream;
use std::os::fd::{FromRawFd, RawFd};
use std::time::Duration;

use crate::clock::Instant;

use anyhow::{Context, Result, bail};
use io_uring::{Submitter, cqueue, squeue, types};

use self::parse::Parser;
use crate::budget::Budget;
use crate::buf_ring::BufRing;
use crate::stats::Stats;
use crate::target::Target;
use crate::tls::{TlsSession, TlsSetup};
use crate::uring::{
    self, CONN_IDX_BITS, OP_CONNECT, OP_CONNECT_TIMEOUT, OP_RECV, OP_SEND, TIMEOUT_USER_DATA,
};

struct Conn {
    /// -1 when there is no connection: [`Conn::close`] puts it back, and a
    /// successful Connect CQE is what makes it a socket again
    fd: RawFd,
    parser: Parser,
    /// TLS session (https URLs only; recreated per TCP connection)
    tls: Option<TlsSession>,
    /// Bytes currently being sent; must stay untouched while a Send is in flight
    out: Vec<u8>,
    out_off: usize,
    /// Whether a Send SQE is in flight for `out`
    sending: bool,
    /// Whether the next request is waiting for that Send to finish. A server
    /// may answer before it has read the whole request - nginx does for a
    /// location that returns a fixed status - and the request after it must
    /// still follow the end of this one on the wire
    queued: bool,
    /// Whether a multishot recv is active (cleared by a CQE without the MORE flag)
    recv_armed: bool,
    /// Reconnect generation. Incremented on every close; CQEs from an old
    /// generation (e.g. a cancelled multishot recv) are identified via
    /// user_data and ignored
    generation: u64,
    /// When the request in flight left for the socket, which is where its
    /// latency counts from. Meaningless while `unsent` is set.
    request_start: Instant,
    /// Whether the request in flight has yet to reach the socket. The clock
    /// starts when it does: a latency is how long the server took to answer
    /// the request, not how long the connection took to be ready for it, so
    /// the TCP connect and the TLS handshake ahead of a first request are
    /// not counted - which is also where wrk starts its timer. Leaving them
    /// in put a handshake on every fiftieth sample of a `-c 50 -n 200` run
    /// over TLS, and p90 at ten times p50.
    unsent: bool,
    /// When the request in flight stops being worth waiting for, if --timeout
    /// was given. None means nothing is outstanding. Unlike the latency it
    /// counts from when the request was decided on, so a connect that never
    /// answers is given up on too.
    deadline: Option<Instant>,
}

impl Conn {
    fn new() -> Self {
        Conn {
            fd: -1,
            parser: Parser::new(),
            tls: None,
            out: Vec::new(),
            out_off: 0,
            sending: false,
            queued: false,
            recv_armed: false,
            generation: 0,
            request_start: Instant::now(),
            unsent: true,
            deadline: None,
        }
    }

    /// The bytes this connection is sending, wherever they live: ciphertext
    /// it built for itself, or the request, which every connection on the run
    /// shares and none of them writes to. `out_off` is how far into it the
    /// socket has got, and is the only part of that which is per-connection.
    fn outbound<'a>(&'a self, request: &'a [u8]) -> &'a [u8] {
        match self.tls {
            Some(_) => &self.out,
            None => request,
        }
    }

    fn close(&mut self) {
        if self.fd >= 0 {
            self.send_close_notify();
            // Close by turning the fd back into a TcpStream and dropping it
            drop(unsafe { TcpStream::from_raw_fd(self.fd) });
            self.fd = -1;
        }
        self.recv_armed = false;
        self.sending = false;
        self.queued = false;
        self.tls = None;
        self.out.clear();
        self.out_off = 0;
        // Bump the generation so CQEs of operations on the old connection are ignored
        self.generation = (self.generation + 1) & uring::GENERATION_MASK;
    }

    /// Best-effort close_notify before the socket goes, so a TLS server sees
    /// a connection that finished rather than one that was cut off (RFC 8446
    /// Section 6.1): OpenSSL 3 logs the bare FIN as an unexpected EOF. The
    /// alert is one small record, so a non-blocking send on the raw fd is
    /// enough, and if the socket buffer is full it closes as it did before.
    /// The send buffer is the kernel's while a send is in flight, and a
    /// connection closed mid-send is being torn down for an error, so that
    /// case keeps the bare close.
    fn send_close_notify(&mut self) {
        let Some(tls) = &mut self.tls else {
            return;
        };
        if self.sending {
            return;
        }
        tls.send_close_notify();
        if tls.take_ciphertext_into(&mut self.out).is_err() || self.out.is_empty() {
            return;
        }
        unsafe {
            libc::send(
                self.fd,
                self.out.as_ptr() as *const libc::c_void,
                self.out.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            );
        }
    }

    /// Reset per-request state for the next request
    fn begin_request(&mut self, timeout: Option<Duration>) {
        self.unsent = true;
        self.deadline = timeout.map(|t| Instant::now() + t);
    }

    /// The request's bytes are going to the socket: start its clock
    fn mark_sent(&mut self) {
        if self.unsent {
            self.unsent = false;
            self.request_start = Instant::now();
        }
    }
}

/// Queue the request bytes for sending on this connection
///
/// TLS appends to the ciphertext behind whatever is in flight. Plaintext
/// sends read the request where it already is, so starting one is only
/// rewinding the offset - which must wait while a Send is still working
/// through the previous copy: rewound under it, the Send CQE would carry on
/// from the new offset and splice the tail of one request into the head of
/// the next.
fn queue_request(conn: &mut Conn, request: &[u8]) -> Result<()> {
    match &mut conn.tls {
        Some(tls) => tls.write_plaintext(request),
        None => {
            if conn.sending {
                conn.queued = true;
            } else {
                conn.out_off = 0;
            }
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
    request: &[u8],
) -> Result<()> {
    if conn.sending {
        return Ok(());
    }
    if let Some(tls) = &mut conn.tls {
        tls.take_ciphertext_into(&mut conn.out)?;
        if !conn.out.is_empty() {
            // Until the handshake is done the ciphertext is the handshake,
            // and the request is only buffered behind it; the first flush
            // after it finishes is the one that carries the request
            if !tls.is_handshaking() {
                conn.mark_sent();
            }
            conn.out_off = 0;
            conn.sending = true;
            uring::push_send_slice(submitter, sq, conn_idx, conn.generation, &conn.out)?;
        }
    } else if conn.out_off < conn.outbound(request).len() {
        conn.mark_sent();
        conn.sending = true;
        let generation = conn.generation;
        uring::push_send_slice(
            submitter,
            sq,
            conn_idx,
            generation,
            &conn.outbound(request)[conn.out_off..],
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
    budget: Budget,
    connect_timeout: Duration,
    timeout: Option<Duration>,
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

    let is_head = target.method == "HEAD";

    // Declare buf_ring / conns before the ring. Reverse drop order then
    // destroys the ring first (its teardown waits for in-flight operations to
    // be cancelled), preventing a use-after-free where the kernel writes into
    // buffers that have already been freed.
    let buf_entries = (connections * 2).next_power_of_two().clamp(64, 32768) as u16;
    let mut buf_ring = BufRing::new(buf_entries)?;
    let mut conns: Vec<Conn> = Vec::with_capacity(connections);
    for _ in 0..connections {
        let mut conn = Conn::new();
        // The method never changes during a run, so the parser is told once
        conn.parser.set_head_request(is_head);
        conns.push(conn);
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
    let mut started: u64 = 0;

    // Held for its lifetime: the SQE points at it until the run is over
    let _deadline = uring::arm_deadline(&submitter, &mut sq, budget.deadline())?;

    // Kick off the initial requests (connection setup is async via io_uring too)
    for (i, conn) in conns.iter_mut().enumerate() {
        if !budget.may_start(started) {
            break;
        }
        started += 1;
        conn.begin_request(timeout);
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

    let mut stop = false;
    // Plaintext scratch for the TLS path, reused across receives
    let mut plain = vec![0u8; 32 * 1024];
    // How many completions one wait should collect before returning
    let batch = uring::batch_size(connections);

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
        if timeout.is_some() {
            let now = Instant::now();
            for (conn_idx, conn) in conns.iter_mut().enumerate() {
                if conn.deadline.is_some_and(|d| now >= d) {
                    stats.errors += 1;
                    conn.deadline = None;
                    conn.close();
                    conn.parser.reset();
                    if stop || !budget.may_start(started) {
                        continue;
                    }
                    started += 1;
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
                        // Arm a connection-lifetime multishot recv right away
                        push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
                        if let Some(setup) = tls_setup {
                            conn.tls = Some(TlsSession::new(setup)?);
                        }
                        // Re-arms the response deadline, which a reconnect
                        // otherwise loses; the latency clock waits for the
                        // request itself to leave
                        conn.begin_request(timeout);
                        queue_request(conn, &target.request_bytes)?;
                        flush(&submitter, &mut sq, conn_idx, conn, &target.request_bytes)?;
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
                        if conn.out_off < conn.outbound(&target.request_bytes).len() {
                            let generation = conn.generation;
                            uring::push_send_slice(
                                &submitter,
                                &mut sq,
                                conn_idx,
                                generation,
                                &conn.outbound(&target.request_bytes)[conn.out_off..],
                            )?;
                        } else {
                            conn.sending = false;
                            // The request that finished under this send goes
                            // out now, from the start
                            if conn.queued {
                                conn.queued = false;
                                conn.out_off = 0;
                            }
                            // TLS may have produced more ciphertext meanwhile
                            flush(&submitter, &mut sq, conn_idx, conn, &target.request_bytes)?;
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
                        if conn.parser.mark_eof() {
                            stats.record_success(conn.parser.status(), conn.request_start);
                            conn.deadline = None;
                        } else {
                            stats.errors += 1;
                        }
                        request_finished = true;
                        keep_conn = false;
                    } else {
                        stats.bytes_received += res as u64;
                        let bid =
                            cqueue::buffer_select(flags).context("recv CQE without buffer id")?;
                        // Plaintext feeds the received bytes to the parser
                        // as they are; TLS decrypts into a reused scratch
                        // buffer first
                        let done: Result<usize> = match &mut conn.tls {
                            Some(tls) => {
                                let parser = &mut conn.parser;
                                let mut completed = 0;
                                tls.feed_into(
                                    buf_ring.data(bid, res as usize),
                                    &mut plain,
                                    |bytes| {
                                        completed += parser.feed(bytes)?;
                                        Ok(())
                                    },
                                )
                                .map(|()| completed)
                            }
                            None => conn.parser.feed(buf_ring.data(bid, res as usize)),
                        };
                        buf_ring.recycle(bid);
                        match done {
                            Ok(0) => {
                                if !conn.recv_armed {
                                    push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
                                }
                                // The TLS handshake may need to send its next
                                // flight even though no request completed
                                flush(&submitter, &mut sq, conn_idx, conn, &target.request_bytes)?;
                            }
                            Ok(_) => {
                                stats.record_success(conn.parser.status(), conn.request_start);
                                request_finished = true;
                                keep_conn = conn.parser.keep_alive() && !target.disable_keepalive;
                            }
                            Err(_) => {
                                stats.errors += 1;
                                request_finished = true;
                                keep_conn = false;
                            }
                        }
                    }
                }
                _ => unreachable!(),
            }

            if request_finished {
                let conn = &mut conns[conn_idx];
                if !stop && budget.may_start(started) {
                    started += 1;
                    conn.begin_request(timeout);
                    // Every path that finishes a request also says whether the
                    // connection survives it, and none of them keeps one that
                    // was never established
                    debug_assert!(!keep_conn || conn.fd >= 0, "reusing a closed connection");
                    if keep_conn {
                        if !conn.recv_armed {
                            push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
                        }
                        queue_request(conn, &target.request_bytes)?;
                        flush(&submitter, &mut sq, conn_idx, conn, &target.request_bytes)?;
                    } else {
                        conn.close();
                        conn.parser.reset();
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
