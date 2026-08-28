//! HTTP/2 (h2c, prior knowledge) benchmark worker

use std::net::TcpStream;
use std::os::fd::{FromRawFd, RawFd};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use io_uring::{Submitter, cqueue, squeue, types};
use shiguredo_http2::{Connection, Event, HeaderField, Limits, StreamId, WindowSize};

use crate::buf_ring::BufRing;
use crate::stats::Stats;
use crate::target::Target;
use crate::uring::{
    self, BUF_GROUP, CONN_IDX_BITS, OP_CONNECT, OP_CONNECT_TIMEOUT, OP_RECV, OP_SEND,
    TIMEOUT_USER_DATA,
};

/// Stream-level receive window advertised via SETTINGS_INITIAL_WINDOW_SIZE.
/// Large enough that per-stream WINDOW_UPDATEs are rare for typical bodies.
const STREAM_WINDOW: u32 = 4 * 1024 * 1024;
/// Connection-level receive window advertised at connection setup.
/// The slack absorbs replenishment inaccuracies (e.g. padded DATA frames).
const CONNECTION_WINDOW: u32 = 64 * 1024 * 1024;

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
fn build_request_headers(target: &Target) -> Result<Vec<HeaderField>> {
    Ok(vec![
        HeaderField::new(":method", "GET").map_err(|e| anyhow::anyhow!("header: {e:?}"))?,
        HeaderField::new(":scheme", "http").map_err(|e| anyhow::anyhow!("header: {e:?}"))?,
        HeaderField::new(":authority", &target.authority)
            .map_err(|e| anyhow::anyhow!("header: {e:?}"))?,
        HeaderField::new(":path", &target.path).map_err(|e| anyhow::anyhow!("header: {e:?}"))?,
    ])
}

struct Conn {
    fd: RawFd,
    /// Whether the TCP connection is established (true after a successful Connect CQE)
    connected: bool,
    /// HTTP/2 connection state machine (recreated per TCP connection)
    h2: Option<Connection>,
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
    /// Stream ID of the in-flight request (one request at a time per connection)
    stream: Option<StreamId>,
    /// Status code of the in-flight request (0 = not received yet)
    status_code: u16,
    request_start: Instant,
}

impl Conn {
    fn new() -> Self {
        Conn {
            fd: -1,
            connected: false,
            h2: None,
            out: Vec::new(),
            out_off: 0,
            sending: false,
            recv_armed: false,
            generation: 0,
            stream: None,
            status_code: 0,
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
        self.out.clear();
        self.out_off = 0;
        self.h2 = None;
        self.stream = None;
        // Bump the generation so CQEs of operations on the old connection are ignored
        self.generation += 1;
    }

    /// Open a new stream for the next request
    fn start_request(&mut self, request_headers: &[HeaderField]) -> Result<()> {
        let h2 = self.h2.as_mut().context("no h2 connection")?;
        let stream_id = h2
            .start_stream(request_headers.to_vec(), true)
            .map_err(|e| anyhow::anyhow!("start_stream failed: {e:?}"))?;
        self.stream = Some(stream_id);
        self.status_code = 0;
        self.request_start = Instant::now();
        Ok(())
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
    if let Some(buf) = h2.poll_output() {
        conn.out = buf;
        conn.out_off = 0;
        conn.sending = true;
        uring::push_send_slice(submitter, sq, conn_idx, conn.generation, &conn.out)?;
    }
    Ok(())
}

/// What happened to the in-flight request after processing h2 events
struct EventOutcome {
    /// The in-flight request finished
    finished: bool,
    /// It finished successfully (response fully received)
    success: bool,
    /// The TCP connection can be reused for the next request
    keep_conn: bool,
}

/// Drain h2 events, replenish flow-control windows, and report the outcome of
/// the in-flight request
fn process_events(conn: &mut Conn) -> EventOutcome {
    let mut outcome = EventOutcome {
        finished: false,
        success: false,
        keep_conn: true,
    };
    let Some(h2) = conn.h2.as_mut() else {
        return outcome;
    };
    // Bytes counted against the connection-level receive window that we must
    // hand back via WINDOW_UPDATE
    let mut conn_consumed: usize = 0;
    while let Some(event) = h2.poll_event() {
        match event {
            Event::HeadersReceived {
                stream_id,
                headers,
                end_stream,
                ..
            } => {
                if Some(stream_id) == conn.stream {
                    for field in &headers {
                        if field.name() == b":status" {
                            conn.status_code = std::str::from_utf8(field.value())
                                .ok()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                        }
                    }
                    if end_stream {
                        outcome.finished = true;
                        outcome.success = true;
                    }
                }
            }
            Event::DataReceived {
                stream_id,
                data,
                end_stream,
            } => {
                conn_consumed += data.len();
                if Some(stream_id) == conn.stream {
                    if end_stream {
                        outcome.finished = true;
                        outcome.success = true;
                    } else if !data.is_empty() {
                        // Replenish the stream-level window; best effort, the
                        // stream may already be gone
                        let _ = h2.send_window_update(stream_id, data.len() as u32);
                    }
                }
            }
            Event::StreamReset {
                stream_id,
                connection_window_consumed,
                ..
            } => {
                conn_consumed += connection_window_consumed;
                if Some(stream_id) == conn.stream && !outcome.finished {
                    outcome.finished = true;
                    outcome.success = false;
                }
            }
            Event::DataDiscarded {
                connection_window_consumed,
                ..
            } => {
                conn_consumed += connection_window_consumed;
            }
            Event::GoawayReceived { .. } => {
                outcome.keep_conn = false;
            }
            Event::ConnectionError { .. } => {
                outcome.keep_conn = false;
                if !outcome.finished {
                    outcome.finished = true;
                    outcome.success = false;
                }
            }
            _ => {}
        }
    }
    // Replenish the connection-level window in one batch
    if conn_consumed > 0 {
        let _ = h2.send_window_update(StreamId::Connection, conn_consumed as u32);
    }
    outcome
}

/// Benchmark loop of a single HTTP/2 worker thread
///
/// Speaks h2c with prior knowledge (no Upgrade dance): the client preface is
/// sent immediately after the TCP connect. One request is in flight per
/// connection at a time.
pub fn run_worker(
    target: &Target,
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

    let limits = make_limits()?;
    let request_headers = build_request_headers(target)?;

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
    let mut stop = false;

    'outer: loop {
        if stats.completed + stats.errors >= max_requests {
            break;
        }
        // Publish the tail of pushed SQEs before submitting
        sq.sync();
        submitter
            .submit_and_wait(1)
            .context("submit_and_wait failed")?;

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
                        uring::push_recv_multi(&submitter, &mut sq, conn_idx, conn.generation)?;
                        conn.recv_armed = true;
                        // h2c prior knowledge: send the client preface + SETTINGS
                        // and the first request in a single flush
                        let mut h2 = Connection::client(limits.clone());
                        h2.initiate()
                            .map_err(|e| anyhow::anyhow!("h2 initiate failed: {e:?}"))?;
                        conn.h2 = Some(h2);
                        conn.start_request(&request_headers)?;
                        flush(&submitter, &mut sq, conn_idx, conn)?;
                    }
                }
                OP_CONNECT_TIMEOUT => {
                    // Handled entirely on the OP_CONNECT side
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
                            let remaining_gen = conn.generation;
                            uring::push_send_slice(
                                &submitter,
                                &mut sq,
                                conn_idx,
                                remaining_gen,
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
                            stats.errors += 1;
                            request_finished = true;
                            keep_conn = false;
                        }
                    } else if res == 0 {
                        if let Some(bid) = cqueue::buffer_select(flags) {
                            buf_ring.recycle(bid);
                        }
                        // EOF mid-request is always an error for HTTP/2
                        stats.errors += 1;
                        request_finished = true;
                        keep_conn = false;
                    } else {
                        stats.bytes_received += res as u64;
                        let bid =
                            cqueue::buffer_select(flags).context("recv CQE without buffer id")?;
                        let feed_ok = {
                            let h2 = conn.h2.as_mut().context("recv without h2 connection")?;
                            h2.feed(buf_ring.data(bid, res as usize)).is_ok()
                        };
                        buf_ring.recycle(bid);
                        let process_ok =
                            feed_ok && conn.h2.as_mut().is_some_and(|h2| h2.process().is_ok());
                        if !process_ok {
                            stats.errors += 1;
                            request_finished = true;
                            keep_conn = false;
                        } else {
                            let outcome = process_events(conn);
                            keep_conn = outcome.keep_conn;
                            if outcome.finished {
                                if outcome.success {
                                    stats.record_success(conn.status_code, conn.request_start);
                                } else {
                                    stats.errors += 1;
                                }
                                conn.stream = None;
                                request_finished = true;
                            }
                            // Send window updates / ACKs generated above
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
                    if keep_conn && conn.connected && conn.h2.is_some() {
                        if !conn.recv_armed {
                            uring::push_recv_multi(&submitter, &mut sq, conn_idx, conn.generation)?;
                            conn.recv_armed = true;
                        }
                        conn.start_request(&request_headers)?;
                        flush(&submitter, &mut sq, conn_idx, conn)?;
                    } else {
                        conn.close();
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
