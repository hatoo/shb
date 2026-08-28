use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use io_uring::{IoUring, Submitter, cqueue, opcode, squeue, types};

use crate::buf_ring::BufRing;
use crate::conn::{Conn, ParseOutcome, make_socket};
use crate::stats::Stats;
use crate::target::Target;

/// Buffer group ID of the provided buffer ring (one per worker)
const BUF_GROUP: u16 = 0;
const TIMEOUT_USER_DATA: u64 = u64::MAX;

// user_data layout: low 2 bits are the operation kind, the next CONN_IDX_BITS
// bits are the connection index, and the rest is the reconnect generation
const OP_SEND: u64 = 0;
const OP_RECV: u64 = 1;
const OP_CONNECT: u64 = 2;
const OP_CONNECT_TIMEOUT: u64 = 3;
const CONN_IDX_BITS: u64 = 20;

fn user_data(conn_idx: usize, generation: u64, op: u64) -> u64 {
    (generation << (2 + CONN_IDX_BITS)) | ((conn_idx as u64) << 2) | op
}

fn push_sqe(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    entry: squeue::Entry,
) -> Result<()> {
    unsafe {
        if sq.push(&entry).is_err() {
            // Publish the tail, let the kernel consume, refresh the head, retry
            sq.sync();
            submitter.submit().context("io_uring submit failed")?;
            sq.sync();
            sq.push(&entry)
                .map_err(|_| anyhow::anyhow!("submission queue full after submit"))?;
        }
    }
    Ok(())
}

/// Push two linked SQEs within a single submission
///
/// An IOSQE_IO_LINK chain must not cross a submission boundary, so submit
/// first to make room when fewer than 2 slots are free.
fn push_sqe_pair(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    first: squeue::Entry,
    second: squeue::Entry,
) -> Result<()> {
    unsafe {
        if sq.capacity() - sq.len() < 2 {
            sq.sync();
            submitter.submit().context("io_uring submit failed")?;
            sq.sync();
        }
        sq.push(&first)
            .map_err(|_| anyhow::anyhow!("submission queue full"))?;
        sq.push(&second)
            .map_err(|_| anyhow::anyhow!("submission queue full"))?;
    }
    Ok(())
}

/// Start an async connect (a Connect SQE + a LinkTimeout as the connect timeout)
///
/// The created fd is registered into the fixed file slot of the connection
/// index; all subsequent SQEs refer to it as `types::Fixed(conn_idx)`.
fn start_connect(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &mut Conn,
    addr: &SocketAddr,
    raw_addr: &socket2::SockAddr,
    timeout: &types::Timespec,
) -> Result<()> {
    conn.fd = make_socket(addr)?;
    // Overwriting the slot also releases the registered reference to the old fd
    submitter
        .register_files_update(conn_idx as u32, &[conn.fd])
        .context("register_files_update failed")?;
    let connect = opcode::Connect::new(
        types::Fixed(conn_idx as u32),
        raw_addr.as_ptr().cast::<libc::sockaddr>(),
        raw_addr.len(),
    )
    .build()
    .flags(squeue::Flags::IO_LINK)
    .user_data(user_data(conn_idx, conn.generation, OP_CONNECT));
    let link_timeout = opcode::LinkTimeout::new(timeout as *const types::Timespec)
        .build()
        .user_data(user_data(conn_idx, conn.generation, OP_CONNECT_TIMEOUT));
    push_sqe_pair(submitter, sq, connect, link_timeout)
}

/// Send the request
///
/// Note: WriteFixed + a registered buffer was also tried, but the socket write
/// path is slower than the send path and fixed buffers gain nothing for ~100B
/// sends, measuring about 4% worse (2026-08). Keep using Send.
fn push_send(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &Conn,
    request: &[u8],
) -> Result<()> {
    let remaining = &request[conn.send_offset..];
    let entry = opcode::Send::new(
        types::Fixed(conn_idx as u32),
        remaining.as_ptr(),
        remaining.len() as u32,
    )
    .build()
    .user_data(user_data(conn_idx, conn.generation, OP_SEND));
    push_sqe(submitter, sq, entry)
}

/// Arm a multishot recv
///
/// A single submission keeps delivering a CQE per receive while the MORE flag
/// stays set, so no per-response Recv SQE is needed. The kernel picks receive
/// buffers from the provided buffer ring and reports the buffer ID in the CQE
/// flags.
fn push_recv_multi(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &mut Conn,
) -> Result<()> {
    let entry = opcode::RecvMulti::new(types::Fixed(conn_idx as u32), BUF_GROUP)
        .build()
        .user_data(user_data(conn_idx, conn.generation, OP_RECV));
    push_sqe(submitter, sq, entry)?;
    conn.recv_armed = true;
    Ok(())
}

/// Benchmark loop of a single worker thread
///
/// Owns a dedicated io_uring and set of connections; shares no state with
/// other threads.
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
    // SINGLE_ISSUER: promise the kernel that only this thread touches the ring
    // COOP_TASKRUN / DEFER_TASKRUN: run socket-completion task work in batches
    // at io_uring_enter instead of interrupting at arbitrary times (kernel 6.1+)
    // NO_SQARRAY: drop the SQ indirection array (kernel 6.6+)
    // CQSIZE: avoid CQ overflow from bursts of multishot recv CQEs
    let mut ring = IoUring::builder()
        .setup_single_issuer()
        .setup_coop_taskrun()
        .setup_defer_taskrun()
        .setup_no_sqarray()
        .setup_cqsize(entries * 4)
        .build(entries)
        .or_else(|_| {
            // Fallback for older kernels
            IoUring::new(entries)
        })
        .context("failed to create io_uring")?;

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
        let entry = opcode::Timeout::new(&**ts as *const types::Timespec)
            .build()
            .user_data(TIMEOUT_USER_DATA);
        push_sqe(&submitter, &mut sq, entry)?;
    }

    // Kick off the initial requests (connection setup is async via io_uring too)
    for (i, conn) in conns.iter_mut().enumerate() {
        if started >= max_requests {
            break;
        }
        started += 1;
        conn.begin_request();
        start_connect(
            &submitter,
            &mut sq,
            i,
            conn,
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
            let op = ud & 0b11;
            let conn_idx = ((ud >> 2) & ((1 << CONN_IDX_BITS) - 1)) as usize;
            let generation = ud >> (2 + CONN_IDX_BITS);

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
                        // Latency is measured from send start (excludes connection setup)
                        conn.request_start = Instant::now();
                        push_send(&submitter, &mut sq, conn_idx, conn, &target.request_bytes)?;
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
                        conn.send_offset += res as usize;
                        if conn.send_offset < target.request_bytes.len() {
                            push_send(&submitter, &mut sq, conn_idx, conn, &target.request_bytes)?;
                        } else if !conn.recv_armed {
                            // Re-arm if the multishot ended (e.g. due to ENOBUFS)
                            push_recv_multi(&submitter, &mut sq, conn_idx, conn)?;
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
                                Ok(ParseOutcome::Complete { .. }) => stats.record_success(conn),
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
                        let feed_result = conn.decoder.feed(buf_ring.data(bid, res as usize));
                        buf_ring.recycle(bid);
                        if feed_result.is_err() {
                            stats.errors += 1;
                            request_finished = true;
                            keep_conn = false;
                        } else {
                            match conn.parse() {
                                Ok(ParseOutcome::Complete { keep_alive }) => {
                                    stats.record_success(conn);
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
                        push_send(&submitter, &mut sq, conn_idx, conn, &target.request_bytes)?;
                    } else {
                        conn.close();
                        conn.decoder.reset();
                        if let Err(e) = start_connect(
                            &submitter,
                            &mut sq,
                            conn_idx,
                            conn,
                            &target.addr,
                            &raw_addr,
                            &connect_timeout,
                        ) {
                            eprintln!("reconnect failed: {e}");
                            break 'outer;
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
