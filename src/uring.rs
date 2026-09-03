use std::net::SocketAddr;
use std::os::fd::{IntoRawFd, RawFd};
use std::time::Duration;

use anyhow::{Context, Result};
use io_uring::{IoUring, Submitter, opcode, squeue, types};

use crate::buf_ring::BufRing;

/// Buffer group ID of the provided buffer ring (one per worker)
pub const BUF_GROUP: u16 = 0;
pub const TIMEOUT_USER_DATA: u64 = u64::MAX;

// user_data layout: low 2 bits are the operation kind, the next CONN_IDX_BITS
// bits are the connection index, and the rest is the reconnect generation
pub const OP_SEND: u64 = 0;
pub const OP_RECV: u64 = 1;
pub const OP_CONNECT: u64 = 2;
pub const OP_CONNECT_TIMEOUT: u64 = 3;
pub const CONN_IDX_BITS: u64 = 20;

pub fn user_data(conn_idx: usize, generation: u64, op: u64) -> u64 {
    (generation << (2 + CONN_IDX_BITS)) | ((conn_idx as u64) << 2) | op
}

/// Decode a user_data value into (op, conn_idx, generation)
pub fn decode_user_data(ud: u64) -> (u64, usize, u64) {
    let op = ud & 0b11;
    let conn_idx = ((ud >> 2) & ((1 << CONN_IDX_BITS) - 1)) as usize;
    let generation = ud >> (2 + CONN_IDX_BITS);
    (op, conn_idx, generation)
}

/// Create an unconnected TCP socket with TCP_NODELAY set
pub fn make_socket(addr: &SocketAddr) -> Result<RawFd> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(*addr),
        socket2::Type::STREAM,
        None,
    )
    .context("socket() failed")?;
    socket
        .set_tcp_nodelay(true)
        .context("setsockopt(TCP_NODELAY) failed")?;
    Ok(socket.into_raw_fd())
}

/// Upper bound for a single submit_and_wait so workers notice a Ctrl-C
/// shutdown request promptly even when completely idle. During active
/// benchmarking CQEs arrive far more often, so this timeout almost never
/// fires.
pub const WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);

/// Largest batch of completions a single wait will hold out for
///
/// Measured on loopback: 8 captures nearly all of the syscall saving, while 16
/// and 32 start giving it back.
const MAX_BATCH: usize = 8;

/// The ceiling for HTTP/2, where waiting pays off for longer. See
/// [`batch_size_multiplexed`].
const MAX_BATCH_MULTIPLEXED: usize = 32;

/// How long the kernel may linger collecting a batch before returning with
/// whatever has arrived
const BATCH_LINGER: u32 = 500;

/// Whether the kernel supports `min_wait_usec` (IORING_FEAT_MIN_TIMEOUT, 6.12+)
static MIN_TIMEOUT_OK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Share of a worker's connections one wait may hold out for
///
/// A completion is what lets its connection issue the next request, so waiting
/// on a batch stalls that fraction of the worker's pipeline. Waiting for a
/// quarter of the connections amortises the syscall without the batch ever
/// needing a full round trip to fill. Measured against a server fast enough to
/// keep shb on the critical path: a quarter is 7-14% ahead of waiting for all
/// of them at 3 to 6 connections per worker, and within noise from 12 up,
/// where the cap of 8 applies either way.
const BATCH_SHARE: usize = 4;

/// How many CQEs one io_uring_enter should wait for
///
/// Without `min_wait_usec` support the batch would block until the 100ms
/// WAIT_TIMEOUT whenever it cannot be filled, which costs far more than the
/// syscalls it saves, so fall back to waking on the first completion.
pub fn batch_size(connections: usize) -> usize {
    if !MIN_TIMEOUT_OK.load(std::sync::atomic::Ordering::Relaxed) {
        return 1;
    }
    (connections / BATCH_SHARE).clamp(1, MAX_BATCH)
}

/// How many completions one wait should collect for HTTP/2
///
/// HTTP/2 puts every stream on one socket, so several requests share a segment
/// only if their completions are handled in one pass and the connection is
/// flushed once afterwards. The more streams a connection carries, the more
/// completions land together and the more there is to join up: at 32 streams
/// this cuts kernel time per request from 11.5 to 3.1 microseconds and adds
/// nothing to the median latency.
///
/// The other two protocols keep to [`batch_size`]. HTTP/1.1 has one request
/// per connection and so nothing to join; HTTP/3 joins its datagrams inside
/// its own transmit pass, where waiting for more completions only delays them
/// - measured at 32 x 32 it costs a third of the throughput.
pub fn batch_size_multiplexed(parallel: usize) -> usize {
    if !MIN_TIMEOUT_OK.load(std::sync::atomic::Ordering::Relaxed) {
        return 1;
    }
    (parallel / 2).clamp(1, MAX_BATCH_MULTIPLEXED)
}

/// Submit pending SQEs and wait for up to `min_complete` CQEs, bounded by
/// `max_wait`
///
/// A timeout (ETIME) and a signal interruption (EINTR) both return Ok with no
/// completions; the caller's loop then re-checks its stop conditions.
pub fn submit_and_wait_timeout(
    submitter: &Submitter<'_>,
    max_wait: std::time::Duration,
    min_complete: usize,
) -> Result<()> {
    let ts = types::Timespec::from(max_wait);
    let mut args = types::SubmitArgs::new().timespec(&ts);
    let want = min_complete.max(1);
    if want > 1 {
        // Hold out for `want` completions, but give up the batching after
        // BATCH_LINGER and return with whatever arrived (still at least one,
        // bounded by max_wait). batch_size only returns > 1 when the kernel
        // supports this.
        args = args.min_wait_usec(BATCH_LINGER);
    }
    match submitter.submit_with_args(want, &args) {
        Ok(_) => Ok(()),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ETIME) | Some(libc::EINTR)) => Ok(()),
        Err(e) => Err(e).context("submit_and_wait failed"),
    }
}

/// Create a UDP socket connected to `addr` (for QUIC)
///
/// UDP connect just sets the default peer, so doing it synchronously here is
/// fine; no io_uring Connect round-trip is needed.
pub fn make_udp_socket(addr: &SocketAddr) -> Result<RawFd> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(*addr),
        socket2::Type::DGRAM,
        None,
    )
    .context("socket() failed")?;
    // Large socket buffers absorb bursts (silently clamped to
    // net.core.{r,w}mem_max); best effort
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
    socket
        .connect(&socket2::SockAddr::from(*addr))
        .context("UDP connect failed")?;
    Ok(socket.into_raw_fd())
}

/// Create the io_uring for a worker
///
/// SINGLE_ISSUER: promise the kernel that only this thread touches the ring
/// COOP_TASKRUN / DEFER_TASKRUN: run socket-completion task work in batches
/// at io_uring_enter instead of interrupting at arbitrary times (kernel 6.1+)
/// NO_SQARRAY: drop the SQ indirection array (kernel 6.6+)
/// CQSIZE: a multishot recv breaks the assumption the default completion
/// queue is sized on - that one submission yields one completion - because a
/// single SQE arms a receive that then produces completions for as long as the
/// peer keeps sending. Overflowing is not fatal (IORING_FEAT_NODROP moves the
/// spill to a backlog rather than dropping it) but it is expensive: forced by
/// shrinking the ring, it costs 28 % of HTTP/1.1's throughput and 39 % of
/// HTTP/2's. It has never been seen at the sizes actually used - zero
/// overflows even with the queue no larger than the submission ring, since the
/// floor of 256 entries already dwarfs the connections one worker holds. The
/// headroom is not free: it costs about 1.7 % on HTTP/1.1 at 1000 connections,
/// reproducibly and in both orders of testing. Kept as insurance against
/// traffic shapes that have not been measured. Measured 2026-08.
///
/// Not SQPOLL, which cannot be combined with DEFER_TASKRUN, so the two are a
/// straight choice. There is nothing for it to save: batching already gets
/// io_uring_enter down to 0.0015 calls per request on HTTP/2 and 0.025 on
/// HTTP/3. What it costs is a kernel thread per ring - at 16 threads that is
/// 16 of them burning ten cores - and it measured slower everywhere, by 29 %
/// on HTTP/2 and 21 % on HTTP/3 at 16 threads. Giving it cores to spare only
/// narrows the gap: still 2.6 % down at 4 threads and 10 % at 1. Measured
/// 2026-08.
pub fn build_ring(entries: u32) -> Result<IoUring> {
    let ring = build_ring_inner(entries)?;
    MIN_TIMEOUT_OK.store(
        ring.params().is_feature_min_timeout(),
        std::sync::atomic::Ordering::Relaxed,
    );
    Ok(ring)
}

fn build_ring_inner(entries: u32) -> Result<IoUring> {
    IoUring::builder()
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
        .map_err(|e| {
            // A container is the usual reason: Docker's default seccomp
            // profile denies io_uring_setup, and EPERM is the only thing the
            // kernel gets to say about it. Worth naming, because the fix is
            // not something anyone guesses.
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                anyhow::anyhow!(
                    "failed to create io_uring: {e}\n\
                     In a container this is usually the seccomp profile \
                     denying io_uring_setup; run with \
                     --security-opt seccomp=unconfined"
                )
            } else {
                anyhow::Error::new(e).context("failed to create io_uring")
            }
        })
}

/// Build the ring a worker runs on
///
/// Two entries per connection covers a send and a receive in flight at once,
/// and the floor keeps a run with few connections from submitting in dribs.
pub fn build_worker_ring(connections: usize) -> Result<IoUring> {
    let entries = (connections * 2).next_power_of_two().max(256) as u32;
    build_ring(entries)
}

/// Register what a worker's ring needs, once it has been split
///
/// The ring fd, so each enter skips an fdget and fput (5.18+; behaviour is
/// identical if it fails). A fixed file slot per connection, so an SQE names
/// its fd as `types::Fixed(conn_idx)` and skips per-operation refcounting. And
/// the provided buffer ring the multishot receives fill from (5.19+, and
/// RecvMulti itself needs 6.0+).
pub fn register_worker(
    submitter: &mut Submitter<'_>,
    connections: usize,
    buf_ring: &BufRing,
) -> Result<()> {
    let _ = submitter.register_ring_fd();
    submitter
        .register_files_sparse(connections as u32)
        .context("register_files_sparse failed")?;
    // SAFETY: the caller declares the buffer ring before the io_uring, so
    // reverse drop order takes the ring down first - and taking it down waits
    // for the operations that would otherwise write into freed buffers
    unsafe {
        submitter
            .register_buf_ring_with_flags(buf_ring.ring_ptr as u64, buf_ring.entries, BUF_GROUP, 0)
            .context("register_buf_ring failed")?;
    }
    Ok(())
}

/// Arm the deadline a duration-mode run ends on, which is how the workers
/// learn the run is over: nothing else watches the clock
///
/// The returned Timespec has to stay alive, because the SQE points at it until
/// then. A run bounded by a request count has no deadline and gets `None`.
pub fn arm_deadline(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    deadline: Option<Duration>,
) -> Result<Option<Box<types::Timespec>>> {
    let Some(after) = deadline else {
        return Ok(None);
    };
    let ts = Box::new(types::Timespec::from(after));
    let entry = opcode::Timeout::new(&*ts as *const types::Timespec)
        .build()
        .user_data(TIMEOUT_USER_DATA);
    push_sqe(submitter, sq, entry)?;
    Ok(Some(ts))
}

pub fn push_sqe(
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
pub fn push_sqe_pair(
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
/// and return the created socket fd
///
/// The created fd is registered into the fixed file slot of the connection
/// index; all subsequent SQEs refer to it as `types::Fixed(conn_idx)`.
pub fn start_connect(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    generation: u64,
    addr: &SocketAddr,
    raw_addr: &socket2::SockAddr,
    timeout: &types::Timespec,
) -> Result<RawFd> {
    let fd = make_socket(addr)?;
    // Overwriting the slot also releases the registered reference to the old fd
    submitter
        .register_files_update(conn_idx as u32, &[fd])
        .context("register_files_update failed")?;
    let connect = opcode::Connect::new(
        types::Fixed(conn_idx as u32),
        raw_addr.as_ptr().cast::<libc::sockaddr>(),
        raw_addr.len(),
    )
    .build()
    .flags(squeue::Flags::IO_LINK)
    .user_data(user_data(conn_idx, generation, OP_CONNECT));
    let link_timeout = opcode::LinkTimeout::new(timeout as *const types::Timespec)
        .build()
        .user_data(user_data(conn_idx, generation, OP_CONNECT_TIMEOUT));
    push_sqe_pair(submitter, sq, connect, link_timeout)?;
    Ok(fd)
}

/// Send a byte slice
///
/// The slice must stay valid and at a stable address until the CQE arrives.
///
/// Note: WriteFixed + a registered buffer was also tried, but the socket write
/// path is slower than the send path and fixed buffers gain nothing for ~100B
/// sends, measuring about 4% worse (2026-08). Keep using Send.
/// Submit a send from a plain slice
///
/// The socket is a registered file but the buffer is not registered, and it
/// does not need to be: a plain send copies out of user memory, so there are
/// no pages to pin and nothing for `register_buffers` to save. Registration
/// would only matter for a zero-copy send, and these are far too small for
/// one to pay - measured 40 bytes on HTTP/1.1, where every request is its own
/// send, and 663 to 766 on HTTP/2, where one send carries a couple of dozen.
/// Zero copy adds a second completion per send and starts winning in the tens
/// of kilobytes.
pub fn push_send_slice(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    generation: u64,
    data: &[u8],
) -> Result<()> {
    let entry = opcode::Send::new(
        types::Fixed(conn_idx as u32),
        data.as_ptr(),
        data.len() as u32,
    )
    .build()
    .user_data(user_data(conn_idx, generation, OP_SEND));
    push_sqe(submitter, sq, entry)
}

/// Arm a multishot recv
///
/// A single submission keeps delivering a CQE per receive while the MORE flag
/// stays set, so no per-response Recv SQE is needed. The kernel picks receive
/// buffers from the provided buffer ring and reports the buffer ID in the CQE
/// flags. The caller is responsible for tracking the armed state.
pub fn push_recv_multi(
    submitter: &Submitter<'_>,
    sq: &mut squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    generation: u64,
) -> Result<()> {
    let entry = opcode::RecvMulti::new(types::Fixed(conn_idx as u32), BUF_GROUP)
        .build()
        .user_data(user_data(conn_idx, generation, OP_RECV));
    push_sqe(submitter, sq, entry)
}
