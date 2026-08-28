use std::net::SocketAddr;
use std::os::fd::{IntoRawFd, RawFd};

use anyhow::{Context, Result};
use io_uring::{IoUring, Submitter, opcode, squeue, types};

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
const WAIT_TIMEOUT: types::Timespec = types::Timespec::new().nsec(100_000_000);

/// Submit pending SQEs and wait for at least one CQE, bounded by
/// [`WAIT_TIMEOUT`]
///
/// A timeout (ETIME) and a signal interruption (EINTR) both return Ok with no
/// completions; the caller's loop then re-checks its stop conditions.
pub fn submit_and_wait_timeout(submitter: &Submitter<'_>) -> Result<()> {
    let args = types::SubmitArgs::new().timespec(&WAIT_TIMEOUT);
    match submitter.submit_with_args(1, &args) {
        Ok(_) => Ok(()),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ETIME) | Some(libc::EINTR)) => Ok(()),
        Err(e) => Err(e).context("submit_and_wait failed"),
    }
}

/// Re-arm TCP_QUICKACK so our ACKs go out immediately
///
/// With many concurrent HTTP/2 streams the peer may have Nagle enabled and
/// wait for our ACK before sending its next small segment; our delayed ACK
/// (up to ~40ms) then stalls the whole pipeline. Quickack mode is not
/// permanent, so call this after every receive batch. Best effort.
pub fn set_quickack(fd: RawFd) {
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Create the io_uring for a worker
///
/// SINGLE_ISSUER: promise the kernel that only this thread touches the ring
/// COOP_TASKRUN / DEFER_TASKRUN: run socket-completion task work in batches
/// at io_uring_enter instead of interrupting at arbitrary times (kernel 6.1+)
/// NO_SQARRAY: drop the SQ indirection array (kernel 6.6+)
/// CQSIZE: avoid CQ overflow from bursts of multishot recv CQEs
pub fn build_ring(entries: u32) -> Result<IoUring> {
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
        .context("failed to create io_uring")
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
