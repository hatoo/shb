use std::mem;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use io_uring::{IoUring, Submitter, cqueue, opcode, squeue, types};
use shiguredo_http11::{BodyKind, BodyProgress, HttpHead, Request, ResponseDecoder};

/// Size of a single buffer in the provided buffer ring
const RECV_BUF_SIZE: usize = 16 * 1024;
/// Buffer group ID of the provided buffer ring (one per worker)
const BUF_GROUP: u16 = 0;
const TIMEOUT_USER_DATA: u64 = u64::MAX;

#[derive(Parser)]
#[command(name = "shb", about = "io_uring HTTP/1.1 benchmarker")]
struct Args {
    /// Target URL (http only), e.g. http://127.0.0.1:8080/
    url: String,

    /// Number of concurrent connections
    #[arg(short, long, default_value_t = 1)]
    connections: usize,

    /// Total number of requests
    #[arg(short = 'n', long, default_value_t = 100_000)]
    requests: u64,

    /// Run for this long instead of a fixed request count (e.g. 10s, 1m30s)
    #[arg(short = 'z', long, value_parser = humantime::parse_duration)]
    duration: Option<Duration>,

    /// Connection establishment timeout (e.g. 3s, 500ms)
    #[arg(long, default_value = "3s", value_parser = humantime::parse_duration)]
    connect_timeout: Duration,

    /// Number of worker threads
    #[arg(short = 't', long, default_value_t = default_threads())]
    threads: usize,

    /// Print the report as JSON
    #[arg(short = 'j', long)]
    json: bool,
}

/// Default number of threads (number of CPUs)
fn default_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

/// Create an unconnected TCP socket with TCP_NODELAY set
fn make_socket(addr: &SocketAddr) -> Result<RawFd> {
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

/// Provided buffer ring for multishot recv
///
/// On every receive the kernel takes a buffer from this ring, writes into it,
/// and reports the buffer ID in the CQE flags. Return processed buffers with
/// `recycle`. The kernel keeps referencing the ring area and the data buffers
/// until the buffer group is unregistered (= the io_uring is dropped), so this
/// struct must be declared before the ring so that reverse drop order destroys
/// it after the ring.
struct BufRing {
    /// io_uring_buf entry array (page-aligned, shared with the kernel)
    ring_ptr: *mut types::BufRingEntry,
    layout: std::alloc::Layout,
    entries: u16,
    mask: u16,
    /// Local shadow of the tail; publish stores it to the shared area with Release
    tail: u16,
    /// Contiguous data buffer of entries * RECV_BUF_SIZE bytes (must never reallocate)
    data: Vec<u8>,
}

impl BufRing {
    fn new(entries: u16) -> Result<Self> {
        assert!(entries.is_power_of_two());
        let layout = std::alloc::Layout::from_size_align(
            entries as usize * mem::size_of::<types::BufRingEntry>(),
            4096,
        )
        .context("invalid buffer ring layout")?;
        let ring_ptr = unsafe { std::alloc::alloc_zeroed(layout) } as *mut types::BufRingEntry;
        if ring_ptr.is_null() {
            bail!("failed to allocate buffer ring");
        }
        let mut this = BufRing {
            ring_ptr,
            layout,
            entries,
            mask: entries - 1,
            tail: 0,
            data: vec![0u8; entries as usize * RECV_BUF_SIZE],
        };
        // Seed the ring with every buffer
        for bid in 0..entries {
            this.push_entry(bid);
        }
        this.publish();
        Ok(this)
    }

    fn push_entry(&mut self, bid: u16) {
        let idx = (self.tail & self.mask) as usize;
        unsafe {
            let entry = &mut *self.ring_ptr.add(idx);
            entry.set_addr(self.data.as_ptr() as u64 + bid as u64 * RECV_BUF_SIZE as u64);
            entry.set_len(RECV_BUF_SIZE as u32);
            entry.set_bid(bid);
        }
        self.tail = self.tail.wrapping_add(1);
    }

    /// Publish the tail to the kernel
    fn publish(&self) {
        unsafe {
            let tail_ptr = types::BufRingEntry::tail(self.ring_ptr) as *const AtomicU16;
            (*tail_ptr).store(self.tail, Ordering::Release);
        }
    }

    /// Borrow the data of the buffer reported by a CQE
    fn data(&self, bid: u16, len: usize) -> &[u8] {
        let off = bid as usize * RECV_BUF_SIZE;
        &self.data[off..off + len]
    }

    /// Return a processed buffer to the ring
    fn recycle(&mut self, bid: u16) {
        self.push_entry(bid);
        self.publish();
    }
}

impl Drop for BufRing {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ring_ptr as *mut u8, self.layout) };
    }
}

struct Target {
    addr: SocketAddr,
    request_bytes: Vec<u8>,
}

fn parse_target(url: &str) -> Result<Target> {
    let rest = url
        .strip_prefix("http://")
        .context("only http:// URLs are supported")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        bail!("missing host in URL");
    }
    // The Host header uses the authority as-is (including an explicit port)
    let (host_for_lookup, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || authority.starts_with('[') => {
            // An IPv6 literal only counts as having a port in the [::1]:8080 form
            if authority.starts_with('[') && !h.ends_with(']') {
                (authority, 80u16)
            } else {
                (h, p.parse::<u16>().context("invalid port")?)
            }
        }
        _ => (authority, 80u16),
    };
    let host_for_lookup = host_for_lookup
        .trim_start_matches('[')
        .trim_end_matches(']');

    let addr = (host_for_lookup, port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {authority}"))?
        .next()
        .context("no address resolved")?;

    let request = Request::new("GET", path)
        .map_err(|e| anyhow::anyhow!("invalid request target: {e:?}"))?
        .header("Host", authority)
        .map_err(|e| anyhow::anyhow!("invalid Host header: {e:?}"))?;
    let request_bytes = request
        .encode()
        .map_err(|e| anyhow::anyhow!("failed to encode request: {e:?}"))?;

    Ok(Target {
        addr,
        request_bytes,
    })
}

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
    /// Resume position for partial sends
    send_offset: usize,
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
            send_offset: 0,
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
        self.send_offset = 0;
        self.resp = None;
        self.request_start = Instant::now();
    }
}

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

struct Stats {
    completed: u64,
    errors: u64,
    connect_errors: u64,
    bytes_received: u64,
    bytes_sent: u64,
    latencies_ns: Vec<u64>,
    status_counts: Box<[u64; 600]>,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            completed: 0,
            errors: 0,
            connect_errors: 0,
            bytes_received: 0,
            bytes_sent: 0,
            latencies_ns: Vec::new(),
            status_counts: Box::new([0u64; 600]),
        }
    }
}

impl Stats {
    fn record_success(&mut self, conn: &Conn) {
        self.completed += 1;
        if let Some(meta) = &conn.resp {
            self.status_counts[meta.status_code as usize] += 1;
        }
        self.latencies_ns
            .push(conn.request_start.elapsed().as_nanos() as u64);
    }

    fn merge(&mut self, other: Stats) {
        self.completed += other.completed;
        self.errors += other.errors;
        self.connect_errors += other.connect_errors;
        self.bytes_received += other.bytes_received;
        self.bytes_sent += other.bytes_sent;
        self.latencies_ns.extend(other.latencies_ns);
        for (a, b) in self
            .status_counts
            .iter_mut()
            .zip(other.status_counts.iter())
        {
            *a += *b;
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.connections == 0 {
        bail!("--connections must be >= 1");
    }
    if args.threads == 0 {
        bail!("--threads must be >= 1");
    }
    let target = parse_target(&args.url)?;

    let duration_limit = args.duration;

    // Each thread gets at least one connection
    let threads = args.threads.min(args.connections);

    // Distribute connections and requests across threads (remainder goes to the first threads)
    let conns_per_thread: Vec<usize> = (0..threads)
        .map(|i| args.connections / threads + usize::from(i < args.connections % threads))
        .collect();
    let requests_per_thread: Vec<u64> = if duration_limit.is_some() {
        // In duration mode the request count is unlimited
        vec![u64::MAX; threads]
    } else {
        (0..threads)
            .map(|i| {
                args.requests / threads as u64
                    + u64::from((i as u64) < args.requests % threads as u64)
            })
            .collect()
    };

    let bench_start = Instant::now();
    let results: Vec<Result<Stats>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|i| {
                let target = &target;
                let connections = conns_per_thread[i];
                let max_requests = requests_per_thread[i];
                let connect_timeout = args.connect_timeout;
                s.spawn(move || {
                    run_worker(
                        target,
                        connections,
                        max_requests,
                        duration_limit,
                        connect_timeout,
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| match h.join() {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!("worker thread panicked")),
            })
            .collect()
    });
    let elapsed = bench_start.elapsed();

    let mut stats = Stats::default();
    for result in results {
        stats.merge(result?);
    }

    if args.json {
        print_json_report(&args, threads, &stats, elapsed)?;
    } else {
        print_report(&args, threads, &stats, elapsed);
    }
    Ok(())
}

/// Benchmark loop of a single worker thread
///
/// Owns a dedicated io_uring and set of connections; shares no state with
/// other threads.
fn run_worker(
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

/// Latency summary (in seconds)
struct LatencySummary {
    min: f64,
    mean: f64,
    p50: f64,
    p90: f64,
    p99: f64,
    max: f64,
}

fn latency_summary(latencies_ns: &[u64]) -> Option<LatencySummary> {
    if latencies_ns.is_empty() {
        return None;
    }
    let mut lat = latencies_ns.to_vec();
    lat.sort_unstable();
    let pct = |p: f64| -> f64 {
        let idx = ((lat.len() as f64 * p).ceil() as usize).saturating_sub(1);
        lat[idx.min(lat.len() - 1)] as f64 / 1e9
    };
    Some(LatencySummary {
        min: lat[0] as f64 / 1e9,
        mean: lat.iter().sum::<u64>() as f64 / lat.len() as f64 / 1e9,
        p50: pct(0.50),
        p90: pct(0.90),
        p99: pct(0.99),
        max: lat[lat.len() - 1] as f64 / 1e9,
    })
}

fn print_report(args: &Args, threads: usize, stats: &Stats, elapsed: Duration) {
    let secs = elapsed.as_secs_f64();
    let total = stats.completed + stats.errors;
    println!("URL:          {}", args.url);
    println!("Threads:      {threads}");
    println!("Connections:  {}", args.connections);
    println!(
        "Requests:     {} ({} ok, {} errors, of which {} connect) in {:.3}s",
        total, stats.completed, stats.errors, stats.connect_errors, secs
    );
    println!("Requests/sec: {:.1}", stats.completed as f64 / secs);
    println!(
        "Transfer:     recv {:.2} MB/s ({} bytes), sent {:.2} MB/s ({} bytes)",
        stats.bytes_received as f64 / secs / (1024.0 * 1024.0),
        stats.bytes_received,
        stats.bytes_sent as f64 / secs / (1024.0 * 1024.0),
        stats.bytes_sent
    );

    let lines: Vec<String> = stats
        .status_counts
        .iter()
        .enumerate()
        .filter(|&(_, &n)| n > 0)
        .map(|(code, &n)| format!("  [{code}] {n}"))
        .collect();
    if !lines.is_empty() {
        println!("Status codes:");
        for line in lines {
            println!("{line}");
        }
    }

    if let Some(l) = latency_summary(&stats.latencies_ns) {
        println!("Latency (ms):");
        println!(
            "  min {:.3}  mean {:.3}  p50 {:.3}  p90 {:.3}  p99 {:.3}  max {:.3}",
            l.min * 1e3,
            l.mean * 1e3,
            l.p50 * 1e3,
            l.p90 * 1e3,
            l.p99 * 1e3,
            l.max * 1e3,
        );
    }
}

fn print_json_report(args: &Args, threads: usize, stats: &Stats, elapsed: Duration) -> Result<()> {
    let secs = elapsed.as_secs_f64();
    let status_codes: serde_json::Map<String, serde_json::Value> = stats
        .status_counts
        .iter()
        .enumerate()
        .filter(|&(_, &n)| n > 0)
        .map(|(code, &n)| (code.to_string(), n.into()))
        .collect();
    let latency = latency_summary(&stats.latencies_ns).map(|l| {
        serde_json::json!({
            "min": l.min,
            "mean": l.mean,
            "p50": l.p50,
            "p90": l.p90,
            "p99": l.p99,
            "max": l.max,
        })
    });
    let report = serde_json::json!({
        "url": args.url,
        "threads": threads,
        "connections": args.connections,
        "durationSeconds": secs,
        "requests": {
            "total": stats.completed + stats.errors,
            "ok": stats.completed,
            "errors": stats.errors,
            "connectErrors": stats.connect_errors,
        },
        "requestsPerSec": stats.completed as f64 / secs,
        "bytesReceived": stats.bytes_received,
        "bytesReceivedPerSec": stats.bytes_received as f64 / secs,
        "bytesSent": stats.bytes_sent,
        "bytesSentPerSec": stats.bytes_sent as f64 / secs,
        "statusCodes": status_codes,
        "latencySeconds": latency,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
