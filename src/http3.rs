//! HTTP/3 benchmark worker (QUIC via quinn-proto, H3/QPACK via shiguredo_http3)
//!
//! Both layers are Sans I/O: quinn-proto turns UDP datagrams into QUIC stream
//! data and shiguredo_http3 turns stream data into HTTP events. UDP datagrams
//! are moved with the same io_uring machinery as the TCP workers (connected
//! UDP socket, multishot recv = one CQE per datagram, one Send SQE per
//! outgoing datagram).

use std::collections::VecDeque;
use std::net::UdpSocket;
use std::os::fd::{FromRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::BytesMut;
use quinn_proto::crypto::rustls::QuicClientConfig;
use quinn_proto::{
    ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, Event as QuicEvent, ReadError,
    StreamEvent, StreamId, VarInt, WriteError,
};
use shiguredo_http3::{ClientConnection, Event as H3Event, Header, Settings};

use crate::buf_ring::BufRing;
use crate::stats::Stats;
use crate::target::Target;
use crate::uring::{self, BUF_GROUP, CONN_IDX_BITS, OP_RECV, OP_SEND, TIMEOUT_USER_DATA};

/// Receive windows, matching the h2 worker's h2load-style sizing
const RECEIVE_WINDOW: u32 = (1 << 30) - 1;

/// UDP_SEGMENT socket option (missing from libc for linux-gnu)
const UDP_SEGMENT: libc::c_int = 103;

/// Max segments per UDP GSO send (kernel limit is 64)
const GSO_SEGMENTS: usize = 64;

/// Advertise a QPACK dynamic table so the server can index repeated response
/// headers instead of Huffman-encoding full literals on every response
/// (measured ~20% of client CPU without it)
fn make_h3_settings() -> Settings {
    let mut settings = Settings::new();
    settings.qpack_max_table_capacity =
        Some(shiguredo_http3::VarInt::new(4096).expect("valid varint"));
    settings.qpack_blocked_streams = Some(shiguredo_http3::VarInt::new(128).expect("valid varint"));
    settings
}

/// One outgoing UDP send: either a single datagram (segment_size == 0) or a
/// GSO batch of equally sized segments with a shorter tail
struct Datagram {
    buf: Vec<u8>,
    segment_size: usize,
}

/// Pinned storage for a sendmsg SQE (msghdr + iovec + GSO cmsg); must stay at
/// a stable address while the SQE is in flight
#[repr(C)]
struct MsgState {
    iov: libc::iovec,
    msg: libc::msghdr,
    cmsg: [u8; 64],
}

/// Whether the kernel supports UDP GSO (UDP_SEGMENT)
fn probe_gso(addr: &std::net::SocketAddr) -> bool {
    let Ok(fd) = uring::make_udp_socket(addr) else {
        return false;
    };
    let zero: libc::c_int = 0;
    let ok = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_UDP,
            UDP_SEGMENT,
            &zero as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    } == 0;
    drop(unsafe { UdpSocket::from_raw_fd(fd) });
    ok
}

fn build_request_headers(target: &Target) -> Result<Vec<Header>> {
    let mut headers = vec![
        Header::new(b":method", target.method.as_bytes())
            .map_err(|e| anyhow::anyhow!("header: {e:?}"))?,
        Header::new(b":scheme", b"https").map_err(|e| anyhow::anyhow!("header: {e:?}"))?,
        Header::new(b":authority", target.authority.as_bytes())
            .map_err(|e| anyhow::anyhow!("header: {e:?}"))?,
        Header::new(b":path", target.path.as_bytes())
            .map_err(|e| anyhow::anyhow!("header: {e:?}"))?,
    ];
    for (name, value) in &target.headers {
        if crate::target::is_connection_specific(name) {
            continue;
        }
        // Field names must be lowercase in HTTP/3, like HTTP/2
        headers.push(
            Header::new(name.to_ascii_lowercase(), value)
                .map_err(|e| anyhow::anyhow!("header {name:?}: {e:?}"))?,
        );
    }
    Ok(headers)
}

fn make_quic_client_config(connect_timeout: Duration) -> Result<quinn_proto::ClientConfig> {
    let rustls_config = crate::tls::client_config(b"h3")?;
    let crypto = QuicClientConfig::try_from(rustls_config)
        .context("rustls config not usable for QUIC (TLS 1.3 required)")?;
    let mut config = quinn_proto::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn_proto::TransportConfig::default();
    // Benchmark-friendly congestion behavior: a large initial window skips
    // slow start (loopback/LAN loss is negligible)
    let mut cubic = quinn_proto::congestion::CubicConfig::default();
    cubic.initial_window(10 * 1024 * 1024);
    // Allow MTU discovery to grow datagrams well past the Ethernet default;
    // on loopback this greatly reduces per-packet costs for large bodies
    let mut mtud = quinn_proto::MtuDiscoveryConfig::default();
    mtud.upper_bound(65527);
    transport
        .receive_window(VarInt::from_u32(RECEIVE_WINDOW))
        .stream_receive_window(VarInt::from_u32(RECEIVE_WINDOW))
        // Server push (server-initiated bidi streams) does not exist in HTTP/3
        .max_concurrent_bidi_streams(VarInt::from_u32(0))
        .congestion_controller_factory(Arc::new(cubic))
        .initial_mtu(1452)
        .mtu_discovery_config(Some(mtud))
        // The spec default of 333ms only matters before the first RTT sample,
        // but a small value speeds up connection ramp-up on fast networks
        .initial_rtt(Duration::from_millis(1))
        // Doubles as the connect timeout: a handshake that gets no response
        // dies when the idle timeout fires
        .max_idle_timeout(Some(
            quinn_proto::IdleTimeout::try_from(connect_timeout)
                .map_err(|e| anyhow::anyhow!("connect timeout too large: {e}"))?,
        ));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// An in-flight request (one open request stream)
struct InFlight {
    stream_id: u64,
    start: Instant,
    /// Status code from :status (0 = not received yet)
    status: u16,
}

struct Conn {
    fd: RawFd,
    handle: Option<ConnectionHandle>,
    quic: Option<quinn_proto::Connection>,
    h3: Option<ClientConnection>,
    /// QUIC handshake finished and the H3 control/QPACK streams are set up
    h3_ready: bool,
    /// GOAWAY received: no new streams on this connection
    goaway: bool,
    /// Outgoing datagrams; the front one is in flight while `sending`
    out_queue: VecDeque<Datagram>,
    /// Pinned sendmsg bookkeeping for GSO sends
    msg_state: Box<MsgState>,
    sending: bool,
    /// Whether a multishot recv is active (cleared by a CQE without the MORE flag)
    recv_armed: bool,
    /// Reconnect generation. Incremented on every close; CQEs from an old
    /// generation are identified via user_data and ignored
    generation: u64,
    /// In-flight requests, up to the configured parallelism
    streams: Vec<InFlight>,
}

impl Conn {
    fn new() -> Self {
        Conn {
            fd: -1,
            handle: None,
            quic: None,
            h3: None,
            h3_ready: false,
            goaway: false,
            out_queue: VecDeque::new(),
            msg_state: Box::new(unsafe { std::mem::zeroed() }),
            sending: false,
            recv_armed: false,
            generation: 0,
            streams: Vec::new(),
        }
    }

    fn close(&mut self) {
        if self.fd >= 0 {
            // Close by turning the fd back into a UdpSocket and dropping it
            drop(unsafe { UdpSocket::from_raw_fd(self.fd) });
            self.fd = -1;
        }
        self.handle = None;
        self.quic = None;
        self.h3 = None;
        self.h3_ready = false;
        self.goaway = false;
        self.out_queue.clear();
        self.sending = false;
        self.recv_armed = false;
        self.streams.clear();
        // Bump the generation so CQEs of operations on the old socket are ignored
        self.generation += 1;
    }

    /// Count all in-flight requests as errors (used when the connection dies)
    fn fail_inflight(&mut self, stats: &mut Stats) {
        stats.errors += self.streams.len() as u64;
        self.streams.clear();
    }
}

/// Copy pending H3 stream data into the QUIC send streams
///
/// The FIN is delivered by get_stream_data as `(empty, true)` once all data
/// has been consumed, at which point the QUIC stream is finished.
fn pump_h3_to_quic(quic: &mut quinn_proto::Connection, h3: &mut ClientConnection) -> Result<()> {
    enum Step {
        Wrote { n: usize, all: bool },
        Fin,
        Blocked,
        Done,
    }
    let writable: Vec<u64> = h3.writable_streams().collect();
    for sid in writable {
        let qsid = StreamId::from(VarInt::from_u64(sid).context("stream id out of range")?);
        loop {
            let step = match h3.get_stream_data(sid) {
                None => Step::Done,
                Some((data, fin)) => {
                    if data.is_empty() {
                        if fin { Step::Fin } else { Step::Done }
                    } else {
                        match quic.send_stream(qsid).write(data) {
                            Ok(n) => Step::Wrote {
                                n,
                                all: n == data.len(),
                            },
                            Err(WriteError::Blocked) => Step::Blocked,
                            Err(e) => bail!("QUIC stream write failed: {e}"),
                        }
                    }
                }
            };
            match step {
                Step::Wrote { n, all } => {
                    h3.consume_stream_data(sid, n);
                    if !all {
                        break;
                    }
                }
                Step::Fin => {
                    let _ = quic.send_stream(qsid).finish();
                    break;
                }
                Step::Blocked | Step::Done => break,
            }
        }
    }
    Ok(())
}

/// Read everything currently readable from a QUIC stream into the H3 layer
///
/// Returns true if the stream was reset by the peer.
fn read_quic_stream(
    quic: &mut quinn_proto::Connection,
    h3: &mut ClientConnection,
    qsid: StreamId,
) -> Result<bool> {
    let sid = u64::from(qsid);
    let mut recv = quic.recv_stream(qsid);
    let mut chunks = match recv.read(true) {
        Ok(chunks) => chunks,
        // Already closed/finished: nothing more to deliver
        Err(_) => return Ok(false),
    };
    let mut reset = false;
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => {
                h3.feed_stream(sid, &chunk.bytes, false)
                    .map_err(|e| anyhow::anyhow!("h3 feed: {e:?}"))?;
            }
            Ok(None) => {
                h3.feed_stream(sid, &[], true)
                    .map_err(|e| anyhow::anyhow!("h3 feed fin: {e:?}"))?;
                break;
            }
            Err(ReadError::Blocked) => break,
            Err(ReadError::Reset(_)) => {
                reset = true;
                break;
            }
        }
    }
    let _ = chunks.finalize();
    Ok(reset)
}

/// Open new request streams until the parallelism target or budget is hit
///
/// Every h3 request must be paired with opening one QUIC bidi stream; both
/// sides allocate ids in the standard 0, 4, 8, ... order, which is asserted.
fn fill_streams(
    conn: &mut Conn,
    request_headers: &[Header],
    body: &[u8],
    parallel: usize,
    started: &mut u64,
    max_requests: u64,
    stop: bool,
) -> Result<()> {
    if stop || conn.goaway || !conn.h3_ready {
        return Ok(());
    }
    let (Some(quic), Some(h3)) = (conn.quic.as_mut(), conn.h3.as_mut()) else {
        return Ok(());
    };
    while conn.streams.len() < parallel && *started < max_requests {
        // None = the server's MAX_STREAMS limit; retry after completions
        let Some(qsid) = quic.streams().open(Dir::Bi) else {
            break;
        };
        let hsid = h3
            .send_request(request_headers, body.is_empty())
            .map_err(|e| anyhow::anyhow!("send_request failed: {e:?}"))?;
        if !body.is_empty() {
            h3.send_body(hsid, body, true)
                .map_err(|e| anyhow::anyhow!("send_body failed: {e:?}"))?;
        }
        if u64::from(qsid) != hsid {
            bail!(
                "stream id mismatch: QUIC {} vs H3 {}",
                u64::from(qsid),
                hsid
            );
        }
        conn.streams.push(InFlight {
            stream_id: hsid,
            start: Instant::now(),
            status: 0,
        });
        *started += 1;
    }
    Ok(())
}

/// Submit the front of the send queue (plain send, or sendmsg with a GSO
/// cmsg for multi-segment batches)
fn push_front_send(
    submitter: &io_uring::Submitter<'_>,
    sq: &mut io_uring::squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &mut Conn,
) -> Result<()> {
    let Some(front) = conn.out_queue.front() else {
        return Ok(());
    };
    conn.sending = true;
    if front.segment_size > 0 {
        unsafe {
            let state = &mut *conn.msg_state;
            state.iov.iov_base = front.buf.as_ptr() as *mut libc::c_void;
            state.iov.iov_len = front.buf.len();
            state.msg = std::mem::zeroed();
            state.msg.msg_iov = &mut state.iov;
            state.msg.msg_iovlen = 1;
            state.msg.msg_control = state.cmsg.as_mut_ptr() as *mut libc::c_void;
            state.msg.msg_controllen = libc::CMSG_SPACE(2) as usize;
            let cmsg = libc::CMSG_FIRSTHDR(&state.msg);
            (*cmsg).cmsg_level = libc::SOL_UDP;
            (*cmsg).cmsg_type = UDP_SEGMENT;
            (*cmsg).cmsg_len = libc::CMSG_LEN(2) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut u16, front.segment_size as u16);
            let entry = io_uring::opcode::SendMsg::new(
                io_uring::types::Fixed(conn_idx as u32),
                &state.msg as *const libc::msghdr,
            )
            .build()
            .user_data(uring::user_data(conn_idx, conn.generation, OP_SEND));
            uring::push_sqe(submitter, sq, entry)?;
        }
    } else {
        uring::push_send_slice(submitter, sq, conn_idx, conn.generation, &front.buf)?;
    }
    Ok(())
}

/// Move pending QUIC datagrams into the send queue and start sending
fn pump_transmits(
    submitter: &io_uring::Submitter<'_>,
    sq: &mut io_uring::squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &mut Conn,
    now: Instant,
    transmit_buf: &mut Vec<u8>,
    gso: bool,
) -> Result<()> {
    if let Some(quic) = conn.quic.as_mut() {
        let max_datagrams = if gso { GSO_SEGMENTS } else { 1 };
        loop {
            transmit_buf.clear();
            match quic.poll_transmit(now, max_datagrams, transmit_buf) {
                Some(transmit) => {
                    // segment_size is only meaningful when the batch holds
                    // more than one segment
                    let segment_size = transmit
                        .segment_size
                        .filter(|s| transmit.size > *s)
                        .unwrap_or(0);
                    conn.out_queue.push_back(Datagram {
                        buf: transmit_buf[..transmit.size].to_vec(),
                        segment_size,
                    });
                }
                None => break,
            }
        }
    }
    if !conn.sending {
        push_front_send(submitter, sq, conn_idx, conn)?;
    }
    Ok(())
}

/// Drive the QUIC and H3 state machines after input (datagrams or timeouts)
///
/// Returns false if the connection is broken.
#[allow(clippy::too_many_arguments)]
fn drive(
    endpoint: &mut Endpoint,
    conn: &mut Conn,
    stats: &mut Stats,
    request_headers: &[Header],
    body: &[u8],
    parallel: usize,
    started: &mut u64,
    max_requests: u64,
    stop: bool,
) -> bool {
    let result = (|| -> Result<bool> {
        let Some(quic) = conn.quic.as_mut() else {
            return Ok(true);
        };

        // 1. QUIC events: connection state, newly readable streams
        let mut readable: Vec<StreamId> = Vec::new();
        let mut alive = true;
        while let Some(event) = quic.poll() {
            match event {
                QuicEvent::Connected => {
                    // Set up the H3 control + QPACK streams; the client uni
                    // streams get ids 2, 6, 10 in open order
                    let mut h3 = ClientConnection::new(make_h3_settings());
                    let control = quic.streams().open(Dir::Uni).context("no uni stream")?;
                    let encoder = quic.streams().open(Dir::Uni).context("no uni stream")?;
                    let decoder = quic.streams().open(Dir::Uni).context("no uni stream")?;
                    let init = h3
                        .init_h3_streams(control.into(), encoder.into(), decoder.into())
                        .map_err(|e| anyhow::anyhow!("init_h3_streams: {e:?}"))?;
                    // init_h3_streams hands the initial stream data (SETTINGS,
                    // QPACK stream types) to the caller; write it to QUIC now.
                    // The windows are fresh, so a short write cannot happen
                    for (sid, data) in [
                        (init.control_stream_id, &init.control_data),
                        (init.encoder_stream_id, &init.encoder_data),
                        (init.decoder_stream_id, &init.decoder_data),
                    ] {
                        if data.is_empty() {
                            continue;
                        }
                        let qsid = StreamId::from(VarInt::from_u64(sid).context("bad stream id")?);
                        let n = quic
                            .send_stream(qsid)
                            .write(data)
                            .map_err(|e| anyhow::anyhow!("H3 init write: {e}"))?;
                        if n != data.len() {
                            bail!("short write of H3 init data");
                        }
                    }
                    conn.h3 = Some(h3);
                    conn.h3_ready = true;
                }
                QuicEvent::ConnectionLost { .. } => {
                    alive = false;
                }
                QuicEvent::Stream(StreamEvent::Opened { dir }) => {
                    // Server-initiated uni streams (control/QPACK); accept and
                    // read them like any other stream
                    while let Some(qsid) = quic.streams().accept(dir) {
                        readable.push(qsid);
                    }
                }
                QuicEvent::Stream(StreamEvent::Readable { id }) => readable.push(id),
                QuicEvent::Stream(_) | QuicEvent::HandshakeDataReady => {}
                QuicEvent::DatagramReceived | QuicEvent::DatagramsUnblocked => {}
            }
        }

        // 2. Deliver readable QUIC stream data to the H3 layer
        if let Some(h3) = conn.h3.as_mut() {
            for qsid in readable {
                if read_quic_stream(quic, h3, qsid)? {
                    // Peer reset the stream: the request (if ours) failed
                    let sid = u64::from(qsid);
                    if let Some(pos) = conn.streams.iter().position(|s| s.stream_id == sid) {
                        conn.streams.swap_remove(pos);
                        stats.errors += 1;
                    }
                }
            }

            // 3. H3 events: response progress and completions
            while let Some(event) = h3
                .poll_event()
                .map_err(|e| anyhow::anyhow!("h3 error: {e:?}"))?
            {
                match event {
                    H3Event::Header {
                        stream_id,
                        name,
                        value,
                    } => {
                        if name == b":status"
                            && let Some(inflight) =
                                conn.streams.iter_mut().find(|s| s.stream_id == stream_id)
                        {
                            inflight.status = std::str::from_utf8(&value)
                                .ok()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                        }
                    }
                    H3Event::StreamEnd { stream_id } => {
                        if let Some(pos) =
                            conn.streams.iter().position(|s| s.stream_id == stream_id)
                        {
                            let inflight = conn.streams.swap_remove(pos);
                            stats.record_success(inflight.status, inflight.start);
                        }
                    }
                    H3Event::StreamReset { stream_id, .. } => {
                        if let Some(pos) =
                            conn.streams.iter().position(|s| s.stream_id == stream_id)
                        {
                            conn.streams.swap_remove(pos);
                            stats.errors += 1;
                        }
                    }
                    H3Event::GoawayReceived { .. } => {
                        conn.goaway = true;
                    }
                    _ => {}
                }
            }
        }

        // 4. Open new requests and push H3 bytes into QUIC
        fill_streams(
            conn,
            request_headers,
            body,
            parallel,
            started,
            max_requests,
            stop,
        )?;
        if let (Some(quic), Some(h3)) = (conn.quic.as_mut(), conn.h3.as_mut()) {
            pump_h3_to_quic(quic, h3)?;
        }

        // 5. Endpoint event plumbing (CID rotation, drain notifications, ...)
        if let (Some(quic), Some(handle)) = (conn.quic.as_mut(), conn.handle) {
            while let Some(endpoint_event) = quic.poll_endpoint_events() {
                if let Some(conn_event) = endpoint.handle_event(handle, endpoint_event) {
                    quic.handle_event(conn_event);
                }
            }
        }

        Ok(alive)
    })();
    result.unwrap_or(false)
}

/// Benchmark loop of a single HTTP/3 worker thread
pub fn run_worker(
    target: &Target,
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

    let request_headers = build_request_headers(target)?;
    let quic_config = make_quic_client_config(connect_timeout)?;
    let gso = probe_gso(&target.addr);
    let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);

    // Declare buf_ring / conns before the ring (see the h1/h2 workers)
    let buf_entries = (connections * 2).next_power_of_two().clamp(64, 32768) as u16;
    let mut buf_ring = BufRing::new(buf_entries)?;
    let mut conns: Vec<Conn> = Vec::with_capacity(connections);
    for _ in 0..connections {
        conns.push(Conn::new());
    }

    let entries = (connections * 2).next_power_of_two().max(256) as u32;
    let mut ring = uring::build_ring(entries)?;
    let (mut submitter, mut sq, mut cq) = ring.split();
    let _ = submitter.register_ring_fd();
    submitter
        .register_files_sparse(connections as u32)
        .context("register_files_sparse failed")?;
    unsafe {
        submitter
            .register_buf_ring_with_flags(buf_ring.ring_ptr as u64, buf_ring.entries, BUF_GROUP, 0)
            .context("register_buf_ring failed")?;
    }

    let mut stats = Stats::default();
    if duration_limit.is_none() {
        stats.latencies_ns.reserve(max_requests as usize);
    }
    let mut started: u64 = 0;

    // Duration mode: the deadline is detected solely via the io_uring Timeout CQE
    let timespec = duration_limit.map(|d| Box::new(io_uring::types::Timespec::from(d)));
    if let Some(ts) = &timespec {
        let entry = io_uring::opcode::Timeout::new(&**ts as *const io_uring::types::Timespec)
            .build()
            .user_data(TIMEOUT_USER_DATA);
        uring::push_sqe(&submitter, &mut sq, entry)?;
    }

    // Kick off the initial connections
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(2048);
    let now = Instant::now();
    for (i, conn) in conns.iter_mut().enumerate() {
        if (i as u64) >= max_requests {
            break;
        }
        conn.fd = uring::make_udp_socket(&target.addr)?;
        submitter
            .register_files_update(i as u32, &[conn.fd])
            .context("register_files_update failed")?;
        let (handle, quic) = endpoint
            .connect(now, quic_config.clone(), target.addr, &target.host)
            .context("QUIC connect failed")?;
        conn.handle = Some(handle);
        conn.quic = Some(quic);
        uring::push_recv_multi(&submitter, &mut sq, i, conn.generation)?;
        conn.recv_armed = true;
        pump_transmits(&submitter, &mut sq, i, conn, now, &mut transmit_buf, gso)?;
    }

    let mut stop = false;
    // How many completions one wait should collect before returning
    let batch = uring::batch_size(connections);

    loop {
        if stats.completed + stats.errors >= max_requests {
            break;
        }
        if crate::shutdown::requested() {
            break;
        }

        // Service expired QUIC timers and bound the wait by the nearest one
        let now = Instant::now();
        let mut wait = uring::WAIT_TIMEOUT;
        for (conn_idx, conn) in conns.iter_mut().enumerate() {
            let mut expired = false;
            if let Some(quic) = conn.quic.as_mut() {
                while let Some(deadline) = quic.poll_timeout() {
                    if deadline <= now {
                        quic.handle_timeout(now);
                        expired = true;
                    } else {
                        // Wait exactly until the nearest QUIC timer (often the
                        // pacer, microseconds away): rounding it up would
                        // quantize the pacing rate and stall the connection
                        wait = wait.min(deadline - now);
                        break;
                    }
                }
            }
            if expired {
                let alive = drive(
                    &mut endpoint,
                    conn,
                    &mut stats,
                    &request_headers,
                    &target.body,
                    parallel,
                    &mut started,
                    max_requests,
                    stop,
                );
                pump_transmits(
                    &submitter,
                    &mut sq,
                    conn_idx,
                    conn,
                    now,
                    &mut transmit_buf,
                    gso,
                )?;
                if !alive {
                    handle_broken(
                        &mut endpoint,
                        &submitter,
                        &mut sq,
                        conn_idx,
                        conn,
                        &mut stats,
                        &quic_config,
                        target,
                        &mut started,
                        max_requests,
                        stop,
                        &mut transmit_buf,
                        gso,
                    )?;
                }
            }
        }

        // Publish the tail of pushed SQEs before submitting
        sq.sync();
        uring::submit_and_wait_timeout(&submitter, wait, batch)?;

        cq.sync();

        let now = Instant::now();
        for cqe in &mut cq {
            let (ud, res, flags) = (cqe.user_data(), cqe.result(), cqe.flags());
            if ud == TIMEOUT_USER_DATA {
                stop = true;
                continue;
            }
            let (op, conn_idx, generation) = uring::decode_user_data(ud);
            if generation != conns[conn_idx].generation {
                if let Some(bid) = io_uring::cqueue::buffer_select(flags) {
                    buf_ring.recycle(bid);
                }
                continue;
            }

            let mut conn_broken = false;
            match op {
                OP_SEND => {
                    let conn = &mut conns[conn_idx];
                    conn.sending = false;
                    if res < 0 {
                        // e.g. ECONNREFUSED delivered via the connected UDP socket
                        conn_broken = true;
                    } else {
                        stats.bytes_sent += res as u64;
                        conn.out_queue.pop_front();
                        push_front_send(&submitter, &mut sq, conn_idx, conn)?;
                    }
                }
                OP_RECV => {
                    let conn = &mut conns[conn_idx];
                    if !io_uring::cqueue::more(flags) {
                        conn.recv_armed = false;
                    }
                    if res < 0 {
                        if let Some(bid) = io_uring::cqueue::buffer_select(flags) {
                            buf_ring.recycle(bid);
                        }
                        if res == -libc::ENOBUFS {
                            uring::push_recv_multi(&submitter, &mut sq, conn_idx, conn.generation)?;
                            conn.recv_armed = true;
                        } else {
                            // e.g. ECONNREFUSED (ICMP port unreachable)
                            conn_broken = true;
                        }
                    } else {
                        // res == 0 is a valid empty datagram for UDP; QUIC
                        // never sends one, so just recycle and move on
                        stats.bytes_received += res as u64;
                        if let Some(bid) = io_uring::cqueue::buffer_select(flags) {
                            if res > 0 {
                                let datagram = BytesMut::from(buf_ring.data(bid, res as usize));
                                transmit_buf.clear();
                                match endpoint.handle(
                                    now,
                                    target.addr,
                                    None,
                                    None,
                                    datagram,
                                    &mut transmit_buf,
                                ) {
                                    Some(DatagramEvent::ConnectionEvent(_, conn_event)) => {
                                        if let Some(quic) = conn.quic.as_mut() {
                                            quic.handle_event(conn_event);
                                        }
                                    }
                                    Some(DatagramEvent::Response(transmit)) => {
                                        conn.out_queue.push_back(Datagram {
                                            buf: transmit_buf[..transmit.size].to_vec(),
                                            segment_size: 0,
                                        });
                                    }
                                    Some(DatagramEvent::NewConnection(_)) | None => {}
                                }
                            }
                            buf_ring.recycle(bid);
                        }
                        if !conn.recv_armed {
                            uring::push_recv_multi(&submitter, &mut sq, conn_idx, conn.generation)?;
                            conn.recv_armed = true;
                        }
                        let alive = drive(
                            &mut endpoint,
                            conn,
                            &mut stats,
                            &request_headers,
                            &target.body,
                            parallel,
                            &mut started,
                            max_requests,
                            stop,
                        );
                        pump_transmits(
                            &submitter,
                            &mut sq,
                            conn_idx,
                            conn,
                            now,
                            &mut transmit_buf,
                            gso,
                        )?;
                        if !alive {
                            conn_broken = true;
                        }
                    }
                }
                _ => unreachable!(),
            }

            if conn_broken {
                let conn = &mut conns[conn_idx];
                handle_broken(
                    &mut endpoint,
                    &submitter,
                    &mut sq,
                    conn_idx,
                    conn,
                    &mut stats,
                    &quic_config,
                    target,
                    &mut started,
                    max_requests,
                    stop,
                    &mut transmit_buf,
                    gso,
                )?;
            }
        }

        if stop {
            break;
        }
    }

    // Best-effort CONNECTION_CLOSE so servers see a clean shutdown
    let now = Instant::now();
    for conn in &mut conns {
        if let Some(quic) = conn.quic.as_mut() {
            quic.close(now, VarInt::from_u32(0), bytes::Bytes::new());
            loop {
                transmit_buf.clear();
                match quic.poll_transmit(now, 1, &mut transmit_buf) {
                    Some(transmit) => unsafe {
                        libc::send(
                            conn.fd,
                            transmit_buf.as_ptr() as *const libc::c_void,
                            transmit.size,
                            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        );
                    },
                    None => break,
                }
            }
        }
        conn.close();
    }

    Ok(stats)
}

/// Fail everything in flight on a broken connection and reconnect if the
/// request budget allows
#[allow(clippy::too_many_arguments)]
fn handle_broken(
    endpoint: &mut Endpoint,
    submitter: &io_uring::Submitter<'_>,
    sq: &mut io_uring::squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &mut Conn,
    stats: &mut Stats,
    quic_config: &quinn_proto::ClientConfig,
    target: &Target,
    started: &mut u64,
    max_requests: u64,
    stop: bool,
    transmit_buf: &mut Vec<u8>,
    gso: bool,
) -> Result<()> {
    if conn.h3_ready {
        conn.fail_inflight(stats);
    } else {
        // Never got as far as a working HTTP/3 connection: count it like the
        // TCP workers count a failed connect, consuming one unit of budget
        stats.errors += 1;
        stats.connect_errors += 1;
        *started += 1;
    }
    conn.close();
    if stop || *started >= max_requests {
        return Ok(());
    }
    conn.fd = uring::make_udp_socket(&target.addr)?;
    submitter
        .register_files_update(conn_idx as u32, &[conn.fd])
        .context("register_files_update failed")?;
    let now = Instant::now();
    let (handle, quic) = endpoint
        .connect(now, quic_config.clone(), target.addr, &target.host)
        .context("QUIC connect failed")?;
    conn.handle = Some(handle);
    conn.quic = Some(quic);
    uring::push_recv_multi(submitter, sq, conn_idx, conn.generation)?;
    conn.recv_armed = true;
    pump_transmits(submitter, sq, conn_idx, conn, now, transmit_buf, gso)?;
    Ok(())
}
