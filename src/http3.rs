//! HTTP/3 benchmark worker (QUIC in [`crate::quic`], H3 and QPACK in [`proto`]
//! and [`qpack`])
//!
//! Every layer is Sans I/O: the QUIC connection turns UDP datagrams into
//! stream data and this module turns stream data into completed requests. The
//! datagrams are moved with the same io_uring machinery as the TCP workers - a
//! connected UDP socket and a multishot recv, which is one completion per
//! datagram since UDP keeps message boundaries. Sending is the one place the
//! shape differs: where the kernel has UDP GSO, one `SendMsg` carries up to 64
//! packets of equal size and the kernel cuts them apart, and only without it
//! does each datagram get its own `Send`.

pub mod proto;
pub mod qpack;

use std::collections::VecDeque;
use std::net::UdpSocket;
use std::os::fd::{FromRawFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use crate::clock::Instant;

use crate::budget::Budget;
use crate::buf_ring::BufRing;
use crate::inflight::H3Ring;
use crate::quic::conn::{Connection, Event as QuicEvent, LocalParamsInput};
use crate::stats::Stats;
use crate::target::Target;
use crate::uring::{self, CONN_IDX_BITS, OP_RECV, OP_SEND, TIMEOUT_USER_DATA};
use anyhow::{Context, Result, bail};

use self::proto::{ResponseReader, UniReader};

/// Whether to narrate what the QUIC connections are doing
///
/// A QUIC stack that is not working is usually not working silently: the peer
/// stops answering and says nothing about why. These traces are what found a
/// probe being sent on every pass, a stream retired while its data was still
/// arriving, and loss detection state outliving the keys it belonged to. They
/// sit on error paths and behind SHB_DEBUG, so they cost a branch.
fn narrate() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("SHB_DEBUG").is_some())
}

const RECEIVE_WINDOW: u32 = (1 << 30) - 1;

/// UDP_SEGMENT socket option (missing from libc for linux-gnu)
const UDP_SEGMENT: libc::c_int = 103;

/// A datagram within this much of the limit was cut off by the limit rather
/// than by running out of things to say, so there is probably more behind it.
/// A full one never reaches the limit exactly: the header and the frame
/// lengths take a variable few bytes off the top.
const NEARLY_FULL: usize = crate::quic::conn::MAX_DATAGRAM - 64;

/// Max segments per UDP GSO send (kernel limit is 64)
const GSO_SEGMENTS: usize = 64;

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

/// A send whose connection was closed from under it
///
/// The SQE was pushed, and may not even have been submitted yet, so the
/// kernel is still going to read the datagram - and the msghdr and iovec
/// that point at it, when it is a GSO batch. Freeing them with the
/// connection is what made nginx log "quic fixed bit is not set" once per
/// reconnect: the old connection's CONNECTION_CLOSE was read from freed
/// memory and sent through the socket that had since taken its slot. They
/// stay here until the completion that carries their user_data is reaped,
/// whatever generation it belongs to.
struct Retired {
    user_data: u64,
    _datagram: Datagram,
    _msg_state: Box<MsgState>,
}

/// How long a connection that has decided to close keeps its socket, waiting
/// for the send of its CONNECTION_CLOSE to complete. A UDP send completes as
/// soon as the kernel has copied it, so this is only for a socket that has
/// stopped taking anything at all.
const CLOSE_GRACE: Duration = Duration::from_secs(1);

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

/// Build the QPACK field section sent for every request
///
/// Encoded once; nothing in it depends on the stream or the connection.
fn build_field_section(target: &Target) -> Vec<u8> {
    let headers: Vec<(String, String)> = target
        .headers
        .iter()
        .filter(|(name, _)| !crate::target::is_connection_specific(name))
        // Field names must be lower-case in HTTP/3, like HTTP/2
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    qpack::encode_request(
        &target.method,
        "https",
        &target.authority,
        &target.path,
        &headers,
        target.body.len(),
    )
}

/// The least shb will wait on a connection with nothing arriving before it
/// counts it as gone. A slow response is a result to report and --timeout
/// is what bounds waiting for one, so the idle timeout only has to outlast
/// it; below that, thirty seconds is what the browsers and the QUIC
/// libraries advertise.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// What shb asks of the peer, and what it promises in return
///
/// The windows are large because the point is to keep the link full: a
/// benchmark client that stalls on flow control is measuring its own limits.
fn local_params(connect_timeout: Duration, timeout: Option<Duration>) -> LocalParamsInput {
    LocalParamsInput {
        initial_max_data: RECEIVE_WINDOW as u64,
        initial_max_stream_data: RECEIVE_WINDOW as u64,
        // The control stream and the two QPACK streams, and nothing else
        initial_max_streams_uni: 3,
        // Binds both sides: the peer closes a connection idle for this long,
        // and so does shb. It used to be the connect timeout, which made a
        // response slower than five seconds an idle connection.
        max_idle_timeout_ms: IDLE_TIMEOUT
            .max(timeout.unwrap_or(Duration::ZERO))
            .as_millis() as u64,
        // What makes a server that never answers a failed connect
        handshake_timeout_ms: connect_timeout.as_millis() as u64,
    }
}

/// Requests a connection gave back - ones the server never started on, so
/// they can be sent again without anything happening twice - and what
/// became of them
///
/// A give-back is sent again unless the connection it came from answered
/// nothing at all, in which case it is an error: that ends a run against a
/// server that turns everything away in one round trip per connection,
/// while a server that answers some of each connection's requests and
/// turns the rest away - nginx past `keepalive_requests`, however many
/// streams are open - is never cut off. The verdict is not always ready
/// when the give-back is: a GOAWAY can arrive a datagram ahead of the
/// responses it lets through, so a give-back from a connection that has
/// answered nothing yet waits until it does, or until nothing is left in
/// flight to answer.
#[derive(Default)]
struct GiveBacks {
    /// Requests answered on this connection since it was opened
    completed: u64,
    /// Given back while nothing had been answered, verdict pending
    unjudged: u64,
    /// Sent again from this connection
    retried: u64,
}

impl GiveBacks {
    fn give_back(&mut self, parallel: usize, stats: &mut Stats, started: &mut u64) {
        if self.completed == 0 {
            self.unjudged += 1;
        } else if self.retried < parallel as u64 * self.completed {
            // A bound that nothing well-behaved reaches: at most the streams
            // open at once come back from a connection that closes, and a
            // server that keeps a connection open only to turn away more
            // than it answers, many times over, is asked no further
            self.retried += 1;
            *started -= 1;
        } else {
            stats.errors += 1;
        }
    }

    /// Settle the give-backs that were waiting on this connection, once it
    /// has answered something or has nothing left in flight
    fn judge(&mut self, drained: bool, parallel: usize, stats: &mut Stats, started: &mut u64) {
        if self.unjudged == 0 {
            return;
        }
        if self.completed > 0 {
            for _ in 0..std::mem::take(&mut self.unjudged) {
                self.give_back(parallel, stats, started);
            }
        } else if drained {
            stats.errors += std::mem::take(&mut self.unjudged);
        }
    }
}

struct InFlight {
    stream_id: u64,
    start: Instant,
    /// Response frame reader for this stream
    reader: ResponseReader,
    /// Request bytes not yet accepted by the QUIC stream
    unsent: Vec<u8>,
}

struct Conn {
    fd: RawFd,
    quic: Option<Connection>,
    /// QUIC handshake finished and the H3 control/QPACK streams are set up
    h3_ready: bool,
    /// Peer-opened unidirectional streams, by QUIC stream id
    uni: Vec<(u64, UniReader)>,
    /// Datagrams have been handed to the endpoint since the state machine was
    /// last driven
    pending: bool,
    /// GOAWAY received, with the first stream id the server did not
    /// process: no new streams on this connection, and requests on that
    /// stream and above are sent again on the next one
    goaway: Option<u64>,
    /// Outgoing datagrams; the front one is in flight while `sending`
    out_queue: VecDeque<Datagram>,
    /// Buffers that have been sent and can be filled again. A datagram batch
    /// is up to 64 segments, so building one from an empty Vec means growing
    /// it back to seventy kilobytes every time.
    spare: Vec<Vec<u8>>,
    /// Scratch for one pass of the event loop, kept so that a pass does not
    /// begin by allocating the two lists it is about to fill
    readable: Vec<u64>,
    finished: Vec<(u64, Option<u64>)>,
    /// Pinned sendmsg bookkeeping for GSO sends
    msg_state: Box<MsgState>,
    sending: bool,
    /// Whether a multishot recv is active (cleared by a CQE without the MORE flag)
    recv_armed: bool,
    /// Reconnect generation. Incremented on every close; CQEs from an old
    /// generation are identified via user_data and ignored
    generation: u64,
    /// In-flight requests, up to the configured parallelism
    streams: H3Ring<InFlight>,
    give_backs: GiveBacks,
    /// The connection is over and its requests are accounted for, but the
    /// socket stays until the send of its CONNECTION_CLOSE completes, or
    /// until this deadline. Closing the socket earlier would hand the
    /// datagram to whichever socket next took the slot.
    closing: Option<Instant>,
}

impl Conn {
    fn new() -> Self {
        Conn {
            fd: -1,
            quic: None,
            h3_ready: false,
            uni: Vec::new(),
            pending: false,
            goaway: None,
            out_queue: VecDeque::new(),
            spare: Vec::new(),
            readable: Vec::new(),
            finished: Vec::new(),
            msg_state: Box::new(unsafe { std::mem::zeroed() }),
            sending: false,
            recv_armed: false,
            generation: 0,
            streams: H3Ring::new(),
            give_backs: GiveBacks::default(),
            closing: None,
        }
    }

    /// Close the socket and forget the connection
    ///
    /// A send still in flight keeps what it points at: the datagram and the
    /// sendmsg bookkeeping move to `retired` until its completion arrives.
    fn close(&mut self, conn_idx: usize, retired: &mut Vec<Retired>) {
        if self.sending
            && let Some(datagram) = self.out_queue.pop_front()
        {
            let msg_state =
                std::mem::replace(&mut self.msg_state, Box::new(unsafe { std::mem::zeroed() }));
            retired.push(Retired {
                user_data: uring::user_data(conn_idx, self.generation, OP_SEND),
                _datagram: datagram,
                _msg_state: msg_state,
            });
        }
        if self.fd >= 0 {
            // Close by turning the fd back into a UdpSocket and dropping it
            drop(unsafe { UdpSocket::from_raw_fd(self.fd) });
            self.fd = -1;
        }
        self.quic = None;
        self.uni.clear();
        self.h3_ready = false;
        self.goaway = None;
        self.out_queue.clear();
        self.sending = false;
        self.recv_armed = false;
        self.streams.clear();
        self.give_backs = GiveBacks::default();
        self.closing = None;
        // Bump the generation so CQEs of operations on the old socket are ignored
        self.generation = (self.generation + 1) & uring::GENERATION_MASK;
    }

    /// Count all in-flight requests as errors (used when the connection dies)
    fn fail_inflight(&mut self, stats: &mut Stats) {
        if narrate() && !self.streams.is_empty() {
            eprintln!(
                "[broken] {} requests in flight discarded",
                self.streams.len()
            );
        }
        stats.errors += self.streams.len() as u64;
        self.streams.clear();
        // Nothing will be answered on it now, so what was waiting on that
        // is settled the same way
        stats.errors += std::mem::take(&mut self.give_backs.unjudged);
    }
}

/// Push whatever of a request the QUIC stream would not take earlier
///
/// A fresh stream has its whole window free and requests are tiny, so this
/// normally moves nothing; it exists so a peer with a small
/// `initial_max_stream_data` cannot lose a request.
fn flush_unsent(quic: &mut Connection, streams: &mut H3Ring<InFlight>) -> Result<()> {
    for inflight in streams.iter_mut().filter(|s| !s.unsent.is_empty()) {
        let n = quic.write(inflight.stream_id, &inflight.unsent);
        inflight.unsent.drain(..n);
        if inflight.unsent.is_empty() {
            quic.finish(inflight.stream_id);
        }
    }
    Ok(())
}

/// Open new request streams until the parallelism target or budget is hit
///
/// Each request is one QUIC bidirectional stream carrying a HEADERS frame
/// (and a DATA frame when there is a body), then a FIN.
fn fill_streams(
    conn: &mut Conn,
    request: &[u8],
    parallel: usize,
    started: &mut u64,
    budget: Budget,
    stop: bool,
) -> Result<()> {
    if stop || conn.goaway.is_some() || !conn.h3_ready {
        return Ok(());
    }
    let Some(quic) = conn.quic.as_mut() else {
        return Ok(());
    };
    while conn.streams.len() < parallel && budget.may_start(*started) {
        // None = the server's MAX_STREAMS limit; retry after completions
        let Some((qsid, sent)) = quic.send_oneshot(request) else {
            break;
        };
        conn.streams.push(
            qsid,
            InFlight {
                stream_id: qsid,
                start: Instant::now(),
                reader: ResponseReader::default(),
                unsent: request[sent..].to_vec(),
            },
        );
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
            // These two are size_t against glibc and socklen_t against musl,
            // so the cast has to be inferred rather than named
            state.msg.msg_controllen = libc::CMSG_SPACE(2) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&state.msg);
            (*cmsg).cmsg_level = libc::SOL_UDP;
            (*cmsg).cmsg_type = UDP_SEGMENT;
            (*cmsg).cmsg_len = libc::CMSG_LEN(2) as _;
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

/// Retire the datagram at the front of the queue, keeping its buffer to fill
/// again. A couple of spares is all one connection ever needs at once.
fn recycle(conn: &mut Conn) {
    const SPARES: usize = 2;
    if let Some(sent) = conn.out_queue.pop_front()
        && conn.spare.len() < SPARES
    {
        conn.spare.push(sent.buf);
    }
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
        // Datagrams are built back to back into one buffer so the kernel can
        // send them as a single GSO batch. They all come out the same size
        // except possibly the last, which is what GSO requires.
        // The first datagram sets the segment size and the rest are padded to
        // match, because GSO splits one send into equal parts and only the
        // last may be shorter. Left to themselves they vary by a few bytes -
        // a packet number or a stream offset crossing a varint width - which
        // is enough to make every batch one segment long.
        // A probe goes out as at most two datagrams (RFC 9002 Section 7.5).
        // Batching it defeats the point: the path that lost the packets being
        // probed for is often losing whole batches, and a probe that is itself
        // a batch is lost the same way, so the timeout doubles and nothing
        // ever gets through.
        let max = match (gso, quic.probing()) {
            (_, true) => 2,
            (true, false) => GSO_SEGMENTS,
            (false, false) => 1,
        };
        transmit_buf.clear();
        let mut segment_size = 0usize;
        let mut count = 0usize;
        // A packet that cannot join the batch. It still has to be sent: by the
        // time its size is known its number is spent and its frames are
        // recorded as sent, so dropping it would leave the peer waiting for
        // bytes this end believes it already wrote.
        let mut oversize = None;
        while count < max {
            let before = transmit_buf.len();
            let pad = (count > 0).then_some(segment_size);
            let n = quic.poll_transmit(now, transmit_buf, pad)?;
            if n == 0 {
                break;
            }
            if count == 0 {
                segment_size = n;
                // Only worth batching if the first one filled up; a short
                // datagram means there was nothing more to send, and padding
                // the next one to match would truncate it
                if n < NEARLY_FULL {
                    count = 1;
                    break;
                }
            } else if n < segment_size {
                // A shorter last segment is what GSO allows, so this one still
                // travels with the batch; it just ends it
                count += 1;
                break;
            } else if n > segment_size {
                // Padding cannot shrink a packet, so this one cannot be a
                // segment of this batch. It leaves on its own, behind it.
                oversize = Some(transmit_buf.split_off(before));
                break;
            }
            count += 1;
        }
        if !transmit_buf.is_empty() {
            if narrate() {
                eprintln!("[gso] {count} segments of {segment_size}");
            }
            let empty = conn.spare.pop().unwrap_or_default();
            conn.out_queue.push_back(Datagram {
                buf: std::mem::replace(transmit_buf, empty),
                segment_size: if count > 1 { segment_size } else { 0 },
            });
        }
        if let Some(buf) = oversize {
            conn.out_queue.push_back(Datagram {
                buf,
                segment_size: 0,
            });
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
    conn: &mut Conn,
    stats: &mut Stats,
    request: &[u8],
    parallel: usize,
    started: &mut u64,
    budget: Budget,
    stop: bool,
) -> bool {
    let result = (|| -> Result<bool> {
        let Some(quic) = conn.quic.as_mut() else {
            return Ok(true);
        };
        let mut alive = true;
        let mut readable = std::mem::take(&mut conn.readable);
        let mut finished = std::mem::take(&mut conn.finished);
        readable.clear();
        finished.clear();

        while let Some(event) = quic.poll_event() {
            match event {
                QuicEvent::Connected => {
                    // RFC 9114 Section 6.2: the control stream and the two
                    // QPACK streams. The QPACK ones stay empty for the life of
                    // the connection - neither side may insert - but they have
                    // to exist.
                    let mut encoder = Vec::new();
                    proto::put_varint(&mut encoder, proto::STREAM_QPACK_ENCODER);
                    let mut decoder = Vec::new();
                    proto::put_varint(&mut decoder, proto::STREAM_QPACK_DECODER);
                    for prelude in [proto::control_stream_prelude(), encoder, decoder] {
                        let id = quic.open_uni().context("the peer allowed no uni streams")?;
                        if quic.write(id, &prelude) != prelude.len() {
                            bail!("short write of H3 init data");
                        }
                        // Not finished: RFC 9114 Section 6.2.1 makes the
                        // control and QPACK streams critical, and closing one
                        // is H3_CLOSED_CRITICAL_STREAM
                    }
                    conn.h3_ready = true;
                }
                QuicEvent::Lost(why) => {
                    if narrate() {
                        eprintln!("[lost] {why}");
                    }
                    alive = false;
                }
                QuicEvent::Readable(id) | QuicEvent::Opened(id) => readable.push(id),
                // The rest of the request stays unsent; whether the server
                // still answers is for the stream's end to say
                QuicEvent::Stopped(id) => {
                    if let Some(inflight) = conn.streams.get_mut(id) {
                        inflight.unsent.clear();
                    }
                }
                // Collected rather than acted on: the same datagram that ends
                // a stream usually carries the response, and completing it
                // here would retire the stream before its body is read
                QuicEvent::Finished { id, reset } => finished.push((id, reset)),
            }
        }

        // Not deduplicated: the connection already drops the repeat that
        // back-to-back frames would cause, and reading a stream that has
        // nothing ready costs less than sorting the list would.
        for &id in &readable {
            if let Some(inflight) = conn.streams.get_mut(id) {
                let reader = &mut inflight.reader;
                quic.consume(id, |data| reader.feed(data))?;
                continue;
            }
            // A peer-opened stream: its control stream, or one of its QPACK
            // streams, which never carry anything shb acts on beyond GOAWAY
            let slot = match conn.uni.iter().position(|(uid, _)| *uid == id) {
                Some(pos) => pos,
                None => {
                    conn.uni.push((id, UniReader::default()));
                    conn.uni.len() - 1
                }
            };
            let reader = &mut conn.uni[slot].1;
            quic.consume(id, |data| reader.feed(data))?;
            if let Some(id) = conn.uni[slot].1.goaway {
                conn.goaway = Some(conn.goaway.map_or(id, |prev| prev.min(id)));
            }
        }

        for &(id, reset) in &finished {
            let Some(inflight) = conn.streams.take(id) else {
                continue;
            };
            let status = inflight.reader.status();
            // A GOAWAY says nothing at or above its stream id was processed
            // (RFC 9114 Section 5.2), whatever code a reset there carries:
            // nginx past twice keepalive_requests ends the connection and
            // resets what is open with H3_INTERNAL_ERROR, having said so
            // in the GOAWAY it queued first
            let unprocessed = status == 0 && conn.goaway.is_some_and(|goaway| id >= goaway);
            if reset == Some(proto::H3_REQUEST_REJECTED) || (reset.is_some() && unprocessed) {
                // The server never started on it, so it can be sent again
                // without anything happening twice (RFC 9114 Section
                // 4.1.1). It goes back to the budget and out on the next
                // connection, timed from there: what is measured is a
                // request the server answered, not one it turned away.
                conn.give_backs.give_back(parallel, stats, started);
            } else if reset.is_some() || status == 0 {
                // Every response begins with a HEADERS frame carrying
                // :status (RFC 9114 Section 4.1); a stream that ends without
                // one never answered the request
                if narrate() {
                    eprintln!("[fail] stream {id} reset={reset:?} status={status}");
                }
                stats.errors += 1;
            } else {
                stats.record_success(status, inflight.start);
                conn.give_backs.completed += 1;
            }
            quic.retire(id, proto::H3_REQUEST_CANCELLED);
        }

        if let Some(goaway) = conn.goaway {
            // RFC 9114 Section 5.2: nothing on a stream at or above the id
            // was processed, so those requests go back to the budget now
            // rather than waiting to be reset one at a time. The rest will
            // finish, and once they have the connection is of no further
            // use: it is closed here rather than left for the server to
            // close, so the replacement is not waiting on it.
            let unprocessed: Vec<u64> = conn
                .streams
                .iter()
                .map(|s| s.stream_id)
                .filter(|&id| id >= goaway)
                .collect();
            if narrate() && !unprocessed.is_empty() {
                eprintln!(
                    "[goaway] {} requests from stream {goaway} sent again",
                    unprocessed.len()
                );
            }
            for id in unprocessed {
                conn.streams.take(id);
                quic.retire(id, proto::H3_REQUEST_CANCELLED);
                conn.give_backs.give_back(parallel, stats, started);
            }
            if conn.streams.is_empty() {
                quic.close(proto::H3_NO_ERROR, b"");
                alive = false;
            }
        }
        conn.give_backs
            .judge(conn.streams.is_empty(), parallel, stats, started);

        flush_unsent(quic, &mut conn.streams)?;
        // Back where the next pass will find them, with the capacity they grew
        conn.readable = readable;
        conn.finished = finished;
        fill_streams(conn, request, parallel, started, budget, stop)?;
        Ok(alive)
    })();

    match result {
        Ok(alive) => alive,
        Err(e) => {
            if narrate() {
                eprintln!("[drive] {e:#}");
            }
            false
        }
    }
}

/// Benchmark loop of a single HTTP/3 worker thread
pub fn run_worker(
    target: &Target,
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

    let field_section = build_field_section(target);
    let request = proto::request_bytes(&field_section, &target.body);
    let tls_config = crate::tls::client_config(b"h3")?;
    let gso = probe_gso(&target.addr);

    // Declare buf_ring / conns before the ring (see the h1/h2 workers)
    let buf_entries = (connections * 2).next_power_of_two().clamp(64, 32768) as u16;
    let mut buf_ring = BufRing::new(buf_entries)?;
    let mut conns: Vec<Conn> = Vec::with_capacity(connections);
    for _ in 0..connections {
        conns.push(Conn::new());
    }
    // Sends outliving their connection; before the ring for the same reason
    let mut retired: Vec<Retired> = Vec::new();

    let mut ring = uring::build_worker_ring(connections)?;
    // Kept alive so that enter can use the registered ring fd; submitter, sq
    // and cq are disjoint borrows, and the ring is not touched from here on
    let (mut submitter, mut sq, mut cq) = ring.split();
    uring::register_worker(&mut submitter, connections, &buf_ring)?;

    let mut stats = Stats::default();
    if let Some(n) = budget.expected_requests() {
        stats.latencies_ns.reserve(n as usize);
    }
    let mut started: u64 = 0;

    // Held for its lifetime: the SQE points at it until the run is over
    let _deadline = uring::arm_deadline(&submitter, &mut sq, budget.deadline())?;

    // Kick off the initial connections
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(2048);
    let now = Instant::now();
    for (i, conn) in conns.iter_mut().enumerate() {
        if !budget.may_start(i as u64) {
            break;
        }
        conn.fd = uring::make_udp_socket(&target.addr)?;
        submitter
            .register_files_update(i as u32, &[conn.fd])
            .context("register_files_update failed")?;
        conn.quic = Some(Connection::connect(
            tls_config.clone(),
            &target.host,
            local_params(connect_timeout, timeout),
        )?);
        uring::push_recv_multi(&submitter, &mut sq, i, conn.generation)?;
        conn.recv_armed = true;
        pump_transmits(&submitter, &mut sq, i, conn, now, &mut transmit_buf, gso)?;
    }

    let mut stop = false;
    // How many completions one wait should collect before returning
    let batch = uring::batch_size(connections);
    // stays: it is what found a probe being sent on every pass rather than
    // once per timeout
    let mut last_dump = Instant::now();

    loop {
        if budget.is_met(stats.completed + stats.errors) {
            break;
        }
        if crate::shutdown::requested() {
            break;
        }

        // Service expired QUIC timers and bound the wait by the nearest one
        let now = Instant::now();
        if narrate() && last_dump.elapsed() > Duration::from_secs(2) {
            last_dump = Instant::now();
            for (i, conn) in conns.iter().enumerate().take(3) {
                match conn.quic.as_ref() {
                    Some(q) => eprintln!("[{i}] ready={} {}", conn.h3_ready, q.debug_state()),
                    None => eprintln!("[{i}] no connection"),
                }
            }
        }

        let mut wait = uring::WAIT_TIMEOUT;
        for (conn_idx, conn) in conns.iter_mut().enumerate() {
            if let Some(deadline) = conn.closing {
                // Waiting only for the send of its CONNECTION_CLOSE to come
                // back; a socket that will not even do that is let go
                if deadline <= now {
                    finish_close(
                        &submitter,
                        &mut sq,
                        conn_idx,
                        conn,
                        &tls_config,
                        connect_timeout,
                        timeout,
                        target,
                        &mut started,
                        budget,
                        stop,
                        &mut transmit_buf,
                        gso,
                        &mut retired,
                    )?;
                } else {
                    wait = wait.min(deadline - now);
                }
                continue;
            }
            let mut expired = false;
            if let Some(quic) = conn.quic.as_mut() {
                while let Some(deadline) = quic.poll_timeout() {
                    if deadline <= now {
                        quic.handle_timeout(now);
                        expired = true;
                    } else {
                        // Wait exactly until the nearest QUIC timer - loss
                        // detection, the probe timeout or the idle deadline -
                        // rather than rounding up to the poll interval, which
                        // would quantize when a loss is noticed. There is no
                        // pacer here to be one of them: sending is gated by a
                        // congestion window, not a rate.
                        wait = wait.min(deadline - now);
                        break;
                    }
                }
            }
            if expired {
                let alive = drive(
                    conn,
                    &mut stats,
                    &request,
                    parallel,
                    &mut started,
                    budget,
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
                    begin_close(
                        &submitter,
                        &mut sq,
                        conn_idx,
                        conn,
                        &mut stats,
                        &tls_config,
                        connect_timeout,
                        timeout,
                        target,
                        &mut started,
                        budget,
                        stop,
                        &mut transmit_buf,
                        gso,
                        now,
                        &mut retired,
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
                // The kernel is done with what the send pointed at
                if op == OP_SEND {
                    retired.retain(|r| r.user_data != ud);
                }
                continue;
            }

            let mut conn_broken = false;
            match op {
                OP_SEND => {
                    let conn = &mut conns[conn_idx];
                    conn.sending = false;
                    if res == -libc::EMSGSIZE {
                        // An MTU probe the kernel will not carry. Dropping it
                        // is exactly what the probe timing out expects, so
                        // discard the datagram and keep the connection
                        recycle(conn);
                        push_front_send(&submitter, &mut sq, conn_idx, conn)?;
                    } else if res < 0 {
                        if narrate() {
                            eprintln!("[send] {}", std::io::Error::from_raw_os_error(-res));
                        }
                        conn_broken = true;
                    } else {
                        stats.bytes_sent += res as u64;
                        recycle(conn);
                        push_front_send(&submitter, &mut sq, conn_idx, conn)?;
                    }
                    // The CONNECTION_CLOSE has left, so the socket can go
                    if conn.closing.is_some() && !conn.sending {
                        conn_broken = true;
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
                        if res == -libc::ENOBUFS || res == -libc::EMSGSIZE {
                            // ENOBUFS: the buffer ring ran dry. EMSGSIZE: a
                            // datagram we sent was too big for the path, and
                            // the ICMP reply is reported on whichever
                            // operation runs next - often a recv rather than
                            // the send itself. Both leave the connection
                            // intact; an MTU probe that draws one is a probe
                            // that timed out, which is what the send path
                            // already assumes.
                            uring::push_recv_multi(&submitter, &mut sq, conn_idx, conn.generation)?;
                            conn.recv_armed = true;
                        } else {
                            if narrate() {
                                eprintln!("[recv] {}", std::io::Error::from_raw_os_error(-res));
                            }
                            conn_broken = true;
                        }
                    } else {
                        // res == 0 is a valid empty datagram for UDP; QUIC
                        // never sends one, so just recycle and move on
                        stats.bytes_received += res as u64;
                        if let Some(bid) = io_uring::cqueue::buffer_select(flags) {
                            if res > 0 {
                                // Straight into the connection: there is no
                                // endpoint to route through, since a client
                                // socket carries exactly one connection
                                if let Some(quic) = conn.quic.as_mut()
                                    && let Err(e) = quic
                                        .handle_datagram(now, buf_ring.data_mut(bid, res as usize))
                                {
                                    if narrate() {
                                        eprintln!("[datagram] {e:#}");
                                    }
                                    conn_broken = true;
                                }
                            }
                            buf_ring.recycle(bid);
                        }
                        if !conn.recv_armed {
                            uring::push_recv_multi(&submitter, &mut sq, conn_idx, conn.generation)?;
                            conn.recv_armed = true;
                        }
                        // Turning the state machine is the expensive part -
                        // polling events, opening streams, building packets -
                        // and it costs the same whether one datagram arrived
                        // or eight, so leave it until the batch is drained
                        conn.pending = true;
                    }
                }
                _ => unreachable!(),
            }

            if conn_broken {
                let conn = &mut conns[conn_idx];
                begin_close(
                    &submitter,
                    &mut sq,
                    conn_idx,
                    conn,
                    &mut stats,
                    &tls_config,
                    connect_timeout,
                    timeout,
                    target,
                    &mut started,
                    budget,
                    stop,
                    &mut transmit_buf,
                    gso,
                    now,
                    &mut retired,
                )?;
            }
        }

        // Turn the state machines once for the whole batch of datagrams
        let now = Instant::now();
        for (conn_idx, conn) in conns.iter_mut().enumerate() {
            if !conn.pending || conn.closing.is_some() {
                conn.pending = false;
                continue;
            }
            conn.pending = false;
            let alive = drive(
                conn,
                &mut stats,
                &request,
                parallel,
                &mut started,
                budget,
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
                begin_close(
                    &submitter,
                    &mut sq,
                    conn_idx,
                    conn,
                    &mut stats,
                    &tls_config,
                    connect_timeout,
                    timeout,
                    target,
                    &mut started,
                    budget,
                    stop,
                    &mut transmit_buf,
                    gso,
                    now,
                    &mut retired,
                )?;
            }
        }

        // A response that never comes would otherwise hold the run open for
        // ever: a wedged server is a result to report, not a reason to wait.
        // Looked at after the batch has been read, so that a response that
        // arrived in it is not counted as one that never came. The server
        // is told: it used to be left to find out from its idle timer,
        // which for nginx meant "quic client timed out" in its log five
        // seconds after every request shb gave up on.
        if let Some(limit) = timeout {
            for (conn_idx, conn) in conns.iter_mut().enumerate() {
                if !conn
                    .streams
                    .iter()
                    .any(|s| now.duration_since(s.start) >= limit)
                {
                    continue;
                }
                if let Some(quic) = conn.quic.as_mut() {
                    // What the code means (RFC 9114 Section 8.1): the
                    // connection goes because shb has cancelled what it was
                    // waiting for on it, which a server's log can tell from
                    // a client that was simply done
                    quic.close(proto::H3_REQUEST_CANCELLED, b"");
                }
                pump_transmits(
                    &submitter,
                    &mut sq,
                    conn_idx,
                    conn,
                    now,
                    &mut transmit_buf,
                    gso,
                )?;
                begin_close(
                    &submitter,
                    &mut sq,
                    conn_idx,
                    conn,
                    &mut stats,
                    &tls_config,
                    connect_timeout,
                    timeout,
                    target,
                    &mut started,
                    budget,
                    stop,
                    &mut transmit_buf,
                    gso,
                    now,
                    &mut retired,
                )?;
            }
        }

        if stop {
            break;
        }
    }

    // What the last pass pushed has not been submitted: for a connection
    // that was closing, that is its CONNECTION_CLOSE, and the buffer is kept
    // past the ring for it. A UDP send runs to completion at submission.
    sq.sync();
    submitter.submit().context("io_uring submit failed")?;

    // Best-effort CONNECTION_CLOSE so servers see a clean shutdown
    let now = Instant::now();
    for (conn_idx, conn) in conns.iter_mut().enumerate() {
        if let Some(quic) = conn.quic.as_mut() {
            quic.close(proto::H3_NO_ERROR, b"");
            transmit_buf.clear();
            if let Ok(n) = quic.poll_transmit(now, &mut transmit_buf, None)
                && n > 0
            {
                unsafe {
                    libc::send(
                        conn.fd,
                        transmit_buf.as_ptr() as *const libc::c_void,
                        n,
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    );
                }
            }
        }
        conn.close(conn_idx, &mut retired);
    }

    Ok(stats)
}

/// Give up on a connection
///
/// Its requests are accounted for now. The socket is not closed yet: the
/// send in flight - the CONNECTION_CLOSE, on the paths that send one - has
/// to complete on this socket first, and until it does its buffer is in
/// use. The close and the reconnect happen when its completion arrives, or
/// at the deadline set here.
#[allow(clippy::too_many_arguments)]
fn begin_close(
    submitter: &io_uring::Submitter<'_>,
    sq: &mut io_uring::squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &mut Conn,
    stats: &mut Stats,
    tls_config: &Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    timeout: Option<Duration>,
    target: &Target,
    started: &mut u64,
    budget: Budget,
    stop: bool,
    transmit_buf: &mut Vec<u8>,
    gso: bool,
    now: Instant,
    retired: &mut Vec<Retired>,
) -> Result<()> {
    if conn.closing.is_none() {
        if conn.h3_ready {
            conn.fail_inflight(stats);
        } else {
            // Never got as far as a working HTTP/3 connection: count it like
            // the TCP workers count a failed connect, consuming one unit of
            // budget
            stats.errors += 1;
            stats.connect_errors += 1;
            *started += 1;
        }
        conn.closing = Some(now + CLOSE_GRACE);
    }
    if conn.sending {
        return Ok(());
    }
    finish_close(
        submitter,
        sq,
        conn_idx,
        conn,
        tls_config,
        connect_timeout,
        timeout,
        target,
        started,
        budget,
        stop,
        transmit_buf,
        gso,
        retired,
    )
}

/// Close the socket of a connection that is over, and open the next one if
/// the request budget allows
#[allow(clippy::too_many_arguments)]
fn finish_close(
    submitter: &io_uring::Submitter<'_>,
    sq: &mut io_uring::squeue::SubmissionQueue<'_>,
    conn_idx: usize,
    conn: &mut Conn,
    tls_config: &Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    timeout: Option<Duration>,
    target: &Target,
    started: &mut u64,
    budget: Budget,
    stop: bool,
    transmit_buf: &mut Vec<u8>,
    gso: bool,
    retired: &mut Vec<Retired>,
) -> Result<()> {
    conn.close(conn_idx, retired);
    if stop || !budget.may_start(*started) {
        return Ok(());
    }
    conn.fd = uring::make_udp_socket(&target.addr)?;
    submitter
        .register_files_update(conn_idx as u32, &[conn.fd])
        .context("register_files_update failed")?;
    let now = Instant::now();
    conn.quic = Some(Connection::connect(
        tls_config.clone(),
        &target.host,
        local_params(connect_timeout, timeout),
    )?);
    uring::push_recv_multi(submitter, sq, conn_idx, conn.generation)?;
    conn.recv_armed = true;
    pump_transmits(submitter, sq, conn_idx, conn, now, transmit_buf, gso)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// nginx past keepalive_requests: it answers some of a connection's
    /// requests and turns the rest away, so the rest go out again
    #[test]
    fn a_connection_that_answered_something_sends_its_give_backs_again() {
        let mut stats = Stats::default();
        let mut started = 100;
        let mut g = GiveBacks {
            completed: 10,
            ..Default::default()
        };
        for _ in 0..90 {
            g.give_back(100, &mut stats, &mut started);
        }
        assert_eq!((started, stats.errors), (10, 0));
    }

    /// A server that turns everything away: once nothing is left in flight
    /// on a connection that answered nothing, what it turned away is an
    /// error, which is what ends a counted run
    #[test]
    fn a_connection_that_answered_nothing_counts_its_give_backs_as_errors() {
        let mut stats = Stats::default();
        let mut started = 8;
        let mut g = GiveBacks::default();
        for _ in 0..8 {
            g.give_back(8, &mut stats, &mut started);
        }
        assert_eq!((started, stats.errors), (8, 0), "not decided yet");
        g.judge(false, 8, &mut stats, &mut started);
        assert_eq!(stats.errors, 0, "something is still in flight");
        g.judge(true, 8, &mut stats, &mut started);
        assert_eq!((started, stats.errors), (8, 8));
    }

    /// A GOAWAY can arrive a datagram ahead of the responses it lets
    /// through, so the verdict waits for them
    #[test]
    fn a_give_back_waits_for_the_first_answer() {
        let mut stats = Stats::default();
        let mut started = 100;
        let mut g = GiveBacks::default();
        for _ in 0..90 {
            g.give_back(100, &mut stats, &mut started);
        }
        g.judge(false, 100, &mut stats, &mut started);
        assert_eq!((started, stats.errors, g.unjudged), (100, 0, 90));
        g.completed = 10;
        g.judge(false, 100, &mut stats, &mut started);
        assert_eq!((started, stats.errors, g.unjudged), (10, 0, 0));
    }

    /// A server that keeps a connection open only to turn away many times
    /// more than it answers is asked no further
    #[test]
    fn give_backs_on_one_connection_are_bounded_by_what_it_answered() {
        let mut stats = Stats::default();
        let mut started = 1000;
        let mut g = GiveBacks {
            completed: 1,
            ..Default::default()
        };
        for _ in 0..40 {
            g.give_back(8, &mut stats, &mut started);
        }
        assert_eq!((started, stats.errors), (992, 32));
    }
}
