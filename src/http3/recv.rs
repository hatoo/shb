//! Decode UDP GRO without copying or exposing recvmsg metadata to QUIC.

use io_uring::types::RecvMsgOut;

// io_uring_recvmsg_out contains four u32 fields. Connected UDP needs no peer
// address; reserve one control message for UDP_GRO's native int segment size.
const PREFIX_SIZE: usize = 4 * std::mem::size_of::<u32>();
const CONTROL_SIZE: usize =
    unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as _) as usize };
const PAYLOAD_OFFSET: usize = PREFIX_SIZE + CONTROL_SIZE;
pub(super) const BUFFER_SIZE: usize = PAYLOAD_OFFSET + 65536;

/// Shared, immutable SQE template. Construct before the io_uring so even an
/// unsubmitted receive on an old connection generation cannot outlive it.
pub(super) fn template() -> Box<libc::msghdr> {
    let mut msg: Box<libc::msghdr> = Box::new(unsafe { std::mem::zeroed() });
    msg.msg_controllen = CONTROL_SIZE as _;
    msg
}

pub(super) struct Received<'a> {
    pub payload: &'a mut [u8],
    pub segment_size: usize,
}

/// The slice must contain exactly the CQE's result bytes, not the unused tail
/// of the provided buffer. A truncated aggregate must never become a single
/// QUIC datagram: that would lose its original packet boundaries.
pub(super) fn decode<'a>(buffer: &'a mut [u8], msg: &libc::msghdr) -> Option<Received<'a>> {
    let received = RecvMsgOut::parse(buffer, msg).ok()?;
    let payload_len = received.payload_data().len();
    if received.is_payload_truncated()
        || received.is_control_data_truncated()
        || received.incoming_payload_len() as usize != payload_len
        || received.incoming_control_len() as usize != received.control_data().len()
        || PAYLOAD_OFFSET + payload_len != buffer.len()
        || buffer.len() > BUFFER_SIZE
    {
        return None;
    }
    let control = received.control_data();
    let mut segment_size = payload_len.max(1);
    if !control.is_empty() {
        let header_len = unsafe { libc::CMSG_LEN(0) as usize };
        if control.len() < header_len {
            return None;
        }
        // The provided buffer need not align cmsghdr. Only one cmsg fits in
        // CONTROL_SIZE; its padding is not another header.
        let header = unsafe { control.as_ptr().cast::<libc::cmsghdr>().read_unaligned() };
        let len = header.cmsg_len;
        if len < header_len || len > control.len() {
            return None;
        }
        if header.cmsg_level == libc::IPPROTO_UDP && header.cmsg_type == libc::UDP_GRO {
            if len != unsafe { libc::CMSG_LEN(4) as usize } || payload_len == 0 {
                return None;
            }
            let size = i32::from_ne_bytes(control[header_len..header_len + 4].try_into().ok()?);
            if size <= 0 || size > u16::MAX as i32 {
                return None;
            }
            segment_size = size as usize;
        }
    }
    Some(Received {
        payload: &mut buffer[PAYLOAD_OFFSET..],
        segment_size,
    })
}

/// Process a current-generation receive and return whether the connection broke.
/// The worker filters stale completions before this call. Every selected buffer
/// is returned, including on invalid metadata or an unsuccessful receive.
pub(super) fn complete(
    conn: &mut super::Conn,
    stats: &mut crate::stats::Stats,
    now: minstant::Instant,
    result: i32,
    flags: u32,
    buffers: &mut crate::buf_ring::BufRing,
    msg: &libc::msghdr,
) -> bool {
    if !io_uring::cqueue::more(flags) {
        conn.recv_armed = false;
    }
    let bid = io_uring::cqueue::buffer_select(flags);
    let broken = (|| {
        if result < 0 {
            // ENOBUFS ends a shot when buffers run dry. EMSGSIZE can report an
            // ICMP reply to an MTU probe on the receive operation; leave QUIC
            // to handle the lost probe through its existing timeout logic.
            if result == -libc::ENOBUFS || result == -libc::EMSGSIZE {
                return false;
            }
            if super::narrate() {
                eprintln!("[recv] {}", std::io::Error::from_raw_os_error(-result));
            }
            return true;
        }
        let Some(bid) = bid else { return true };
        let Some(received) = decode(buffers.data_mut(bid, result as usize), msg) else {
            if super::narrate() {
                eprintln!("[recv] invalid or truncated UDP receive metadata");
            }
            return true;
        };
        // The prefix and ancillary data are not network bytes. Empty UDP
        // contributes no QUIC input, just as with the previous RecvMulti path.
        stats.bytes_received += received.payload.len() as u64;
        if let Some(quic) = conn.quic.as_mut() {
            for datagram in received.payload.chunks_mut(received.segment_size) {
                if let Err(e) = quic.handle_datagram(now, datagram) {
                    if super::narrate() {
                        eprintln!("[datagram] {e:#}");
                    }
                    return true;
                }
            }
        }
        // Keep the existing batch boundary and clock: requests and latency
        // samples are collected by drive after the completion batch is drained.
        conn.pending = true;
        false
    })();
    if let Some(bid) = bid {
        buffers.recycle(bid);
    }
    broken
}

#[cfg(test)]
mod tests;
