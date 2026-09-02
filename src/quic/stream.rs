//! Streams and flow control (RFC 9000 Sections 2, 3 and 4)
//!
//! Shaped around what a benchmark client does: it opens a bidirectional
//! stream per request, writes the whole request at once, and reads a response
//! that almost always arrives in order. So the send side keeps one contiguous
//! buffer rather than a rope, and the receive side has a fast path that
//! appends in-order data straight through and only sorts when a datagram
//! actually arrives out of order.

use anyhow::{Result, bail};

/// How much buffer a pooled stream keeps hold of. Requests are tens of bytes
/// and most responses are small, so this covers the common case; a stream that
/// carried a large body gives the rest back rather than keeping it for a
/// connection's lifetime.
const POOLED_CAPACITY: usize = 4096;

/// Which side opened a stream, and whether it carries data both ways
/// (RFC 9000 Section 2.1)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    Bi,
    Uni,
}

pub const fn stream_dir(id: u64) -> Dir {
    if id & 0x2 == 0 { Dir::Bi } else { Dir::Uni }
}

pub const fn is_client_initiated(id: u64) -> bool {
    id & 0x1 == 0
}

/// The nth stream a client opens in the given direction
pub const fn client_stream_id(dir: Dir, n: u64) -> u64 {
    match dir {
        Dir::Bi => n * 4,
        Dir::Uni => n * 4 + 2,
    }
}

/// One end of a stream we write to
#[derive(Default)]
pub struct SendStream {
    /// Everything written and not yet acknowledged, starting at `base_offset`
    buf: Vec<u8>,
    /// Stream offset of `buf[0]`
    base_offset: u64,
    /// How much of `buf` has been put into a packet at least once
    sent: usize,
    /// Offsets the peer has not acknowledged and that need sending again,
    /// as (start, end) relative to `base_offset`
    lost: Vec<(usize, usize)>,
    /// The peer's MAX_STREAM_DATA for this stream
    limit: u64,
    fin: bool,
    /// The FIN has been put into a packet
    fin_sent: bool,
}

impl SendStream {
    /// Start a stream on a buffer that an earlier one has already grown. A
    /// stream lives for one request, so a fresh buffer each time is an
    /// allocation per request on each side.
    pub fn with_buf(limit: u64, mut buf: Vec<u8>) -> Self {
        buf.clear();
        buf.shrink_to(POOLED_CAPACITY);
        Self {
            buf,
            base_offset: 0,
            sent: 0,
            lost: Vec::new(),
            limit,
            fin: false,
            fin_sent: false,
        }
    }

    /// Give the buffer back for the next stream to use
    pub fn take_buf(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            ..Default::default()
        }
    }

    /// How many bytes flow control still allows
    pub fn writable(&self) -> u64 {
        self.limit
            .saturating_sub(self.base_offset + self.buf.len() as u64)
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        let room = self.writable().min(data.len() as u64) as usize;
        self.buf.extend_from_slice(&data[..room]);
        room
    }

    pub fn finish(&mut self) {
        self.fin = true;
    }

    pub fn set_limit(&mut self, limit: u64) {
        self.limit = self.limit.max(limit);
    }

    /// The next run of data to put in a packet: retransmissions first, since
    /// the peer is already waiting on them
    /// Whether `next_send` would produce anything, without borrowing the data
    pub fn has_pending(&self) -> bool {
        !self.lost.is_empty() || self.buf.len() > self.sent || (self.fin && !self.fin_sent)
    }

    pub fn next_send(&self, max: usize) -> Option<(u64, &[u8], bool)> {
        if let Some(&(start, end)) = self.lost.first() {
            let end = end.min(start + max);
            return Some((
                self.base_offset + start as u64,
                &self.buf[start..end],
                false,
            ));
        }
        let end = self.buf.len().min(self.sent + max);
        if end > self.sent {
            let fin = self.fin && end == self.buf.len();
            return Some((
                self.base_offset + self.sent as u64,
                &self.buf[self.sent..end],
                fin,
            ));
        }
        // Nothing left but the FIN itself. Only once the data is all sent:
        // a FIN sits at the end of the buffer, so sending one while bytes are
        // still unsent would tell the peer the stream ends at an offset this
        // end has not written to it yet
        if self.fin && !self.fin_sent && self.sent >= self.buf.len() {
            return Some((self.base_offset + self.buf.len() as u64, &[], true));
        }
        None
    }

    /// Record that `len` bytes from `offset` went into a packet
    pub fn on_sent(&mut self, offset: u64, len: usize, fin: bool) {
        let start = (offset - self.base_offset) as usize;
        if let Some(pos) = self.lost.iter().position(|&(s, e)| s == start && e > start) {
            let (s, e) = self.lost[pos];
            if s + len >= e {
                self.lost.remove(pos);
            } else {
                self.lost[pos] = (s + len, e);
            }
        } else if len > 0 {
            // A frame carrying no data must not move the mark: the FIN's
            // offset is the end of the buffer, and treating that as sent
            // would strand every byte before it
            self.sent = self.sent.max(start + len);
        }
        if fin {
            self.fin_sent = true;
        }
    }

    /// The peer acknowledged everything below `offset`, so it can be dropped
    pub fn on_acked(&mut self, offset: u64, len: usize) {
        let end = offset + len as u64;
        if end <= self.base_offset {
            return;
        }
        // Only a prefix can be released, since the buffer is contiguous
        if offset <= self.base_offset {
            let drop = (end - self.base_offset) as usize;
            let drop = drop.min(self.buf.len());
            self.buf.drain(..drop);
            self.base_offset += drop as u64;
            self.sent = self.sent.saturating_sub(drop);
            for r in &mut self.lost {
                r.0 = r.0.saturating_sub(drop);
                r.1 = r.1.saturating_sub(drop);
            }
            self.lost.retain(|&(s, e)| e > s);
        }
    }

    /// The packet carrying this run was declared lost
    pub fn on_lost(&mut self, offset: u64, len: usize, fin: bool) {
        // The FIN is not data and is not covered by base_offset, so it has to
        // be reconsidered even when every byte in the packet was already
        // acknowledged - an empty stream whose lost FIN is never sent again
        // leaves the peer waiting for an end that never comes
        if fin {
            self.fin_sent = false;
        }
        if offset + len as u64 <= self.base_offset {
            return;
        }
        let start = offset.saturating_sub(self.base_offset) as usize;
        let end = (start + len).min(self.buf.len());
        if end > start {
            self.lost.push((start, end));
            self.lost.sort_unstable();
        }
    }

    /// STOP_SENDING: the peer does not want the rest, so drop it
    pub fn reset(&mut self) {
        self.buf.clear();
        self.lost.clear();
    }
}

/// One end of a stream we read from
#[derive(Default)]
pub struct RecvStream {
    /// Contiguous data from `read_offset` that the application has not taken.
    /// Only ever appended to and taken whole, so a Vec beats a VecDeque: both
    /// halves of the operation become a memcpy.
    ready: Vec<u8>,
    /// Stream offset of the next byte the application will see
    read_offset: u64,
    /// Data that arrived early, sorted by offset
    pending: Vec<(u64, Vec<u8>)>,
    /// Offset the stream ends at, once the peer says so
    final_size: Option<u64>,
    /// Total bytes delivered, for connection-level flow control accounting
    received: u64,
}

impl RecvStream {
    /// The receiving half of [`SendStream::with_buf`]
    pub fn with_buf(mut ready: Vec<u8>) -> Self {
        ready.clear();
        ready.shrink_to(POOLED_CAPACITY);
        Self {
            ready,
            read_offset: 0,
            pending: Vec::new(),
            final_size: None,
            received: 0,
        }
    }

    pub fn take_buf(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.ready)
    }

    /// Take a STREAM frame. Returns how many new bytes of stream this covered,
    /// which is what counts against the flow control window.
    pub fn push(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<u64> {
        if fin {
            let end = offset + data.len() as u64;
            match self.final_size {
                Some(prev) if prev != end => bail!("stream final size changed"),
                _ => self.final_size = Some(end),
            }
        }
        let end = offset + data.len() as u64;
        if let Some(final_size) = self.final_size
            && end > final_size
        {
            bail!("stream data past its final size");
        }
        let new = end.saturating_sub(self.received.max(self.read_offset));
        self.received = self.received.max(end);

        if offset <= self.read_offset + self.ready.len() as u64 {
            // In order, or overlapping what we already have: the common case,
            // and it costs one extend
            let skip = (self.read_offset + self.ready.len() as u64 - offset) as usize;
            if skip < data.len() {
                self.ready.extend_from_slice(&data[skip..]);
            }
            self.drain_pending();
        } else if !data.is_empty() {
            self.pending.push((offset, data.to_vec()));
            self.pending.sort_unstable_by_key(|(o, _)| *o);
        }
        Ok(new)
    }

    /// Move anything that has become contiguous out of `pending`
    fn drain_pending(&mut self) {
        while let Some((offset, _)) = self.pending.first() {
            let head = self.read_offset + self.ready.len() as u64;
            if *offset > head {
                break;
            }
            let (offset, data) = self.pending.remove(0);
            let skip = (head - offset) as usize;
            if skip < data.len() {
                self.ready.extend_from_slice(&data[skip..]);
            }
        }
    }

    /// Hand the application everything contiguous that is ready
    pub fn read(&mut self, out: &mut Vec<u8>) -> usize {
        let n = self.ready.len();
        out.append(&mut self.ready);
        self.read_offset += n as u64;
        n
    }

    pub fn is_finished(&self) -> bool {
        match self.final_size {
            Some(size) => self.read_offset + self.ready.len() as u64 >= size,
            None => false,
        }
    }

    pub fn has_data(&self) -> bool {
        !self.ready.is_empty()
    }

    pub fn reset(&mut self, final_size: u64) -> Result<()> {
        if let Some(prev) = self.final_size
            && prev != final_size
        {
            bail!("RESET_STREAM final size disagrees with the data already sent");
        }
        self.final_size = Some(final_size);
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_fin_does_not_go_out_ahead_of_the_data_it_ends() {
        // A packet with only enough room for a frame header leaves no budget
        // for data. The FIN sits at the end of the buffer, so sending it here
        // would tell the peer the stream ends at an offset nothing has been
        // written to - and marking that offset as sent strands every byte
        // before it, leaving the peer waiting for a body that never comes.
        let mut s = SendStream::new(1 << 20);
        assert_eq!(s.write(b"GET / HTTP/3 request.."), 22);
        s.finish();

        assert_eq!(s.next_send(0), None);
        assert!(s.has_pending());

        let (offset, data, fin) = s.next_send(1200).expect("the data is still owed");
        assert_eq!((offset, data.len(), fin), (0, 22, true));
    }

    #[test]
    fn an_empty_frame_never_marks_unsent_bytes_as_sent() {
        let mut s = SendStream::new(1 << 20);
        s.write(b"twenty-two bytes here!");
        s.finish();
        // As if a zero-length frame had gone out at the end of the buffer
        s.on_sent(22, 0, true);
        let (offset, data, _) = s.next_send(1200).expect("the body is still owed");
        assert_eq!((offset, data.len()), (0, 22));
    }
    use super::*;

    fn read_all(r: &mut RecvStream) -> Vec<u8> {
        let mut out = Vec::new();
        r.read(&mut out);
        out
    }

    #[test]
    fn stream_ids_follow_the_spec() {
        // RFC 9000 Table 1: the two low bits are initiator and direction
        assert_eq!(client_stream_id(Dir::Bi, 0), 0);
        assert_eq!(client_stream_id(Dir::Bi, 1), 4);
        assert_eq!(client_stream_id(Dir::Uni, 0), 2);
        assert_eq!(client_stream_id(Dir::Uni, 1), 6);
        assert_eq!(stream_dir(0), Dir::Bi);
        assert_eq!(stream_dir(2), Dir::Uni);
        assert_eq!(stream_dir(3), Dir::Uni);
        assert!(is_client_initiated(4));
        assert!(!is_client_initiated(3), "a server-initiated uni stream");
    }

    #[test]
    fn in_order_data_goes_straight_through() {
        let mut r = RecvStream::default();
        assert_eq!(r.push(0, b"hello ", false).unwrap(), 6);
        assert_eq!(r.push(6, b"world", true).unwrap(), 5);
        assert_eq!(read_all(&mut r), b"hello world");
        assert!(r.is_finished());
    }

    #[test]
    fn out_of_order_data_is_reassembled() {
        let mut r = RecvStream::default();
        r.push(6, b"world", true).unwrap();
        assert!(!r.has_data(), "nothing is contiguous yet");
        r.push(0, b"hello ", false).unwrap();
        assert_eq!(read_all(&mut r), b"hello world");
        assert!(r.is_finished());
    }

    /// Three chunks arriving backwards, which is the case the fast path has
    /// to fall out of and still get right
    #[test]
    fn reassembly_handles_a_full_reversal() {
        let mut r = RecvStream::default();
        r.push(8, b"cccc", true).unwrap();
        r.push(4, b"bbbb", false).unwrap();
        r.push(0, b"aaaa", false).unwrap();
        assert_eq!(read_all(&mut r), b"aaaabbbbcccc");
        assert!(r.is_finished());
    }

    /// A peer may resend data we already have; it must not appear twice
    #[test]
    fn duplicate_and_overlapping_data_is_absorbed() {
        let mut r = RecvStream::default();
        r.push(0, b"abcdef", false).unwrap();
        assert_eq!(r.push(0, b"abcdef", false).unwrap(), 0, "nothing new");
        assert_eq!(r.push(3, b"defghi", false).unwrap(), 3, "three new bytes");
        assert_eq!(read_all(&mut r), b"abcdefghi");
    }

    #[test]
    fn reading_twice_continues_where_it_left_off() {
        let mut r = RecvStream::default();
        r.push(0, b"aaa", false).unwrap();
        assert_eq!(read_all(&mut r), b"aaa");
        r.push(3, b"bbb", true).unwrap();
        assert_eq!(read_all(&mut r), b"bbb");
        assert!(r.is_finished());
    }

    #[test]
    fn a_changed_final_size_is_rejected() {
        let mut r = RecvStream::default();
        r.push(0, b"abc", true).unwrap();
        assert!(r.push(0, b"abcdef", true).is_err());
    }

    #[test]
    fn data_past_the_final_size_is_rejected() {
        let mut r = RecvStream::default();
        r.push(0, b"abc", true).unwrap();
        assert!(r.push(3, b"more", false).is_err());
    }

    #[test]
    fn a_reset_disagreeing_with_the_data_is_rejected() {
        let mut r = RecvStream::default();
        r.push(0, b"abcde", true).unwrap();
        assert!(r.reset(99).is_err());
        assert!(r.reset(5).is_ok());
    }

    #[test]
    fn writing_is_capped_by_the_peers_limit() {
        let mut s = SendStream::new(4);
        assert_eq!(s.write(b"abcdefgh"), 4, "only four bytes are allowed");
        assert_eq!(s.writable(), 0);
        s.set_limit(8);
        assert_eq!(s.write(b"efgh"), 4);
    }

    /// MAX_STREAM_DATA can arrive out of order, and a smaller one must not
    /// claw back credit already granted
    #[test]
    fn the_limit_only_ever_grows() {
        let mut s = SendStream::new(10);
        s.set_limit(4);
        assert_eq!(s.writable(), 10);
    }

    #[test]
    fn sending_walks_the_buffer_then_the_fin() {
        let mut s = SendStream::new(100);
        s.write(b"abcdef");
        s.finish();
        let (off, data, fin) = s.next_send(4).unwrap();
        assert_eq!((off, data, fin), (0, &b"abcd"[..], false));
        s.on_sent(off, data.len(), fin);
        let (off, data, fin) = s.next_send(4).unwrap();
        assert_eq!((off, data, fin), (4, &b"ef"[..], true));
        s.on_sent(off, data.len(), fin);
        assert!(s.next_send(4).is_none(), "nothing left to send");
        s.on_acked(0, 6);
        assert!(
            s.next_send(4).is_none(),
            "and nothing comes back after the ack"
        );
    }

    /// An empty stream still has to send its FIN
    #[test]
    fn an_empty_stream_sends_its_fin() {
        let mut s = SendStream::new(100);
        s.finish();
        let (off, data, fin) = s.next_send(1200).unwrap();
        assert_eq!((off, data.len(), fin), (0, 0, true));
        s.on_sent(off, 0, true);
        assert!(s.next_send(1200).is_none());
    }

    /// Lost data goes out again before anything new, because the peer is
    /// already blocked on it
    #[test]
    fn retransmissions_come_first() {
        let mut s = SendStream::new(100);
        s.write(b"aaaabbbb");
        let (off, data, fin) = s.next_send(4).unwrap();
        s.on_sent(off, data.len(), fin);
        let (off2, data2, fin2) = s.next_send(4).unwrap();
        s.on_sent(off2, data2.len(), fin2);
        assert!(s.next_send(4).is_none());

        s.on_lost(0, 4, false);
        let (off, data, _) = s.next_send(4).unwrap();
        assert_eq!((off, data), (0, &b"aaaa"[..]), "the lost run, not new data");
    }

    /// A lost FIN has to be sent again too, or the peer waits forever
    #[test]
    fn a_lost_fin_is_sent_again() {
        let mut s = SendStream::new(100);
        s.finish();
        let (off, _, _) = s.next_send(10).unwrap();
        s.on_sent(off, 0, true);
        assert!(s.next_send(10).is_none());
        s.on_lost(0, 0, true);
        let (_, _, fin) = s.next_send(10).unwrap();
        assert!(fin);
    }

    #[test]
    fn acknowledged_data_is_released() {
        let mut s = SendStream::new(1000);
        s.write(&[b'x'; 500]);
        let (off, data, fin) = s.next_send(500).unwrap();
        s.on_sent(off, data.len(), fin);
        s.on_acked(0, 200);
        // The released prefix must not be resent, and the rest still can be
        s.on_lost(200, 300, false);
        let (off, data, _) = s.next_send(1000).unwrap();
        assert_eq!(off, 200);
        assert_eq!(data.len(), 300);
    }

    /// Acknowledging a run that was already dropped must not shift anything
    #[test]
    fn a_late_acknowledgement_of_released_data_is_ignored() {
        let mut s = SendStream::new(1000);
        s.write(b"abcdef");
        s.on_acked(0, 3);
        s.on_acked(0, 3);
        let (off, data, _) = s.next_send(100).unwrap();
        assert_eq!((off, data), (3, &b"def"[..]));
    }
}
