//! QUIC frames (RFC 9000 Section 19)
//!
//! Decoding borrows from the packet buffer rather than copying: a frame's
//! payload is a slice into the datagram that is about to be processed and
//! then dropped, so there is nothing to own. That is the main difference from
//! quinn-proto, which hands out `Bytes` and pays for a refcount per frame.

use anyhow::{Result, bail};

use super::varint::{get_varint, put_varint};

pub const PADDING: u64 = 0x00;
pub const PING: u64 = 0x01;
pub const ACK: u64 = 0x02;
pub const ACK_ECN: u64 = 0x03;
pub const RESET_STREAM: u64 = 0x04;
pub const STOP_SENDING: u64 = 0x05;
pub const CRYPTO: u64 = 0x06;
pub const NEW_TOKEN: u64 = 0x07;
pub const STREAM_BASE: u64 = 0x08;
pub const STREAM_MAX: u64 = 0x0f;
pub const MAX_DATA: u64 = 0x10;
pub const MAX_STREAM_DATA: u64 = 0x11;
pub const MAX_STREAMS_BIDI: u64 = 0x12;
pub const MAX_STREAMS_UNI: u64 = 0x13;
pub const DATA_BLOCKED: u64 = 0x14;
pub const STREAM_DATA_BLOCKED: u64 = 0x15;
pub const STREAMS_BLOCKED_BIDI: u64 = 0x16;
pub const STREAMS_BLOCKED_UNI: u64 = 0x17;
pub const NEW_CONNECTION_ID: u64 = 0x18;
pub const RETIRE_CONNECTION_ID: u64 = 0x19;
pub const PATH_CHALLENGE: u64 = 0x1a;
pub const PATH_RESPONSE: u64 = 0x1b;
pub const CONNECTION_CLOSE_QUIC: u64 = 0x1c;
pub const CONNECTION_CLOSE_APP: u64 = 0x1d;
pub const HANDSHAKE_DONE: u64 = 0x1e;

/// The transport error code that stands in for an application close while
/// the handshake is still on (RFC 9000 Section 20.1)
pub const APPLICATION_ERROR: u64 = 0x0c;

/// The STREAM type bits (RFC 9000 Section 19.8)
const STREAM_FIN: u64 = 0x01;
const STREAM_LEN: u64 = 0x02;
const STREAM_OFF: u64 = 0x04;

#[derive(Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    Padding,
    Ping,
    Ack {
        largest: u64,
        delay: u64,
        /// First ACK Range, then the gap/range pairs, left as written so the
        /// ranges can be walked without allocating
        first_range: u64,
        ranges: &'a [u8],
        range_count: u64,
    },
    ResetStream {
        id: u64,
        error: u64,
        final_size: u64,
    },
    StopSending {
        id: u64,
        error: u64,
    },
    Crypto {
        offset: u64,
        data: &'a [u8],
    },
    NewToken,
    Stream {
        id: u64,
        offset: u64,
        fin: bool,
        data: &'a [u8],
    },
    MaxData(u64),
    MaxStreamData {
        id: u64,
        limit: u64,
    },
    MaxStreams {
        uni: bool,
        limit: u64,
    },
    DataBlocked(u64),
    StreamDataBlocked {
        id: u64,
        limit: u64,
    },
    StreamsBlocked {
        uni: bool,
        limit: u64,
    },
    NewConnectionId {
        seq: u64,
        retire_prior_to: u64,
        cid: &'a [u8],
        reset_token: &'a [u8],
    },
    RetireConnectionId(u64),
    PathChallenge(&'a [u8]),
    PathResponse(&'a [u8]),
    Close {
        /// An application close carries no frame type and its reason is the
        /// application's, not the transport's
        app: bool,
        error: u64,
        reason: &'a [u8],
    },
    HandshakeDone,
}

impl Frame<'_> {
    /// Does this frame make the peer acknowledge the packet carrying it?
    /// (RFC 9000 Section 2 and Section 13.2.1)
    pub fn ack_eliciting(&self) -> bool {
        !matches!(
            self,
            Frame::Padding | Frame::Ack { .. } | Frame::Close { .. }
        )
    }
}

/// Walks the frames in a decrypted packet payload
pub struct Iter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn varint(&mut self) -> Result<u64> {
        // Frame types, small stream ids and ack ranges nearly all fit the
        // one-byte form, and that one is cheap enough to read here.
        if let Some(&b) = self.buf.get(self.pos)
            && b < 0x40
        {
            self.pos += 1;
            return Ok(b as u64);
        }
        let Some((v, n)) = get_varint(&self.buf[self.pos..]) else {
            bail!("truncated varint in frame");
        };
        self.pos += n;
        Ok(v)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() - self.pos < n {
            bail!("frame runs past the end of the packet");
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn next_frame(&mut self) -> Result<Frame<'a>> {
        let kind = self.varint()?;
        Ok(match kind {
            PADDING => {
                // Padding is a run of zero bytes; swallow it in one go rather
                // than emitting a frame per byte, which is what makes a
                // 1200-byte Initial cheap to parse
                while self.pos < self.buf.len() && self.buf[self.pos] == 0 {
                    self.pos += 1;
                }
                Frame::Padding
            }
            PING => Frame::Ping,
            ACK | ACK_ECN => {
                let largest = self.varint()?;
                let delay = self.varint()?;
                let range_count = self.varint()?;
                let first_range = self.varint()?;
                let start = self.pos;
                for _ in 0..range_count {
                    self.varint()?; // gap
                    self.varint()?; // range length
                }
                let ranges = &self.buf[start..self.pos];
                if kind == ACK_ECN {
                    self.varint()?;
                    self.varint()?;
                    self.varint()?;
                }
                Frame::Ack {
                    largest,
                    delay,
                    first_range,
                    ranges,
                    range_count,
                }
            }
            STREAM_BASE..=STREAM_MAX => {
                let id = self.varint()?;
                let offset = if kind & STREAM_OFF != 0 {
                    self.varint()?
                } else {
                    0
                };
                let data = if kind & STREAM_LEN != 0 {
                    let len = self.varint()? as usize;
                    self.take(len)?
                } else {
                    // No length means the frame runs to the end of the packet
                    self.take(self.buf.len() - self.pos)?
                };
                Frame::Stream {
                    id,
                    offset,
                    fin: kind & STREAM_FIN != 0,
                    data,
                }
            }
            MAX_DATA => Frame::MaxData(self.varint()?),
            MAX_STREAMS_BIDI | MAX_STREAMS_UNI => Frame::MaxStreams {
                uni: kind == MAX_STREAMS_UNI,
                limit: self.varint()?,
            },
            _ => self.rare_frame(kind)?,
        })
    }

    /// Parse the frames a steady run does not carry
    ///
    /// The handshake, path validation, connection ids, teardown and the
    /// blocked signals all land here. Kept out of line because the parser is
    /// one of the largest functions on the hot path, and the arms a run never
    /// takes still push the ones it does out of the instruction cache.
    #[cold]
    #[inline(never)]
    fn rare_frame(&mut self, kind: u64) -> Result<Frame<'a>> {
        Ok(match kind {
            RESET_STREAM => Frame::ResetStream {
                id: self.varint()?,
                error: self.varint()?,
                final_size: self.varint()?,
            },
            STOP_SENDING => Frame::StopSending {
                id: self.varint()?,
                error: self.varint()?,
            },
            CRYPTO => {
                let offset = self.varint()?;
                let len = self.varint()? as usize;
                Frame::Crypto {
                    offset,
                    data: self.take(len)?,
                }
            }
            NEW_TOKEN => {
                let len = self.varint()? as usize;
                self.take(len)?;
                Frame::NewToken
            }
            MAX_STREAM_DATA => Frame::MaxStreamData {
                id: self.varint()?,
                limit: self.varint()?,
            },
            DATA_BLOCKED => Frame::DataBlocked(self.varint()?),
            STREAM_DATA_BLOCKED => Frame::StreamDataBlocked {
                id: self.varint()?,
                limit: self.varint()?,
            },
            STREAMS_BLOCKED_BIDI | STREAMS_BLOCKED_UNI => Frame::StreamsBlocked {
                uni: kind == STREAMS_BLOCKED_UNI,
                limit: self.varint()?,
            },
            NEW_CONNECTION_ID => {
                let seq = self.varint()?;
                let retire_prior_to = self.varint()?;
                let len = *self.take(1)?.first().unwrap() as usize;
                if len > super::packet::MAX_CID_LEN {
                    bail!("NEW_CONNECTION_ID with an oversized connection ID");
                }
                Frame::NewConnectionId {
                    seq,
                    retire_prior_to,
                    cid: self.take(len)?,
                    reset_token: self.take(16)?,
                }
            }
            RETIRE_CONNECTION_ID => Frame::RetireConnectionId(self.varint()?),
            PATH_CHALLENGE => Frame::PathChallenge(self.take(8)?),
            PATH_RESPONSE => Frame::PathResponse(self.take(8)?),
            CONNECTION_CLOSE_QUIC | CONNECTION_CLOSE_APP => {
                let error = self.varint()?;
                if kind == CONNECTION_CLOSE_QUIC {
                    self.varint()?; // the frame type that caused it
                }
                let len = self.varint()? as usize;
                Frame::Close {
                    app: kind == CONNECTION_CLOSE_APP,
                    error,
                    reason: self.take(len)?,
                }
            }
            HANDSHAKE_DONE => Frame::HandshakeDone,
            other => bail!("unknown frame type {other:#x}"),
        })
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = Result<Frame<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        match self.next_frame() {
            Ok(f) => Some(Ok(f)),
            Err(e) => {
                // Stop after an error rather than trying to resynchronise:
                // frames are not self-delimiting, so the rest is meaningless
                self.pos = self.buf.len();
                Some(Err(e))
            }
        }
    }
}

/// The packet number ranges an ACK frame acknowledges, largest first
pub struct AckRanges<'a> {
    largest: u64,
    first_range: u64,
    ranges: &'a [u8],
    pos: usize,
    done_first: bool,
    next_largest: u64,
}

impl<'a> AckRanges<'a> {
    pub fn new(largest: u64, first_range: u64, ranges: &'a [u8]) -> Self {
        Self {
            largest,
            first_range,
            ranges,
            pos: 0,
            done_first: false,
            next_largest: largest,
        }
    }
}

impl Iterator for AckRanges<'_> {
    /// An inclusive range of acknowledged packet numbers
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        if !self.done_first {
            self.done_first = true;
            let smallest = self.largest.checked_sub(self.first_range)?;
            self.next_largest = smallest;
            return Some((smallest, self.largest));
        }
        if self.pos >= self.ranges.len() {
            return None;
        }
        let (gap, n) = get_varint(&self.ranges[self.pos..])?;
        self.pos += n;
        let (len, n) = get_varint(&self.ranges[self.pos..])?;
        self.pos += n;
        // RFC 9000 Section 19.3.1: the next largest is two below the previous
        // smallest, less the gap
        let largest = self.next_largest.checked_sub(gap + 2)?;
        let smallest = largest.checked_sub(len)?;
        self.next_largest = smallest;
        Some((smallest, largest))
    }
}

// -------------------------------------------------------------------------
// Encoding
// -------------------------------------------------------------------------

pub fn put_ping(out: &mut Vec<u8>) {
    out.push(PING as u8);
}

pub fn put_crypto(out: &mut Vec<u8>, offset: u64, data: &[u8]) {
    put_varint(out, CRYPTO);
    put_varint(out, offset);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// A STREAM frame, always with an explicit length so more frames can follow
pub fn put_stream(out: &mut Vec<u8>, id: u64, offset: u64, fin: bool, data: &[u8]) {
    let mut kind = STREAM_BASE | STREAM_LEN;
    if offset != 0 {
        kind |= STREAM_OFF;
    }
    if fin {
        kind |= STREAM_FIN;
    }
    put_varint(out, kind);
    put_varint(out, id);
    if offset != 0 {
        put_varint(out, offset);
    }
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

pub fn put_max_data(out: &mut Vec<u8>, limit: u64) {
    put_varint(out, MAX_DATA);
    put_varint(out, limit);
}

/// Only the decoder side of this is used in anger: shb reads MAX_STREAM_DATA
/// from the peer but never sends one, since it grants stream credit once
/// through the transport parameters and never revises it. The encoder is here
/// so the decoder can be round-tripped.
#[cfg(test)]
pub fn put_max_stream_data(out: &mut Vec<u8>, id: u64, limit: u64) {
    put_varint(out, MAX_STREAM_DATA);
    put_varint(out, id);
    put_varint(out, limit);
}

/// Likewise: shb reads MAX_STREAMS and never sends one, because a client
/// accepts no streams the peer opens beyond the three HTTP/3 requires
#[cfg(test)]
pub fn put_max_streams(out: &mut Vec<u8>, uni: bool, limit: u64) {
    put_varint(
        out,
        if uni {
            MAX_STREAMS_UNI
        } else {
            MAX_STREAMS_BIDI
        },
    );
    put_varint(out, limit);
}

pub fn put_reset_stream(out: &mut Vec<u8>, id: u64, error: u64, final_size: u64) {
    put_varint(out, RESET_STREAM);
    put_varint(out, id);
    put_varint(out, error);
    put_varint(out, final_size);
}

pub fn put_retire_connection_id(out: &mut Vec<u8>, seq: u64) {
    put_varint(out, RETIRE_CONNECTION_ID);
    put_varint(out, seq);
}

pub fn put_path_response(out: &mut Vec<u8>, data: &[u8]) {
    put_varint(out, PATH_RESPONSE);
    out.extend_from_slice(data);
}

/// An application close, which only a 0-RTT or 1-RTT packet may carry
/// (RFC 9000 Section 12.4)
pub fn put_close(out: &mut Vec<u8>, error: u64, reason: &[u8]) {
    put_varint(out, CONNECTION_CLOSE_APP);
    put_varint(out, error);
    put_varint(out, reason.len() as u64);
    out.extend_from_slice(reason);
}

/// A transport close. shb never closes over a frame the peer sent, so the
/// frame type is always "none"; what it does need this for is closing while
/// the handshake is still on, when RFC 9000 Section 10.2.3 says an
/// application close has to be sent as APPLICATION_ERROR with no reason.
pub fn put_transport_close(out: &mut Vec<u8>, error: u64) {
    put_varint(out, CONNECTION_CLOSE_QUIC);
    put_varint(out, error);
    put_varint(out, PADDING);
    put_varint(out, 0);
}

/// An ACK covering `ranges`, which must be sorted largest first and not touch
pub fn put_ack(out: &mut Vec<u8>, ranges: &[(u64, u64)], delay: u64) {
    let (smallest, largest) = ranges[0];
    put_varint(out, ACK);
    put_varint(out, largest);
    put_varint(out, delay);
    put_varint(out, ranges.len() as u64 - 1);
    put_varint(out, largest - smallest);
    let mut prev_smallest = smallest;
    for &(smallest, largest) in &ranges[1..] {
        put_varint(out, prev_smallest - largest - 2);
        put_varint(out, largest - smallest);
        prev_smallest = smallest;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(buf: &[u8]) -> Vec<Frame<'_>> {
        Iter::new(buf).map(|f| f.unwrap()).collect()
    }

    #[test]
    fn stream_frames_round_trip_in_every_shape() {
        for &offset in &[0u64, 1, 0x4000] {
            for &fin in &[false, true] {
                let mut out = Vec::new();
                put_stream(&mut out, 4, offset, fin, b"hello");
                assert_eq!(
                    frames(&out),
                    vec![Frame::Stream {
                        id: 4,
                        offset,
                        fin,
                        data: b"hello",
                    }],
                    "offset {offset}, fin {fin}"
                );
            }
        }
    }

    /// A STREAM frame without the LEN bit runs to the end of the packet
    #[test]
    fn a_stream_frame_without_a_length_takes_the_rest() {
        // type 0x08 (no OFF, no LEN, no FIN), stream 0, then the body
        let buf = [0x08, 0x00, b'a', b'b', b'c'];
        assert_eq!(
            frames(&buf),
            vec![Frame::Stream {
                id: 0,
                offset: 0,
                fin: false,
                data: b"abc",
            }]
        );
    }

    #[test]
    fn crypto_frames_round_trip() {
        let mut out = Vec::new();
        put_crypto(&mut out, 0x1234, b"handshake");
        assert_eq!(
            frames(&out),
            vec![Frame::Crypto {
                offset: 0x1234,
                data: b"handshake",
            }]
        );
    }

    /// Padding is a run of zeroes and has to be swallowed in one step: a
    /// 1200-byte Initial is mostly padding, and a frame per byte would make
    /// parsing it cost more than everything else in the packet
    #[test]
    fn a_run_of_padding_is_one_frame() {
        let mut buf = vec![0u8; 1000];
        buf.push(PING as u8);
        let f = frames(&buf);
        assert_eq!(f, vec![Frame::Padding, Frame::Ping]);
    }

    /// RFC 9000 Section 19.3.1, worked by hand: largest 20, first range 2
    /// covers 18..=20, then gap 1 and length 3 covers 12..=15
    #[test]
    fn ack_ranges_walk_backwards_from_the_largest() {
        let mut out = Vec::new();
        put_ack(&mut out, &[(18, 20), (12, 15)], 7);
        let f = frames(&out);
        let Frame::Ack {
            largest,
            delay,
            first_range,
            ranges,
            range_count,
        } = f[0]
        else {
            panic!("expected an ACK, got {:?}", f[0]);
        };
        assert_eq!((largest, delay, first_range, range_count), (20, 7, 2, 1));
        let got: Vec<_> = AckRanges::new(largest, first_range, ranges).collect();
        assert_eq!(got, vec![(18, 20), (12, 15)]);
    }

    #[test]
    fn a_single_range_ack_round_trips() {
        let mut out = Vec::new();
        put_ack(&mut out, &[(0, 0)], 0);
        let f = frames(&out);
        let Frame::Ack {
            largest,
            first_range,
            ranges,
            ..
        } = f[0]
        else {
            panic!("expected an ACK");
        };
        let got: Vec<_> = AckRanges::new(largest, first_range, ranges).collect();
        assert_eq!(got, vec![(0, 0)]);
    }

    /// An ACK with ECN counts has three more varints the decoder has to step
    /// over, or every frame after it is garbage
    #[test]
    fn ecn_counts_are_stepped_over() {
        let mut buf = vec![ACK_ECN as u8];
        put_varint(&mut buf, 5); // largest
        put_varint(&mut buf, 0); // delay
        put_varint(&mut buf, 0); // range count
        put_varint(&mut buf, 0); // first range
        put_varint(&mut buf, 1); // ect0
        put_varint(&mut buf, 2); // ect1
        put_varint(&mut buf, 3); // ce
        buf.push(PING as u8);
        assert_eq!(frames(&buf).len(), 2, "the PING after the ACK must survive");
        assert_eq!(frames(&buf)[1], Frame::Ping);
    }

    #[test]
    fn connection_close_carries_its_reason() {
        let mut out = Vec::new();
        put_close(&mut out, 0x100, b"done");
        assert_eq!(
            frames(&out),
            vec![Frame::Close {
                app: true,
                error: 0x100,
                reason: b"done",
            }]
        );
    }

    #[test]
    fn a_transport_close_round_trips_with_no_reason() {
        let mut out = Vec::new();
        put_transport_close(&mut out, APPLICATION_ERROR);
        out.push(PING as u8);
        let f = frames(&out);
        assert_eq!(
            f[0],
            Frame::Close {
                app: false,
                error: APPLICATION_ERROR,
                reason: b"",
            }
        );
        assert_eq!(f[1], Frame::Ping, "the frame type field was written");
    }

    /// The transport-level close has an extra field the application one does
    /// not, and mixing them up desynchronises the rest of the packet
    #[test]
    fn a_transport_close_has_one_more_field() {
        let mut buf = vec![CONNECTION_CLOSE_QUIC as u8];
        put_varint(&mut buf, 0x0a); // error
        put_varint(&mut buf, 0x06); // the frame type at fault
        put_varint(&mut buf, 2); // reason length
        buf.extend_from_slice(b"no");
        buf.push(PING as u8);
        let f = frames(&buf);
        assert_eq!(
            f[0],
            Frame::Close {
                app: false,
                error: 0x0a,
                reason: b"no",
            }
        );
        assert_eq!(f[1], Frame::Ping);
    }

    #[test]
    fn new_connection_id_is_parsed_whole() {
        let mut buf = vec![NEW_CONNECTION_ID as u8];
        put_varint(&mut buf, 3); // sequence
        put_varint(&mut buf, 1); // retire prior to
        buf.push(4); // CID length
        buf.extend_from_slice(&[9, 9, 9, 9]);
        buf.extend_from_slice(&[7u8; 16]); // stateless reset token
        buf.push(PING as u8);
        let f = frames(&buf);
        assert_eq!(
            f[0],
            Frame::NewConnectionId {
                seq: 3,
                retire_prior_to: 1,
                cid: &[9, 9, 9, 9],
                reset_token: &[7u8; 16],
            }
        );
        assert_eq!(f[1], Frame::Ping, "the frame after it must still parse");
    }

    #[test]
    fn reset_stream_round_trips() {
        let mut out = Vec::new();
        put_reset_stream(&mut out, 8, 0x10c, 1234);
        assert_eq!(
            frames(&out),
            vec![Frame::ResetStream {
                id: 8,
                error: 0x10c,
                final_size: 1234,
            }]
        );
    }

    #[test]
    fn retire_connection_id_round_trips() {
        let mut out = Vec::new();
        put_retire_connection_id(&mut out, 3);
        assert_eq!(frames(&out), vec![Frame::RetireConnectionId(3)]);
    }

    #[test]
    fn oversized_connection_ids_are_rejected() {
        let mut buf = vec![NEW_CONNECTION_ID as u8];
        put_varint(&mut buf, 0);
        put_varint(&mut buf, 0);
        buf.push(21); // one past what RFC 9000 allows
        buf.extend_from_slice(&[0u8; 21 + 16]);
        assert!(Iter::new(&buf).next().unwrap().is_err());
    }

    #[test]
    fn truncated_frames_are_rejected() {
        // A CRYPTO frame claiming more data than the packet holds
        let mut buf = vec![CRYPTO as u8];
        put_varint(&mut buf, 0);
        put_varint(&mut buf, 100);
        buf.extend_from_slice(b"short");
        assert!(Iter::new(&buf).next().unwrap().is_err());
    }

    #[test]
    fn an_unknown_frame_type_is_an_error() {
        // 0x3f is not assigned; a peer sending one is doing something we
        // cannot safely guess at
        assert!(Iter::new(&[0x3f]).next().unwrap().is_err());
    }

    #[test]
    fn parsing_stops_after_an_error() {
        let mut buf = vec![0x3f];
        buf.push(PING as u8);
        let all: Vec<_> = Iter::new(&buf).collect();
        assert_eq!(all.len(), 1, "frames are not self-delimiting");
    }

    /// RFC 9000 Section 13.2.1: everything but ACK, PADDING and
    /// CONNECTION_CLOSE makes the peer send an acknowledgement
    #[test]
    fn ack_eliciting_is_classified_by_the_spec() {
        assert!(!Frame::Padding.ack_eliciting());
        assert!(
            !Frame::Ack {
                largest: 0,
                delay: 0,
                first_range: 0,
                ranges: &[],
                range_count: 0,
            }
            .ack_eliciting()
        );
        assert!(
            !Frame::Close {
                app: true,
                error: 0,
                reason: &[],
            }
            .ack_eliciting()
        );
        assert!(Frame::Ping.ack_eliciting());
        assert!(Frame::HandshakeDone.ack_eliciting());
        assert!(
            Frame::Stream {
                id: 0,
                offset: 0,
                fin: false,
                data: &[],
            }
            .ack_eliciting()
        );
    }

    #[test]
    fn flow_control_frames_round_trip() {
        let mut out = Vec::new();
        put_max_data(&mut out, 1 << 30);
        put_max_stream_data(&mut out, 4, 1 << 20);
        put_max_streams(&mut out, true, 100);
        put_max_streams(&mut out, false, 200);
        assert_eq!(
            frames(&out),
            vec![
                Frame::MaxData(1 << 30),
                Frame::MaxStreamData {
                    id: 4,
                    limit: 1 << 20
                },
                Frame::MaxStreams {
                    uni: true,
                    limit: 100
                },
                Frame::MaxStreams {
                    uni: false,
                    limit: 200
                },
            ]
        );
    }

    #[test]
    fn path_challenge_is_answered_with_the_same_bytes() {
        let mut buf = vec![PATH_CHALLENGE as u8];
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let f = frames(&buf);
        assert_eq!(f[0], Frame::PathChallenge(&[1, 2, 3, 4, 5, 6, 7, 8]));
        let mut out = Vec::new();
        put_path_response(&mut out, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            frames(&out),
            vec![Frame::PathResponse(&[1, 2, 3, 4, 5, 6, 7, 8])]
        );
    }

    /// Every frame the peer can send has to at least parse, or one of them
    /// arriving mid-connection takes the whole thing down
    #[test]
    fn the_frames_a_server_may_send_all_parse() {
        let mut buf = Vec::new();
        buf.push(HANDSHAKE_DONE as u8);
        put_varint(&mut buf, NEW_TOKEN);
        put_varint(&mut buf, 3);
        buf.extend_from_slice(b"tok");
        put_varint(&mut buf, RESET_STREAM);
        put_varint(&mut buf, 4);
        put_varint(&mut buf, 1);
        put_varint(&mut buf, 9);
        put_varint(&mut buf, STOP_SENDING);
        put_varint(&mut buf, 4);
        put_varint(&mut buf, 2);
        put_varint(&mut buf, RETIRE_CONNECTION_ID);
        put_varint(&mut buf, 1);
        put_varint(&mut buf, DATA_BLOCKED);
        put_varint(&mut buf, 10);
        put_varint(&mut buf, STREAM_DATA_BLOCKED);
        put_varint(&mut buf, 4);
        put_varint(&mut buf, 10);
        put_varint(&mut buf, STREAMS_BLOCKED_UNI);
        put_varint(&mut buf, 3);
        let f = frames(&buf);
        assert_eq!(f.len(), 8, "got {f:?}");
        assert_eq!(f[0], Frame::HandshakeDone);
        assert_eq!(f[1], Frame::NewToken);
    }
}
