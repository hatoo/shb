//! The QUIC client connection
//!
//! Ties the pieces together: rustls drives the handshake and owns the keys,
//! this decides what goes in each packet and what to do with what comes back.
//!
//! Two choices differ from a general implementation and are the point of
//! writing it. Packets are built straight into the caller's datagram buffer,
//! so a datagram costs no allocation. And streams live in a ring indexed by
//! stream number rather than a hash map, because a client opens them in order
//! and finishes them in nearly the same order.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rustls::quic::{ClientConnection, DirectionalKeys, KeyChange, Keys};

use super::ack::AckState;
use super::crypto::initial_keys;
use super::frame::{self, AckRanges, Frame};
use super::header::{self, Incoming, LongHeader};
use super::packet::{
    ConnectionId, Space, decode_packet_number, encode_packet_number, protect_header,
    unprotect_header,
};
use super::recovery::{Congestion, Rtt, SentFrame, SentPacket, SentPackets, pto_deadline};
use super::stream::{
    Dir, RecvStream, SendStream, client_stream_id, is_client_initiated, stream_dir,
};
use super::transport::{LocalParams, Params};

/// The smallest datagram a client may send while handshaking
/// (RFC 9000 Section 14.1)
const MIN_INITIAL_DATAGRAM: usize = 1200;
/// What shb sends without probing for more. Anything larger risks being
/// dropped by a path that cannot carry it, and a benchmark client gains more
/// from certainty than from the last few percent of payload.
pub const MAX_DATAGRAM: usize = 1200;
/// The AEAD tag every packet carries
const TAG_LEN: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// The handshake finished and 1-RTT keys are in use
    Connected,
    /// A stream we opened has data to read
    Readable(u64),
    /// The peer opened a unidirectional stream
    Opened(u64),
    /// A stream ended, whether by FIN or reset
    Finished { id: u64, reset: bool },
    /// The connection is over
    Lost(String),
}

/// One packet number space's keys, numbers and record of what is in flight
#[derive(Default)]
struct SpaceState {
    keys: Option<Keys>,
    next_packet_number: u64,
    largest_received: Option<u64>,
    ack: AckState,
    sent: SentPackets,
    /// Handshake bytes the peer has not acknowledged, starting at
    /// `crypto_offset`. Held rather than dropped when sent: until an
    /// acknowledgement arrives there is no other copy, and a probe timeout
    /// has to be able to send them again.
    crypto_out: Vec<u8>,
    crypto_offset: u64,
    /// How much of `crypto_out` has been put in a packet at least once
    crypto_sent: usize,
    /// Incoming handshake bytes, reassembled. rustls needs the handshake in
    /// order, and a certificate chain spans several packets, so on a real
    /// network the pieces do arrive out of order.
    crypto_in: RecvStream,
}

pub struct Connection {
    tls: ClientConnection,
    spaces: [SpaceState; 3],
    /// The 1-RTT keys, which arrive after the handshake spaces are done
    one_rtt_local: Option<DirectionalKeys>,
    one_rtt_remote: Option<DirectionalKeys>,

    local_cid: ConnectionId,
    /// Where to address packets: the peer's chosen connection ID
    peer_cid: ConnectionId,

    params: Params,
    handshake_done: bool,
    connected: bool,
    closed: Option<String>,
    /// A CONNECTION_CLOSE we still owe the peer
    close_pending: Option<(u64, Vec<u8>)>,

    /// Connection-level flow control
    max_data_local: u64,
    data_received: u64,
    max_data_peer: u64,
    data_sent: u64,

    max_streams_bidi: u64,
    next_bidi: u64,
    next_uni: u64,

    /// Client-initiated bidirectional streams, indexed by number from `base`
    streams: VecDeque<Option<StreamPair>>,
    base_stream: u64,
    /// Peer-opened unidirectional streams, few and long-lived
    peer_uni: Vec<(u64, RecvStream)>,
    /// Our own unidirectional streams
    local_uni: Vec<(u64, SendStream)>,

    rtt: Rtt,
    congestion: Congestion,
    pto_count: u32,
    /// Probe packets owed to the current timeout, counted down as they are
    /// sent. Without this a probe goes out on every pass rather than once.
    pto_probes: u32,
    loss_deadline: Option<Instant>,
    idle_deadline: Option<Instant>,
    events: VecDeque<Event>,
    /// Set when something needs sending that is not stream data
    needs_send: bool,
    /// A PATH_CHALLENGE the peer sent that we owe an answer to
    path_response: Option<[u8; 8]>,
}

struct StreamPair {
    send: SendStream,
    recv: RecvStream,
    /// Reported to the worker already
    finished: bool,
}

impl Connection {
    pub fn connect(
        config: Arc<rustls::ClientConfig>,
        server_name: &str,
        local_params: LocalParamsInput,
    ) -> Result<Self> {
        let local_cid = ConnectionId::random();
        // The first destination connection ID doubles as the secret both
        // sides derive their initial keys from (RFC 9001 Section 5.2)
        let initial_dcid = ConnectionId::random();
        let params = LocalParams {
            initial_max_data: local_params.initial_max_data,
            initial_max_stream_data_bidi_local: local_params.initial_max_stream_data,
            initial_max_stream_data_uni: local_params.initial_max_stream_data,
            initial_max_streams_uni: local_params.initial_max_streams_uni,
            max_idle_timeout_ms: local_params.max_idle_timeout_ms,
            max_udp_payload_size: MAX_DATAGRAM as u64,
            source_connection_id: local_cid,
        };
        let name = server_name
            .to_string()
            .try_into()
            .context("the server name is not a valid DNS name")?;
        let tls = ClientConnection::new(config, rustls::quic::Version::V1, name, params.encode())
            .context("starting the TLS handshake")?;

        let mut spaces: [SpaceState; 3] = Default::default();
        spaces[Space::Initial as usize].keys =
            Some(initial_keys(initial_dcid.as_slice(), rustls::Side::Client)?);

        Ok(Self {
            tls,
            spaces,
            one_rtt_local: None,
            one_rtt_remote: None,
            local_cid,
            peer_cid: initial_dcid,
            params: Params::default(),
            handshake_done: false,
            connected: false,
            closed: None,
            close_pending: None,
            max_data_local: local_params.initial_max_data,
            data_received: 0,
            max_data_peer: 0,
            data_sent: 0,
            max_streams_bidi: 0,
            next_bidi: 0,
            next_uni: 0,
            streams: VecDeque::new(),
            base_stream: 0,
            peer_uni: Vec::new(),
            local_uni: Vec::new(),
            rtt: Rtt::default(),
            congestion: Congestion::default(),
            pto_count: 0,
            pto_probes: 0,
            loss_deadline: None,
            idle_deadline: None,
            events: VecDeque::new(),
            needs_send: true,
            path_response: None,
        })
    }

    /// Drop everything belonging to a packet number space
    ///
    /// RFC 9002 Section 6.2 requires the loss detection state to go with the
    /// keys. Keeping it means the probe timer keeps firing for packets that
    /// can never be acknowledged, because there are no longer keys to send in
    /// that space - the count climbs forever and every expiry sends another
    /// probe in whatever space still can, which floods the peer.
    fn discard_space(&mut self, space: Space) {
        let s = &mut self.spaces[space as usize];
        s.keys = None;
        s.ack = AckState::default();
        s.sent = SentPackets::default();
        s.crypto_out.clear();
        s.crypto_sent = 0;
        s.crypto_in = RecvStream::default();
        self.pto_count = 0;
        self.pto_probes = 0;
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// A one-line summary for working out why a connection is not moving
    pub fn debug_state(&self) -> String {
        format!(
            "connected={} h3_streams={} pto={} closed={:?} initial_keys={} hs_keys={} \
             crypto_out=[{},{},{}] sent=[{},{},{}] max_bidi={} next_bidi={}",
            self.connected,
            self.streams.len(),
            self.pto_count,
            self.closed.as_deref().unwrap_or("-"),
            self.spaces[0].keys.is_some(),
            self.spaces[1].keys.is_some(),
            self.spaces[0].crypto_out.len(),
            self.spaces[1].crypto_out.len(),
            self.spaces[2].crypto_out.len(),
            self.spaces[0].sent.bytes_in_flight(),
            self.spaces[1].sent.bytes_in_flight(),
            self.spaces[2].sent.bytes_in_flight(),
            self.max_streams_bidi,
            self.next_bidi,
        )
    }
}

/// What the caller wants from its side of the connection
pub struct LocalParamsInput {
    pub initial_max_data: u64,
    pub initial_max_stream_data: u64,
    pub initial_max_streams_uni: u64,
    pub max_idle_timeout_ms: u64,
}

// -------------------------------------------------------------------------
// Sending
// -------------------------------------------------------------------------

impl Connection {
    /// Move whatever rustls has produced into the right space's crypto buffer
    fn pump_tls(&mut self) -> Result<()> {
        loop {
            let space = if self.spaces[Space::Handshake as usize].keys.is_some() {
                Space::Handshake
            } else {
                Space::Initial
            };
            let before = self.spaces[space as usize].crypto_out.len();
            let change = self
                .tls
                .write_hs(&mut self.spaces[space as usize].crypto_out);
            let produced = self.spaces[space as usize].crypto_out.len() != before;
            match change {
                Some(KeyChange::Handshake { keys }) => {
                    self.spaces[Space::Handshake as usize].keys = Some(keys);
                    // RFC 9001 Section 4.9.1: a client drops its Initial keys
                    // as soon as it has Handshake ones. Keeping them means
                    // every datagram carrying an Initial is padded to 1200
                    // bytes, which leaves no room for anything else.
                    self.discard_space(Space::Initial);
                }
                Some(KeyChange::OneRtt { keys, next }) => {
                    self.one_rtt_local = Some(keys.local);
                    self.one_rtt_remote = Some(keys.remote);
                    let _ = next;
                    self.connected = true;
                    self.events.push_back(Event::Connected);
                }
                None if !produced => return Ok(()),
                None => {}
            }
            self.needs_send = true;
        }
    }

    /// The keys to encrypt with in a space, if we have them
    fn local_keys(&self, space: Space) -> Option<&DirectionalKeys> {
        match space {
            Space::Data => self.one_rtt_local.as_ref(),
            other => self.spaces[other as usize].keys.as_ref().map(|k| &k.local),
        }
    }

    fn remote_keys(&self, space: Space) -> Option<&DirectionalKeys> {
        match space {
            Space::Data => self.one_rtt_remote.as_ref(),
            other => self.spaces[other as usize].keys.as_ref().map(|k| &k.remote),
        }
    }

    /// Build one datagram's worth of packets into `out`
    ///
    /// Returns how many bytes were written. Packets from different spaces are
    /// coalesced into the same datagram, which is what keeps a handshake to
    /// two round trips.
    /// `pad_to` makes the datagram exactly that many bytes, which is what a
    /// GSO batch needs: the kernel splits one send into equal segments, and
    /// only the last may be shorter.
    pub fn poll_transmit(
        &mut self,
        now: Instant,
        out: &mut Vec<u8>,
        pad_to: Option<usize>,
    ) -> Result<usize> {
        if self.closed.is_some() && self.close_pending.is_none() {
            return Ok(0);
        }
        self.pump_tls()?;
        let start = out.len();
        let in_flight: usize = Space::ALL
            .iter()
            .map(|s| self.spaces[*s as usize].sent.bytes_in_flight())
            .sum();
        let congested = !self.congestion.can_send(in_flight);

        for space in Space::ALL {
            if out.len() - start >= MAX_DATAGRAM {
                break;
            }
            if self.local_keys(space).is_none() {
                continue;
            }
            // RFC 9000 Section 14.1: a datagram carrying an Initial has to
            // be at least 1200 bytes, so a server knows the path carries that
            // much before it commits memory. The padding is PADDING frames
            // inside the packet, covered by the length field and the AEAD -
            // zeroes appended after the tag would read to the peer as a
            // second, broken packet, and it drops the datagram.
            let pad = if space == Space::Initial && !self.handshake_done {
                Some(MIN_INITIAL_DATAGRAM)
            } else {
                pad_to
            };
            let wrote = self.write_packet(space, now, out, start, congested, pad)?;
            if wrote && pad.is_some() {
                // The datagram is full of padding now, so nothing can be
                // coalesced behind it; the next space goes in its own
                break;
            }
        }

        Ok(out.len() - start)
    }

    /// Append one packet for `space`, if there is anything to put in it
    ///
    /// `pad_to` makes the finished datagram exactly that long, with PADDING
    /// frames inside this packet's payload.
    fn write_packet(
        &mut self,
        space: Space,
        now: Instant,
        out: &mut Vec<u8>,
        datagram_start: usize,
        congested: bool,
        pad_to: Option<usize>,
    ) -> Result<bool> {
        let room = MAX_DATAGRAM.saturating_sub(out.len() - datagram_start);
        // Header, packet number and tag all have to fit with something left over
        if room < 64 {
            return Ok(false);
        }

        let pn = self.spaces[space as usize].next_packet_number;
        let (truncated_pn, pn_len) =
            encode_packet_number(pn, self.spaces[space as usize].sent.largest_acked);

        let header_start = out.len();
        let long = match space {
            Space::Data => None,
            _ => Some(LongHeader {
                space,
                dcid: self.peer_cid,
                scid: self.local_cid,
                token: Vec::new(),
            }),
        };
        match &long {
            Some(h) => h.put(out, pn_len, 0),
            None => header::put_short_header(out, &self.peer_cid, pn_len, false),
        }
        let length_field = long.as_ref().map(|_| out.len() - 4);
        let pn_offset = out.len();
        out.extend_from_slice(&truncated_pn.to_be_bytes()[8 - pn_len..]);

        let payload_start = out.len();
        // A padded datagram has to come out exactly the requested size, so the
        // payload is capped there rather than at the usual limit: topping it
        // up afterwards cannot help if the frames already overshot, and they
        // do - a wider packet number or stream offset moves the total by a
        // byte or two, which is enough to break a GSO batch.
        let limit = pad_to.unwrap_or(MAX_DATAGRAM);
        let budget = limit.saturating_sub(out.len() - datagram_start + TAG_LEN);
        let mut frames = Vec::new();
        let ack_eliciting = self.fill_payload(space, now, out, budget, &mut frames, congested)?;

        if out.len() == payload_start {
            // Nothing to say in this space
            out.truncate(header_start);
            return Ok(false);
        }

        // RFC 9001 Section 5.4.2: the sample starts four bytes past the packet
        // number, so the payload has to reach that far
        let min_payload = 4 + 16 - pn_len;
        if out.len() - payload_start < min_payload {
            out.resize(payload_start + min_payload, 0);
        }
        // PADDING is a run of zero bytes, so filling to the target length is
        // the whole of it
        if let Some(target) = pad_to {
            let want = (datagram_start + target).saturating_sub(TAG_LEN);
            if out.len() < want {
                out.resize(want, 0);
            }
        }

        // The length field is part of the additional authenticated data, so
        // it has to hold its final value before anything is encrypted: the
        // peer computes the AAD from the header it received, and a length of
        // zero here would make every packet fail to decrypt.
        if let Some(at) = length_field {
            let length = pn_len + (out.len() - payload_start) + TAG_LEN;
            header::set_varint_fixed4(out, at, length as u64);
        }

        // The header is the additional authenticated data and the payload is
        // encrypted in place, so the two halves have to be split apart first;
        // payload_start is exactly where the packet number ends
        let (head, body) = out.split_at_mut(payload_start);
        let tag = self
            .local_keys(space)
            .expect("checked by the caller")
            .packet
            .encrypt_in_place(pn, &head[header_start..], body)
            .map_err(|e| anyhow::anyhow!("packet encryption: {e}"))?;
        out.extend_from_slice(tag.as_ref());
        let hp = self.local_keys(space).expect("checked by the caller");
        protect_header(
            hp.header.as_ref(),
            &mut out[header_start..],
            pn_offset - header_start,
            pn_len,
        )?;

        let size = out.len() - header_start;
        let s = &mut self.spaces[space as usize];
        s.next_packet_number += 1;
        s.sent.push(SentPacket {
            number: pn,
            time_sent: now,
            size,
            ack_eliciting,
            frames,
        });
        Ok(true)
    }
}

impl Connection {
    /// Put as much as will fit into one packet's payload
    ///
    /// Order matters: acknowledgements first because they are what frees the
    /// peer's window, then handshake data, then the connection-level
    /// housekeeping, and stream data with whatever room is left.
    fn fill_payload(
        &mut self,
        space: Space,
        now: Instant,
        out: &mut Vec<u8>,
        budget: usize,
        frames: &mut Vec<SentFrame>,
        congested: bool,
    ) -> Result<bool> {
        let start = out.len();
        let mut ack_eliciting = false;
        let room = |out: &Vec<u8>| budget.saturating_sub(out.len() - start);

        // Only when something arrived that the peer wants acknowledged
        // (RFC 9000 Section 13.2.1). Sending the same ranges again on every
        // pass would fill the link with ACK-only packets and, while the
        // handshake keys are still around, pad each one to 1200 bytes.
        if self.spaces[space as usize].ack.ack_eliciting_pending && room(out) > 32 {
            let delay = self.spaces[space as usize]
                .ack
                .delay(now, self.params.ack_delay_exponent);
            let ranges = self.spaces[space as usize].ack.ranges().to_vec();
            frame::put_ack(out, &ranges, delay);
            self.spaces[space as usize].ack.take_pending();
        }

        if let Some(data) = self.path_response.take()
            && room(out) > 9
        {
            frame::put_path_response(out, &data);
            ack_eliciting = true;
        }

        if let Some((code, reason)) = self.close_pending.take() {
            frame::put_close(out, code, &reason);
            return Ok(false);
        }

        // Handshake bytes that have not been sent yet, or that a probe
        // timeout has put back at the start of the buffer
        loop {
            let s = &self.spaces[space as usize];
            let avail = room(out);
            if avail < 8 || s.crypto_sent >= s.crypto_out.len() {
                break;
            }
            let len = (s.crypto_out.len() - s.crypto_sent).min(avail - 8);
            if len == 0 {
                break;
            }
            let offset = s.crypto_offset + s.crypto_sent as u64;
            let data: Vec<u8> = s.crypto_out[s.crypto_sent..s.crypto_sent + len].to_vec();
            frame::put_crypto(out, offset, &data);
            frames.push(SentFrame::Crypto { offset, len });
            ack_eliciting = true;
            self.spaces[space as usize].crypto_sent += len;
        }

        if space == Space::Data {
            ack_eliciting |= self.fill_data_payload(out, budget, start, frames, congested)?;
        }

        // A probe has to make the peer answer, and an ACK alone will not.
        // It goes into an otherwise empty packet on purpose: the case a probe
        // exists for is having nothing else to send while waiting on
        // something lost. It is also counted down rather than driven by
        // pto_count, which stays raised until something arrives - sending one
        // per pass instead of one per timeout floods the peer, and a server
        // that cannot keep up with the flood never answers, which keeps the
        // timeout raised.
        if self.pto_probes > 0 && room(out) > 1 {
            self.pto_probes -= 1;
            if !ack_eliciting {
                frame::put_ping(out);
                frames.push(SentFrame::Ping);
                ack_eliciting = true;
            }
        }
        Ok(ack_eliciting)
    }

    /// The 1-RTT half: flow control, then stream data
    fn fill_data_payload(
        &mut self,
        out: &mut Vec<u8>,
        budget: usize,
        start: usize,
        frames: &mut Vec<SentFrame>,
        congested: bool,
    ) -> Result<bool> {
        let mut ack_eliciting = false;
        let room = |out: &Vec<u8>| budget.saturating_sub(out.len() - start);

        // Hand the peer more connection-level credit once it has used enough
        // of what it has that another window would not arrive in time
        if self.data_received + self.max_data_local / 2 > self.max_data_local && room(out) > 16 {
            self.max_data_local += self.data_received;
            frame::put_max_data(out, self.max_data_local);
            ack_eliciting = true;
        }

        if congested {
            return Ok(ack_eliciting);
        }

        // Our own unidirectional streams: the control and QPACK streams, which
        // are written once and never again
        for i in 0..self.local_uni.len() {
            let avail = room(out);
            if avail < 16 {
                break;
            }
            let (id, ref mut send) = self.local_uni[i];
            if let Some((offset, data, fin)) = send.next_send(avail - 16) {
                let (len, data) = (data.len(), data.to_vec());
                frame::put_stream(out, id, offset, fin, &data);
                send.on_sent(offset, len, fin);
                frames.push(SentFrame::Stream {
                    id,
                    offset,
                    len,
                    fin,
                });
                ack_eliciting = true;
            }
        }

        for i in 0..self.streams.len() {
            let avail = room(out);
            if avail < 16 {
                break;
            }
            let id = client_stream_id(Dir::Bi, self.base_stream + i as u64);
            let Some(pair) = self.streams[i].as_mut() else {
                continue;
            };
            let cap = self.max_data_peer.saturating_sub(self.data_sent) as usize;
            let avail = avail.min(cap + 16);
            if avail < 16 {
                break;
            }
            if let Some((offset, data, fin)) = pair.send.next_send(avail - 16) {
                let (len, data) = (data.len(), data.to_vec());
                frame::put_stream(out, id, offset, fin, &data);
                pair.send.on_sent(offset, len, fin);
                self.data_sent += len as u64;
                frames.push(SentFrame::Stream {
                    id,
                    offset,
                    len,
                    fin,
                });
                ack_eliciting = true;
            }
        }
        Ok(ack_eliciting)
    }
}

// -------------------------------------------------------------------------
// Receiving
// -------------------------------------------------------------------------

impl Connection {
    /// Take one datagram, which may hold several coalesced packets
    pub fn handle_datagram(&mut self, now: Instant, datagram: &mut [u8]) -> Result<()> {
        if self.closed.is_some() {
            return Ok(());
        }
        self.arm_idle(now);
        let mut pos = 0;
        while pos < datagram.len() {
            let consumed = self.handle_packet(now, &mut datagram[pos..])?;
            if consumed == 0 {
                break;
            }
            pos += consumed;
        }
        Ok(())
    }

    /// Returns how much of the buffer this packet took
    fn handle_packet(&mut self, now: Instant, buf: &mut [u8]) -> Result<usize> {
        let (space, pn_offset, end, retry_scid) =
            match header::decode_header(buf, self.local_cid.len())? {
                Incoming::VersionNegotiation => {
                    self.lose("the server does not speak QUIC version 1");
                    return Ok(0);
                }
                Incoming::Retry { scid, token, .. } => {
                    self.on_retry(scid, token)?;
                    return Ok(0);
                }
                Incoming::Long {
                    space,
                    scid,
                    pn_offset,
                    end,
                    ..
                } => (space, pn_offset, end, Some(scid)),
                Incoming::Short { pn_offset, end, .. } => (Space::Data, pn_offset, end, None),
            };

        // A packet in a space whose keys have not arrived yet is dropped, not
        // an error: it is normal for a Handshake packet to overtake the
        // Initial that carries the keys for it
        let Some(keys) = self.remote_keys(space) else {
            return Ok(end);
        };
        let (first, pn_len) =
            match unprotect_header(keys.header.as_ref(), &mut buf[..end], pn_offset) {
                Ok(v) => v,
                // A packet we cannot unprotect is not worth tearing the
                // connection down for; the peer will resend
                Err(_) => return Ok(end),
            };
        let mut truncated = 0u64;
        for &b in &buf[pn_offset..pn_offset + pn_len] {
            truncated = (truncated << 8) | b as u64;
        }
        let pn = decode_packet_number(
            self.spaces[space as usize].largest_received.unwrap_or(0),
            truncated,
            pn_len as u32 * 8,
        );

        let payload_start = pn_offset + pn_len;
        let keys = self.remote_keys(space).expect("checked above");
        let (head, body) = buf[..end].split_at_mut(payload_start);
        let plain = match keys.packet.decrypt_in_place(pn, head, body) {
            Ok(p) => p.len(),
            Err(_) => return Ok(end),
        };
        // The first byte was unmasked in place, so the AAD the peer used is
        // what we just fed in
        let _ = first;

        if let Some(scid) = retry_scid
            && !self.handshake_done
        {
            // The server picks its own connection ID in its first flight
            self.peer_cid = scid;
        }

        let s = &mut self.spaces[space as usize];
        s.largest_received = Some(match s.largest_received {
            Some(prev) => prev.max(pn),
            None => pn,
        });

        let mut ack_eliciting = false;
        let payload_range = payload_start..payload_start + plain;
        // The borrow of `buf` has to end before the frames touch `self`
        let payload = buf[payload_range].to_vec();
        for f in frame::Iter::new(&payload) {
            let f = f?;
            ack_eliciting |= f.ack_eliciting();
            self.handle_frame(space, f, now)?;
        }
        self.spaces[space as usize]
            .ack
            .record(pn, ack_eliciting, now);
        if ack_eliciting {
            self.needs_send = true;
        }
        self.pto_count = 0;
        self.pto_probes = 0;
        Ok(end)
    }

    fn handle_frame(&mut self, space: Space, f: Frame<'_>, now: Instant) -> Result<()> {
        match f {
            Frame::Padding | Frame::Ping | Frame::NewToken => {}
            Frame::Ack {
                largest,
                delay,
                first_range,
                ranges,
                ..
            } => self.on_ack(space, largest, delay, first_range, ranges, now)?,
            Frame::Crypto { offset, data } => self.on_crypto(space, offset, data)?,
            Frame::HandshakeDone => {
                self.handshake_done = true;
                // RFC 9001 Section 4.9.2: the handshake keys are no longer
                // needed and holding them only risks using them
                self.discard_space(Space::Handshake);
            }
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            } => self.on_stream(id, offset, data, fin)?,
            Frame::ResetStream { id, final_size, .. } => self.on_reset(id, final_size)?,
            Frame::StopSending { id, .. } => {
                if let Some(pair) = self.stream_mut(id) {
                    pair.send.reset();
                }
            }
            Frame::MaxData(limit) => self.max_data_peer = self.max_data_peer.max(limit),
            Frame::MaxStreamData { id, limit } => {
                if let Some(pair) = self.stream_mut(id) {
                    pair.send.set_limit(limit);
                }
            }
            Frame::MaxStreams { uni, limit } => {
                if !uni {
                    self.max_streams_bidi = self.max_streams_bidi.max(limit);
                }
            }
            Frame::DataBlocked(_)
            | Frame::StreamDataBlocked { .. }
            | Frame::StreamsBlocked { .. } => {}
            Frame::NewConnectionId { .. } | Frame::RetireConnectionId(_) => {}
            Frame::PathChallenge(data) => {
                // Answered on the next packet. A client that never migrates
                // has one path, so there is nothing to validate beyond
                // echoing the bytes back.
                self.path_response = Some(<[u8; 8]>::try_from(data)?);
                self.needs_send = true;
            }
            Frame::PathResponse(_) => {}
            Frame::Close { error, reason, app } => {
                let reason = String::from_utf8_lossy(reason).into_owned();
                self.lose(&format!(
                    "the peer closed the connection: {}{error:#x}{}",
                    if app {
                        "application error "
                    } else {
                        "transport error "
                    },
                    if reason.is_empty() {
                        String::new()
                    } else {
                        format!(" ({reason})")
                    }
                ));
            }
        }
        Ok(())
    }

    fn on_crypto(&mut self, space: Space, offset: u64, data: &[u8]) -> Result<()> {
        // rustls needs the handshake in order and rejects anything else as a
        // corrupt message, so the pieces are reassembled first. A certificate
        // chain spans several packets, which is exactly where a real network
        // reorders them; a server on loopback never does, which is why this
        // only shows up against someone else's.
        let s = &mut self.spaces[space as usize];
        s.crypto_in.push(offset, data, false)?;
        let mut ordered = Vec::new();
        if s.crypto_in.read(&mut ordered) == 0 {
            return Ok(());
        }
        self.tls
            .read_hs(&ordered)
            .map_err(|e| anyhow::anyhow!("TLS handshake: {e}"))?;
        if self.params.initial_max_data == 0
            && let Some(raw) = self.tls.quic_transport_parameters()
        {
            self.params = Params::decode(raw)?;
            self.max_data_peer = self.params.initial_max_data;
            self.max_streams_bidi = self.params.initial_max_streams_bidi;
        }
        self.pump_tls()?;
        Ok(())
    }

    fn on_ack(
        &mut self,
        space: Space,
        largest: u64,
        delay: u64,
        first_range: u64,
        ranges: &[u8],
        now: Instant,
    ) -> Result<()> {
        let ranges: Vec<(u64, u64)> = AckRanges::new(largest, first_range, ranges).collect();
        let acked = self.spaces[space as usize].sent.drain_acked(&ranges);
        if acked.is_empty() {
            return Ok(());
        }
        if let Some(newest) = acked.iter().find(|p| p.number == largest)
            && newest.ack_eliciting
        {
            let sample = now.saturating_duration_since(newest.time_sent);
            let delay = Duration::from_micros(delay << self.params.ack_delay_exponent);
            let max = Duration::from_millis(self.params.max_ack_delay_ms);
            self.rtt.update(sample, delay, max);
        }
        let mut bytes = 0;
        for p in &acked {
            bytes += p.size;
            for f in &p.frames {
                self.on_frame_acked(*f);
            }
        }
        self.congestion.on_ack(bytes, now);
        self.spaces[space as usize].ack.trim_below(0);

        let loss_delay = self.rtt.loss_delay();
        let (lost, deadline) = self.spaces[space as usize]
            .sent
            .detect_lost(now, loss_delay);
        for p in &lost {
            self.congestion.on_loss(p.time_sent, now);
            for f in &p.frames {
                self.on_frame_lost(space, *f);
            }
        }
        self.loss_deadline = deadline;
        if !lost.is_empty() {
            self.needs_send = true;
        }
        Ok(())
    }

    fn on_frame_acked(&mut self, f: SentFrame) {
        match f {
            // A PING is only there to draw an acknowledgement, and CRYPTO is
            // released by the handshake advancing rather than by this
            SentFrame::Ping | SentFrame::Crypto { .. } => {}
            SentFrame::Stream {
                id, offset, len, ..
            } => {
                if let Some(send) = self.send_mut(id) {
                    send.on_acked(offset, len);
                }
            }
        }
    }

    fn on_frame_lost(&mut self, space: Space, f: SentFrame) {
        match f {
            SentFrame::Ping => {}
            SentFrame::Crypto { offset, len } => {
                // Rewind to the lost run. Anything after it goes out again
                // too, which costs a little bandwidth once and avoids
                // tracking holes in a buffer that is a few kilobytes at most.
                let s = &mut self.spaces[space as usize];
                let _ = len;
                let start = offset.saturating_sub(s.crypto_offset) as usize;
                s.crypto_sent = s.crypto_sent.min(start);
            }
            SentFrame::Stream {
                id,
                offset,
                len,
                fin,
            } => {
                if let Some(send) = self.send_mut(id) {
                    send.on_lost(offset, len, fin);
                }
            }
        }
    }

    fn lose(&mut self, why: &str) {
        if self.closed.is_none() {
            self.closed = Some(why.to_string());
            self.events.push_back(Event::Lost(why.to_string()));
        }
    }

    fn on_retry(&mut self, scid: ConnectionId, _token: &[u8]) -> Result<()> {
        // A benchmark client has nothing to gain from following a Retry: it
        // would mean starting the handshake again with a token, and a server
        // that demands one under load is a server whose numbers would not
        // mean anything anyway
        let _ = scid;
        self.lose("the server asked for a Retry, which shb does not follow");
        Ok(())
    }

    fn arm_idle(&mut self, now: Instant) {
        let ms = self.params.max_idle_timeout_ms;
        if ms > 0 {
            self.idle_deadline = Some(now + Duration::from_millis(ms));
        }
    }
}

// -------------------------------------------------------------------------
// Streams
// -------------------------------------------------------------------------

impl Connection {
    /// Client-initiated bidirectional streams are numbered 0, 4, 8..., so the
    /// stream number is the index into the ring once the base is taken off.
    /// No hashing, and the memory is reused as streams retire.
    fn stream_index(&self, id: u64) -> Option<usize> {
        if !is_client_initiated(id) || stream_dir(id) != Dir::Bi {
            return None;
        }
        let n = id / 4;
        n.checked_sub(self.base_stream)
            .map(|i| i as usize)
            .filter(|&i| i < self.streams.len())
    }

    fn stream_mut(&mut self, id: u64) -> Option<&mut StreamPair> {
        let i = self.stream_index(id)?;
        self.streams[i].as_mut()
    }

    /// The send half of a stream, wherever it lives
    ///
    /// Request streams and the three HTTP/3 control streams are kept apart -
    /// one kind is numbered and retired, the other is opened once and lives
    /// for the connection - but everything that writes, finishes,
    /// acknowledges or resends is indifferent to which it has.
    fn send_mut(&mut self, id: u64) -> Option<&mut SendStream> {
        if let Some(i) = self.stream_index(id) {
            return self.streams[i].as_mut().map(|pair| &mut pair.send);
        }
        self.local_uni
            .iter_mut()
            .find(|(uid, _)| *uid == id)
            .map(|(_, send)| send)
    }

    /// Open a bidirectional stream, if the peer's limit allows another
    pub fn open_bi(&mut self) -> Option<u64> {
        if self.next_bidi >= self.max_streams_bidi {
            return None;
        }
        let id = client_stream_id(Dir::Bi, self.next_bidi);
        self.next_bidi += 1;
        self.streams.push_back(Some(StreamPair {
            send: SendStream::new(self.params.initial_max_stream_data_bidi_remote),
            recv: RecvStream::default(),
            finished: false,
        }));
        Some(id)
    }

    /// Open a unidirectional stream for the HTTP/3 control and QPACK streams
    pub fn open_uni(&mut self) -> Option<u64> {
        if self.next_uni >= self.params.initial_max_streams_uni {
            return None;
        }
        let id = client_stream_id(Dir::Uni, self.next_uni);
        self.next_uni += 1;
        self.local_uni
            .push((id, SendStream::new(self.params.initial_max_stream_data_uni)));
        Some(id)
    }

    pub fn write(&mut self, id: u64, data: &[u8]) -> usize {
        self.needs_send = true;
        self.send_mut(id).map_or(0, |send| send.write(data))
    }

    pub fn finish(&mut self, id: u64) {
        self.needs_send = true;
        if let Some(send) = self.send_mut(id) {
            send.finish();
        }
    }

    /// Take whatever the stream has ready. Returns how many bytes moved.
    pub fn read(&mut self, id: u64, out: &mut Vec<u8>) -> usize {
        if let Some(pair) = self.stream_mut(id) {
            return pair.recv.read(out);
        }
        if let Some((_, recv)) = self.peer_uni.iter_mut().find(|(i, _)| *i == id) {
            return recv.read(out);
        }
        0
    }

    /// Forget a stream that the worker is done with, releasing its slot
    pub fn retire(&mut self, id: u64) {
        if let Some(i) = self.stream_index(id) {
            self.streams[i] = None;
        }
        // Trim the front so the ring does not grow for the life of the run
        while matches!(self.streams.front(), Some(None)) {
            self.streams.pop_front();
            self.base_stream += 1;
        }
    }

    fn on_stream(&mut self, id: u64, offset: u64, data: &[u8], fin: bool) -> Result<()> {
        let new = if let Some(i) = self.stream_index(id) {
            let Some(pair) = self.streams[i].as_mut() else {
                // Already retired; the peer is answering a stream we stopped
                // caring about, which is not an error
                return Ok(());
            };
            let new = pair.recv.push(offset, data, fin)?;
            let readable = pair.recv.has_data();
            let done = pair.recv.is_finished() && !pair.finished;
            if done {
                pair.finished = true;
            }
            if readable {
                self.events.push_back(Event::Readable(id));
            }
            if done {
                self.events.push_back(Event::Finished { id, reset: false });
            }
            new
        } else if is_client_initiated(id) && stream_dir(id) == Dir::Bi {
            // Below the ring's base: a stream we opened, finished and retired.
            // Data for one of those is ordinary - a retransmission, or a frame
            // that crossed the response - and dropping it is right. Only an id
            // we have never handed out is a protocol violation.
            if id / 4 >= self.next_bidi {
                bail!("the peer sent data on client stream {id}, which we did not open");
            }
            return Ok(());
        } else if is_client_initiated(id) {
            // A unidirectional stream we opened: the peer may not write to it
            bail!("the peer sent data on our unidirectional stream {id}");
        } else {
            let pos = match self.peer_uni.iter().position(|(i, _)| *i == id) {
                Some(pos) => pos,
                None => {
                    self.peer_uni.push((id, RecvStream::default()));
                    self.events.push_back(Event::Opened(id));
                    self.peer_uni.len() - 1
                }
            };
            let new = self.peer_uni[pos].1.push(offset, data, fin)?;
            if self.peer_uni[pos].1.has_data() {
                self.events.push_back(Event::Readable(id));
            }
            new
        };

        self.data_received += new;
        if self.data_received > self.max_data_local {
            bail!("the peer sent more than the connection flow control window allows");
        }
        Ok(())
    }

    fn on_reset(&mut self, id: u64, final_size: u64) -> Result<()> {
        if let Some(i) = self.stream_index(id) {
            if let Some(pair) = self.streams[i].as_mut() {
                pair.recv.reset(final_size)?;
                if !pair.finished {
                    pair.finished = true;
                    self.events.push_back(Event::Finished { id, reset: true });
                }
            }
        } else if let Some((_, recv)) = self.peer_uni.iter_mut().find(|(i, _)| *i == id) {
            recv.reset(final_size)?;
        }
        Ok(())
    }
}

// -------------------------------------------------------------------------
// Timers
// -------------------------------------------------------------------------

impl Connection {
    pub fn poll_timeout(&self) -> Option<Instant> {
        let spaces = [
            &self.spaces[0].sent,
            &self.spaces[1].sent,
            &self.spaces[2].sent,
        ];
        let pto = pto_deadline(
            &spaces,
            &self.rtt,
            Duration::from_millis(self.params.max_ack_delay_ms),
            self.pto_count,
        )
        .map(|(_, at)| at);
        [self.loss_deadline, pto, self.idle_deadline]
            .into_iter()
            .flatten()
            .min()
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        if self.idle_deadline.is_some_and(|d| now >= d) {
            self.lose("the connection went idle");
            return;
        }
        if self.loss_deadline.is_some_and(|d| now >= d) {
            let loss_delay = self.rtt.loss_delay();
            for space in Space::ALL {
                let (lost, deadline) = self.spaces[space as usize]
                    .sent
                    .detect_lost(now, loss_delay);
                for p in &lost {
                    self.congestion.on_loss(p.time_sent, now);
                    for f in &p.frames {
                        self.on_frame_lost(space, *f);
                    }
                }
                self.loss_deadline = deadline;
            }
            self.needs_send = true;
            return;
        }
        // A probe timeout: send something the peer has to acknowledge, so a
        // loss we have no other way of noticing is discovered
        let spaces = [
            &self.spaces[0].sent,
            &self.spaces[1].sent,
            &self.spaces[2].sent,
        ];
        let due = pto_deadline(
            &spaces,
            &self.rtt,
            Duration::from_millis(self.params.max_ack_delay_ms),
            self.pto_count,
        );
        if due.is_some_and(|(space, at)| {
            if now < at {
                return false;
            }
            // RFC 9002 Section 6.2.4: a probe sends new data or sends
            // unacknowledged data again. In a handshake space that means the
            // CRYPTO bytes: a PING would be answered with nothing, because a
            // peer that never received the ClientHello has no connection to
            // answer about, and the connection would wait forever.
            let _ = space;
            true
        }) {
            if let Some((space, _)) = due {
                self.spaces[space as usize].crypto_sent = 0;
            }
            self.pto_count += 1;
            // RFC 9002 Section 6.2.4 allows two, which recovers a lost probe
            // without another timeout
            self.pto_probes = 2;
            self.needs_send = true;
        }
    }

    /// Ask for a CONNECTION_CLOSE on the next packet
    pub fn close(&mut self, code: u64, reason: &[u8]) {
        if self.closed.is_none() {
            self.close_pending = Some((code, reason.to_vec()));
            self.closed = Some("closed locally".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a client Initial and read it back the way a server would
    ///
    /// Needs no server, and pinpoints whether a handshake that goes nowhere
    /// is a packet we built wrong or something later.
    #[test]
    fn our_own_initial_packet_decodes_as_a_server_would_read_it() {
        let tls = crate::tls::client_config(b"h3").unwrap();
        let mut conn = Connection::connect(
            tls,
            "localhost",
            LocalParamsInput {
                initial_max_data: 1 << 20,
                initial_max_stream_data: 1 << 20,
                initial_max_streams_uni: 3,
                max_idle_timeout_ms: 5_000,
            },
        )
        .unwrap();
        let mut out = Vec::new();
        let n = conn.poll_transmit(Instant::now(), &mut out, None).unwrap();
        assert_eq!(
            n, MIN_INITIAL_DATAGRAM,
            "an Initial datagram is padded to 1200"
        );

        // Taken off the wire rather than out of the connection: what a server
        // derives its keys from is what we actually sent, and the decryption
        // below is what would notice if those two ever disagreed
        let dcid = ConnectionId::new(&out[6..6 + out[5] as usize]).unwrap();

        // A server derives its keys from the destination connection ID we chose
        let keys = initial_keys(dcid.as_slice(), rustls::Side::Server).unwrap();
        let Incoming::Long {
            space,
            pn_offset,
            end,
            ..
        } = header::decode_header(&out, 0).unwrap()
        else {
            panic!("a client Initial has a long header");
        };
        assert_eq!(space, Space::Initial);
        assert_eq!(end, out.len(), "the length field must cover the datagram");

        let (first, pn_len) =
            unprotect_header(keys.remote.header.as_ref(), &mut out[..end], pn_offset).unwrap();
        assert_eq!(first & 0x30, 0x00, "still an Initial after unmasking");
        let mut pn = 0u64;
        for &b in &out[pn_offset..pn_offset + pn_len] {
            pn = (pn << 8) | b as u64;
        }
        assert_eq!(pn, 0, "the first packet is number zero");

        let payload_start = pn_offset + pn_len;
        let (head, body) = out[..end].split_at_mut(payload_start);
        let plain = keys
            .remote
            .packet
            .decrypt_in_place(pn, head, body)
            .expect("a server must be able to decrypt our Initial");
        let frames: Vec<_> = frame::Iter::new(plain).map(|f| f.unwrap()).collect();
        assert!(
            frames.iter().any(|f| matches!(f, Frame::Crypto { .. })),
            "the Initial has to carry the ClientHello, got {frames:?}"
        );
    }

    /// A whole HTTP/3 exchange over shb's own QUIC: handshake, control and
    /// QPACK streams, a request, a response with a status
    ///
    ///     cargo test --bin shb request_against_a_real_server -- --ignored
    #[test]
    #[ignore]
    fn request_against_a_real_server() {
        use crate::http3::proto;
        use crate::http3::qpack;
        use std::net::UdpSocket;

        let addr: std::net::SocketAddr = std::env::var("SHB_QUIC_TEST")
            .unwrap_or_else(|_| "127.0.0.1:3453".into())
            .parse()
            .unwrap();
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();

        let mut conn = Connection::connect(
            crate::tls::client_config(b"h3").unwrap(),
            "localhost",
            LocalParamsInput {
                initial_max_data: 1 << 22,
                initial_max_stream_data: 1 << 20,
                initial_max_streams_uni: 3,
                max_idle_timeout_ms: 5_000,
            },
        )
        .unwrap();

        let mut out = Vec::with_capacity(2048);
        let mut buf = [0u8; 2048];
        let mut opened_uni = false;
        let mut request: Option<u64> = None;
        let mut reader = proto::ResponseReader::default();
        let mut scratch = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);

        while Instant::now() < deadline {
            let now = Instant::now();

            if conn.connected && !opened_uni {
                // RFC 9114 Section 6.2: the control stream and the two QPACK
                // streams, each opened with its type
                for kind in [
                    proto::STREAM_CONTROL,
                    proto::STREAM_QPACK_ENCODER,
                    proto::STREAM_QPACK_DECODER,
                ] {
                    let id = conn.open_uni().expect("the server allows three");
                    let prelude = if kind == proto::STREAM_CONTROL {
                        proto::control_stream_prelude()
                    } else {
                        let mut v = Vec::new();
                        crate::quic::varint::put_varint(&mut v, kind);
                        v
                    };
                    assert_eq!(conn.write(id, &prelude), prelude.len());
                }
                opened_uni = true;
            }

            if opened_uni
                && request.is_none()
                && let Some(id) = conn.open_bi()
            {
                let block = qpack::encode_request("GET", "https", "localhost", "/", &[], 0);
                let bytes = proto::request_bytes(&block, b"");
                assert_eq!(conn.write(id, &bytes), bytes.len());
                conn.finish(id);
                request = Some(id);
            }

            out.clear();
            let n = conn.poll_transmit(now, &mut out, None).unwrap();
            if n > 0 {
                sock.send(&out[..n]).unwrap();
            }

            while let Some(ev) = conn.poll_event() {
                match ev {
                    Event::Lost(why) => panic!("connection lost: {why}"),
                    Event::Readable(id) if Some(id) == request => {
                        scratch.clear();
                        conn.read(id, &mut scratch);
                        reader.feed(&scratch).unwrap();
                    }
                    Event::Finished { id, reset } if Some(id) == request => {
                        assert!(!reset, "the server reset the request stream");
                        assert_eq!(reader.status(), 200, "the status nginx answers with");
                        return;
                    }
                    _ => {}
                }
            }

            match sock.recv(&mut buf) {
                Ok(len) => conn
                    .handle_datagram(Instant::now(), &mut buf[..len])
                    .unwrap(),
                Err(_) => conn.handle_timeout(Instant::now()),
            }
        }
        panic!(
            "no response within ten seconds (status so far {})",
            reader.status()
        );
    }

    /// The moment of truth: a real handshake against a real server
    ///
    /// Ignored by default because it needs something listening; run it with
    ///     cargo test --bin shb handshake_against_a_real_server -- --ignored
    #[test]
    #[ignore]
    fn handshake_against_a_real_server() {
        use std::net::UdpSocket;

        let addr: std::net::SocketAddr = std::env::var("SHB_QUIC_TEST")
            .unwrap_or_else(|_| "127.0.0.1:3453".into())
            .parse()
            .unwrap();
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();

        let tls = crate::tls::client_config(b"h3").unwrap();
        let mut conn = Connection::connect(
            tls,
            "localhost",
            LocalParamsInput {
                initial_max_data: 1 << 20,
                initial_max_stream_data: 1 << 20,
                initial_max_streams_uni: 3,
                max_idle_timeout_ms: 5_000,
            },
        )
        .unwrap();

        let mut out = Vec::with_capacity(2048);
        let mut buf = [0u8; 2048];
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let now = Instant::now();
            out.clear();
            let n = conn.poll_transmit(now, &mut out, None).unwrap();
            if n > 0 {
                sock.send(&out[..n]).unwrap();
            }
            while let Some(ev) = conn.poll_event() {
                match ev {
                    Event::Connected => return,
                    Event::Lost(why) => panic!("connection lost: {why}"),
                    _ => {}
                }
            }
            match sock.recv(&mut buf) {
                Ok(len) => {
                    if let Err(e) = conn.handle_datagram(Instant::now(), &mut buf[..len]) {
                        panic!("handling the datagram failed: {e:#}");
                    }
                }
                Err(_) => conn.handle_timeout(Instant::now()),
            }
        }
        panic!("the handshake did not finish within five seconds");
    }
}
