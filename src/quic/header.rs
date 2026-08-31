//! Reading and writing the bytes around a packet's payload
//! (RFC 9000 Section 17)

use anyhow::{Result, bail};

use super::packet::{ConnectionId, MAX_CID_LEN, Space};
use super::varint::{get_varint, put_varint};

pub const VERSION_1: u32 = 0x0000_0001;

const FORM_LONG: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
const LONG_TYPE_MASK: u8 = 0x30;
const TYPE_INITIAL: u8 = 0x00;
const TYPE_HANDSHAKE: u8 = 0x20;
const TYPE_RETRY: u8 = 0x30;

/// What a datagram turned out to hold, before it is decrypted
/// Only what the connection acts on. The connection IDs are stepped over
/// rather than returned: a client socket carries one connection, so the
/// destination is ours by construction, and copying one out of every 1-RTT
/// packet would cost more than it tells us.
pub enum Incoming<'a> {
    Long {
        space: Space,
        /// The server picks its own connection ID in its first flight
        scid: ConnectionId,
        /// Where the packet number starts
        pn_offset: usize,
        /// One past the end of this packet's payload
        end: usize,
    },
    Short {
        pn_offset: usize,
        end: usize,
    },
    Retry {
        scid: ConnectionId,
        token: &'a [u8],
    },
    VersionNegotiation,
}

/// Parse one packet's framing out of a datagram. Datagrams can hold several
/// packets back to back (RFC 9000 Section 12.2), which is why this returns
/// where the packet ends rather than assuming it is the whole datagram.
pub fn decode_header(buf: &[u8], local_cid_len: usize) -> Result<Incoming<'_>> {
    let Some(&first) = buf.first() else {
        bail!("empty datagram");
    };
    if first & FORM_LONG == 0 {
        // Short header: the destination connection ID is whatever length we
        // told the peer to use, since there is no length field
        let pn_offset = 1 + local_cid_len;
        if buf.len() < pn_offset + 4 {
            bail!("short header packet is truncated");
        }
        return Ok(Incoming::Short {
            pn_offset,
            // A short header packet always runs to the end of the datagram
            end: buf.len(),
        });
    }

    if buf.len() < 6 {
        bail!("long header packet is truncated");
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let mut pos = 5;
    let dcid_len = buf[pos] as usize;
    pos += 1;
    if dcid_len > MAX_CID_LEN || buf.len() < pos + dcid_len + 1 {
        bail!("long header destination connection ID is bad");
    }
    pos += dcid_len;
    let scid_len = buf[pos] as usize;
    pos += 1;
    if scid_len > MAX_CID_LEN || buf.len() < pos + scid_len {
        bail!("long header source connection ID is bad");
    }
    let scid = ConnectionId::new(&buf[pos..pos + scid_len])?;
    pos += scid_len;

    // Version zero means the peer does not speak ours (RFC 9000 Section 17.2.1)
    if version == 0 {
        return Ok(Incoming::VersionNegotiation);
    }
    if version != VERSION_1 {
        bail!("unsupported QUIC version {version:#x}");
    }

    match first & LONG_TYPE_MASK {
        TYPE_RETRY => {
            if buf.len() < pos + 16 {
                bail!("Retry packet is truncated");
            }
            // The last 16 bytes are the integrity tag, which only matters to
            // a client that follows a Retry
            let split = buf.len() - 16;
            Ok(Incoming::Retry {
                scid,
                token: &buf[pos..split],
            })
        }
        kind @ (TYPE_INITIAL | TYPE_HANDSHAKE) => {
            if kind == TYPE_INITIAL {
                // A server's Initial carries an empty token, but the field is
                // there and has to be stepped over to reach the length
                let Some((len, n)) = get_varint(&buf[pos..]) else {
                    bail!("truncated token length");
                };
                pos += n;
                if buf.len() < pos + len as usize {
                    bail!("token runs past the end");
                }
                pos += len as usize;
            }
            let Some((len, n)) = get_varint(&buf[pos..]) else {
                bail!("truncated length field");
            };
            pos += n;
            let end = pos
                .checked_add(len as usize)
                .filter(|&e| e <= buf.len())
                .ok_or_else(|| anyhow::anyhow!("packet length runs past the datagram"))?;
            Ok(Incoming::Long {
                space: if kind == TYPE_INITIAL {
                    Space::Initial
                } else {
                    Space::Handshake
                },
                scid,
                pn_offset: pos,
                end,
            })
        }
        // 0-RTT, which a server never sends to a client
        _ => bail!("unexpected 0-RTT packet"),
    }
}

/// Write a long header up to but not including the length field, returning
/// where the length varint has to go
pub struct LongHeader {
    pub space: Space,
    pub dcid: ConnectionId,
    pub scid: ConnectionId,
    pub token: Vec<u8>,
}

impl LongHeader {
    /// Append the header. `payload_len` counts the packet number and the
    /// encrypted payload, since that is what the length field covers.
    pub fn put(&self, out: &mut Vec<u8>, pn_len: usize, payload_len: usize) {
        let kind = match self.space {
            Space::Initial => TYPE_INITIAL,
            Space::Handshake => TYPE_HANDSHAKE,
            Space::Data => unreachable!("1-RTT packets use a short header"),
        };
        // The low two bits carry the packet number length, less one, and are
        // masked by header protection afterwards
        out.push(FORM_LONG | FIXED_BIT | kind | (pn_len as u8 - 1));
        out.extend_from_slice(&VERSION_1.to_be_bytes());
        out.push(self.dcid.len() as u8);
        out.extend_from_slice(self.dcid.as_slice());
        out.push(self.scid.len() as u8);
        out.extend_from_slice(self.scid.as_slice());
        if self.space == Space::Initial {
            put_varint(out, self.token.len() as u64);
            out.extend_from_slice(&self.token);
        }
        put_varint_fixed4(out, payload_len as u64);
    }
}

/// A short header: just the first byte and the peer's connection ID
pub fn put_short_header(out: &mut Vec<u8>, dcid: &ConnectionId, pn_len: usize, key_phase: bool) {
    let mut first = FIXED_BIT | (pn_len as u8 - 1);
    if key_phase {
        first |= 0x04;
    }
    out.push(first);
    out.extend_from_slice(dcid.as_slice());
}

/// Write a length as a four-byte varint whatever its value
///
/// The length has to be written before the payload is encrypted but its value
/// is not known until afterwards, and a varint that changes width would move
/// everything after it. Always using the widest form keeps the offsets fixed
/// for two bytes of overhead.
pub fn put_varint_fixed4(out: &mut Vec<u8>, value: u64) {
    debug_assert!(value < (1 << 30), "value does not fit a four-byte varint");
    // The four-byte form is tagged 10 in the top two bits; 11 is the
    // eight-byte one, and a peer reading four bytes as eight loses the packet
    out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
}

/// Overwrite a four-byte varint written earlier
pub fn set_varint_fixed4(buf: &mut [u8], at: usize, value: u64) {
    debug_assert!(value < (1 << 30));
    buf[at..at + 4].copy_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixed-width length field has to read back as the same number
    /// through the ordinary varint decoder, or the peer sees a different
    /// packet length than the one written
    #[test]
    fn a_fixed_width_length_reads_back_as_itself() {
        for value in [0u64, 1, 63, 64, 16383, 16384, 1200, (1 << 30) - 1] {
            let mut out = Vec::new();
            put_varint_fixed4(&mut out, value);
            assert_eq!(out.len(), 4, "value {value}");
            assert_eq!(
                get_varint(&out),
                Some((value, 4)),
                "value {value} did not survive the four-byte form"
            );
        }
    }

    #[test]
    fn a_fixed_width_length_can_be_written_after_the_fact() {
        let mut buf = vec![0xaa];
        put_varint_fixed4(&mut buf, 0);
        buf.push(0xbb);
        set_varint_fixed4(&mut buf, 1, 1182);
        assert_eq!(get_varint(&buf[1..]), Some((1182, 4)));
        assert_eq!((buf[0], buf[5]), (0xaa, 0xbb), "nothing else moved");
    }

    /// RFC 9001 Appendix A.2's header, read back
    #[test]
    fn the_spec_example_initial_header_parses() {
        let buf = (0..)
            .step_by(2)
            .zip(0..)
            .take_while(|&(i, _)| i < "c300000001088394c8f03e5157080000449e".len())
            .map(|(i, _)| {
                u8::from_str_radix(&"c300000001088394c8f03e5157080000449e"[i..i + 2], 16).unwrap()
            })
            .collect::<Vec<_>>();
        // The length field says 1182 bytes follow, so give it that much
        let mut packet = buf.clone();
        packet.extend(std::iter::repeat_n(0u8, 1182));
        let Incoming::Long {
            space,
            scid,
            pn_offset,
            end,
        } = decode_header(&packet, 0).unwrap()
        else {
            panic!("expected a long header");
        };
        assert_eq!(space, Space::Initial);
        assert_eq!(scid.len(), 0);
        // The connection ID, token and length are stepped over rather than
        // returned, so where the packet number lands is what proves they were
        // all read at their true widths
        assert_eq!(pn_offset, 18, "where RFC 9001 Appendix A.2 puts it");
        assert_eq!(end, 18 + 1182);
    }

    #[test]
    fn a_long_header_round_trips() {
        let h = LongHeader {
            space: Space::Handshake,
            dcid: ConnectionId::new(&[1, 2, 3, 4]).unwrap(),
            scid: ConnectionId::new(&[5, 6]).unwrap(),
            token: Vec::new(),
        };
        let mut out = Vec::new();
        h.put(&mut out, 2, 100);
        let mut packet = out.clone();
        packet.extend(std::iter::repeat_n(0u8, 100));
        let Incoming::Long {
            space,
            scid,
            pn_offset,
            end,
        } = decode_header(&packet, 0).unwrap()
        else {
            panic!("expected a long header");
        };
        assert_eq!(space, Space::Handshake);
        assert_eq!(&packet[6..10], &[1, 2, 3, 4], "the destination we wrote");
        assert_eq!(scid.as_slice(), &[5, 6]);
        assert_eq!(pn_offset, out.len());
        assert_eq!(end, out.len() + 100);
    }

    #[test]
    fn an_initial_header_carries_its_token() {
        let h = LongHeader {
            space: Space::Initial,
            dcid: ConnectionId::new(&[1, 2]).unwrap(),
            scid: ConnectionId::new(&[3]).unwrap(),
            token: vec![7, 7, 7],
        };
        let mut out = Vec::new();
        h.put(&mut out, 1, 50);
        let mut packet = out.clone();
        packet.extend(std::iter::repeat_n(0u8, 50));
        let Incoming::Long { pn_offset, .. } = decode_header(&packet, 0).unwrap() else {
            panic!("expected a long header");
        };
        // The token is stepped over, so the packet number landing after it is
        // what says its length was read correctly
        assert_eq!(&packet[11..14], &[7, 7, 7], "the token we wrote");
        assert_eq!(pn_offset, out.len());
    }

    /// A short header has no length field, so the connection ID length has to
    /// come from what we told the peer to use
    #[test]
    fn a_short_header_uses_our_own_connection_id_length() {
        let mut out = Vec::new();
        let cid = ConnectionId::new(&[9, 9, 9, 9, 9, 9, 9, 9]).unwrap();
        put_short_header(&mut out, &cid, 1, false);
        out.extend(std::iter::repeat_n(0u8, 20));
        let Incoming::Short { pn_offset, end } = decode_header(&out, 8).unwrap() else {
            panic!("expected a short header");
        };
        // Nothing tells a short header how long its connection ID is, so the
        // packet number offset comes from the length we told the peer to use
        assert_eq!(pn_offset, 9);
        assert_eq!(end, out.len(), "it runs to the end of the datagram");
    }

    #[test]
    fn version_negotiation_is_recognised() {
        let mut buf = vec![0x80];
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&VERSION_1.to_be_bytes());
        assert!(matches!(
            decode_header(&buf, 0).unwrap(),
            Incoming::VersionNegotiation
        ));
    }

    #[test]
    fn a_retry_packet_splits_off_its_integrity_tag() {
        let mut buf = vec![0x80 | 0x40 | 0x30];
        buf.extend_from_slice(&VERSION_1.to_be_bytes());
        buf.push(0); // no destination CID
        buf.push(2);
        buf.extend_from_slice(&[0xab, 0xcd]);
        buf.extend_from_slice(b"token");
        buf.extend_from_slice(&[0xee; 16]);
        let Incoming::Retry { scid, token } = decode_header(&buf, 0).unwrap() else {
            panic!("expected a Retry");
        };
        assert_eq!(scid.as_slice(), &[0xab, 0xcd]);
        assert_eq!(token, b"token", "the tag is split off the end");
    }

    #[test]
    fn a_length_past_the_end_of_the_datagram_is_rejected() {
        let h = LongHeader {
            space: Space::Handshake,
            dcid: ConnectionId::new(&[1]).unwrap(),
            scid: ConnectionId::new(&[2]).unwrap(),
            token: Vec::new(),
        };
        let mut out = Vec::new();
        h.put(&mut out, 1, 9999);
        out.extend(std::iter::repeat_n(0u8, 10));
        assert!(decode_header(&out, 0).is_err());
    }

    #[test]
    fn an_unknown_version_is_rejected() {
        let mut buf = vec![0xc0];
        buf.extend_from_slice(&0xdead_beefu32.to_be_bytes());
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&[0u8; 20]);
        assert!(decode_header(&buf, 0).is_err());
    }
}
