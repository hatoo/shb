//! QUIC packet headers, packet numbers and header protection (RFC 9000
//! Section 17, RFC 9001 Section 5.4)
//!
//! The crypto itself stays with rustls: this module decides what the bytes
//! around it look like.

use anyhow::{Result, bail};
use rustls::quic::HeaderProtectionKey;

/// Longest connection ID RFC 9000 Section 17.2 allows
pub const MAX_CID_LEN: usize = 20;

/// A connection ID, inline rather than heap-allocated: they are at most 20
/// bytes and every packet carries one, so an allocation per packet would be
/// the wrong trade.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConnectionId {
    len: u8,
    bytes: [u8; MAX_CID_LEN],
}

impl ConnectionId {
    pub fn new(slice: &[u8]) -> Result<Self> {
        if slice.len() > MAX_CID_LEN {
            bail!("connection ID longer than {MAX_CID_LEN} bytes");
        }
        let mut bytes = [0u8; MAX_CID_LEN];
        bytes[..slice.len()].copy_from_slice(slice);
        Ok(Self {
            len: slice.len() as u8,
            bytes,
        })
    }

    pub fn random() -> Self {
        // Eight bytes is what quinn and most servers use: enough that a peer
        // cannot guess one, short enough to keep the header small
        let mut bytes = [0u8; MAX_CID_LEN];
        getrandom(&mut bytes[..8]);
        Self { len: 8, bytes }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }
}

impl std::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.as_slice() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// rustls already carries a CSPRNG, so there is no reason to pull in another
fn getrandom(out: &mut [u8]) {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(out)
        .expect("the system CSPRNG failed");
}

/// The three packet number spaces (RFC 9000 Section 12.3). Each keeps its own
/// packet numbers, its own acknowledgements and its own keys.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Space {
    Initial = 0,
    Handshake = 1,
    Data = 2,
}

impl Space {
    pub const ALL: [Space; 3] = [Space::Initial, Space::Handshake, Space::Data];
}

/// Smallest number of bytes that encodes `pn` unambiguously given what the
/// peer has already acknowledged (RFC 9000 Appendix A.2)
///
/// The peer decodes against the largest packet number it has *received*, so
/// the window has to cover everything that might still be in flight: twice the
/// range between the largest acknowledged packet and this one.
pub fn encode_packet_number(pn: u64, largest_acked: Option<u64>) -> (u64, usize) {
    let range = match largest_acked {
        Some(acked) => (pn - acked) * 2,
        // Nothing acknowledged yet, so the peer has no history to decode
        // against and the full number has to be spelled out
        None => pn + 1,
    };
    let len = match range {
        0..=0xff => 1,
        0x100..=0xffff => 2,
        0x10000..=0xff_ffff => 3,
        _ => 4,
    };
    (pn & (u64::MAX >> (64 - len * 8)), len)
}

/// Recover the full packet number from the truncated one on the wire
/// (RFC 9000 Appendix A.3)
pub fn decode_packet_number(largest_pn: u64, truncated: u64, pn_nbits: u32) -> u64 {
    let expected = largest_pn + 1;
    let win = 1u64 << pn_nbits;
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;
    // Pick the candidate nearest the expected number, preferring the smaller
    // one on a tie, which is what the pseudocode in the appendix does
    if candidate + hwin <= expected && candidate + win < (1u64 << 62) {
        candidate + win
    } else if candidate > expected + hwin && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

/// The sample RFC 9001 Section 5.4.2 protects the header with starts four
/// bytes past the packet number field, whatever length the number was
const SAMPLE_OFFSET: usize = 4;
const SAMPLE_LEN: usize = 16;

/// Mask the first byte and the packet number, in place (RFC 9001 Section 5.4.1)
///
/// `pn_offset` is where the packet number starts; `pn_len` how long it is. The
/// packet must already be encrypted, since the mask comes from the ciphertext.
pub fn protect_header(
    hp: &dyn HeaderProtectionKey,
    packet: &mut [u8],
    pn_offset: usize,
    pn_len: usize,
) -> Result<()> {
    let sample_start = pn_offset + SAMPLE_OFFSET;
    if packet.len() < sample_start + SAMPLE_LEN {
        bail!("packet too short to sample for header protection");
    }
    let mut sample = [0u8; SAMPLE_LEN];
    sample.copy_from_slice(&packet[sample_start..sample_start + SAMPLE_LEN]);
    let (first, rest) = packet.split_at_mut(1);
    let pn = &mut rest[pn_offset - 1..pn_offset - 1 + pn_len];
    hp.encrypt_in_place(&sample, &mut first[0], pn)
        .map_err(|e| anyhow::anyhow!("header protection: {e}"))
}

/// Undo header protection, returning the unmasked first byte and the packet
/// number length it revealed
pub fn unprotect_header(
    hp: &dyn HeaderProtectionKey,
    packet: &mut [u8],
    pn_offset: usize,
) -> Result<(u8, usize)> {
    let sample_start = pn_offset + SAMPLE_OFFSET;
    if packet.len() < sample_start + SAMPLE_LEN {
        bail!("packet too short to sample for header protection");
    }
    let mut sample = [0u8; SAMPLE_LEN];
    sample.copy_from_slice(&packet[sample_start..sample_start + SAMPLE_LEN]);
    // The length lives in the two bits the mask also covers, so unmask the
    // largest number it could be and then trim
    let (first, rest) = packet.split_at_mut(1);
    let pn = &mut rest[pn_offset - 1..pn_offset - 1 + 4];
    hp.decrypt_in_place(&sample, &mut first[0], pn)
        .map_err(|e| anyhow::anyhow!("header protection: {e}"))?;
    Ok((first[0], (first[0] & 0x03) as usize + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9000 Appendix A.2
    #[test]
    fn packet_number_encoding_matches_the_spec() {
        // "if the highest successfully authenticated packet number is
        // 0xabe8b3 and the packet number being sent is 0xac5c02, then two
        // bytes, 0x5c02, are sufficient"
        assert_eq!(encode_packet_number(0xac5c02, Some(0xabe8b3)), (0x5c02, 2));
        // "if the largest acknowledged packet number is 0xabe8b3 and the
        // packet number being sent is 0xace8fe, three bytes are needed"
        assert_eq!(
            encode_packet_number(0xace8fe, Some(0xabe8b3)),
            (0xace8fe, 3)
        );
    }

    /// RFC 9000 Appendix A.3
    #[test]
    fn packet_number_decoding_matches_the_spec() {
        // largest received 0xa82f30ea, two-byte 0x9b32 decodes to 0xa82f9b32
        assert_eq!(decode_packet_number(0xa82f30ea, 0x9b32, 16), 0xa82f9b32);
    }

    #[test]
    fn a_number_with_nothing_acknowledged_is_spelled_out() {
        // With no history the peer decodes against zero, so the encoding has
        // to be wide enough for the number itself
        assert_eq!(encode_packet_number(0, None), (0, 1));
        assert_eq!(encode_packet_number(0xff, None), (0xff, 2));
    }

    #[test]
    fn decoding_picks_the_nearest_candidate() {
        // Just below a wrap: the candidate above is nearer than the one below
        assert_eq!(decode_packet_number(0xff, 0x01, 8), 0x101);
        // And just after one
        assert_eq!(decode_packet_number(0x100, 0xff, 8), 0xff);
    }

    #[test]
    fn connection_ids_round_trip() {
        let cid = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]).unwrap();
        assert_eq!(cid.len(), 8);
        assert_eq!(format!("{cid:?}"), "8394c8f03e515708");
        assert!(ConnectionId::new(&[0u8; MAX_CID_LEN + 1]).is_err());
        // Two random ones should differ; a fixed generator would be a bug the
        // peer could exploit to confuse connections
        assert_ne!(
            ConnectionId::random().as_slice(),
            ConnectionId::random().as_slice()
        );
    }
}
