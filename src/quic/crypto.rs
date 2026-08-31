//! Keys, taken from rustls rather than derived here
//!
//! rustls already implements the TLS 1.3 handshake, the QUIC key schedule
//! (RFC 9001 Section 5) and the AEAD and header-protection primitives. There
//! is nothing to gain and a great deal to lose by writing that again, so this
//! module is only the small amount of glue that picks the initial keys and
//! names the pieces the rest of the connection needs.

use anyhow::{Context, Result};
use rustls::Side;
use rustls::quic::{Keys, Version};

/// The cipher suite RFC 9001 Section 5.2 requires for Initial packets
fn initial_suite() -> Result<&'static rustls::Tls13CipherSuite> {
    match rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256 {
        rustls::SupportedCipherSuite::Tls13(suite) => Ok(suite),
        _ => anyhow::bail!("TLS13_AES_128_GCM_SHA256 is not a TLS 1.3 suite"),
    }
}

/// Initial keys, which both sides derive from the client's first destination
/// connection ID alone (RFC 9001 Section 5.2)
pub fn initial_keys(dcid: &[u8], side: Side) -> Result<Keys> {
    let suite = initial_suite()?;
    let quic = suite
        .quic
        .context("the initial cipher suite has no QUIC algorithm")?;
    Ok(Keys::initial(Version::V1, suite, quic, dcid, side))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::packet::protect_header;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9001 Appendix A.2, the worked example of a client Initial packet
    ///
    /// This is the one test that proves the initial keys and the header
    /// protection together: the appendix gives the unprotected header, the
    /// ciphertext sample the mask comes from, and the protected header that
    /// must come out. Getting any of the three wrong produces a packet a
    /// server silently drops, which is exactly the kind of failure that only
    /// shows up against someone else's implementation.
    #[test]
    fn client_initial_header_protection_matches_the_spec() {
        let dcid = hex("8394c8f03e515708");
        let keys = initial_keys(&dcid, Side::Client).unwrap();

        // Header up to but not including the packet number, then the
        // four-byte number, then the ciphertext the sample is taken from
        let header = hex("c300000001088394c8f03e5157080000449e");
        assert_eq!(header.len(), 18, "packet number starts at offset 18");
        let mut packet = header.clone();
        packet.extend_from_slice(&hex("00000002"));
        packet.extend_from_slice(&hex("d1b1c98dd7689fb8ec11d242b123dc9b"));

        protect_header(keys.local.header.as_ref(), &mut packet, 18, 4).unwrap();

        assert_eq!(
            packet[..22],
            hex("c000000001088394c8f03e5157080000449e7b9aec34")[..],
            "protected header from RFC 9001 Appendix A.2"
        );
    }

    /// The same example backwards: unprotecting the protected header has to
    /// give back the original first byte and packet number length
    #[test]
    fn header_protection_round_trips() {
        use crate::quic::packet::unprotect_header;
        let dcid = hex("8394c8f03e515708");
        let keys = initial_keys(&dcid, Side::Client).unwrap();

        let mut packet = hex("c000000001088394c8f03e5157080000449e7b9aec34");
        packet.extend_from_slice(&hex("d1b1c98dd7689fb8ec11d242b123dc9b"));
        let (first, pn_len) =
            unprotect_header(keys.local.header.as_ref(), &mut packet, 18).unwrap();

        assert_eq!(first, 0xc3, "the unmasked first byte");
        assert_eq!(pn_len, 4);
        assert_eq!(packet[18..22], hex("00000002")[..]);
    }

    /// The server derives its own keys from the same connection ID, and they
    /// must not be the client's
    #[test]
    fn the_two_sides_derive_different_keys() {
        let dcid = hex("8394c8f03e515708");
        let client = initial_keys(&dcid, Side::Client).unwrap();
        let server = initial_keys(&dcid, Side::Server).unwrap();

        let mut a = vec![0u8; 22 + 16];
        let mut b = a.clone();
        protect_header(client.local.header.as_ref(), &mut a, 18, 4).unwrap();
        protect_header(server.local.header.as_ref(), &mut b, 18, 4).unwrap();
        assert_ne!(a, b);
    }
}
