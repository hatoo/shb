//! Retry tokens must survive repeated Initial builds without affecting the
//! packet length, protection, recovery state or another packet number space.

use super::*;

const CRYPTO: [u8; 16] = *b"initial-contents";

fn retry_packet(conn: &Connection, token: &[u8]) -> Vec<u8> {
    let mut packet = vec![0xf0, 0, 0, 0, 1, conn.local_cid.len() as u8];
    packet.extend_from_slice(conn.local_cid.as_slice());
    packet.push(8);
    packet.extend_from_slice(&[0xa7; 8]);
    packet.extend_from_slice(token);
    let mut pseudo = vec![conn.original_dcid.len() as u8];
    pseudo.extend_from_slice(conn.original_dcid.as_slice());
    pseudo.extend_from_slice(&packet);
    // RFC 9001 Section 5.8: fixed Retry integrity key and nonce.
    let key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(
            &ring::aead::AES_128_GCM,
            &[
                0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68,
                0xc8, 0x4e,
            ],
        )
        .unwrap(),
    );
    let tag = key
        .seal_in_place_separate_tag(
            ring::aead::Nonce::assume_unique_for_key([
                0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
            ]),
            ring::aead::Aad::from(&pseudo),
            &mut [],
        )
        .unwrap();
    packet.extend_from_slice(tag.as_ref());
    packet
}

fn retried(token: &[u8], now: Instant) -> Connection {
    let mut conn = client();
    conn.spaces[0].crypto_out = CRYPTO.to_vec();
    let mut out = Vec::new();
    assert!(
        conn.write_packet(Space::Initial, now, &mut out, 0, false, Some(1200))
            .unwrap()
    );
    let mut packet = retry_packet(&conn, token);
    let mut forged = packet.clone();
    *forged.last_mut().unwrap() ^= 1;
    conn.handle_datagram(now, &mut forged).unwrap();
    assert!(!conn.retried);
    assert!(conn.retry_token.is_empty());
    assert_eq!(conn.spaces[0].sent.bytes_in_flight(), 1200);
    conn.handle_datagram(now, &mut packet).unwrap();
    assert!(conn.retried);
    assert_eq!(conn.retry_token, token);
    assert_eq!(conn.spaces[0].sent.bytes_in_flight(), 0);
    assert_eq!(conn.spaces[0].crypto_sent, 0);
    assert_eq!(conn.spaces[0].next_packet_number, 1);
    let mut second = retry_packet(&conn, b"must not replace the first token");
    conn.handle_datagram(now, &mut second).unwrap();
    assert_eq!(conn.retry_token, token);
    conn
}

// Independent scalar header/length/PN layout, followed by the same AEAD
// primitive. The receiver below also decrypts the actual packet separately.
fn expected_initial(conn: &Connection, token: &[u8], pn: u64, pn_len: usize) -> Vec<u8> {
    let mut packet = vec![0xc0 | (pn_len as u8 - 1), 0, 0, 0, 1];
    packet.push(conn.peer_cid.len() as u8);
    packet.extend_from_slice(conn.peer_cid.as_slice());
    packet.push(conn.local_cid.len() as u8);
    packet.extend_from_slice(conn.local_cid.as_slice());
    if token.len() < 64 {
        packet.push(token.len() as u8);
    } else {
        packet.extend_from_slice(&(0x4000 | token.len() as u16).to_be_bytes());
    }
    packet.extend_from_slice(token);
    let remaining = 1200 - packet.len() - 4;
    packet.extend_from_slice(&(0x8000_0000 | remaining as u32).to_be_bytes());
    let pn_offset = packet.len();
    packet.extend_from_slice(&pn.to_be_bytes()[8 - pn_len..]);
    packet.extend_from_slice(&[6, 0, 16]); // CRYPTO, offset zero, 16 bytes
    packet.extend_from_slice(&CRYPTO);
    packet.resize(1200 - TAG_LEN, 0);
    let keys = initial_keys(conn.peer_cid.as_slice(), rustls::Side::Server).unwrap();
    let (head, body) = packet.split_at_mut(pn_offset + pn_len);
    let tag = keys.remote.packet.encrypt_in_place(pn, head, body).unwrap();
    packet.extend_from_slice(tag.as_ref());
    protect_header(keys.remote.header.as_ref(), &mut packet, pn_offset, pn_len).unwrap();
    packet
}

fn check_initial(conn: &Connection, packet: &[u8], token: &[u8], pn: u64, pn_len: usize) {
    assert_eq!(
        packet,
        expected_initial(conn, token, pn, pn_len),
        "token={} pn={pn}",
        token.len()
    );
    let Incoming::Long {
        space,
        pn_offset,
        end,
        ..
    } = header::decode_header(packet, 0).unwrap()
    else {
        panic!("expected Initial");
    };
    assert_eq!(space, Space::Initial);
    assert_eq!(end, 1200);
    let keys = initial_keys(conn.peer_cid.as_slice(), rustls::Side::Server).unwrap();
    let mut plain = packet.to_vec();
    let (_, width) = unprotect_header(keys.remote.header.as_ref(), &mut plain, pn_offset).unwrap();
    assert_eq!(width, pn_len);
    let (head, body) = plain.split_at_mut(pn_offset + pn_len);
    let payload = keys.remote.packet.decrypt_in_place(pn, head, body).unwrap();
    assert_eq!(&payload[..3], &[6, 0, 16]);
    assert_eq!(&payload[3..19], &CRYPTO);
    assert!(payload[19..].iter().all(|&byte| byte == 0));
}

#[test]
fn retry_initial_wire_survives_loss_reordering_and_empty_builds() {
    for token_len in [1, 63, 64, 256, 1000] {
        let token: Vec<u8> = (0..token_len).map(|n| (n ^ (n >> 8)) as u8).collect();
        for (pn, width) in [(1, 1), (253, 1), (255, 2), (65535, 3), (16777215, 4)] {
            let now = Instant::now();
            let mut conn = retried(&token, now);
            conn.spaces[0].next_packet_number = pn;
            let token_ptr = conn.retry_token.as_ptr();
            let mut first = vec![0xba; 13];
            assert!(
                conn.write_packet(Space::Initial, now, &mut first, 13, false, Some(1200))
                    .unwrap()
            );
            assert_eq!(&first[..13], &[0xba; 13]);
            check_initial(&conn, &first[13..], &token, pn, width);
            assert_eq!(conn.spaces[0].next_packet_number, pn + 1);
            let deadline = conn.poll_timeout().unwrap();
            let saved = first.clone();
            assert!(
                !conn
                    .write_packet(
                        Space::Initial,
                        now,
                        &mut first,
                        saved.len(),
                        false,
                        Some(1200)
                    )
                    .unwrap()
            );
            assert_eq!(first, saved, "empty output must roll back its header");
            assert_eq!(conn.spaces[0].next_packet_number, pn + 1);
            assert_eq!(conn.poll_timeout(), Some(deadline));
            assert_eq!(conn.spaces[0].sent.bytes_in_flight(), 1200);

            // Withhold the first flight; the real PTO rewinds CRYPTO. Deliver
            // its replacement before the original and acknowledge in that order.
            conn.handle_timeout(deadline);
            assert_eq!(conn.spaces[0].crypto_sent, 0);
            let mut replacement = Vec::new();
            assert!(
                conn.write_packet(
                    Space::Initial,
                    deadline,
                    &mut replacement,
                    0,
                    false,
                    Some(1200)
                )
                .unwrap()
            );
            check_initial(&conn, &replacement, &token, pn + 1, width);
            check_initial(&conn, &first[13..], &token, pn, width);
            conn.on_ack(Space::Initial, pn + 1, 0, 0, &[], deadline)
                .unwrap();
            conn.on_ack(Space::Initial, pn, 0, 0, &[], deadline)
                .unwrap();
            assert_eq!(conn.spaces[0].sent.bytes_in_flight(), 0);
            assert_eq!(conn.spaces[0].next_packet_number, pn + 2);
            assert_eq!(conn.retry_token, token);
            assert_eq!(conn.retry_token.as_ptr(), token_ptr);
        }
    }
}

#[test]
fn a_retry_token_is_not_written_into_a_coalesced_handshake() {
    let now = Instant::now();
    let token = [0x98; 64];
    let mut conn = retried(&token, now);
    with_handshake_keys(&mut conn);
    conn.spaces[1].crypto_out = CRYPTO.to_vec();
    let mut out = vec![0x5a; 7];
    assert!(
        conn.write_packet(Space::Initial, now, &mut out, 7, false, None)
            .unwrap()
    );
    let start = out.len();
    assert!(
        conn.write_packet(Space::Handshake, now, &mut out, 7, false, Some(1200))
            .unwrap()
    );
    assert_eq!(&out[..7], &[0x5a; 7]);
    assert_eq!(out.len(), 1207);
    let Incoming::Long {
        space,
        pn_offset,
        end,
        ..
    } = header::decode_header(&out[start..], 0).unwrap()
    else {
        panic!("expected Handshake");
    };
    assert_eq!(space, Space::Handshake);
    assert_eq!(pn_offset, 11 + conn.peer_cid.len() + conn.local_cid.len());
    assert_eq!(end, out.len() - start);
    let keys = initial_keys(&[9; 8], rustls::Side::Server).unwrap();
    let (_, width) =
        unprotect_header(keys.remote.header.as_ref(), &mut out[start..], pn_offset).unwrap();
    let (head, body) = out[start..].split_at_mut(pn_offset + width);
    let plain = keys.remote.packet.decrypt_in_place(0, head, body).unwrap();
    assert_eq!(&plain[..3], &[6, 0, 16]);
    assert_eq!(&plain[3..19], &CRYPTO);
    assert!(plain[19..].iter().all(|&byte| byte == 0));
    assert_eq!(conn.retry_token, token);
}
