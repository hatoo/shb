//! Exercise the backlog with bounded rustls writes and real decrypted peers.

use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;

use rustls::{ServerConfig, ServerConnection, SupportedProtocolVersion};

use super::{TlsSession, setup};

const VERSIONS: [&SupportedProtocolVersion; 2] = [&rustls::version::TLS12, &rustls::version::TLS13];

fn pair(version: &'static SupportedProtocolVersion) -> (TlsSession, ServerConnection) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap();
    (
        TlsSession::new(&setup("localhost", b"http/1.1").unwrap()).unwrap(),
        ServerConnection::new(Arc::new(config)).unwrap(),
    )
}

fn pattern(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| ((i + seed) % 251) as u8).collect()
}

// The peer's plaintext buffer is also bounded. Drain it between reads so a
// large encrypted flight is verified in full, including record boundaries.
fn receive(server: &mut ServerConnection, mut wire: &[u8]) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0; 997];
    while !wire.is_empty() {
        assert!(server.read_tls(&mut wire).unwrap() > 0);
        server.process_new_packets().unwrap();
        loop {
            match server.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => panic!("peer read: {e}"),
            }
        }
    }
    got
}

fn exchange(client: &mut TlsSession, server: &mut ServerConnection) -> (Vec<u8>, Vec<u8>) {
    let mut upload = Vec::new();
    let mut download = Vec::new();
    let mut scratch = [0; 1031];
    for _ in 0..16 {
        let sent = client.take_ciphertext().unwrap();
        upload.extend(receive(server, &sent));
        let mut reply = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut reply).unwrap();
        }
        client
            .feed_into(&reply, &mut scratch, |bytes| {
                download.extend_from_slice(bytes);
                Ok(())
            })
            .unwrap();
        if sent.is_empty() && reply.is_empty() {
            assert!(!client.is_handshaking());
            assert!(!server.is_handshaking());
            return (upload, download);
        }
    }
    panic!("TLS exchange did not quiesce");
}

#[test]
fn large_pre_handshake_backlog_preserves_every_byte_and_can_be_reused() {
    for version in VERSIONS {
        let (mut client, mut server) = pair(version);
        client.conn.set_buffer_limit(Some(4096));
        for round in 0..3 {
            let data = pattern(1024 * 1024 + 37, round);
            client.write_plaintext(&data).unwrap();
            assert!(client.pending_pos > 0);
            assert!(client.pending_pos < client.pending_plaintext.len());
            let (got, reply) = exchange(&mut client, &mut server);
            assert_eq!(got, data);
            assert!(reply.is_empty());
            assert!(client.pending_plaintext.is_empty());
            assert_eq!(client.pending_pos, 0);
            client.write_plaintext(&[]).unwrap();
            assert!(client.take_ciphertext().unwrap().is_empty());
        }
    }
}

#[test]
fn append_to_a_blocked_backlog_preserves_order_with_and_without_compaction() {
    for version in VERSIONS {
        // A half-consumed, full buffer can reclaim room; a smaller consumed
        // prefix must not trigger repeated large suffix moves. Spare tail
        // capacity needs no compaction at all.
        for (initial, capacity) in [(8192, 8192), (16384, 16384), (8192, 16384)] {
            let (mut client, mut server) = pair(version);
            client.conn.set_buffer_limit(Some(4096));
            client.pending_plaintext = Vec::with_capacity(capacity);
            let mut want = pattern(initial, 7);
            let tail = pattern(4096, 19);
            client.write_plaintext(&want).unwrap();
            assert_eq!(client.pending_pos, 4096);
            // Empty writes while blocked must neither lose the offset nor
            // manufacture ciphertext capacity.
            client.write_plaintext(&[]).unwrap();
            assert_eq!(client.pending_pos, 4096);
            client.write_plaintext(&tail).unwrap();
            want.extend_from_slice(&tail);
            if initial == capacity && initial == 8192 {
                assert_eq!(client.pending_pos, 0);
                assert_eq!(client.pending_plaintext.capacity(), capacity);
            } else {
                assert_eq!(client.pending_pos, 4096);
            }
            assert_eq!(exchange(&mut client, &mut server).0, want);
            assert_eq!(client.pending_pos, 0);
        }
    }
}

#[test]
fn zero_capacity_backlog_waits_then_resumes() {
    for version in VERSIONS {
        let (mut client, mut server) = pair(version);
        client.conn.set_buffer_limit(Some(0));
        let mut want = pattern(131_073, 4);
        client.write_plaintext(&want).unwrap();
        assert_eq!(client.pending_pos, 0);
        assert!(exchange(&mut client, &mut server).0.is_empty());
        let tail = pattern(521, 83);
        client.write_plaintext(&tail).unwrap();
        want.extend_from_slice(&tail);
        client.conn.set_buffer_limit(Some(1024));
        assert_eq!(exchange(&mut client, &mut server).0, want);
    }
}

#[test]
fn incoming_reply_does_not_disturb_a_partially_accepted_upload() {
    for version in VERSIONS {
        let (mut client, mut server) = pair(version);
        exchange(&mut client, &mut server);
        client.conn.set_buffer_limit(Some(4096));
        let mut want = pattern(128 * 1024 + 3, 47);
        client.write_plaintext(&want).unwrap();
        server.writer().write_all(b"early response").unwrap();
        let mut reply = Vec::new();
        server.write_tls(&mut reply).unwrap();
        let mut received = Vec::new();
        client
            .feed_into(&reply, &mut [0; 7], |part| {
                received.extend_from_slice(part);
                Ok(())
            })
            .unwrap();
        assert_eq!(received, b"early response");
        let tail = pattern(128 * 1024 + 17, 131);
        client.write_plaintext(&tail).unwrap();
        want.extend_from_slice(&tail);
        assert_eq!(exchange(&mut client, &mut server).0, want);
    }
}

#[test]
fn close_notify_discards_only_the_unaccepted_suffix() {
    for version in VERSIONS {
        let (mut client, mut server) = pair(version);
        exchange(&mut client, &mut server);
        client.conn.set_buffer_limit(Some(1024));
        let want = pattern(128 * 1024, 23);
        client.write_plaintext(&want).unwrap();
        let accepted = client.pending_pos;
        assert!(accepted > 0 && accepted < want.len());
        client.send_close_notify();
        assert!(client.pending_plaintext.is_empty());
        assert_eq!(client.pending_pos, 0);
        assert_eq!(exchange(&mut client, &mut server).0, want[..accepted]);
        assert_eq!(server.reader().read(&mut [0; 1]).unwrap(), 0);
        assert!(client.take_ciphertext().unwrap().is_empty());
    }
}

fn record_shapes(mut wire: &[u8]) -> Vec<(u8, usize)> {
    let mut records = Vec::new();
    while !wire.is_empty() {
        assert!(wire.len() >= 5);
        let size = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        assert!(wire.len() >= size + 5);
        records.push((wire[0], size));
        wire = &wire[size + 5..];
    }
    records
}

fn flush_input(client: &mut TlsSession, data: &[u8], out: &mut Vec<u8>, combined: bool) {
    if combined {
        client
            .write_plaintext_and_take_ciphertext(data, out)
            .unwrap();
    } else {
        // The sequential write/drain, retained as an independent
        // reference for record boundaries and the order of accepted bytes.
        client.write_plaintext(data).unwrap();
        client.take_ciphertext_into(out).unwrap();
    }
}

#[test]
fn combined_flush_matches_queued_records_and_plaintext_at_buffer_boundaries() {
    for version in VERSIONS {
        for limit in [Some(0), Some(1), Some(1024), Some(65536), None] {
            let (mut client, mut server) = pair(version);
            let (mut reference, mut peer) = pair(version);
            exchange(&mut client, &mut server);
            exchange(&mut reference, &mut peer);
            client.conn.set_buffer_limit(limit);
            reference.conn.set_buffer_limit(limit);
            let sizes: &[usize] = if limit == Some(1) {
                &[0, 1, 73]
            } else {
                &[0, 256, 16384, 65536, 131073, 1048613]
            };
            let mut out = vec![0xaa; 19];
            let mut expected = out.clone();
            for &size in sizes {
                let data = pattern(size, 37);
                flush_input(&mut client, &data, &mut out, true);
                flush_input(&mut reference, &data, &mut expected, false);
                assert_eq!(record_shapes(&out), record_shapes(&expected));
                assert_eq!(
                    &client.pending_plaintext[client.pending_pos..],
                    &reference.pending_plaintext[reference.pending_pos..]
                );
                let got = receive(&mut server, &out);
                assert_eq!(got, receive(&mut peer, &expected));
                if limit == Some(0) {
                    assert!(got.is_empty());
                    client.conn.set_buffer_limit(Some(4096));
                    reference.conn.set_buffer_limit(Some(4096));
                    assert_eq!(exchange(&mut client, &mut server).0, data);
                    assert_eq!(exchange(&mut reference, &mut peer).0, data);
                    client.conn.set_buffer_limit(limit);
                    reference.conn.set_buffer_limit(limit);
                } else {
                    assert_eq!(got, data);
                    assert!(client.pending_plaintext.is_empty());
                    assert_eq!(client.pending_plaintext.capacity(), 0);
                }
                assert_eq!(client.pending_pos, 0);
            }
        }
    }
}

#[test]
fn combined_flush_keeps_queued_ciphertext_and_backlog_ahead_of_new_bytes() {
    for version in VERSIONS {
        for prefix_len in [317, 8192, 131073] {
            let (mut client, mut server) = pair(version);
            let (mut reference, mut peer) = pair(version);
            exchange(&mut client, &mut server);
            exchange(&mut reference, &mut peer);
            client.conn.set_buffer_limit(Some(4096));
            reference.conn.set_buffer_limit(Some(4096));
            let mut want = pattern(prefix_len, 11);
            client.write_plaintext(&want).unwrap();
            reference.write_plaintext(&want).unwrap();
            let tail = pattern(1048613, 41);
            let mut out = Vec::new();
            let mut expected = Vec::new();
            flush_input(&mut client, &tail, &mut out, true);
            flush_input(&mut reference, &tail, &mut expected, false);
            want.extend_from_slice(&tail);
            assert_eq!(record_shapes(&out), record_shapes(&expected));
            assert_eq!(receive(&mut server, &out), want);
            assert_eq!(receive(&mut peer, &expected), want);
            assert!(client.pending_plaintext.is_empty());
            assert_eq!(client.pending_pos, 0);
        }
    }
}

#[test]
fn combined_flush_owns_handshake_and_zero_progress_suffixes() {
    for version in VERSIONS {
        for established in [false, true] {
            for limit in [0, 4096] {
                let (mut client, mut server) = pair(version);
                if established {
                    exchange(&mut client, &mut server);
                }
                client.conn.set_buffer_limit(Some(limit));
                let want = pattern(131073, 7);
                let mut borrowed = want.clone();
                let mut out = vec![0xff; 19];
                client
                    .write_plaintext_and_take_ciphertext(&borrowed, &mut out)
                    .unwrap();
                // The caller may immediately overwrite its recycled input.
                borrowed.fill(0xcc);
                drop(borrowed);
                let mut got = receive(&mut server, &out);
                client.conn.set_buffer_limit(Some(4096));
                got.extend(exchange(&mut client, &mut server).0);
                assert_eq!(got, want);
                assert!(client.pending_plaintext.is_empty());
                assert_eq!(client.pending_pos, 0);
            }
        }
    }
}

#[test]
fn combined_flush_preserves_close_notify_and_existing_discard_behavior() {
    for version in VERSIONS {
        let mut shapes = Vec::new();
        for combined in [false, true] {
            let (mut client, mut server) = pair(version);
            exchange(&mut client, &mut server);
            client.conn.set_buffer_limit(Some(1024));
            let prefix = pattern(16384, 17);
            client.write_plaintext(&prefix).unwrap();
            let accepted = client.pending_pos;
            client.send_close_notify();
            let tail = pattern(521, 19);
            let mut out = Vec::new();
            flush_input(&mut client, &tail, &mut out, combined);
            shapes.push(record_shapes(&out));
            assert_eq!(receive(&mut server, &out), prefix[..accepted]);
            assert_eq!(server.reader().read(&mut [0; 1]).unwrap(), 0);
            // rustls consumes and discards writes after our close_notify;
            // neither path may put these bytes after the alert on the wire.
            assert!(client.pending_plaintext.is_empty());
            assert_eq!(client.pending_pos, 0);
            assert!(client.take_ciphertext().unwrap().is_empty());
        }
        assert_eq!(shapes[0], shapes[1]);
    }
}

#[test]
fn combined_flush_after_peer_close_preserves_existing_half_close_behavior() {
    for version in VERSIONS {
        let mut shapes = Vec::new();
        for combined in [false, true] {
            let (mut client, mut server) = pair(version);
            exchange(&mut client, &mut server);
            server.send_close_notify();
            let mut reply = Vec::new();
            server.write_tls(&mut reply).unwrap();
            client.feed_into(&reply, &mut [0; 7], |_| Ok(())).unwrap();
            assert!(client.peer_closed());
            let data = pattern(131073, 73);
            let mut out = Vec::new();
            flush_input(&mut client, &data, &mut out, combined);
            shapes.push(record_shapes(&out));
            assert_eq!(receive(&mut server, &out), data);
        }
        assert_eq!(shapes[0], shapes[1]);
    }
}

#[test]
fn combined_empty_flush_drains_the_same_alert_after_corrupt_ciphertext() {
    for version in VERSIONS {
        let mut shapes = Vec::new();
        for combined in [false, true] {
            let (mut client, mut server) = pair(version);
            exchange(&mut client, &mut server);
            server.writer().write_all(b"authenticate this").unwrap();
            let mut reply = Vec::new();
            server.write_tls(&mut reply).unwrap();
            *reply.last_mut().unwrap() ^= 1;
            assert!(
                client
                    .feed_into(&reply, &mut [0; 17], |_| panic!(
                        "unauthenticated plaintext"
                    ))
                    .is_err()
            );
            let mut out = vec![0xaa; 19];
            flush_input(&mut client, &[], &mut out, combined);
            assert!(!out.is_empty());
            shapes.push(record_shapes(&out));
            server.read_tls(&mut &out[..]).unwrap();
            assert!(matches!(
                server.process_new_packets(),
                Err(rustls::Error::AlertReceived(_))
            ));
        }
        assert_eq!(shapes[0], shapes[1]);
    }
}
