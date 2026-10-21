//! Protected packets, including byte-for-byte replays. No packet is injected
//! through handle_frame: header protection and AEAD run on every receipt.

use super::*;

fn receiver() -> Connection {
    let mut conn = client();
    conn.spaces[Space::Handshake as usize].keys =
        Some(initial_keys(&[8; 8], rustls::Side::Client).unwrap());
    conn.one_rtt_remote = Some(initial_keys(&[9; 8], rustls::Side::Client).unwrap().remote);
    conn.one_rtt_local = Some(initial_keys(&[9; 8], rustls::Side::Client).unwrap().local);
    conn.connected = true;
    conn.max_data_peer = 1 << 20;
    conn.test_send_limits(128, 1 << 20);
    conn
}

fn protected(conn: &Connection, space: Space, pn: u64, payload: &[u8]) -> Vec<u8> {
    let dcid = match space {
        Space::Initial => conn.original_dcid,
        Space::Handshake => ConnectionId::new(&[8; 8]).unwrap(),
        Space::Data => ConnectionId::new(&[9; 8]).unwrap(),
    };
    let keys = initial_keys(dcid.as_slice(), rustls::Side::Server).unwrap();
    seal(
        conn,
        space,
        pn,
        false,
        &keys.local,
        keys.local.packet.as_ref(),
        payload,
    )
}

fn seal(
    conn: &Connection,
    space: Space,
    pn: u64,
    phase: bool,
    keys: &DirectionalKeys,
    packet_key: &dyn rustls::quic::PacketKey,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    if space == Space::Data {
        header::put_short_header(&mut out, &conn.local_cid, 4, phase);
    } else {
        LongHeader {
            space,
            dcid: conn.local_cid,
            scid: ConnectionId::new(&[7; 8]).unwrap(),
            token: Vec::new(),
        }
        .put(&mut out, 4, 4 + payload.len() + TAG_LEN);
    }
    let pn_offset = out.len();
    out.extend_from_slice(&(pn as u32).to_be_bytes());
    out.extend_from_slice(payload);
    let (head, body) = out.split_at_mut(pn_offset + 4);
    let tag = packet_key.encrypt_in_place(pn, head, body).unwrap();
    out.extend_from_slice(tag.as_ref());
    protect_header(keys.header.as_ref(), &mut out, pn_offset, 4).unwrap();
    out
}

fn receive(conn: &mut Connection, now: Instant, wire: &[u8]) {
    conn.handle_datagram(now, &mut wire.to_vec()).unwrap();
}

#[test]
fn duplicate_packets_preserve_pending_probes_in_every_number_space() {
    for space in [Space::Initial, Space::Handshake, Space::Data] {
        let mut conn = receiver();
        let now = Instant::now();
        let packet = protected(&conn, space, 0, &[frame::PING as u8]);
        receive(&mut conn, now, &packet);
        assert_eq!(conn.spaces[space as usize].largest_received, Some(0));
        conn.spaces[space as usize].ack.take_pending();
        conn.pto_count = 3;
        conn.pto_probes = 2;
        conn.pto_space = space;
        receive(&mut conn, now + Duration::from_millis(50), &packet);
        assert_eq!((conn.pto_count, conn.pto_probes), (3, 2), "{space:?}");
        // Discarded packets do not generate ACKs; a retransmission in a new
        // packet is processed and acknowledged normally.
        assert!(!conn.spaces[space as usize].ack.take_pending());
        assert_eq!(conn.pto_space, space);
    }
}

#[test]
fn duplicate_path_challenge_is_not_dispatched_after_ack_of_ack() {
    let mut conn = receiver();
    let now = Instant::now();
    let mut payload = vec![frame::PATH_CHALLENGE as u8];
    payload.extend_from_slice(b"original");
    let original = protected(&conn, Space::Data, 0, &payload);
    receive(&mut conn, now, &original);
    assert_eq!(conn.path_response.take(), Some(*b"original"));
    conn.spaces[Space::Data as usize].sent.push(SentPacket {
        number: 7,
        time_sent: now,
        size: 40,
        ack_eliciting: false,
        ack_largest: Some(0),
        frames: Vec::new(),
    });
    conn.on_ack(Space::Data, 7, 0, 0, &[], now).unwrap();
    assert!(conn.spaces[Space::Data as usize].ack.ranges().is_empty());
    receive(&mut conn, now + Duration::from_millis(100), &original);
    assert_eq!(
        conn.path_response, None,
        "ACK pruning must not enable replay"
    );

    // The same frame retransmitted in a new packet is still processed.
    let retry = protected(&conn, Space::Data, 1, &payload);
    receive(&mut conn, now + Duration::from_millis(200), &retry);
    assert_eq!(conn.path_response.take(), Some(*b"original"));
}

#[test]
fn duplicate_stream_does_not_repeat_readable_or_finished_events() {
    let mut conn = receiver();
    let now = Instant::now();
    let (id, _) = conn.send_oneshot(b"request").unwrap();
    let mut payload = Vec::new();
    frame::put_stream(&mut payload, id, 0, true, b"response");
    let packet = protected(&conn, Space::Data, 0, &payload);
    receive(&mut conn, now, &packet);
    assert!(conn.events.contains(&Event::Readable(id)));
    assert!(conn.events.contains(&Event::Finished { id, reset: None }));
    conn.events.clear();
    let received = conn.data_received;
    for _ in 0..64 {
        receive(&mut conn, now, &packet);
    }
    assert!(
        conn.events.is_empty(),
        "replayed frame events: {:?}",
        conn.events
    );
    assert_eq!(conn.data_received, received);
    assert_eq!(received, 8);
}

#[test]
fn replayed_ack_only_packet_neither_cancels_probes_nor_creates_ack_loop() {
    let mut conn = receiver();
    let now = Instant::now();
    let mut payload = Vec::new();
    frame::put_ack(&mut payload, &[(0, 0)], 0);
    let packet = protected(&conn, Space::Data, 0, &payload);
    receive(&mut conn, now, &packet);
    conn.pto_count = 2;
    conn.pto_probes = 1;
    conn.needs_send = false;
    for _ in 0..8 {
        receive(&mut conn, now, &packet);
    }
    assert!(!conn.spaces[Space::Data as usize].ack.ack_eliciting_pending);
    assert!(!conn.needs_send);
    assert_eq!((conn.pto_count, conn.pto_probes), (2, 1));
}

#[test]
fn unauthenticated_packets_cannot_poison_history_or_refresh_idle() {
    let mut conn = receiver();
    let now = Instant::now();
    let original = protected(&conn, Space::Data, 0, &[frame::PING as u8]);
    receive(&mut conn, now, &original);
    let deadline = conn.idle_deadline;
    conn.pto_count = 3;
    conn.pto_probes = 2;
    conn.spaces[Space::Data as usize].ack.take_pending();
    for pn in [0, 1, 1000] {
        let mut forged = protected(&conn, Space::Data, pn, &[frame::PING as u8]);
        *forged.last_mut().unwrap() ^= 1;
        receive(&mut conn, now + Duration::from_millis(50), &forged);
        assert_eq!(conn.idle_deadline, deadline);
        assert_eq!(conn.spaces[Space::Data as usize].largest_received, Some(0));
        assert_eq!((conn.pto_count, conn.pto_probes), (3, 2));
        assert!(!conn.spaces[Space::Data as usize].ack.ack_eliciting_pending);
    }
    let valid = protected(&conn, Space::Data, 1, &[frame::PING as u8]);
    receive(&mut conn, now + Duration::from_millis(100), &valid);
    assert_eq!(conn.spaces[Space::Data as usize].largest_received, Some(1));
    assert!(conn.spaces[Space::Data as usize].ack.take_pending());
    assert_eq!((conn.pto_count, conn.pto_probes), (0, 0));
}

#[test]
fn ack_pruning_preserves_unseen_gaps_and_the_original_ack_delay() {
    let mut conn = receiver();
    let now = Instant::now();
    for pn in [0, 2] {
        let packet = protected(&conn, Space::Data, pn, &[frame::PING as u8]);
        receive(&mut conn, now, &packet);
    }
    let later = now + Duration::from_millis(50);
    let duplicate = protected(&conn, Space::Data, 2, &[frame::PING as u8]);
    let ack = &mut conn.spaces[Space::Data as usize].ack;
    let delay = ack.delay(later, 3);
    assert!(ack.ack_eliciting_pending);
    receive(&mut conn, later, &duplicate);
    let ack = &mut conn.spaces[Space::Data as usize].ack;
    assert_eq!(ack.delay(later, 3), delay);
    assert!(ack.take_pending(), "a duplicate cannot cancel an owed ACK");
    ack.trim_below(2);
    receive(&mut conn, later, &duplicate);
    assert!(conn.spaces[Space::Data as usize].ack.ranges().is_empty());
    let reordered = protected(&conn, Space::Data, 1, &[frame::PING as u8]);
    receive(&mut conn, later, &reordered);
    assert_eq!(conn.spaces[Space::Data as usize].ack.ranges(), &[(1, 1)]);
    assert!(conn.spaces[Space::Data as usize].ack.take_pending());
    assert_eq!(conn.spaces[Space::Data as usize].largest_received, Some(2));
}

#[test]
fn history_survives_key_updates_and_accepts_unseen_previous_key_packets() {
    let mut conn = receiver();
    let now = Instant::now();
    let old = protected(&conn, Space::Data, 0, &[frame::PING as u8]);
    receive(&mut conn, now, &old);
    let next = initial_keys(&[10; 8], rustls::Side::Client).unwrap();
    conn.next_1rtt = Some(rustls::quic::PacketKeySet {
        local: next.local.packet,
        remote: next.remote.packet,
    });
    let hp = initial_keys(&[9; 8], rustls::Side::Server).unwrap();
    let next_keys = initial_keys(&[10; 8], rustls::Side::Server).unwrap();
    let new = seal(
        &conn,
        Space::Data,
        2,
        true,
        &hp.local,
        next_keys.local.packet.as_ref(),
        &[frame::PING as u8],
    );
    receive(&mut conn, now, &new);
    assert!(conn.key_phase);
    assert_eq!(conn.rotate_at, 2);
    conn.pto_count = 3;
    conn.pto_probes = 2;
    for packet in [&old, &new] {
        receive(&mut conn, now, packet);
        assert_eq!((conn.pto_count, conn.pto_probes), (3, 2));
        assert_eq!(conn.rotate_at, 2);
    }
    // It was delayed, not previously received. Old keys remain usable.
    let reordered = protected(&conn, Space::Data, 1, &[frame::PING as u8]);
    receive(&mut conn, now, &reordered);
    assert_eq!((conn.pto_count, conn.pto_probes), (0, 0));
    assert_eq!(conn.spaces[Space::Data as usize].ack.ranges(), &[(0, 2)]);
    assert!(conn.key_phase);
}

#[test]
fn evicted_replays_are_dropped_but_new_packet_retransmissions_still_progress() {
    let mut conn = receiver();
    let now = Instant::now();
    let (id, _) = conn.send_oneshot(b"request").unwrap();
    let mut response = Vec::new();
    frame::put_stream(&mut response, id, 0, true, b"response");
    let delayed = protected(&conn, Space::Data, 1, &response);
    let original = protected(&conn, Space::Data, 0, &[frame::PING as u8]);
    receive(&mut conn, now, &original);
    for pn in (2..=1024).step_by(2) {
        let packet = protected(&conn, Space::Data, pn, &[frame::PING as u8]);
        receive(&mut conn, now, &packet);
    }
    conn.pto_count = 3;
    conn.pto_probes = 2;
    for packet in [&original, &delayed] {
        receive(&mut conn, now, packet);
        assert_eq!((conn.pto_count, conn.pto_probes), (3, 2));
        assert_eq!(conn.data_received, 0);
    }
    let retry = protected(&conn, Space::Data, 1025, &response);
    receive(&mut conn, now, &retry);
    assert_eq!(conn.data_received, 8);
    assert_eq!(conn.unanswered, 0);
    assert_eq!(
        conn.events
            .iter()
            .filter(|e| matches!(e, Event::Finished { .. }))
            .count(),
        1
    );
}

#[test]
fn a_duplicate_coalesced_packet_does_not_hide_the_next_number_space() {
    let mut conn = receiver();
    let now = Instant::now();
    let initial = protected(&conn, Space::Initial, 0, &[frame::PING as u8]);
    let handshake = protected(&conn, Space::Handshake, 0, &[frame::PING as u8]);
    receive(&mut conn, now, &initial);
    let mut coalesced = initial.clone();
    coalesced.extend_from_slice(&handshake);
    receive(&mut conn, now, &coalesced);
    assert_eq!(
        conn.spaces[Space::Handshake as usize].largest_received,
        Some(0)
    );
    assert!(conn.spaces[Space::Handshake as usize].ack.take_pending());
}

#[test]
fn a_new_authenticated_malformed_packet_still_reports_its_error() {
    let mut conn = receiver();
    // PATH_CHALLENGE with its eight-byte body missing.
    let mut malformed = protected(&conn, Space::Data, 0, &[frame::PATH_CHALLENGE as u8]);
    assert!(
        conn.handle_datagram(Instant::now(), &mut malformed)
            .is_err()
    );
}

#[test]
fn sparse_ack_only_eviction_preserves_replay_protection_in_every_space() {
    for space in [Space::Initial, Space::Handshake, Space::Data] {
        let mut conn = receiver();
        let now = Instant::now();
        let mut payload = Vec::new();
        frame::put_ack(&mut payload, &[(0, 0)], 0);
        let original = protected(&conn, space, 0, &payload);
        for pn in (0..160).step_by(2) {
            let packet = protected(&conn, space, pn, &payload);
            receive(&mut conn, now, &packet);
        }
        assert!(!conn.spaces[space as usize].ack.ack_eliciting_pending);
        let newest = protected(&conn, space, 160, &[frame::PING as u8]);
        receive(&mut conn, now, &newest);
        let later = now + Duration::from_millis(50);
        let delay = conn.spaces[space as usize].ack.delay(later, 3);
        conn.pto_count = 3;
        conn.pto_probes = 2;
        receive(&mut conn, later, &original);
        assert_eq!((conn.pto_count, conn.pto_probes), (3, 2));
        assert_eq!(conn.spaces[space as usize].ack.delay(later, 3), delay);

        let mut out = Vec::new();
        let filled = conn
            .fill_payload(space, later, &mut out, 1200, &mut Vec::new(), false)
            .unwrap();
        assert_eq!(filled.ack_largest, Some(160));
        let Frame::Ack {
            largest,
            first_range,
            ranges,
            delay: wire_delay,
            ..
        } = frame::Iter::new(&out).next().unwrap().unwrap()
        else {
            panic!("expected ACK");
        };
        assert_eq!(wire_delay, delay);
        assert_eq!(
            AckRanges::new(largest, first_range, ranges).collect::<Vec<_>>(),
            (49..=80).rev().map(|n| (n * 2, n * 2)).collect::<Vec<_>>()
        );

        conn.spaces[space as usize].sent.push(SentPacket {
            number: 7,
            time_sent: now,
            size: 80,
            ack_eliciting: false,
            ack_largest: filled.ack_largest,
            frames: Vec::new(),
        });
        conn.on_ack(space, 7, 0, 0, &[], later).unwrap();
        assert!(conn.spaces[space as usize].ack.ranges().is_empty());
        receive(&mut conn, later, &original);
        receive(&mut conn, later, &newest);
        assert!(conn.spaces[space as usize].ack.ranges().is_empty());
        assert!(!conn.spaces[space as usize].ack.take_pending());
        assert_eq!(conn.spaces[space as usize].largest_received, Some(160));
        let reordered = protected(&conn, space, 159, &[frame::PING as u8]);
        receive(&mut conn, later, &reordered);
        assert_eq!(conn.spaces[space as usize].ack.ranges(), &[(159, 159)]);
        assert!(conn.spaces[space as usize].ack.take_pending());
        assert_eq!(conn.spaces[space as usize].largest_received, Some(160));
    }
}

#[test]
fn ack_eviction_preserves_delayed_stream_bytes_and_new_packet_retransmissions() {
    let mut conn = receiver();
    let now = Instant::now();
    let (id, _) = conn.send_oneshot(b"request").unwrap();
    let mut response = Vec::new();
    frame::put_stream(&mut response, id, 0, false, b"first");
    let original = protected(&conn, Space::Data, 0, &response);
    receive(&mut conn, now, &original);
    for pn in (2..160).step_by(2) {
        let packet = protected(&conn, Space::Data, pn, &[frame::PING as u8]);
        receive(&mut conn, now, &packet);
    }
    response.clear();
    frame::put_stream(&mut response, id, 5, true, b"second");
    let delayed = protected(&conn, Space::Data, 1, &response);
    receive(&mut conn, now, &delayed);
    assert_eq!(conn.data_received, 11);
    assert_eq!(conn.unanswered, 0);
    assert_eq!(
        conn.events
            .iter()
            .filter(|e| matches!(e, Event::Finished { .. }))
            .count(),
        1
    );
    let pending_events = conn.events.len();
    for packet in [&original, &delayed] {
        receive(&mut conn, now, packet);
        assert_eq!(conn.events.len(), pending_events);
    }
    let retry = protected(&conn, Space::Data, 160, &response);
    receive(&mut conn, now, &retry);
    assert_eq!(conn.data_received, 11);
    assert_eq!(
        conn.events
            .iter()
            .filter(|e| matches!(e, Event::Finished { .. }))
            .count(),
        1
    );
    assert_eq!(
        conn.spaces[Space::Data as usize].ack.ranges()[0],
        (160, 160)
    );
    assert!(conn.spaces[Space::Data as usize].ack.take_pending());
}

#[test]
fn unauthenticated_receive_limit_violation_cannot_close_the_connection() {
    let mut conn = receiver();
    conn.stream_window = 8;
    let (id, _) = conn.send_oneshot(b"request").unwrap();
    let mut payload = Vec::new();
    frame::put_stream(&mut payload, id, 8, true, b"x");
    let valid = protected(&conn, Space::Data, 0, &payload);
    let mut forged = valid.clone();
    *forged.last_mut().unwrap() ^= 1;
    let now = Instant::now();
    receive(&mut conn, now, &forged);
    assert!(conn.closed.is_none());
    assert_eq!(conn.data_received, 0);
    assert!(conn.events.is_empty());
    receive(&mut conn, now, &valid);
    assert!(conn.closed.is_some());
    assert_eq!(conn.close_pending.as_ref().unwrap().code, 0x03);
    assert!(!conn.close_pending.as_ref().unwrap().app);
    assert_eq!(conn.data_received, 0);
    assert!(!conn.recv_mut(id).unwrap().has_data());
    assert_eq!(conn.events.len(), 1);
    assert!(matches!(conn.events.front(), Some(Event::Lost(_))));
    receive(&mut conn, now, &valid);
    assert_eq!(conn.events.len(), 1);
}

#[test]
fn peer_stream_limit_closes_only_for_authenticated_frames() {
    for id in [1, 15, (1 << 62) - 1] {
        for reset in [false, true] {
            let mut conn = receiver();
            let (request, _) = conn.send_oneshot(b"request").unwrap();
            let mut payload = Vec::new();
            if reset {
                frame::put_reset_stream(&mut payload, id, 42, 0);
            } else {
                frame::put_stream(&mut payload, id, 0, false, b"");
            }
            // An invalid frame must stop dispatch before a later frame can
            // turn this request into a successful latency sample.
            frame::put_stream(&mut payload, request, 0, true, b"response");
            let valid = protected(&conn, Space::Data, 0, &payload);
            let mut forged = valid.clone();
            *forged.last_mut().unwrap() ^= 1;
            let now = Instant::now();
            receive(&mut conn, now, &forged);
            assert!(conn.closed.is_none());
            assert!(conn.close_pending.is_none());
            assert!(conn.peer_uni.is_empty());
            assert_eq!(conn.peer_uni.capacity(), 0);
            assert_eq!(conn.data_received, 0);
            assert_eq!(conn.unanswered, 1);
            assert!(conn.events.is_empty());
            receive(&mut conn, now, &valid);
            assert!(conn.closed.is_some());
            assert_eq!(conn.close_pending.as_ref().unwrap().code, 4);
            assert!(!conn.close_pending.as_ref().unwrap().app);
            assert!(conn.peer_uni.is_empty());
            assert_eq!(conn.peer_uni.capacity(), 0);
            assert_eq!(conn.data_received, 0);
            assert_eq!(conn.unanswered, 1);
            assert!(!conn.recv_mut(request).unwrap().has_data());
            assert_eq!(conn.events.len(), 1);
            assert!(matches!(conn.events.front(), Some(Event::Lost(_))));
            receive(&mut conn, now, &valid);
            assert_eq!(conn.events.len(), 1);
        }
    }
}
