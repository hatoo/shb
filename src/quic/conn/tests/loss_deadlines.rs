//! Drive the real ACK and timeout paths with fixed packet histories. No sleeps,
//! network timing, or writes to the cached loss deadlines are involved.

use super::*;

fn connection(now: Instant) -> Connection {
    let mut conn = test_connection();
    conn.rtt
        .update(Duration::from_millis(100), Duration::ZERO, Duration::ZERO);
    conn.rtt_sampled_at = Some(now);
    conn
}

fn ack_only(number: u64, now: Instant) -> SentPacket {
    SentPacket {
        number,
        time_sent: now,
        size: 0,
        ack_eliciting: false,
        ack_largest: None,
        frames: Vec::new(),
    }
}

// Leave packet 0 behind an acknowledged packet 1. ACK-only packet 1 keeps the
// RTT fixed, so all expected deadlines follow from the 100 ms sample above.
fn arm(conn: &mut Connection, space: Space, sent_at: Instant, ack_at: Instant) -> Instant {
    let s = &mut conn.spaces[space as usize];
    s.crypto_out = vec![7; 16];
    s.crypto_sent = 16;
    let mut packet = lost_packet(0, sent_at);
    packet.frames.push(if space == Space::Data {
        SentFrame::RetireConnectionId(7)
    } else {
        SentFrame::Crypto { offset: 4, len: 4 }
    });
    s.sent.push(packet);
    s.sent.push(ack_only(1, sent_at));
    conn.on_ack(space, 1, 0, 0, &[], ack_at).unwrap();
    sent_at + conn.rtt.loss_delay()
}

#[test]
fn ack_in_another_space_preserves_pending_loss() {
    for pending in Space::ALL {
        for other in Space::ALL {
            if pending == other {
                continue;
            }
            let now = Instant::now();
            let mut conn = connection(now);
            let deadline = arm(&mut conn, pending, now, now + Duration::from_millis(10));
            conn.spaces[other as usize].sent.push(ack_only(0, now));
            conn.on_ack(other, 0, 0, 0, &[], now + Duration::from_millis(20))
                .unwrap();
            assert_eq!(conn.poll_timeout(), Some(deadline), "{pending:?}/{other:?}");
            conn.handle_timeout(deadline);
            assert_eq!(conn.spaces[pending as usize].sent.bytes_in_flight(), 0);
            assert_eq!(conn.pto_count, 0, "loss recovery must not wait for PTO");
            if pending == Space::Data {
                assert_eq!(conn.retire_pending, [7]);
            } else {
                assert_eq!(conn.spaces[pending as usize].crypto_sent, 4);
            }
        }
    }
}

#[test]
fn earliest_loss_is_independent_of_ack_space_order() {
    let now = Instant::now();
    for order in [
        [Space::Initial, Space::Handshake, Space::Data],
        [Space::Data, Space::Handshake, Space::Initial],
    ] {
        let mut conn = connection(now);
        // Handshake is earliest regardless of insertion order; neither array
        // position nor the last ACK is a valid choice of connection timer.
        for space in order {
            let offset = match space {
                Space::Handshake => 0,
                Space::Initial => 10,
                Space::Data => 20,
            };
            arm(
                &mut conn,
                space,
                now + Duration::from_millis(offset),
                now + Duration::from_millis(50),
            );
        }
        assert_eq!(conn.poll_timeout(), Some(now + conn.rtt.loss_delay()));
    }
}

#[test]
fn timeout_keeps_the_next_deadline_with_empty_data_space() {
    let now = Instant::now();
    let mut conn = connection(now);
    let ack_at = now + Duration::from_millis(50);
    let second = arm(
        &mut conn,
        Space::Handshake,
        now + Duration::from_millis(20),
        ack_at,
    );
    let first = arm(&mut conn, Space::Initial, now, ack_at);
    assert_eq!(conn.poll_timeout(), Some(first));
    conn.handle_timeout(first);
    assert_eq!(conn.spaces[0].crypto_sent, 4);
    assert_eq!(conn.spaces[1].crypto_sent, 16);
    assert_eq!(conn.poll_timeout(), Some(second));
    conn.handle_timeout(second);
    assert_eq!(conn.spaces[1].crypto_sent, 4);
    assert_eq!(conn.pto_count, 0);
}

#[test]
fn a_longer_rtt_rearms_loss_without_repeating_the_expired_timer() {
    let now = Instant::now();
    let mut conn = connection(now);
    let ack_at = now + Duration::from_millis(50);
    let first = arm(&mut conn, Space::Handshake, now, ack_at);
    arm(
        &mut conn,
        Space::Data,
        now + Duration::from_millis(20),
        ack_at,
    );
    // A sample in another space can lengthen the connection's loss delay
    // before a previously calculated deadline expires.
    conn.rtt
        .update(Duration::from_millis(200), Duration::ZERO, Duration::ZERO);
    conn.handle_timeout(first);
    let next = now + conn.rtt.loss_delay();
    assert!(next > first);
    assert_eq!(conn.poll_timeout(), Some(next));
    assert_eq!(conn.spaces[1].crypto_sent, 16);
    assert_eq!(conn.spaces[1].sent.bytes_in_flight(), 1200);
    assert!(conn.retire_pending.is_empty());
    conn.handle_timeout(next);
    assert_eq!(conn.spaces[1].crypto_sent, 4);
    let data = (now + Duration::from_millis(20)) + conn.rtt.loss_delay();
    assert_eq!(conn.poll_timeout(), Some(data));
    conn.handle_timeout(data);
    assert_eq!(conn.retire_pending, [7]);
    assert!(conn.poll_timeout().is_none());
}

#[test]
fn timeout_keeps_a_later_packet_in_the_same_space() {
    for space in [Space::Initial, Space::Handshake] {
        let now = Instant::now();
        let mut conn = connection(now);
        let later = now + Duration::from_millis(20);
        let s = &mut conn.spaces[space as usize];
        s.crypto_out = vec![7; 16];
        s.crypto_sent = 16;
        for (number, at, offset) in [(0, now, 4), (1, later, 8)] {
            let mut packet = lost_packet(number, at);
            packet.frames.push(SentFrame::Crypto { offset, len: 4 });
            s.sent.push(packet);
        }
        s.sent.push(ack_only(2, later));
        conn.on_ack(space, 2, 0, 0, &[], later + Duration::from_millis(10))
            .unwrap();
        let first = now + conn.rtt.loss_delay();
        let second = later + conn.rtt.loss_delay();
        assert_eq!(conn.poll_timeout(), Some(first));
        conn.handle_timeout(first);
        assert_eq!(conn.spaces[space as usize].crypto_sent, 4);
        assert_eq!(conn.poll_timeout(), Some(second));
        conn.spaces[space as usize].crypto_sent = 16;
        conn.handle_timeout(second);
        assert_eq!(conn.spaces[space as usize].crypto_sent, 8);
        assert_eq!(conn.spaces[space as usize].sent.bytes_in_flight(), 0);
        assert!(conn.poll_timeout().is_none_or(|d| d > second));
        assert!(second > first);
    }
}

#[test]
fn discarding_a_space_removes_only_its_deadline() {
    for discarded in [Space::Initial, Space::Handshake] {
        let now = Instant::now();
        let mut conn = connection(now);
        conn.handshake_done = true;
        let ack_at = now + Duration::from_millis(50);
        let surviving = arm(
            &mut conn,
            Space::Data,
            now + Duration::from_millis(20),
            ack_at,
        );
        arm(&mut conn, discarded, now, ack_at);
        conn.discard_space(discarded);
        assert_eq!(conn.poll_timeout(), Some(surviving));
        conn.handle_timeout(surviving);
        assert_eq!(conn.retire_pending, [7]);
        assert_eq!(conn.pto_count, 0);
        assert!(conn.poll_timeout().is_none());
    }
}

#[test]
fn handshake_confirmation_keeps_application_loss_armed() {
    let now = Instant::now();
    let mut conn = connection(now);
    conn.discard_space(Space::Initial);
    let ack_at = now + Duration::from_millis(50);
    let data_deadline = arm(
        &mut conn,
        Space::Data,
        now + Duration::from_millis(20),
        ack_at,
    );
    arm(&mut conn, Space::Handshake, now, ack_at);
    conn.on_handshake_done();
    assert_eq!(conn.poll_timeout(), Some(data_deadline));
    conn.handle_timeout(data_deadline);
    assert_eq!(conn.retire_pending, [7]);
    assert!(conn.poll_timeout().is_none());
}

#[test]
fn reordered_and_late_acks_do_not_recover_frames_twice() {
    let now = Instant::now();
    let mut conn = connection(now);
    conn.handshake_done = true;
    let deadline = arm(&mut conn, Space::Data, now, now + Duration::from_millis(10));
    conn.handle_timeout(deadline);
    assert_eq!(conn.retire_pending, [7]);
    assert!(conn.poll_timeout().is_none());
    let window = conn.congestion.window;
    // Duplicated ACK of 1 and a late ACK for the lost 0 cannot deliver its
    // loss callback twice or resurrect a stale deadline.
    conn.on_ack(Space::Data, 1, 0, 0, &[], deadline).unwrap();
    conn.on_ack(Space::Data, 0, 0, 0, &[], deadline).unwrap();
    conn.handle_timeout(deadline + Duration::from_millis(1));
    assert_eq!(conn.retire_pending, [7]);
    assert_eq!(conn.congestion.window, window);
    assert_eq!(conn.pto_count, 0);
    assert!(conn.poll_timeout().is_none());
}

#[test]
fn reordered_ack_cancels_only_its_own_loss() {
    let now = Instant::now();
    let mut conn = connection(now);
    let ack_at = now + Duration::from_millis(50);
    let data = arm(
        &mut conn,
        Space::Data,
        now + Duration::from_millis(20),
        ack_at,
    );
    arm(&mut conn, Space::Handshake, now, ack_at);
    conn.on_ack(Space::Handshake, 0, 0, 0, &[], ack_at).unwrap();
    assert_eq!(conn.poll_timeout(), Some(data));
    conn.handle_timeout(data);
    assert_eq!(
        conn.spaces[1].crypto_sent, 16,
        "acknowledged CRYPTO stays sent"
    );
    assert_eq!(conn.retire_pending, [7]);
    assert!(conn.poll_timeout().is_none());
}

#[test]
fn sparse_ack_and_ack_only_loss_preserve_other_spaces() {
    let now = Instant::now();
    let mut conn = connection(now);
    let ack_at = now + Duration::from_millis(50);
    let hs = arm(
        &mut conn,
        Space::Handshake,
        now + Duration::from_millis(20),
        ack_at,
    );
    // A sparse ACK of Data packets 2 and 0 leaves ACK-only packet 1 to retire
    // by time. It must not enqueue retransmissions or erase Handshake loss.
    for number in 0..3 {
        conn.spaces[2].sent.push(ack_only(number, now));
    }
    conn.on_ack(Space::Data, 2, 0, 0, &[0, 0], ack_at).unwrap();
    let first = now + conn.rtt.loss_delay();
    assert_eq!(conn.poll_timeout(), Some(first));
    conn.handle_timeout(first);
    assert!(conn.retire_pending.is_empty());
    assert_eq!(conn.poll_timeout(), Some(hs));
    conn.handle_timeout(hs);
    assert_eq!(conn.spaces[1].crypto_sent, 4);
    assert_eq!(conn.pto_count, 0);
    assert!(conn.poll_timeout().is_none());
}

#[test]
fn retry_resets_the_initial_loss_timer_with_its_flight() {
    let now = Instant::now();
    let mut conn = connection(now);
    // RFC 9001 A.4's authenticated Retry. Seed recovery directly to check the
    // reset path: a real Retry precedes any authenticated server ACK.
    conn.original_dcid =
        ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]).unwrap();
    conn.local_cid = ConnectionId::new(&[]).unwrap();
    let scid = ConnectionId::new(&[0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5]).unwrap();
    let packet = [
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5,
        0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58,
        0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
    ];
    let deadline = arm(
        &mut conn,
        Space::Initial,
        now,
        now + Duration::from_millis(10),
    );
    let mut forged = packet;
    forged[35] ^= 1;
    conn.on_retry(conn.local_cid, scid, b"token", &forged)
        .unwrap();
    assert!(!conn.retried);
    assert_eq!(conn.poll_timeout(), Some(deadline));
    conn.on_retry(conn.local_cid, scid, b"token", &packet)
        .unwrap();
    assert!(conn.retried);
    assert_eq!(conn.spaces[0].sent.bytes_in_flight(), 0);
    assert_eq!(conn.spaces[0].crypto_sent, 0);
    assert_eq!(conn.spaces[0].crypto_out, [7; 16]);
    assert!(
        conn.poll_timeout().is_none(),
        "the old flight cannot be recovered"
    );
}
