//! Recovery timer modes, driven through ACK processing and explicit instants.
//! No test assigns a cached loss deadline or sleeps to make a timer expire.

use super::*;

fn stable_connection() -> Connection {
    let mut conn = test_connection();
    // A settled 100 ms path: PTO is 101 ms, time-threshold loss is 112.5 ms.
    // Zero is a valid peer max_ack_delay, including for Application Data.
    for _ in 0..32 {
        conn.rtt
            .update(Duration::from_millis(100), Duration::ZERO, Duration::ZERO);
    }
    conn.params.max_ack_delay_ms = 0;
    assert_eq!(conn.rtt.pto(Duration::ZERO), Duration::from_millis(101));
    conn
}

fn arm_loss(conn: &mut Connection, space: Space, sent: Instant, acked: Instant) -> Instant {
    let s = &mut conn.spaces[space as usize];
    let mut packet = lost_packet(0, sent);
    packet.frames.push(SentFrame::Ping);
    s.sent.push(packet);
    s.sent.push(SentPacket {
        number: 1,
        time_sent: sent,
        size: 0,
        ack_eliciting: false,
        ack_largest: None,
        frames: Vec::new(),
    });
    // ACK-only packet 1 neither refreshes the PTO send time nor samples RTT.
    conn.on_ack(space, 1, 0, 0, &[], acked).unwrap();
    sent + conn.rtt.loss_delay()
}

fn pto(conn: &Connection) -> (Space, Instant) {
    pto_deadline(
        &[
            &conn.spaces[0].sent,
            &conn.spaces[1].sent,
            &conn.spaces[2].sent,
        ],
        &conn.rtt,
        Duration::from_millis(conn.params.max_ack_delay_ms),
        conn.pto_count,
        conn.pto_fallback(),
    )
    .expect("fixture has a PTO candidate")
}

#[test]
fn pending_loss_selects_recovery_mode_even_when_pto_is_earlier() {
    for space in Space::ALL {
        let now = Instant::now();
        let mut conn = stable_connection();
        let loss = arm_loss(&mut conn, space, now, now + Duration::from_millis(100));
        assert!(pto(&conn).1 < loss);
        assert_eq!(conn.poll_timeout(), Some(loss), "{space:?}");
    }
}

#[test]
fn early_timeout_cannot_probe_in_any_space_while_loss_is_pending() {
    for loss_space in Space::ALL {
        for probe_space in Space::ALL {
            let now = Instant::now();
            let mut conn = stable_connection();
            let sent = if loss_space == probe_space {
                now
            } else {
                now + Duration::from_millis(20)
            };
            let loss = arm_loss(
                &mut conn,
                loss_space,
                sent,
                now + Duration::from_millis(100),
            );
            if probe_space != loss_space {
                conn.spaces[probe_space as usize]
                    .sent
                    .push(lost_packet(0, now));
            }
            let (chosen, early) = pto(&conn);
            assert_eq!(chosen, probe_space);
            assert!(early < loss);
            conn.needs_send = false;
            conn.handle_timeout(early);
            assert_eq!(conn.pto_count, 0, "{loss_space:?}/{probe_space:?}");
            assert_eq!(conn.pto_probes, 0);
            assert!(!conn.needs_send);
            assert_eq!(
                conn.spaces[loss_space as usize].sent.bytes_in_flight(),
                1200
            );
            assert_eq!(conn.poll_timeout(), Some(loss));
        }
    }
}

#[test]
fn encrypted_initial_flight_does_not_emit_premature_probes() {
    let now = Instant::now();
    let mut conn = stable_connection();
    let mut datagram = Vec::new();
    assert_eq!(conn.poll_transmit(now, &mut datagram, None).unwrap(), 1200);
    let hello = conn.spaces[0].crypto_out.clone();
    assert_eq!(conn.spaces[0].crypto_sent, hello.len());
    datagram.clear();
    assert_eq!(conn.poll_transmit(now, &mut datagram, None).unwrap(), 0);

    // A server Initial elicits our ACK-only packet 1. Its ACK leaves the
    // ClientHello in packet 0 pending until the time threshold expires.
    let ack_sent = now + Duration::from_millis(10);
    conn.spaces[0].ack.record(0, true, ack_sent);
    assert_eq!(
        conn.poll_transmit(ack_sent, &mut datagram, None).unwrap(),
        1200
    );
    assert_eq!(conn.spaces[0].next_packet_number, 2);
    conn.on_ack(
        Space::Initial,
        1,
        0,
        0,
        &[],
        now + Duration::from_millis(100),
    )
    .unwrap();
    let loss = conn.loss_deadline().unwrap();
    let early = pto(&conn).1;
    assert!(early < loss);
    conn.handle_timeout(early);
    let mut packets = 0;
    let mut bytes = 0;
    for _ in 0..4 {
        datagram.clear();
        let len = conn.poll_transmit(early, &mut datagram, None).unwrap();
        if len == 0 {
            break;
        }
        packets += 1;
        bytes += len;
    }
    eprintln!(
        "before loss: datagrams={packets}, bytes={bytes}, pto_count={}",
        conn.pto_count
    );
    assert_eq!((packets, bytes, conn.pto_count), (0, 0, 0));

    conn.handle_timeout(loss);
    assert_eq!(conn.spaces[0].crypto_sent, 0);
    assert_eq!(conn.pto_probes, 0);
    datagram.clear();
    assert_eq!(conn.poll_transmit(loss, &mut datagram, None).unwrap(), 1200);
    assert_eq!(conn.spaces[0].crypto_out, hello);
    assert_eq!(conn.spaces[0].crypto_sent, hello.len());
    assert_eq!(conn.spaces[0].next_packet_number, 3);
    assert!(conn.loss_deadline().is_none());
    conn.handle_timeout(loss);
    datagram.clear();
    assert_eq!(conn.poll_transmit(loss, &mut datagram, None).unwrap(), 0);
    assert_eq!(conn.pto_count, 0);
}

#[test]
fn ack_clearing_last_loss_reenables_other_spaces_pto() {
    let now = Instant::now();
    let mut conn = stable_connection();
    arm_loss(
        &mut conn,
        Space::Handshake,
        now,
        now + Duration::from_millis(100),
    );
    conn.spaces[0].sent.push(lost_packet(0, now));
    // Late ACK of the missing packet clears only its own space's loss time.
    conn.on_ack(
        Space::Handshake,
        0,
        0,
        0,
        &[],
        now + Duration::from_millis(100),
    )
    .unwrap();
    assert!(conn.loss_deadline().is_none());
    let (space, at) = pto(&conn);
    assert_eq!(space, Space::Initial);
    assert_eq!(conn.poll_timeout(), Some(at));
    conn.handle_timeout(at);
    assert_eq!((conn.pto_count, conn.pto_probes), (1, 2));
    assert_eq!(conn.pto_space, space);
}

#[test]
fn discard_clearing_last_loss_reenables_other_spaces_pto() {
    let now = Instant::now();
    let mut conn = stable_connection();
    arm_loss(
        &mut conn,
        Space::Initial,
        now,
        now + Duration::from_millis(100),
    );
    conn.spaces[1].sent.push(lost_packet(0, now));
    conn.discard_space(Space::Initial);
    assert!(conn.loss_deadline().is_none());
    let (space, at) = pto(&conn);
    assert_eq!(space, Space::Handshake);
    assert_eq!(conn.poll_timeout(), Some(at));
    conn.handle_timeout(at);
    assert_eq!((conn.pto_count, conn.pto_probes), (1, 2));
    assert_eq!(conn.pto_space, space);
}

#[test]
fn simultaneous_loss_and_pto_recover_without_probes_or_backoff() {
    let now = Instant::now();
    let mut conn = stable_connection();
    // 100 ms + 4 * 3.125 ms = the 112.5 ms loss threshold.
    conn.rtt.var = Duration::from_micros(3125);
    let loss = arm_loss(
        &mut conn,
        Space::Handshake,
        now,
        now + Duration::from_millis(100),
    );
    assert_eq!(pto(&conn).1, loss);
    conn.handle_timeout(loss);
    assert_eq!(conn.spaces[1].sent.bytes_in_flight(), 0);
    assert_eq!((conn.pto_count, conn.pto_probes), (0, 0));
    assert!(conn.poll_timeout().is_none());
    conn.needs_send = false;
    conn.handle_timeout(loss);
    assert!(!conn.needs_send, "loss is retired once");
}

#[test]
fn rtt_growth_rearms_loss_without_entering_pto_mode() {
    let now = Instant::now();
    let mut conn = stable_connection();
    let loss = arm_loss(
        &mut conn,
        Space::Handshake,
        now,
        now + Duration::from_millis(100),
    );
    conn.rtt
        .update(Duration::from_millis(200), Duration::ZERO, Duration::ZERO);
    conn.handle_timeout(loss);
    let next = now + conn.rtt.loss_delay();
    assert!(next > loss);
    assert!(pto(&conn).1 < next);
    assert_eq!(conn.poll_timeout(), Some(next));
    conn.handle_timeout(pto(&conn).1);
    assert_eq!((conn.pto_count, conn.pto_probes), (0, 0));
    conn.handle_timeout(next);
    assert_eq!(conn.spaces[1].sent.bytes_in_flight(), 0);
    assert!(conn.poll_timeout().is_none());
}

#[test]
fn loss_mode_does_not_delay_idle_or_keepalive() {
    for idle in [false, true] {
        let now = Instant::now();
        let mut conn = stable_connection();
        let loss = arm_loss(
            &mut conn,
            Space::Data,
            now,
            now + Duration::from_millis(100),
        );
        let other = now + Duration::from_millis(105);
        if idle {
            conn.idle_deadline = Some(other);
        } else {
            conn.connected = true;
            conn.unanswered = 1;
            conn.next_keepalive = Some(other);
        }
        assert_eq!(conn.poll_timeout(), Some(other));
        conn.handle_timeout(other);
        assert_eq!((conn.pto_count, conn.pto_probes), (0, 0));
        assert_eq!(conn.spaces[2].sent.bytes_in_flight(), 1200);
        if idle {
            assert!(conn.closed.is_some());
            assert!(conn.poll_timeout().is_none());
        } else {
            assert!(conn.keepalive_pending);
            assert_eq!(conn.poll_timeout(), Some(loss));
        }
    }
}

#[test]
fn confirmation_clears_handshake_loss_and_leaves_data_pto() {
    let now = Instant::now();
    let mut conn = stable_connection();
    arm_loss(
        &mut conn,
        Space::Handshake,
        now,
        now + Duration::from_millis(100),
    );
    conn.spaces[2].sent.push(lost_packet(0, now));
    conn.handle_frame(
        Space::Data,
        Frame::HandshakeDone,
        now + Duration::from_millis(100),
    )
    .unwrap();
    assert!(conn.handshake_done);
    assert!(conn.loss_deadline().is_none());
    let (space, at) = pto(&conn);
    assert_eq!(space, Space::Data);
    assert_eq!(conn.poll_timeout(), Some(at));
    conn.handle_timeout(at);
    assert_eq!((conn.pto_count, conn.pto_probes), (1, 2));
    assert_eq!(conn.pto_space, Space::Data);
}

#[test]
fn initial_loss_retirement_keeps_anti_deadlock_fallback() {
    for handshake_keys in [false, true] {
        let now = Instant::now();
        let mut conn = stable_connection();
        let loss = arm_loss(
            &mut conn,
            Space::Initial,
            now,
            now + Duration::from_millis(100),
        );
        if handshake_keys {
            with_handshake_keys(&mut conn);
        }
        conn.handle_timeout(loss);
        assert!(conn.loss_deadline().is_none());
        assert_eq!(conn.spaces[0].sent.bytes_in_flight(), 0);
        assert_eq!((conn.pto_count, conn.pto_probes), (0, 0));
        // No Handshake ACK/confirmation yet: an empty flight must not stop
        // probing a server that might be blocked by its amplification limit.
        let (space, at) = pto(&conn);
        assert!(at <= loss);
        assert_eq!(conn.poll_timeout(), Some(at));
        conn.handle_timeout(loss);
        assert_eq!((conn.pto_count, conn.pto_probes), (1, 2));
        assert_eq!(conn.pto_space, space);
        assert_eq!(
            space,
            if handshake_keys {
                Space::Handshake
            } else {
                Space::Initial
            }
        );
    }
}
