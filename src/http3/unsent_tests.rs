use super::*;
use crate::quic::frame::Frame;
use std::collections::BTreeMap;

fn connection(window: u64) -> Conn {
    let mut conn = Conn::new();
    let mut quic = Connection::connect(
        crate::tls::client_config(b"h3").unwrap(),
        "localhost",
        local_params(Duration::from_secs(5), None),
    )
    .unwrap();
    quic.test_send_limits(1 << 20, window);
    conn.quic = Some(quic);
    conn.h3_ready = true;
    conn
}

fn flush(conn: &mut Conn) {
    flush_unsent(
        conn.quic.as_mut().unwrap(),
        &mut conn.streams,
        &mut conn.has_unsent,
    );
    assert_eq!(
        conn.has_unsent,
        conn.streams
            .iter()
            .any(|request| !request.unsent.is_empty())
    );
}

fn fill(conn: &mut Conn, request: &[u8], parallel: usize, started: &mut u64) {
    fill_streams(
        conn,
        request,
        parallel,
        started,
        Budget::Requests(1 << 20),
        false,
    )
    .unwrap();
}

#[test]
fn fully_accepted_requests_leave_the_gate_clear() {
    let mut conn = connection(1024);
    let mut started = 0;
    flush(&mut conn);
    fill(&mut conn, b"request", 128, &mut started);
    assert_eq!(started, 128);
    assert!(!conn.has_unsent);
    let starts: Vec<_> = conn.streams.iter().map(|s| s.start).collect();
    for id in 1..127 {
        conn.streams.take(id * 4).unwrap();
    }
    for _ in 0..16 {
        flush(&mut conn);
        for id in [0, 508] {
            assert_eq!(
                conn.quic.as_ref().unwrap().test_buffered_request(id),
                Some((&b"request"[..], true))
            );
        }
        assert_eq!(conn.streams.get_mut(0).unwrap().start, starts[0]);
        assert_eq!(conn.streams.get_mut(508).unwrap().start, starts[127]);
    }
}

#[test]
fn zero_and_incremental_credit_preserve_every_byte_and_fin() {
    let mut conn = connection(0);
    let mut started = 0;
    let request = b"a request split across several credit updates";
    fill(&mut conn, request, 3, &mut started);
    assert!(conn.has_unsent);
    for _ in 0..4 {
        flush(&mut conn);
        assert!(conn.streams.iter().all(|s| s.unsent == request));
    }
    for limit in [1, 1, 3, 2, 19, request.len()] {
        for id in [8, 0, 4] {
            conn.quic
                .as_mut()
                .unwrap()
                .test_receive_frame(Frame::MaxStreamData {
                    id,
                    limit: limit as u64,
                });
            flush(&mut conn);
            let inflight = conn.streams.get_mut(id).unwrap();
            let accepted = request.len() - inflight.unsent.len();
            assert!(accepted >= limit);
            assert_eq!(inflight.unsent, request[accepted..]);
            assert_eq!(
                conn.quic.as_ref().unwrap().test_buffered_request(id),
                Some((&request[..accepted], accepted == request.len()))
            );
        }
    }
    assert!(!conn.has_unsent);
    assert_eq!((started, conn.streams.len()), (3, 3));
    // Opening another blocked stream must set the flag again.
    fill(&mut conn, request, 4, &mut started);
    assert!(conn.has_unsent);
    assert_eq!(conn.streams.get_mut(12).unwrap().unsent, request);
}

#[test]
fn stopped_and_reset_requests_do_not_keep_the_gate_set() {
    let mut conn = connection(2);
    let mut started = 0;
    let mut stats = Stats::default();
    fill(&mut conn, b"long request", 3, &mut started);
    let starts: Vec<_> = conn.streams.iter().map(|s| s.start).collect();
    conn.quic
        .as_mut()
        .unwrap()
        .test_receive_frame(Frame::StopSending {
            id: 0,
            error: proto::H3_REQUEST_CANCELLED,
        });
    conn.quic
        .as_mut()
        .unwrap()
        .test_receive_frame(Frame::ResetStream {
            id: 4,
            error: proto::H3_REQUEST_CANCELLED,
            final_size: 0,
        });
    assert!(drive(
        &mut conn,
        &mut stats,
        b"",
        3,
        &mut started,
        Budget::Requests(3),
        true
    ));
    assert!(conn.has_unsent, "the third request still needs credit");
    assert_eq!(stats.errors, 1);
    assert!(stats.latencies_ns.is_empty());
    assert!(conn.streams.get_mut(0).unwrap().unsent.is_empty());
    assert_eq!(conn.streams.get_mut(0).unwrap().start, starts[0]);
    assert_eq!(conn.streams.get_mut(8).unwrap().start, starts[2]);
    conn.quic
        .as_mut()
        .unwrap()
        .test_receive_frame(Frame::StopSending {
            id: 8,
            error: proto::H3_REQUEST_CANCELLED,
        });
    assert!(drive(
        &mut conn,
        &mut stats,
        b"",
        3,
        &mut started,
        Budget::Requests(3),
        true
    ));
    assert!(!conn.has_unsent);
    assert_eq!(
        (started, stats.completed, stats.errors, conn.streams.len()),
        (3, 0, 1, 2)
    );
}

#[test]
fn rejected_goaway_and_failed_requests_clear_pending_state_before_reconnect() {
    let mut conn = connection(0);
    let mut started = 0;
    let mut stats = Stats::default();
    fill(&mut conn, b"request", 4, &mut started);
    conn.give_backs.completed = 1;
    conn.quic
        .as_mut()
        .unwrap()
        .test_receive_frame(Frame::ResetStream {
            id: 4,
            error: proto::H3_REQUEST_REJECTED,
            final_size: 0,
        });
    conn.goaway = Some(8);
    assert!(drive(
        &mut conn,
        &mut stats,
        b"",
        4,
        &mut started,
        Budget::Requests(4),
        true
    ));
    assert_eq!((started, stats.errors, conn.streams.len()), (1, 0, 1));
    assert!(conn.has_unsent);
    conn.fail_inflight(&mut stats);
    assert_eq!(stats.errors, 1);
    assert!(!conn.has_unsent);
    conn.close(0, &mut Vec::new());
    assert!(!conn.has_unsent);
    let replacement = connection(1024);
    conn.quic = replacement.quic;
    conn.h3_ready = true;
    fill(&mut conn, b"request", 1, &mut started);
    assert!(!conn.has_unsent);
    assert_eq!(conn.streams.get_mut(0).unwrap().unsent, b"");
    // close itself must clear pending state, without relying on fail_inflight.
    conn.quic.as_mut().unwrap().test_send_limits(1024, 0);
    fill(&mut conn, b"request", 2, &mut started);
    assert!(conn.has_unsent);
    conn.close(0, &mut Vec::new());
    assert!(!conn.has_unsent);
}

#[test]
fn pending_gate_matches_an_independent_credit_model_across_sparse_retirement() {
    let mut conn = connection(0);
    let mut started = 0;
    let request: Vec<_> = (0..97).collect();
    let mut expected = BTreeMap::new();
    let mut random = 0x0fe1_2345_6789_abcd_u64;
    for step in 0..16_384 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        if expected.is_empty() || (random & 3 == 0 && expected.len() < 128) {
            let id = started * 4;
            fill(&mut conn, &request, expected.len() + 1, &mut started);
            expected.insert(id, (0_usize, conn.streams.get_mut(id).unwrap().start));
        } else {
            let id = *expected
                .keys()
                .nth((random >> 8) as usize % expected.len())
                .unwrap();
            if random & 3 == 1 {
                expected.remove(&id);
                conn.streams.take(id).unwrap();
                conn.quic
                    .as_mut()
                    .unwrap()
                    .retire(id, proto::H3_REQUEST_CANCELLED);
            } else {
                let limit = ((random >> 16) % 128) as usize;
                let entry = expected.get_mut(&id).unwrap();
                entry.0 = entry.0.max(limit.min(request.len()));
                conn.quic
                    .as_mut()
                    .unwrap()
                    .test_receive_frame(Frame::MaxStreamData {
                        id,
                        limit: limit as u64,
                    });
            }
        }
        flush(&mut conn);
        assert_eq!(conn.streams.len(), expected.len(), "step {step}");
        for (&id, &(accepted, start)) in &expected {
            let inflight = conn.streams.get_mut(id).unwrap();
            assert_eq!(inflight.start, start);
            assert_eq!(inflight.unsent, request[accepted..]);
            let sent = conn.quic.as_ref().unwrap().test_buffered_request(id);
            assert_eq!(
                sent,
                (accepted != 0).then_some((&request[..accepted], accepted == request.len()))
            );
        }
    }
}
