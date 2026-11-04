use super::*;
use crate::quic::frame::Frame;

// Independent wire expectations: control type, SETTINGS length nine, QPACK
// capacity zero, blocked streams zero, max field section size 1 MiB.
const CONTROL: &[u8] = &[0, 4, 9, 1, 0, 7, 0, 6, 0x80, 0x10, 0, 0];
const PREFIXES: [&[u8]; 3] = [CONTROL, &[2], &[3]];

fn connection(window: u64) -> Conn {
    let mut conn = Conn::new();
    let mut quic = Connection::connect(
        crate::tls::client_config(b"h3").unwrap(),
        "localhost",
        local_params(Duration::from_secs(5), None),
    )
    .unwrap();
    quic.test_h3_connected(window);
    conn.quic = Some(quic);
    conn
}

fn step(conn: &mut Conn, started: &mut u64) {
    let mut stats = Stats::default();
    assert!(drive(
        conn,
        &mut stats,
        b"request",
        2,
        started,
        Budget::Requests(2),
        false,
    ));
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (0, 0, 0)
    );
    assert!(stats.latencies_ns.is_empty());
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 0);
}

fn assert_prefixes(conn: &Conn, limits: [usize; 3]) {
    let actual = conn.quic.as_ref().unwrap().test_buffered_uni();
    assert_eq!(actual.len(), 3, "streams must be opened exactly once");
    for (i, (id, bytes, fin)) in actual.iter().enumerate() {
        assert_eq!(*id, 2 + 4 * i as u64);
        assert_eq!(bytes, &PREFIXES[i][..limits[i].min(PREFIXES[i].len())]);
        assert!(!fin, "critical streams must remain open");
    }
}

#[test]
fn full_credit_finishes_startup_without_retained_state() {
    let mut conn = connection(1024);
    let mut started = 0;
    step(&mut conn, &mut started);
    assert!(conn.h3_ready);
    assert!(conn.h3_init.is_none());
    assert_eq!(started, 2);
    assert_prefixes(&conn, [1024; 3]);
    let starts: Vec<_> = conn.streams.iter().map(|stream| stream.start).collect();
    for _ in 0..8 {
        step(&mut conn, &mut started);
        assert!(conn.h3_init.is_none());
        assert_prefixes(&conn, [1024; 3]);
        assert_eq!(started, 2);
        assert!(
            conn.streams
                .iter()
                .map(|stream| stream.start)
                .eq(starts.iter().copied())
        );
    }
}

#[test]
fn zero_partial_and_stale_credit_preserve_prefixes_and_request_budget() {
    let mut conn = connection(0);
    let mut started = 0;
    for _ in 0..4 {
        step(&mut conn, &mut started);
        assert!(!conn.h3_ready);
        assert!(conn.h3_init.is_some());
        assert_eq!(started, 0);
        assert!(conn.streams.is_empty());
        assert_prefixes(&conn, [0; 3]);
    }
    let mut limits = [0; 3];
    // Complete the control stream before the QPACK streams. Duplicate and
    // lower grants must not repeat bytes or advance another stream's cursor.
    for (i, limit) in [(0, 1), (0, 5), (0, 1), (0, 5), (0, 12), (2, 1), (1, 1)] {
        conn.quic
            .as_mut()
            .unwrap()
            .test_receive_frame(Frame::MaxStreamData {
                id: 2 + i as u64 * 4,
                limit: limit as u64,
            });
        limits[i] = limits[i].max(limit);
        let before = Instant::now();
        for _ in 0..3 {
            step(&mut conn, &mut started);
            assert_prefixes(&conn, limits);
        }
        let ready = limits == [12, 1, 1];
        assert_eq!(conn.h3_ready, ready);
        assert_eq!(conn.h3_init.is_none(), ready);
        assert_eq!(started, if ready { 2 } else { 0 });
        assert_eq!(conn.streams.len(), started as usize);
        assert!(conn.streams.iter().all(|stream| stream.start >= before));
    }
}

#[test]
fn close_drops_partial_startup_before_reusing_the_connection() {
    let mut conn = connection(5);
    let mut started = 0;
    step(&mut conn, &mut started);
    assert_prefixes(&conn, [5; 3]);
    assert!(conn.h3_init.is_some());
    let mut retired = Vec::new();
    conn.close(0, &mut retired);
    assert_eq!(conn.generation, 1);
    assert!(conn.h3_init.is_none());
    assert!(!conn.h3_ready);
    assert!(conn.quic.is_none());
    assert!(retired.is_empty());
    conn.quic = connection(1024).quic.take();
    step(&mut conn, &mut started);
    assert_prefixes(&conn, [1024; 3]);
    assert_eq!(started, 2);
    assert!(conn.h3_ready);
    assert!(conn.h3_init.is_none());
}

#[test]
fn finishing_startup_respects_stop_and_an_exhausted_budget() {
    for stop in [false, true] {
        let mut conn = connection(1);
        let mut started = 0;
        step(&mut conn, &mut started);
        conn.quic
            .as_mut()
            .unwrap()
            .test_receive_frame(Frame::MaxStreamData {
                id: 2,
                limit: CONTROL.len() as u64,
            });
        let mut stats = Stats::default();
        let budget = if stop {
            Budget::Requests(2)
        } else {
            Budget::Requests(0)
        };
        assert!(drive(
            &mut conn,
            &mut stats,
            b"request",
            2,
            &mut started,
            budget,
            stop
        ));
        assert!(conn.h3_ready);
        assert!(conn.h3_init.is_none());
        assert_eq!(started, 0);
        assert!(conn.streams.is_empty());
        assert_eq!(
            (stats.completed, stats.errors, stats.connect_errors),
            (0, 0, 0)
        );
        assert!(stats.latencies_ns.is_empty());
        assert_prefixes(&conn, [1024; 3]);
    }
}
