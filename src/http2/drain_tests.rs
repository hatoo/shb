use super::*;

fn control() -> RunControl {
    RunControl::new(
        Budget::Duration(Duration::from_secs(1)),
        Some(Duration::from_secs(1)),
    )
    .unwrap()
}

#[test]
fn deadline_stops_issuing_before_the_timer_cqe_is_seen() {
    let mut control = control();
    let now = std::time::Instant::now();
    control.drain = Some((now, now + Duration::from_secs(1)));
    assert!(!control.stopped);
    assert!(!control.may_start(0));
    let mut stats = Stats::default();
    let mut attempts = 0;
    control.fail_connect(&mut stats, &mut attempts);
    assert_eq!((attempts, stats.connect_errors, stats.errors), (0, 0, 0));
    let mut conn = Conn::new();
    let mut h2 = Connection::new();
    h2.initiate();
    conn.h2 = Some(h2);
    let mut started = 0;
    fill_streams(
        &mut conn,
        &[0x82, 0x86, 0x84],
        &[],
        32,
        &mut started,
        &control,
    );
    assert_eq!(started, 0);
    assert!(conn.streams.is_empty());
    control.refresh(std::slice::from_mut(&mut conn), &mut Stats::default());
    assert!(control.draining());
    assert!(!control.expired());
    assert!(control.wait_timeout() <= uring::WAIT_TIMEOUT);
}

#[test]
fn refused_requests_and_held_retries_are_charged_once_when_issuing_ends() {
    for answered in [0, 1] {
        let mut control = control();
        let mut conn = Conn::new();
        let start = Instant::now();
        conn.answered = answered;
        conn.held = 2;
        conn.streams.push(1, InFlight { start, status: 200 });
        conn.streams.push(3, InFlight { start, status: 0 });
        let mut stats = Stats::default();
        let mut started = 4;
        control.stop(std::slice::from_mut(&mut conn), &mut stats);
        control.stop(std::slice::from_mut(&mut conn), &mut stats);
        assert_eq!((conn.held, stats.errors), (0, 2));
        assert!(conn.streams.get_mut(1).unwrap().start == start);
        process_events(
            &mut conn,
            &[
                Event::Unprocessed { stream_id: 3 },
                Event::End { stream_id: 1 },
            ],
            &mut stats,
            &mut started,
            false,
        );
        process_events(
            &mut conn,
            &[
                Event::Unprocessed { stream_id: 3 },
                Event::End { stream_id: 1 },
            ],
            &mut stats,
            &mut started,
            false,
        );
        control.fail_connect(&mut stats, &mut started);
        conn.fail_inflight(&mut stats);
        assert_eq!(
            (started, stats.completed, stats.errors, stats.connect_errors),
            (4, 1, 3, 0)
        );
        assert_eq!(stats.latencies_ns.len(), 1);
    }
}

#[test]
fn drain_expiry_accounts_for_unsent_requests_without_success_samples() {
    let mut conn = Conn::new();
    let start = Instant::now();
    for id in [1, 3, 5] {
        conn.streams.push(id, InFlight { start, status: 200 });
    }
    // Neither receipt of headers nor bytes left in a partial Send completes a
    // response. The same accounting applies to requests not yet on the wire.
    conn.out = vec![1; 1024];
    conn.out_off = 15;
    conn.sending = true;
    let mut stats = Stats::default();
    conn.fail_inflight(&mut stats);
    conn.fail_inflight(&mut stats);
    assert_eq!((stats.completed, stats.errors), (0, 3));
    assert!(stats.latencies_ns.is_empty());
    assert!(conn.sending);
    assert_eq!(
        (conn.out.len(), conn.out_off),
        (1024, 15),
        "accounting never mutates kernel-owned storage"
    );
    let mut control = control();
    let now = std::time::Instant::now();
    control.drain = Some((now, now));
    assert!(control.expired());
    assert_eq!(control.wait_timeout(), Duration::ZERO);
}

#[test]
fn counted_runs_cannot_use_drain_and_overflow_is_rejected() {
    assert!(RunControl::new(Budget::Requests(1), Some(Duration::from_secs(1))).is_err());
    assert!(RunControl::new(Budget::Duration(Duration::MAX), Some(Duration::ZERO)).is_err());
    assert!(
        RunControl::new(
            Budget::Duration(Duration::from_secs(1)),
            Some(Duration::MAX)
        )
        .is_err()
    );
}
