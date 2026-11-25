use super::*;

fn push(conn: &mut Conn, id: u32, start: Instant, started: &mut u64) {
    conn.streams.push(id.into(), InFlight { start, status: 0 });
    *started += 1;
}

fn pin(conn: &mut Conn, start: Instant, stats: &mut Stats, started: &mut u64) {
    push(conn, 1, start, started);
    for id in (3..257).step_by(2) {
        push(conn, id, start, started);
        process_events(
            conn,
            &[Event::Reset { stream_id: id }],
            stats,
            started,
            true,
        );
    }
    assert_eq!(conn.streams.len(), 1);
    assert_eq!(stats.errors, 127);
}

#[test]
fn sparse_status_waits_for_end_and_records_the_original_timestamp_once() {
    let mut conn = Conn::new();
    let mut stats = Stats::default();
    let mut started = 0;
    let start = Instant::now();
    pin(&mut conn, start, &mut stats, &mut started);
    process_events(
        &mut conn,
        &[Event::Status {
            stream_id: 1,
            status: 201,
        }],
        &mut stats,
        &mut started,
        true,
    );
    assert_eq!((stats.completed, stats.latencies_ns.len()), (0, 0));
    assert_eq!(conn.streams.get_mut(1).unwrap().start, start);
    let now = Instant::now();
    let limit = now.duration_since(start);
    assert!(conn.timed_out(now, limit, false));
    assert!(!conn.timed_out(now, limit + Duration::from_nanos(1), false));
    let before = Instant::now();
    process_events(
        &mut conn,
        &[
            Event::End { stream_id: 1 },
            Event::End { stream_id: 1 },
            Event::Reset { stream_id: 1 },
        ],
        &mut stats,
        &mut started,
        true,
    );
    let after = Instant::now();
    assert_eq!((stats.completed, stats.errors, started), (1, 127, 128));
    assert_eq!(stats.status_counts[201], 1);
    assert_eq!(stats.latencies_ns.len(), 1);
    assert!(
        (before.duration_since(start).as_nanos() as u64
            ..=after.duration_since(start).as_nanos() as u64)
            .contains(&stats.latencies_ns[0])
    );
    assert!(conn.streams.is_empty());
}

#[test]
fn sparse_refusal_goaway_and_reconnect_preserve_exact_budget() {
    for answer in [false, true] {
        let mut conn = Conn::new();
        let mut stats = Stats::default();
        let mut started = 0;
        let start = Instant::now();
        pin(&mut conn, start, &mut stats, &mut started);
        push(&mut conn, 257, start, &mut started);
        push(&mut conn, 259, start, &mut started);
        process_events(
            &mut conn,
            &[
                Event::Unprocessed { stream_id: 257 },
                Event::Unprocessed { stream_id: 257 },
                Event::Reset { stream_id: 259 },
                Event::Goaway,
            ],
            &mut stats,
            &mut started,
            true,
        );
        assert_eq!((started, conn.held, stats.errors), (130, 1, 128));
        assert!(conn.goaway);
        if answer {
            process_events(
                &mut conn,
                &[
                    Event::Status {
                        stream_id: 1,
                        status: 200,
                    },
                    Event::End { stream_id: 1 },
                ],
                &mut stats,
                &mut started,
                true,
            );
            assert_eq!((started, conn.held, stats.completed), (129, 0, 1));
        }
        conn.fail_inflight(&mut stats);
        conn.fail_inflight(&mut stats);
        assert_eq!(stats.errors, if answer { 128 } else { 130 });
        assert_eq!(stats.latencies_ns.len(), usize::from(answer));
        let generation = conn.generation;
        conn.close();
        assert_eq!(conn.generation, generation + 1);
        assert!(!conn.goaway);
        push(&mut conn, 1, Instant::now(), &mut started);
        assert_eq!(conn.streams.len(), 1);
        assert_eq!(conn.streams.get_mut(1).unwrap().status, 0);
        assert!(conn.streams.get_mut(257).is_none());
    }
}

#[test]
fn duration_drain_retires_sparse_and_dense_responses_without_refunding_attempts() {
    let mut conn = Conn::new();
    let mut stats = Stats::default();
    let mut started = 0;
    let start = Instant::now();
    pin(&mut conn, start, &mut stats, &mut started);
    push(&mut conn, 257, start, &mut started);
    push(&mut conn, 259, start, &mut started);
    let mut control = RunControl::new(
        Budget::Duration(Duration::from_secs(1)),
        Some(Duration::from_secs(1)),
    )
    .unwrap();
    control.stop(std::slice::from_mut(&mut conn), &mut stats);
    assert!(!control.may_start(started));
    let before = Instant::now();
    let events = [
        Event::Status {
            stream_id: 1,
            status: 201,
        },
        Event::Status {
            stream_id: 257,
            status: 200,
        },
        Event::End { stream_id: 257 },
        Event::Unprocessed { stream_id: 259 },
        Event::End { stream_id: 1 },
    ];
    process_events(
        &mut conn,
        &events,
        &mut stats,
        &mut started,
        !control.draining(),
    );
    let after = Instant::now();
    // Duplicate responses/refusals never add a sample, refund or error.
    process_events(
        &mut conn,
        &events,
        &mut stats,
        &mut started,
        !control.draining(),
    );
    conn.fail_inflight(&mut stats);
    assert_eq!(
        (started, stats.completed, stats.errors, conn.held),
        (130, 2, 128, 0)
    );
    assert_eq!((stats.status_counts[200], stats.status_counts[201]), (1, 1));
    assert_eq!(stats.latencies_ns.len(), 2);
    for &latency in &stats.latencies_ns {
        assert!(
            (before.duration_since(start).as_nanos() as u64
                ..=after.duration_since(start).as_nanos() as u64)
                .contains(&latency)
        );
    }
    assert!(conn.streams.is_empty());
}

#[test]
fn expired_drain_fails_sparse_pins_and_dense_tails_once_before_reconnect() {
    let mut conn = Conn::new();
    let mut stats = Stats::default();
    let mut started = 0;
    let start = Instant::now();
    pin(&mut conn, start, &mut stats, &mut started);
    push(&mut conn, 257, start, &mut started);
    push(&mut conn, 259, start, &mut started);
    conn.streams.get_mut(1).unwrap().status = 200;
    conn.streams.get_mut(257).unwrap().status = 201;
    conn.out = vec![0x5a; 1024];
    conn.out_off = 15;
    conn.sending = true;
    let mut control = RunControl::new(
        Budget::Duration(Duration::from_secs(1)),
        Some(Duration::from_secs(1)),
    )
    .unwrap();
    let now = std::time::Instant::now();
    control.drain = Some((now, now));
    control.refresh(std::slice::from_mut(&mut conn), &mut stats);
    assert!(control.expired());
    assert!(!control.may_start(started));
    conn.fail_inflight(&mut stats);
    conn.fail_inflight(&mut stats);
    assert_eq!((started, stats.completed, stats.errors), (130, 0, 130));
    assert!(stats.latencies_ns.is_empty());
    assert!(stats.status_counts.iter().all(|&count| count == 0));
    assert!(conn.sending);
    assert_eq!(conn.out, vec![0x5a; 1024]);
    assert_eq!(conn.out_off, 15);
    assert!(conn.streams.is_empty());
    // Model the send completion before close; accounting must not touch the
    // allocation still owned by the kernel.
    conn.sending = false;
    conn.close();
    push(&mut conn, 1, Instant::now(), &mut started);
    assert_eq!(conn.streams.len(), 1);
    assert_eq!(conn.streams.get_mut(1).unwrap().status, 0);
    assert!(conn.streams.get_mut(257).is_none());
}
