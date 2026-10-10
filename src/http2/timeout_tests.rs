use super::*;
use std::collections::BTreeMap;

fn push(conn: &mut Conn, id: u32, start: Instant) {
    conn.streams.push(id as u64, InFlight { start, status: 0 });
}

fn start_at(n: u64) -> Instant {
    Instant::ZERO + Duration::from_micros(n)
}

#[test]
fn the_oldest_live_request_keeps_the_exact_timeout_boundary() {
    let mut conn = Conn::new();
    push(&mut conn, 1, start_at(10));
    push(&mut conn, 3, start_at(10)); // Equal timestamps are allowed.
    push(&mut conn, 5, start_at(20));
    let now = start_at(30);
    // Derive the boundary from the same clock: synthetic Instant arithmetic
    // can round by a tick when nanoseconds are converted to/from cycles.
    let limit = now.duration_since(start_at(10));
    assert!(!conn.timed_out(now, limit + Duration::from_nanos(1), false));
    assert!(conn.timed_out(now, limit, false));
    assert!(conn.idle_since == now);
    assert!(conn.streams.take(1).is_some());
    assert!(conn.timed_out(now, limit, false));
    assert!(conn.streams.take(3).is_some());
    assert!(!conn.timed_out(now, limit, false));
    assert!(conn.timed_out(now, Duration::ZERO, false));
    assert!(conn.streams.slot(0).unwrap().start == start_at(20));
}

#[test]
fn a_pinned_request_and_compacted_prefix_preserve_the_oldest_start() {
    let mut conn = Conn::new();
    for i in 0..4096 {
        push(&mut conn, 1 + 2 * i, start_at(i as u64));
    }
    // A held first request leaves thousands of holes behind it.
    for i in 1..4000 {
        assert!(conn.streams.take(1 + 2 * i).is_some());
    }
    let now = start_at(5000);
    let limit = now.duration_since(start_at(0));
    assert!(conn.timed_out(now, limit, true));
    assert_eq!(conn.streams.slot_count(), 4096);
    assert!(conn.streams.take(1).is_some()); // Settles holes and compacts.
    assert_eq!(conn.streams.slot_count(), 96);
    assert!(conn.streams.slot(0).unwrap().start == start_at(4000));
    assert!(!conn.timed_out(now, limit, true));
    for i in 4096..8192 {
        push(&mut conn, 1 + 2 * i, start_at(i as u64));
        assert!(conn.streams.take(1 + 2 * (i - 96) as u64).is_some());
        assert!(conn.streams.slot(0).unwrap().start == start_at((i - 95) as u64));
    }
    assert_eq!(conn.streams.len(), 96);
}

#[test]
fn idle_timeouts_keep_held_requests_and_connect_state_distinct() {
    let now = start_at(100);
    let idle = start_at(10);
    let limit = now.duration_since(idle);
    let mut conn = Conn::new();
    conn.idle_since = idle;
    assert!(
        !conn.timed_out(now, limit, true),
        "connect has its own timer"
    );
    conn.connected = true;
    assert!(!conn.timed_out(now, limit, false), "budget exhausted");
    assert!(conn.timed_out(now, limit, true));
    conn.held = 4;
    assert!(
        conn.timed_out(now, limit, false),
        "held first flight still owed"
    );
    assert!(!conn.timed_out(now, limit + Duration::from_nanos(1), false));
    assert!(
        conn.idle_since == idle,
        "idle polling cannot extend its timer"
    );
    let mut stats = Stats::default();
    conn.fail_inflight(&mut stats);
    assert_eq!(stats.errors, 4);
    assert_eq!(stats.connect_errors, 0);
    assert!(stats.latencies_ns.is_empty());
    conn.close();
    conn.connected = true;
    push(&mut conn, 1, now); // A new connection restarts stream IDs.
    assert!(!conn.timed_out(now, limit, false));
}

#[test]
fn reset_refusal_and_goaway_retire_only_their_own_timestamps() {
    let mut conn = Conn::new();
    let mut stats = Stats::default();
    let mut started = 4;
    for i in 0..4 {
        push(&mut conn, 1 + i * 2, start_at(i as u64 * 10));
    }
    process_events(
        &mut conn,
        &[
            Event::Reset { stream_id: 1 },
            Event::Unprocessed { stream_id: 3 },
            Event::Unprocessed { stream_id: 7 },
            Event::Goaway,
        ],
        &mut stats,
        &mut started,
    );
    assert_eq!((stats.errors, started, conn.held), (1, 4, 2));
    assert!(conn.streams.slot(0).unwrap().start == start_at(20));
    let now = start_at(30);
    assert!(!conn.timed_out(now, now.duration_since(start_at(0)), false));
    assert!(conn.timed_out(now, now.duration_since(start_at(20)), false));
    conn.fail_inflight(&mut stats);
    assert_eq!((stats.errors, started, conn.held), (4, 4, 0));
    assert!(stats.latencies_ns.is_empty());
}

#[test]
fn timeout_decisions_and_accounting_match_a_full_scan_model() {
    let mut conn = Conn::new();
    let mut live = BTreeMap::<u32, Instant>::new();
    let mut stats = Stats::default();
    let mut started = 0;
    let mut next_id = 1;
    let mut random = 0x4d59_5df4_d0f3_3173_u64;
    let mut expected_errors = 0;
    let mut expected_ok = 0;
    let mut expected_connect_errors = 0;
    let mut expired = 0;
    for step in 0..32768 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let now = start_at(step / 4); // Includes identical creation times.
        match random % 16 {
            0..=8 => {
                conn.connected = true;
                push(&mut conn, next_id, now);
                live.insert(next_id, now);
                next_id += 2;
                started += 1;
            }
            9..=13 if !live.is_empty() => {
                let id = *live
                    .keys()
                    .nth((random >> 8) as usize % live.len())
                    .unwrap();
                let events = match random % 3 {
                    0 => {
                        expected_errors += 1;
                        vec![Event::Reset { stream_id: id }]
                    }
                    1 => vec![Event::Unprocessed { stream_id: id }],
                    _ => {
                        expected_ok += 1;
                        vec![
                            Event::Status {
                                stream_id: id,
                                status: 200,
                            },
                            Event::End { stream_id: id },
                        ]
                    }
                };
                process_events(&mut conn, &events, &mut stats, &mut started);
                live.remove(&id);
            }
            14 => process_events(&mut conn, &[Event::Goaway], &mut stats, &mut started),
            _ => {}
        }
        let may_start = random & 64 != 0;
        let limit = Duration::from_micros((random >> 16) % 1024);
        let expected = if live.is_empty() {
            conn.connected
                && (conn.held > 0 || may_start)
                && now.duration_since(conn.idle_since) >= limit
        } else {
            live.values()
                .any(|&start| now.duration_since(start) >= limit)
        };
        let idle_before = conn.idle_since;
        assert_eq!(
            conn.timed_out(now, limit, may_start),
            expected,
            "step {step}"
        );
        assert!(conn.idle_since == if live.is_empty() { idle_before } else { now });
        assert_eq!(conn.streams.len(), live.len());
        assert!(
            conn.streams
                .iter()
                .map(|s| s.start)
                .eq(live.values().copied())
        );
        if expected {
            expired += 1;
            if live.is_empty() && conn.held == 0 {
                expected_errors += 1;
                expected_connect_errors += 1;
                stats.errors += 1;
                stats.connect_errors += 1;
                started += 1;
            }
            expected_errors += live.len() as u64 + conn.held;
            conn.fail_inflight(&mut stats);
            conn.close();
            conn.idle_since = now;
            next_id = 1;
            live.clear();
        }
        assert_eq!(
            (stats.errors, stats.completed),
            (expected_errors, expected_ok)
        );
        assert_eq!(stats.connect_errors, expected_connect_errors);
        assert_eq!(stats.latencies_ns.len() as u64, expected_ok);
        assert_eq!(stats.status_counts[200], expected_ok);
    }
    assert!(
        expired > 100,
        "exercise expiration and reconnection repeatedly"
    );
}
