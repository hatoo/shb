use super::*;
use std::collections::BTreeMap;

fn at(n: u64) -> Instant {
    Instant::ZERO + Duration::from_micros(n)
}

fn push(conn: &mut Conn, id: u64, start: Instant) {
    conn.streams.push(
        id,
        InFlight {
            stream_id: id,
            start,
            reader: ResponseReader::default(),
            unsent: Vec::new(),
        },
    );
}

#[test]
fn oldest_timeout_preserves_equal_starts_and_the_exact_boundary() {
    let mut conn = Conn::new();
    assert!(!conn.timed_out(at(30), Duration::ZERO));
    push(&mut conn, 0, at(10));
    push(&mut conn, 4, at(10));
    push(&mut conn, 8, at(20));
    // Derive the boundary from the clock to allow synthetic TSC rounding.
    let limit = at(30).duration_since(at(10));
    assert!(!conn.timed_out(at(30), limit + Duration::from_nanos(1)));
    assert!(conn.timed_out(at(30), limit));
    conn.streams.take(0).unwrap();
    assert!(conn.timed_out(at(30), limit));
    conn.streams.take(4).unwrap();
    assert!(!conn.timed_out(at(30), limit));
    assert!(conn.timed_out(at(30), Duration::ZERO));
}

#[test]
fn requests_opened_during_the_batch_keep_saturating_elapsed_time() {
    let mut conn = Conn::new();
    // The batch's `now` precedes fill_streams, which samples fresh starts.
    push(&mut conn, 0, at(20));
    push(&mut conn, 4, at(30));
    assert!(!conn.timed_out(at(10), Duration::from_nanos(1)));
    assert!(conn.timed_out(at(10), Duration::ZERO));
    conn.streams.take(0).unwrap();
    assert!(!conn.timed_out(at(20), Duration::from_nanos(1)));
    assert!(conn.timed_out(at(20), Duration::ZERO));
}

#[test]
fn a_held_oldest_request_survives_holes_compaction_and_partial_sends() {
    let mut conn = Conn::new();
    for n in 0..4096 {
        push(&mut conn, 4 * n, at(n));
    }
    conn.streams.get_mut(0).unwrap().unsent = vec![1; 128];
    for n in 1..4000 {
        conn.streams.take(4 * n).unwrap();
    }
    let limit = at(5000).duration_since(at(0));
    assert!(conn.timed_out(at(5000), limit));
    assert_eq!(conn.streams.slot_count(), 4096);
    conn.streams.take(0).unwrap();
    assert_eq!(conn.streams.slot_count(), 96);
    assert!(!conn.timed_out(at(5000), limit));
    for n in 4096..8192 {
        push(&mut conn, 4 * n, at(n));
        conn.streams.take(4 * (n - 96)).unwrap();
        assert!(conn.streams.slot(0).unwrap().start == at(n - 95));
    }
}

#[test]
fn closing_a_sparse_connection_charges_live_requests_once_and_restarts_ids() {
    let mut conn = Conn::new();
    for n in 0..128 {
        push(&mut conn, n * 4, at(n));
    }
    for n in 1..127 {
        conn.streams.take(n * 4).unwrap();
    }
    conn.give_backs.unjudged = 3;
    let mut stats = Stats::default();
    assert!(conn.timed_out(at(200), Duration::from_micros(100)));
    conn.fail_inflight(&mut stats);
    conn.fail_inflight(&mut stats);
    assert_eq!(
        (stats.errors, stats.completed, stats.connect_errors),
        (5, 0, 0)
    );
    assert!(stats.latencies_ns.is_empty());
    conn.close(0, &mut Vec::new());
    assert!(!conn.timed_out(at(200), Duration::ZERO));
    push(&mut conn, 0, at(200));
    assert!(!conn.timed_out(at(200), Duration::from_nanos(1)));
}

#[test]
fn timeout_eligibility_matches_a_full_scan_through_seeded_lifecycles() {
    let mut conn = Conn::new();
    let mut live = BTreeMap::new();
    let mut next_id = 0;
    let mut random = 0xa32f_83d4_c072_619b_u64;
    let mut expirations = 0;
    let mut future_checks = 0;
    for step in 0..32768 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let start = at(step / 4 + 1); // Equal starts, plus a stale batch clock.
        match random % 16 {
            0..=9 => {
                push(&mut conn, next_id, start);
                live.insert(next_id, start);
                next_id += 4;
            }
            10..=13 if !live.is_empty() => {
                // Successful or reset streams retire in arbitrary order.
                let id = *live
                    .keys()
                    .nth((random >> 8) as usize % live.len())
                    .unwrap();
                live.remove(&id);
                conn.streams.take(id).unwrap();
            }
            14 if !live.is_empty() => {
                // GOAWAY retires the unprocessed suffix, never retimes it.
                let id = *live
                    .keys()
                    .nth((random >> 8) as usize % live.len())
                    .unwrap();
                let removed = live.split_off(&id);
                for id in removed.keys() {
                    conn.streams.take(*id).unwrap();
                }
                // No new streams are opened after GOAWAY on this connection.
                next_id = live.last_key_value().map_or(0, |(&id, _)| id + 4);
            }
            _ => {}
        }
        let now = at((step / 4).saturating_sub((random >> 16) % 8));
        let limit = Duration::from_micros((random >> 24) % 128);
        future_checks += live.values().any(|&start| start > now) as usize;
        let expected = live
            .values()
            .any(|&start| now.duration_since(start) >= limit);
        assert_eq!(conn.timed_out(now, limit), expected, "step {step}");
        assert_eq!(conn.streams.len(), live.len());
        assert!(
            conn.streams
                .iter()
                .map(|s| s.start)
                .eq(live.values().copied())
        );
        if expected || random % 16 == 14 {
            expirations += expected as usize;
            conn.close(0, &mut Vec::new());
            live.clear();
            next_id = 0;
        }
    }
    assert!(expirations > 100);
    assert!(future_checks > 1000);
}
