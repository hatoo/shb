use super::*;

fn open(conn: &mut Conn, started: &mut u64, budget: Budget) {
    let mut h2 = Connection::new();
    h2.initiate();
    conn.h2 = Some(h2);
    fill_streams(conn, &[0x82, 0x86, 0x84], &[], 3, started, budget, false);
}

fn answer(conn: &mut Conn, stats: &mut Stats, started: &mut u64, stream_id: u32) {
    process_events(
        conn,
        &[
            Event::Status {
                stream_id,
                status: 200,
            },
            Event::End { stream_id },
        ],
        stats,
        started,
    );
}

fn assert_samples(stats: &Stats, completed: u64) {
    assert_eq!(stats.completed, completed);
    assert_eq!(stats.latencies_ns.len() as u64, completed);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), completed);
}

#[test]
fn late_connect_failures_preserve_live_requests_and_their_timestamps() {
    let mut conn = Conn::new();
    let mut stats = Stats::default();
    let mut started = 0;
    let budget = Budget::Requests(3);
    open(&mut conn, &mut started, budget);
    assert_eq!(started, 3);
    let starts: Vec<_> = conn.streams.iter().map(|s| s.start).collect();
    // Several other connections fail while all units belong to this one.
    for _ in 0..4 {
        fail_connect(&mut stats, &mut started, budget);
    }
    assert_eq!((started, stats.errors, stats.connect_errors), (3, 0, 0));
    assert!(conn.streams.iter().map(|s| s.start).eq(starts));
    for id in [3, 5, 1] {
        answer(&mut conn, &mut stats, &mut started, id);
        fail_connect(&mut stats, &mut started, budget);
    }
    assert_eq!((started, stats.errors, stats.connect_errors), (3, 0, 0));
    assert_samples(&stats, 3);
}

#[test]
fn failed_attempts_charge_only_unassigned_budget_at_each_boundary() {
    for initial in [0, 2, 3, 4] {
        let mut stats = Stats::default();
        let mut started = initial;
        fail_connect(&mut stats, &mut started, Budget::Requests(3));
        let charged = u64::from(initial < 3);
        assert_eq!(started, initial + charged);
        assert_eq!((stats.errors, stats.connect_errors), (charged, charged));
        assert_samples(&stats, 0);
    }
    let mut stats = Stats::default();
    let mut started = 0;
    for _ in 0..16 {
        fail_connect(&mut stats, &mut started, Budget::Requests(3));
    }
    assert_eq!((started, stats.errors, stats.connect_errors), (3, 3, 3));
    assert_samples(&stats, 0);
}

#[test]
fn exhausted_budget_still_fails_live_requests_and_held_give_backs_once() {
    let mut conn = Conn::new();
    let mut stats = Stats::default();
    let mut started = 0;
    let budget = Budget::Requests(3);
    open(&mut conn, &mut started, budget);
    process_events(
        &mut conn,
        &[
            Event::Unprocessed { stream_id: 1 },
            Event::Unprocessed { stream_id: 5 },
            Event::Goaway,
        ],
        &mut stats,
        &mut started,
    );
    assert_eq!((conn.streams.len(), conn.held, started), (1, 2, 3));
    fail_connect(&mut stats, &mut started, budget);
    assert_eq!((stats.errors, stats.connect_errors), (0, 0));
    conn.fail_inflight(&mut stats);
    conn.fail_inflight(&mut stats);
    assert_eq!((started, stats.errors, stats.connect_errors), (3, 3, 0));
    assert_samples(&stats, 0);
}

#[test]
fn a_confirmed_give_back_can_pay_for_a_later_connect_failure() {
    let mut conn = Conn::new();
    let mut stats = Stats::default();
    let mut started = 0;
    let budget = Budget::Requests(3);
    open(&mut conn, &mut started, budget);
    process_events(
        &mut conn,
        &[Event::Unprocessed { stream_id: 5 }, Event::Goaway],
        &mut stats,
        &mut started,
    );
    fail_connect(&mut stats, &mut started, budget);
    assert_eq!((started, stats.errors, conn.held), (3, 0, 1));
    answer(&mut conn, &mut stats, &mut started, 1);
    let samples = stats.latencies_ns.clone();
    assert_eq!((started, conn.held), (2, 0));
    fail_connect(&mut stats, &mut started, budget);
    conn.fail_inflight(&mut stats);
    assert_eq!((started, stats.errors, stats.connect_errors), (3, 2, 1));
    assert_eq!(stats.latencies_ns, samples);
    assert_samples(&stats, 1);
}

#[test]
fn duration_runs_continue_counting_failed_attempts() {
    let mut stats = Stats::default();
    let mut started = 7;
    fail_connect(
        &mut stats,
        &mut started,
        Budget::Duration(Duration::from_secs(1)),
    );
    assert_eq!((started, stats.errors, stats.connect_errors), (8, 1, 1));
    assert_samples(&stats, 0);
}
