//! Peer stream limits count stream IDs, including implicit gaps, for the life
//! of the connection. They do not count only streams currently holding data.
use super::*;

fn fixture(limit: u64) -> Connection {
    Connection::connect(
        crate::tls::client_config(b"h3").unwrap(),
        "localhost",
        LocalParamsInput {
            initial_max_data: 1 << 20,
            initial_max_stream_data: 1 << 20,
            initial_max_streams_uni: limit,
            max_idle_timeout_ms: 5_000,
            handshake_timeout_ms: 5_000,
        },
    )
    .unwrap()
}

fn rejected(conn: &mut Connection, id: u64, reset: bool) {
    let before = (
        conn.peer_uni.len(),
        conn.peer_uni.capacity(),
        conn.data_received,
        conn.unanswered,
    );
    let events: Vec<_> = conn.events.iter().collect();
    assert!(events.is_empty());
    let result = if reset {
        conn.on_reset(id, 42, 65_536)
    } else {
        conn.on_stream(id, 0, &[0xaa; 65_536], true)
    };
    let error = result.expect_err("an out-of-limit peer stream must be rejected");
    assert_eq!(
        error
            .downcast_ref::<RecvError>()
            .copied()
            .map(RecvError::code),
        Some(4)
    );
    assert_eq!(
        (
            conn.peer_uni.len(),
            conn.peer_uni.capacity(),
            conn.data_received,
            conn.unanswered
        ),
        before,
        "rejection must not allocate stream storage or change accounting"
    );
    assert!(conn.events.is_empty());
}

#[test]
fn peer_stream_limit_zero_rejects_stream_and_reset_before_registration() {
    for reset in [false, true] {
        let mut conn = fixture(0);
        rejected(&mut conn, 3, reset);
        rejected(&mut conn, 7, reset);
    }
}

#[test]
fn peer_stream_limit_uses_advertised_count_and_not_registered_count() {
    for limit in [1, 3, 16] {
        for reset in [false, true] {
            let mut conn = fixture(limit);
            // Even the first received stream can already exceed the limit.
            rejected(&mut conn, 4 * limit + 3, reset);
            rejected(&mut conn, 4 * (limit + 1) + 3, reset);
            let last = 4 * (limit - 1) + 3;
            if reset {
                conn.on_reset(last, 42, 8).unwrap();
            } else {
                conn.on_stream(last, 0, b"abcdefgh", true).unwrap();
            }
            assert_eq!(conn.peer_uni.len(), 1, "implicit gaps need no entries");
            assert_eq!(conn.peer_uni[0].0, last);
            assert_eq!(conn.data_received, 8);
        }
    }
}

#[test]
fn peer_stream_limit_rejects_all_server_bidirectional_ids() {
    for reset in [false, true] {
        let mut conn = fixture(3);
        conn.max_streams_bidi = 100;
        let request = conn.open_bi().unwrap();
        for id in [1, 5, 9, (1 << 62) - 3] {
            rejected(&mut conn, id, reset);
        }
        conn.on_stream(request, 0, b"response", true).unwrap();
        assert_eq!(conn.unanswered, 0);
    }
}

#[test]
fn peer_stream_limit_handles_maximum_ids_without_overflow_or_gap_allocation() {
    let last = (1 << 62) - 1;
    for reset in [false, true] {
        rejected(&mut fixture((1 << 60) - 1), last, reset);
        let mut conn = fixture(1 << 60);
        if reset {
            conn.on_reset(last, 42, 0).unwrap();
        } else {
            conn.on_stream(last, 0, b"", false).unwrap();
        }
        assert_eq!(conn.peer_uni.len(), 1);
        assert_eq!(conn.peer_uni[0].0, last);
        assert_eq!(conn.data_received, 0);
    }
}

#[test]
fn peer_stream_limit_preserves_reordering_duplicates_and_reset_first() {
    let mut conn = fixture(3);
    conn.on_reset(11, 42, 8).unwrap();
    conn.on_stream(7, 4, b"efgh", true).unwrap();
    conn.on_stream(3, 0, b"abcd", false).unwrap();
    conn.on_stream(7, 0, b"abcdef", false).unwrap();
    conn.on_stream(3, 4, b"efgh", true).unwrap();
    for id in [11, 3, 7] {
        conn.on_stream(id, 0, b"abcdefgh", true).unwrap();
        conn.on_reset(id, 42, 8).unwrap();
        conn.on_reset(id, 42, 8).unwrap();
    }
    assert_eq!(
        conn.peer_uni.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        [11, 7, 3]
    );
    assert_eq!(conn.data_received, 24);
    assert_eq!(conn.unanswered, 0);
    assert_eq!(
        conn.events
            .iter()
            .filter(|e| matches!(e, Event::Opened(_)))
            .count(),
        3
    );
    assert!(
        !conn
            .events
            .iter()
            .any(|e| matches!(e, Event::Finished { .. } | Event::Lost(_)))
    );
    conn.events.clear();
    // Finishing/resetting earlier streams does not replenish a cumulative limit.
    rejected(&mut conn, 15, false);
    rejected(&mut conn, 15, true);
}

#[test]
fn peer_stream_limit_rejects_empty_frames_and_checks_existing_entries() {
    for reset in [false, true] {
        for id in [1, 15] {
            let mut conn = fixture(3);
            // Model an existing entry: the check must precede both lookup and
            // registration, not just insertion into the vector.
            conn.peer_uni.push((id, RecvStream::new(1 << 20)));
            let result = if reset {
                conn.on_reset(id, 42, 0)
            } else {
                conn.on_stream(id, 0, b"", false)
            };
            let error = result.unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<RecvError>()
                    .copied()
                    .map(RecvError::code),
                Some(4)
            );
            assert_eq!(conn.peer_uni.len(), 1);
            assert!(!conn.peer_uni[0].1.size_known());
            assert_eq!(conn.data_received, 0);
            assert!(conn.events.is_empty());
        }
    }
}

#[test]
fn peer_stream_limit_does_not_use_the_peers_outgoing_stream_credit() {
    let mut conn = fixture(1);
    conn.handle_frame(
        Space::Data,
        Frame::MaxStreams {
            uni: true,
            limit: 100,
        },
        Instant::now(),
    )
    .unwrap();
    conn.handle_frame(
        Space::Data,
        Frame::MaxStreams {
            uni: false,
            limit: 100,
        },
        Instant::now(),
    )
    .unwrap();
    rejected(&mut conn, 7, false);
    rejected(&mut conn, 7, true);
    // Incoming peer stream limits do not limit our own request stream IDs.
    let mut ids = Vec::new();
    for _ in 0..5 {
        ids.push(conn.open_bi().unwrap());
    }
    for id in ids.into_iter().rev() {
        conn.on_stream(id, 0, b"response", true).unwrap();
    }
    assert_eq!(conn.unanswered, 0);
    assert_eq!(conn.data_received, 40);
    assert!(conn.peer_uni.is_empty());
}
