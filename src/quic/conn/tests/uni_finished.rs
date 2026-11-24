// Adapted from hatoo/xdp-http c433 (MIT); transport originally derived from shb.
use super::*;

fn events(conn: &mut Connection) -> Vec<Event> {
    std::iter::from_fn(|| conn.poll_event()).collect()
}

#[test]
fn peer_fin_waits_for_gaps_and_reports_readable_before_one_terminal_event() {
    let mut conn = client();
    conn.on_stream(3, 2, &[4, 0], true).unwrap();
    assert_eq!(events(&mut conn), [Event::Opened(3)]);
    conn.on_stream(3, 0, &[0x40], false).unwrap();
    assert_eq!(events(&mut conn), [Event::Readable(3)]);
    conn.consume(3, |bytes| {
        assert_eq!(bytes, &[0x40]);
        Ok(())
    })
    .unwrap();
    conn.on_stream(3, 1, &[0], false).unwrap();
    assert_eq!(
        events(&mut conn),
        [Event::Readable(3), Event::Finished { id: 3, reset: None }]
    );
    conn.consume(3, |bytes| {
        assert_eq!(bytes, &[0, 4, 0]);
        Ok(())
    })
    .unwrap();
    for _ in 0..1000 {
        conn.on_stream(3, 0, &[0x40, 0, 4, 0], true).unwrap();
        conn.on_reset(3, 42, 4).unwrap();
    }
    assert!(events(&mut conn).is_empty());
    assert_eq!(conn.data_received, 4);
    assert_eq!(conn.unanswered, 0);
}

#[test]
fn peer_reset_preserves_readable_data_and_notifies_once_even_with_late_fin() {
    for read_before_reset in [false, true] {
        let mut conn = client();
        conn.on_stream(3, 0, &[2], false).unwrap();
        events(&mut conn);
        if read_before_reset {
            conn.consume(3, |_| Ok(())).unwrap();
        }
        conn.on_reset(3, 42, 2).unwrap();
        let got = events(&mut conn);
        let mut expected = Vec::new();
        if !read_before_reset {
            expected.push(Event::Readable(3));
        }
        expected.push(Event::Finished {
            id: 3,
            reset: Some(42),
        });
        assert_eq!(got, expected);
        conn.on_stream(3, 1, &[0x20], true).unwrap();
        assert_eq!(events(&mut conn), [Event::Readable(3)]);
        conn.consume(3, |_| Ok(())).unwrap();
        for _ in 0..1000 {
            conn.on_reset(3, 43, 2).unwrap();
        }
        assert!(events(&mut conn).is_empty());
        assert_eq!(conn.data_received, 2);
    }
}

#[test]
fn reset_first_empty_fin_and_stream_limit_bound_terminal_events() {
    let mut conn = client();
    for id in [3, 7, 11] {
        conn.on_reset(id, 42, 1).unwrap();
        assert_eq!(
            events(&mut conn),
            [
                Event::Opened(id),
                Event::Finished {
                    id,
                    reset: Some(42)
                }
            ]
        );
        conn.on_stream(id, 0, &[2], true).unwrap();
        assert_eq!(events(&mut conn), [Event::Readable(id)]);
        conn.consume(id, |_| Ok(())).unwrap();
    }
    assert_eq!(conn.peer_uni.len(), 3);
    assert!(conn.on_reset(15, 42, 0).is_err());
    assert!(events(&mut conn).is_empty());
    assert_eq!(conn.data_received, 3);
    let mut empty = client();
    empty.on_stream(3, 0, &[], true).unwrap();
    assert_eq!(
        events(&mut empty),
        [Event::Opened(3), Event::Finished { id: 3, reset: None }]
    );
    for _ in 0..1000 {
        empty.on_stream(3, 0, &[], true).unwrap();
    }
    assert!(events(&mut empty).is_empty());
    println!(
        "peer receive entry: old={}B new={}B; terminal events <= advertised peer streams; HTTP/3 limit=3",
        std::mem::size_of::<(u64, RecvStream)>(),
        std::mem::size_of::<PeerUni>()
    );
}

#[test]
fn invalid_fin_reset_and_late_data_cannot_publish_or_mutate_terminal_state() {
    for terminal in [false, true] {
        let mut conn = client();
        conn.on_stream(3, 0, &[2], terminal).unwrap();
        events(&mut conn);
        let before = (conn.data_received, conn.peer_uni[0].finished);
        for result in [conn.on_reset(3, 42, 0), conn.on_reset(3, 42, (1 << 20) + 1)] {
            assert!(result.is_err());
        }
        assert_eq!((conn.data_received, conn.peer_uni[0].finished), before);
        assert!(events(&mut conn).is_empty());
        if terminal {
            assert!(conn.on_stream(3, 1, &[0x20], false).is_err());
            assert!(events(&mut conn).is_empty());
        }
    }
    let mut conn = client();
    conn.max_data_local = 1;
    assert!(conn.on_reset(3, 42, 2).is_err());
    assert!(conn.peer_uni.is_empty());
    assert!(events(&mut conn).is_empty());
}
