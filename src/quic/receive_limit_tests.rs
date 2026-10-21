use super::*;

// Include contents and capacities: a rejected frame must neither copy its data
// nor reserve space for it, even when a buffer came from the reuse pool.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    ready: Vec<u8>,
    ready_capacity: usize,
    pending: Vec<(u64, Vec<u8>)>,
    pending_capacity: usize,
    read_offset: u64,
    received: u64,
    final_size: Option<u64>,
}

fn snapshot(recv: &RecvStream) -> Snapshot {
    Snapshot {
        ready: recv.ready.clone(),
        ready_capacity: recv.ready.capacity(),
        pending: recv.pending.clone(),
        pending_capacity: recv.pending.capacity(),
        read_offset: recv.read_offset,
        received: recv.received,
        final_size: recv.final_size,
    }
}

#[test]
fn receive_limits_check_stream_and_connection_boundaries_without_mutation() {
    for pooled in [false, true] {
        for (window, credit) in [(8, 16), (16, 8)] {
            for offset in [0, 4, 8, 9] {
                for length in [0, 1, 4, 7, 8, 9, 65536] {
                    for fin in [false, true] {
                        let data = vec![0xab; length];
                        let mut recv = RecvStream::with_buf(
                            window,
                            if pooled {
                                Vec::with_capacity(16)
                            } else {
                                Vec::new()
                            },
                        );
                        let before = snapshot(&recv);
                        let result = recv.push_with_credit(offset, &data, fin, credit);
                        if offset + length as u64 <= 8 {
                            assert_eq!(result, Ok(offset + length as u64));
                        } else {
                            assert_eq!(result, Err(RecvError::FlowControl));
                            assert_eq!(snapshot(&recv), before);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn receive_limits_count_high_water_once_across_reordering_overlap_and_fin() {
    let mut recv = RecvStream::new(8);
    assert_eq!(recv.push_with_credit(6, b"gh", true, 8), Ok(8));
    assert_eq!(recv.push_with_credit(3, b"defg", false, 0), Ok(0));
    assert_eq!(recv.push_with_credit(6, b"gh", true, 0), Ok(0));
    assert_eq!(recv.push_with_credit(0, b"abcd", false, 0), Ok(0));
    assert!(recv.is_finished());
    assert_eq!(recv.ready, b"abcdefgh");
    recv.consume(|data| {
        assert_eq!(data, b"abcdefgh");
        Ok(())
    })
    .unwrap();
    assert_eq!(recv.push_with_credit(0, b"abcdefgh", true, 0), Ok(0));
    assert!(!recv.has_data());
    assert_eq!(recv.received, 8);
}

#[test]
fn receive_limits_validate_final_size_against_high_water_before_mutation() {
    for reset in [false, true] {
        let mut recv = RecvStream::new(16);
        recv.push(6, b"gh", false).unwrap();
        let before = snapshot(&recv);
        let result = if reset {
            recv.reset(7, 16)
        } else {
            recv.push(7, b"", true)
        };
        assert_eq!(result, Err(RecvError::FinalSize));
        assert_eq!(snapshot(&recv), before);
        recv.push(8, b"", true).unwrap();
        let before = snapshot(&recv);
        for size in [7, 9] {
            let result = if reset {
                recv.reset(size, 16)
            } else {
                recv.push(size, b"", true)
            };
            assert_eq!(result, Err(RecvError::FinalSize));
            assert_eq!(snapshot(&recv), before);
        }
    }
}

#[test]
fn receive_limits_reset_checks_credit_and_preserves_duplicate_accounting() {
    for (window, credit) in [(8, 16), (16, 4)] {
        let mut recv = RecvStream::new(window);
        recv.push(2, b"cd", false).unwrap();
        let before = snapshot(&recv);
        assert_eq!(recv.reset(9, credit), Err(RecvError::FlowControl));
        assert_eq!(snapshot(&recv), before);
        assert_eq!(recv.reset(8, credit), Ok(4));
        assert_eq!(recv.reset(8, 0), Ok(0));
        assert_eq!(recv.push_with_credit(4, b"efgh", true, 0), Ok(0));
        assert_eq!(recv.received, 8);
    }
}

#[test]
fn receive_limits_grants_are_monotonic_and_pool_reuse_starts_fresh() {
    let mut recv = RecvStream::new(8);
    recv.push(0, b"abcd", false).unwrap();
    recv.consume(|_| Ok(())).unwrap();
    assert!(recv.wants_credit(8));
    assert_eq!(recv.push(8, b"i", false), Err(RecvError::FlowControl));
    assert_eq!(recv.grant(8), 12);
    assert_eq!(recv.grant(1), 12);
    assert_eq!(recv.push_with_credit(4, b"efghijkl", true, 8), Ok(8));
    let mut reused = RecvStream::with_buf(2, recv.take_buf());
    assert_eq!(reused.push(2, b"c", false), Err(RecvError::FlowControl));
    assert_eq!(reused.push(0, b"ab", true), Ok(2));
    assert_eq!(reused.ready, b"ab");
}

#[test]
fn receive_limits_reject_offset_overflow_in_both_profiles() {
    for (offset, data) in [
        (u64::MAX, &b"x"[..]),
        ((1 << 62) - 1, &b"x"[..]),
        (1 << 62, &b""[..]),
    ] {
        let mut recv = RecvStream::default();
        let before = snapshot(&recv);
        assert_eq!(
            recv.push(offset, data, false),
            Err(RecvError::FrameEncoding)
        );
        assert_eq!(snapshot(&recv), before);
    }
    let mut recv = RecvStream::new((1 << 62) - 1);
    assert_eq!(recv.push((1 << 62) - 1, b"", true), Ok((1 << 62) - 1));
}

#[test]
fn receive_limits_crypto_reassembly_does_not_use_application_credit() {
    let mut recv = RecvStream::default();
    recv.push(8192, &[2; 8192], false).unwrap();
    recv.push(0, &[1; 8192], false).unwrap();
    assert_eq!(recv.ready.len(), 16384);
    assert_eq!(
        recv.consume(|data| {
            assert_eq!(&data[..8192], &[1; 8192]);
            Ok(())
        })
        .unwrap(),
        16384
    );
}
