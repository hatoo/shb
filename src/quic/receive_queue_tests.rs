use super::*;

fn consume(recv: &mut RecvStream, delivered: &mut Vec<u8>) {
    recv.consume(|bytes| {
        delivered.extend_from_slice(bytes);
        Ok(())
    })
    .unwrap();
}

#[test]
fn receive_queue_permutations_preserve_bytes_credit_and_early_fin() {
    fn visit(order: &mut [usize], at: usize, check: &mut impl FnMut(&[usize])) {
        if at == order.len() {
            check(order);
        } else {
            for index in at..order.len() {
                order.swap(at, index);
                visit(order, at + 1, check);
                order.swap(at, index);
            }
        }
    }

    let expected = b"abcdefghijklmnopqrstu";
    let mut cases = 0;
    visit(&mut [1, 2, 3, 4, 5, 6], 0, &mut |order| {
        let mut recv = RecvStream::new(expected.len() as u64);
        let mut credited = 0;
        for &part in order {
            let offset = part * 3;
            credited += recv
                .push_with_credit(
                    offset as u64,
                    &expected[offset..offset + 3],
                    part == 6,
                    expected.len() as u64 - credited,
                )
                .unwrap();
            assert!(!recv.has_data());
            assert!(!recv.is_finished());
        }
        assert_eq!(credited, expected.len() as u64);
        assert!(recv.size_known());
        assert_eq!(recv.push_with_credit(0, &expected[..3], false, 0), Ok(0));
        assert!(recv.is_finished());
        let mut delivered = Vec::new();
        consume(&mut recv, &mut delivered);
        assert_eq!(delivered, expected);
        assert_eq!(recv.push_with_credit(0, expected, true, 0), Ok(0));
        consume(&mut recv, &mut delivered);
        assert_eq!(delivered, expected);
        cases += 1;
    });
    assert_eq!(cases, 720);
}

#[test]
fn receive_queue_large_reordering_overlaps_and_buffer_reuse() {
    let expected: Vec<u8> = (0..=4096).map(|i| (i % 251) as u8).collect();
    let mut pooled = Vec::new();
    for round in 0..3 {
        let mut recv = RecvStream::with_buf(expected.len() as u64, pooled);
        // An odd multiplier permutes all 4096 suffix offsets. Withhold byte
        // zero so every fragment must survive the queue, including duplicates.
        let mut credited = 0;
        for index in 0..4096 {
            let offset = (index * 2053 + round * 17) % 4096 + 1;
            let end = (offset + 5).min(expected.len());
            credited += recv
                .push_with_credit(
                    offset as u64,
                    &expected[offset..end],
                    end == expected.len(),
                    expected.len() as u64 - credited,
                )
                .unwrap();
            if index % 17 == 0 {
                assert_eq!(
                    recv.push_with_credit(offset as u64, &expected[offset..end], false, 0),
                    Ok(0)
                );
            }
        }
        assert_eq!(credited, expected.len() as u64);
        assert!(!recv.has_data());
        assert_eq!(recv.push_with_credit(0, &expected[..1], false, 0), Ok(0));
        assert!(recv.is_finished());
        let mut delivered = Vec::new();
        consume(&mut recv, &mut delivered);
        assert_eq!(delivered, expected);
        pooled = recv.take_buf();
    }
}

#[test]
fn receive_queue_partial_consumption_keeps_later_gaps_and_failed_reads() {
    let expected = b"abcdefghijklmnopqrstuvwxyz";
    let mut recv = RecvStream::new(26);
    assert_eq!(recv.push(20, &expected[20..], true), Ok(26));
    assert_eq!(
        recv.push_with_credit(10, &expected[10..16], false, 0),
        Ok(0)
    );
    assert_eq!(recv.push_with_credit(4, &expected[4..10], false, 0), Ok(0));
    assert_eq!(recv.push_with_credit(0, &expected[..4], false, 0), Ok(0));
    assert!(!recv.is_finished());
    assert!(
        recv.consume(|bytes| {
            assert_eq!(bytes, &expected[..16]);
            anyhow::bail!("consumer rejected bytes")
        })
        .is_err()
    );
    let mut delivered = Vec::new();
    consume(&mut recv, &mut delivered);
    assert_eq!(delivered, &expected[..16]);
    assert_eq!(
        recv.push_with_credit(17, &expected[17..22], false, 0),
        Ok(0)
    );
    assert!(!recv.has_data());
    assert_eq!(
        recv.push_with_credit(14, &expected[14..18], false, 0),
        Ok(0)
    );
    assert!(recv.is_finished());
    consume(&mut recv, &mut delivered);
    assert_eq!(delivered, expected);
}

#[test]
fn receive_queue_rejects_invalid_credit_and_final_size_before_queueing() {
    let mut recv = RecvStream::new(12);
    assert_eq!(recv.push(8, b"ijkl", false), Ok(12));
    assert_eq!(
        recv.push_with_credit(12, b"m", false, 0),
        Err(RecvError::FlowControl)
    );
    assert_eq!(recv.push(10, b"", true), Err(RecvError::FinalSize));
    assert!(!recv.size_known());
    assert_eq!(recv.reset(12, 0), Ok(0));
    assert_eq!(recv.reset(12, 0), Ok(0));
    assert_eq!(recv.push(12, b"m", false), Err(RecvError::FinalSize));
    assert_eq!(recv.push_with_credit(0, b"abcdefgh", false, 0), Ok(0));
    assert!(recv.is_finished());
    let mut delivered = Vec::new();
    consume(&mut recv, &mut delivered);
    assert_eq!(delivered, b"abcdefghijkl");
}
