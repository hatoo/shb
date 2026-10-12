use super::SendStream;

fn body(len: usize) -> Vec<u8> {
    let mut state = 0x213a_57fe_8db9_c406_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

fn transmit(s: &mut SendStream, expected: &[u8], room: usize, credit: u64) -> usize {
    let (offset, data, fin) = s.next_send(room, credit).unwrap();
    assert_eq!(
        data,
        &expected[offset as usize..offset as usize + data.len()]
    );
    let len = data.len();
    s.on_sent(offset, len, fin)
}

#[test]
fn prefix_ack_does_not_move_the_retransmission_payload() {
    let data = body(262_151);
    let mut s = SendStream::new(data.len() as u64);
    s.write(&data);
    s.finish();
    let original = s.next_send(usize::MAX, u64::MAX).unwrap().1.as_ptr();
    assert_eq!(transmit(&mut s, &data, usize::MAX, u64::MAX), data.len());
    s.on_acked(0, 1024, false);
    s.on_lost(1024, 1152, false);
    let (offset, bytes, fin) = s.next_send(1152, 0).unwrap();
    assert_eq!((offset, bytes, fin), (1024, &data[1024..2176], false));
    assert_eq!(bytes.as_ptr(), original.wrapping_add(1024));
    assert_eq!(s.on_sent(offset, bytes.len(), fin), 0);
}

#[test]
fn append_after_prefix_release_preserves_unsent_and_lost_offsets() {
    let data = body(1536);
    let mut s = SendStream::new(1024);
    assert_eq!(s.write(&data), 1024);
    assert_eq!(transmit(&mut s, &data, 768, u64::MAX), 768);
    s.on_lost(512, 256, false);
    s.on_acked(0, 512, false);
    assert_eq!(s.writable(), 0, "ACKs do not grant stream credit");
    s.set_limit(1536);
    assert_eq!(s.write(&data[1024..]), 512);
    s.finish();
    assert_eq!(s.next_send(1024, 0), Some((512, &data[512..768], false)));
    assert_eq!(transmit(&mut s, &data, 1024, 0), 0);
    assert_eq!(
        s.next_send(1024, 0),
        None,
        "fresh data needs connection credit"
    );
    assert_eq!(transmit(&mut s, &data, 1024, u64::MAX), 768);
    assert!(s.fully_sent());
    s.on_acked(512, 1024, true);
    assert!(s.is_settled());
}

#[test]
fn packet_sized_acks_and_late_duplicate_loss_preserve_bytes_and_fin() {
    let data = body(131_083);
    for grant in [1, 1024, 65_536] {
        let mut s = SendStream::new(data.len() as u64);
        s.write(&data);
        s.finish();
        let mut fresh = 0;
        while s.has_pending() {
            fresh += transmit(&mut s, &data, grant, u64::MAX);
        }
        assert_eq!(fresh, data.len());
        let mut prefix = 0;
        while prefix < data.len() {
            let end = (prefix + grant).min(data.len());
            s.on_acked(prefix as u64, end - prefix, end == data.len());
            s.on_acked(prefix as u64, end - prefix, end == data.len());
            // A late loss overlaps the already released prefix. Only its
            // surviving suffix is retransmitted, spending no fresh credit.
            let lost_end = (end + 17).min(data.len());
            s.on_lost(prefix as u64, lost_end - prefix, false);
            if lost_end > end {
                assert_eq!(
                    s.next_send(17, 0),
                    Some((end as u64, &data[end..lost_end], false))
                );
                assert_eq!(transmit(&mut s, &data, 17, 0), 0);
            }
            assert!(!s.has_pending());
            prefix = end;
        }
        assert!(s.is_settled());
        assert_eq!(s.writable(), 0);
        assert_eq!(s.next_send(0, 0), None);
    }
}

#[test]
fn sparse_ack_does_not_discard_an_unacknowledged_gap() {
    let data = body(8192);
    let mut s = SendStream::new(8192);
    s.write(&data);
    s.finish();
    transmit(&mut s, &data, 8192, 8192);
    s.on_acked(4096, 4096, true);
    assert!(!s.is_settled());
    s.on_acked(0, 1024, false);
    s.on_lost(0, 4096, false);
    assert_eq!(s.next_send(8192, 0), Some((1024, &data[1024..4096], false)));
    assert_eq!(transmit(&mut s, &data, 8192, 0), 0);
    s.on_acked(1024, 3072, false);
    assert!(s.is_settled());
}

#[test]
fn sparse_ack_cancels_pending_loss_and_late_loss_cannot_restore_it() {
    let data = body(19);
    for ack_first in [false, true] {
        let mut s = SendStream::new(19);
        s.write(&data);
        s.on_sent(0, 16, false);
        if !ack_first {
            s.on_lost(0, 16, false);
        }
        s.on_acked(4, 4, false);
        s.on_acked(12, 4, false);
        if ack_first {
            s.on_lost(0, 16, false);
        }
        for (start, end) in [(0, 4), (8, 12)] {
            assert_eq!(
                s.next_send(100, 0),
                Some((start, &data[start as usize..end], false))
            );
            assert_eq!(transmit(&mut s, &data, 100, 0), 0);
        }
        assert_eq!(s.next_send(100, 0), None, "unsent bytes need fresh credit");
        s.on_acked(8, 4, false);
        s.on_acked(0, 4, false);
        assert_eq!(s.next_send(100, 3), Some((16, &data[16..], false)));
        assert_eq!(transmit(&mut s, &data, 100, 3), 3);
        s.finish();
        assert_eq!(transmit(&mut s, &data, 0, 0), 0);
        s.on_acked(16, 3, true);
        assert!(s.is_settled());
    }
}

#[test]
fn acknowledged_fin_is_not_retransmitted_after_loss_of_another_copy() {
    let mut s = SendStream::new(8);
    s.write(b"abcdefgh");
    s.finish();
    s.on_sent(0, 8, true);
    s.on_lost(0, 8, true);
    s.on_acked(4, 4, true);
    s.on_lost(4, 4, true);
    assert_eq!(s.next_send(8, 0), Some((0, &b"abcd"[..], false)));
    assert_eq!(s.on_sent(0, 4, false), 0);
    assert_eq!(s.next_send(8, 0), None);
    s.on_acked(0, 4, false);
    assert!(s.is_settled());
    s.on_lost(0, 8, true);
    assert!(!s.has_pending());
    assert!(s.fully_sent());
}

#[test]
fn overlapping_sparse_acks_merge_without_releasing_unsent_bytes() {
    let data = body(64);
    let mut s = SendStream::new(64);
    s.write(&data);
    s.on_sent(0, 48, false);
    for (start, end) in [(16, 24), (32, 40), (20, 36), (40, 48), (16, 48)] {
        s.on_acked(start, end - start as usize, false);
    }
    assert_eq!(s.acked, [(16, 48)]);
    s.on_acked(0, 8, false);
    s.on_acked(4, 12, false);
    assert_eq!(s.base_offset, 48);
    assert!(s.acked.is_empty());
    assert_eq!(s.writable(), 0);
    assert_eq!(s.next_send(64, 0), None);
    assert_eq!(s.next_send(64, 16), Some((48, &data[48..], false)));
    assert_eq!(transmit(&mut s, &data, 64, 16), 16);
    s.finish();
    transmit(&mut s, &data, 0, 0);
    s.on_acked(64, 0, true);
    assert!(!s.is_settled(), "FIN-only ACK does not cover the data");
    s.on_acked(48, 16, false);
    assert!(s.is_settled());
}

#[test]
fn ordered_acks_need_no_interval_allocation_and_reverse_acks_merge() {
    for reverse in [false, true] {
        let data = body(4096);
        let mut s = SendStream::new(4096);
        s.write(&data);
        s.finish();
        s.on_sent(0, data.len(), true);
        for n in 0..4096 {
            let offset = if reverse { 4095 - n } else { n };
            s.on_acked(offset, 1, offset == 4095);
            assert!(s.acked.len() <= 1);
            if !reverse {
                assert_eq!(s.acked.capacity(), 0);
            }
        }
        assert!(s.is_settled());
        assert!(s.acked.is_empty());
    }
}

#[test]
fn sparse_acks_survive_append_compaction_and_reset_discards_them() {
    let data = body(128);
    let mut s = SendStream::new(128);
    s.write(&data[..64]);
    s.on_sent(0, 64, false);
    s.on_acked(48, 16, false);
    s.on_acked(0, 32, false);
    // Reclaims the prefix while a remembered ACK uses absolute offsets.
    s.write(&data[64..]);
    assert_eq!(s.buf_start, 0);
    s.on_lost(0, 64, false);
    assert_eq!(s.next_send(128, 0), Some((32, &data[32..48], false)));
    transmit(&mut s, &data, 128, 0);
    s.on_acked(32, 16, false);
    assert_eq!(s.base_offset, 64);
    assert_eq!(transmit(&mut s, &data, 32, 32), 32);
    s.on_acked(80, 16, false);
    assert_eq!(s.reset(), 96);
    assert!(s.acked.is_empty());
    s.on_acked(64, 32, false);
    s.on_lost(64, 32, true);
    assert!(!s.has_pending());
    assert!(!s.is_settled());
    s.on_reset_acked();
    assert!(s.is_settled());
    let mut replacement = SendStream::with_buf(3, s.take_buf());
    replacement.write(b"new");
    replacement.finish();
    assert_eq!(replacement.next_send(3, 3), Some((0, &b"new"[..], true)));
    assert_eq!(replacement.acked.capacity(), 0);
}

/// Independent byte-set oracle: every acknowledged byte must disappear from
/// queued and future retransmissions, irrespective of range boundaries/order.
#[test]
fn sparse_ack_and_loss_sequences_match_a_byte_set() {
    const SENT: usize = 257;
    let data = body(SENT + 17);
    for seed in 1..=128 {
        let mut rng = seed * 0x13ab_752f_u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng as usize
        };
        let mut s = SendStream::new(data.len() as u64);
        s.write(&data);
        s.on_sent(0, SENT, false);
        let mut acked = [false; SENT];
        for _ in 0..512 {
            let start = next() % SENT;
            let end = (start + next() % 33 + 1).min(SENT);
            if next() % 3 == 0 {
                acked[start..end].fill(true);
                s.on_acked(start as u64, end - start, false);
            } else {
                s.on_lost(start as u64, end - start, false);
            }
            assert_eq!(
                s.base_offset as usize,
                acked.iter().take_while(|&&b| b).count()
            );
            assert_eq!(s.writable(), 0);
            assert!(s.acked.windows(2).all(|w| w[0].1 < w[1].0));
            if next() % 4 == 0 {
                while let Some((offset, bytes, fin)) = s.next_send(7, 0) {
                    let range = offset as usize..offset as usize + bytes.len();
                    assert!(!bytes.is_empty());
                    assert_eq!(bytes, &data[range.clone()]);
                    assert!(acked[range].iter().all(|b| !b));
                    assert!(!fin);
                    assert_eq!(s.on_sent(offset, bytes.len(), fin), 0);
                }
            }
        }
        for offset in (0..SENT).rev() {
            s.on_acked(offset as u64, 1, false);
        }
        s.on_lost(0, SENT, false);
        assert_eq!(s.next_send(100, 0), None);
        s.finish();
        assert_eq!(transmit(&mut s, &data, 100, 17), 17);
        s.on_acked(SENT as u64, 17, true);
        assert!(s.is_settled());
    }
}

#[test]
fn one_byte_ack_append_cycles_keep_storage_bounded() {
    const WINDOW: usize = 4096;
    let data = body(WINDOW * 17);
    let mut s = SendStream::new(data.len() as u64);
    s.write(&data[..WINDOW]);
    transmit(&mut s, &data, WINDOW, u64::MAX);
    for offset in 0..WINDOW * 16 {
        s.on_acked(offset as u64, 1, false);
        assert_eq!(s.write(&data[offset + WINDOW..offset + WINDOW + 1]), 1);
        assert_eq!(transmit(&mut s, &data, 1, 1), 1);
        assert!(
            s.buf.capacity() <= WINDOW * 2,
            "released prefixes must be reclaimed"
        );
    }
    s.finish();
    assert_eq!(s.next_send(0, 0), Some((data.len() as u64, &[][..], true)));
    assert_eq!(transmit(&mut s, &data, 0, 0), 0);
    s.on_acked((WINDOW * 16) as u64, WINDOW, true);
    assert!(s.is_settled());
}

#[test]
fn reset_after_prefix_release_preserves_final_size_and_pool_reuse() {
    let data = body(16_384);
    let mut s = SendStream::new(16_384);
    s.write(&data);
    transmit(&mut s, &data, 8192, u64::MAX);
    s.on_acked(0, 4096, false);
    assert_eq!(s.reset(), 8192);
    s.on_lost(0, 8192, true);
    s.on_acked(4096, 4096, false);
    s.set_limit(32_768);
    assert_eq!(s.write(b"ignored"), 0);
    assert_eq!(s.next_send(usize::MAX, u64::MAX), None);
    s.on_reset_acked();
    assert!(s.is_settled());
    let mut replacement = SendStream::with_buf(5, s.take_buf());
    assert_eq!(replacement.write(b"fresh"), 5);
    replacement.finish();
    assert_eq!(replacement.next_send(5, 5), Some((0, &b"fresh"[..], true)));
}

#[test]
fn recycling_a_partially_acked_buffer_discards_its_prefix_and_suffix() {
    let mut s = SendStream::new(8192);
    s.write(&body(8192));
    s.on_sent(0, 4096, false);
    s.on_acked(0, 1024, false);
    let mut replacement = SendStream::with_buf(3, s.take_buf());
    assert_eq!(replacement.writable(), 3);
    assert_eq!(replacement.write(b"new"), 3);
    replacement.finish();
    assert_eq!(replacement.next_send(3, 3), Some((0, &b"new"[..], true)));
}
