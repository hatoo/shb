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
    // The existing conservative prefix policy retains a sparse ACK's data
    // until another ACK covers it; this change does not alter that policy.
    s.on_acked(4096, 4096, true);
    assert!(s.is_settled());
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
