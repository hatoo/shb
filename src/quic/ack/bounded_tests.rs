use super::*;
use crate::quic::frame::{self, AckRanges, Frame};
use std::collections::BTreeSet;
use std::time::Duration;

fn model_ranges(packets: &BTreeSet<u64>) -> Vec<(u64, u64)> {
    let mut ranges = Vec::<(u64, u64)>::new();
    for &pn in packets {
        if let Some(last) = ranges.last_mut()
            && last.1 + 1 == pn
        {
            last.1 = pn;
        } else {
            ranges.push((pn, pn));
        }
    }
    ranges.reverse();
    ranges
}

fn assert_wire(ack: &AckState, expected: &[(u64, u64)], now: Instant) {
    assert_eq!(ack.ranges(), expected);
    if expected.is_empty() {
        return;
    }
    let delay = ack.delay(now, 3);
    let mut wire = Vec::new();
    frame::put_ack(&mut wire, ack.ranges(), delay);
    let mut frames = frame::Iter::new(&wire);
    let Frame::Ack {
        largest,
        first_range,
        ranges,
        delay: decoded_delay,
        range_count,
    } = frames.next().unwrap().unwrap()
    else {
        panic!("expected ACK");
    };
    assert_eq!(
        AckRanges::new(largest, first_range, ranges).collect::<Vec<_>>(),
        expected
    );
    assert_eq!(decoded_delay, delay);
    assert_eq!(range_count as usize + 1, expected.len());
    assert!(frames.next().is_none());
}

#[test]
fn sparse_ack_only_history_bounds_allocated_storage_as_well_as_wire_ranges() {
    let now = Instant::now();
    let mut ack = AckState::default();
    for n in 0..4096 {
        ack.record(n * 2, false, now);
        assert!(ack.ranges.len() <= 32);
        assert!(ack.ranges.capacity() <= 32);
        assert!(!ack.ack_eliciting_pending);
    }
    assert_wire(
        &ack,
        &(4064..4096)
            .rev()
            .map(|n| (n * 2, n * 2))
            .collect::<Vec<_>>(),
        now,
    );
    ack.trim_below(8190);
    assert!(ack.ranges.is_empty());
    assert!(
        ack.ranges.capacity() <= 32,
        "trimming must not retain an oversized allocation"
    );
}

#[test]
fn full_storage_still_extends_and_bridges_the_oldest_retained_range() {
    let now = Instant::now();
    let mut ack = AckState::default();
    for pn in (100..164).step_by(2) {
        ack.record(pn, false, now);
    }
    ack.record(0, true, now);
    assert_eq!(
        ack.ranges.len(),
        32,
        "discard a new range below the retained window"
    );
    assert!(
        ack.take_pending(),
        "processed eliciting packets still request an ACK"
    );
    ack.record(99, false, now);
    assert_eq!(ack.ranges.last(), Some(&(99, 100)));
    ack.record(101, false, now);
    assert_eq!(ack.ranges.last(), Some(&(99, 102)));
    assert_eq!(ack.ranges.len(), 31);
    ack.record(98, false, now);
    ack.record(97, false, now);
    assert_eq!(ack.ranges.last(), Some(&(97, 102)));
    assert!(ack.ranges.capacity() <= 32);
}

#[test]
fn eviction_does_not_invent_packets_when_later_gaps_merge() {
    let now = Instant::now();
    let mut ack = AckState::default();
    for pn in (0..=64).step_by(2) {
        ack.record(pn, false, now);
    }
    // 0 was forgotten. Filling all other gaps cannot resurrect it on the wire.
    for pn in (1..64).step_by(2) {
        ack.record(pn, true, now);
    }
    assert_wire(&ack, &[(1, 64)], now);
    ack.trim_below(32);
    assert_wire(&ack, &[(1, 64)], now); // Existing whole-range ACK-of-ACK policy.
    ack.trim_below(64);
    assert!(ack.ranges.is_empty());
    assert!(ack.take_pending());
}

#[test]
fn bounded_ranges_handle_zero_and_the_maximum_quic_packet_number() {
    let now = Instant::now();
    let max = (1_u64 << 62) - 1;
    let mut ack = AckState::default();
    for pn in [0, max, max - 2, max - 1, 1] {
        ack.record(pn, true, now);
    }
    assert_wire(&ack, &[(max - 2, max), (0, 1)], now);
    for pn in (0..128).rev().step_by(2) {
        ack.record(pn, false, now);
    }
    assert!(ack.ranges.capacity() <= 32);
    assert_eq!(ack.ranges()[0], (max - 2, max));
}

#[test]
fn bounded_storage_matches_a_set_and_wire_oracle_across_pruning_and_reordering() {
    for seed in [1_u64, 0x133, 0x5eed] {
        let start = Instant::now();
        let mut ack = AckState::default();
        let mut packets = BTreeSet::new();
        let mut rng = seed;
        let mut received_at = None;
        let mut pending = false;
        for step in 0..8000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let pn = if step < 512 { step * 2 } else { rng % 2048 };
            let now = start + Duration::from_micros(step * 100);
            let eliciting = rng & 1 != 0;
            if packets.last().is_none_or(|&n| pn > n) {
                received_at = Some(now);
            }
            pending |= eliciting;
            packets.insert(pn);
            let ranges = model_ranges(&packets);
            if ranges.len() > 32 {
                packets = packets.split_off(&ranges[31].0);
            }
            ack.record(pn, eliciting, now);
            if step % 97 == 96 {
                let cutoff = rng % 2048;
                let retained = model_ranges(&packets);
                packets.retain(|pn| {
                    retained
                        .iter()
                        .any(|&(lo, hi)| hi > cutoff && (lo..=hi).contains(pn))
                });
                ack.trim_below(cutoff);
            }
            assert_wire(&ack, &model_ranges(&packets), now);
            assert!(ack.ranges.capacity() <= 32, "seed {seed}, step {step}");
            assert_eq!(ack.ack_eliciting_pending, pending);
            let later = now + Duration::from_micros(8000);
            let expected = later
                .saturating_duration_since(received_at.unwrap())
                .as_micros() as u64
                >> 3;
            assert_eq!(ack.delay(later, 3), expected);
            if step % 11 == 0 {
                assert_eq!(ack.take_pending(), pending);
                pending = false;
            }
        }
    }
}
