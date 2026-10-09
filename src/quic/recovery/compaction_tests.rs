use super::*;

/// A value snapshot also remembers each frame allocation. Moving a packet
/// must transfer that allocation intact to recovery or to the caller's pool.
#[derive(Debug, PartialEq, Eq)]
struct Packet {
    number: u64,
    ack_largest: Option<u64>,
    time_sent: Instant,
    size: usize,
    ack_eliciting: bool,
    frames: Vec<SentFrame>,
    frame_ptr: usize,
    frame_capacity: usize,
}

fn snapshot(packet: &SentPacket) -> Packet {
    Packet {
        number: packet.number,
        ack_largest: packet.ack_largest,
        time_sent: packet.time_sent,
        size: packet.size,
        ack_eliciting: packet.ack_eliciting,
        frames: packet.frames.clone(),
        frame_ptr: packet.frames.as_ptr() as usize,
        frame_capacity: packet.frames.capacity(),
    }
}

fn snapshots(packets: &[SentPacket]) -> Vec<Packet> {
    packets.iter().map(snapshot).collect()
}

fn packet(number: u64, time_sent: Instant) -> SentPacket {
    let ack_eliciting = !number.is_multiple_of(3);
    let frames = if ack_eliciting {
        vec![
            SentFrame::Crypto {
                offset: number * 17,
                len: 17,
            },
            SentFrame::Stream {
                id: number * 4,
                offset: number * 100,
                len: 100,
                fin: number.is_multiple_of(2),
            },
            SentFrame::Ping,
            SentFrame::RetireConnectionId(number),
            SentFrame::ResetStream {
                id: number * 4,
                error: 9,
                final_size: number * 100,
            },
            SentFrame::MaxData(number * 1000),
            SentFrame::MaxStreamData {
                id: number * 4,
                limit: number * 2000,
            },
        ]
    } else {
        Vec::new()
    };
    SentPacket {
        number,
        ack_largest: number.checked_sub(1),
        time_sent,
        size: 100 + number as usize,
        ack_eliciting,
        frames,
    }
}

fn assert_flight(sent: &SentPackets, expected: &[Packet], last: Option<Instant>) {
    assert_eq!(snapshots(&sent.packets), expected);
    assert_eq!(sent.last_ack_eliciting, last);
    let in_flight = expected.iter().filter(|p| p.ack_eliciting);
    assert_eq!(
        sent.bytes_in_flight(),
        in_flight.clone().map(|p| p.size).sum::<usize>()
    );
    let any = in_flight.count() != 0;
    assert_eq!(sent.any_ack_eliciting(), any);
    let rtt = Rtt::default();
    let empty = SentPackets::default();
    let delay = Duration::from_millis(25);
    assert_eq!(
        pto_deadline(&[&empty, &empty, sent], &rtt, delay, 1, None),
        if any {
            Some((Space::Data, last.unwrap() + rtt.pto(delay) * 2))
        } else {
            None
        }
    );
}

#[test]
fn every_small_ack_subset_preserves_packets_and_frame_allocations() {
    let now = Instant::now();
    for mask in 0..256 {
        for prior in [None, Some(5), Some(100)] {
            let mut sent = SentPackets::default();
            for n in 0..8 {
                sent.push(packet(n * 2, now + Duration::from_millis(n)));
            }
            sent.largest_acked = prior;
            let last = sent.last_ack_eliciting;
            let capacity = sent.packets.capacity();
            let ranges: Vec<_> = (0..8)
                .rev()
                .filter(|n| mask & (1 << n) != 0)
                .map(|n| (n * 2, n * 2))
                .collect();
            let (mut expected_acked, retained): (Vec<_>, Vec<_>) = snapshots(&sent.packets)
                .into_iter()
                .partition(|p| mask & (1 << (p.number / 2)) != 0);
            // The public method appends to its caller's existing output.
            let mut acked = vec![packet(31, now)];
            expected_acked.insert(0, snapshot(&acked[0]));
            let largest = prior
                .into_iter()
                .chain(expected_acked.iter().map(|p| p.number))
                .max();
            sent.drain_acked(&ranges, &mut acked);
            assert_eq!(snapshots(&acked), expected_acked);
            assert_eq!(sent.largest_acked, largest);
            assert_eq!(sent.packets.capacity(), capacity);
            assert_flight(&sent, &retained, last);

            acked.clear();
            sent.drain_acked(&ranges, &mut acked);
            assert!(acked.is_empty(), "duplicate ACKs must not extract twice");
            assert_eq!(sent.largest_acked, largest);
            assert_flight(&sent, &retained, last);
        }
    }
}

#[test]
fn wide_flights_survive_prefix_sparse_overlapping_and_reordered_acks() {
    let now = Instant::now();
    let mut sent = SentPackets::default();
    for n in 0..4096 {
        sent.push(packet(n, now));
    }
    let mut remaining = snapshots(&sent.packets);
    let last = sent.last_ack_eliciting;
    let mut largest = None;
    let mut acked = Vec::with_capacity(4096);
    for ranges in [
        vec![(0, 1023)],
        vec![(4090, 4095), (2000, 2500), (2100, 2600), (1500, 1500)],
        vec![(1024, 1200)],
        vec![(2000, 2500), (0, 1023)],
        vec![],
        vec![(0, u64::MAX)],
    ] {
        let (selected, retained): (Vec<_>, Vec<_>) = remaining
            .into_iter()
            .partition(|p| ranges.iter().any(|&(lo, hi)| (lo..=hi).contains(&p.number)));
        largest = largest
            .into_iter()
            .chain(selected.iter().map(|p| p.number))
            .max();
        acked.clear();
        sent.drain_acked(&ranges, &mut acked);
        assert_eq!(snapshots(&acked), selected);
        assert_eq!(sent.largest_acked, largest);
        assert_flight(&sent, &retained, last);
        assert_eq!(acked.capacity(), 4096);
        remaining = retained;
    }
    assert!(remaining.is_empty());
    assert_eq!(largest, Some(4095));
}

#[test]
fn loss_subsets_match_a_reference_partition_and_earliest_deadline() {
    let start = Instant::now();
    let delay = Duration::from_millis(3);
    let now = start + Duration::from_millis(5);
    for time_mask in 0..256 {
        for largest in [None, Some(0), Some(3), Some(8), Some(14), Some(19)] {
            let mut sent = SentPackets::default();
            for n in 0..8 {
                let time =
                    start + Duration::from_millis(if time_mask & (1 << n) == 0 { 10 } else { 0 });
                sent.push(packet(n * 2, time));
            }
            sent.largest_acked = largest;
            let last = sent.last_ack_eliciting;
            let capacity = sent.packets.capacity();
            let (expected_lost, retained): (Vec<_>, Vec<_>) =
                snapshots(&sent.packets).into_iter().partition(|p| {
                    largest.is_some_and(|largest| {
                        p.number <= largest
                            && (largest - p.number >= 3 || p.time_sent + delay <= now)
                    })
                });
            let expected_deadline = retained
                .iter()
                .filter(|p| largest.is_some_and(|largest| p.number <= largest))
                .map(|p| p.time_sent + delay)
                .min();
            let (lost, deadline) = sent.detect_lost(now, delay);
            assert_eq!(snapshots(&lost), expected_lost);
            assert_eq!(deadline, expected_deadline);
            assert_eq!(sent.largest_acked, largest);
            assert_eq!(sent.packets.capacity(), capacity);
            assert_flight(&sent, &retained, last);
            let (again, again_deadline) = sent.detect_lost(now, delay);
            assert!(again.is_empty(), "a packet can be lost only once");
            assert_eq!(again_deadline, deadline);
        }
    }
}

#[test]
fn ack_then_loss_keeps_boundary_packets_and_their_recyclable_frames() {
    let now = Instant::now();
    let mut sent = SentPackets::default();
    for n in 0..4096 {
        sent.push(packet(n, now));
    }
    let mut expected = snapshots(&sent.packets);
    let last = sent.last_ack_eliciting;
    let mut acked = Vec::new();
    sent.drain_acked(&[(4095, 4095)], &mut acked);
    assert_eq!(snapshot(&acked[0]), expected.pop().unwrap());
    let delay = Duration::from_millis(20);
    let deadline = now + delay;
    let (lost, next) = sent.detect_lost(deadline - Duration::from_micros(1), delay);
    assert_eq!(snapshots(&lost), expected[..4093]);
    assert_eq!(next, Some(deadline));
    assert_flight(&sent, &expected[4093..], last);
    let (mut final_lost, next) = sent.detect_lost(deadline, delay);
    assert_eq!(snapshots(&final_lost), expected[4093..]);
    assert_eq!(next, None);
    assert_flight(&sent, &[], last);
    assert_eq!(sent.largest_acked, Some(4095));

    // A caller can still take and reuse every frame list after compaction.
    for p in &mut final_lost {
        let mut frames = std::mem::take(&mut p.frames);
        let ptr = frames.as_ptr();
        let capacity = frames.capacity();
        frames.clear();
        if capacity != 0 {
            frames.push(SentFrame::Ping);
            assert_eq!(frames.as_ptr(), ptr);
        }
        assert!(p.frames.is_empty());
    }
}
