use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    number: u64,
    time: Instant,
    size: usize,
    eliciting: bool,
}

impl Record {
    fn packet(&self) -> SentPacket {
        SentPacket {
            ack_largest: None,
            number: self.number,
            time_sent: self.time,
            size: self.size,
            ack_eliciting: self.eliciting,
            frames: Vec::new(),
        }
    }

    fn read(packet: &SentPacket) -> Self {
        Self {
            number: packet.number,
            time: packet.time_sent,
            size: packet.size,
            eliciting: packet.ack_eliciting,
        }
    }
}

#[derive(Default)]
struct Model {
    live: Vec<Record>,
    largest: Option<u64>,
    last: Option<Instant>,
}

impl Model {
    fn check(&self, sent: &SentPackets) {
        let recomputed: usize = self
            .live
            .iter()
            .filter(|p| p.eliciting)
            .map(|p| p.size)
            .sum();
        assert_eq!(sent.bytes_in_flight(), recomputed);
        assert_eq!(
            sent.any_ack_eliciting(),
            self.live.iter().any(|p| p.eliciting)
        );
        assert_eq!(sent.largest_acked, self.largest);
        assert_eq!(sent.last_ack_eliciting, self.last);
        assert_eq!(
            sent.packets.iter().map(Record::read).collect::<Vec<_>>(),
            self.live
        );
    }

    fn push(&mut self, sent: &mut SentPackets, record: Record) {
        sent.push(record.packet());
        if record.eliciting {
            self.last = Some(record.time);
        }
        self.live.push(record);
        self.check(sent);
    }

    fn ack(&mut self, sent: &mut SentPackets, ranges: &[(u64, u64)]) {
        let (expected, retained): (Vec<_>, Vec<_>) = self.live.drain(..).partition(|p| {
            ranges
                .iter()
                .any(|&(low, high)| (low..=high).contains(&p.number))
        });
        self.live = retained;
        self.largest = self
            .largest
            .into_iter()
            .chain(expected.iter().map(|p| p.number))
            .max();
        let mut out = Vec::new();
        sent.drain_acked(ranges, &mut out);
        assert_eq!(out.iter().map(Record::read).collect::<Vec<_>>(), expected);
        self.check(sent);
    }

    fn lose(&mut self, sent: &mut SentPackets, now: Instant, delay: Duration) {
        let (expected, retained): (Vec<_>, Vec<_>) = self.live.drain(..).partition(|p| {
            self.largest.is_some_and(|largest| {
                p.number <= largest && (largest - p.number >= 3 || now >= p.time + delay)
            })
        });
        self.live = retained;
        let deadline = self
            .live
            .iter()
            .filter(|p| self.largest.is_some_and(|largest| p.number <= largest))
            .map(|p| p.time + delay)
            .min();
        let (out, actual_deadline) = sent.detect_lost(now, delay);
        assert_eq!(out.iter().map(Record::read).collect::<Vec<_>>(), expected);
        assert_eq!(actual_deadline, deadline);
        self.check(sent);
    }
}

#[test]
fn every_ack_subset_removes_each_packet_from_the_total_once() {
    let now = Instant::now();
    for subset in 0u16..256 {
        let mut sent = SentPackets::default();
        let mut model = Model::default();
        for number in 0..8 {
            model.push(
                &mut sent,
                Record {
                    number,
                    time: now,
                    size: number as usize * 137,
                    eliciting: number % 3 != 1,
                },
            );
        }
        let ranges: Vec<_> = (0..8)
            .rev()
            .filter(|n| subset & (1 << n) != 0)
            .map(|n| (n, n))
            .collect();
        model.ack(&mut sent, &ranges);
        model.ack(&mut sent, &ranges);

        // Callers can append into a reused output. Packets that were already
        // there must never be subtracted from this flight a second time.
        let mut output = vec![
            Record {
                number: 99,
                time: now,
                size: usize::MAX,
                eliciting: true,
            }
            .packet(),
        ];
        sent.drain_acked(&[(0, 7), (4, 7), (0, 3)], &mut output);
        assert_eq!(output.len(), 1 + model.live.len());
        assert_eq!(sent.bytes_in_flight(), 0);
        assert!(!sent.any_ack_eliciting());
        sent.drain_acked(&[(0, 7)], &mut output);
        assert_eq!(sent.bytes_in_flight(), 0);
        assert_eq!(sent.largest_acked, Some(99));
    }
}

#[test]
fn wide_flights_keep_exact_totals_through_sparse_ack_and_loss() {
    let start = Instant::now();
    for count in [1u64, 32, 256, 4096] {
        let mut sent = SentPackets::default();
        let mut model = Model::default();
        for number in 0..count {
            let record = Record {
                number,
                time: start + Duration::from_micros(number),
                size: 40 + (number as usize * 19 % 1413),
                eliciting: number % 4 != 0,
            };
            sent.push(record.packet());
            if record.eliciting {
                model.last = Some(record.time);
            }
            model.live.push(record);
        }
        model.check(&sent);
        let mut ranges: Vec<_> = (0..count).step_by(7).map(|n| (n, n)).collect();
        ranges.reverse();
        ranges.push((count / 2, count / 2 + 2));
        model.ack(&mut sent, &ranges);
        model.ack(&mut sent, &ranges);
        model.lose(
            &mut sent,
            start + Duration::from_millis(5),
            Duration::from_millis(20),
        );
        model.lose(
            &mut sent,
            start + Duration::from_secs(1),
            Duration::from_millis(20),
        );
        model.ack(&mut sent, &[(0, count)]);
        assert_eq!(sent.bytes_in_flight(), 0);
        assert!(!sent.any_ack_eliciting());
    }
}

#[test]
fn mixed_events_and_space_resets_match_independent_recomputation() {
    let start = Instant::now();
    let rtt = Rtt::default();
    let ack_delay = Duration::from_millis(25);
    let congestion = Congestion {
        window: 2400,
        ..Congestion::default()
    };
    for seed in 1..=32 {
        let mut rng = seed;
        let mut random = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut spaces: [SentPackets; 3] = std::array::from_fn(|_| SentPackets::default());
        let mut models: [Model; 3] = std::array::from_fn(|_| Model::default());
        let mut next = [0u64; 3];
        for step in 0..512 {
            let slot = random() as usize % 3;
            let now = start + Duration::from_micros(step * 100);
            let sent = &mut spaces[slot];
            let model = &mut models[slot];
            match random() % 8 {
                0..=3 => {
                    let number = next[slot];
                    next[slot] += 1;
                    model.push(
                        sent,
                        Record {
                            number,
                            time: now,
                            size: (random() % 1453) as usize,
                            eliciting: random() % 3 != 0,
                        },
                    );
                }
                4 | 5 => {
                    let high = random() % (next[slot] + 1);
                    let low = high.saturating_sub(random() % 5);
                    model.ack(sent, &[(high, high), (low, high), (0, 0)]);
                    model.ack(sent, &[(low, high)]);
                }
                6 => model.lose(sent, now, Duration::from_micros(750)),
                _ => {
                    *sent = SentPackets::default();
                    *model = Model::default();
                    next[slot] = 0;
                }
            }
            for (sent, model) in spaces.iter().zip(&models) {
                model.check(sent);
            }
            let expected: usize = models
                .iter()
                .flat_map(|m| &m.live)
                .filter(|p| p.eliciting)
                .map(|p| p.size)
                .sum();
            let actual = spaces.iter().map(SentPackets::bytes_in_flight).sum();
            assert_eq!(actual, expected);
            assert_eq!(congestion.can_send(actual), expected < 2400);
            let expected_pto = models
                .iter()
                .enumerate()
                .filter(|(_, m)| m.live.iter().any(|p| p.eliciting))
                .map(|(i, m)| {
                    (
                        Space::ALL[i],
                        m.last.unwrap() + rtt.pto(if i == 2 { ack_delay } else { Duration::ZERO }),
                    )
                })
                .min_by_key(|(_, at)| *at);
            assert_eq!(
                pto_deadline(
                    &[&spaces[0], &spaces[1], &spaces[2]],
                    &rtt,
                    ack_delay,
                    0,
                    None
                ),
                expected_pto
            );
        }
    }
}

#[test]
fn loss_then_late_ack_does_not_remove_retransmitted_bytes() {
    let start = Instant::now();
    let mut sent = SentPackets::default();
    let mut model = Model::default();
    for number in 0..4 {
        model.push(
            &mut sent,
            Record {
                number,
                time: start + Duration::from_millis(number),
                size: (number as usize + 1) * 100,
                eliciting: true,
            },
        );
    }
    let delay = Duration::from_millis(10);
    model.ack(&mut sent, &[(3, 3)]);
    model.lose(&mut sent, start + Duration::from_millis(3), delay);
    assert_eq!(
        sent.bytes_in_flight(),
        500,
        "packet threshold removed packet 0"
    );
    model.push(
        &mut sent,
        Record {
            number: 4,
            time: start + delay,
            size: 100,
            eliciting: true,
        },
    );
    model.ack(&mut sent, &[(0, 0)]);
    assert_eq!(
        sent.bytes_in_flight(),
        600,
        "late ACK of lost packet 0 preserves new packet 4"
    );
    // Instant converts durations to clock ticks with rounding. Derive the
    // boundary from the actual send time, rather than adding elapsed durations
    // separately or converting the difference back to a Duration.
    let deadline = model.live.iter().find(|p| p.number == 1).unwrap().time + delay;
    model.lose(&mut sent, deadline - Duration::from_micros(1), delay);
    assert_eq!(sent.bytes_in_flight(), 600);
    model.lose(&mut sent, deadline, delay);
    assert_eq!(
        sent.bytes_in_flight(),
        400,
        "exact time threshold removes packet 1"
    );
    model.lose(&mut sent, start + Duration::from_secs(1), delay);
    assert_eq!(
        sent.bytes_in_flight(),
        100,
        "nothing above largest ACK is time-lost"
    );
    model.ack(&mut sent, &[(0, 3), (1, 2)]);
    assert_eq!(sent.bytes_in_flight(), 100);
    model.ack(&mut sent, &[(4, 4)]);
    assert_eq!(sent.bytes_in_flight(), 0);
}

#[test]
fn zero_bytes_and_ack_only_packets_preserve_presence_and_pto_semantics() {
    let now = Instant::now();
    let mut sent = SentPackets::default();
    let mut model = Model::default();
    model.push(
        &mut sent,
        Record {
            number: 0,
            time: now,
            size: 0,
            eliciting: true,
        },
    );
    model.push(
        &mut sent,
        Record {
            number: 1,
            time: now,
            size: usize::MAX,
            eliciting: false,
        },
    );
    assert_eq!(sent.bytes_in_flight(), 0);
    assert!(
        sent.any_ack_eliciting(),
        "presence cannot be inferred from byte count"
    );
    let empty = SentPackets::default();
    let rtt = Rtt::default();
    assert!(pto_deadline(&[&sent, &empty, &empty], &rtt, Duration::ZERO, 0, None).is_some());
    model.push(
        &mut sent,
        Record {
            number: 2,
            time: now,
            size: usize::MAX,
            eliciting: true,
        },
    );
    assert_eq!(sent.bytes_in_flight(), usize::MAX);
    model.ack(&mut sent, &[(2, 2)]);
    assert_eq!(sent.bytes_in_flight(), 0);
    assert!(sent.any_ack_eliciting());
    model.ack(&mut sent, &[(0, 0)]);
    assert!(!sent.any_ack_eliciting());
    assert!(pto_deadline(&[&sent, &empty, &empty], &rtt, Duration::ZERO, 0, None).is_none());
    model.ack(&mut sent, &[(1, 1)]);
}
