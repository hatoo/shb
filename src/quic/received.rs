//! Bounded duplicate history, independent of ACK serialization and ACK-of-ACK.

#[derive(Default)]
pub(super) struct ReceivedPackets {
    /// Inclusive ranges, largest first. In-order traffic uses just one range,
    /// regardless of the connection's age or packet rate.
    ranges: Vec<(u64, u64)>,
    /// Forgotten history cannot become eligible for processing again. This
    /// floor also discards unseen gaps below it (RFC 9000 Section 12.3).
    minimum: u64,
}

impl ReceivedPackets {
    // Bound sparse history while allowing substantial reordering. This limit
    // counts gaps rather than packets, so a long in-order burst cannot evict a
    // delayed packet by itself. At most 4096 bytes of range storage per space.
    const MAX_RANGES: usize = 256;

    /// Record an authenticated packet, returning true only for a new number.
    pub(super) fn insert(&mut self, pn: u64) -> bool {
        if pn < self.minimum {
            return false;
        }
        let at = self.ranges.partition_point(|r| r.0 > pn);
        if self.ranges.get(at).is_some_and(|r| pn <= r.1) {
            return false;
        }
        let above = at > 0 && self.ranges[at - 1].0.checked_sub(1) == Some(pn);
        let below = self
            .ranges
            .get(at)
            .is_some_and(|r| r.1.checked_add(1) == Some(pn));
        match (above, below) {
            (true, true) => {
                self.ranges[at - 1].0 = self.ranges[at].0;
                self.ranges.remove(at);
            }
            (true, false) => self.ranges[at - 1].0 = pn,
            (false, true) => self.ranges[at].1 = pn,
            (false, false) => {
                // Evict before inserting to keep capacity, not just length,
                // bounded. A new oldest range can be discarded immediately.
                if self.ranges.len() == Self::MAX_RANGES {
                    if at == Self::MAX_RANGES {
                        self.minimum = pn + 1;
                        return false;
                    }
                    self.minimum = self.ranges.pop().unwrap().1 + 1;
                }
                self.ranges.insert(at, (pn, pn));
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn contiguous_traffic_preserves_old_gaps_and_uses_one_range() {
        let mut history = ReceivedPackets::default();
        assert!(history.insert(0));
        for pn in 2..10_000 {
            assert!(history.insert(pn));
        }
        assert_eq!(history.ranges, [(2, 9999), (0, 0)]);
        assert!(history.insert(1));
        assert_eq!(history.ranges, [(0, 9999)]);
        for pn in [0, 1, 300, 9999] {
            assert!(!history.insert(pn));
        }
        assert_eq!(history.minimum, 0);
    }

    #[test]
    fn evicted_ranges_and_their_gaps_never_become_new_again() {
        let mut history = ReceivedPackets::default();
        for pn in (0..=1024).step_by(2) {
            assert!(history.insert(pn));
        }
        assert_eq!(history.ranges.len(), ReceivedPackets::MAX_RANGES);
        assert_eq!(history.minimum, 513);
        assert!(history.ranges.capacity() <= ReceivedPackets::MAX_RANGES);
        for pn in 0..513 {
            assert!(!history.insert(pn));
        }
        // The gap immediately below the oldest retained range can still join it.
        assert!(history.insert(513));
        assert!(!history.insert(512));
        assert_eq!(history.minimum, 513);
        assert!(history.insert(515));
        assert_eq!(history.ranges.len(), ReceivedPackets::MAX_RANGES - 1);
    }

    #[test]
    fn older_new_range_at_capacity_advances_the_floor_without_growing() {
        let mut history = ReceivedPackets::default();
        for pn in (1000..1512).step_by(2) {
            assert!(history.insert(pn));
        }
        assert!(!history.insert(500));
        assert_eq!(history.minimum, 501);
        assert!(!history.insert(499));
        assert!(history.insert(999));
        assert_eq!(history.ranges.len(), ReceivedPackets::MAX_RANGES);
        assert!(history.ranges.capacity() <= ReceivedPackets::MAX_RANGES);
    }

    #[test]
    fn packet_number_boundaries_do_not_wrap() {
        for top in [(1 << 62) - 1, u64::MAX] {
            let mut history = ReceivedPackets::default();
            for pn in [top, top - 2, top - 1, 0, 1] {
                assert!(history.insert(pn));
                assert!(!history.insert(pn));
            }
            assert_eq!(history.ranges, [(top - 2, top), (0, 1)]);
        }
    }

    #[test]
    fn bounded_history_matches_an_independent_set_model() {
        for seed in [1_u64, 0x132, 0x5eed] {
            let mut history = ReceivedPackets::default();
            let mut seen = BTreeSet::new();
            let mut floor = 0;
            let mut rng = seed;
            for step in 0..8000 {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                let pn = if step < 1000 { step * 2 } else { rng % 16_000 };
                let fresh = pn >= floor && seen.insert(pn);
                let mut ranges = Vec::<(u64, u64)>::new();
                for &n in &seen {
                    if let Some(last) = ranges.last_mut()
                        && last.1 + 1 == n
                    {
                        last.1 = n;
                    } else {
                        ranges.push((n, n));
                    }
                }
                if ranges.len() > ReceivedPackets::MAX_RANGES {
                    floor = ranges.remove(0).1 + 1;
                    seen = seen.split_off(&floor);
                }
                assert_eq!(
                    history.insert(pn),
                    fresh && pn >= floor,
                    "seed {seed}, step {step}"
                );
                ranges.reverse();
                assert_eq!(history.ranges, ranges);
                assert_eq!(history.minimum, floor);
                assert!(history.ranges.capacity() <= ReceivedPackets::MAX_RANGES);
            }
        }
    }
}
