//! What to acknowledge, and when (RFC 9000 Section 13.2)

use crate::clock::Instant;

/// Received packet numbers, kept as ranges largest first
///
/// A benchmark client receives packets almost entirely in order, so this
/// stays one or two ranges long and a linear walk beats anything cleverer.
#[derive(Default)]
pub struct AckState {
    /// (smallest, largest), descending and never touching
    ranges: Vec<(u64, u64)>,
    /// Set when something arrived that the peer wants acknowledged
    pub ack_eliciting_pending: bool,
    /// When the largest packet number was received, for the delay we report
    largest_received_at: Option<Instant>,
}

impl AckState {
    pub fn record(&mut self, pn: u64, ack_eliciting: bool, now: Instant) {
        if ack_eliciting {
            self.ack_eliciting_pending = true;
        }
        if self.ranges.first().is_none_or(|&(_, largest)| pn > largest) {
            self.largest_received_at = Some(now);
        }
        self.insert(pn);
    }

    fn insert(&mut self, pn: u64) {
        for i in 0..self.ranges.len() {
            let (smallest, largest) = self.ranges[i];
            if pn >= smallest && pn <= largest {
                return;
            }
            if pn == largest + 1 {
                self.ranges[i].1 = pn;
                // It may now touch the range above
                if i > 0 && self.ranges[i - 1].0 == pn + 1 {
                    self.ranges[i].1 = self.ranges[i - 1].1;
                    self.ranges.remove(i - 1);
                }
                return;
            }
            if smallest > 0 && pn == smallest - 1 {
                self.ranges[i].0 = pn;
                if i + 1 < self.ranges.len() && self.ranges[i + 1].1 + 1 == pn {
                    self.ranges[i].0 = self.ranges[i + 1].0;
                    self.ranges.remove(i + 1);
                }
                return;
            }
            if pn > largest {
                self.ranges.insert(i, (pn, pn));
                return;
            }
        }
        self.ranges.push((pn, pn));
    }

    /// The ranges to put in an ACK frame, largest first
    ///
    /// Capped, because a connection that loses packets steadily would
    /// otherwise grow an ACK frame without limit; the peer only needs the
    /// recent ones to make progress.
    pub fn ranges(&self) -> &[(u64, u64)] {
        const MAX_RANGES: usize = 32;
        &self.ranges[..self.ranges.len().min(MAX_RANGES)]
    }

    /// Microseconds since the largest packet arrived, scaled by the exponent
    /// the peer asked for (RFC 9000 Section 19.3)
    pub fn delay(&self, now: Instant, exponent: u32) -> u64 {
        let Some(at) = self.largest_received_at else {
            return 0;
        };
        (now.saturating_duration_since(at).as_micros() as u64) >> exponent
    }

    /// Drop ranges the peer has confirmed it knows about, so the ACK frame
    /// does not carry them forever
    pub fn trim_below(&mut self, largest_acked_by_peer: u64) {
        self.ranges
            .retain(|&(_, largest)| largest > largest_acked_by_peer);
    }

    pub fn take_pending(&mut self) -> bool {
        std::mem::take(&mut self.ack_eliciting_pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(pns: &[u64]) -> AckState {
        let now = Instant::now();
        let mut s = AckState::default();
        for &pn in pns {
            s.record(pn, true, now);
        }
        s
    }

    #[test]
    fn packets_in_order_collapse_into_one_range() {
        let s = state(&[0, 1, 2, 3, 4]);
        assert_eq!(s.ranges(), &[(0, 4)]);
    }

    #[test]
    fn a_gap_makes_two_ranges_largest_first() {
        let s = state(&[0, 1, 3, 4]);
        assert_eq!(s.ranges(), &[(3, 4), (0, 1)]);
    }

    /// The packet that fills a hole has to join the ranges on both sides,
    /// or the ACK claims a gap that is no longer there
    #[test]
    fn filling_a_hole_merges_both_sides() {
        let s = state(&[0, 2]);
        assert_eq!(s.ranges(), &[(2, 2), (0, 0)]);
        let s = state(&[0, 2, 1]);
        assert_eq!(s.ranges(), &[(0, 2)], "one range now");
    }

    #[test]
    fn duplicates_change_nothing() {
        let s = state(&[5, 5, 5]);
        assert_eq!(s.ranges(), &[(5, 5)]);
    }

    #[test]
    fn packets_arriving_backwards_still_sort() {
        let s = state(&[9, 7, 8, 5]);
        assert_eq!(s.ranges(), &[(7, 9), (5, 5)]);
    }

    #[test]
    fn only_ack_eliciting_packets_arm_the_flag() {
        let now = Instant::now();
        let mut s = AckState::default();
        s.record(0, false, now);
        assert!(!s.ack_eliciting_pending);
        s.record(1, true, now);
        assert!(s.ack_eliciting_pending);
        assert!(s.take_pending());
        assert!(!s.ack_eliciting_pending, "taking it clears it");
    }

    #[test]
    fn ranges_are_capped_so_an_ack_frame_cannot_grow_without_limit() {
        // Every other packet number, so nothing merges
        let s = state(&(0..200).map(|n| n * 2).collect::<Vec<_>>());
        assert_eq!(s.ranges().len(), 32);
        assert_eq!(s.ranges()[0], (398, 398), "the most recent come first");
    }

    #[test]
    fn confirmed_ranges_are_dropped() {
        let mut s = state(&[0, 1, 2, 5, 6]);
        s.trim_below(2);
        assert_eq!(s.ranges(), &[(5, 6)]);
    }

    #[test]
    fn the_reported_delay_is_scaled_by_the_peers_exponent() {
        let now = Instant::now();
        let mut s = AckState::default();
        s.record(0, true, now);
        let later = now + std::time::Duration::from_micros(8000);
        // The clock is free to round the 8000us by a tick either way. What the
        // exponent does to whatever it reports is the thing under test.
        let unscaled = s.delay(later, 0);
        assert!((7999..=8001).contains(&unscaled), "{unscaled}");
        assert_eq!(s.delay(later, 3), unscaled >> 3, "microseconds >> 3");
    }
}
