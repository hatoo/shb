//! Loss detection and congestion control (RFC 9002)
//!
//! A benchmark client is not a general transport. It runs against a server
//! that is usually one hop away, it wants to keep the pipe full, and every
//! connection is short. So the RTT estimator and the loss rules here follow
//! the specification, while congestion control is deliberately plain: enough
//! to be well behaved, not enough to be worth tuning.

use std::time::{Duration, Instant};

use super::packet::Space;

/// RFC 9002 Section 6.1.1: a packet is lost once a later one has been
/// acknowledged and it is more than this many packets behind
const REORDER_THRESHOLD: u64 = 3;
/// RFC 9002 Section 6.1.2, as a fraction: 9/8 of the greater of RTT and
/// smoothed RTT
const TIME_THRESHOLD_NUM: u32 = 9;
const TIME_THRESHOLD_DEN: u32 = 8;
/// RFC 9002 Section 6.2.1
const TIMER_GRANULARITY: Duration = Duration::from_millis(1);
/// RFC 9002 Section 6.2.2, the value to use before the first RTT sample
const INITIAL_RTT: Duration = Duration::from_millis(333);

/// A packet we have sent and not yet heard about
pub struct SentPacket {
    pub number: u64,
    pub time_sent: Instant,
    pub size: usize,
    pub ack_eliciting: bool,
    /// What has to be sent again if this packet is declared lost. Indexes
    /// into the connection's own record of what it put in the packet.
    pub frames: Vec<SentFrame>,
}

/// The parts of a packet that have to be recovered if it is lost. Frames the
/// peer will learn about another way - ACK, MAX_DATA - are deliberately not
/// here: resending stale flow control credit is worse than useless.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SentFrame {
    Crypto {
        offset: u64,
        len: usize,
    },
    Stream {
        id: u64,
        offset: u64,
        len: usize,
        fin: bool,
    },
    /// A PING sent purely to make the peer acknowledge something
    Ping,
}

#[derive(Default)]
pub struct Rtt {
    pub latest: Duration,
    pub smoothed: Option<Duration>,
    pub var: Duration,
    pub min: Option<Duration>,
}

impl Rtt {
    /// RFC 9002 Section 5.3
    pub fn update(&mut self, sample: Duration, ack_delay: Duration, max_ack_delay: Duration) {
        self.latest = sample;
        self.min = Some(match self.min {
            Some(min) => min.min(sample),
            None => sample,
        });
        let Some(smoothed) = self.smoothed else {
            // First sample: there is nothing to smooth against
            self.smoothed = Some(sample);
            self.var = sample / 2;
            return;
        };
        // Only take the peer's reported delay out if doing so leaves a sample
        // above the minimum we have seen, which is the spec's guard against a
        // peer inflating it
        let min = self.min.unwrap_or(sample);
        let adjusted = if sample > min {
            sample.saturating_sub(ack_delay.min(max_ack_delay))
        } else {
            sample
        };
        let adjusted = adjusted.max(min);
        let var_sample = smoothed.abs_diff(adjusted);
        self.var = (self.var * 3 + var_sample) / 4;
        self.smoothed = Some((smoothed * 7 + adjusted) / 8);
    }

    pub fn smoothed_or_initial(&self) -> Duration {
        self.smoothed.unwrap_or(INITIAL_RTT)
    }

    /// RFC 9002 Section 6.2.1
    pub fn pto(&self, max_ack_delay: Duration) -> Duration {
        self.smoothed_or_initial() + (self.var * 4).max(TIMER_GRANULARITY) + max_ack_delay
    }

    /// RFC 9002 Section 6.1.2
    pub fn loss_delay(&self) -> Duration {
        let base = self.latest.max(self.smoothed_or_initial());
        (base * TIME_THRESHOLD_NUM / TIME_THRESHOLD_DEN).max(TIMER_GRANULARITY)
    }
}

/// Sent packets for one packet number space, kept in flight order
#[derive(Default)]
pub struct SentPackets {
    /// Ascending by packet number, which is the order they were sent in
    packets: Vec<SentPacket>,
    pub largest_acked: Option<u64>,
    /// When the most recent ack-eliciting packet went out, for the PTO timer
    pub last_ack_eliciting: Option<Instant>,
}

impl SentPackets {
    pub fn push(&mut self, packet: SentPacket) {
        if packet.ack_eliciting {
            self.last_ack_eliciting = Some(packet.time_sent);
        }
        self.packets.push(packet);
    }

    pub fn any_ack_eliciting(&self) -> bool {
        self.packets.iter().any(|p| p.ack_eliciting)
    }

    /// Packets the peer has acknowledged, removed from flight
    pub fn drain_acked(&mut self, ranges: &[(u64, u64)]) -> Vec<SentPacket> {
        let mut acked = Vec::new();
        let mut i = 0;
        while i < self.packets.len() {
            let n = self.packets[i].number;
            if ranges.iter().any(|&(lo, hi)| n >= lo && n <= hi) {
                acked.push(self.packets.remove(i));
            } else {
                i += 1;
            }
        }
        if let Some(max) = acked.iter().map(|p| p.number).max() {
            self.largest_acked = Some(match self.largest_acked {
                Some(prev) => prev.max(max),
                None => max,
            });
        }
        acked
    }

    /// Packets that count as lost now (RFC 9002 Section 6.1), removed from
    /// flight, plus when the next one would become lost by time alone
    pub fn detect_lost(
        &mut self,
        now: Instant,
        loss_delay: Duration,
    ) -> (Vec<SentPacket>, Option<Instant>) {
        let Some(largest_acked) = self.largest_acked else {
            return (Vec::new(), None);
        };
        let mut lost = Vec::new();
        let mut next_deadline: Option<Instant> = None;
        let mut i = 0;
        while i < self.packets.len() {
            let p = &self.packets[i];
            if p.number > largest_acked {
                i += 1;
                continue;
            }
            let by_reorder = largest_acked >= p.number + REORDER_THRESHOLD;
            let deadline = p.time_sent + loss_delay;
            if by_reorder || deadline <= now {
                lost.push(self.packets.remove(i));
            } else {
                next_deadline = Some(match next_deadline {
                    Some(d) => d.min(deadline),
                    None => deadline,
                });
                i += 1;
            }
        }
        (lost, next_deadline)
    }

    pub fn bytes_in_flight(&self) -> usize {
        self.packets.iter().map(|p| p.size).sum()
    }
}

/// Congestion control
///
/// Deliberately simple: slow start with a large initial window, and a plain
/// halving on loss. shb runs against a server on the same machine or the same
/// network, where the interesting limit is the kernel and the server rather
/// than the path, and a benchmark client that models a congested wide-area
/// path would be measuring its own controller.
pub struct Congestion {
    pub window: usize,
    ssthresh: usize,
    recovery_until: Option<Instant>,
}

/// RFC 9002 Section 7.2 puts the initial window at ten packets; shb starts
/// far above that because the path it cares about does not lose packets and
/// slow start would otherwise dominate a short run
const INITIAL_WINDOW: usize = 4 * 1024 * 1024;
const MIN_WINDOW: usize = 2 * 1200;

impl Default for Congestion {
    fn default() -> Self {
        Self {
            window: INITIAL_WINDOW,
            ssthresh: usize::MAX,
            recovery_until: None,
        }
    }
}

impl Congestion {
    pub fn on_ack(&mut self, bytes: usize, now: Instant) {
        if self.recovery_until.is_some_and(|t| now < t) {
            return;
        }
        if self.window < self.ssthresh {
            self.window += bytes;
        } else {
            // Congestion avoidance: one more packet per window
            self.window += 1200 * bytes / self.window.max(1);
        }
    }

    pub fn on_loss(&mut self, sent: Instant, now: Instant) {
        // One halving per round trip, not one per lost packet
        if self.recovery_until.is_some_and(|t| sent < t) {
            return;
        }
        self.window = (self.window / 2).max(MIN_WINDOW);
        self.ssthresh = self.window;
        self.recovery_until = Some(now);
    }

    pub fn can_send(&self, in_flight: usize) -> bool {
        in_flight < self.window
    }
}

/// Which space needs a probe next, and when (RFC 9002 Section 6.2)
pub fn pto_deadline(
    spaces: &[&SentPackets; 3],
    rtt: &Rtt,
    max_ack_delay: Duration,
    pto_count: u32,
) -> Option<(Space, Instant)> {
    let mut best: Option<(Space, Instant)> = None;
    for (i, space) in Space::ALL.iter().enumerate() {
        let sent = spaces[i];
        if !sent.any_ack_eliciting() {
            continue;
        }
        let Some(last) = sent.last_ack_eliciting else {
            continue;
        };
        // The handshake spaces do not wait on the peer's ack delay, since it
        // is only committed to one after the handshake (RFC 9002 Section 6.2.1)
        let delay = if *space == Space::Data {
            max_ack_delay
        } else {
            Duration::ZERO
        };
        let timeout = rtt.pto(delay) * 2u32.saturating_pow(pto_count);
        let at = last + timeout;
        if best.is_none_or(|(_, t)| at < t) {
            best = Some((*space, at));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sent(number: u64, at: Instant, ack_eliciting: bool) -> SentPacket {
        SentPacket {
            number,
            time_sent: at,
            size: 1200,
            ack_eliciting,
            frames: Vec::new(),
        }
    }

    /// RFC 9002 Section 5.3: the first sample is taken as-is and the variance
    /// starts at half of it
    #[test]
    fn the_first_rtt_sample_seeds_the_estimator() {
        let mut rtt = Rtt::default();
        rtt.update(
            Duration::from_millis(100),
            Duration::ZERO,
            Duration::from_millis(25),
        );
        assert_eq!(rtt.smoothed, Some(Duration::from_millis(100)));
        assert_eq!(rtt.var, Duration::from_millis(50));
        assert_eq!(rtt.min, Some(Duration::from_millis(100)));
    }

    #[test]
    fn later_samples_are_smoothed() {
        let mut rtt = Rtt::default();
        let max = Duration::from_millis(25);
        rtt.update(Duration::from_millis(100), Duration::ZERO, max);
        rtt.update(Duration::from_millis(200), Duration::ZERO, max);
        // 7/8 of 100 plus 1/8 of 200
        assert_eq!(
            rtt.smoothed,
            Some(Duration::from_millis(112) + Duration::from_micros(500))
        );
        assert_eq!(
            rtt.min,
            Some(Duration::from_millis(100)),
            "the minimum holds"
        );
    }

    /// The peer's reported ack delay is only removed while that leaves a
    /// sample at or above the minimum seen, so a peer cannot talk the
    /// estimate down by inflating it
    #[test]
    fn a_peer_cannot_inflate_the_ack_delay_to_shrink_the_rtt() {
        let mut rtt = Rtt::default();
        let max = Duration::from_millis(25);
        rtt.update(Duration::from_millis(100), Duration::ZERO, max);
        rtt.update(Duration::from_millis(101), Duration::from_millis(90), max);
        assert!(
            rtt.smoothed.unwrap() >= Duration::from_millis(99),
            "smoothed {:?} fell below the minimum",
            rtt.smoothed
        );
    }

    /// And the delay is capped at what the peer committed to
    #[test]
    fn the_reported_delay_is_capped_at_max_ack_delay() {
        let mut a = Rtt::default();
        let mut b = Rtt::default();
        let max = Duration::from_millis(25);
        for rtt in [&mut a, &mut b] {
            rtt.update(Duration::from_millis(10), Duration::ZERO, max);
        }
        a.update(Duration::from_millis(200), Duration::from_millis(25), max);
        b.update(Duration::from_millis(200), Duration::from_millis(500), max);
        assert_eq!(a.smoothed, b.smoothed, "anything past the cap is ignored");
    }

    #[test]
    fn the_pto_covers_the_round_trip_and_the_peers_delay() {
        let mut rtt = Rtt::default();
        rtt.update(
            Duration::from_millis(100),
            Duration::ZERO,
            Duration::from_millis(25),
        );
        // smoothed 100ms + 4 * 50ms variance + 25ms
        assert_eq!(
            rtt.pto(Duration::from_millis(25)),
            Duration::from_millis(325)
        );
    }

    #[test]
    fn loss_delay_is_nine_eighths_of_the_rtt() {
        let mut rtt = Rtt::default();
        rtt.update(
            Duration::from_millis(80),
            Duration::ZERO,
            Duration::from_millis(25),
        );
        assert_eq!(rtt.loss_delay(), Duration::from_millis(90));
    }

    /// RFC 9002 Section 6.1.1: three packets past a later acknowledgement
    #[test]
    fn packets_far_enough_behind_an_ack_are_lost() {
        let now = Instant::now();
        let mut s = SentPackets::default();
        for n in 0..5 {
            s.push(sent(n, now, true));
        }
        s.drain_acked(&[(4, 4)]);
        let (lost, _) = s.detect_lost(now, Duration::from_secs(10));
        let numbers: Vec<_> = lost.iter().map(|p| p.number).collect();
        assert_eq!(numbers, vec![0, 1], "0 and 1 are three or more behind 4");
    }

    /// And a packet only slightly behind is held until the timer says so
    #[test]
    fn a_recently_sent_packet_waits_for_the_timer() {
        let now = Instant::now();
        let mut s = SentPackets::default();
        s.push(sent(0, now, true));
        s.push(sent(1, now, true));
        s.drain_acked(&[(1, 1)]);
        let (lost, deadline) = s.detect_lost(now, Duration::from_millis(50));
        assert!(lost.is_empty(), "not yet");
        assert_eq!(deadline, Some(now + Duration::from_millis(50)));

        let (lost, _) = s.detect_lost(now + Duration::from_millis(50), Duration::from_millis(50));
        assert_eq!(lost.len(), 1, "the timer has expired");
    }

    #[test]
    fn nothing_is_lost_before_the_first_acknowledgement() {
        let now = Instant::now();
        let mut s = SentPackets::default();
        s.push(sent(0, now - Duration::from_secs(60), true));
        let (lost, deadline) = s.detect_lost(now, Duration::from_millis(1));
        assert!(lost.is_empty(), "loss is only ever inferred from an ACK");
        assert!(deadline.is_none());
    }

    #[test]
    fn acknowledgement_removes_packets_from_flight() {
        let now = Instant::now();
        let mut s = SentPackets::default();
        for n in 0..4 {
            s.push(sent(n, now, true));
        }
        assert_eq!(s.bytes_in_flight(), 4 * 1200);
        let acked = s.drain_acked(&[(1, 2)]);
        assert_eq!(acked.len(), 2);
        assert_eq!(s.bytes_in_flight(), 2 * 1200);
        assert_eq!(s.largest_acked, Some(2));
    }

    /// A later ACK naming an older packet must not walk the largest backwards
    #[test]
    fn the_largest_acknowledged_only_grows() {
        let now = Instant::now();
        let mut s = SentPackets::default();
        for n in 0..4 {
            s.push(sent(n, now, true));
        }
        s.drain_acked(&[(3, 3)]);
        s.drain_acked(&[(0, 0)]);
        assert_eq!(s.largest_acked, Some(3));
    }

    #[test]
    fn the_window_halves_once_per_round_trip_not_once_per_packet() {
        let now = Instant::now();
        let mut c = Congestion::default();
        let start = c.window;
        c.on_loss(now, now);
        let after_one = c.window;
        assert_eq!(after_one, start / 2);
        // A second loss from a packet sent before recovery began changes
        // nothing; one sent after it halves again
        c.on_loss(now - Duration::from_millis(1), now);
        assert_eq!(c.window, after_one);
        c.on_loss(
            now + Duration::from_millis(1),
            now + Duration::from_millis(1),
        );
        assert_eq!(c.window, after_one / 2);
    }

    #[test]
    fn the_window_never_falls_below_two_packets() {
        let mut now = Instant::now();
        let mut c = Congestion::default();
        for _ in 0..40 {
            c.on_loss(now, now);
            now += Duration::from_millis(1);
        }
        assert_eq!(c.window, MIN_WINDOW);
        assert!(c.can_send(0));
    }

    #[test]
    fn a_probe_is_scheduled_only_where_something_is_in_flight() {
        let now = Instant::now();
        let mut initial = SentPackets::default();
        let handshake = SentPackets::default();
        let mut data = SentPackets::default();
        initial.push(sent(0, now, true));
        data.push(sent(0, now + Duration::from_millis(10), true));
        let rtt = Rtt::default();
        let (space, at) = pto_deadline(
            &[&initial, &handshake, &data],
            &rtt,
            Duration::from_millis(25),
            0,
        )
        .unwrap();
        assert_eq!(space, Space::Initial, "the older one fires first");
        assert_eq!(at, now + rtt.pto(Duration::ZERO));

        let empty = SentPackets::default();
        assert!(
            pto_deadline(
                &[&empty, &empty, &empty],
                &rtt,
                Duration::from_millis(25),
                0
            )
            .is_none()
        );
    }

    /// A packet carrying only an ACK does not arm the probe timer: there is
    /// nothing to recover if it is lost
    #[test]
    fn a_non_ack_eliciting_packet_does_not_arm_the_timer() {
        let now = Instant::now();
        let mut s = SentPackets::default();
        s.push(sent(0, now, false));
        assert!(!s.any_ack_eliciting());
        let rtt = Rtt::default();
        let empty = SentPackets::default();
        assert!(pto_deadline(&[&s, &empty, &empty], &rtt, Duration::ZERO, 0).is_none());
    }

    #[test]
    fn the_probe_timeout_backs_off_exponentially() {
        let now = Instant::now();
        let mut s = SentPackets::default();
        s.push(sent(0, now, true));
        let rtt = Rtt::default();
        let empty = SentPackets::default();
        let (_, first) = pto_deadline(&[&s, &empty, &empty], &rtt, Duration::ZERO, 0).unwrap();
        let (_, second) = pto_deadline(&[&s, &empty, &empty], &rtt, Duration::ZERO, 1).unwrap();
        assert_eq!(second - now, (first - now) * 2);
    }
}
