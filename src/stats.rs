use crate::clock::Instant;

pub struct Stats {
    pub completed: u64,
    pub errors: u64,
    pub connect_errors: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub latencies_ns: Vec<u64>,
    /// One slot per three-digit status. The valid ones are 100 to 599 (RFC
    /// 9110 Section 15), but every decoder accepts any three digits - a
    /// CDN's 999 is a real answer a run gets - and a response that counts as
    /// ok has to be in this table, or it does not sum to what the report says
    /// completed.
    pub status_counts: Box<[u64; 1000]>,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            completed: 0,
            errors: 0,
            connect_errors: 0,
            bytes_received: 0,
            bytes_sent: 0,
            latencies_ns: Vec::new(),
            status_counts: Box::new([0u64; 1000]),
        }
    }
}

impl Stats {
    /// `status_code` is three digits, which is what every decoder produces,
    /// so it is always in the table
    pub fn record_success(&mut self, status_code: u16, request_start: Instant) {
        self.completed += 1;
        self.status_counts[usize::from(status_code)] += 1;
        self.latencies_ns
            .push(request_start.elapsed().as_nanos() as u64);
    }

    pub fn merge(&mut self, other: Stats) {
        self.completed += other.completed;
        self.errors += other.errors;
        self.connect_errors += other.connect_errors;
        self.bytes_received += other.bytes_received;
        self.bytes_sent += other.bytes_sent;
        self.latencies_ns.extend(other.latencies_ns);
        for (a, b) in self
            .status_counts
            .iter_mut()
            .zip(other.status_counts.iter())
        {
            *a += *b;
        }
    }
}

/// Percentile sample points, matching oha's latency distribution
pub const PERCENTILES: [f64; 9] = [10.0, 25.0, 50.0, 75.0, 90.0, 95.0, 99.0, 99.9, 99.99];

/// Latency summary (in seconds)
pub struct LatencySummary {
    pub min: f64,
    pub mean: f64,
    pub max: f64,
    /// Percentiles paired with [`PERCENTILES`] (seconds)
    pub percentiles: [f64; 9],
}

/// Selects exact percentile ranks in place; large unordered samples do not need
/// a full sort or copy. The sample multiset is preserved, but its order is
/// unspecified.
pub fn latency_summary(latencies_ns: &mut [u64]) -> Option<LatencySummary> {
    if latencies_ns.is_empty() {
        return None;
    }
    let lat = latencies_ns;
    let len = lat.len();
    let mean = lat.iter().sum::<u64>() as f64 / len as f64 / 1e9;
    // Same index formula as oha: floor(p/100 * len), clamped to the last element.
    let ranks = PERCENTILES.map(|p| ((p / 100.0 * len as f64) as usize).min(len - 1));

    // Sorting is cheaper for small inputs. Preserve the linear ordered-input
    // path too: selection would repeatedly partition those same samples.
    if len <= 1024 {
        lat.sort_unstable();
    }
    let (min, max) = if len <= 1024 || lat.is_sorted() {
        (lat[0], lat[len - 1])
    } else if lat.is_sorted_by(|a, b| a >= b) {
        return Some(LatencySummary {
            min: lat[len - 1] as f64 / 1e9,
            mean,
            max: lat[0] as f64 / 1e9,
            percentiles: ranks.map(|rank| lat[len - 1 - rank] as f64 / 1e9),
        });
    } else {
        select_ranks(lat, &ranks, 0);
        // Everything outside these boundary partitions lies between the
        // lowest and highest selected percentiles.
        (
            *lat[..=ranks[0]].iter().min().unwrap(),
            *lat[ranks[ranks.len() - 1]..].iter().max().unwrap(),
        )
    };
    Some(LatencySummary {
        min: min as f64 / 1e9,
        mean,
        max: max as f64 / 1e9,
        percentiles: ranks.map(|rank| lat[rank] as f64 / 1e9),
    })
}

/// Place each requested order statistic at its original index. Ranks are
/// nondecreasing; selecting near the partition midpoint limits repeated scans.
fn select_ranks(samples: &mut [u64], ranks: &[usize], offset: usize) {
    if ranks.is_empty() {
        return;
    }
    let middle = offset + samples.len() / 2;
    let split = ranks
        .partition_point(|&rank| rank < middle)
        .min(ranks.len() - 1);
    let rank = ranks[split];
    let (lower, _, upper) = samples.select_nth_unstable(rank - offset);
    // Coincident ranks all refer to this pivot; neither child includes it.
    let lower_end = ranks.partition_point(|&r| r < rank);
    let upper_start = ranks.partition_point(|&r| r <= rank);
    select_ranks(lower, &ranks[..lower_end], offset);
    select_ranks(upper, &ranks[upper_start..], rank + 1);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn ms(values: &[u64]) -> Vec<u64> {
        values.iter().map(|v| v * 1_000_000).collect()
    }

    fn assert_matches_sort(mut samples: Vec<u64>) {
        let mut sorted = samples.clone();
        sorted.sort_unstable();
        let got = latency_summary(&mut samples);
        if sorted.is_empty() {
            assert!(got.is_none());
            assert!(samples.is_empty());
            return;
        }
        let got = got.unwrap();
        let len = sorted.len();
        assert_eq!(got.min.to_bits(), (sorted[0] as f64 / 1e9).to_bits());
        assert_eq!(got.max.to_bits(), (sorted[len - 1] as f64 / 1e9).to_bits());
        assert_eq!(
            got.mean.to_bits(),
            (sorted.iter().sum::<u64>() as f64 / len as f64 / 1e9).to_bits()
        );
        for (p, actual) in PERCENTILES.iter().zip(got.percentiles) {
            let idx = ((p / 100.0 * len as f64) as usize).min(len - 1);
            assert_eq!(
                actual.to_bits(),
                (sorted[idx] as f64 / 1e9).to_bits(),
                "p{p} of {len} samples"
            );
        }
        // A second report of the same samples must agree too.
        let again = latency_summary(&mut samples).unwrap();
        assert_eq!(again.min.to_bits(), got.min.to_bits());
        assert_eq!(again.mean.to_bits(), got.mean.to_bits());
        assert_eq!(again.max.to_bits(), got.max.to_bits());
        assert_eq!(
            again.percentiles.map(f64::to_bits),
            got.percentiles.map(f64::to_bits)
        );
        samples.sort_unstable();
        assert_eq!(samples, sorted, "every sample must be retained exactly");
    }

    #[test]
    fn selection_matches_sort_for_all_small_ternary_inputs() {
        // Exhaustively cover ties, coincident ranks, and every ordering.
        for len in 0..=8u32 {
            for mut code in 0..3usize.pow(len) {
                let samples: Vec<_> = (0..len)
                    .map(|_| {
                        let value = (code % 3) as u64;
                        code /= 3;
                        value
                    })
                    .collect();
                if !samples.is_empty() {
                    // Exercise selection itself even below the sort cutoff.
                    let mut selected = samples.clone();
                    let mut sorted = samples.clone();
                    sorted.sort_unstable();
                    let ranks = PERCENTILES.map(|p| {
                        ((p / 100.0 * samples.len() as f64) as usize).min(samples.len() - 1)
                    });
                    select_ranks(&mut selected, &ranks, 0);
                    for rank in ranks {
                        assert_eq!(selected[rank], sorted[rank]);
                    }
                    selected.sort_unstable();
                    assert_eq!(selected, sorted);
                }
                assert_matches_sort(samples);
            }
        }
    }

    #[test]
    fn selection_matches_sort_at_percentile_boundaries() {
        for len in (1..=130).chain([999, 1000, 1001, 1023, 1024, 1025, 9999, 10_000, 10_001]) {
            assert_matches_sort(vec![0; len]);
            assert_matches_sort(vec![123_456_789; len]);
            assert_matches_sort((0..len as u64).collect());
            assert_matches_sort((0..len as u64).rev().collect());
            let mut skewed = vec![42; len];
            skewed[len / 2] = 1_000_000_000_000;
            skewed[len - 1] = 0;
            assert_matches_sort(skewed);
        }
    }

    #[test]
    fn selection_matches_sort_for_seeded_large_inputs() {
        for seed in [1u64, 0xc73, 0x0123_4567_89ab_cdef] {
            let mut state = seed;
            for len in [32, 1024, 65_537, 1_000_000] {
                let samples: Vec<_> = (0..len)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state % 1_000_000_000
                    })
                    .collect();
                assert_matches_sort(samples.iter().map(|v| v % 11).collect());
                assert_matches_sort(samples);
            }
        }
    }

    #[test]
    fn selection_preserves_large_values_and_integer_mean() {
        // Stay within the existing u64 sum contract, including its boundary.
        assert_matches_sort(vec![u64::MAX]);
        assert_matches_sort(vec![0, u64::MAX, 0, 0]);
        assert_matches_sort(vec![u64::MAX / 2, 0, u64::MAX / 2, 1]);
        assert_matches_sort(vec![1 << 53, (1 << 53) + 1, (1 << 53) + 3, 0]);
    }

    #[test]
    fn no_samples_have_no_summary() {
        assert!(latency_summary(&mut []).is_none());
    }

    /// Expected values worked out by hand rather than by re-running the
    /// formula: with 100 samples the index is floor(p/100 * 100), so p50 is
    /// the 51st sample rather than the 50th.
    #[test]
    fn percentile_indices_are_the_ones_oha_picks() {
        let mut lat = ms(&(1..=100).collect::<Vec<_>>());
        let s = latency_summary(&mut lat).unwrap();
        let got: Vec<u64> = s
            .percentiles
            .iter()
            .map(|p| (p * 1000.0).round() as u64)
            .collect();
        assert_eq!(
            got,
            vec![11, 26, 51, 76, 91, 96, 100, 100, 100],
            "p10 p25 p50 p75 p90 p95 p99 p99.9 p99.99, in milliseconds"
        );
        assert_eq!(s.min, 0.001);
        assert_eq!(s.max, 0.1);
        assert!((s.mean - 0.0505).abs() < 1e-12, "mean of 1..=100 ms");
    }

    #[test]
    fn the_top_percentiles_stay_inside_the_samples() {
        // oha reads values[(p/100 * len) as usize]; for the largest percentile
        // shb reports, 0.9999 * len is always below len, so the index is
        // always in range however few samples there are
        for len in [1usize, 2, 3, 7, 100, 10_000] {
            let mut lat = ms(&(1..=len as u64).collect::<Vec<_>>());
            let s = latency_summary(&mut lat).unwrap();
            for (p, v) in PERCENTILES.iter().zip(s.percentiles) {
                let idx = (p / 100.0 * len as f64) as usize;
                assert!(idx < len, "p{p} with {len} samples indexes past the end");
                assert_eq!(v, lat[idx] as f64 / 1e9, "p{p} with {len} samples");
            }
        }
    }

    #[test]
    fn a_single_sample_is_every_percentile() {
        let s = latency_summary(&mut ms(&[7])).unwrap();
        assert_eq!(s.min, 0.007);
        assert_eq!(s.max, 0.007);
        assert_eq!(s.mean, 0.007);
        assert!(s.percentiles.iter().all(|p| *p == 0.007));
    }

    #[test]
    fn samples_do_not_have_to_arrive_in_order() {
        let sorted = latency_summary(&mut ms(&[1, 2, 3, 4, 5])).unwrap();
        let shuffled = latency_summary(&mut ms(&[4, 1, 5, 3, 2])).unwrap();
        assert_eq!(sorted.percentiles, shuffled.percentiles);
        assert_eq!(sorted.min, shuffled.min);
        assert_eq!(sorted.max, shuffled.max);
    }

    #[test]
    fn recording_a_success_tallies_the_status_and_keeps_the_latency() {
        let mut stats = Stats::default();
        // Slept rather than backdated: `Instant` cannot name a time before the
        // run began, and what is under test is that the latency is measured
        // from the instant handed in.
        let start = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        stats.record_success(200, start);
        stats.record_success(404, start);
        stats.record_success(200, start);
        assert_eq!(stats.completed, 3);
        assert_eq!(stats.status_counts[200], 2);
        assert_eq!(stats.status_counts[404], 1);
        assert_eq!(stats.latencies_ns.len(), 3);
        assert!(stats.latencies_ns.iter().all(|ns| *ns >= 5_000_000));
    }

    /// Every three-digit status has a slot, so the table always sums to the
    /// completed count the report prints next to it. A 999 used to be
    /// counted as ok and left out of the table.
    #[test]
    fn every_three_digit_status_is_tallied() {
        let mut stats = Stats::default();
        for status in [0, 100, 200, 599, 600, 999] {
            stats.record_success(status, Instant::now());
        }
        assert_eq!(stats.completed, 6);
        assert_eq!(stats.status_counts.iter().sum::<u64>(), stats.completed);
        assert_eq!(stats.status_counts[999], 1);
        assert_eq!(stats.status_counts[600], 1);
    }

    #[test]
    fn merging_adds_every_counter() {
        let mut a = Stats::default();
        a.record_success(200, Instant::now());
        a.errors = 2;
        a.connect_errors = 1;
        a.bytes_received = 100;
        a.bytes_sent = 10;

        let mut b = Stats::default();
        b.record_success(200, Instant::now());
        b.record_success(500, Instant::now());
        b.errors = 3;
        b.connect_errors = 2;
        b.bytes_received = 200;
        b.bytes_sent = 20;

        a.merge(b);
        assert_eq!(a.completed, 3);
        assert_eq!(a.errors, 5);
        assert_eq!(a.connect_errors, 3);
        assert_eq!(a.bytes_received, 300);
        assert_eq!(a.bytes_sent, 30);
        assert_eq!(a.status_counts[200], 2);
        assert_eq!(a.status_counts[500], 1);
        assert_eq!(a.latencies_ns.len(), 3);
    }
}
