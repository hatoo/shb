use crate::clock::Instant;

pub struct Stats {
    pub completed: u64,
    pub errors: u64,
    pub connect_errors: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub latencies_ns: Vec<u64>,
    pub status_counts: Box<[u64; 600]>,
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
            status_counts: Box::new([0u64; 600]),
        }
    }
}

impl Stats {
    pub fn record_success(&mut self, status_code: u16, request_start: Instant) {
        self.completed += 1;
        if (status_code as usize) < self.status_counts.len() {
            self.status_counts[status_code as usize] += 1;
        }
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

/// Sorts in place rather than on a copy: every latency of the run is held, so
/// at the point this is called a copy is the largest allocation the process
/// would ever make, and it is only wanted to be sorted.
pub fn latency_summary(latencies_ns: &mut [u64]) -> Option<LatencySummary> {
    if latencies_ns.is_empty() {
        return None;
    }
    let lat = latencies_ns;
    lat.sort_unstable();
    // Same index formula as oha: floor(p/100 * len), clamped to the last element
    let pct = |p: f64| -> f64 {
        let idx = ((p / 100.0 * lat.len() as f64) as usize).min(lat.len() - 1);
        lat[idx] as f64 / 1e9
    };
    Some(LatencySummary {
        min: lat[0] as f64 / 1e9,
        mean: lat.iter().sum::<u64>() as f64 / lat.len() as f64 / 1e9,
        max: lat[lat.len() - 1] as f64 / 1e9,
        percentiles: PERCENTILES.map(pct),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn ms(values: &[u64]) -> Vec<u64> {
        values.iter().map(|v| v * 1_000_000).collect()
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

    /// A status outside the table is counted as a completion but not tallied,
    /// rather than panicking on the index
    #[test]
    fn an_out_of_range_status_does_not_panic() {
        let mut stats = Stats::default();
        stats.record_success(999, Instant::now());
        assert_eq!(stats.completed, 1);
        assert_eq!(stats.status_counts.iter().sum::<u64>(), 0);
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
