use std::time::Instant;

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

/// Latency summary (in seconds)
pub struct LatencySummary {
    pub min: f64,
    pub mean: f64,
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub max: f64,
}

pub fn latency_summary(latencies_ns: &[u64]) -> Option<LatencySummary> {
    if latencies_ns.is_empty() {
        return None;
    }
    let mut lat = latencies_ns.to_vec();
    lat.sort_unstable();
    let pct = |p: f64| -> f64 {
        let idx = ((lat.len() as f64 * p).ceil() as usize).saturating_sub(1);
        lat[idx.min(lat.len() - 1)] as f64 / 1e9
    };
    Some(LatencySummary {
        min: lat[0] as f64 / 1e9,
        mean: lat.iter().sum::<u64>() as f64 / lat.len() as f64 / 1e9,
        p50: pct(0.50),
        p90: pct(0.90),
        p99: pct(0.99),
        max: lat[lat.len() - 1] as f64 / 1e9,
    })
}
