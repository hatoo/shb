//! Fixture-only byte scheduling, injected into a private, pinned Quinn build.
//! Packets, congestion control, flow control, ACK validation and loss recovery
//! remain Quinn's. A prefix is never sent until every suffix byte is ACKed.

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;
use std::sync::OnceLock;

#[derive(Clone, Debug)]
struct Config {
    mode: String,
    body: u64,
    chunk: u64,
}

#[derive(Debug)]
pub(super) struct NativeSchedule {
    config: Config,
    body_start: u64,
    end: u64,
    pending: VecDeque<Range<u64>>,
    acked: BTreeMap<u64, u64>,
    released: bool,
}

impl NativeSchedule {
    pub(super) fn from_write(length: usize, start: u64, unsent: u64) -> Option<Self> {
        static CONFIG: OnceLock<Option<Config>> = OnceLock::new();
        let config = CONFIG.get_or_init(|| {
            let value = std::env::var("SHB_NATIVE_REORDER").ok()?;
            let fields: Vec<_> = value.split(':').collect();
            assert_eq!(fields.len(), 3, "mode:body_bytes:fragment_bytes required");
            let config = Config {
                mode: fields[0].into(),
                body: fields[1].parse().expect("body bytes"),
                chunk: fields[2].parse().expect("fragment bytes"),
            };
            assert!(matches!(
                config.mode.as_str(),
                "ordered" | "reverse" | "mixed" | "duplicates" | "missing-prefix"
            ));
            assert!((64..=1024).contains(&config.chunk));
            assert!((2 * config.chunk..=16 * 1024 * 1024).contains(&config.body));
            Some(config)
        });
        let config = config.as_ref()?;
        if length as u64 != config.body {
            return None;
        }
        let schedule = Self::new(config.clone(), start, unsent);
        eprintln!("NATIVE_REORDER {{\"event\":\"armed\",\"start\":{start},\"end\":{},\"chunk\":{},\"mode\":\"{}\"}}", schedule.end, config.chunk, config.mode);
        Some(schedule)
    }

    fn new(config: Config, body_start: u64, unsent: u64) -> Self {
        let end = body_start + config.body;
        let mut suffix: Vec<_> = ((body_start + config.chunk)..end)
            .step_by(config.chunk as usize)
            .map(|start| start..end.min(start + config.chunk))
            .collect();
        match config.mode.as_str() {
            "reverse" | "missing-prefix" => suffix.reverse(),
            "mixed" => suffix.sort_by_key(|r| {
                let index = (r.start - body_start) / config.chunk;
                (index % 2, u64::MAX - index)
            }),
            "duplicates" => suffix = suffix.into_iter().flat_map(|r| [r.clone(), r]).collect(),
            _ => {}
        }
        let mut pending = VecDeque::new();
        if unsent < body_start {
            pending.push_back(unsent..body_start);
        }
        if config.mode == "ordered" {
            pending.push_back(body_start..body_start + config.chunk);
        }
        pending.extend(suffix);
        Self {
            released: config.mode == "ordered",
            config,
            body_start,
            end,
            pending,
            acked: BTreeMap::new(),
        }
    }

    pub(super) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub(super) fn poll(&mut self, max_len: usize) -> Option<Range<u64>> {
        let range = self.pending.pop_front()?;
        let end = range
            .end
            .min(range.start + max_len.saturating_sub(16) as u64);
        if end < range.end {
            self.pending.push_front(end..range.end);
        }
        Some(range.start..end)
    }

    pub(super) fn ack(&mut self, mut range: Range<u64>) {
        if self.released || self.config.mode == "missing-prefix" || range.is_empty() {
            return;
        }
        // Union ACKed byte intervals. Acknowledging only interval endpoints
        // cannot release the gate across an interior missing byte.
        if let Some((&start, &end)) = self.acked.range(..=range.start).next_back() {
            if end >= range.start {
                self.acked.remove(&start);
                range.start = start;
                range.end = range.end.max(end);
            }
        }
        while let Some((&start, &end)) = self.acked.range(range.start..).next() {
            if start > range.end {
                break;
            }
            self.acked.remove(&start);
            range.end = range.end.max(end);
        }
        self.acked.insert(range.start, range.end);
        let suffix = self.body_start + self.config.chunk;
        if self.pending.is_empty()
            && self
                .acked
                .range(..=suffix)
                .next_back()
                .is_some_and(|(_, &end)| end >= self.end)
        {
            self.released = true;
            self.pending.push_back(self.body_start..suffix);
            eprintln!("NATIVE_REORDER {{\"event\":\"fence\",\"start\":{},\"end\":{},\"suffix_bytes_acked\":{},\"distinct_chunks\":{}}}", self.body_start, self.end, self.end - suffix, (self.end - suffix).div_ceil(self.config.chunk));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(mode: &str) -> NativeSchedule {
        NativeSchedule::new(
            Config {
                mode: mode.into(),
                body: 513 * 1024,
                chunk: 1024,
            },
            20,
            0,
        )
    }

    fn send_all(schedule: &mut NativeSchedule) -> Vec<Range<u64>> {
        let mut spans = Vec::new();
        while let Some(range) = schedule.poll(1200) {
            assert!(!range.is_empty());
            spans.push(range);
        }
        spans
    }

    #[test]
    fn sparse_ack_fence_requires_every_byte_and_drained_schedule() {
        let mut s = schedule("reverse");
        let spans = send_all(&mut s);
        assert_eq!(spans.len(), 513);
        assert_eq!(spans[0], 0..20);
        assert_eq!(spans[1].end, s.end);
        assert!(spans[1..].iter().all(|r| r.start >= 1044));
        s.ack(1044..2048);
        s.ack(2049..s.end);
        s.ack(0..20);
        assert!(!s.released && !s.has_pending());
        s.ack(2048..2049);
        assert!(s.released);
        let prefix = send_all(&mut s);
        assert_eq!(prefix.len(), 1);
        assert_eq!(prefix[0], 20..1044);
        s.ack(1044..s.end);
        assert!(!s.has_pending(), "duplicate ACK cannot release twice");
    }

    #[test]
    fn duplicates_and_split_packets_preserve_exact_coverage() {
        for mode in ["ordered", "reverse", "mixed", "duplicates"] {
            let mut s = schedule(mode);
            let mut counts = vec![0u8; s.end as usize];
            let mut spans = Vec::new();
            while let Some(r) = s.poll(333) {
                for n in r.clone() {
                    counts[n as usize] += 1;
                }
                spans.push(r);
            }
            for r in spans.into_iter().rev() {
                s.ack(r);
            }
            for r in send_all(&mut s) {
                for n in r {
                    counts[n as usize] += 1;
                }
            }
            assert!(counts[..1044].iter().all(|&n| n == 1));
            assert!(counts[1044..]
                .iter()
                .all(|&n| n == if mode == "duplicates" { 2 } else { 1 }));
        }
    }

    #[test]
    fn missing_prefix_fault_never_opens_gate() {
        let mut s = schedule("missing-prefix");
        for r in send_all(&mut s) {
            s.ack(r);
        }
        assert!(!s.released && !s.has_pending());
    }

    #[test]
    fn independent_generations_do_not_share_acks() {
        let mut a = schedule("reverse");
        let mut b = schedule("reverse");
        for r in send_all(&mut a) {
            a.ack(r);
        }
        send_all(&mut b);
        assert!(a.released && !b.released);
        b.ack(1044..b.end - 1);
        assert!(!b.released);
        b.ack(b.end - 1..b.end);
        assert!(b.released);
    }
}
