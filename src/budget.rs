//! What ends a run
//!
//! `-n` and `-z` are mutually exclusive, and clap enforces that, but the two
//! used to be carried separately: a request count and an optional duration.
//! Duration mode then had to spell itself as a count of `u64::MAX`, and every
//! place that read the count had to remember to check the duration first -
//! reserving room for the latencies of `u64::MAX` requests is the obvious way
//! to get that wrong. One value that can only be one of the two removes the
//! question.

use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Budget {
    /// Stop after this many requests
    Requests(u64),
    /// Stop after this long, however many requests fit
    Duration(Duration),
}

impl Budget {
    /// Nothing to do at all
    pub fn is_empty(&self) -> bool {
        *self == Budget::Requests(0)
    }

    /// May another request be started, given how many already have been?
    ///
    /// A duration run is bounded by its timer rather than by a count.
    pub fn may_start(&self, started: u64) -> bool {
        match self {
            Budget::Requests(n) => started < *n,
            Budget::Duration(_) => true,
        }
    }

    /// Has the run met its own terms? A duration run ends on the timeout
    /// instead, so this is never true for one.
    pub fn is_met(&self, finished: u64) -> bool {
        match self {
            Budget::Requests(n) => finished >= *n,
            Budget::Duration(_) => false,
        }
    }

    /// How many requests this will take, when that is knowable in advance
    pub fn expected_requests(&self) -> Option<u64> {
        match self {
            Budget::Requests(n) => Some(*n),
            Budget::Duration(_) => None,
        }
    }

    /// The deadline to arm, if there is one
    pub fn deadline(&self) -> Option<Duration> {
        match self {
            Budget::Duration(d) => Some(*d),
            Budget::Requests(_) => None,
        }
    }

    /// One budget per thread
    ///
    /// A request count is divided, with the remainder going to the first
    /// threads; a duration applies to every thread as it stands.
    pub fn split(&self, threads: usize) -> Vec<Budget> {
        match self {
            Budget::Duration(d) => vec![Budget::Duration(*d); threads],
            Budget::Requests(total) => (0..threads as u64)
                .map(|i| {
                    Budget::Requests(total / threads as u64 + u64::from(i < total % threads as u64))
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_count_bounds_what_may_start() {
        let b = Budget::Requests(3);
        assert!(b.may_start(0));
        assert!(b.may_start(2));
        assert!(!b.may_start(3));
    }

    /// A duration run is bounded by its timer, so the count never stops it
    #[test]
    fn a_duration_never_runs_out_of_requests() {
        let b = Budget::Duration(Duration::from_secs(10));
        assert!(b.may_start(0));
        assert!(b.may_start(u64::MAX - 1));
        assert!(!b.is_met(u64::MAX - 1));
    }

    #[test]
    fn a_request_count_is_met_when_it_is_reached() {
        let b = Budget::Requests(5);
        assert!(!b.is_met(4));
        assert!(b.is_met(5));
        assert!(b.is_met(6), "overshooting still counts as met");
    }

    /// Only a counted run knows how many latencies to make room for. Asking a
    /// duration run gives None rather than a number to allocate against,
    /// which is what the separate count made easy to get wrong.
    #[test]
    fn only_a_counted_run_can_be_reserved_for() {
        assert_eq!(Budget::Requests(1000).expected_requests(), Some(1000));
        assert_eq!(
            Budget::Duration(Duration::from_secs(1)).expected_requests(),
            None
        );
    }

    #[test]
    fn only_a_timed_run_arms_a_deadline() {
        assert_eq!(Budget::Requests(10).deadline(), None);
        assert_eq!(
            Budget::Duration(Duration::from_millis(250)).deadline(),
            Some(Duration::from_millis(250))
        );
    }

    #[test]
    fn a_count_splits_with_the_remainder_at_the_front() {
        let parts = Budget::Requests(10).split(3);
        assert_eq!(
            parts,
            vec![
                Budget::Requests(4),
                Budget::Requests(3),
                Budget::Requests(3)
            ]
        );
        let total: u64 = parts.iter().filter_map(|b| b.expected_requests()).sum();
        assert_eq!(total, 10, "nothing is lost in the division");
    }

    /// Every thread runs for the whole duration; it is not divided
    #[test]
    fn a_duration_is_given_to_every_thread_whole() {
        let d = Duration::from_secs(7);
        assert_eq!(Budget::Duration(d).split(3), vec![Budget::Duration(d); 3]);
    }

    #[test]
    fn fewer_requests_than_threads_leaves_some_with_none() {
        let parts = Budget::Requests(2).split(4);
        assert_eq!(parts[0], Budget::Requests(1));
        assert_eq!(parts[1], Budget::Requests(1));
        assert!(parts[2].is_empty());
        assert!(parts[3].is_empty());
    }
}
