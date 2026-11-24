use super::*;
use crate::quic::frame::Frame;

// Static QPACK :status 200, followed by a complete three-byte DATA frame.
const RESPONSE: &[u8] = &[1, 3, 0, 0, 0xd9, 0, 3, b'a', b'b', b'c'];

struct Fixture {
    conn: Conn,
    stats: Stats,
    started: u64,
}

impl Fixture {
    fn new() -> Self {
        let mut conn = Conn::new();
        let mut quic = Connection::connect(
            crate::tls::client_config(b"h3").unwrap(),
            "localhost",
            local_params(Duration::from_secs(5), None),
        )
        .unwrap();
        quic.test_send_limits(8, 4096);
        conn.quic = Some(quic);
        conn.h3_ready = true;
        let mut started = 0;
        fill_streams(
            &mut conn,
            b"request",
            4,
            &mut started,
            Budget::Requests(4),
            false,
        )
        .unwrap();
        assert_eq!(started, 4);
        Self {
            conn,
            stats: Stats::default(),
            started,
        }
    }

    fn stream(&mut self, id: u64, offset: u64, data: &[u8], fin: bool) {
        self.conn
            .quic
            .as_mut()
            .unwrap()
            .test_receive_frame(Frame::Stream {
                id,
                offset,
                data,
                fin,
            });
    }

    fn reset(&mut self, id: u64, final_size: u64) {
        self.conn
            .quic
            .as_mut()
            .unwrap()
            .test_receive_frame(Frame::ResetStream {
                id,
                error: proto::H3_REQUEST_REJECTED,
                final_size,
            });
    }

    fn step(&mut self) -> bool {
        drive(
            &mut self.conn,
            &mut self.stats,
            b"request",
            4,
            &mut self.started,
            Budget::Requests(4),
            true,
        )
    }

    fn assert_closed(&mut self, completed: u64) {
        let before: Vec<_> = self
            .conn
            .streams
            .iter()
            .map(|request| request.start)
            .collect();
        assert!(!self.step());
        assert_eq!(
            self.conn.quic.as_ref().unwrap().test_close_code(),
            Some((proto::H3_CLOSED_CRITICAL_STREAM, true))
        );
        assert_eq!(
            self.conn
                .streams
                .iter()
                .map(|request| request.start)
                .collect::<Vec<_>>(),
            before
        );
        assert_eq!(self.started, 4);
        // begin_close charges requests through this method; invoking it twice
        // must not charge an error or an undecided give-back twice.
        self.conn.fail_inflight(&mut self.stats);
        self.conn.fail_inflight(&mut self.stats);
        assert_eq!(
            (
                self.stats.completed,
                self.stats.errors,
                self.stats.connect_errors
            ),
            (completed, 4 - completed, 0)
        );
        assert_eq!(self.stats.latencies_ns.len() as u64, completed);
        assert_eq!(self.stats.status_counts.iter().sum::<u64>(), completed);
        assert!(!self.conn.has_unsent);
        self.conn.close(0, &mut Vec::new());
        assert!(self.conn.uni.is_empty());
    }
}

#[test]
fn critical_fin_and_reset_win_over_same_batch_responses_in_either_order() {
    for kind in [0, 2, 3] {
        for reset in [false, true] {
            for known in [false, true] {
                for response_first in [false, true] {
                    let mut f = Fixture::new();
                    if known {
                        f.stream(3, 0, &[kind], false);
                        assert!(f.step());
                    }
                    if response_first {
                        f.stream(0, 0, RESPONSE, true);
                    }
                    f.stream(3, 0, &[kind], !reset);
                    if reset {
                        f.reset(3, 1);
                    }
                    if !response_first {
                        f.stream(0, 0, RESPONSE, true);
                    }
                    f.assert_closed(0);
                }
            }
        }
    }
}

#[test]
fn fragmented_critical_fin_waits_for_the_missing_prefix() {
    for kind in [0, 2, 3] {
        let mut f = Fixture::new();
        f.stream(3, 1, &[kind], true);
        assert!(f.step(), "a FIN beyond a gap is not yet delivered");
        assert_eq!(f.stats.errors, 0);
        f.stream(3, 0, &[0x40], false);
        f.assert_closed(0);
    }
}

#[test]
fn reset_before_fragmented_type_is_remembered_until_identification() {
    for kind in [0, 2, 3] {
        let mut f = Fixture::new();
        f.reset(3, 2);
        assert!(f.step(), "no type prefix must be tolerated");
        f.stream(3, 0, &[0x40], false);
        assert!(f.step(), "partial type prefix must be tolerated");
        assert_eq!(f.conn.uni.len(), 1);
        f.stream(3, 1, &[kind], false);
        f.assert_closed(0);
    }
}

#[test]
fn unknown_empty_and_partial_streams_allow_complete_responses_and_samples() {
    for prefix in [&[0x21][..], &[][..], &[0x40][..]] {
        for reset in [false, true] {
            let mut f = Fixture::new();
            f.stream(11, 0, prefix, !reset);
            if reset {
                f.reset(11, prefix.len() as u64);
            }
            for id in [12, 4, 8, 0] {
                f.stream(id, 0, RESPONSE, true);
            }
            assert!(f.step());
            assert_eq!(
                (
                    f.started,
                    f.stats.completed,
                    f.stats.errors,
                    f.stats.connect_errors
                ),
                (4, 4, 0, 0)
            );
            assert_eq!(f.stats.latencies_ns.len(), 4);
            assert_eq!(f.stats.status_counts.iter().sum::<u64>(), 4);
            assert_eq!(f.conn.uni.len(), 1, "sparse IDs need no gap entries");
            assert!(f.conn.streams.is_empty());
            assert_eq!(f.conn.quic.as_ref().unwrap().test_close_code(), None);
            for _ in 0..8 {
                f.reset(11, prefix.len() as u64);
                assert!(f.step());
            }
            assert_eq!(f.stats.latencies_ns.len(), 4);
        }
    }
}

#[test]
fn critical_closure_preserves_prior_samples_but_rejects_new_same_batch_success() {
    let mut f = Fixture::new();
    f.stream(0, 0, RESPONSE, true);
    assert!(f.step());
    let sample = f.stats.latencies_ns.clone();
    assert_eq!(sample.len(), 1);
    f.stream(4, 0, RESPONSE, true);
    f.stream(3, 0, &[0, 4, 0, 7, 1, 8], true);
    f.assert_closed(1);
    assert_eq!(f.stats.latencies_ns, sample);
}

#[test]
fn critical_closure_settles_undecided_goaway_give_backs_once() {
    let mut f = Fixture::new();
    // GOAWAY leaves two active requests and two undecided give-backs.
    f.stream(3, 0, &[0, 4, 0, 7, 1, 8], false);
    assert!(f.step());
    assert_eq!(
        (f.started, f.conn.streams.len(), f.conn.give_backs.unjudged),
        (4, 2, 2)
    );
    assert_eq!(f.stats.errors, 0);
    f.stream(3, 6, &[], true);
    f.assert_closed(0);
}
