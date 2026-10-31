//! Literal frame schedules and an independent request ledger exercise parser
//! notices together with worker accounting, without relying on event layout.

use super::*;
use std::collections::BTreeMap;

#[path = "goaway_tests.rs"]
mod goaway_tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Notice {
    Status(u32, u16),
    End(u32),
    Reset(u32),
    Retry(u32),
    Goaway,
}

struct Frame {
    bytes: Vec<u8>,
    notices: Vec<Notice>,
    fails: bool,
}

fn frame(kind: u8, flags: u8, id: u32, body: &[u8], notices: &[Notice]) -> Frame {
    let n = body.len();
    let mut bytes = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, kind, flags];
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(body);
    Frame {
        bytes,
        notices: notices.to_vec(),
        fails: false,
    }
}

fn notices(events: &[Event]) -> Vec<Notice> {
    let mut notices = Vec::new();
    for event in events {
        match *event {
            Event::Status { stream_id, status } => notices.push(Notice::Status(stream_id, status)),
            Event::End { stream_id } => notices.push(Notice::End(stream_id)),
            Event::Reset { stream_id } => notices.push(Notice::Reset(stream_id)),
            Event::Unprocessed { stream_id } => notices.push(Notice::Retry(stream_id)),
            Event::Goaway => notices.push(Notice::Goaway),
        }
    }
    notices
}

/// A separate request ledger, driven by the fixture's semantic notices rather
/// than the parser's output or the worker's H2Ring representation.
struct Ledger {
    live: BTreeMap<u32, u16>,
    successes: Vec<(u32, u16)>,
    errors: u64,
    started: u64,
    held: u64,
    goaway: bool,
}

impl Ledger {
    fn apply(&mut self, notices: &[Notice]) {
        for &notice in notices {
            match notice {
                Notice::Status(id, status) => {
                    if let Some(old) = self.live.get_mut(&id) {
                        *old = status;
                    }
                }
                Notice::End(id) => match self.live.remove(&id) {
                    Some(0) => self.errors += 1,
                    Some(status) => {
                        self.successes.push((id, status));
                        self.started -= self.held;
                        self.held = 0;
                    }
                    None => {}
                },
                Notice::Reset(id) => self.errors += u64::from(self.live.remove(&id).is_some()),
                Notice::Retry(id) => {
                    if self.live.remove(&id).is_some() {
                        if self.successes.is_empty() {
                            self.held += 1;
                        } else {
                            self.started -= 1;
                        }
                    }
                }
                Notice::Goaway => self.goaway = true,
            }
        }
    }

    fn check(&self, conn: &mut Conn, stats: &Stats, started: u64) {
        assert_eq!(started, self.started);
        assert_eq!(conn.held, self.held);
        assert_eq!(conn.goaway, self.goaway);
        assert_eq!(conn.answered as usize, self.successes.len());
        assert_eq!(stats.completed as usize, self.successes.len());
        assert_eq!(stats.latencies_ns.len(), self.successes.len());
        assert_eq!(stats.errors, self.errors);
        assert_eq!(stats.connect_errors, 11);
        assert_eq!((stats.bytes_sent, stats.bytes_received), (37, 41));
        let mut counts = [0; 1000];
        for &(_, status) in &self.successes {
            counts[usize::from(status)] += 1;
        }
        assert_eq!(*stats.status_counts, counts);
        assert_eq!(conn.streams.len(), self.live.len());
        for (&id, &status) in &self.live {
            assert_eq!(conn.streams.get_mut(id.into()).unwrap().status, status);
        }
    }
}

fn run_schedule(frames: &[Frame], cuts: &[usize]) {
    run_schedule_with_ids(frames, cuts, &[1, 3, 5, 7]);
}

fn run_schedule_with_ids(frames: &[Frame], cuts: &[usize], ids: &[u32]) {
    let mut conn = Conn::new();
    let mut protocol = Connection::new();
    protocol.initiate();
    protocol
        .feed(&frame(4, 0, 0, &[], &[]).bytes, &mut Vec::new())
        .unwrap();
    let mut starts = BTreeMap::new();
    for &id in ids {
        assert_eq!(protocol.start_stream(&[0x82], b""), Some(id));
        let start = Instant::now();
        starts.insert(id, start);
        conn.streams
            .push(u64::from(id), InFlight { start, status: 0 });
    }
    protocol.take_output();
    conn.h2 = Some(protocol);
    let mut stats = Stats {
        connect_errors: 11,
        bytes_sent: 37,
        bytes_received: 41,
        ..Stats::default()
    };
    let mut started = ids.len() as u64;
    let mut model = Ledger {
        live: ids.iter().map(|&id| (id, 0)).collect(),
        successes: Vec::new(),
        errors: 0,
        started,
        held: 0,
        goaway: false,
    };
    let wire: Vec<_> = frames.iter().flat_map(|f| &f.bytes).copied().collect();
    let mut frame_index = 0;
    let mut frame_end = frames[0].bytes.len();
    let mut events = Vec::new();
    let mut position = 0;
    for end in cuts.iter().copied().chain([wire.len()]) {
        events.clear();
        let fed = conn
            .h2
            .as_mut()
            .unwrap()
            .feed(&wire[position..end], &mut events);
        position = end;
        let mut expected = Vec::new();
        let mut failed = false;
        while frame_index < frames.len() && frame_end <= end {
            let f = &frames[frame_index];
            expected.extend_from_slice(&f.notices);
            failed = f.fails;
            frame_index += 1;
            if frame_index < frames.len() {
                frame_end += frames[frame_index].bytes.len();
            }
            if failed {
                break;
            }
        }
        assert_eq!(fed.is_err(), failed, "receive ending at {end}");
        assert_eq!(notices(&events), expected, "receive ending at {end}");
        let samples_before = model.successes.len();
        model.apply(&expected);
        let before = Instant::now();
        // Production processes parsed events even if a later frame failed.
        process_events(&mut conn, &events, &mut stats, &mut started);
        let after = Instant::now();
        model.check(&mut conn, &stats, started);
        for &id in model.live.keys() {
            assert_eq!(conn.streams.get_mut(id.into()).unwrap().start, starts[&id]);
        }
        for (index, &(id, _)) in model.successes.iter().enumerate().skip(samples_before) {
            let low = before.duration_since(starts[&id]).as_nanos() as u64;
            let high = after.duration_since(starts[&id]).as_nanos() as u64;
            assert!((low..=high).contains(&stats.latencies_ns[index]));
        }
        if failed {
            break;
        }
    }
    // A subsequent connection failure must count each still-owned request once.
    model.errors += model.live.len() as u64 + model.held;
    model.live.clear();
    model.held = 0;
    conn.fail_inflight(&mut stats);
    conn.fail_inflight(&mut stats);
    model.check(&mut conn, &stats, started);
}

#[test]
fn completion_schedules_preserve_notices_accounting_and_samples_at_every_cut() {
    use Notice::*;
    let ok = || frame(1, 5, 1, &[0x88], &[Status(1, 200), End(1)]);
    let headers = || frame(1, 4, 1, &[0x88], &[Status(1, 200)]);
    let end = || frame(0, 1, 1, b"body", &[End(1)]);
    let trailer = || frame(1, 5, 1, &[0, 1, b'x', 1, b'y'], &[End(1)]);
    let interim = || frame(1, 4, 1, &[8, 3, b'1', b'0', b'3'], &[]);
    let mut bad_ping = frame(6, 0, 0, &[], &[]);
    bad_ping.fails = true;
    let mut bad_hpack = frame(1, 5, 3, &[0xff], &[]);
    bad_hpack.fails = true;
    let schedules = vec![
        vec![ok()],
        vec![headers(), frame(0, 0, 1, b"more", &[]), end()],
        vec![interim(), headers(), trailer()],
        vec![
            headers(),
            frame(1, 5, 3, &[0x8d], &[Status(3, 404), End(3)]),
            end(),
        ],
        vec![
            headers(),
            frame(1, 4, 3, &[0x8d], &[Status(3, 404)]),
            end(),
            frame(0, 1, 3, &[], &[End(3)]),
        ],
        vec![end()],
        vec![interim(), trailer()],
        vec![headers(), frame(1, 4, 1, &[0x8d], &[Status(1, 404)]), end()],
        vec![
            ok(),
            frame(1, 5, 1, &[0x8d], &[Status(1, 404)]),
            frame(0, 1, 1, &[], &[]),
            frame(3, 0, 1, &[0; 4], &[]),
        ],
        vec![
            headers(),
            frame(3, 0, 1, &[0; 4], &[Reset(1)]),
            frame(0, 1, 1, &[], &[]),
        ],
        vec![
            frame(3, 0, 3, &[0, 0, 0, 7], &[Retry(3)]),
            ok(),
            frame(3, 0, 5, &[0, 0, 0, 7], &[Retry(5)]),
        ],
        vec![
            frame(
                7,
                0,
                0,
                &[0, 0, 0, 1, 0, 0, 0, 0],
                &[Retry(3), Retry(5), Retry(7), Goaway],
            ),
            ok(),
        ],
        vec![headers(), frame(6, 0, 0, b"12345678", &[]), end()],
        vec![
            frame(1, 1, 1, &[8, 3], &[]),
            frame(9, 0, 1, &[], &[]),
            frame(9, 4, 1, b"503", &[Status(1, 503), End(1)]),
        ],
        vec![
            ok(),
            bad_ping,
            frame(1, 5, 3, &[0x88], &[Status(3, 200), End(3)]),
        ],
        vec![ok(), bad_hpack],
    ];
    for (index, frames) in schedules.iter().enumerate() {
        let len: usize = frames.iter().map(|f| f.bytes.len()).sum();
        for cut in 0..=len {
            run_schedule(frames, &[cut]);
        }
        run_schedule(frames, &(0..=len).collect::<Vec<_>>());
        eprintln!(
            "completion schedule {index}: {} transport schedules",
            len + 2
        );
    }
}
