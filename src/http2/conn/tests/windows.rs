//! Wire-level credit checks with an eager, ordered reference model. The oracle
//! stores absolute windows and visits every stream for each SETTINGS entry.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone)]
struct Stream {
    window: i64,
    sent: usize,
}

struct Oracle {
    initial: u32,
    connection: i64,
    streams: BTreeMap<u32, Stream>,
}

impl Oracle {
    fn settings(&mut self, value: u32) {
        let adjustment = i64::from(value) - i64::from(self.initial);
        for stream in self.streams.values_mut() {
            stream.window += adjustment;
        }
        self.initial = value;
    }

    fn send(&mut self, id: u32, body: &[u8]) -> Vec<(u32, bool, Vec<u8>)> {
        let stream = self.streams.get_mut(&id).unwrap();
        let available = self.connection.min(stream.window).max(0) as usize;
        let end = body.len().min(stream.sent + available);
        let frames = body[stream.sent..end]
            .chunks(16_384)
            .enumerate()
            .map(|(index, bytes)| {
                (
                    id,
                    end == body.len() && stream.sent + index * 16_384 + bytes.len() == end,
                    bytes.to_vec(),
                )
            })
            .collect();
        let used = (end - stream.sent) as i64;
        stream.sent = end;
        stream.window -= used;
        self.connection -= used;
        frames
    }
}

fn settings(values: &[u32]) -> Vec<u8> {
    let mut payload = Vec::new();
    for value in values {
        payload.extend_from_slice(&[0, 4]);
        payload.extend_from_slice(&value.to_be_bytes());
    }
    frame(SETTINGS, 0, 0, &payload)
}

#[test]
fn window_changes_match_eager_credit_through_open_reset_and_slot_reuse() {
    for length in [1, 17, 16_385] {
        for seed in 1..=32u64 {
            let mut rng = seed;
            let body: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
            let mut c = connected();
            let mut oracle = Oracle {
                initial: 65_535,
                connection: 65_535,
                streams: BTreeMap::new(),
            };
            let mut events = Vec::new();
            let mut next_id = 1;
            for step in 0..256 {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                let mut expected = Vec::new();
                match step % 8 {
                    0 | 1 => {
                        let id = c.start_stream(&[0x82], &body).unwrap();
                        assert_eq!(id, next_id);
                        next_id += 2;
                        oracle.streams.insert(
                            id,
                            Stream {
                                window: i64::from(oracle.initial),
                                sent: 0,
                            },
                        );
                        expected.extend(oracle.send(id, &body));
                    }
                    2 | 3 => {
                        // Multiple occurrences in a single frame, including
                        // decreases and repeats, apply in wire order.
                        let values = [0, (rng % 19) as u32, 16_384, 3, 65_535];
                        let values = &values[..1 + rng as usize % values.len()];
                        c.feed(&settings(values), &mut events).unwrap();
                        for &value in values {
                            oracle.settings(value);
                        }
                    }
                    4 => {
                        let credit = 1 + rng as u32 % 8192;
                        c.feed(
                            &frame(WINDOW_UPDATE, 0, 0, &credit.to_be_bytes()),
                            &mut events,
                        )
                        .unwrap();
                        oracle.connection += i64::from(credit);
                    }
                    5 => {
                        let id = 1 + 2 * (rng as u32 % (next_id / 2));
                        let credit = 1 + rng as u32 % 31;
                        c.feed(
                            &frame(WINDOW_UPDATE, 0, id, &credit.to_be_bytes()),
                            &mut events,
                        )
                        .unwrap();
                        if let Some(stream) = oracle.streams.get_mut(&id) {
                            stream.window += i64::from(credit);
                        }
                    }
                    6 => {
                        // Alternate retirement at the front and in the
                        // middle, keeping holes as new stream IDs arrive.
                        let at = if step % 16 == 6 {
                            0
                        } else {
                            oracle.streams.len() / 2
                        };
                        if let Some(&id) = oracle.streams.keys().nth(at) {
                            c.feed(&frame(RST_STREAM, 0, id, &8u32.to_be_bytes()), &mut events)
                                .unwrap();
                            oracle.streams.remove(&id);
                            assert!(
                                matches!(events.as_slice(), [Event::Reset { stream_id }] if *stream_id == id)
                            );
                            events.clear();
                        }
                    }
                    _ => {}
                }
                for id in oracle.streams.keys().copied().collect::<Vec<_>>() {
                    expected.extend(oracle.send(id, &body));
                }
                c.pump_bodies(&body);
                assert_eq!(
                    body_burst::data_frames(&c.take_output().unwrap_or_default()),
                    expected,
                    "length={length}, seed={seed}, step={step}"
                );
                assert_eq!(c.send_window, oracle.connection);
                assert_eq!(c.open.len(), oracle.streams.len());
                assert!(events.is_empty());
            }
            // Release every remaining body and complete every surviving
            // response, so the model covers the full lifecycle.
            c.feed(&settings(&[1_000_000]), &mut events).unwrap();
            oracle.settings(1_000_000);
            c.feed(
                &frame(WINDOW_UPDATE, 0, 0, &1_000_000u32.to_be_bytes()),
                &mut events,
            )
            .unwrap();
            oracle.connection += 1_000_000;
            let mut expected = Vec::new();
            for id in oracle.streams.keys().copied().collect::<Vec<_>>() {
                expected.extend(oracle.send(id, &body));
            }
            c.pump_bodies(&body);
            assert_eq!(
                body_burst::data_frames(&c.take_output().unwrap_or_default()),
                expected
            );
            for (&id, stream) in &oracle.streams {
                assert_eq!(stream.sent, body.len());
                c.feed(
                    &frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, id, &[0x88]),
                    &mut events,
                )
                .unwrap();
                assert!(
                    matches!(events.as_slice(), [Event::Status { stream_id, status: 200 }, Event::End { stream_id: ended }] if *stream_id == id && *ended == id)
                );
                events.clear();
            }
            assert_eq!(c.open.len(), 0);
        }
    }
}

#[test]
fn extreme_settings_preserve_private_grants_and_negative_windows() {
    let mut c = connected();
    let mut events = Vec::new();
    c.feed(&settings(&[3]), &mut events).unwrap();
    let id = c.start_stream(&[0x82], b"abcdefg").unwrap();
    assert_eq!(
        body_burst::drain(&mut c),
        vec![(id, false, b"abc".to_vec())]
    );
    c.feed(&settings(&[MAX_WINDOW, MAX_WINDOW, 0]), &mut events)
        .unwrap();
    c.feed(
        &frame(WINDOW_UPDATE, 0, id, &3u32.to_be_bytes()),
        &mut events,
    )
    .unwrap();
    c.pump_bodies(b"abcdefg");
    assert!(body_burst::drain(&mut c).is_empty());
    c.feed(&settings(&[1, 0, 2]), &mut events).unwrap();
    c.pump_bodies(b"abcdefg");
    assert_eq!(body_burst::drain(&mut c), vec![(id, false, b"de".to_vec())]);
    c.feed(&settings(&[4]), &mut events).unwrap();
    c.pump_bodies(b"abcdefg");
    assert_eq!(body_burst::drain(&mut c), vec![(id, true, b"fg".to_vec())]);
    c.feed(&settings(&[MAX_WINDOW, 0, MAX_WINDOW]), &mut events)
        .unwrap();
    c.pump_bodies(b"abcdefg");
    assert!(body_burst::drain(&mut c).is_empty());
}

#[test]
fn invalid_initial_window_is_rejected_without_acknowledging_it() {
    let mut c = connected();
    let mut events = Vec::new();
    assert!(c.feed(&settings(&[MAX_WINDOW + 1]), &mut events).is_err());
    assert!(c.take_output().is_none());
    assert!(events.is_empty());
}

#[test]
fn unchanged_windows_preserve_negative_credit_holes_and_later_settings() {
    for chunk in [1, 7, usize::MAX] {
        let mut c = connected();
        let mut events = Vec::new();
        let body = b"abcdefg";
        c.feed(&settings(&[3]), &mut events).unwrap();
        c.take_output();
        let first = c.start_stream(&[0x82], body).unwrap();
        let retired = c.start_stream(&[0x82], body).unwrap();
        let last = c.start_stream(&[0x82], body).unwrap();
        assert_eq!(body_burst::drain(&mut c).len(), 3);
        c.feed(
            &frame(RST_STREAM, 0, retired, &8u32.to_be_bytes()),
            &mut events,
        )
        .unwrap();
        assert!(matches!(events.as_slice(), [Event::Reset { stream_id }] if *stream_id == retired));
        events.clear();
        c.feed(&settings(&[0]), &mut events).unwrap();
        c.take_output();
        assert!(c.open.iter_mut().all(|s| s.window == -3));

        // Repeated zero deltas must not hide a later change or a different
        // setting in the same frame. Fragment every part of the wire header.
        let mut payload = settings(&[0, 0, 5, 5, 4])[FRAME_HEADER_LEN..].to_vec();
        payload.extend_from_slice(&[0, 3, 0, 0, 0, 2]);
        for bytes in frame(SETTINGS, 0, 0, &payload).chunks(chunk) {
            c.feed(bytes, &mut events).unwrap();
        }
        assert_eq!(c.take_output().unwrap(), frame(SETTINGS, FLAG_ACK, 0, &[]));
        assert_eq!(c.peer_initial_window, 4);
        assert!(!c.can_open());
        c.pump_bodies(body);
        assert_eq!(
            body_burst::drain(&mut c),
            vec![(first, false, b"d".to_vec()), (last, false, b"d".to_vec())]
        );
        c.feed(&settings(&[4, 7, 7]), &mut events).unwrap();
        assert_eq!(c.take_output().unwrap(), frame(SETTINGS, FLAG_ACK, 0, &[]));
        c.pump_bodies(body);
        assert_eq!(
            body_burst::drain(&mut c),
            vec![
                (first, true, b"efg".to_vec()),
                (last, true, b"efg".to_vec())
            ]
        );
        for id in [first, last] {
            c.feed(
                &frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, id, &[0x88]),
                &mut events,
            )
            .unwrap();
            assert!(
                matches!(events.as_slice(), [Event::Status { stream_id, status: 200 }, Event::End { stream_id: ended }] if *stream_id == id && *ended == id)
            );
            events.clear();
        }
        assert_eq!(c.open.len(), 0);
        assert!(c.take_output().is_none());
    }
}

#[test]
fn unchanged_window_does_not_hide_later_invalid_settings() {
    for invalid in [vec![0, 4, 128, 0, 0, 0], vec![0, 5, 0, 0, 0, 0]] {
        let mut c = connected();
        let mut events = Vec::new();
        let mut payload = vec![0, 4, 0, 0, 255, 255];
        payload.extend(invalid);
        assert!(
            c.feed(&frame(SETTINGS, 0, 0, &payload), &mut events)
                .is_err()
        );
        assert!(c.take_output().is_none());
        assert!(events.is_empty());
    }
}
