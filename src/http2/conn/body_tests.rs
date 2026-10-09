use super::tests::{connected, frame};
use super::*;

fn pending(c: &Connection, expected: usize, body: &[u8]) {
    assert_eq!(c.pending_bodies, expected);
    assert_eq!(c.open.iter().filter(|s| s.body_pending).count(), expected);
    for s in c.open.iter() {
        assert_eq!(s.body_pending, s.sent < body.len());
    }
}

fn credit(c: &mut Connection, id: u32, n: u32) {
    c.feed(
        &frame(WINDOW_UPDATE, 0, id, &n.to_be_bytes()),
        &mut Vec::new(),
    )
    .unwrap();
}

fn window(c: &mut Connection, n: u32) {
    let mut payload = SETTINGS_INITIAL_WINDOW_SIZE.to_be_bytes().to_vec();
    payload.extend_from_slice(&n.to_be_bytes());
    c.feed(&frame(SETTINGS, 0, 0, &payload), &mut Vec::new())
        .unwrap();
    assert_eq!(c.take_output().unwrap(), frame(SETTINGS, FLAG_ACK, 0, &[]));
}

#[test]
fn completed_bodies_and_empty_requests_need_no_more_data() {
    for body in [&b""[..], &b"small POST"[..]] {
        let mut c = connected();
        for id in (1..65).step_by(2) {
            assert_eq!(c.start_stream(&[0x82], body), Some(id));
            let mut expected = frame(
                HEADERS,
                FLAG_END_HEADERS | if body.is_empty() { FLAG_END_STREAM } else { 0 },
                id,
                &[0x82],
            );
            if !body.is_empty() {
                expected.extend(frame(DATA, FLAG_END_STREAM, id, body));
            }
            assert_eq!(c.take_output().unwrap(), expected);
            pending(&c, 0, body);
        }
        for _ in 0..32 {
            c.pump_bodies(body);
            assert!(c.take_output().is_none());
            pending(&c, 0, body);
        }
        assert_eq!(c.open.len(), 32, "responses remain outstanding");
    }
}

#[test]
fn both_windows_must_unblock_a_body_and_end_it_exactly_once() {
    let body = b"windowed";
    for stream_first in [false, true] {
        let mut c = connected();
        window(&mut c, 0);
        c.send_window = 0;
        let id = c.start_stream(&[0x82], body).unwrap();
        c.take_output();
        pending(&c, 1, body);
        credit(&mut c, if stream_first { id } else { 0 }, 3);
        c.pump_bodies(body);
        assert!(c.take_output().is_none());
        pending(&c, 1, body);
        credit(&mut c, if stream_first { 0 } else { id }, 3);
        c.pump_bodies(body);
        assert_eq!(c.take_output().unwrap(), frame(DATA, 0, id, &body[..3]));
        pending(&c, 1, body);
        credit(&mut c, 0, 100);
        credit(&mut c, id, 100);
        c.pump_bodies(body);
        assert_eq!(
            c.take_output().unwrap(),
            frame(DATA, FLAG_END_STREAM, id, &body[3..])
        );
        pending(&c, 0, body);
        credit(&mut c, id, 100);
        c.pump_bodies(body);
        assert!(c.take_output().is_none());
    }
}

#[test]
fn negative_windows_and_mixed_completed_bodies_keep_pending_membership() {
    let body = b"0123456789";
    let mut c = connected();
    c.start_stream(&[0x82], body).unwrap();
    c.take_output();
    window(&mut c, 3);
    let id = c.start_stream(&[0x82], body).unwrap();
    c.take_output();
    pending(&c, 1, body);
    window(&mut c, 0);
    assert_eq!(c.open.get_mut(id as u64).unwrap().window, -3);
    credit(&mut c, id, 3);
    c.pump_bodies(body);
    assert!(c.take_output().is_none());
    pending(&c, 1, body);
    credit(&mut c, id, 7);
    c.pump_bodies(body);
    assert_eq!(
        c.take_output().unwrap(),
        frame(DATA, FLAG_END_STREAM, id, &body[3..])
    );
    pending(&c, 0, body);
}

#[test]
fn early_end_reset_and_duplicate_reset_retire_only_the_named_body() {
    let body = b"request not fully sent";
    for response_kind in [HEADERS, DATA, RST_STREAM] {
        let mut c = connected();
        window(&mut c, 1);
        let a = c.start_stream(&[0x82], body).unwrap();
        let b = c.start_stream(&[0x82], body).unwrap();
        c.take_output();
        pending(&c, 2, body);
        let mut events = Vec::new();
        let response = match response_kind {
            HEADERS => frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, a, &[0x88]),
            DATA => frame(DATA, FLAG_END_STREAM, a, &[]),
            _ => frame(RST_STREAM, 0, a, &8u32.to_be_bytes()),
        };
        c.feed(&response, &mut events).unwrap();
        pending(&c, 1, body);
        assert!(events.iter().any(
            |e| matches!(e, Event::End {stream_id} | Event::Reset {stream_id} if *stream_id == a)
        ));
        let count = events.len();
        for _ in 0..2 {
            c.feed(&frame(RST_STREAM, 0, a, &8u32.to_be_bytes()), &mut events)
                .unwrap();
        }
        assert_eq!(events.len(), count);
        pending(&c, 1, body);
        credit(&mut c, b, body.len() as u32);
        c.pump_bodies(body);
        assert_eq!(
            c.take_output().unwrap(),
            frame(DATA, FLAG_END_STREAM, b, &body[1..])
        );
        pending(&c, 0, body);
    }
}

#[test]
fn goaway_retires_pending_and_completed_streams_above_its_limit() {
    let body = b"goaway";
    for last in [0u32, 1, 3, 5] {
        let mut c = connected();
        let a = c.start_stream(&[0x82], body).unwrap();
        c.take_output();
        window(&mut c, 0);
        let b = c.start_stream(&[0x82], body).unwrap();
        let d = c.start_stream(&[0x82], body).unwrap();
        c.take_output();
        let mut payload = last.to_be_bytes().to_vec();
        payload.extend_from_slice(&0u32.to_be_bytes());
        let mut events = Vec::new();
        c.feed(&frame(GOAWAY, 0, 0, &payload), &mut events).unwrap();
        pending(&c, [b, d].iter().filter(|id| **id <= last).count(), body);
        let expected: Vec<_> = [a, b, d].into_iter().filter(|id| *id > last).collect();
        let actual: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Event::Unprocessed { stream_id } => Some(*stream_id),
                _ => None,
            })
            .collect();
        assert_eq!(actual, expected);
        assert!(matches!(events.last(), Some(Event::Goaway)));
        assert_eq!(c.start_stream(&[0x82], body), None);
        window(&mut c, body.len() as u32);
        c.pump_bodies(body);
        let expected: Vec<_> = [b, d]
            .into_iter()
            .filter(|id| *id <= last)
            .flat_map(|id| frame(DATA, FLAG_END_STREAM, id, body))
            .collect();
        assert_eq!(c.take_output().unwrap_or_default(), expected);
        pending(&c, 0, body);
        // A second GOAWAY may lower the limit and retire another body.
        c.feed(&frame(GOAWAY, 0, 0, &[0; 8]), &mut events).unwrap();
        assert!(c.open.is_empty());
        pending(&c, 0, body);
        drop(c);
        let mut replacement = connected();
        assert_eq!(replacement.start_stream(&[0x82], body), Some(1));
        pending(&replacement, 0, body);
    }
}

#[test]
fn sparse_holes_and_compaction_do_not_lose_a_blocked_body() {
    let body = b"sparse";
    let mut c = connected();
    window(&mut c, 0);
    let ids: Vec<_> = (0..256)
        .map(|_| c.start_stream(&[0x82], body).unwrap())
        .collect();
    c.take_output();
    for &id in &ids[1..255] {
        assert!(c.finish_stream(id));
    }
    pending(&c, 2, body);
    credit(&mut c, ids[255], body.len() as u32);
    c.pump_bodies(body);
    assert_eq!(
        c.take_output().unwrap(),
        frame(DATA, FLAG_END_STREAM, ids[255], body)
    );
    pending(&c, 1, body);
    assert!(c.finish_stream(ids[0]));
    pending(&c, 0, body);
    assert_eq!(c.open.slot_count(), 1);
    let next = c.start_stream(&[0x82], body).unwrap();
    c.take_output();
    pending(&c, 1, body);
    credit(&mut c, next, body.len() as u32);
    c.pump_bodies(body);
    assert_eq!(
        c.take_output().unwrap(),
        frame(DATA, FLAG_END_STREAM, next, body)
    );
    pending(&c, 0, body);
}

#[test]
fn seeded_lifecycles_match_a_body_progress_model() {
    use std::collections::BTreeMap;
    let body = b"0123456789abcdef";
    for seed in 1..=16u64 {
        let mut rng = seed;
        let mut c = connected();
        window(&mut c, 0);
        // Independent model holds the sent prefix and credit per stream.
        let mut model = BTreeMap::<u32, (usize, usize)>::new();
        for _ in 0..1024 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            match rng % 4 {
                0 => {
                    let id = c.start_stream(&[0x82], body).unwrap();
                    model.insert(id, (0, 0));
                    assert_eq!(
                        c.take_output().unwrap(),
                        frame(HEADERS, FLAG_END_HEADERS, id, &[0x82])
                    );
                }
                1 if !model.is_empty() => {
                    let pos = rng as usize % model.len();
                    let (&id, state) = model.iter_mut().nth(pos).unwrap();
                    let n = 1 + ((rng >> 16) as usize % 19);
                    state.1 += n;
                    credit(&mut c, id, n as u32);
                }
                2 if !model.is_empty() => {
                    let id = *model.keys().nth(rng as usize % model.len()).unwrap();
                    model.remove(&id);
                    let mut events = Vec::new();
                    c.feed(&frame(RST_STREAM, 0, id, &8u32.to_be_bytes()), &mut events)
                        .unwrap();
                    assert!(matches!(&events[..], [Event::Reset {stream_id}] if *stream_id == id));
                }
                _ => {
                    let mut expected = Vec::new();
                    for (&id, (sent, window)) in &mut model {
                        let n = (body.len() - *sent).min(*window);
                        if n != 0 {
                            expected.extend(frame(
                                DATA,
                                if *sent + n == body.len() {
                                    FLAG_END_STREAM
                                } else {
                                    0
                                },
                                id,
                                &body[*sent..*sent + n],
                            ));
                            *sent += n;
                            *window -= n;
                        }
                    }
                    c.pump_bodies(body);
                    assert_eq!(c.take_output().unwrap_or_default(), expected);
                }
            }
            pending(
                &c,
                model
                    .values()
                    .filter(|(sent, _)| *sent < body.len())
                    .count(),
                body,
            );
            assert_eq!(c.open.len(), model.len());
        }
    }
}
