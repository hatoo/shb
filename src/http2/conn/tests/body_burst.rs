use super::*;

// Decode the wire independently of Connection's frame writer. Keep DATA from
// each call separate so a later grant cannot conceal an early send or FIN.
pub(super) fn data_frames(wire: &[u8]) -> Vec<(u32, bool, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < wire.len() {
        assert!(wire.len() - offset >= 9);
        let h = &wire[offset..offset + 9];
        let len = ((h[0] as usize) << 16) | ((h[1] as usize) << 8) | h[2] as usize;
        let end = offset + 9 + len;
        assert!(end <= wire.len());
        if h[3] == 0 {
            assert_ne!(len, 0, "an upload must not invent empty DATA frames");
            assert_eq!(h[4] & !1, 0);
            frames.push((
                u32::from_be_bytes(h[5..9].try_into().unwrap()),
                h[4] == 1,
                wire[offset + 9..end].to_vec(),
            ));
        }
        offset = end;
    }
    frames
}

pub(super) fn drain(c: &mut Connection) -> Vec<(u32, bool, Vec<u8>)> {
    let wire = c.take_output().unwrap_or_default();
    let frames = data_frames(&wire);
    c.recycle(wire);
    frames
}

#[test]
fn data_bursts_preserve_bytes_frame_boundaries_and_both_credit_ledgers() {
    for max in [16_384, 65_536, 16_777_215] {
        for length in [0, 1, 16_383, 16_384, 16_385, 65_535, 65_536, 131_073] {
            let body: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
            for connection_credit in [-1, 0, 1, 16_384, 65_535, 200_000] {
                for stream_credit in [-7, 0, 1, 16_383, 16_385, 200_000] {
                    let mut c = connected();
                    c.peer_max_frame = max;
                    // Open a body with no initial credit, then set a signed
                    // stream window as a SETTINGS reduction can produce.
                    c.send_window = 0;
                    let id = c.start_stream(&[0x82], &body).unwrap();
                    assert!(drain(&mut c).is_empty());
                    c.send_window = connection_credit;
                    c.open.get_mut(id as u64).unwrap().window = stream_credit;
                    c.pump_bodies(&body);
                    let frames = drain(&mut c);
                    let payload: Vec<_> = frames.iter().flat_map(|(_, _, b)| b.clone()).collect();
                    let expected = length.min(connection_credit.min(stream_credit).max(0) as usize);
                    assert_eq!(payload, body[..expected]);
                    assert!(
                        frames
                            .iter()
                            .all(|(stream, _, bytes)| *stream == id && bytes.len() <= max as usize)
                    );
                    assert!(frames.iter().rev().skip(1).all(|(_, fin, _)| !fin));
                    assert_eq!(
                        frames.iter().filter(|(_, fin, _)| *fin).count(),
                        usize::from(length != 0 && expected == length)
                    );
                    if frames.len() > 1 {
                        assert!(
                            frames[..frames.len() - 1]
                                .iter()
                                .all(|(_, _, bytes)| bytes.len() == max as usize)
                        );
                    }
                    let state = c.open.get_mut(id as u64).unwrap();
                    assert_eq!(state.sent, expected);
                    assert_eq!(state.window, stream_credit - expected as i64);
                    assert_eq!(c.send_window, connection_credit - expected as i64);
                    c.pump_bodies(&body);
                    assert!(
                        drain(&mut c).is_empty(),
                        "no duplicate DATA without new credit"
                    );
                }
            }
        }
    }
}

#[test]
fn signed_settings_credit_and_separate_grants_never_resend_a_prefix() {
    let mut c = connected();
    c.peer_initial_window = 3;
    c.send_window = 5;
    let body = b"abcdefghijklmnopq";
    let id = c.start_stream(&[0x82], body).unwrap();
    assert_eq!(drain(&mut c), vec![(id, false, b"abc".to_vec())]);
    let mut events = Vec::new();
    c.feed(&frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 0]), &mut events)
        .unwrap();
    assert_eq!(c.open.get_mut(id as u64).unwrap().window, -3);
    c.feed(
        &frame(WINDOW_UPDATE, 0, 0, &10u32.to_be_bytes()),
        &mut events,
    )
    .unwrap();
    c.pump_bodies(body);
    assert!(drain(&mut c).is_empty());
    c.feed(
        &frame(WINDOW_UPDATE, 0, id, &5u32.to_be_bytes()),
        &mut events,
    )
    .unwrap();
    c.pump_bodies(body);
    assert_eq!(drain(&mut c), vec![(id, false, b"de".to_vec())]);
    c.feed(
        &frame(WINDOW_UPDATE, 0, id, &20u32.to_be_bytes()),
        &mut events,
    )
    .unwrap();
    c.pump_bodies(body);
    assert_eq!(drain(&mut c), vec![(id, false, b"fghijklmno".to_vec())]);
    assert_eq!(c.send_window, 0);
    c.feed(
        &frame(WINDOW_UPDATE, 0, 0, &2u32.to_be_bytes()),
        &mut events,
    )
    .unwrap();
    c.pump_bodies(body);
    assert_eq!(drain(&mut c), vec![(id, true, b"pq".to_vec())]);
    assert_eq!(c.open.get_mut(id as u64).unwrap().sent, body.len());
    assert_eq!(c.open.get_mut(id as u64).unwrap().window, 8);
    assert_eq!(c.send_window, 0);
    c.pump_bodies(body);
    assert!(drain(&mut c).is_empty());
}

#[test]
fn shared_connection_credit_keeps_stream_order_across_a_retired_hole() {
    let mut c = connected();
    c.send_window = 0;
    c.peer_initial_window = 100_000;
    let body: Vec<_> = (0..65_537).map(|i| (i % 251) as u8).collect();
    let ids: Vec<_> = (0..3)
        .map(|_| c.start_stream(&[0x82], &body).unwrap())
        .collect();
    assert!(drain(&mut c).is_empty());
    // Retiring the middle stream leaves a hole in the shared stream table.
    c.feed(
        &frame(RST_STREAM, 0, ids[1], &8u32.to_be_bytes()),
        &mut Vec::new(),
    )
    .unwrap();
    c.send_window = 65_540;
    c.pump_bodies(&body);
    let frames = drain(&mut c);
    assert_eq!(
        frames
            .iter()
            .map(|(id, _, b)| (*id, b.len()))
            .collect::<Vec<_>>(),
        vec![
            (ids[0], 16_384),
            (ids[0], 16_384),
            (ids[0], 16_384),
            (ids[0], 16_384),
            (ids[0], 1),
            (ids[2], 3)
        ]
    );
    assert_eq!(
        frames
            .iter()
            .filter(|(_, fin, _)| *fin)
            .map(|(id, _, _)| *id)
            .collect::<Vec<_>>(),
        vec![ids[0]]
    );
    assert_eq!(
        frames
            .iter()
            .filter(|(id, _, _)| *id == ids[0])
            .flat_map(|(_, _, b)| b.clone())
            .collect::<Vec<_>>(),
        body
    );
    assert_eq!(frames.last().unwrap().2, body[..3]);
    assert_eq!(c.send_window, 0);
    c.send_window = 100_000;
    c.pump_bodies(&body);
    let frames = drain(&mut c);
    assert!(frames.iter().all(|(id, _, _)| *id == ids[2]));
    assert_eq!(
        frames
            .iter()
            .flat_map(|(_, _, b)| b.clone())
            .collect::<Vec<_>>(),
        body[3..]
    );
    assert_eq!(frames.iter().filter(|(_, fin, _)| *fin).count(), 1);
    assert!(frames.last().unwrap().1);
    assert_eq!(c.send_window, 100_000 - (body.len() - 3) as i64);
}
