//! Compare receive partitioning with the original append-then-parse path.
use super::*;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    out.extend_from_slice(&[kind, flags]);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

// Keep the old receive assembly as a reference. Both paths use the same frame
// parser; the comparison isolates buffering and when the parser is invoked.
fn reference(c: &mut Connection, data: &[u8], events: &mut Vec<Event>) -> Result<()> {
    if c.pending.is_empty() {
        let used = c.run(data, events)?;
        if used < data.len() {
            c.pending.extend_from_slice(&data[used..]);
        }
        return Ok(());
    }
    let mut buf = std::mem::take(&mut c.pending);
    buf.extend_from_slice(data);
    match c.run(&buf, events) {
        Ok(used) => {
            buf.drain(..used);
            c.pending = buf;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn connection() -> Connection {
    let mut c = Connection::new();
    c.initiate();
    for _ in 0..8 {
        c.start_stream(&[0x82], &vec![b'q'; 70_003]).unwrap();
    }
    c.recv_consumed = WINDOW_REFRESH - 20;
    c
}

fn same(a: &Connection, b: &Connection) {
    macro_rules! fields {
        ($($field:ident),* $(,)?) => { $(assert_eq!(a.$field, b.$field, stringify!($field));)* };
    }
    fields!(
        out,
        spare,
        pending,
        header_block,
        header_stream,
        header_end_stream,
        next_id,
        max_concurrent,
        max_concurrent_assumed,
        send_window,
        peer_initial_window,
        peer_max_frame,
        recv_consumed,
        table_size,
        table_size_update,
        goaway,
        peer_preface_seen,
    );
    let streams = |c: &Connection| {
        c.open
            .iter()
            .map(|s| (s.id, s.sent, s.window))
            .collect::<Vec<_>>()
    };
    assert_eq!(streams(a), streams(b));
    assert_eq!(a.can_open(), b.can_open());
}

fn compare(data: &[u8], chunks: impl IntoIterator<Item = usize>) {
    let (mut a, mut b) = (connection(), connection());
    let (mut ae, mut be) = (Vec::new(), Vec::new());
    let mut pos = 0;
    for size in chunks {
        let end = (pos + size).min(data.len());
        let ar = a.feed(&data[pos..end], &mut ae).map_err(|e| e.to_string());
        let br = reference(&mut b, &data[pos..end], &mut be).map_err(|e| e.to_string());
        assert_eq!(ar, br, "receive {pos}..{end}");
        assert_eq!(format!("{ae:?}"), format!("{be:?}"));
        same(&a, &b);
        if ar.is_err() {
            return;
        }
        a.pump_bodies(&[b'q'; 70_003]);
        b.pump_bodies(&[b'q'; 70_003]);
        same(&a, &b);
        pos = end;
    }
    assert_eq!(pos, data.len());
}

fn response_mix(body: usize) -> Vec<u8> {
    let mut data = frame(
        SETTINGS,
        0,
        0,
        &[
            0, 1, 0, 0, 0, 0, // Encoder table shrinks.
            0, 4, 0, 1, 0x38, 0x80, // Stream window changes with bodies in flight.
        ],
    );
    data.extend(frame(PING, 0, 0, b"12345678"));
    data.extend(frame(HEADERS, 0, 1, &[0x88]));
    data.extend(frame(
        CONTINUATION,
        FLAG_END_HEADERS,
        1,
        &[0, 1, b'x', 1, b'y'],
    ));
    data.extend(frame(DATA, FLAG_PADDED, 1, &[3, b'a', b'b', 0, 0, 0]));
    for chunk in vec![b'd'; body].chunks(16_384) {
        data.extend(frame(DATA, 0, 1, chunk));
    }
    data.extend(frame(DATA, FLAG_END_STREAM, 1, b""));
    // Informational headers followed by a padded response with priority fields.
    data.extend(frame(
        HEADERS,
        FLAG_END_HEADERS,
        3,
        &[8, 3, b'1', b'0', b'3'],
    ));
    data.extend(frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM | FLAG_PADDED | FLAG_PRIORITY,
        3,
        &[2, 0, 0, 0, 0, 16, 0x88, 0, 0],
    ));
    data.extend(frame(HEADERS, FLAG_END_HEADERS, 5, &[0x8d]));
    data.extend(frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        5,
        &[0, 1, b'x', 1, b'z'],
    ));
    data.extend(frame(WINDOW_UPDATE, 0, 0, &100_000u32.to_be_bytes()));
    data.extend(frame(WINDOW_UPDATE, 0, 11, &100_000u32.to_be_bytes()));
    data.extend(frame(RST_STREAM, 0, 7, &REFUSED_STREAM.to_be_bytes()));
    data.extend(frame(RST_STREAM, 0, 9, &8u32.to_be_bytes()));
    data.extend(frame(0xfe, 0, 0, b"unknown frame"));
    data.extend(frame(GOAWAY, 0, 0, &[0, 0, 0, 11, 0, 0, 0, 0]));
    data.extend(frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        11,
        &[0x88],
    ));
    data.extend(frame(RST_STREAM, 0, 1, &0u32.to_be_bytes()));
    data
}

#[test]
fn every_split_preserves_events_output_credit_and_streams() {
    let bytes = response_mix(53);
    for split in 0..=bytes.len() {
        compare(&bytes, [0, split, 0, bytes.len() - split, 0]);
    }
    compare(&bytes, std::iter::repeat_n(1, bytes.len()));
}

#[test]
fn large_and_coalesced_frames_match_at_seeded_boundaries() {
    let bytes = response_mix(49_153);
    for seed in 1u64..=32 {
        let mut state = seed;
        let chunks = std::iter::repeat_with(|| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state as usize % 16_385) + 1
        })
        .take(bytes.len().div_ceil(1_000) * 20);
        compare(&bytes, chunks);
    }
    for chunk in [8, 9, 53, 16_384] {
        compare(
            &bytes,
            std::iter::repeat_n(chunk, bytes.len().div_ceil(chunk)),
        );
    }
}

#[test]
fn malformed_frames_fail_on_the_same_receive_with_the_same_events() {
    let preface = frame(SETTINGS, 0, 0, &[]);
    let mut cases = vec![
        b"HTTP/1.1 501 Unsupported\r\n".to_vec(),
        b"<!DOCTYPE html>".to_vec(),
        frame(SETTINGS, FLAG_ACK, 0, &[]),
        frame(DATA, 0, 1, b"invalid preface"),
        frame(SETTINGS, 0, 0, &[0]),
    ];
    for bad in [
        frame(PING, 0, 1, b"12345678"),
        frame(PING, 0, 0, b"short"),
        frame(HEADERS, FLAG_PADDED | FLAG_END_HEADERS, 1, &[9, 0x88]),
        frame(HEADERS, FLAG_PRIORITY | FLAG_END_HEADERS, 1, &[0x88]),
        frame(HEADERS, FLAG_END_HEADERS, 1, &[8, 3, b'2', b'x', b'0']),
        frame(CONTINUATION, FLAG_END_HEADERS, 1, &[0x88]),
        frame(WINDOW_UPDATE, 0, 0, &[0]),
        frame(RST_STREAM, 0, 3, &[0]),
        frame(GOAWAY, 0, 0, &[0]),
    ] {
        let mut bytes = preface.clone();
        bytes.extend(frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &[0x88],
        ));
        bytes.extend(bad);
        bytes.extend(frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            3,
            &[0x88],
        ));
        cases.push(bytes);
    }
    for bad in [
        frame(PING, 0, 0, b"12345678"),
        frame(CONTINUATION, FLAG_END_HEADERS, 3, &[0x88]),
    ] {
        let mut bytes = preface.clone();
        bytes.extend(frame(HEADERS, 0, 1, &[0x88]));
        bytes.extend(bad);
        cases.push(bytes);
    }
    for bytes in cases {
        for split in 0..=bytes.len() {
            compare(&bytes, [split, bytes.len() - split]);
        }
        compare(&bytes, std::iter::repeat_n(1, bytes.len()));
    }
}

#[test]
fn partial_prefaces_keep_the_existing_early_error_boundaries() {
    for (bytes, boundary) in [
        (b"HTTP/1.1 501".as_slice(), 5),
        (b"<!DOCTYPE html>".as_slice(), 9),
    ] {
        let mut c = Connection::new();
        for (pos, byte) in bytes.iter().enumerate().take(boundary) {
            let result = c.feed(&[*byte], &mut Vec::new());
            assert_eq!(result.is_err(), pos + 1 == boundary);
        }
    }
    let settings = frame(SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 5]);
    let mut c = Connection::new();
    c.feed(&settings[..9], &mut Vec::new()).unwrap();
    assert!(c.peer_preface_seen);
    assert!(c.max_concurrent_assumed);
    c.feed(&settings[9..], &mut Vec::new()).unwrap();
    assert_eq!(c.max_concurrent, 5);
}

#[test]
fn carry_storage_is_bounded_by_the_split_frame_not_the_receive() {
    let mut c = Connection::new();
    let mut bytes = frame(SETTINGS, 0, 0, &[]);
    // Unknown frames have no output or stream storage, isolating the carry.
    for _ in 0..4_096 {
        bytes.extend(frame(0xfe, 0, 0, &[0; 44]));
    }
    let mut events = Vec::new();
    for data in bytes.chunks(16_384) {
        c.feed(data, &mut events).unwrap();
        assert!(
            c.pending.capacity() <= 106,
            "capacity {}",
            c.pending.capacity()
        );
        assert!(c.pending.len() < 53);
    }
    assert!(c.pending.is_empty());
    assert!(events.is_empty());
}
