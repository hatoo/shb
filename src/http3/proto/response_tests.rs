use super::*;

#[path = "frozen_response.rs"]
mod reference;

fn varint(out: &mut Vec<u8>, value: u64, width: usize) {
    assert!(matches!(width, 1 | 2 | 4 | 8));
    assert!(value < (1u64 << (width * 8 - 2)));
    let start = out.len();
    out.extend_from_slice(&value.to_be_bytes()[8 - width..]);
    out[start] |= (width.trailing_zeros() as u8) << 6;
}

fn frame(out: &mut Vec<u8>, kind: u64, section: &[u8], width: usize) {
    varint(out, kind, width);
    varint(out, section.len() as u64, width);
    out.extend_from_slice(section);
}

fn compare(chunks: &[&[u8]]) {
    let mut actual = ResponseReader::default();
    let mut frozen = reference::ResponseReader::default();
    for (i, chunk) in chunks.iter().enumerate() {
        let a = actual.feed(chunk).map_err(|e| e.to_string());
        let b = frozen.feed(chunk).map_err(|e| e.to_string());
        assert_eq!(a, b, "result at feed {i}: {chunk:02x?}");
        assert_eq!(actual.status(), frozen.status(), "status at feed {i}");
        assert_eq!(
            (actual.pending.as_slice(), actual.skip, actual.status),
            frozen.state(),
            "state at feed {i}"
        );
    }
}

#[test]
fn frozen_reader_matches_every_pair_of_splits_and_empty_feeds() {
    for width in [1, 2, 4, 8] {
        let mut wire = Vec::new();
        frame(&mut wire, FRAME_HEADERS, &[0, 0, 0xd8], width); // 103
        frame(&mut wire, 0x21, b"grease", width);
        frame(&mut wire, FRAME_HEADERS, &[0, 0, 0xd9], width); // 200
        frame(&mut wire, FRAME_DATA, b"body", width);
        frame(
            &mut wire,
            FRAME_HEADERS,
            &[0, 0, 0x21, b'x', 1, b'y'],
            width,
        );
        frame(&mut wire, FRAME_DATA, b"", width);
        for first in 0..=wire.len() {
            for second in first..=wire.len() {
                compare(&[
                    &wire[..first],
                    &[],
                    &wire[first..second],
                    &[],
                    &wire[second..],
                    &[],
                ]);
            }
        }
        compare(&wire.chunks(1).collect::<Vec<_>>());
    }
}

#[test]
fn malformed_sections_keep_error_timing_and_state() {
    for section in [
        &[][..],
        &[0],
        &[1, 0, 0xd9], // forbidden dynamic table
        &[0, 0, 0x80],
        &[0, 0, 0x54, 3, b'x'],       // truncated literal
        &[0, 0, 0xd9, 0x54, 3, b'x'], // valid status before malformed tail
        &[0, 0, 0xff, 0xff, 0xff],
    ] {
        let mut wire = vec![1, 3, 0, 0, 0xdb]; // existing 404
        frame(&mut wire, FRAME_HEADERS, section, 2);
        wire.extend_from_slice(&[1, 3, 0, 0, 0xd9]);
        for split in 0..=wire.len() {
            compare(&[&wire[..split], &wire[split..], &[], &[1, 3, 0, 0, 0xd9]]);
        }
        compare(&wire.chunks(1).collect::<Vec<_>>());
    }
    let mut oversized = Vec::new();
    put_varint(&mut oversized, FRAME_GOAWAY);
    put_varint(&mut oversized, (1 << 20) + 1);
    oversized.extend_from_slice(&[1, 3, 0, 0, 0xd9]);
    for split in 0..=oversized.len() {
        compare(&[&oversized[..split], &oversized[split..], &[]]);
    }
}

#[test]
fn generated_mutations_and_truncated_streams_match_frozen_reader() {
    let mut wire = Vec::new();
    frame(&mut wire, FRAME_HEADERS, &[0, 0, 0xd8], 2);
    frame(&mut wire, FRAME_HEADERS, &[0, 0, 0xd9], 2);
    frame(&mut wire, FRAME_DATA, b"abcdefg", 2);
    frame(&mut wire, FRAME_HEADERS, &[0, 0], 2);
    let mut rng = 0xace7_1023u32;
    for position in 0..wire.len() {
        for value in 0..=255 {
            let mut changed = wire.clone();
            changed[position] = value;
            let mut chunks = Vec::new();
            let mut rest = changed.as_slice();
            while !rest.is_empty() {
                rng ^= rng << 13;
                rng ^= rng >> 17;
                rng ^= rng << 5;
                let take = (1 + rng as usize % 13).min(rest.len());
                chunks.push(&rest[..take]);
                rest = &rest[take..];
            }
            chunks.push(&[]);
            compare(&chunks);
        }
    }
    for end in 0..=wire.len() {
        compare(&wire[..end].chunks(1).collect::<Vec<_>>());
    }
}

#[test]
fn advertised_lengths_do_not_reserve_unreceived_payload() {
    for kind in [FRAME_HEADERS, FRAME_DATA, 0x21, (1 << 62) - 1] {
        for len in [
            0,
            1,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut wire = Vec::new();
            put_varint(&mut wire, kind);
            put_varint(&mut wire, len);
            for split in 1..wire.len() {
                compare(&[&wire[..split], &wire[split..], &[]]);
            }
            let mut reader = ResponseReader::default();
            for byte in wire.chunks(1) {
                if reader.feed(byte).is_err() {
                    break;
                }
            }
            assert!(reader.pending.capacity() <= 16);
        }
    }
}

#[test]
fn completing_data_or_unknown_headers_does_not_buffer_the_body() {
    for kind in [FRAME_DATA, 0x21, (1 << 62) - 1] {
        let mut wire = Vec::new();
        frame(&mut wire, kind, &vec![b'x'; 1 << 20], 8);
        wire.extend_from_slice(&[1, 3, 0, 0, 0xd9]);
        for split in 1..16 {
            let mut reader = ResponseReader::default();
            reader.feed(&wire[..split]).unwrap();
            reader.feed(&wire[split..]).unwrap();
            assert_eq!(reader.status(), 200);
            assert_eq!(reader.skip, 0);
            assert!(reader.pending.is_empty());
            assert!(reader.pending.capacity() <= 32);
            compare(&[&wire[..split], &wire[split..]]);
        }
    }
}

#[test]
fn completed_headers_do_not_carry_following_data_or_partial_frames() {
    let mut section = vec![0, 0, 0xd9];
    section.resize(1024, 0xd1); // ignored static fields
    let mut wire = Vec::new();
    frame(&mut wire, FRAME_HEADERS, &section, 2);
    let headers_end = wire.len();
    frame(&mut wire, FRAME_DATA, &vec![b'x'; 65536], 4);
    // Leave the next frame's type incomplete in this receive, too.
    wire.extend_from_slice(&[0x80, 0]);
    let mut reader = ResponseReader::default();
    reader.feed(&wire[..headers_end - 1]).unwrap();
    reader.feed(&wire[headers_end - 1..]).unwrap();
    assert_eq!(reader.status(), 200);
    assert_eq!(reader.pending, [0x80, 0]);
    assert!(reader.pending.capacity() <= 2 * headers_end);
    reader.feed(&[0, 0, 0]).unwrap(); // remaining DATA type, zero length
    assert!(reader.pending.is_empty());
    compare(&[
        &wire[..headers_end - 1],
        &wire[headers_end - 1..],
        &[0, 0, 0],
    ]);
}
