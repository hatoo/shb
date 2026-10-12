use super::*;

/// Each payload contains no HPACK bytes, even when HEADERS metadata is present.
fn empty_fragments() -> [(u8, &'static [u8]); 5] {
    [
        (0, &[]),
        (FLAG_PADDED, &[0]),
        (FLAG_PADDED, &[3, 0, 0, 0]),
        (FLAG_PRIORITY, &[0, 0, 0, 0, 15]),
        (FLAG_PADDED | FLAG_PRIORITY, &[2, 0, 0, 0, 0, 15, 0, 0]),
    ]
}

fn events(events: &[Event]) -> Vec<(u32, Option<u16>)> {
    events
        .iter()
        .map(|event| match *event {
            Event::Status { stream_id, status } => (stream_id, Some(status)),
            Event::End { stream_id } => (stream_id, None),
            _ => panic!("unexpected {event:?}"),
        })
        .collect()
}

#[test]
fn empty_initial_fragments_allow_empty_continuations() {
    for (flags, payload) in empty_fragments() {
        for end_stream in [false, true] {
            for empty_final in [false, true] {
                let mut c = connected();
                let id = c.start_stream(&[0x82], b"").unwrap();
                let mut got = Vec::new();
                c.feed(
                    &frame(HEADERS, flags | u8::from(end_stream), id, payload),
                    &mut got,
                )
                .unwrap();
                for _ in 0..3 {
                    c.feed(&frame(CONTINUATION, 0, id, &[]), &mut got).unwrap();
                }
                assert!(got.is_empty());
                assert_eq!(c.open.len(), 1, "END_STREAM waits for END_HEADERS");
                if empty_final {
                    c.feed(&frame(CONTINUATION, 0, id, &[0x88]), &mut got)
                        .unwrap();
                    assert!(got.is_empty());
                    c.feed(&frame(CONTINUATION, FLAG_END_HEADERS, id, &[]), &mut got)
                        .unwrap();
                } else {
                    c.feed(
                        &frame(CONTINUATION, FLAG_END_HEADERS, id, &[0x88]),
                        &mut got,
                    )
                    .unwrap();
                }
                if !end_stream {
                    assert_eq!(events(&got), [(id, Some(200))]);
                    assert_eq!(c.open.len(), 1);
                    c.feed(&frame(DATA, FLAG_END_STREAM, id, b"body"), &mut got)
                        .unwrap();
                }
                assert_eq!(events(&got), [(id, Some(200)), (id, None)]);
                assert_eq!(c.open.len(), 0);
            }
        }
    }
}

#[test]
fn fragmented_sections_match_whole_sections_at_every_transport_cut() {
    let block = [0x08, 3, b'2', b'0', b'1']; // literal :status = 201
    for (flags, payload) in empty_fragments() {
        for end_stream in [false, true] {
            let mut whole = frame(HEADERS, FLAG_END_HEADERS | u8::from(end_stream), 1, &block);
            let mut split = frame(HEADERS, flags | u8::from(end_stream), 1, payload);
            split.extend(frame(CONTINUATION, 0, 1, &[]));
            for byte in block {
                split.extend(frame(CONTINUATION, 0, 1, &[byte]));
            }
            split.extend(frame(CONTINUATION, FLAG_END_HEADERS, 1, &[]));
            if !end_stream {
                // Empty trailers are a valid empty field section too.
                whole.extend(frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &[]));
                split.extend(frame(HEADERS, FLAG_END_STREAM, 1, &[]));
                split.extend(frame(CONTINUATION, FLAG_END_HEADERS, 1, &[]));
            }
            // Another stream and a connection control prove state was cleared.
            for bytes in [&mut whole, &mut split] {
                bytes.extend(frame(PING, 0, 0, b"12345678"));
                bytes.extend(frame(
                    HEADERS,
                    FLAG_END_HEADERS | FLAG_END_STREAM,
                    3,
                    &[0x89],
                ));
            }
            let make_connection = || {
                let mut c = connected();
                assert_eq!(c.start_stream(&[0x82], b""), Some(1));
                assert_eq!(c.start_stream(&[0x82], b""), Some(3));
                c.take_output();
                c
            };
            let mut oracle = make_connection();
            let mut expected = Vec::new();
            oracle.feed(&whole, &mut expected).unwrap();
            let output = oracle.take_output();
            for cut in 0..=split.len() {
                let mut c = make_connection();
                let mut got = Vec::new();
                c.feed(&split[..cut], &mut got).unwrap();
                c.feed(&split[cut..], &mut got).unwrap();
                assert_eq!(events(&got), events(&expected), "cut {cut}, flags {flags}");
                assert_eq!(c.open.len(), 0);
                assert!(c.pending.is_empty());
                assert_eq!(c.take_output(), output);
            }
            let mut c = make_connection();
            let mut got = Vec::new();
            for byte in &split {
                c.feed(&[*byte], &mut got).unwrap();
            }
            assert_eq!(events(&got), events(&expected));
            assert_eq!(c.open.len(), 0);
        }
    }
}

#[test]
fn empty_header_blocks_reject_interleaving() {
    let interleaved = [
        frame(DATA, FLAG_END_STREAM, 1, &[]),
        frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &[0x88]),
        frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, &[0x88]),
        frame(PING, 0, 0, b"12345678"),
        frame(SETTINGS, 0, 0, &[]),
        frame(RST_STREAM, 0, 1, &[0; 4]),
        frame(GOAWAY, 0, 0, &[0; 8]),
        frame(WINDOW_UPDATE, 0, 0, &[0, 0, 0, 1]),
        frame(2, 0, 1, &[0; 5]), // PRIORITY
        frame(0xff, 0, 0, &[]),  // unknown frames cannot interrupt a field block
    ];
    for (flags, payload) in empty_fragments() {
        for next in &interleaved {
            for cut in 0..=next.len() {
                let mut c = connected();
                c.start_stream(&[0x82], b"").unwrap();
                let mut got = Vec::new();
                c.feed(&frame(HEADERS, flags, 1, payload), &mut got)
                    .unwrap();
                let result = c
                    .feed(&next[..cut], &mut got)
                    .and_then(|()| c.feed(&next[cut..], &mut got));
                let err = result.unwrap_err();
                assert!(err.to_string().contains("interleaved"), "{err}");
                assert!(
                    got.is_empty(),
                    "invalid interleaving must not complete a request"
                );
                assert_eq!(c.open.len(), 1);
            }
        }
    }
}

#[test]
fn continuation_requires_the_pending_stream_and_rejects_duplicates() {
    for initial in [&[][..], &[0x88][..]] {
        for wrong in [0, 3, 0x7fff_ffff] {
            let mut c = connected();
            let mut got = Vec::new();
            c.feed(&frame(HEADERS, 0, 1, initial), &mut got).unwrap();
            assert!(
                c.feed(&frame(CONTINUATION, FLAG_END_HEADERS, wrong, &[]), &mut got)
                    .is_err()
            );
            assert!(got.is_empty());
        }
    }
    for completed in [false, true] {
        let mut c = connected();
        let mut got = Vec::new();
        if completed {
            c.feed(&frame(HEADERS, 0, 1, &[0x88]), &mut got).unwrap();
            c.feed(&frame(CONTINUATION, FLAG_END_HEADERS, 1, &[]), &mut got)
                .unwrap();
            got.clear();
        }
        assert!(
            c.feed(&frame(CONTINUATION, FLAG_END_HEADERS, 1, &[0x88]), &mut got)
                .is_err()
        );
        assert!(got.is_empty());
    }
}

#[test]
fn completed_fragmented_blocks_reuse_storage_without_stale_end_stream() {
    let mut c = connected();
    let mut got = Vec::new();
    for end_stream in [true, false, true, false] {
        let id = c.start_stream(&[0x82], b"").unwrap();
        c.feed(&frame(HEADERS, u8::from(end_stream), id, &[]), &mut got)
            .unwrap();
        c.feed(&frame(CONTINUATION, 0, id, &[0x88]), &mut got)
            .unwrap();
        let storage = c.header_block.as_ptr();
        c.feed(&frame(CONTINUATION, FLAG_END_HEADERS, id, &[]), &mut got)
            .unwrap();
        assert!(c.header_block.is_empty());
        assert_eq!(c.header_block.as_ptr(), storage);
        if !end_stream {
            assert_eq!(events(&got), [(id, Some(200))]);
            c.feed(&frame(DATA, FLAG_END_STREAM, id, &[]), &mut got)
                .unwrap();
        }
        assert_eq!(events(&got), [(id, Some(200)), (id, None)]);
        got.clear();
    }
}

#[test]
fn headers_and_continuations_cannot_use_stream_zero() {
    for flags in [0, FLAG_END_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM] {
        let mut c = connected();
        let mut got = Vec::new();
        assert!(
            c.feed(&frame(HEADERS, flags, 0, &[0x88]), &mut got)
                .is_err()
        );
        assert!(got.is_empty());
    }
}
