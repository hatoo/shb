use super::*;

#[path = "reference.rs"]
mod reference;

/// Compare every receive boundary, including the first error and metadata
/// visibility before completion. The frozen oracle retains every unfinished line.
fn compare(data: &[u8], ends: &[usize], head: bool) {
    let mut actual = Parser::new();
    let mut expected = reference::Parser::new();
    actual.set_head_request(head);
    expected.set_head_request(head);
    let mut pos = 0;
    for &end in ends.iter().chain(std::iter::once(&data.len())) {
        let a = actual.feed(&data[pos..end]).map_err(|e| e.to_string());
        let b = expected.feed(&data[pos..end]).map_err(|e| e.to_string());
        assert_eq!(a, b, "receive {pos}..{end}, HEAD={head}");
        assert_eq!(actual.status(), expected.status(), "status at {end}");
        assert_eq!(actual.keep_alive(), expected.keep_alive(), "reuse at {end}");
        if a.is_err() {
            break;
        }
        pos = end;
    }
    assert_eq!(actual.mark_eof(), expected.mark_eof());
    assert_eq!(actual.keep_alive(), expected.keep_alive());
    assert_eq!(actual.mark_eof(), expected.mark_eof());
    actual.reset();
    expected.reset();
    // reset preserves the request method but forgets all framing metadata.
    let next = b"HTTP/1.1 201 Created\r\nContent-Length: 9\r\n\r\n";
    assert_eq!(actual.feed(next).unwrap(), expected.feed(next).unwrap());
    assert_eq!(actual.status(), 201);
    assert_eq!(actual.keep_alive(), expected.keep_alive());
    assert_eq!(
        actual.feed(b"123456789").unwrap(),
        expected.feed(b"123456789").unwrap()
    );
}

#[test]
fn reference_matches_all_three_part_splits() {
    let cases: &[&[u8]] = &[
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
        b"HTTP/1.0 200\nConnection: keep-alive, TE\nContent-Length: 0\n\n",
        b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
        b"HTTP/1.1 304\r\nContent-Length: 123\r\n\r\n",
        b"HTTP/1.1 103 Hints\nLink: x\n\nHTTP/1.1 100 Continue\n\nHTTP/1.1 200\nContent-Length: 0\n\n",
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n",
        b"HTTP/1.1 200\nTransfer-Encoding: chunked\n\n1\r\na\r\n0;ext=x\r\nX: y\r\n\r\n",
        b"HTTP/1.0 200\nConnection: keep-alive\nTransfer-Encoding: chunked\n\n0\r\n\r\n",
        b"HTTP/1.1 200\nTransfer-Encoding: chunked, gzip\nContent-Length: 1\n\nbody",
        b"HTTP/1.1 200\nTransfer-Encoding: gzip; x=\"a,chunked\"\n\nbody",
        b"HTTP/1.1 200\nTransfer-Encoding: chunked\nTransfer-Encoding: ,\n\n0\r\n\r\n",
        b"HTTP/1.1 200\nX-Unknown: \xff\xfe\nno-colon\n\nbody",
        b"HTTP/1.1 000\nContent-Length: 0\n\nHTTP/1.1 999\nContent-Length: 0\n\n",
        b"HTTP/1.1 200\nContent-Length: 4\n\nab",
        b"HTTP/1.1 200\r\nConnection: close\r\nContent-Length: 0\r\nX: unfinished",
        b"HTTP/1.1 200\nContent-Length: 1\nContent-Length: 2\n",
        b"HTTP/1.1 200\nContent-Length: 18446744073709551616\n",
        b"HTTP/1.1 200\nContent-Length: -1\n",
        b"HTTP/1.1 200\nContent-Length: \n",
        b"HTTP/1.1 200\nTransfer-Encoding: gzip; x=\"open\n",
        b"HTTP/1.1 200\nTransfer-Encoding: chunked\n\n1\r\na\rX0\r\n\r\n",
        b"HTTP/1.1 200\nTransfer-Encoding: chunked\n\nffffffffffffffff\r\n",
        b"HTTP/1.9 200\r\n",
        b"HTTP/1.1 2000\r\n",
        b"HTTP/1.1 2x0\r\n",
        b"not http at all\n",
    ];
    for &head in &[false, true] {
        for &data in cases {
            for a in 0..=data.len() {
                for b in a..=data.len() {
                    compare(data, &[a, b], head);
                }
            }
            compare(data, &(0..=data.len()).collect::<Vec<_>>(), head);
        }
    }
}

fn random(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

#[test]
fn reference_matches_seeded_large_headers_and_pipelines() {
    for mut seed in 1..=24 {
        let mut wire = Vec::new();
        for i in 0..24 {
            if i % 3 == 0 {
                wire.extend_from_slice(b"HTTP/1.1 103 Hints\r\nX: y\r\n\r\n");
            }
            wire.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
            for _ in 0..(random(&mut seed) % 64) {
                wire.extend_from_slice(b"X-Field: opaque-value\r\n");
            }
            wire.extend_from_slice(b"X-Long: ");
            wire.extend(std::iter::repeat_n(
                b'x',
                (random(&mut seed) % 65536) as usize,
            ));
            wire.extend_from_slice(b"\r\nConnection: keep-alive\r\n");
            if i % 2 == 0 {
                wire.extend_from_slice(b"Content-Length: 13\r\n\r\nhello, world!");
            } else {
                wire.extend_from_slice(b"Transfer-Encoding: gzip; a=\"b,c\", chunked\r\n\r\n3\r\nabc\r\n0\r\nT: x\r\n\r\n");
            }
        }
        let mut ends = Vec::new();
        let mut pos = 0;
        while pos < wire.len() {
            pos = (pos + 1 + (random(&mut seed) % 16384) as usize).min(wire.len());
            ends.push(pos);
        }
        compare(&wire, &ends, false);
    }
}

#[test]
fn completed_fields_are_not_retained_and_large_suffix_is_parsed_in_place() {
    let mut p = Parser::new();
    p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n")
        .unwrap();
    for _ in 0..1024 {
        assert_eq!(p.feed(b"X-Ignored: value\r\n").unwrap(), 0);
        assert!(p.pending.is_empty());
        assert_eq!(p.pending.capacity(), 0);
    }
    p.feed(b"X-Last: split").unwrap();
    let capacity = p.pending.capacity();
    let mut tail = b"\r\n\r\n".to_vec();
    tail.extend(std::iter::repeat_n(b'b', 1048576));
    assert_eq!(p.feed(&tail).unwrap(), 1);
    assert!(p.pending.is_empty());
    assert!(p.pending.capacity() <= capacity * 2);
    assert_eq!(p.status(), 200);
}

#[test]
fn fragmented_long_lines_status_chunks_and_trailers() {
    let mut wire = b"HTTP/1.1 200 ".to_vec();
    wire.extend(std::iter::repeat_n(b'x', 65536));
    wire.extend_from_slice(b"\r\nX-Long: ");
    wire.extend(std::iter::repeat_n(b'x', 1048576));
    wire.extend_from_slice(b"\r\nTransfer-Encoding: chunked\r\n\r\n1;ignored=");
    wire.extend(std::iter::repeat_n(b'x', 65536));
    wire.extend_from_slice(b"\r\na\r\n0\r\nTrailer: ");
    wire.extend(std::iter::repeat_n(b'x', 65536));
    wire.extend_from_slice(b"\r\n\r\n");
    for width in [53, 16384] {
        compare(
            &wire,
            &(0..wire.len()).step_by(width).collect::<Vec<_>>(),
            false,
        );
    }
}

#[test]
fn reset_discards_each_possible_partial_header_state() {
    let data = b"HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Length: 999\r\nX: partial\r\n\r\n";
    for split in 0..=data.len() {
        let mut p = Parser::new();
        p.set_head_request(true);
        p.feed(&data[..split]).unwrap();
        p.reset();
        assert!(p.pending.is_empty());
        assert_eq!(p.status(), 0);
        assert!(p.keep_alive());
        assert!(!p.mark_eof());
        assert_eq!(p.feed(b"HTTP/1.1 200\nContent-Length: 99\n\n").unwrap(), 1);
        assert!(p.keep_alive());
    }
}

#[test]
fn errors_still_arrive_at_the_end_of_the_invalid_line() {
    for invalid in [
        "Content-Length: 2",
        "Content-Length: -1",
        "Transfer-Encoding: gzip; x=\"unclosed",
    ] {
        let mut p = Parser::new();
        p.feed(b"HTTP/1.1 200\r\nContent-Length: 1\r\n").unwrap();
        for byte in invalid.bytes().chain(*b"\r") {
            assert_eq!(p.feed(&[byte]).unwrap(), 0);
        }
        assert!(p.feed(b"\n").is_err());
    }
}

#[test]
fn partial_field_names_match_reference_at_every_split() {
    let fields: &[&[u8]] = &[
        b"",
        b"\r",
        b"\r\r",
        b"\rX",
        b"c",
        b"t",
        b"co",
        b"con",
        b"Content-Length",
        b"Content-Lengthx: -1",
        b"Content-Length : -1",
        b"Content-Length: 0",
        b"CONTENT-LENGTH: -1",
        b"Connection",
        b"Connectionx: close",
        b"cOnNeCtIoN: close",
        b"connection\x1a close",
        b"Transfer-Encoding",
        b"Transfer-Encodingx: chunked",
        b"Transfer-Encoding: chunked",
        b"transfer-encoding\x1a gzip; x=\"open",
        b" no-colon",
        b"\0\xff\xfe",
        b"Content-Length\r: -1",
    ];
    for &field in fields {
        let mut wire = b"HTTP/1.1 200\nContent-Length: 0\n".to_vec();
        wire.extend_from_slice(field);
        wire.extend_from_slice(b"\r\n\r\n0\r\n\r\n");
        for head in [false, true] {
            for a in 0..=wire.len() {
                for b in a..=wire.len() {
                    compare(&wire, &[a, b], head);
                }
            }
        }
    }
}

#[test]
fn each_relevant_name_byte_must_match_before_retaining_values() {
    for field in [
        b"content-length: 0".as_slice(),
        b"connection: close",
        b"transfer-encoding: chunked",
    ] {
        for i in 0..=field.iter().position(|&b| b == b':').unwrap() {
            for byte in [
                0,
                b'\r',
                0x1a,
                0xff,
                b' ',
                b':',
                field[i].to_ascii_uppercase(),
            ] {
                let mut changed = field.to_vec();
                changed[i] = byte;
                let mut wire = b"HTTP/1.1 200\nContent-Length: 0\n".to_vec();
                wire.extend_from_slice(&changed);
                wire.extend_from_slice(b"\r\n\r\n0\r\n\r\n");
                for split in 0..=wire.len() {
                    compare(&wire, &[split], false);
                }
                compare(&wire, &(0..=wire.len()).collect::<Vec<_>>(), false);
            }
        }
    }
}

#[test]
fn irrelevant_partial_lines_have_bounded_carry() {
    for name in [
        b"X-Long: ".as_slice(),
        b"Connectionx:",
        b"Transfer-Encodingx:",
        b"\r\r",
    ] {
        let mut p = Parser::new();
        p.feed(b"HTTP/1.1 200\nContent-Length: 3\n").unwrap();
        for &byte in name {
            assert_eq!(p.feed(&[byte]).unwrap(), 0);
            assert!(p.pending.len() < b"transfer-encoding:".len());
        }
        assert!(p.pending.is_empty());
        let fragment = vec![b'x'; 16384];
        for _ in 0..256 {
            assert_eq!(p.feed(&fragment).unwrap(), 0);
            assert!(p.pending.is_empty());
            assert!(p.pending.capacity() <= 32);
        }
        // An LF that follows a previously discarded CR still ends only this
        // field, never the head. EOF cannot complete this partial response.
        assert_eq!(p.feed(b"\r").unwrap(), 0);
        assert!(!p.mark_eof());
        assert_eq!(p.feed(b"\nConnection: close\r\n\r").unwrap(), 0);
        assert_eq!(
            p.feed(b"\nabcHTTP/1.1 201\nContent-Length: 0\n\n").unwrap(),
            2
        );
        assert_eq!(p.status(), 201);
        assert!(p.keep_alive());
        p.reset();
        assert_eq!(p.feed(b"HTTP/1.1 204\n\n").unwrap(), 1);
    }
    // Even when only the ambiguous name was carried, the receive that
    // finishes a large irrelevant field must not be copied into pending.
    let mut p = Parser::new();
    p.feed(b"HTTP/1.1 204\nTransfer-Encod").unwrap();
    let mut suffix = b"ingx: ".to_vec();
    suffix.resize(1048576, b'x');
    suffix.extend_from_slice(b"\r\n\r\n");
    assert_eq!(p.feed(&suffix).unwrap(), 1);
    assert!(p.pending.capacity() <= 32);
}

#[test]
fn huge_relevant_fields_preserve_validation_and_reuse() {
    for (prefix, suffix) in [
        (b"Content-Length: ".as_slice(), b"\r\n\r\n".as_slice()),
        (b"Connection: ", b", close\r\nContent-Length: 0\r\n\r\n"),
        (
            b"Transfer-Encoding: gzip; q=\"",
            b"\", chunked\r\n\r\n0\r\n\r\n",
        ),
        (b"Transfer-Encoding: gzip; q=\"", b"\r\n\r\n"),
    ] {
        let mut wire = b"HTTP/1.1 200\r\n".to_vec();
        wire.extend_from_slice(prefix);
        wire.extend(std::iter::repeat_n(b'0', 65536));
        wire.extend_from_slice(suffix);
        for width in [53, 16384] {
            compare(
                &wire,
                &(0..wire.len()).step_by(width).collect::<Vec<_>>(),
                false,
            );
        }
    }
}

#[test]
fn arbitrary_partial_header_bytes_match_reference() {
    for mut seed in 1..=256 {
        let mut wire = b"HTTP/1.1 200\r\nContent-Length: 0\r\n".to_vec();
        for _ in 0..(random(&mut seed) % 256) {
            wire.push(random(&mut seed) as u8);
        }
        // Test EOF/reset while a line is skipped as well as when terminated.
        let mut ends = Vec::new();
        let mut pos = 0;
        while pos < wire.len() {
            pos = (pos + 1 + (random(&mut seed) % 19) as usize).min(wire.len());
            ends.push(pos);
        }
        compare(&wire, &ends, false);
        wire.extend_from_slice(b"\r\n\r\nHTTP/1.1 201\r\nContent-Length: 0\r\n\r\n");
        compare(&wire, &ends, false);
    }
}
