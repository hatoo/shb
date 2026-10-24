use super::{resolve_body, strip_body_newlines};

fn check(input: &[u8]) {
    let expected: Vec<_> = input
        .iter()
        .copied()
        .filter(|b| !b"\r\n".contains(b))
        .collect();
    // Exercise spare capacity too, and require normalization to reuse it.
    for spare in [0, 37] {
        let mut data = Vec::with_capacity(input.len() + spare);
        data.extend_from_slice(input);
        let pointer = data.as_ptr();
        let capacity = data.capacity();
        strip_body_newlines(&mut data);
        assert_eq!(data, expected);
        assert_eq!(data.as_ptr(), pointer);
        assert_eq!(data.capacity(), capacity);
    }
}

#[test]
fn normalization_matches_byte_filter_exhaustively() {
    check(&[]);
    for byte in 0..=u8::MAX {
        check(&[byte]);
    }
    check(&(0..=u8::MAX).collect::<Vec<_>>());
    for len in 1..=8u32 {
        for mut code in 0..3usize.pow(len) {
            let input: Vec<_> = (0..len)
                .map(|_| {
                    let byte = b"a\r\n"[code % 3];
                    code /= 3;
                    byte
                })
                .collect();
            check(&input);
        }
    }
}

#[test]
fn normalization_preserves_binary_bytes_at_search_boundaries() {
    for len in [
        15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 4096, 65537,
    ] {
        let mut input: Vec<_> = (0..len)
            .map(|i| match (i % 256) as u8 {
                b'\r' | b'\n' => 0,
                byte => byte,
            })
            .collect();
        check(&input);
        for index in [0, len / 2, len - 1] {
            let original = input[index];
            for byte in *b"\r\n" {
                input[index] = byte;
                check(&input);
            }
            input[index] = original;
        }
        for i in (0..len).step_by(31) {
            input[i] = b'\r';
        }
        check(&input);
    }
}

#[test]
fn normalization_handles_long_suffixes_and_interior_newlines() {
    for prefix in [b"".as_slice(), b"plain", b"a\rb\nc\r\nd"] {
        for suffix in [b"\r".as_slice(), b"\n", b"\r\n"] {
            let mut input = prefix.to_vec();
            input.extend(suffix.repeat(65537));
            check(&input);
        }
    }
}

#[test]
fn literal_bodies_keep_newlines_and_presence() {
    assert_eq!(resolve_body(None).unwrap(), None);
    for literal in ["", "\r\n", "a\r\nb\n", "a\0b\u{ff}", "plain"] {
        assert_eq!(
            resolve_body(Some(literal)).unwrap(),
            Some(literal.as_bytes().to_vec())
        );
    }
}
