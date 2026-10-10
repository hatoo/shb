//! Replay identical response bytes through the production HTTP/1 parser.
//! Arguments: fields|line|near|connection header-bytes receive-bytes repetitions.
//! Build both revisions with the same harness, dependency artifacts and release
//! settings. Input construction, warmup and validation are outside measurement.
//! Callgrind: --collect-atstart=no --toggle-collect=measured_headers, H1_WARMUPS=0.
//! This measures parser work, not network throughput or kernel execution.

use std::hint::black_box;
use std::time::Instant;

#[allow(dead_code)]
#[path = "../src/http1/parse.rs"]
mod parse;

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub fn is_informational(status: u16) -> bool {
    (100..200).contains(&status)
}

fn cpu_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut time) },
        0
    );
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

// A stable measurement boundary, outside the production implementation.
#[inline(never)]
#[unsafe(no_mangle)]
fn measured_headers(
    parser: &mut parse::Parser,
    wire: &[u8],
    receive: usize,
    repeats: usize,
) -> usize {
    let mut done = 0;
    for _ in 0..repeats {
        for bytes in wire.chunks(receive) {
            done += parser.feed(black_box(bytes)).unwrap();
        }
    }
    black_box(done)
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        5,
        "fields|line|near|connection header-bytes receive-bytes repetitions"
    );
    let pattern = &args[1];
    let header: usize = args[2].parse().unwrap();
    let receive: usize = args[3].parse().unwrap();
    let repeats: usize = args[4].parse().unwrap();
    assert!(repeats > 0 && receive > 0);
    let mut wire = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n".to_vec();
    if header > 64 {
        match pattern.as_str() {
            "fields" => {
                while wire.len() + 53 < header {
                    wire.extend_from_slice(
                        b"X-Field: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n",
                    );
                }
            }
            "line" | "near" | "connection" => {
                wire.extend_from_slice(match pattern.as_str() {
                    "near" => b"Transfer-Encoding-Extension: ",
                    "connection" => b"Connection: ",
                    _ => b"X-Long: ",
                });
                wire.resize(header.saturating_sub(4).max(wire.len()), b'x');
                wire.extend_from_slice(b"\r\n");
            }
            _ => panic!("unknown pattern"),
        }
    }
    wire.extend_from_slice(b"\r\nhello, world!");
    let mut parser = parse::Parser::new();
    let warmups = std::env::var("H1_WARMUPS").map_or(3, |v| v.parse().unwrap());
    for _ in 0..warmups {
        assert_eq!(measured_headers(&mut parser, &wire, receive, 1), 1);
    }
    let cpu = cpu_ns();
    let wall = Instant::now();
    let done = measured_headers(&mut parser, &wire, receive, repeats);
    let wall = wall.elapsed().as_nanos();
    let cpu = cpu_ns() - cpu;
    assert_eq!(done, repeats);
    assert_eq!(parser.status(), 200);
    assert!(parser.keep_alive());
    assert!(!parser.mark_eof());
    println!(
        "{{\"pattern\":\"{pattern}\",\"header\":{header},\"wire_bytes\":{},\"receive\":{receive},\"repeats\":{repeats},\"completed\":{done},\"parser_bytes\":{},\"cpu_ns\":{cpu},\"wall_ns\":{wall}}}",
        wire.len(),
        std::mem::size_of::<parse::Parser>()
    );
}
