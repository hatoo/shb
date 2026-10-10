//! Whole production ResponseReader replay, including creation and destruction.
//! Arguments: aligned|data-prefix|headers-tail|wide headers body receive repeats.
//! Use identical inputs/dependencies/compiler flags for both source revisions.
//! H3_WARMUPS=0 and Callgrind --collect-atstart=no
//! --toggle-collect=measured_responses isolate the full reader lifecycle.
//! Parser CPU and copies do not establish a network throughput improvement.

#![allow(dead_code)]

use std::hint::black_box;
use std::time::Instant;

#[path = "../src/http3/proto.rs"]
mod proto;
#[path = "../src/http3/qpack.rs"]
mod qpack;
#[path = "../src/status.rs"]
mod status;
#[path = "../src/quic/varint.rs"]
pub mod varint;
mod quic {
    pub use crate::varint;
}

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

fn put_length(out: &mut Vec<u8>, len: usize) {
    if len < 127 {
        out.push(len as u8);
    } else {
        out.push(127);
        let mut rest = len - 127;
        while rest >= 128 {
            out.push((rest as u8 & 127) | 128);
            rest >>= 7;
        }
        out.push(rest as u8);
    }
}

fn frame(out: &mut Vec<u8>, kind: u64, payload: &[u8], wide: bool) {
    for value in [kind, payload.len() as u64] {
        if wide {
            out.extend_from_slice(&(value | (3 << 62)).to_be_bytes());
        } else {
            varint::put_varint(out, value);
        }
    }
    out.extend_from_slice(payload);
}

// A stable measurement boundary outside production code.
#[inline(never)]
#[unsafe(no_mangle)]
fn measured_responses(chunks: &[&[u8]], repeats: usize) -> u64 {
    let mut statuses = 0;
    for _ in 0..repeats {
        let mut reader = proto::ResponseReader::default();
        for bytes in chunks {
            reader.feed(black_box(bytes)).unwrap();
        }
        statuses += black_box(reader.status()) as u64;
        black_box(&reader);
    }
    black_box(statuses)
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        6,
        "pattern header-value-bytes body-bytes receive-bytes repeats"
    );
    let pattern = &args[1];
    let header: usize = args[2].parse().unwrap();
    let body: usize = args[3].parse().unwrap();
    let receive: usize = args[4].parse().unwrap();
    let repeats: usize = args[5].parse().unwrap();
    assert!(repeats > 0 && receive > 0);
    let mut section = vec![0, 0];
    if header > 0 {
        section.extend_from_slice(&[0x21, b'x']); // literal name
        put_length(&mut section, header);
        section.resize(section.len() + header, b'y');
    }
    section.push(0xd9); // status 200 after the ignored field
    let mut wire = Vec::new();
    frame(&mut wire, 1, &section, pattern == "wide");
    let headers_end = wire.len();
    frame(&mut wire, 0, &vec![b'x'; body], pattern == "wide");
    frame(&mut wire, 1, &[0, 0], pattern == "wide"); // trailers
    let cut = match pattern.as_str() {
        "aligned" => 0,
        "data-prefix" => headers_end + 1,
        "headers-tail" => headers_end - 1,
        "wide" => 1,
        _ => panic!("unknown pattern"),
    };
    let mut chunks = Vec::new();
    if cut > 0 {
        chunks.extend(wire[..cut].chunks(receive));
    }
    chunks.extend(wire[cut..].chunks(receive));
    let warmups = std::env::var("H3_WARMUPS").map_or(3, |v| v.parse().unwrap());
    for _ in 0..warmups {
        assert_eq!(measured_responses(&chunks, 1), 200);
    }
    let cpu = cpu_ns();
    let wall = Instant::now();
    let statuses = measured_responses(&chunks, repeats);
    let wall = wall.elapsed().as_nanos();
    let cpu = cpu_ns() - cpu;
    assert_eq!(statuses, 200 * repeats as u64);
    println!(
        "{{\"pattern\":\"{pattern}\",\"header\":{header},\"body\":{body},\"receive\":{receive},\"repeats\":{repeats},\"statuses\":{statuses},\"reader_bytes\":{},\"wire_bytes\":{},\"cpu_ns\":{cpu},\"wall_ns\":{wall}}}",
        std::mem::size_of::<proto::ResponseReader>(),
        wire.len()
    );
}
