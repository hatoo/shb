//! Standalone benchmark of the complete production latency summary.
//! Build with `rustc --edition=2024 -O -C lto=fat -C codegen-units=1
//! benchmarks/latency-summary.rs -o /tmp/latency-summary`.
//! Run: `/tmp/latency-summary random 1000000 10 73` (pattern, length, repeats, seed).
//! Each JSON line measures one summary; input generation/reset, validation, and
//! printing are outside the interval. Three warmups use the same input.
//! For instruction counts: SUMMARY_WARMUPS=0 valgrind --tool=callgrind --collect-atstart=no
//! --toggle-collect=measured_summary /tmp/latency-summary random 1000000 1 73
//! Use the identical harness for both revisions.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::Instant;

mod clock {
    pub use std::time::Instant;
}
#[allow(dead_code)]
#[path = "../src/stats.rs"]
mod stats;

struct Allocator;
static COUNT: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNT.load(Relaxed) {
            ALLOCATIONS.fetch_add(1, Relaxed);
            BYTES.fetch_add(layout.size() as u64, Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if COUNT.load(Relaxed) {
            ALLOCATIONS.fetch_add(1, Relaxed);
            BYTES.fetch_add(layout.size() as u64, Relaxed);
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNT.load(Relaxed) {
            ALLOCATIONS.fetch_add(1, Relaxed);
            BYTES.fetch_add(size as u64, Relaxed);
        }
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[repr(C)]
struct Timespec {
    seconds: std::ffi::c_long,
    nanoseconds: std::ffi::c_long,
}
unsafe extern "C" {
    fn clock_gettime(id: std::ffi::c_int, time: *mut Timespec) -> std::ffi::c_int;
}
fn cpu_ns() -> u64 {
    let mut time = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // Linux CLOCK_PROCESS_CPUTIME_ID.
    assert_eq!(unsafe { clock_gettime(2, &mut time) }, 0);
    time.seconds as u64 * 1_000_000_000 + time.nanoseconds as u64
}

// A stable boundary for Callgrind, not a production compiler hint.
#[inline(never)]
#[unsafe(no_mangle)]
fn measured_summary(samples: &mut [u64]) -> Option<stats::LatencySummary> {
    black_box(stats::latency_summary(black_box(samples)))
}

fn bits(summary: &Option<stats::LatencySummary>) -> Vec<u64> {
    match summary {
        None => Vec::new(),
        Some(s) => [s.min, s.mean, s.max]
            .into_iter()
            .chain(s.percentiles)
            .map(f64::to_bits)
            .collect(),
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 5, "pattern length repeats seed");
    let pattern = &args[1];
    let len: usize = args[2].parse().unwrap();
    let repeats: usize = args[3].parse().unwrap();
    let seed: u64 = args[4].parse().unwrap();
    let warmups: usize = std::env::var("SUMMARY_WARMUPS").map_or(3, |s| s.parse().unwrap());
    assert_ne!(seed, 0);
    let mut state = seed;
    let original: Vec<_> = (0..len)
        .map(|i| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            match pattern.as_str() {
                "random" => state % 1_000_000_000,
                "duplicates" => state % 32 * 1000,
                "sorted" => i as u64,
                "reverse" => (len - i) as u64,
                "equal" => 123_456,
                "skewed" => {
                    if state % 1000 == 0 {
                        state % 1_000_000_000
                    } else {
                        state % 1000
                    }
                }
                "runs" => (i % (len / 16).max(1)) as u64,
                _ => panic!("unknown pattern"),
            }
        })
        .collect();
    // Full-sort oracle, kept outside all measured intervals.
    let mut sorted = original.clone();
    sorted.sort_unstable();
    let expected = if sorted.is_empty() {
        None
    } else {
        Some(stats::LatencySummary {
            min: sorted[0] as f64 / 1e9,
            mean: sorted.iter().sum::<u64>() as f64 / len as f64 / 1e9,
            max: sorted[len - 1] as f64 / 1e9,
            percentiles: stats::PERCENTILES
                .map(|p| sorted[((p / 100.0 * len as f64) as usize).min(len - 1)] as f64 / 1e9),
        })
    };
    let mut samples = original.clone();
    for iteration in 0..repeats + warmups {
        samples.copy_from_slice(&original);
        ALLOCATIONS.store(0, Relaxed);
        BYTES.store(0, Relaxed);
        let cpu = cpu_ns();
        let wall = Instant::now();
        COUNT.store(true, Relaxed);
        let summary = measured_summary(&mut samples);
        COUNT.store(false, Relaxed);
        let wall = wall.elapsed().as_nanos();
        let cpu = cpu_ns() - cpu;
        let allocations = ALLOCATIONS.load(Relaxed);
        let allocated_bytes = BYTES.load(Relaxed);
        let summary_bits = bits(&summary);
        assert_eq!(summary_bits, bits(&expected));
        if iteration >= warmups {
            println!(
                "{{\"pattern\":\"{pattern}\",\"len\":{len},\"seed\":{seed},\"iteration\":{},\"wall_ns\":{wall},\"cpu_ns\":{cpu},\"allocations\":{allocations},\"allocated_bytes\":{allocated_bytes},\"summary_bits\":{summary_bits:?}}}",
                iteration - warmups,
            );
        }
    }
    samples.sort_unstable();
    assert_eq!(samples, sorted, "sample multiset changed");
}
