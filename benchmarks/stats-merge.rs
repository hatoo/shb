//! Measures production aggregation, optionally including the complete report.
//! cargo run --release --example stats-merge -- merge 1000000 4 5 85 grown random
//! Arguments: merge|json|text, total samples, workers, repeats, seed,
//! grown|exact (worker Vec capacities), random|sorted (sample distribution).
//! Reports go to stdout; timing/count JSON lines go to stderr. Generation,
//! validation, and destruction of the aggregate are outside the interval.
//! STATS_COUNT=1 enables requested allocation counts (run separately from time).
//! STATS_WARMUPS=0 valgrind --tool=callgrind --collect-atstart=no
//! --toggle-collect=measured_merge target/release/examples/stats-merge ...

use std::alloc::{GlobalAlloc, Layout};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

#[path = "../src/clock.rs"]
mod clock;
#[path = "../src/report.rs"]
mod report;
#[allow(dead_code)]
#[path = "../src/stats.rs"]
mod stats;

struct Args {
    url: String,
    connections: usize,
    http2: bool,
    http3: bool,
}

#[cfg(feature = "mimalloc")]
static INNER: mimalloc::MiMalloc = mimalloc::MiMalloc;
#[cfg(not(feature = "mimalloc"))]
static INNER: std::alloc::System = std::alloc::System;
struct Allocator;
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
static COUNT: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static REALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static DELTA: AtomicI64 = AtomicI64::new(0);
static PEAK: AtomicI64 = AtomicI64::new(0);

fn account(allocated: usize, freed: usize) {
    BYTES.fetch_add(allocated as u64, Relaxed);
    let change = allocated as i64 - freed as i64;
    let live = DELTA.fetch_add(change, Relaxed) + change;
    PEAK.fetch_max(live, Relaxed);
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNT.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
            account(layout.size(), 0);
        }
        unsafe { INNER.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if COUNT.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
            account(layout.size(), 0);
        }
        unsafe { INNER.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNT.load(Relaxed) {
            REALLOCS.fetch_add(1, Relaxed);
            account(size, layout.size());
        }
        unsafe { INNER.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if COUNT.load(Relaxed) {
            account(0, layout.size());
        }
        unsafe { INNER.dealloc(ptr, layout) }
    }
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

// This boundary is for Callgrind; production code has no compiler hint.
#[inline(never)]
#[unsafe(no_mangle)]
fn measured_merge(workers: Vec<anyhow::Result<stats::Stats>>) -> (stats::Stats, bool) {
    let sole_pointer = if workers.len() == 1 {
        Some(workers[0].as_ref().unwrap().latencies_ns.as_ptr())
    } else {
        None
    };
    let result = stats::merge_workers(black_box(workers)).unwrap();
    let reused = sole_pointer == Some(result.latencies_ns.as_ptr());
    (black_box(result), reused)
}

fn make_workers(samples: &[u64], count: usize, grown: bool) -> Vec<stats::Stats> {
    let mut start = 0;
    (0..count)
        .map(|id| {
            let len = samples.len() / count + usize::from(id < samples.len() % count);
            let mut worker = stats::Stats {
                completed: len as u64,
                errors: id as u64 * 3,
                connect_errors: id as u64,
                bytes_received: len as u64 * 197,
                bytes_sent: len as u64 * 97,
                ..Default::default()
            };
            if !grown {
                worker.latencies_ns.reserve_exact(len);
            }
            for (offset, &value) in samples[start..start + len].iter().enumerate() {
                worker.latencies_ns.push(value);
                let status = match (start + offset) % 1024 {
                    0 => 999,
                    1 => 500,
                    _ => 200,
                };
                worker.status_counts[status] += 1;
            }
            start += len;
            worker
        })
        .collect()
}

fn main() {
    let argv: Vec<_> = std::env::args().collect();
    assert_eq!(
        argv.len(),
        8,
        "merge|json|text samples workers repeats seed grown|exact random|sorted"
    );
    let mode = &argv[1];
    assert!(matches!(mode.as_str(), "merge" | "json" | "text"));
    let n: usize = argv[2].parse().unwrap();
    let workers: usize = argv[3].parse().unwrap();
    let repeats: usize = argv[4].parse().unwrap();
    let seed: u64 = argv[5].parse().unwrap();
    assert!(workers > 0 && seed > 0);
    let capacity = &argv[6];
    assert!(matches!(capacity.as_str(), "grown" | "exact"));
    let pattern = &argv[7];
    assert!(matches!(pattern.as_str(), "random" | "sorted"));
    let warmups = std::env::var("STATS_WARMUPS").map_or(3, |v| v.parse().unwrap());
    let count_allocations = std::env::var_os("STATS_COUNT").is_some();
    let mut state = seed;
    let original: Vec<_> = (0..n)
        .map(|i| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            if pattern == "sorted" {
                i as u64
            } else {
                state % 1_000_000_000
            }
        })
        .collect();
    let mut sorted = original.clone();
    sorted.sort_unstable();
    let args = Args {
        url: "https://example.invalid/merge".into(),
        connections: workers,
        http2: false,
        http3: false,
    };
    // Initialize stdout before counting/measuring report writes.
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    for iteration in 0..warmups + repeats {
        let inputs = make_workers(&original, workers, capacity == "grown");
        let input_capacity: usize = inputs.iter().map(|s| s.latencies_ns.capacity()).sum();
        let first_bytes = inputs
            .iter()
            .find(|s| !s.latencies_ns.is_empty())
            .map_or(0, |s| s.latencies_ns.len() * 8);
        let inputs: Vec<anyhow::Result<_>> = inputs.into_iter().map(Ok).collect();
        ALLOCS.store(0, Relaxed);
        REALLOCS.store(0, Relaxed);
        BYTES.store(0, Relaxed);
        DELTA.store(0, Relaxed);
        PEAK.store(0, Relaxed);
        let cpu = cpu_ns();
        let wall = Instant::now();
        COUNT.store(count_allocations, Relaxed);
        let (mut result, sole_buffer_reused) = measured_merge(black_box(inputs));
        if mode == "json" {
            report::print_json_report(&args, workers, &mut result, Duration::from_millis(1250))
                .unwrap();
        } else if mode == "text" {
            report::print_report(&args, workers, &mut result, Duration::from_millis(1250));
        }
        COUNT.store(false, Relaxed);
        let wall_ns = wall.elapsed().as_nanos();
        let cpu_ns = cpu_ns() - cpu;
        let allocations = ALLOCS.load(Relaxed);
        let reallocations = REALLOCS.load(Relaxed);
        let requested_bytes = BYTES.load(Relaxed);
        let peak_extra_requested_bytes = PEAK.load(Relaxed);
        let capacity = result.latencies_ns.capacity();
        assert_eq!(result.completed, n as u64);
        assert_eq!(result.errors, (workers * (workers - 1) / 2 * 3) as u64);
        assert_eq!(result.connect_errors, (workers * (workers - 1) / 2) as u64);
        assert_eq!(result.bytes_received, n as u64 * 197);
        assert_eq!(result.bytes_sent, n as u64 * 97);
        let mut expected_status = [0; 1000];
        expected_status[999] = (n / 1024 + usize::from(!n.is_multiple_of(1024))) as u64;
        expected_status[500] = (n / 1024 + usize::from(n % 1024 > 1)) as u64;
        expected_status[200] = n as u64 - expected_status[999] - expected_status[500];
        assert_eq!(*result.status_counts, expected_status);
        if mode == "merge" {
            assert_eq!(result.latencies_ns, original);
        } else {
            result.latencies_ns.sort_unstable();
            assert_eq!(result.latencies_ns, sorted);
        }
        if iteration >= warmups {
            eprintln!(
                "{{\"mode\":\"{mode}\",\"n\":{n},\"workers\":{workers},\"seed\":{seed},\"grown\":{},\"pattern\":\"{pattern}\",\"iteration\":{},\"wall_ns\":{wall_ns},\"cpu_ns\":{cpu_ns},\"counted\":{count_allocations},\"allocations\":{allocations},\"reallocations\":{reallocations},\"requested_bytes\":{requested_bytes},\"peak_extra_requested_bytes\":{peak_extra_requested_bytes},\"input_capacity\":{input_capacity},\"capacity\":{capacity},\"sole_buffer_reused\":{sole_buffer_reused},\"first_bytes\":{first_bytes}}}",
                argv[6] == "grown",
                iteration - warmups
            );
        }
    }
}
