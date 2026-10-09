# Exact latency percentile selection (c73, 2026-10-09)

Large unordered latency arrays previously needed a complete sort to obtain nine
percentiles. Select only the requested ranks, partitioning near the middle of
each remaining range and handling coincident ranks together. Keep sorting for
at most 1,024 samples and directly read ascending/descending arrays. Min, mean,
max, percentile index arithmetic, and every retained sample remain exact.

This improves **latency-summary computation after a run**. The benchmark's elapsed
time is captured before merging statistics and reporting. No request throughput,
collection, timestamp, or latency-accuracy improvement is claimed.

## Measurement

Baseline: `e09bfd12aef9b242d315d32197fbe56ff38b0083`. Linux/WSL2, Ryzen 9 3950X,
one process pinned to CPU 8. `latency-summary.rs` compiles the actual `stats.rs`
from each revision with identical `-O -C lto=fat -C codegen-units=1` flags. Only
the unused recording clock is substituted with `std::time::Instant` to make the
summary harness standalone. Its counting system allocator records zero summary
allocations on both sides.

Each series uses five alternating process pairs, three warmups per process, and
five timed summaries per process. Resetting/generating samples, the full-sort
oracle, output, and multiset validation are outside the timed interval. The
complete summary, including mean/min/max, is inside. Every invocation compares
all 12 floating-point output bit patterns against the sort oracle.

Primary: Rust 1.98.0, seed 73. Independent confirmation: separately compiled Rust
1.91.0 binaries, seed 73073, reversed initial process order. Both variants in
each series use identical inputs and settings. Tables show medians of the five
process CPU medians; changes are medians of the five paired relative changes.

| Samples | Distribution | Baseline CPU ms | Candidate CPU ms | Primary change | Confirmation change |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1,000,000 | Uniform unordered | 18.029 | 4.025 | -77.67% | -78.07% |
| 1,000,000 | 32 distinct values | 4.202 | 3.535 | -15.89% | -11.22% |
| 1,000,000 | Ascending | 0.602 | 0.508 | -21.40% | -11.89% |
| 1,000,000 | Descending | 0.753 | 0.815 | +10.25% | -15.12% |
| 1,000,000 | All equal | 0.613 | 0.553 | -22.97% | -17.67% |
| 1,000,000 | Skewed with rare outliers | 7.710 | 4.151 | -43.41% | -44.20% |
| 1,000,000 | 16 ascending runs | 16.249 | 4.887 | -69.67% | -69.48% |
| 10,000,000 | Uniform unordered | 217.896 | 68.022 | -69.25% | -68.93% |
| 10,000,000 | 32 distinct values | 66.702 | 67.346 | +0.97% | +5.74% |
| 10,000,000 | Ascending | 15.687 | 15.337 | -2.88% | -2.64% |
| 10,000,000 | Descending | 21.362 | 16.485 | -22.62% | -30.33% |
| 10,000,000 | All equal | 15.830 | 15.114 | -3.09% | -0.39% |
| 10,000,000 | Skewed with rare outliers | 96.289 | 70.447 | -26.68% | -29.26% |
| 10,000,000 | 16 ascending runs | 210.290 | 89.049 | -58.13% | -60.49% |

The primary unordered paired ranges were -79.26..-76.80% at one million and
-69.51..-64.35% at ten million. Confirmation ranges were -78.45..-75.73% and
-70.74..-65.22%. Wall-time results agree with these large CPU reductions.

There is no universal speed claim. The ten-million-sample, 32-value case did not
improve (confirmation pairs +1.67..+9.38%). Smaller ordered cases are noisy;
the one-million descending result changed direction across series. Existing WSL
noise still prevents conclusions about small changes. Empty/tiny/1,024-sample
cases were recorded but have no timing claim. No network A/A controls were rerun.

Callgrind counted only the complete production summary in three independent
process pairs per case; all repeated instruction counts were identical. At one
million samples, unordered instructions fell 181,559,734 -> 53,364,828 (-70.61%),
32-value -12.13%, ascending/all-equal -43.21%, descending -18.60%, skewed -45.39%,
and 16-run -65.56%. Empty/singleton add 2/44 instructions; 32 and 1,024 samples
add 47. Neither variant allocates during any measured summary.

## Correctness

- Four new regressions: exhaustive ternary arrays through length eight (including
  direct selection below the small-sort cutoff), percentile/cutoff boundaries,
  seeded million-element arrays, and integer/floating-point boundary values.
  Compare every summary bit, repeat summaries, and verify the full multiset.
- Debug and release: 315 unit tests plus 51 integration tests pass per profile;
  two pre-existing unit tests remain ignored. Strict all-target Clippy and format
  checks pass. Standalone Rust 1.91 tests: baseline 8, candidate 12 pass.
- 36 independent complete report comparisons (text/JSON, all three protocols,
  0/1/32/1,024/1,025/1,000,000 samples) are byte-identical. Counters, elapsed time,
  rates, status codes, and latency fields all match.
- Fixed hfast `1c84bc6`: 12 alternating process runs, 196,608 exact status-200
  successes across H1/H2/H3, zero request/connect errors. Their rates are not
  performance evidence.

## Reproduction

Copy the same two harness files to both source trees, then build each:

```sh
rustc --edition=2024 -O -C lto=fat -C codegen-units=1 \
  benchmarks/latency-summary.rs -o /tmp/summary-baseline
# Run in the candidate tree with output /tmp/summary-candidate.
python3 benchmarks/compare-latency-summary.py \
  /tmp/summary-baseline /tmp/summary-candidate results.jsonl --cpu 8
SUMMARY_WARMUPS=0 valgrind --tool=callgrind --collect-atstart=no \
  --toggle-collect=measured_summary /tmp/summary-candidate random 1000000 1 73
```

Use `rustc +1.91.0` for the independent compiler series and
`--seed 73073 --candidate-first` for its runner. Output files are created
exclusively so an existing result cannot be replaced accidentally.

Full local evidence: `optimization-results/c73-timing-{primary,confirmation}.jsonl`,
`c73-timing-summary.json`, `c73-instruction-results.json`, `c73-report-results.json`,
`c73-fixed-server-results.json`, compiler/binary manifests, and correctness logs.
Raw measurements and diagnostic report harnesses remain outside the commit.
