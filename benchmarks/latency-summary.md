# Exact latency-summary fixture

`latency-summary.rs` calls the production `src/stats.rs` summary. It preserves
the existing four positional arguments: pattern, sample count, repeat count,
and nonzero seed. Each JSON line describes one measured call, after three
warmups by default (`SUMMARY_WARMUPS` overrides that count).

```sh
rustc --edition=2024 -O -C lto=fat -C codegen-units=1 \
  benchmarks/latency-summary.rs -o /tmp/latency-summary
/tmp/latency-summary random 1000000 10 73
```

The original patterns are `random`, `duplicates`, `sorted`, `reverse`, `equal`,
`skewed`, and `runs`. Additional patterns exercise arithmetic beyond the range
of a u64 total: `wide` uses full-width pseudorandom samples, `wide-duplicates`
uses 32 values near `u64::MAX`, `wide-sorted` and `wide-reverse` order values
near that maximum, and `wide-equal` uses the maximum itself. `boundaries` cycles
through zero, one, and values around 2^32, 2^53 and 2^64.

Save inputs once, then use those exact bytes for both revisions:

```sh
SUMMARY_SAVE_INPUT=/tmp/latency-wide.bin \
  /tmp/latency-summary wide 1000000 1 73
SUMMARY_INPUT=/tmp/latency-wide.bin \
  /tmp/latency-summary wide 1000000 10 73
```

A corpus is exactly `sample count * 8` bytes: unsigned 64-bit nanoseconds in
little-endian order, with no header. An empty corpus represents zero samples.
Replay checks the byte length before decoding. The pattern and seed remain
required and validated but do not alter a replayed corpus; the JSON `input`
field distinguishes `generated` from `replay`. Keep the corpus, its hash, the
command, compiler options, source revision, and binary hash with results.
`SUMMARY_SAVE_INPUT` uses create-new semantics and refuses to overwrite any
existing output, including when input and output refer to the same file. Both
variables may be set to copy a corpus to a new path. Zero repeats are allowed
for generation or warmup-only checks; they emit no measurement rows.

Every call must agree bit for bit with a full-sort oracle that sums in u128,
allocate zero times/bytes, and preserve the exact complete sample multiset.
Those checks also cover warmups. Input generation, loading, saving, reset,
the oracle, multiset sorting, and JSON output are outside the measured interval.
All existing JSON fields remain; `summary_bits` contains the f64 bits of min,
mean, max, then p10/p25/p50/p75/p90/p95/p99/p99.9/p99.99 in seconds. Empty input
has an empty `summary_bits` array. Allocation counters cover the summary call.

For deterministic user instruction counts on Linux with Valgrind installed:

```sh
SUMMARY_WARMUPS=0 SUMMARY_INPUT=/tmp/latency-wide.bin \
  valgrind --tool=callgrind --collect-atstart=no \
  --toggle-collect=measured_summary --callgrind-out-file=/tmp/summary.callgrind \
  /tmp/latency-summary wide 1000000 1 73
```

Callgrind counts only `measured_summary`; wall/process CPU intervals also include
clock and allocation-counter bookkeeping. Use identical harness versions and
compiler settings for both revisions. Per-call multiset validation changes work
between measured calls compared with the older fixture, so old/new harness
timings are not comparable. These measurements cover final report generation,
not HTTP throughput, and instruction counts do not establish a timing gain.

The independent Python regressions compile debug and release fixtures, validate
generated and handwritten saved inputs with Python integer/full-sort oracles,
check float bits and file/error handling, and prove that intentional u64-sum,
warmup sample-corruption, and allocation mutants fail. Each mutant also has a
passing ordinary control. There are no dependencies beyond Python 3 and Rust:

```sh
python3 -m unittest discover -s benchmarks -p 'test_latency_summary.py' -v
RUSTUP_TOOLCHAIN=1.91.0 \
  python3 -m unittest discover -s benchmarks -p 'test_latency_summary.py' -v
rustfmt --edition 2024 --check --config skip_children=true benchmarks/latency-summary.rs
```
