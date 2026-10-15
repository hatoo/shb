# Reserve the complete multiworker latency buffer

After `main` captures benchmark elapsed time, `merge_workers` combines the
workers' counters and latency samples for reporting. Previously its initially
empty vector grew as each worker was appended, copying already merged samples
again on each reallocation. Summing the sample lengths first permits one final
allocation. Sample order, counters, first-error behavior, and the existing
single-worker ownership shortcut are preserved.

This reduces post-run aggregation cost. HTTP throughput and request latency
measurement are outside the changed code and are not performance claims here.

## Measurements

Baseline: `12e95af17ef6015020776ab65996bef9531099e0`. Both immutable benchmark
binaries use the same existing `stats-merge` example, Rust 1.98.0, release fat
LTO, one codegen unit, and default mimalloc, on WSL2. No production compiler
hints or dependency changes are involved.

Five alternating process pairs, CPU 8, three warmups and three observations per
process. Confirmation uses five new pairs, reversed starting order, and a
different seed (162162 instead of 162). Table entries are medians of paired
process-median CPU changes. Wall time agrees in direction. Input generation,
oracle validation, and final aggregate destruction are outside the interval;
worker destruction is included. Allocation counters are disabled during timing.

| Samples | Workers | Aggregation, primary / confirmation | Full JSON report, primary / confirmation |
| --- | --- | --- | --- |
| 1 million | 4 | -38.336% / -33.851% | -10.836% / -9.075% |
| 1 million | 16 | -46.447% / -42.608% | -10.041% / -12.413% |
| 10 million | 4 | -43.198% / -44.107% | -9.142% / -7.287% |
| 10 million | 16 | -37.326% / -38.576% | -7.247% / -8.506% |

All 40 aggregation pairs improve. All ten full-report pairs improve in each
of the first three rows. At 10 million samples / 16 workers, nine improve and
one is +0.390%; full-report improvement in that cell is less uniform.
For scale, primary aggregation CPU medians at 10 million samples / 16 workers
are 13.382 ms versus 8.340 ms. These absolute medians are not the paired-percent
calculation above. Single-worker full-report medians change +0.162% / -1.049%
at 1 million / 10 million samples with mixed pairs; no single-worker gain or
universal reporting improvement is claimed.

Every timing pair produces byte-identical JSON reports. An additional 324
small-input comparisons cover merge/JSON/text, empty/one/1024 samples, 1/4/16
workers, grown/exact worker capacities, and random/sorted input. Merge mode
checks the exact sample sequence; report modes check the entire sample multiset,
counters, and status histogram. The reporter and elapsed input are unchanged.

## Allocation and memory tradeoff

Three separate allocation-count process pairs reproduce identical results for
0/1/1024/1M/10M samples, 1/4/16 workers, and grown/exact worker capacities.
At 10 million samples, aggregation reallocations fall from 2 to 0 with four
workers and from 4 to 0 with sixteen. Requested allocation bytes fall from
140,008,000 / 155,008,000 respectively to 80,008,000. Both paths allocate the
status table and final sample buffer; the single-worker path still allocates
nothing. Final multiworker capacity equals the exact sample count.

The full output buffer is reserved before any worker storage is freed. Peak
extra *live requested* bytes therefore rise: for sixteen grown workers at
10 million samples, 12,835,136 becomes 80,008,000. This counter subtracts an
old allocation during `realloc`; it does not include the allocator's temporary
old/new buffers or page retention, so it is not peak physical memory.

Three alternating fresh-process RSS pairs at 10 million samples, no warmups,
show lower whole-harness peak RSS: four workers grown/exact -6.27%/-15.87%,
sixteen workers grown/exact -14.28%/-19.08%. The harness also holds reference
sample arrays, and these results are not a general production RSS guarantee.
Reserving sooner changes allocation timing and can require more address space
while worker buffers are still owned.

## Correctness

Debug and release each pass 508 unit tests and 62 integration tests, with two
pre-existing ignored tests. Strict all-target Clippy and formatting pass. New
coverage includes uneven worker lengths and empty reserved buffers; existing
tests verify exact counters/sample order, first errors, and single-worker reuse.

Fixed hfast production code (binary from `95bae7f`) serves 442,368 successful
requests across HTTP/1, HTTP/2, HTTP/3 and 1/4/16 client workers, with zero request
or connection errors. A separately built audit executable verifies every sample
in order and every counter/status before and after merging for 147,456 of those
requests. These are correctness checks, not network throughput measurements.

## Reproduction

The benchmark and comparator already exist in both revisions. Build each with
the same settings and save immutable copies before changing source:

```sh
CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/merge-target \
  cargo build --locked --release --example stats-merge
# Save as /tmp/merge-baseline or /tmp/merge-candidate for the matching revision.
python3 benchmarks/compare-stats-merge.py /tmp/merge-baseline /tmp/merge-candidate \
  /tmp/merge-primary --modes merge,json --sizes 1000000,10000000 \
  --workers 4,16 --pairs 5 --repeats 3 --seed 162
python3 benchmarks/compare-stats-merge.py /tmp/merge-baseline /tmp/merge-candidate \
  /tmp/merge-confirmation --modes merge,json --sizes 1000000,10000000 \
  --workers 4,16 --pairs 5 --repeats 3 --seed 162162 --reverse
python3 benchmarks/compare-stats-merge.py /tmp/merge-baseline /tmp/merge-candidate \
  /tmp/merge-counts --modes merge --sizes 0,1,1024,1000000,10000000 \
  --workers 1,4,16 --capacities grown,exact --pairs 3 --repeats 1 --count
```

Output directories must be new. Raw commands, observations, complete reports,
binary/source manifests, and the RSS guard are retained as c162 artifacts under
the workspace's `shb/optimization-results/`, not committed as raw benchmarks.
