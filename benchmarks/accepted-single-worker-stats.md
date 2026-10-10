# Reuse complete single-worker statistics

`main` captures benchmark elapsed time before combining worker results. With one
worker, its statistics already contain the complete report. Returning that value
avoids allocating another status table and latency buffer, copying every sample,
and adding every counter to zero. Multiple workers retain the previous sequential
merge loop, sample order, and allocation growth. The first worker error is still
returned. Recording timestamps and selecting percentiles are unchanged.

This is a post-run aggregation improvement, not an HTTP throughput claim.

## Measurements

Compared against `fede6eb60b5ca38d8141ada641d437ccfaa4e8d6` with Rust 1.98.0,
release fat LTO, one codegen unit, and the default mimalloc allocator on WSL2.
The harness calls production aggregation and, in JSON mode, the complete
production reporter. Input generation, validation, and final aggregate destruction
are outside the interval. Allocation counters are disabled during timing.

Five alternating process pairs, three warmups and three measured observations
per process, pinned to CPU 8. A separate five-pair confirmation reversed the
starting order and changed the input seed from 85 to 85085. Changes below are
medians of paired process medians, not ratios of pooled measurements.

| One worker, randomly ordered samples | Primary CPU change | Confirmation CPU change |
| --- | ---: | ---: |
| Aggregate 1 million samples | -99.115% | -99.124% |
| Aggregate 10 million samples | -99.883% | -99.886% |
| Aggregate and print JSON, 1 million samples | -19.606% | -9.259% |

For the one-million-sample JSON report, all ten process pairs improve: primary
range -24.69% to -5.92%; confirmation -20.92% to -3.70%. Primary aggregation CPU
medians are 0.8243 to 0.0072 ms at one million samples, and 5.7647 to 0.0068 ms at
ten million. Whole ten-million-sample JSON reporting is inconclusive: primary
-1.877% (pairs -12.72% to +4.51%), confirmation -11.990%. No general report-time
or multiworker speed improvement is claimed. Small timings remain noise-sensitive.

Separate allocation runs cover 0/1/1024/1M/10M samples, 1/4/16 workers, both
naturally grown and exactly reserved worker vectors, with three process pairs.
For one nonempty worker, aggregation allocations fall from two to zero. Requested
bytes and extra live requested bytes fall from 8,008,000 to zero at 1M, and
80,008,000 to zero at 10M. This includes the 8,000-byte status table. All three
repetitions agree; multiworker allocation counts, requested sizes, and final
capacities are identical. Counts describe requested allocation sizes, not RSS or
allocator-internal peaks during reallocation.

Reusing a naturally grown buffer retains its spare capacity until reporting ends.
At 1M samples, retained latency storage is 8,388,608 rather than 8,000,000 bytes;
at 10M, 134,217,728 rather than 80,000,000 bytes. It was already held by the worker;
the change avoids the second temporary buffer. Exactly reserved inputs do not
have this retained-capacity difference.

Three Callgrind process pairs count only the aggregation boundary. At 1M and 10M
samples with one worker, simulated user instructions fall from 896,569 and
6,924,837 respectively to 169. Four workers add five instructions to 1,600,524;
sixteen-worker baseline counts vary by 452 around 9.4M and candidate counts are
9,401,431. These are simulated instructions, not hardware counters. The original
prototype adopted the first buffer for every worker count; it was discarded
after reproducible 10M multiworker aggregation regressions caused by spare capacity
changing later growth. The final change avoids that path.

## Correctness

- 327 unit and 51 integration tests pass in both debug and release, with two
  pre-existing ignored tests; all-target Clippy and formatting pass.
- All 16 touched-module tests pass on Rust 1.91. The buffer/table ownership test
  fails against the original aggregation loop. This checks the module's MSRV,
  not the entire dependency graph.
- Every timed JSON pair and 24 additional text/JSON pairs produce byte-identical
  reports, including counters, errors, statuses, elapsed time, rates and latencies.
  Merge-only runs check exact sample sequences; report runs check full sample
  multisets. Error-order and empty-worker cases have focused unit coverage.
- Fixed hfast `732bedd2a401cc2b8d24f5238cbfb75ed29d1bac`: 442,368 HTTP/1.1,
  HTTP/2 and HTTP/3 successes with 1/4/16 client workers and no unexpected errors.
  A separate native audit build compares every worker sample and counter before
  and after aggregation for 147,456 of these requests. Network rates are not
  performance evidence for this change.

## Reproduction

Build the same benchmark source and example declaration with both revisions:

```sh
CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/shb-merge-target cargo build --locked --release --example stats-merge
cp /tmp/shb-merge-target/release/examples/stats-merge /tmp/merge-candidate
```

Use a separate baseline checkout and target directory. Copy this revision's
`benchmarks/stats-merge.rs` and its `[[example]]` declaration to that checkout.
The baseline lacks `merge_workers`; append this adapter to its `src/stats.rs`.
It is exactly the aggregation loop from baseline `main.rs`:

```rust
pub fn merge_workers<E>(results: Vec<Result<Stats, E>>) -> Result<Stats, E> {
    let mut stats = Stats::default();
    for result in results {
        stats.merge(result?);
    }
    Ok(stats)
}
```

Save both binaries before measuring. Output directories must not already exist:

```sh
python3 benchmarks/compare-stats-merge.py /tmp/merge-baseline /tmp/merge-candidate /tmp/merge-primary --repeats 3
python3 benchmarks/compare-stats-merge.py /tmp/merge-baseline /tmp/merge-candidate /tmp/merge-confirmation --sizes 1000000,10000000 --repeats 3 --reverse --seed 85085
python3 benchmarks/compare-stats-merge.py /tmp/merge-baseline /tmp/merge-candidate /tmp/merge-counts --modes merge --sizes 0,1,1024,1000000,10000000 --capacities grown,exact --pairs 3 --repeats 1 --count
```

The runner preserves binary hashes, commands, every observation, and complete
reports. The source header documents isolated instruction counting. Raw c85
measurements, manifests, native audit sources and rejected-prototype evidence
are retained under the workspace's `shb/optimization-results/`; they are not
committed as benchmark artifacts.
