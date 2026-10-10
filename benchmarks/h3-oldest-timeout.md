# HTTP/3 oldest-live timeout: c92

A nonexpired HTTP/3 request timeout used to scan every retained stream slot after
each completion batch. A held first response can leave hundreds of thousands of
holes behind it. Request creation times increase with stream IDs, and the ring
keeps its oldest live request at slot zero, so checking that request is enough.
No timestamp, sample, timeout boundary, polling point, error charge or close code
changes. `flush_unsent` still scans the ring; only the timeout scan is removed.

## Accepted scope

One connection, 128 concurrent streams, **262,144 GET requests**, first response
held until all younger responses have been queued and then delayed another
100 ms, with `--timeout 10s`. The fixed peer uses independent Quinn and h3.
Every response completes, including the held response, and every latency sample
and the entire delay stay in the ordinary measurement.

Three alternating pairs gave **+29.839% median requests/s**.
Three independently reversed pairs confirmed **+29.694%**.
All six pairs improve (+24.706% to +36.461%).
Complete client process CPU, including reporting, changes by
**-32.049% / -30.722%**.

Ordinary workloads, smaller held cases and timeout-off controls have mixed
results. They do not establish a general throughput gain or equivalence.
In particular, reductions in client CPU alone are not treated as throughput
improvements. WSL2 has historical noise that limits small timing claims.

## Complete corrected socket results

Each cell is the median paired percentage change, primary / confirmation.
Negative CPU values mean less complete client process CPU.

| Workload | Requests/s | Complete client CPU |
|---|---:|---:|
| fixed hfast c1-p1-n65536-t0 | +0.155% / -0.240% | -0.892% / -0.382% |
| fixed hfast c1-p1-n65536-t1 | +0.100% / -0.731% | -0.597% / -0.346% |
| fixed hfast c1-p128-n1048576-t1 | +1.721% / +1.073% | -2.551% / -1.992% |
| fixed hfast c1-p4096-n1048576-t0 | +0.370% / -3.007% | -0.741% / +2.594% |
| fixed hfast c1-p4096-n1048576-t1 | -0.565% / +0.349% | -1.238% / -2.619% |
| fixed hfast c16-p128-n1048576-t1 | +1.680% / +1.559% | -1.519% / -1.409% |
| held Quinn c1-p128-n131072-t1 | -1.875% / +0.374% | -22.805% / -24.644% |
| held Quinn c1-p128-n16384-t1 | -8.520% / -0.567% | -16.303% / -20.676% |
| held Quinn c1-p128-n65536-t0 | -0.777% / +0.931% | -1.167% / +1.675% |
| held Quinn c1-p128-n65536-t1 | +0.094% / -2.738% | -32.466% / -32.781% |
| held Quinn c1-p128-n262144-t1 | +29.839% / +29.694% | -32.049% / -30.722% |

`c` is connections, `p` concurrent streams per connection, `n` request count,
and `t1` enables `--timeout 10s` (`t0` disables it). Each binary gets an
8,192-request warmup before every measurement. Confirmation reverses cases
and variant order. Every accepted comparison uses the same workload on both
binaries; changes in request counts are never counted as optimization gains.

The 262,144 case was added once after smaller cases showed lower client CPU
but mixed throughput: it tests the point where the growing scan dominates
client work. No A/A retry, CPU-affinity sweep or threshold reduction was used.

All **59,473,920** corrected benchmark and warmup requests succeeded with zero
errors. Separate diagnostic builds validate **952,574** exact
samples plus **258** intentional timeout/reset errors, including
held responses at all four sizes, retry/GOAWAY and duration stopping. Those
instrumented binaries are not used for speed claims.

## Correctness and mechanism

- Debug/release: 346 unit tests and 55 end-to-end tests per profile pass (2 pre-existing ignored).
- Rust 1.91: 33 HTTP/3 tests and 4 Quinn fixtures pass; formatting and strict all-target Clippy pass.
- A 32,768-step full-scan model covers equal/future starts, exact `>=` boundary, holes, compaction, suffix retirement and reconnection.
- Independent Quinn fixtures observe cancellation at the peer, reset/GOAWAY retry accounting, retained held latency and duration stopping. Existing tests cover loss, reordered/duplicate packets and partially sent bodies.
- Conn remains 3,552 bytes, InFlight 80 bytes; eligibility allocates nothing.
- Three Callgrind pairs: nonexpired dense 4,096-slot checks 163,869 -> 51 instructions; sparse 65,536 slots 327,779 -> 51. These are predicate-only counts, not whole-worker gains.
- Native dense 4,096 / sparse 65,536 CPU reductions repeat near 99.96% / 99.99%; singleton timing remains mixed.

## Build audit and reproduction

The first socket series was **discarded** before publication. Its candidate CLI
was copied from `cargo test --release`, which unified transitive development
features differently from the baseline production build. No speed or regression
conclusions from that series are retained. Native profiling and accounting audits
already used matching production dependencies and remain valid.

All results above use fresh, matching `cargo build --release --locked` binaries.
`check-release-inputs.py` rejects differing compiler/profile/flags/features or
dependency fingerprints (including transitive inputs). The comparison runner
also verifies the immutable binary hashes from that manifest. The guard was
checked against both the known mismatched pair (rejected) and corrected pair.

Baseline shb: `3c3638c4cc96bf62d901f3561ef2f3845d2db011`.
Fixed hfast: `30b137401746eab4fc9670550e143ce313e489b2`.
Compiler: rustc 1.98.0 (88d9e12ae), locked release profile, full LTO,
one codegen unit, mimalloc, `CARGO_INCREMENTAL=0`, isolated target directories.
WSL2 kernel 6.18.40.1; client CPU 2, fixed peer CPUs 0,1.

Build each production client with `cargo build --release --locked` in a separate
clean target directory, then copy its binary to an immutable path. Do not reuse
the production target for `cargo test`. From the candidate source directory:

```sh
python3 benchmarks/check-release-inputs.py /path/to/baseline-target/release \
  /path/to/candidate-target/release /tmp/h3-inputs.json

# A separate target supplies the fixed peer's independent protocol libraries.
CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/h3-peer-target \
  cargo test --release --locked --no-run
python3 benchmarks/build-h3-timeout-peer.py /tmp/h3-peer-target/release \
  benchmarks/h3-timeout-peer.rs /tmp/h3-peer /tmp/h3-peer-build.json

python3 benchmarks/compare-h3-timeout.py \
  --baseline /path/to/baseline-shb --candidate /path/to/candidate-shb \
  --hfast /path/to/fixed-hfast --peer /tmp/h3-peer --output /path/to/results \
  --build-manifest /tmp/h3-inputs.json --mode held --held-counts 262144 \
  --cases c1-p128-n262144-t1 --prefix large --phase primary
```

Repeat with `--phase confirmation`. Use `--mode direct` for the fixed-hfast
matrix and `--mode held` without case selection for smaller held cases and
the timeout-off control. Output files are created exclusively.

Original local `c92-v2-*` files preserve corrected raw reports and manifests;
`c92-feature-mismatch-invalidation.json` identifies every discarded timing series.
All failed fixture/harness setup attempts, scripts, immutable binaries and source
snapshots are retained locally. Large raw artifacts are not committed.
