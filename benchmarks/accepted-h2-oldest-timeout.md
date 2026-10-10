# HTTP/2 oldest-live timeout check (c91)

With `--timeout` enabled, each completion batch scanned every live request and
every hole behind a delayed request, even when no request had expired. Requests
receive their immutable start timestamps in stream-ID order. The in-flight ring
keeps the oldest live request at slot zero through removal and compaction, so
checking that entry suffices. The idle/held-request branch, `>=` boundary,
polling point, request accounting and latency collection retain their behavior.

Baseline: shb `b9179e0cd3612be3edcfd7528219fb75e54b09d3`.
Fixed server: hfast `30b137401746eab4fc9670550e143ce313e489b2`.
Both clients were freshly built with Rust 1.98.0, release fat LTO, one codegen
unit, default mimalloc, and separate target directories (`CARGO_INCREMENTAL=0`).
Measurements use immutable copies, Linux 6.18.40.1 under WSL2, one client worker
on CPU 2, one hfast worker on CPU 0, and the optional relay on CPU 3.

Each case has three alternating baseline/candidate pairs, then three more with
reversed order. Every process has an 8,192-request warmup. Accepted cases use
`--http2 --timeout 10s -t 1`; all six paired changes are positive in each case.

| Workload | Primary median RPS change | Reversed median RPS change | Complete client CPU change, primary/reversed |
| --- | ---: | ---: | ---: |
| Direct hfast, 16 connections, 128 streams each, 4,194,304 requests | +5.018% | +4.843% | -4.370% / -5.572% |
| One connection, 128 streams, first response held until all 131,072 replies arrive | +13.120% | +10.203% | -39.835% / -37.658% |

Direct paired RPS changes: `+5.018, +4.213, +5.120, +4.843, +3.114, +5.485%`.
Held-response changes: `+7.652, +13.120, +19.495, +10.755, +5.421, +10.203%`.
The relay forwards hfast frames unchanged except delaying stream 1; it delivers
that response at the end too. Reported throughput and all request latencies
include setup and the held response's wait. Complete process CPU also includes
JSON reporting; shb's own throughput timer ends before reporting, as before.

Other results do not establish a general speedup or equivalence:

| Case | Primary / reversed median RPS change |
| --- | ---: |
| Direct 1 connection / 1 stream, timeout enabled | -2.331% / -0.181% |
| Direct 1 / 4096, timeout enabled | +0.820% / +2.146% |
| Direct 1 / 1, timeout disabled | +1.697% / -0.581% |
| Direct 1 / 4096, timeout disabled | +1.240% / -1.265% |
| Held first response, 16,384 requests | +1.161% / +3.595%, mixed pair signs |
| Held first response, 65,536 requests | +6.695% / +4.778%, all positive but wider scatter |

Direct single-connection parallelism 64/128 produced only +0.602%/+0.435% in
the first series and was not repeated. The 65,536-request held case also has
consistent CPU reductions (-17.869%/-20.733%), but the two larger effects above
are the acceptance scope. The singleton's initial slowdown did not reproduce at
that magnitude. No identical-binary retries, affinity sweeps, or lowered threshold.

Across the final benchmark and warmup runs: **206,340,096 successful requests,
zero unexpected errors**, with exact totals/status counts and latency reports.
Separate instrumented binaries assert one latency sample per successful response
for ordinary, delayed TCP/TLS, held-response, duration, and independent Caddy TLS
workloads. They are not used for performance claims. Intentionally timed-out and
refused requests are checked separately. A preliminary Caddy audit used a stale
port; its connection errors were retained, and the unfinished check was rerun
against the verified live listener.

Three independent native count/Callgrind pairs using the production predicate:

| Nonexpired ring | Baseline slot reads / instructions | Candidate slot reads / instructions |
| --- | ---: | ---: |
| 1 live request | 1 / 71 | 1 / 52 |
| 64 live requests | 64 / 2,591 | 1 / 52 |
| 128 live requests | 128 / 5,151 | 1 / 52 |
| 4,096 live requests | 4,096 / 163,871 | 1 / 52 |
| 65,536 slots, two live requests | 65,536 / 327,781 | 1 / 52 |

Already-expired checks still read one request. Native nonexpired 4,096-stream
predicate CPU fell 99.956%/99.957% in alternating/reversed series; this is a
predicate-only result. Connection size remains 1,416 bytes, `InFlight` 16 bytes,
and the check allocates nothing. Native singleton/expired timings are noisy.
No latency timestamps are cached, rounded, skipped, or reassigned.

Correctness: 337 unit tests and 55 end-to-end tests pass in debug and release
(two pre-existing ignored tests); strict all-target Clippy and formatting pass.
Rust 1.91 passes 58 HTTP/2 unit tests and both new TCP/TLS wire tests. New tests
cover equal starts and the exact timeout boundary, holes and repeated compaction,
idle/held requests, resets/refusals/GOAWAY, and 32,768 seeded transitions against
a full-scan model. Each wire test verifies 384 successes, 128 intentional timeout
errors, and a successful replacement connection. The fixture accepts replacement
connections concurrently because an outstanding io_uring receive can retain the
old socket until ring teardown.

Reproduce with fresh immutable release binaries (choose available CPU IDs):

```sh
python3 benchmarks/compare-h2-timeout.py \
  --baseline /absolute/shb-baseline --candidate /absolute/shb-candidate \
  --hfast /absolute/hfast-fixed --output /new/results \
  --phase primary --mode direct
python3 benchmarks/compare-h2-timeout.py \
  --baseline /absolute/shb-baseline --candidate /absolute/shb-candidate \
  --hfast /absolute/hfast-fixed --output /new/results \
  --phase confirmation --mode direct \
  --case c1-p1-n65536-t1 --case c1-p4096-n4194304-t1 \
  --case c16-p128-n4194304-t1 --case c1-p1-n65536-t0 \
  --case c1-p4096-n4194304-t0
# Run each phase again with --mode held and without --case filters.
```

The script creates every result exclusively. Detailed local evidence is indexed
in `optimization-results/c91-record.md`, `c91-performance-final.json`, and the
immutable c91 reproducibility archive; raw measurements are not committed.
