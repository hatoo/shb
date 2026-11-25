# Bounded H2 worker tracking behind old responses

**AWAITING_PERFORMANCE_VALIDATION.** This experimental candidate bounds worker
request storage; no end-to-end throughput gain is accepted. C457 places the C454
tracker on the merged bounded-drain baseline `449c547`. The original C454
`0fa4e2f` branch remains unchanged.

## Implementation

New requests keep direct positional lookup in the existing dense ring. Under
span pressure, only the oldest live prefix spills to a reusable sparse arena.
A stream-ID boundary selects the ring or sparse index. The insertion-order links
keep oldest-request timeout checks constant-time without scanning a hash map.
Storage depends on observed peak concurrency rather than the lifetime of an old
response. Empty stores reuse capacity. Original timestamps and status values move
with their requests; completion/error and latency accounting remain unchanged.

The bounded-span idea follows xdp-http `b4e6075`; attribution is retained in
`src/http2/streams.rs`. The protocol engine, H3 positional rings, flow control,
compiler settings and default mimalloc are unchanged. Worker memory is only part
of process memory: protocol storage, latency samples and allocator retention
remain present.

## Correctness on the merged predecessor

- Debug and release: 652 active unit and 80 end-to-end tests per profile pass;
  two existing opt-in external QUIC unit tests remain ignored.
- Rust 1.91: all 652 active unit tests and strict production Clippy pass.
  Stable formatting and strict all-target Clippy pass.
- Independent ordered/drop ledgers cover dense/sparse transitions, long pinned
  churn, arbitrary removal, duplicates/invalid IDs, near-limit IDs and reconnect.
  Sparse timeout wire tests preserve exact counts over cleartext and TLS.
- Two new worker regressions cover sparse/dense duration drain, unprocessed
  requests after issuing stops, duplicate events, exact original timestamps,
  bounded expiry and preservation of active kernel-owned send storage.
- Independent hyper-h2: baseline 3,466 and candidate 2,986 exact samples; each
  binary passes one/two workers with all eight connection PING acknowledgments.
- Fixed traced C455 peer: eight cleartext/TLS and one/two-worker cases total
  2,061,007 exact samples, all 32 peer-close ledgers matching with no pending work.
- Separate namespace correctness runs: 25,166,338 shb and 25,979,568 fixed xdp
  samples, zero errors/drops, all 512 shb close ledgers exact. Traced timings are
  excluded from performance evidence. Xdp client counts are exact; its final
  server fence logs can race teardown.

## Matched native comparison

Fresh WSL2/veth namespaces, generic/SKB XDP and copy mode, offloads disabled;
cleartext H2 GET `/`, 13-byte responses, 64 connections, 32 streams, linger 1 us.
Both shb variants use five-second issuing plus `--drain-timeout 3s`, with the same
merged drain implementation. RPS includes final drain. Client physical CPUs
17/19 (cores 8/9), eight fixed server workers on 0,2,...14 (cores 0–7), one/two
queues and recorded cross-worker forwarding. No simultaneous compilation or
other benchmark workload ran during timing.

Immutable shb baseline/candidate, fixed untraced C455 peer and fixed accepted xdp
control. Initial AB/BA/AB at one/two workers; exactly one independent BA/AB/BA
confirmation at one worker. Every measured trial has a separate one-second
warmup. No A/A retries, affinity sweep or further timing campaign.

| Campaign | Workers | Median paired shb RPS | Fixed xdp RPS | Peak shb RSS |
| --- | ---: | ---: | ---: | ---: |
| Primary | 1 | +3.339% | -1.937% | -28.151% |
| Primary | 2 | +1.929% | +0.360% | -24.779% |
| Confirmation | 1 | +8.717% | +3.040% | -25.448% |

Primary shb changes are +3.339/-2.568/+3.470% with one worker and
+6.149/+1.929/-0.699% with two. One-worker confirmation is
+5.058/+8.717/+9.404%; its fixed-control changes are +7.564/+0.741/+3.040%.
All observations, including slower baseline trials, are retained. These limited
runs show a positive signal, but control variation is comparable to the assessed
effect; they do not establish a gain beyond measurement uncertainty. Percentages
are descriptive engineering results, not statistical-significance claims.

Whole-process peak RSS is lower in all nine paired comparisons. Primary medians
are 417,088 -> 300,504 KiB at one worker and 786,504 -> 590,088 KiB at two;
confirmation 403,196 -> 298,428 KiB. These are matched-duration workloads, so
completed request counts differ. `/usr/bin/time` obtains child peak RSS through
wait accounting without sampling/instrumenting the request path; its common
wrapper overhead is outside the client's reported RPS interval.

All 72 timing/warmup trials reconcile 316,827,028 shb and 330,850,085 fixed xdp
samples with zero unexpected errors/drops. All final issued work is accounted by
the qualified bounded-drain implementation. Explicit samples, commands, worker
placement, binary hashes and raw control results are retained. No physical-NIC
or hardware-zero-copy result is implied; client CPU excludes some server/softirq
work. The runner's main-checkout Git metadata is not the executed binary identity.

## Historical resource evidence and remaining gate

C454's unchanged worker tracker measured 3,316 peak requested bytes versus
100,663,296 for the original at width32/100,000 pinned cohorts, zero warmed
allocations; its full-cycle instruction count remained +46.098% versus original.
Those are historical System-allocator microbenchmarks, not new application gains.
C455's fixed-count process RSS reductions were 35–41%. Old duration measurements
without bounded draining were later found to truncate live responses; equal
reported completions/samples did not prove full drain. They are not acceptance
evidence here.

Frozen SHA-256 prefixes: merged baseline `0dc7dbbe48b4`, candidate `080be183c2ee`,
fixed untraced peer `42eded421079`, fixed xdp `34636e4705b4`. The reused baseline
source tree exactly equals merged `449c547` and uses the same Rust 1.100.0/default
release settings. Full evidence lives in shared
`shb/optimization-results/c457-h2-drained-tail-20261125/`; raw namespace results
are `xdp-http/benchmark-results/c457-h2-*`.

No performance PR or auto-merge is requested. Preserve this candidate until a
materially more stable environment can confirm a full-drain effect beyond
uncertainty with ordinary and multiworker guards. Do not repeat these unchanged
WSL comparisons. The next independent implementation targets xdp-http QUIC
receive-prefix retirement, recorded in this experiment's `next-task.md`.
