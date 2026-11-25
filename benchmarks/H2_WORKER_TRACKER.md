# Experimental H2 worker request tracker

**Status: AWAITING_PERFORMANCE_VALIDATION. No verified throughput improvement.**

A peer that holds the oldest response open makes the existing worker ring retain
one slot for every subsequent request. This experiment keeps that ring for dense
traffic, switches worker accounting to an ordered map beyond twice peak concurrency,
and recovers dense storage after the live window drains. The protocol engine and
shared H2/H3 rings are unchanged; total connection memory is not bounded by this patch.

The policy follows hatoo/xdp-http `src/http2/streams.rs` at b4e6075.

Complete tracker cycles at width 32 and 100,000 pinned cohorts (3,100,001 requests)
reduce peak requested allocation from 100,663,296 to 1,816 bytes. System allocator
counters exclude allocator metadata and are not process RSS. Allocation calls rise
from 21 to 399,998. Exact resource and instruction counts reproduce in reverse order.

| Standalone workload (width 32) | Baseline Ir | Candidate Ir | Change |
| --- | ---: | ---: | ---: |
| Dense sliding, 1000 cohorts | 4,313,065 | 6,364,588 | +47.565% |
| Pinned oldest, 1000 cohorts | 3,390,692 | 18,827,730 | +455.277% |
| Four pinned then 1000 dense | 3,566,317 | 5,616,191 | +57.479% |

These are whole-process Callgrind counts for the source-bound tracker driver,
including assertions and complete construction/destruction, not client throughput.

Native measurements compare immutable own-shb baseline d29fae1 (binary 76a2ffec)
to this candidate (157c2e2d), with fixed hfast 18bec9f1 or qualified C451 drain
peer ae99b382 and xdp 34636e47. H2 64 connections/32 streams, 13-byte GET /, no extra headers, linger 1,
five seconds, 1/2 workers, AB/BA/AB plus warmups. Eight fixed server workers on
0,2,4,6,8,10,12,14; client 17/19 on disjoint physical cores. Fresh namespaces,
WSL/veth SKB/copy, offloads off, queues=workers; no simultaneous compilation.
RPS includes startup/final drain; client CPU excludes some server/softirq work.

| Workload | Workers | Median paired shb RPS | Fixed xdp control |
| --- | ---: | ---: | ---: |
| Ordinary | 1 | +2.972% | -6.189% |
| Ordinary | 2 | +10.915% | -2.866% |
| C451 held/drained | 1 | -3.304% | -3.385% |
| C451 held/drained | 2 | -0.589% | -7.274% |

All 96 trials reconcile 510,742,948 shb and 588,174,921 xdp explicit latency samples
with zero unexpected errors/connect errors or dispatch drops. Pair directions
are mixed. Ordinary 2-worker pair 1 has a +133.960% outlier; held 1-worker pair 3 has
a +60.436% outlier. Every adverse control/latency result is retained. No gain is
accepted, no reverse confirmation or A/A/affinity retry was attempted. Native
continuously-pinned throughput and whole-client RSS were not measured.

Correctness: 642 active unit tests and 70 distinct e2e cases pass across debug and
release runs; two opt-in external QUIC tests remain ignored. Rust 1.91.0 unit
tests and production Clippy pass; stable all-target strict Clippy and fmt pass.
New independent cleartext/TLS timeout cases force sparse storage and reconcile
512 requests, 480 successes/samples, 32 expected timeouts, then reconnect. New unit
tests cover ownership, oldest timestamps, duplicates, resets/refusals/GOAWAY,
clear/recovery, near-limit IDs and randomized ordered ledgers.

Local raw evidence and reproducible drivers are retained under
`shb/optimization-results/c452-h2-worker-tracker-20261125/`; native runner outputs
are under `xdp-http/benchmark-results/c452-h2-{dense,primary}-p*-*/`.
The next experiment should remove sparse allocation churn and dense dispatch
overhead before another native campaign. Do not rerun this unchanged candidate.
