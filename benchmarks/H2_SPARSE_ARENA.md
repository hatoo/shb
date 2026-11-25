# Experimental H2 worker sparse arena (C453)

**AWAITING_PERFORMANCE_VALIDATION.** This candidate eliminates the C452 sparse
tracker's allocation churn. Native comparisons do not establish a throughput
gain, so it is preserved without a performance PR.

## Change

The HTTP/2 worker keeps its positional ring for ordinary traffic. After the
retained ID span exceeds twice observed peak concurrency, live requests move
to reusable arena slots indexed by a standard HashMap. Insertion-order links
preserve constant-time oldest-timeout lookup; a free list recycles retired slots.
Only empty sparse windows recover dense storage. IDs arrive monotonically from
the protocol engine. No timestamps or samples are coalesced or omitted.

The dense/sparse policy derives from xdp-http `b4e6075`. This reimplements C452
`fafed64` on current shb default `d29fae1`; neither experimental branch is a
performance baseline for the native comparison. Protocol and H3 rings, Cargo
settings, parsing, and statistics processing are unchanged.

## Correctness

- Debug and release: **643 unit tests and 70 end-to-end tests pass per profile**.
  Two existing opt-in external QUIC tests remain ignored, not passed.
- Rust 1.91: all 643 active unit tests and production strict Clippy pass.
- Stable all-target strict Clippy and formatting pass. The initial lint error
  was a new test's map-key iteration; it was fixed and all six tracker tests
  rerun. Earlier passing release/MSRV production source remains identical.
- Independent ordered-map, exact drop, and free/live-list ledgers cover arbitrary
  completion order, stale/reused slots, arena/index growth, pinned cohorts,
  near-limit IDs, clear/recovery, and reconnects. Worker tests preserve timeout
  boundaries, status-before-END semantics, resets, refusals and GOAWAY budgets.
- Independent cleartext/TLS wire peers force sparse tracking, then timeout and
  reconnect: each new case reconciles 512 requests, 480 successes/latency samples,
  32 expected request errors, and no connect errors. Existing H1/H2/H3 cases,
  including large/fragmented messages, QUIC loss/reordering and generations, pass.

## Resource evidence

Source-bound standalone complete construction/promotion/lookup/retirement/drop
cycles: 54 resource processes and 36 Callgrind processes in alternating/reverse
orders, Rust 1.100.0, opt-level 3, fat LTO, one codegen unit. All request counts,
original timestamps, status checks and final sums agree. The harness uses a
16-byte request value and System allocator, not the application's default
mimalloc; instruction totals include the full harness and teardown. These are
tracker measurements, not application CPU, total RSS, or RPS claims.

At width 32 and 100,000 younger cohorts behind one held request:

| Tracker | Allocation calls | Peak requested bytes | Retained after empty |
| --- | ---: | ---: | ---: |
| Original | 21 | 100,663,296 | 100,663,296 |
| C452 BTreeMap | 399,998 | 1,816 | 280 |
| C453 arena | 7 | 5,008 | 3,472 |

C453 also makes 7 calls at 1,000 cohorts, and **zero calls after the first ten
cohorts**. Width 2/128 pinned runs likewise have zero warmed calls (3/9 total).
At width 2, C452 needs only 2 calls. Ordinary width-32 allocation counts remain
6 for all variants. Recovery calls are original/C452/C453 = 6/18/11.

| Complete cycle | C453 Ir vs original | C453 Ir vs C452 |
| --- | ---: | ---: |
| Dense, 1,000 cohorts | +35.683% | -8.053% |
| Pinned, 1,000 cohorts | +408.740% | -8.373% |
| Pinned, 100,000 cohorts | +472.620% | -8.516% |
| Recovery, 1,000 cohorts | +50.095% | -4.689% |

Three independent instruction runs retain randomized standard HashMap seeding;
small instruction variation is recorded, not treated as exact equality. Original
and C452 totals reproduce exactly. Reduced churn does not remove the remaining
lookup and dense-mode overhead, and arena peak storage exceeds C452's tree.

## Native comparison

96 trials: 48 measured and 48 separate one-second warmups. Three AB/BA/AB pairs
per workload, fixed 5-second runs, own-original shb baseline. HTTP/2 prior
knowledge, GET `/`, 13-byte body, no custom headers, 64 connections, 32 streams,
batch linger 1, one/two client workers. Fixed hfast ordinary peer or qualified
C451 hold/SETTINGS0/full-drain/PING peer, and a fixed accepted xdp client control.

Fresh namespaces per trial; WSL2/veth generic SKB/copy, offloads off. Physical
client CPUs 17/19 (cores 8/9), eight server workers on 0,2,...14 (cores 0–7).
CPU pools are disjoint; no compilation or competing benchmark during timing.
The installed comparison runner accepts explicit frozen binary paths; its
shared scripts/configuration and main-checkout binaries are unchanged. Its smoke
command is tied to the main checkout and was not used as candidate proof.

Median of three paired RPS changes, not a statistical significance claim:

| Workload | shb 1 worker | shb 2 workers | fixed xdp 1 worker | fixed xdp 2 workers |
| --- | ---: | ---: | ---: | ---: |
| Ordinary | +4.174% | -0.726% | +0.119% | -0.359% |
| C451 sparse/drain | +0.340% | -1.438% | +6.432% | -0.992% |

All three two-worker sparse/drain pairs are negative (-4.148/-1.438/-0.461%);
the one-worker pairs range from -4.673% to +11.430%. Fixed-control outliers and
all adverse results remain in the evidence. No gain or confirmed regression is
claimed; no unchanged confirmation, identical-binary or affinity campaign followed.
The C451 peer drains its short initial sparse phase; this is not a sustained
sparse-throughput or whole-process-memory experiment.

All **520,286,268 shb and 606,100,820 xdp** explicit latency samples reconcile
with successful requests and status totals, including final drains. Zero
unexpected request/connect errors or dispatch drops. Expected negative
correctness-test errors are separate from these benchmark counters. Client CPU
excludes some softirq and server work. No physical-NIC, hardware-zero-copy,
H1 or H3 gain is claimed.

Frozen SHA-256 prefixes: shb original `76a2ffec0211`, candidate `04676291424c`,
xdp `34636e4705b4`, hfast ordinary `18bec9f1bd10`, C451 peer `ae99b38266ce`.
Full source, binary, compiler and runner bindings plus commands, per-trial
latency/tail/CPU data, resource sources and raw evidence are preserved under
`optimization-results/c453-h2-sparse-arena-20261125/` in the shared shb checkout.
Native output is under `xdp-http/benchmark-results/c453-h2-*`.

Next: a worker-only dense tail with sparse pinned outliers, allowing younger
requests to keep direct ring lookup. Require independent ownership/timeout and
multi-pin lifecycle tests, bounded allocation counts and materially lower
original-relative full-cycle costs before another native comparison. The exact
implementation and validation plan is in the experiment's `next-task.md`.
