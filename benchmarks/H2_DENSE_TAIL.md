# H2 dense tail and sparse old pins (C454)

**AWAITING_PERFORMANCE_VALIDATION.** Native results are inconclusive. This branch is based on
shb default `d29fae1`, independently of the experimental C452/C453 branches.

## Change

The H2 worker always retains its positional ring for newer requests. Only an
oldest live prefix spills into a reusable sparse arena when the retained span
reaches a concurrency-derived bound. A stream-ID boundary routes newer responses
directly to the ring; old spilled requests use the existing standard HashMap and
insertion-order links. Removing the oldest pin does not change any timestamp.

Span-pressure checks update the bound only when needed, and spilling frees at
least half the dense span. Both stores reuse capacity after empty windows. The
bound depends on observed peak concurrency, not the number of requests issued
behind an old pin. The bounded-span idea follows xdp-http `b4e6075`; this variant
keeps the dense tail alive while old sparse requests remain outstanding.

Only worker request tracking changes. Shared protocol/H3 positional rings, HTTP
parsing, start times, completion/error accounting, all latency samples, Cargo
settings and default mimalloc remain unchanged. Worker-only memory savings must
not be described as whole-client RSS savings: protocol and latency storage still
contribute to the process footprint.

## Correctness

Debug/release each pass 645 active unit tests and 70 end-to-end cases. Two opt-in
external QUIC unit tests remain ignored. Rust 1.91 runs all active unit tests and
production strict Clippy; stable all-target strict Clippy and fmt also pass.

Eight tracker tests compare independent ordered and ownership/drop ledgers,
covering multiple pins, sparse/dense interleaving, arbitrary unlinks and reuse,
stale/invalid IDs, long churn, all-spilled/empty transitions, near-limit stream
IDs, and clear/reconnect. Worker tests retain exact timeout boundaries, status
until END, duplicate completion, reset/refusal/GOAWAY and budget accounting.
Independent cleartext/TLS sparse wire cases each reconcile 512 issued requests,
480 successes and latency samples, 32 expected timeout errors, zero connect
errors, and socket retirement before reconnect. Existing H1/H2/H3 interoperability,
partial/large/fragmented messages and recovery cases pass against the candidate.
The initial test-only reverse-range compile error was fixed before the full suites;
its original failure log is retained.

## Deterministic resource comparison

108 allocation and 108 Callgrind processes, three alternating/reverse repetitions,
plus the retained 16-process initial screen. One identical source-bound driver
executes complete construction/insertion/status/oldest/retirement/drop cycles
for original, C452, C453 and C454. Rust 1.100.0, opt-level 3, fat LTO, one codegen
unit. Widths 2/32/128 and 1,000/100,000 pinned cohorts, plus width32 ordinary,
recovery and rotating-multiple-pin guards. All request counts, original start
values, status checks and final sum ledgers agree across all variants/runs.

The allocation probe uses System with a 16-byte request value, not application
mimalloc. Instruction totals include the whole driver and teardown; randomized
standard HashMap seed variation is retained. Driver/code shape affects totals,
so no application CPU or native RPS gain is inferred from these measurements.

Width32 and 100,000 younger cohorts behind one held request:

| Tracker | Allocation calls | Peak requested bytes | Retained after empty |
| --- | ---: | ---: | ---: |
| Original | 21 | 100,663,296 | 100,663,296 |
| C452 ordered tree | 399,998 | 1,816 | 280 |
| C453 sparse arena | 7 | 5,008 | 3,472 |
| C454 dense tail | 8 | 3,316 | 3,316 |

C454 allocation counts and requested peak bytes are identical at 1,000 and
100,000 cohorts: width2 3 calls/340 bytes, width32 8/3,316, width128 9/6,388.
All pinned cases allocate zero times after the first ten cohorts. Ordinary
width32 stays at 6 calls/3,072 bytes for all variants. Recovery uses 8 calls
versus original6/C45218/C45311; rotating pins use 11 versus original11/C4523998/
C4537. Retaining both stores costs more than the ordered tree in some cases.

| Full cycle | C454 Ir vs original | C454 Ir vs C453 |
| --- | ---: | ---: |
| pinned, width2, 1,000 cohorts | +11.588% | -42.428% |
| pinned, width2, 100,000 cohorts | +36.611% | -67.313% |
| pinned, width32, 1,000 cohorts | +37.518% | -72.722% |
| pinned, width32, 100,000 cohorts | +46.098% | -74.218% |
| pinned, width128, 1,000 cohorts | +43.909% | -74.037% |
| pinned, width128, 100,000 cohorts | +46.262% | -74.569% |
| dense, width32, 1,000 cohorts | +30.968% | -4.905% |
| recovery, width32, 1,000 cohorts | +39.571% | -7.057% |
| multipin, width32, 1,000 cohorts | +16.074% | -71.275% |

The dense tail removes most of C453's sparse-request instruction cost, but all
measured C454 cycles still cost more instructions than the original unbounded
tracker. The initial source annotation also shows a different driver insertion
code shape; no compiler-hint or hasher campaign was performed.

## Native comparison and decision

120 uninstrumented native trials: 60 measured and 60 separate one-second warmups.
The initial matrix uses three AB/BA/AB pairs at one/two workers for ordinary H2
and C451's hold/drain fixture. One independent BA/AB/BA confirmation targets only
the two-worker drain case because all three initial pairs were slower. No further
native comparison, identical-binary retry or CPU-affinity sweep followed.

Own-original shb baseline, fixed hfast ordinary/C451 peers and fixed accepted
xdp control. H2 cleartext GET `/`, 13-byte body, no custom headers, c64/p32,
linger1, five-second measured runs. Fresh namespaces, WSL2/veth SKB/copy,
offloads disabled, 1/2 queues, physical client CPUs17/19 (cores8/9), eight server
workers on0,2,...14 (cores0-7). CPU pools are disjoint. No compilation or competing
benchmark ran during timing; CPU/affinity/commands and hashes are retained.
The installed runner uses explicit frozen paths; its scripts/config are unchanged.
Its main-checkout Git metadata does not identify these binaries: binding.json and
per-trial executed paths/SHA-256 identify the candidate and fixed components.

Median paired RPS changes (not statistical significance claims):

| Workload | shb 1 worker | shb 2 workers | fixed xdp 1 worker | fixed xdp 2 workers |
| --- | ---: | ---: | ---: | ---: |
| Ordinary | +3.327% | -2.740% | -2.389% | -0.452% |
| C451 initial hold/drain | -1.265% | -4.636% | -1.431% | +0.791% |

The initial two-worker drain shb pairs were -5.642/-4.636/-1.232%, while the
fixed xdp pairs were +2.740/-0.029/+0.791%. The one permitted focused reverse
confirmation produced shb -18.012/+176.012/+5.309%, and fixed xdp
+2.564/-3.932/-16.304%. The +176% pair contains a much slower original-binary
trial; it is retained and is not evidence of a gain. The median of each variant's
RPS also differs from the median paired change; all raw values remain available.
Neither a throughput improvement nor a confirmed regression is established.
The environment is unsuitable for accepting a small effect from these results.

All **640,333,604 shb and 754,082,940 xdp** explicit latency samples
reconcile with successful requests, statuses and final drains. Zero unexpected
request/connect errors or dispatch drops; 17,378,311 forwarded packets are
accounted. Negative correctness cases' expected errors are separate. Client CPU
excludes some server/softirq work; no physical-NIC or hardware-zero-copy claim.

C451 holds briefly and then drains; these trials do not measure sustained sparse
throughput or whole-process memory. The verified result is bounded worker memory
and substantially lower tracker instruction cost than C453, with remaining
original-relative overhead. The candidate stays experimental and has no PR,
auto-merge, or merge. Branch-only pushes do not trigger shb's master/PR CI.

Frozen SHA-256 prefixes: original `76a2ffec0211`, candidate `99ea8e9eba70`, xdp
`34636e4705b4`, hfast ordinary `18bec9f1bd10`, C451 peer `ae99b38266ce`.
Full source/compiler/runner/topology binding, tests, resource probe sources,
all raw results and audit scripts are in
`optimization-results/c454-h2-dense-tail-20261125/` in the shared shb checkout.
Native output is `xdp-http/benchmark-results/c454-h2-*` in the shared workspace.

Next: qualify a bounded, timer-released persistent-pin hfast test peer, then test
C454 against its frozen original under sustained sparse traffic with exact drain
and sample accounting. No unchanged ordinary/C451 retiming. Full requirements,
independent interoperability cases and CPU/memory/throughput gates are in the
experiment's `next-task.md`. This fixture is currently missing; C451 does not
supply the sustained exposure required for acceptance.
