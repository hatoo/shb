# HTTP/1 close-after-one receives (c321)

A lifetime multishot receive outlives an ordinary complete response, so HTTP/1
retirement must synchronously cancel it before unregistering its fixed file and
closing the socket. Plain `--disable-keepalive` now selects a single-shot receive
from the same provided-buffer pool. Incomplete responses rearm it. A consumed
successful Connect CQE, terminal receive, and completed send prove when retirement
can skip publication/cancellation; pending I/O and all TLS/keepalive connections
retain the existing barrier. File unregistration, byte counts and latency clocks
are unchanged.

The test suite covers queued and submitted I/O, pending connects and linked
timeouts, early responses during partial uploads, buffer exhaustion/recycling,
slot reuse and stale generations, fragments, chunked/HEAD/EOF bodies, request
timeouts and teardown. Removing the live-receive condition from the compiled
candidate fails the queued/submitted retirement regression.

## Reproduction

The independent peer is `benchmarks/h1-close-peer.py`. It binds CPU 1, sends an
exact 65,537-byte body after each request, and verifies the client closes that
socket before accepting the next. Its final ledger verifies all requests,
connections and wire bytes. This models a sequential server that releases each
completed connection before servicing its replacement. It is not a measurement
of hfast's response throughput.

Use immutable release client binaries built with the same compiler, dependencies
and flags. Measurements used Rust 1.99.1, default mimalloc, fat LTO and one codegen
unit, baseline master `5e8827a53e1011417d3073f77e47922a895191c5`, WSL2/Linux,
client CPU 8 and peer CPU 1. The kernel ephemeral-port range was 32768–60999,
TCP TIME_WAIT reuse was 2 and its reuse delay 1000 ms. Do not change these between
variants. The source peer is AST-identical to the measured script.

The runner selects a fresh unused five-digit destination port for every trial,
checks `/proc/net/tcp` for existing entries, and never reuses a selected port.
Request and response sizes remain identical. An initial shared-port series gave
+20.12% primary and +20.60% confirmation, but one identical-binary control differed
by +7.64%. That series was excluded from acceptance. Fresh ports were the single
targeted methodology adjustment; the cause of the earlier variation is unproven.

Run the published harness with a new output directory:

```sh
python3 benchmarks/compare-h1-close.py \
  --baseline /path/to/immutable/shb-baseline \
  --candidate /path/to/immutable/shb-candidate \
  --output /path/to/new/results
```

The harness saves both native reports, the server wire ledger, CPU usage, commands,
monotonic intervals and port preflight checks for each trial. It runs two
identical-baseline control pairs first, then four alternating candidate pairs,
then three reversed confirmation pairs. Every trial uses an 8192-request warmup
and 131072 measured requests, one connection/worker, `--batch-size 1`,
`--disable-keepalive`, and a ten-second response timeout. Each request sends 60
bytes and receives 65579 bytes. The peer independently checks all 139264 requests
and closes; every native report must have exactly one latency sample per request.

Preset gates require zero errors, a median improvement above 3% with every
candidate comparison positive, and identical controls within 1.5% median/3%
maximum. A failed gate remains experimental. Retain CPU usage and tail latency;
a throughput increase need not imply a comparable CPU reduction. The published
benchmark and validation functions are AST-identical to those measured; only
CLI paths and the failure wording were generalized.

## Verified result

Accepted for the workload above; CI remains the correctness gate before merging.

| Series | Per-pair throughput changes | Median |
|---|---|---|
| Primary | +21.930%, +21.686%, +20.001%, +19.779% | +20.844% |
| Independent confirmation | +20.182%, +25.464%, +20.530% | +20.530% |
| Identical baseline controls | +0.453%, -0.120% | +0.166% |

All 36 warmup/measured reports and their independent peer ledgers account for
2,506,752 complete requests and latency samples, with zero errors. Primary client
CPU/request changed by a median -2.74%; confirmation by -2.49%. Measured p99.9
latency decreased in every accepted comparison; this does not establish tail
neutrality for other workloads. The immutable candidate SHA256 is
`4e3991a703eed26c9fb7abc785c3974bfac1aed70d8991254fbd683073d671f9`.

Correctness validation: 667 passing Rust tests in each of debug/release, two
pre-existing external-server tests ignored, 65 focused HTTP/1 tests/profile after
the test-fixture refinement, strict all-target Clippy, fmt, Rust 1.91 all-target
checks and 65 focused MSRV tests, 18 independent Python/OpenSSL scenarios, 11
existing cohort tests, four accounting/qualification guard tests, and one caught
compiled live-receive-barrier mutant. The fixture refinement only drains a
linked timeout CQE before a subsequent receive assertion; runtime source and the
measured binary were unchanged.

## Scope and costs

The original fixed-hfast small-response experiment remains below the engineering
threshold: four pairs +0.519/+0.316/+0.625/+0.726%, median +0.572%. Those runs used
two client producers, each CPU8/9,c64,t1,n262144,warmup65536,batch1, against one
unchanged hfast worker on CPU1. All ten qualification/primary runs had both
clients above 0.85 active core and the server below 0.80 core. No small-response
throughput gain is claimed.

Count-only traces for 1024 small responses showed 1024 ->0 synchronous
cancellations, identical 4096 submitted SQEs, and unchanged 2048 fixed-file
updates. Keepalive retained 16 cancellations for 1024 requests/c16. Timing under
strace was excluded. For six deliberately fragmented responses, receive SQEs
increased from 6 to36; for six 65,537-byte bodies, 6 to30. These receive counts
are inferred from total submitted SQEs minus the known Connect/LinkTimeout/small
Send per request.

Two reversed cost-screening pairs gave ordinary serial H1 -0.39/-0.67%,
concurrent H1 +0.76/-0.74%, fragmented churn -0.12/-0.25%, TLS keepalive
-1.17/-3.08%, and TLS churn -0.28/-1.80%. Several p99.9 costs increased, including
TLS churn +16.97/+15.64%. These short screenings do not establish equivalence,
a general regression, or latency neutrality. The implementation is scoped to
plain close-after-one connections; verify the workload of interest before using
this as evidence of a broader throughput benefit.
