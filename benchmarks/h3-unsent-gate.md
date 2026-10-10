# HTTP/3 empty request flush: c93

`flush_unsent` used to scan every retained request slot on every drive, even
when QUIC had already accepted every request byte. A held early response keeps
holes for later completed requests in that ring. A conservative connection flag
now skips the scan when no request bytes remain. New partial writes set it;
flushing recomputes it; connection close/failure clears it. A reset, STOP_SENDING
or GOAWAY can leave one extra scan, never a hidden pending request.

Request order, QUIC retransmission/flow control, FINs, timestamps, latency
samples, error accounting and response handling retain their existing behavior.

## Measurement scope

The accepted workload is one connection, 128 concurrent streams and 262,144 GETs,
with `--timeout 10s`. The independent Quinn/h3 peer holds the first response
until all younger replies are queued, then delays it another 100 ms. The held
reply, its full delay and every latency sample remain in the normal report.

Three alternating pairs give **+28.337% median requests/s**;
three independently reversed pairs confirm **+26.166%**.
All six pairs improve (+21.527% to +28.712%).
Complete client process CPU, including normal reporting, changes by
**-77.222% / -76.894%**.

Ordinary GET/POST, blocked POST, smaller held cases and timeout-off controls do
not establish an improvement or equivalence. Some smaller held cases reverse
direction between phases despite lower CPU. No general HTTP/3 speed claim is
made. All **59,553,024** revised comparison’s benchmark and warmup
requests succeed with zero errors; the failed baseline-only hfast pilot below
is retained separately. WSL limits remain relevant to small effects.

The initial implementation wrote the flag for every new request and every
blocked stream. It was rejected after all six ordinary c16/p128 pairs slowed
down (median -3.707% / -3.309%). The revised candidate sets the flag only when
a new request is partially accepted and stores the flush result once per scan.
All initial binaries and measurements are retained separately as c93 v1.

## Complete revised-candidate socket results

Cells are median paired percentage changes, primary / confirmation. `c` is
connections, `p` requested concurrent streams per connection, `n` requests,
and `t1` enables the 10s timeout (`t0` disables it). Fixed hfast limits streams
to 1,024 per connection, so requested `p4096` is limited by that server setting.

| Workload | Requests/s | Complete client CPU |
|---|---:|---:|
| get c1-p1-n65536-t0 | -2.563% / -1.188% | +1.541% / +1.184% |
| get c1-p1-n65536-t1 | -0.931% / +0.379% | +0.406% / +0.054% |
| get c1-p128-n1048576-t1 | +1.090% / +0.751% | -0.239% / -0.638% |
| get c1-p4096-n1048576-t0 | -2.750% / -0.162% | +1.133% / +0.122% |
| get c1-p4096-n1048576-t1 | +1.796% / -0.001% | -1.030% / +0.142% |
| get c16-p128-n1048576-t1 | +3.532% / +0.173% | -3.105% / +0.078% |
| held c1-p128-n131072-t1 | -4.556% / -2.164% | -61.392% / -62.921% |
| held c1-p128-n16384-t1 | +6.472% / -2.106% | -22.303% / -15.641% |
| held c1-p128-n262144-t1 | +28.337% / +26.166% | -77.222% / -76.894% |
| held c1-p128-n65536-t0 | +3.925% / -3.068% | -46.523% / -45.124% |
| held c1-p128-n65536-t1 | +7.749% / -7.889% | -47.526% / -41.174% |
| post c1-p1-n1024-t1 | +0.055% / -0.289% | +0.095% / +0.156% |
| post c1-p8-n2048-t0 | +2.950% / +1.514% | -1.561% / -0.462% |
| post c1-p8-n2048-t1 | +2.318% / -2.293% | -1.381% / +0.827% |
| blocked-post c1-p1-n256-t1 | -2.369% / -1.736% | +1.212% / +0.519% |
| blocked-post c1-p8-n512-t0 | -0.112% / -0.176% | -0.198% / -0.166% |
| blocked-post c1-p8-n512-t1 | +1.985% / -0.576% | -0.864% / +1.018% |

## Correctness and mechanism

Debug/release each passed 358 unit and 55 end-to-end tests (2 existing ignored).
Rust 1.91 passed 38 HTTP/3, 5 independent credit and 4 independent timeout fixtures.
Formatting and strict all-target Clippy pass. Full-body credit fixtures verify
every byte of 65,543-byte POSTs through 2,048-byte stream and 4,096-byte connection
windows, including loss and reordered late duplicates. A separate fixture checks
responses after STOP_SENDING while the request body remains blocked.
Five scheduler regressions include a 16,384-transition independent credit model,
zero/incremental credit, sparse retirement, rejection/GOAWAY and reconnect.

Native replay uses the real flush and QUIC write path. Empty flushes visit zero
slots: Callgrind instructions per call change from 36,899 to 19 at 4,096 dense slots,
and 393,257 to 19 at 65,536 sparse slots. No flush allocations are added. InFlight stays
80 bytes; Conn grows 3,552 to 3,560 bytes. Blocked zero-credit flushes still scan in
stream order and cost 146 to 151 instructions for one request, 14,243 to 14,883
for 128, and 454,691 to 475,171 for 4,096. This is a 3.4–4.5% instruction cost.
Native repeated blocked CPU changes are +3.124% / +1.749% for one request,
-0.135% / -0.422% at 128, and +3.377% / -0.996% at 4,096. These subroutine costs
are disclosed separately from end-to-end throughput. Empty-flush CPU falls
about 99.9% for the larger rings in both series; that alone is not a worker gain.

Independent instrumented builds preserve 952,574 samples and 258 intentional
reset/timeout errors across held/retry/GOAWAY/duration cases. An additional
blocked-POST audit preserves 512 measured samples per variant (plus 32 warmup each),
with every body checked by the independent peer. Instrumented builds are not
used for speed measurements.

## Reproduction

Baseline shb 1a672c84c823078c6817248401f4b3e52dbe0691; fixed hfast
30b137401746eab4fc9670550e143ce313e489b2. Build each production client using
`CARGO_INCREMENTAL=0 cargo build --release --locked` with separate clean
`CARGO_TARGET_DIR`s. Copy each binary to an immutable path. Use a third target
for tests and independent peer dependencies; never benchmark a CLI produced
by `cargo test`. Compiler, flags, dependency features/fingerprints and binary
hashes must match the manifest guard.

```sh
python3 benchmarks/check-release-inputs.py /path/to/baseline-target/release \
  /path/to/candidate-target/release /tmp/c93-inputs.json
CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/c93-peer-target \
  cargo test --release --locked --no-run
python3 benchmarks/build-h3-timeout-peer.py /tmp/c93-peer-target/release \
  benchmarks/h3-timeout-peer.rs /tmp/c93-held-peer /tmp/c93-held-build.json
python3 benchmarks/build-h3-timeout-peer.py /tmp/c93-peer-target/release \
  benchmarks/h3-post-peer.rs /tmp/c93-post-peer /tmp/c93-post-build.json

python3 benchmarks/compare-h3-timeout.py \
  --baseline /path/to/baseline-shb --candidate /path/to/candidate-shb \
  --hfast /path/to/fixed-hfast --peer /tmp/c93-held-peer --output /path/to/results \
  --build-manifest /tmp/c93-inputs.json --mode held --held-counts 16384,65536,131072,262144 \
  --prefix c93-held --phase primary
```

Repeat with `--phase confirmation`, which reverses both case and variant order.
Use `--mode direct` for ordinary GETs; add `--body-bytes 65543` and a new prefix
for fixed-hfast POSTs. To exercise blocked request bodies use `--mode post-peer
--body-bytes 65543 --peer /tmp/c93-post-peer` with another prefix. The fixed
independent Quinn/h3 POST peer checks all bytes before responding. GET warmups
use 8,192 requests, POST warmups 32 requests. Three alternating pairs and three
reversed pairs are used per case. All replies/delays and samples remain in the
normal measurements. Client affinity 2, peer 0,1; WSL2 6.18.40.1, rustc 1.98.0,
release full LTO, one codegen unit, mimalloc. Small changes remain limited by WSL
noise; no A/A retries, affinity sweeps or threshold reductions are used.

An excluded baseline-only pilot with 16,777,223-byte POSTs stalled on hfast's
fixed 16 MiB stream window: 0 replies, 4 timeouts. hfast explicitly sends no
MAX_STREAM_DATA updates. This is not a candidate regression or speed result;
it is why the blocked-body comparison uses the independent peer. General hfast
QUIC recovery is not claimed to be fixed.

Raw evidence, scripts, preserved source/binary manifests and all failed fixture
build attempts remain locally under `shb/optimization-results/c93-v2-*` (v1 remains under `c93-*`); large raw
artifacts are not committed.
