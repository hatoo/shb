# HTTP/1 TLS request flushing (c198, 2026-10-23)

An established HTTP/1 connection previously copied every immutable request into
`TlsSession::pending_plaintext`, immediately before flushing encrypted output.
The combined path keeps that request borrowed across bounded rustls writes and
ciphertext drains. The handshake, older backlog, blocked writer and pending Send
retain their queued fallback. A separate submission helper sends prepared TLS
output without clearing it again. No new connection state is needed.

## Confirmed workload

Accepted for complete 1 MiB uploads over eight persistent HTTP/1 TLS connections,
one client worker, against the fixed OpenSSL peer in `h1-upload-server.c`.
The peer compares every body byte before sending a success response. It reports
exact request, connection and byte counts, and disables TLS session resumption.
The nonconstant body is byte `33 + (offset % 90)`.

All numbers below are medians of paired percentage changes (candidate/baseline),
three alternating pairs per phase. The second phase reverses workload and binary
order. A third, longer phase checks whether subsecond runs overstated the gain.

| Phase | Requests/run | TLS | RPS | Client CPU/request | p99 | p99.9 |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| Primary | 1,024 | 1.3 | +21.613% | -16.928% | -19.024% | -10.552% |
| Reversed | 1,024 | 1.3 | +20.604% | -16.598% | -13.922% | +0.394% |
| Longer reversed | 8,192 | 1.3 | +18.918% | -16.221% | -12.535% | -9.833% |
| Primary | 1,024 | 1.2 | +17.768% | -14.444% | -13.882% | +1.665% |
| Reversed | 1,024 | 1.2 | +17.152% | -14.663% | -13.157% | -17.545% |
| Longer reversed | 8,192 | 1.2 | +16.687% | -14.334% | -11.142% | -10.874% |

All nine throughput pairs per TLS version improved. Longer-run individual RPS
changes: TLS1.3 +21.348/+14.885/+18.918%; TLS1.2 +17.666/+16.687/+16.240%.
This exceeds the small-workload variation in the comparison matrix.

WSL2; rustc1.99.1; default release features, fat LTO and one codegen unit;
identical `cargo build --release --locked --bin shb` builds. Both production
executables were frozen before timing. Baseline is default1680e60, SHA256
`5fa94e05c7a8ca06dfa14e5035b7633c50296c67740d97a836fb75920ee3d679`;
candidate SHA256
`9a6cecafd6a812715457c64b9f390bee1f25c99424aeaea81c432f5ab71a98ce`.
The client uses CPU2; the fixed threaded OpenSSL peer uses CPUs8,10,12,14.
Each measured run has a separate64-request warmup for large bodies. CPU values
are client user+system time per request; peer CPU is recorded separately.
Instrumented executables and test-generated binaries were excluded from timing.

## Limits and guards

These results establish the specified concurrent large-upload gain. Smaller
requests, serial uploads and tail latencies outside that workload remain mixed.
No general latency or throughput improvement is asserted.

| Guard | RPS primary/reversed | CPU/request primary/reversed |
| --- | ---: | ---: |
| TLS1.3,256B,c8 | +2.289/+0.599% | -2.502/-0.563% |
| TLS1.3,16KiB,c1 | -1.056/-1.012% | +1.001/+0.612% |
| TLS1.3,16KiB,c8 | +0.064/+1.702% | -0.172/-1.521% |
| TLS1.3,1MiB,c1 | +4.895/+3.933% | -7.385/-5.148% |
| TLS1.2,16KiB,c8 | +0.313/+0.287% | -0.166/-0.861% |
| TLS1.3,bodyless,c8 | -1.044/+0.023% | +1.523/+0.157% |
| TLS1.3,16KiB,churn,c1 | -0.968/+0.978% | +2.164/-7.672% |
| H2 TLS1.3,16KiB,c8,p8 | +0.668/-1.100% | -0.681/-1.384% |
| H1 cleartext,bodyless,c8 | +1.638/-0.170% | -1.591/-0.252% |
| H2 cleartext,bodyless,c8,p8 | -0.624/+0.163% | +0.622/-0.289% |

For example, serial16KiB p99 changed -10.015/+40.808%, churn p99.9
+32.253/-1.122%, and cleartext H1 p99.9 -17.950/+24.683%. The serial1MiB
confirmation includes a -8.451% RPS pair. These are retained rather than used
to claim universal improvement, equivalence or a confirmed guard regression.

28 separately instrumented real-H1 runs verified3,136 uploads and1,091,829,760
body bytes. With128 requests on one connection, a1MiB request staged
134,232,576 bytes before and1,048,692 after (the first request only). Eight
connections stage8,389,536 bytes after, down from134,232,576. Staging counts include HTTP
request headers. Churn stages the same bytes.
**Retained staging capacity is unchanged**: first-request handshake staging still
allocates the buffer. This experiment does not claim an RSS/allocation reduction.

## Correctness

614 tests pass in each debug/release profile (two inherited ignored tests).
Eight added tests cover exact TLS1.2/1.3 decrypted bytes and record shapes,
bounded/zero buffers, handshake/backlog, alerts, half-close, pending-Send storage
and clock ownership, and complete keepalive uploads with every success/sample.
Existing retirement tests exercise the combined path. Partial upload cancellation
now covers both initial and established requests before a complete reconnection.
Strict all-target Clippy, formatting, Rust1.91 and musl checks pass.
Independent H2 upload oracle:9 cases/128 successes plus3 native success/fault
cases pass. The OpenSSL benchmark peer also passes six independent TLS1.2/1.3
complete/wrong-byte/truncated-body cases. The portable runner passes its smoke.
All measured, warmup, smoke and diagnostic runs check exact counts and peer bytes.

## Reproduce

Build and freeze a baseline from1680e60 and this candidate in separate worktrees
with `cargo build --release --locked --bin shb`, identical compiler and flags.
Build the fixed peer, then run the portable comparison twice with fresh output
directories. It creates an ephemeral RSA2048 certificate and body file, warms up
each run, checks both ledgers and saves raw reports, hashes and paired summaries.

```sh
cc -O3 -pthread benchmarks/h1-upload-server.c -lssl -lcrypto -o /tmp/h1-upload-server
python3 benchmarks/compare-h1-tls-uploads.py \
  --baseline /path/to/frozen-baseline --candidate /path/to/frozen-candidate \
  --peer /tmp/h1-upload-server --out /tmp/h1-primary --requests 8192
python3 benchmarks/compare-h1-tls-uploads.py \
  --baseline /path/to/frozen-baseline --candidate /path/to/frozen-candidate \
  --peer /tmp/h1-upload-server --out /tmp/h1-confirmation --requests 8192 --reverse
```

Use `--client-cpu` and `--server-cpus` for the host's available CPUs; keep them
fixed between variants. The original full matrix, copy probes, command ledgers,
source archives and raw reports remain in the workspace's
`shb/optimization-results/c198/`; `summary-final.json` includes all three phases.
