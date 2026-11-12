# Repeated unchanged HTTP/2 initial windows

`h2-unchanged-settings-server.rs` is a fixed, dependency-free h2c peer. It holds
one cohort of empty requests open, sends a SETTINGS frame containing repeated
`INITIAL_WINDOW_SIZE = 65535` entries, waits for its acknowledgment, then sends
one status-200 END_STREAM response for every request. Stream IDs, header-block
consistency, client settings, ACK counts and shutdown are checked. The client
must independently report the exact request/status/latency-sample count and no
errors. A failed or truncated exchange makes the peer fail.

Build the peer once and keep it fixed across both client binaries:

```sh
rustc --edition=2024 -D warnings -O -C lto=fat -C codegen-units=1 \
  benchmarks/h2-unchanged-settings-server.rs -o /tmp/h2-settings-server
```

In one terminal, start the peer (port, cohort size, cohort count, repetitions):

```sh
taskset -c 2 /tmp/h2-settings-server 8080 16384 128 1024
```

Then run one immutable client binary from another terminal:

```sh
taskset -c 0 /path/to/shb --http2 -t 1 -c 1 -p 16384 -n 2097152 \
  --timeout 30s --batch-linger 1 -j http://127.0.0.1:8080/
```

The peer exits after the client closes. Expect 2,097,152 requests and responses,
129 settings ACKs, and matching client successes, status-200s and latency samples.
Use a fresh peer per run. Port zero prints the assigned port in its READY line.
Use the same workload, compiler and release settings for both clients. Warm up
both binaries, alternate AB/BA/AB, then confirm separately in BA/AB/BA order.
Record CPU affinity, binary hashes, every JSON report, peer output and process
CPU time. A repetition count of zero omits the repeated SETTINGS frames and
provides an ordinary cohort guard, with one settings ACK. Also test ordinary
streaming responses from a fixed server, since this peer deliberately delays
responses. All production latency samples must still be collected.

## c405 result, WSL2 / Rust 1.99.1

Baseline `c665e37`, frozen SHA-256 `117bfeae38dcd581a5a44c17e3228ac71b182e4726ce9b61df55e09b3fa11a06`;
candidate `74909e06b3c63af1073a85a2806b382ada529d54ec984fcc105fba1aa93fe205`;
fixed peer `76bf620fb50659ef14acdc31e05cf04b9a8f628bf0842b742345dc517663a2aa`.
Locked release builds use fat LTO, one codegen unit and identical native
dependency artifacts. Only the unchanged-setting scan is removed.

| Workload | Primary median RPS change | Reversed confirmation |
| --- | ---: | ---: |
| Repeated settings above | +344.39% (4.44x) | +335.57% (4.36x) |
| Ordinary cohort, repetitions = 0 | -3.27% | +0.84% |
| Fixed hfast, one connection / 64 streams | -0.18% | +0.24% |

Affected process CPU/request medians fall 87.80% and 88.14%. This is a scoped
result for repeated equal settings on large live cohorts, not an ordinary HTTP/2
throughput claim. The ordinary cohort's initial tail increase does not repeat;
ordinary small differences, tail equivalence and RSS changes remain unqualified.
Latency includes deliberate response withholding. No timing or sample collection
was removed. `/usr/bin/time` CPU values have 10 ms resolution.

Each table cell uses three paired runs of 2,097,152 requests per client; all
75,497,472 measured requests, status-200s and latency samples reconcile with zero
errors. Separate plain/TLS hyper-h2 checks and fixed-server H1/H2/H3 checks pass.
Local evidence is under `shb/optimization-results/c405/`: `measurement-plan.md`,
`assessment.json`, `native.py`, `streaming.py`, raw reports, and validation logs.
Raw evidence and binaries are not committed.
