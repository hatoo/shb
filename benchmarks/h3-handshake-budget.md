# HTTP/3 late-handshake request accounting

A failed handshake previously consumed one request even if other connections
had already assigned the entire counted budget. This could over-report errors,
or end the run before a real response arrived. `begin_close` now charges that
failure only if an unassigned request remains. Live-request failures, duration
mode, give-backs, socket cleanup and reconnect generations retain their behavior.

This is a correctness repair, with no throughput claim.

## Reproductions

Against an unused local UDP port, run:

```sh
shb --http3 -j -n 129 -c 129 -p 1 -t 1 \
  --connect-timeout 1s --timeout 5s https://127.0.0.1:PORT/
```

WSL2 production builds from baseline `443f9d7` and this change used Rust 1.98,
the default release profile, and identical feature/dependency fingerprints.
The immutable baseline and candidate reported:

| Requests / connections / workers | Baseline errors | Fixed errors |
| --- | ---: | ---: |
| 1 / 8 / 1 | 1 | 1 |
| 129 / 129 / 1 | 160 | 129 |
| 257 / 32 / 3 | 266 | 257 |
| 1025 / 64 / 4 | 1040 | 1025 |

All errors were connection errors; all these runs had zero successes and samples.
Exact baseline overcounts can depend on completion batching.

The independent Quinn fixture accepts two requests on one connection, then
refuses another pending handshake while holding the second response for 250ms.
The baseline reports one success and one connection error. The repaired worker
records both responses (200 and 201), zero errors and two latency samples,
including the delayed response's full latency.

## Regression coverage

- Six deterministic io_uring tests cover available/exhausted/overdrawn budgets,
  repeated closes with a real send in flight, reconnect exhaustion, live-request
  errors, pending and returned give-backs, duration stop and unchanged timestamps.
- The Quinn fixture above and a CLI refused-port matrix run in the regular suite.
- Debug and release each passed 372 unit tests and 56 end-to-end tests. Two
  existing external-server tests remain ignored. Existing loss, reordered
  duplicate, timeout, GOAWAY and patterned-body recovery fixtures passed.
- Rust 1.91 passed 48 HTTP/3 unit, 13 Quinn/credit and 9 end-to-end tests.
- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` passed.

Fixed hfast `a8ad11f` guards used one connection / 128 streams and 128 connections /
one stream, with warmups and reversed baseline/candidate order. Production runs
completed 139,264 requests; separately instrumented binaries completed 32,768.
All had zero errors, exact status totals, and the instrumented runs verified one
latency sample per successful response. Silent-socket handshake timeouts and a
duration stop also retained correct accounting. These short runs validate
correctness and do not establish a performance difference.
