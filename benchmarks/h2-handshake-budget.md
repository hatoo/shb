# HTTP/2 late-handshake request accounting

A connection attempt does not reserve a request. With `-n 2 -c 2 -p 2 -t 1`,
one TLS/H2 connection can own both requests while the other is still negotiating
TLS. If the second handshake fails after the first response, charging another
request ends the run with one success and one connection error. The second real
response and its latency sample are lost.

`fail_connect` now charges only an unassigned request unit. TCP connect failures,
TLS failures, ALPN rejection and idle timeouts use the same operation. Live
requests and unjudged GOAWAY give-backs still fail independently of that guard;
returned budget can still pay for a later failed connection attempt.

## Reproduction and validation

The permanent `tests/support/h2_handshake.rs` fixture uses an independent rustls
server with raw HTTP/2 frames. It receives both request streams on one connection,
then either closes another pending TLS handshake or completes it without ALPN.
It holds the second response for 250 ms and checks both statuses and both latency
samples. On baseline `692a6f7`, both tests fail with `(ok, errors, connect_errors)`
equal to `(1, 1, 1)`. With the repair, both return `(2, 0, 0)` and two samples.

Five deterministic tests cover budget boundaries, repeated attempts, original
timestamps, live and held request failures, returned budget and duration mode.
An independent OpenSSL/raw-H2 peer confirms the same before/after behavior for
both failure paths using release audit binaries.

Validation on Linux/WSL2, Rust 1.98.0:

- Debug and release: 379 unit tests and 56 end-to-end tests pass per profile;
  two existing external-server tests remain ignored.
- Rust 1.91: 63 HTTP/2 unit tests, both handshake fixtures and 18 H2 end-to-end
  tests pass. Formatting and strict all-target Clippy pass.
- Fixed hfast `a8ad11f`, cleartext H2 at `c1/p128` and `c128/p1`: alternating
  baseline/candidate order with warmups, 139,264 production successes and
  32,768 audited successes, zero errors. Every audited worker has
  `completed == samples == sum(statuses)` and `started == completed + errors`.
- Refused connections preserve exact budgets of 1, 129, 257 and 1,025 across
  one, three and four workers. A silent TLS peer produces exactly 17 connection
  errors for 17 requests; a duration run continues to report actual failures.

Production binaries have matched compiler, release profile, features and
dependency fingerprints. Audit builds are separate from production builds.
These are correctness guards; the short runs do not establish a throughput gain.

Focused reproduction:

```sh
cargo test --bin shb h2_handshake
cargo test --bin shb http2::budget_tests
cargo test --test e2e h2
```
