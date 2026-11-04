# HTTP/3 startup with small unidirectional receive windows

A peer can initially grant less credit than the 12-byte control-stream prefix.
At baseline `999f388`, a short write ended the connection and charged a connect
error before any request started. Subsequent MAX_STREAM_DATA grants could not
repair the abandoned HTTP/3 startup.

The worker now opens its three critical streams once and retains each accepted
prefix length when credit blocks setup. It retries after input and starts request
budgets and latency clocks only when all three prefixes have been accepted by
QUIC. The control and QPACK streams stay open. Closing the connection discards
the pending initialization before the socket slot is reused.

Run the independent wire oracle with the CI-pinned aioquic environment:

```sh
cargo test --locked http3::init_tests
cargo build --release --locked
python benchmarks/check-h3-startup-credit.py --shb ./target/release/shb
```

`--baseline` expects the old failure, and is only for checking an immutable
baseline binary. `--case` selects an individual scenario. The script records
exact delivered prefixes and, in the loss case, independently authenticated
packet numbers, STREAM offsets, bytes and encrypted datagrams. It uses aioquic
private receive-window and crypto interfaces, pinned to version 1.3.0 by CI.

Observed baseline/candidate results, with 16 request-budget units per case:

| Peer | Baseline | Candidate |
| --- | --- | --- |
| Ordinary credit | 16 successes | 16 successes |
| 1-byte uni window | 16 connect errors | 16 successes |
| 5-byte uni window | 16 connect errors | 16 successes |
| 1-byte window, dropped fragment and late duplicate original | 16 connect errors | 16 successes; retransmission and replay verified |
| Close the first connection during startup | 16 connect errors | 1 expected connect error, 15 successes on its replacement |

The peer checks all 14 control/QPACK bytes, absence of FIN, complete GETs,
alternating 200/503 responses, and exact request/status/latency-sample counts.
Unit tests also cover zero credit, repeated and decreasing grants, QPACK still
blocked after the control prefix completes, stop/exhausted budgets, and reuse of
the same connection object. Mutations that forget the accepted prefix offset or
declare readiness before the control prefix finishes fail these tests.

This is a correctness repair; no throughput or latency improvement is claimed.
A focused allocation audit of the actual startup drive path found the same
8 allocations, 1 reallocation and 565 requested bytes with ordinary credit in
both versions. It excludes TLS construction, sockets, packet processing and
application requests. The worker connection grows from 3,696 to 3,704 bytes on
x86_64. A blocked startup retains a 120-byte boxed state plus its bounded prefix
vectors. The ordinary path never allocates that box. After readiness, 256 idle
drive calls performed no prefix visits and no allocations in either version.
