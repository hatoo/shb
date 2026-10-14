# HTTP/3 final-send byte accounting

`check-h3-send-accounting.py` checks the complete client against aioquic 1.3.0.
The peer records every UDP payload before QUIC endpoint demultiplexing. `strace`
identifies the client's separate, best-effort `CONNECTION_CLOSE` by its exact
successful `sendto` payload. Removing that packet leaves the benchmark traffic:
its byte sum must equal `bytesSent`. io_uring sends do not use the `sendto`
syscall and remain in the benchmark ledger.

```sh
python3 -m venv /tmp/shb-h3-accounting
/tmp/shb-h3-accounting/bin/pip install aioquic==1.3.0
# Install strace with your distribution's package manager.
/tmp/shb-h3-accounting/bin/python benchmarks/check-h3-send-accounting.py \
  --shb ./target/release/shb > h3-send-accounting.json
```

Pass `--original` only for a baseline expected to omit final sends. The fixture
requires at least one reproduced deficit in that mode; the normal mode requires
exact equality in every run. It exercises 1/8/64/257 requests and parallelism up
to 128, three times each, with exact stream IDs, successful response counts,
statuses, and response body lengths. JSON includes the socket and syscall
ledgers, all reports, and independent QUIC packet/frame logs. Timing under
`strace` is not performance evidence.

Rust tests in `src/http3/send_accounting_tests.rs` separately exercise real
kernel completions: queued singleton/GSO sends over IPv4 and IPv6, plain and
worker rings, multiple connections, queued unscheduled tails, zero/failed sends,
a deterministically blocked linked send, retained old-generation sends alongside
the replacement send, and receive/deadline cancellation. They check buffer
recycling and preservation of request/error/status/sample counts and timestamps.
