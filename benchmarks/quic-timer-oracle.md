# Independent encrypted QUIC timer regression

The loss-before-PTO unit tests seed RTT and sent-packet history. This oracle
reaches the ordering through actual TLS and authenticated datagrams. It tests
the production `Connection` through public APIs that already take an `Instant`;
it never assigns private RTT, loss deadlines, packet history or recovery state.
The example is separate from the benchmark executable and uses raw bidirectional
QUIC streams with ALPN `quic-timer-oracle`, not an HTTP workload.

## Schedule and assertions

The pinned aioquic 1.3.0 peer advertises `max_ack_delay=0` in its TLS transport
parameters. This is a valid value. Both peers complete a full, unresumed TLS
handshake. Forty exact request/receipt exchanges, with 50 ms logical time in
each direction, settle the client's RTT using real acknowledgements.

The ordinary case completes another stream. The two loss cases instead:

1. Drop the entire target request (including FIN) in client packet N.
2. Deliver a peer PING sent 50 ms earlier. The client sends ACK-only N+1.
3. Deliver N+1 to aioquic and return its authenticated ACK at N's send +100 ms.
   Every scripted ACK is checked against the delivered packet ledger.
4. Require a timeout near +112.5 ms, no output or probe at an early +105 ms
   wakeup, and request recovery after a +113 ms wakeup.
5. Deliver all recovery output on the same schedule, including premature output
   on a historical client. Require all 41 request bodies and SHA-256 receipts,
   exact final sizes, and one application FIN per response.

The sparse case ACKs N-1 and N+1, reorders an older authenticated ACK behind the
newer one, then repeats the newer encrypted ACK. Byte/FIN checks are unchanged.
Client output is independently authenticated and decoded with aioquic before
the controller chooses whether to deliver it. The peer uses normal TLS and
stream processing; only transport parameters and the ACK/PING schedule are
controlled. Recovery remains the production client's implementation.

Negative runs omit the required ACK, omit the response FIN, and corrupt a
same-length receipt. Each must fail its specific assertion after the TLS
handshake, without an adapter process failure. Eight malformed-input cases
exercise adapter bounds. Commands, datagrams, stream sizes, logical horizon,
exchange turns, and adapter process waits are bounded. Each command and raw
encrypted datagram is flushed to `wire.jsonl`, including when a test fails.
The adapter's diagnostics and each case's result are retained as well.

## Run

```sh
python3 -m venv /tmp/quic-timer-venv
/tmp/quic-timer-venv/bin/pip install aioquic==1.3.0 pylsqpack==0.3.24 hpack==4.1.0
cargo build --locked --example quic-timer-peer
/tmp/quic-timer-venv/bin/python -m unittest discover -s benchmarks -p 'test_quic_timer.py'
/tmp/quic-timer-venv/bin/python benchmarks/check-quic-timer.py \
  --adapter target/debug/examples/quic-timer-peer --output /tmp/quic-timer-debug
cargo build --release --locked --example quic-timer-peer
/tmp/quic-timer-venv/bin/python benchmarks/check-quic-timer.py \
  --adapter target/release/examples/quic-timer-peer --output /tmp/quic-timer-release
```

Output directories must be new. CI runs both profiles and retains all evidence
even on failure. `--case` selects one positive case for diagnosis.

## Historical regression evidence

With the same adapter, peer and schedule, production source at `676315f`
(before the timer-mode repair) completes all streams but fails both loss cases:
its deadline is +101 ms, and the early wakeup emits two probe datagrams / 90
bytes. Recovery at +113 ms adds two datagrams / 95 bytes, for four / 185 total.
Production source at `a0d7bdd` emits zero early probes and two / 95 at loss.

Use separate Cargo target directories for different source worktrees, freeze
the resulting binaries, and record source and binary hashes before comparing.
Sharing a target directory can reuse an example built from the other worktree
when older source timestamps do not invalidate Cargo's cache. Such identical
historical/current binaries are invalid comparison inputs.

These are deterministic packet-work counts in a deliberately scheduled case.
They establish independent recovery evidence for the existing correctness fix;
they establish no end-to-end throughput or latency gain. The production
benchmark's request accounting, latency clock and samples are unchanged.
