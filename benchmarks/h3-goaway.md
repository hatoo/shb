# HTTP/3 GOAWAY correctness oracle

`check-h3-goaway.py` drives the release client against an independent encrypted
aioquic peer. It checks cancellation, retries, request/error/status accounting
and latency sample counts. This is a correctness gate, with no throughput claim.
It does not exercise packet loss or establish general QUIC recovery correctness.

```sh
python3 -m venv /tmp/h3-goaway-venv
/tmp/h3-goaway-venv/bin/pip install aioquic==1.3.0 pylsqpack==0.3.24
cargo build --release --locked
python3 -m unittest discover -s benchmarks -p 'test_h3_goaway.py'
/tmp/h3-goaway-venv/bin/python benchmarks/check-h3-goaway.py \
  --shb ./target/release/shb --output /tmp/h3-goaway.json
```

The output file must be new. Without `--output`, the full JSON goes to stdout.
Each run includes the client binary SHA-256, command, exit status, raw report,
peer packet/stream ledgers, callback failures and semantic fault controls.
CI runs this in its existing pinned aioquic environment and retains the evidence
as an artifact, including on failure. `--case NAME` selects a case for debugging.

| Case | Parallel requests | Expected behavior |
| --- | ---: | --- |
| mixed | 8 | GOAWAY(16), complete/partial responses and resets share one encrypted packet. A response on stream 16 completes before rejection; the reset below the boundary counts as one error. Three rejected requests retry, yielding 7 successes and 1 error. |
| decreasing | 8 | Boundaries 24, 24, 16, 8, 8 retire successive suffixes while two accepted requests keep their original latency interval. Six requests retry; all 8 succeed. |
| no-suffix | 1, 64 | Repeated GOAWAY at the next stream ID rejects nothing; the held response finishes with one sample per success. |
| zero | 1, 64 | GOAWAY(0) rejects everything. The run ends with exactly the configured error count, no reconnect loop and no latency samples. |
| ordinary | 1, 64 | All requests complete without GOAWAY or retries. |
| blocked-upload | 8 | Initial streams have only 128 bytes of credit. Four rejected uploads send RESET_STREAM with H3_REQUEST_CANCELLED and final size 128 before accepted responses finish. Four retries deliver the entire POST body on a new connection. |

The nine runs use one worker and one connection slot. Separate connections are
counted by the peer, independent of the client's request budget. The mixed,
decreasing, no-suffix and upload phases wait for authenticated client ACKs of
their actual packet numbers; qlog proves mixed-event co-location. Accepted
responses remain open for 100 ms, and the report must retain at least 80 ms of
latency. The peer compares every upload byte and requires FIN on complete retries.

Every successful live ledger is replayed with deliberately changed evidence:
missing/extra samples, wrong budgets, extra attempts, missing retries, absent
upload cancellation, cancellation after response completion, incomplete retry
bodies, missing ACKs, lost held latency, or mixed events in separate packets.
Each control must fail with its specific semantic code. A process crash, failed
handshake, peer exception, unrelated validation error or disabled validator does
not count as detecting the intended fault. These are **evidence mutations**,
not modified client binaries, and do not replace the live positive runs.

`h3_goaway.py` contains the replay validator. The small fixture in
`fixtures/h3-goaway.json` retains only consumed fields from nine successful
encrypted runs of the accepted client; its metadata identifies the source and
binary. The standard-library unit tests exercise the same 62 fault controls and
the controls' failure handling. Live runs regenerate evidence independently;
they never load the fixture or depend on a deferred optimization branch.

Client execution has a 30-second deadline, each ACK/cancellation barrier has a
5-second deadline, and remaining schedule tasks have a 5-second completion
deadline. Cleanup kills/reaps an unfinished client, cancels and joins peer tasks,
closes the UDP server and restores the event loop's exception handler. Run with
normal Python assertion checking, as the peer uses assertions for protocol
invariants.
