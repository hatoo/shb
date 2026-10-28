# Native HTTP/3 response-flight peer

This Quinn/h3 server supplies a fixed native producer for large-response client
experiments. It validates an empty GET to `/response`, sends a preallocated
patterned body with Content-Length and FIN, and counts a response only after
Quinn reports authenticated receipt of all stream data. Successful writes alone
are insufficient. STOP_SENDING, request errors, task panics, connection errors,
deadlines and incomplete final counts fail the run.

```sh
cargo build --release --locked --example h3-response-flight-peer
python3 -m unittest discover -s benchmarks -p 'test_h3_response_flight.py'
# Use the pinned aioquic environment also used by the CI wire fixtures.
python3 -m venv /tmp/response-venv
/tmp/response-venv/bin/pip install aioquic==1.3.0 pylsqpack==0.3.24
/tmp/response-venv/bin/python benchmarks/check-h3-response-flight.py \
  --peer ./target/release/examples/h3-response-flight-peer \
  --shb ./target/release/shb --output /tmp/new-response-results
```

The output directory must be new. The checker retains commands, stdout, stderr,
exit codes and ledgers. CI uploads them even when a check fails. Its independent
aioquic client checks every body byte, status, length, complete H3 frame boundaries
and QUIC FIN for 1 KiB, 1 MiB and 8 MiB responses, including following requests
and multiplexing. FIN on a final ignored GREASE frame is checked even when
aioquic emits no corresponding HTTP event.

Negative cases cover truncated/corrupted responses, missing FIN, an invalid
request, a failure after receipt, an empty run and early process exit. Another
case receives the complete body and FIN but withholds all application-space
ACKs: the peer must report a queued FIN and **zero acknowledged responses**.
This guards against replacing receipt with send completion. Only that negative
case uses aioquic's pinned private ACK writer. Unit tests also reject missing,
inconsistent and noninteger counters, incomplete framing and a nonzero exit
despite a complete ledger.

Four native shb runs check 1 MiB/8 MiB responses at c1/p1 and c2/p4. Each requires
the exact requested total, successful requests, 200 statuses and latency samples,
zero request/connection errors, and matching peer receipt and byte counts.
Client ACKs establish transport receipt; **they do not prove that shb checked or
hashed response content**. The independent aioquic probe checks the producer's
content. These tests do not establish general QUIC loss-recovery correctness.

## Using the producer for measurements

```sh
./target/release/examples/h3-response-flight-peer \
  --requests 256 --body-bytes 8388608 --workers 4 --deadline-seconds 60
```

The first stdout JSON record gives the loopback address and configuration. Keep
stdin open, run a client for exactly the configured request count, then send
`finish\n`. The peer drains outstanding receipt tasks and prints one final JSON
record. EOF is an error; a run and its shutdown each have a bounded deadline.
`--fault` is solely for oracle tests and must remain `none` in measurements.

`h3_response_flight.run_shb` provides this lifecycle and strict result checks;
it supports affinity/time command prefixes and terminates their process groups
on failure. Preallocated response bytes use `(i * 31 + i / 251) % 256`. TLS,
QUIC transport settings, body size, concurrency, peer executable and runtime
worker count must stay fixed between baseline and candidate. Use immutable
release clients, warmup, alternating pairs and independent confirmation; retain
client user+kernel CPU, rate, p99/p99.9 and all accounting. Establish producer
headroom separately. Python drives processes here; it does not serve packets in
native timing runs. The independent Python probe is a correctness test only.

Large bodies do not automatically imply a large unretired client flight. Audit
actual flight sizes and retirement groups separately from timing before using
this workload to evaluate recovery data structures. No throughput improvement
or stable-host claim is made by this fixture.
