# HTTP/2 complete-upload validation

An HTTP/2 response can finish before its request body. A load generator's
successful response count therefore does not establish that every configured
upload byte reached the server. In particular, a peer that responds to HEADERS
is unsuitable for measuring complete-upload throughput without an independent
body-completion ledger.

`check-h2-complete-uploads.py` uses hyper-h2 4.3.0 to validate real shb requests.
It checks every byte against a nonconstant ASCII body, content length,
END_STREAM, response/error/latency sample totals and, for cleartext, the complete
TCP send count (excluding the existing best-effort teardown GOAWAY). Cases cover:

- 16,383-byte, 16 KiB and 1 MiB bodies, with two connections and eight streams.
- 64 KiB frames, a frame-size SETTINGS change, and 3,072-byte stream credit.
- Repeated GOAWAY/reconnects with 1 MiB bodies.
- TLS uploads of 16 KiB and 1 MiB.

The nine cases make 128 successful requests. A response is sent only after the
entire expected body and END_STREAM have arrived. The byte pattern contains no
CR or LF, so shb's documented `-d @file` newline handling does not change it.

```sh
cargo build --release --locked --bin shb --example h2-upload-server
python3 -m venv /tmp/h2-upload-check
/tmp/h2-upload-check/bin/pip install h2==4.3.0 hpack==4.1.0
/tmp/h2-upload-check/bin/python benchmarks/check-h2-complete-uploads.py \
  --shb target/release/shb --peer target/release/examples/h2-upload-server
```

The optional `--peer` argument also validates the native h2 0.4.19 benchmark
peer over cleartext, TLS 1.2 and TLS 1.3. Python SSL and hyper-h2 independently
check the negotiated version and h2 ALPN. Each transport runs seven cases:

- Complete 1 MiB body, corrupt payload, and a body one byte short.
- END_STREAM split across writes, and a final DATA frame missing its payload.
- Eight connections with eight concurrent 16 KiB uploads each.
- Those same concurrent streams closed before END_STREAM.

A PING fences the full DATA payload before END_STREAM; no response may have
arrived. Every success checks status, response length and `Hello, World!`.
Faults must produce no successful response, and every closed connection must
report an exact request/byte ledger with zero pending tasks. Rejected uploads
are counted separately. Wrong TLS versions, incompatible ALPN and absent ALPN
add six rejection cases. The existing nine shb-to-Python cases also still run.
All these checks run in the existing complete-body CI step.

The native peer uses four Tokio workers, a 4 MiB stream receive window, a 32 MiB
connection receive window, 1,024 concurrent streams and 16 KiB frames. Its
positional arguments remain a TCP port and the file containing the expected
request body. Port zero selects an unused port; `READY <actual-port>` is written
to stderr after binding. It compares each DATA chunk, releases credit as it
consumes data, and responds only after the declared body and END_STREAM. A
missing or zero content length is permitted for bodyless control requests.
Stream tasks are joined before the final per-connection ledger is emitted,
including after rejected or interrupted uploads. TLS configuration is optional;
`--tls tls12` or `--tls tls13` requires `--cert` and `--key` PEM paths. The async
TLS adapter is a development dependency.

```sh
# Generate a body with no newline characters.
python3 -c 'from pathlib import Path; Path("/tmp/upload.body").write_bytes(bytes(33+i%90 for i in range(1048576)))'
taskset -c 8,10,12,14 target/release/examples/h2-upload-server 18779 /tmp/upload.body
# In another terminal, with CPUs chosen for the local machine:
taskset -c 2 target/release/shb --http2 -n 8192 -c 8 -p 8 -t 1 \
  --batch-linger 10 --timeout 10s -d @/tmp/upload.body -j http://127.0.0.1:18779/
```

A valid timing run requires zero unexpected errors, exactly 8,192 successes,
`latencySamples: 8192`, and a peer ledger totaling 8,192 requests,
8,589,934,592 body bytes and zero
pending tasks. Preserve the ledger with the client report. Freeze the peer
binary when comparing clients; alternate immutable release clients with
identical bodies, settings and counts. This fixture adds no production client
behavior and makes no performance-improvement claim.

For TLS, generate a test certificate and select one protocol version explicitly:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/upload.key \
  -out /tmp/upload.crt -days 1 -subj /CN=localhost
target/release/examples/h2-upload-server 18779 /tmp/upload.body \
  --tls tls13 --cert /tmp/upload.crt --key /tmp/upload.key
# Use an https:// URL with the same client arguments above.
```

`compare-h2-tls-uploads.py` runs a fixed 16 KiB/c8/p8/t1 workload against this
peer for both TLS versions, with 512 warmup requests before each measurement
and 32,768 measured requests. It alternates immutable clients for three pairs,
checks every connection ledger, saves the raw client reports and server logs,
and records CPU time separately for the client and peer (whole-process CPU,
including startup and teardown). Throughput, p99 and p99.9 come from shb's
unchanged reports. Warmups use separate processes. Output directories must be
new, and input hashes are checked before and after the run.

Both this validator and the HTTP/1 and HTTP/2 TLS comparison scripts require
an explicit `latencySamples` count equal to successful completions and the sum
of status counts. Missing, extra or lost samples invalidate the run. Clients
built before this field was added need the same reporting-only change applied
to both baseline and candidate before comparison; the scripts do not infer a
count for older binaries. This checks the live count, not individual raw samples.
Run the fault checks with:

```sh
python3 -m unittest discover -s benchmarks -p 'test_report_accounting.py'
```

```sh
python3 benchmarks/compare-h2-tls-uploads.py \
  --baseline /path/to/frozen-baseline --candidate /path/to/frozen-candidate \
  --peer /path/to/frozen-h2-upload-server --out /tmp/h2-tls-primary
# Repeat with a new output directory and --reverse for independent confirmation.
```

Freeze the same peer for both clients and both comparison orders. Its TLS and
stream-task scheduling differ from other peers, so rates measured against
different peers are different workloads. This tool alone cannot establish that
a client has improved or that a previously observed regression was noise.
