# HTTP/2 complete-upload validation

An HTTP/2 response can finish before its request body. A load generator's
successful response count therefore does not establish that every configured
upload byte reached the server. In particular, a peer that responds to HEADERS
is unsuitable for measuring complete-upload throughput without an independent
body-completion ledger.

`check-h2-complete-uploads.py` uses hyper-h2 4.3.0 to validate real shb requests.
It checks every byte against a nonconstant ASCII body, content length,
END_STREAM, response/error totals and, for cleartext, the complete TCP send
count (excluding the existing best-effort teardown GOAWAY). Cases cover:

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
peer. A PING fences the full DATA payload before END_STREAM; no response may
have arrived. Sending END_STREAM then produces exactly one complete response.
Separate wrong-payload and truncated-body cases must reset the stream without
a successful response. The wrong-payload case deliberately triggers the
peer's assertion in its connection task; its captured log is checked by the
oracle. These faults are expected test outcomes, not successful workloads.

The native peer uses four Tokio workers, a 4 MiB stream receive window, a 32 MiB
connection receive window, and 16 KiB frames. Its only arguments are a TCP port
and the file containing the exact expected request body. It compares each DATA
chunk, releases credit as it consumes data, and responds with `Hello, World!`
only after the exact declared body and stream end. Each closed connection logs
a ledger of completed requests, body bytes and pending tasks.

```sh
# Generate a body with no newline characters.
python3 -c 'from pathlib import Path; Path("/tmp/upload.body").write_bytes(bytes(33+i%90 for i in range(1048576)))'
taskset -c 8,10,12,14 target/release/examples/h2-upload-server 18779 /tmp/upload.body
# In another terminal, with CPUs chosen for the local machine:
taskset -c 2 target/release/shb --http2 -n 8192 -c 8 -p 8 -t 1 \
  --batch-linger 10 --timeout 10s -d @/tmp/upload.body -j http://127.0.0.1:18779/
```

A valid timing run requires zero unexpected errors, exactly 8,192 successes,
and a peer ledger totaling 8,192 requests, 8,589,934,592 body bytes and zero
pending tasks. Preserve the ledger with the client report. Freeze the peer
binary when comparing clients; alternate immutable release clients with
identical bodies, settings and counts. This fixture adds no production client
behavior and makes no performance-improvement claim.
