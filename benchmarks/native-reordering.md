# Native QUIC response reordering checks

This fixture exercises shb's real UDP receive path with a large pending STREAM
fragment queue. It is a correctness and exposure test, not a throughput result.
The ordinary 25-byte benchmark response cannot establish this exposure.

Build and run (Linux, Rust 1.91+, Python 3.12+, `ip`, `unshare`):

```sh
git fetch --no-tags origin 9fcad6b56c9d8b258e82fba93570ff6d2e8660b6
python3 benchmarks/build-native-reordering.py /new/reorder-peer
python3 benchmarks/build-reordering-exposure.py \
  9fcad6b56c9d8b258e82fba93570ff6d2e8660b6 /new/reorder-observer
python3 -m unittest discover -s benchmarks -p test_native_reordering.py -v
python3 -m venv /new/reorder-venv
/new/reorder-venv/bin/pip install aioquic==1.3.0 pylsqpack==0.3.24
/new/reorder-venv/bin/python benchmarks/run-native-reordering-suite.py \
  --peer /new/reorder-peer/native-reordering-peer \
  --shb /absolute/path/to/frozen/shb \
  --exposure /new/reorder-observer/shb-exposure --output /new/reorder-results
```

Every output directory must be new. `NATIVE_REORDER_TARGET` and
`NATIVE_EXPOSURE_TARGET` may select build caches. The builders read immutable Git
objects, extract the pinned Quinn 0.11.19 crate after checking its Cargo.lock
checksum, and patch only private output copies. Neither checkout, registry
source, production Cargo.lock nor existing binary is modified. Builds record
compiler, source and executable hashes; final executables are read-only.

The peer reuses the published Quinn/h3 HTTP server's GET, path, body, response
and authenticated-receipt checks. Its private SendBuffer scheduler selects the
single contiguous body write of the configured size, retains its first 1024
bytes, and sends the other 512 chunks in reverse, mixed-gap or duplicate order.
The prefix is released only after ordinary authenticated ACK processing covers
every suffix byte. Losses retain Quinn's retransmission paths. Congestion and
flow control remain active; MTU discovery is disabled to fix packet capacity and
keep probe loss separate from response loss. Frame splitting can produce more
than 512 distinct pending fragments. Ordered delivery is the zero-queue control.

This bounded workload requires the whole body write to fit available send and
receive credit. A partial body write, missing schedule activation or missing ACK
fence fails the oracle. It does not claim to cover all flow-control workloads.
The peer's ACK fence proves transport receipt; application delivery is checked
separately. Pinned aioquic verifies every patterned body byte, HTTP status,
content length and FIN. Its qlog independently reconstructs suffix byte coverage
in previously ACKed packets before the prefix arrives, including FIN-before-gap.
Three sequential requests exercise pooled stream reuse. One response-sized
datagram is deliberately lost in the recovery case; normal recovery and exact
delivery must complete. Missing-prefix, missing-FIN and corrupt-body controls
must reach their specific failure states, rather than fail for an unrelated
handshake or process error. A corrupt body can still be ACKed at the transport
layer; the independent application oracle must reject it.

The observer checks every shb DATA byte, records each retired stream's actual
peak queue, and requires consumed bytes, charged credit and final size to agree.
Its source patch and binary hash are retained. **Observer executables are never
timing inputs.** The unmodified shb also runs each workload and must report exact
request/status/error/latency-sample counts. No client timestamps are changed.

Each case runs in new network and PID namespaces, with bounded process cleanup.
The default uses unprivileged user namespaces; `--namespace sudo` uses
noninteractive `sudo unshare` where CI disables user namespaces. The controller
records its parent namespace and requires a different child network namespace.
Owned live peer/reader sockets, actual reader buffer capacity, namespace UDP
counters, Quinn packet/loss counters, exit codes, commands and qlogs are retained.
Unavailable or nonzero UDP error counters fail. Kernel UDP datagram counters
count GSO/GRO operations differently from Quinn packet counters; no equality
between these distinct quantities is assumed. Deliberate reader loss is logged
separately from kernel drops. Failure artifacts are preserved too.

The trace-retaining peer and independent reader can limit throughput. A runtime
optimization still needs immutable uninstrumented baseline/candidate binaries,
a frozen peer, warmup, alternating comparisons and independent confirmation on
a qualified host, plus ordinary protocol and tail-latency guards. Passing this
fixture alone does not establish an end-to-end speedup or justify merging a
performance candidate.
