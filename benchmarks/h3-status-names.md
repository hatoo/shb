# Literal Huffman QPACK status names

A server can encode `:status` as a literal name with Huffman coding (RFC 9204
section 4.5.6). Previously shb skipped that name, so a valid response ending with
FIN was counted as an error with no status or latency sample. The decoder now
compares the canonical five encoded bytes directly. It allocates nothing and
leaves the static-reference path and ignored-field policy unchanged.

`check-h3-status-names.py` uses aioquic as an independent QUIC peer. python-hpack
encodes the names and values; pylsqpack decodes every valid QPACK test section
before it is sent. These packages are test tools only:

```sh
python3 -m venv /tmp/qpack-oracle
/tmp/qpack-oracle/bin/pip install aioquic==1.3.0 pylsqpack==0.3.24 hpack==4.1.0
cargo build --release
/tmp/qpack-oracle/bin/python benchmarks/check-h3-status-names.py \
  --shb ./target/release/shb --output qpack-results.json
python3 -m unittest discover -s benchmarks -p 'test_h3_response_fragments.py'
```

There are 45 cases: all 41 original cases plus three valid wide/fragmented
workloads and a fragmented truncated-name rejection. The 36 valid cases send
308 responses covering both N bits, plain/Huffman names and values, 201/404/503,
static references, 103 before the final response, trailers, extended lengths,
fragmented streams, and multiplexing. Nine malformed or missing-status cases
must produce no successful samples. `--original` checks the known unfixed
Huffman-name behavior (216 valid responses fail; 92 succeed). Every client,
including a source mutant used with that flag, must expose `latencySamples`.

Fragmented responses use authenticated ACK barriers instead of sleeps to infer
receive boundaries. The next chunk is queued only after aioquic's sender has
retired the preceding bytes. Replay independently reconstructs that proof from
its authenticated 1-RTT receive events and exact emitted STREAM bytes, offsets,
and packet numbers. Wide frame type/length fields and QPACK names/values are
split. GREASE and DATA payloads contain false HEADERS that must remain ignored.
The eight concurrent streams have independent barriers. Valid streams wait for
all response bytes to be acknowledged before a separate empty FIN. A terminal
malformed field section carries FIN with its last bytes; rejection may close the
connection without acknowledging it, so the exact parser diagnostic is required.

The standard-library `h3_response_fragments.py` validator and four curated live
wire fixtures cover corrupt ACK ranges/order, cross-phase frames, altered body
bytes, early/missing FIN, wrong streams, status/sample accounting, and cleanup.
Each live case also replays precise negative controls. Every control must fail
with its expected reason; crashes, TLS failures, peer exceptions, or timeouts
cannot substitute for semantic detection. Acknowledged original bytes remain
valid proof when a later retransmission goes unacknowledged. This is not a
complete packet-loss or recovery test.

`--output` creates a new evidence file and refuses to overwrite it; `--case`
selects individual cases. Reports, independent pylsqpack decodes, authenticated
ACKs, emitted frames, writes, and cleanup results are retained even when a case
fails. CI runs all cases and uploads this evidence with `if: always()`.

The JSON output retains every client report and separate request, response
stream, and UDP payload ledgers. QUIC ACKs, packetization, and final unread
packets make UDP byte totals timing dependent. The runner checks bounded receive
accounting without equating application bytes with wire bytes. Rust worker tests
also check exact status/sample counts and independent socket byte bounds. The
full suite retains Quinn loss, reordering, replay, and sparse-ACK coverage;
these cases do not prove all QUIC recovery behavior.

These are correctness checks, not throughput evidence. Ordinary static-status
performance is measured separately with immutable clients and one fixed server.
