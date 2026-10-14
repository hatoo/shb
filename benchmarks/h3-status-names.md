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
  --shb ./target/release/shb > qpack-results.json
```

There are 41 cases: 33 valid and eight expected failures. The valid cases send
284 responses covering both N bits, plain/Huffman names and values, 201/404/503,
static references, 103 before the final response, trailers, extended lengths,
fragmented streams, and multiplexing. Malformed lengths/values and missing or
similar names must not produce successful samples. `--original` checks the
known unfixed behavior: 192 valid responses fail across 17 cases, while 92
succeed. It does not excuse other failures.

The JSON output retains every client report and separate request, response
stream, and UDP payload ledgers. QUIC ACKs, packetization, and final unread
packets make UDP byte totals timing dependent. The runner checks bounded receive
accounting without equating application bytes with wire bytes. Rust worker tests
also check exact status/sample counts and independent socket byte bounds. The
full suite retains Quinn loss, reordering, replay, and sparse-ACK coverage;
these cases do not prove all QUIC recovery behavior.

These are correctness checks, not throughput evidence. Ordinary static-status
performance is measured separately with immutable clients and one fixed server.
