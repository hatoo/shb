# Independent HTTP/3 request-encoding checks

The request encoder is small enough that matching an encoder with its own
decoder can miss an incorrect static index. `check-h3-request-encoding.py`
instead uses pylsqpack's table and decoder, followed by a live aioquic server.
It accepts both literal names and static-name references and asserts exact
decoded fields, rather than requiring one particular compression strategy.

```sh
python3 -m venv /tmp/shb-h3-encoding-venv
/tmp/shb-h3-encoding-venv/bin/pip install aioquic==1.3.0 pylsqpack==0.3.24
cargo build --release --locked --bin shb
cp target/release/shb /tmp/shb-encoding-client
cargo build --release --locked --example h3-request-encoding
/tmp/shb-h3-encoding-venv/bin/python benchmarks/check-h3-request-encoding.py \
  --probe target/release/examples/h3-request-encoding \
  --shb /tmp/shb-encoding-client
```

The adapter includes the production encoder source and reads JSON requests from
stdin. The Python oracle obtains the 52 distinct names from all 99 static entries
using the independent decoder. Its 437 blocks cover duplicates and ordering,
empty and UTF-8 values, unknown names, integer-length boundaries, large headers
and paths, custom methods/schemes, and content length. Each block is decoded
on three reordered stream IDs with zero dynamic capacity and no encoder-stream
instructions. This follows the static-table and field-representation rules in
[RFC 9204](https://www.rfc-editor.org/rfc/rfc9204.html#appendix-A).

Seventeen live aioquic cases each require 32 successful responses. The server
checks the exact ordered fields, waits for FIN, and validates every body byte
before returning an 11-byte response. Small receive windows force large headers
and bodies to cross flow-control updates. The final ledger checks 544 requests
and responses, 2,240,128 request-body bytes, stream IDs, and zero QPACK encoder or
decoder instructions. The output retains the complete shb JSON reports.

The Rust test `h3_static_header_names_with_body_and_reordering` independently
checks repeated standard and unknown header names and a 70 KB body through
loss, duplication, and reordering against h3/quinn. Existing recovery and
measurement-accounting tests remain part of the full suite.

These are correctness checks. They do not measure throughput or change the
production encoder. CI runs the Python oracle after the normal debug and
release suites, using pinned decoder versions.
