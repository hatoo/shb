# QUIC Retry correctness contracts

`check-quic-retry.py` runs the release client against an independent aioquic
1.3.0 HTTP/3 server. Five fixed schedules check Retry tokens, CRYPTO retransmission,
packet ordering and exact request/status/latency-sample accounting. This is a
correctness gate; it makes no throughput claim or claim about general QUIC recovery.

```sh
python3 -m venv /tmp/quic-retry-venv
/tmp/quic-retry-venv/bin/pip install aioquic==1.3.0
cargo build --release --locked
python3 -m unittest discover -s benchmarks -p 'test_quic_retry.py' -v
/tmp/quic-retry-venv/bin/python benchmarks/check-quic-retry.py \
  --shb ./target/release/shb --output /tmp/quic-retry.json
```

The output file must be new. Without `--output`, JSON goes to stdout. Repeat
`--case NAME` to select schedules. Each schedule uses one worker, one connection,
four concurrent requests and exactly 32 successful GETs, HTTP 200 statuses and
latency samples. The peer independently requires one handshake, unique stream
IDs, complete request FINs and one response per request.

| Schedule | Required wire behavior |
| --- | --- |
| no-retry | Empty Initial tokens, no Retry sent, all received Initials delivered. |
| retry | Exactly one authentic Retry; every later Initial repeats its exact 256-byte token, with unchanged ClientHello CRYPTO bytes. |
| drop | Discard the first post-Retry Initial; a later packet number retransmits the same CRYPTO before completing all requests. |
| reorder | Hold that Initial until its replacement arrives, then deliver the replacement followed by the original. |
| forged-second | Send an invalid-integrity Retry with a different token before the authentic Retry. Before answering the accepted Initial, send another valid-integrity Retry with a different CID/token. The client must retain the first authentic token. |

Initial payloads are decrypted by aioquic and recorded as CRYPTO offsets, lengths
and SHA-256 digests. The received packet and actual delivery ledgers share a
sequence counter with sent Retries. The first post-Retry flight targets the Retry
CID; a new server CID after the server answers is valid. Reordering must be proved
by the delivery ledger, and a dropped packet must never be delivered later.
The forgery has a different token so accepting it cannot hide behind a later
authentic Retry with the same token. A short delay only orders the two sends; it
is not a latency assertion or a timing benchmark.

`quic_retry.py` validates recorded evidence using only the standard library.
Every successful live schedule also runs precise negative controls against copies
of its ledger: missing/extra samples, wrong budget/statuses, duplicate requests,
missing responses or CRYPTO, wrong token/CID/packet number, missing/reordered
deliveries, absent impairment, incorrect forgery and incomplete cleanup. Each
must fail for its own semantic reason. A crash, TLS failure, callback exception,
unrelated validation error or disabled validator cannot count as detection.
These controls modify evidence, not the client executable.

The five small replay fixtures contain only fields consumed by the validator
from successful encrypted runs of the accepted client; their metadata records
the revision and binary hash. The 14 unit tests replay all 101 controls and
exercise their failure handling. Live CI runs regenerate evidence without
loading the fixture. CI retains JSON, including failures, as an artifact.

Each client has a 20-second process deadline and each cleanup wait is bounded by
5 seconds. Failure paths retain client output, report, wire ledgers and callback
errors. Cleanup kills/reaps an unfinished client, cancels delayed Retry callbacks,
closes peers and the UDP server, and cancels aioquic timer handles. A successful
run requires all peers closed and the original event-loop handler restored.

Rust tests add 192 scalar header cases across token varint boundaries, CID sizes,
packet-number widths and Initial/Handshake spaces. Another 25 encrypted schedules
cover forged/second Retry rejection, PTO, unchanged tokens, empty-output rollback
and out-of-order ACKs; a separate coalescing test ensures the token cannot leak
into a Handshake header. These tests run on the existing owned-token runtime.
