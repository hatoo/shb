# HTTP/3 critical peer-stream closure

The independent aioquic peer in `h3_critical_close.py` closes its control,
QPACK encoder, or QPACK decoder stream after decoding four requests. It checks
the actual io_uring client and decrypts the client's application close. QUIC,
TLS, request decoding, response encoding, and close decoding use aioquic 1.3.0.

The peer waits for acknowledgement of the stream type before sending FIN or
RESET_STREAM. A reset can discard an unsent prefix; that would exercise the
permitted absent-type case instead of closing an identified critical stream.
The fixture only observes aioquic's pinned sender offsets and never changes its
delivery or recovery state. ACK-only datagrams also trigger the readiness check.

Run against an explicit, immutable release binary:

```sh
python3 -m venv /tmp/h3-closure-venv
/tmp/h3-closure-venv/bin/pip install aioquic==1.3.0 pylsqpack==0.3.24
/tmp/h3-closure-venv/bin/python -m unittest discover -s benchmarks -p test_h3_critical_close.py -v
/tmp/h3-closure-venv/bin/python benchmarks/h3_critical_close.py \
  --shb /absolute/path/to/shb --output /new/path/critical-close.json
```

The default matrix has 24 cases: one/two workers, six stream types, and FIN/reset.
Each worker has one connection, four streams, four total requests, a two-second
request timeout, and `--batch-linger 1`. Critical closures require four errors
per worker, zero successes/samples, and peer-decrypted application close `0x104`.
Unknown, absent, and incomplete types require four status-200 responses and
four explicit latency samples per worker. All cases require complete cleanup,
exact budgets, zero connect errors, and no unexpected peer failures/reconnects.
The JSON includes raw reports, stderr, commands, close ledgers, acknowledged
prefix offsets, fixture hashes, and before/after binary identity.

`--baseline` requires the known critical-stream timeout failure (`0x10c`) while
retaining the same workload and harmless-case checks. Against master `b04b25c`,
all twelve critical cases time out; the repair rejects them with `0x104`.
Both versions pass all twelve harmless cases. Each full matrix accounts for
144 requests: 72 expected errors and 72 completions with 72 explicit samples.
These are correctness results, with no throughput or latency improvement claim.

Rust regressions cover contiguous FIN, reset before type, fragmented prefixes,
duplicate/late frames, stream/credit/final-size limits, same-batch completion
ordering, prior samples, and GOAWAY give-backs. Peer terminal events occur at most
once per advertised stream. On the tested x86-64 build each receive entry grows
from 96 to 104 bytes; shb advertises three peer unidirectional streams. Existing
io_uring close/send-buffer retirement handles delivery and cleanup.

Closure semantics follow [RFC 9114 section 6.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2)
and [RFC 9204 section 4.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2).
The fixture and bounded terminal-state design adapt hatoo/xdp-http c433 (MIT);
its QUIC implementation was originally derived from shb.
