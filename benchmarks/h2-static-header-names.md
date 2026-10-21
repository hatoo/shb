# Static HPACK request header names

Verified candidate c178 (GitHub CI is the merge gate). Replace each spelled-out standard header name with its
RFC 7541 static-table name reference, while keeping the caller's value plain.
The request block is prepared once and reused for every request. The peer's
dynamic table stays empty. Unknown names retain their literal representation.

For `GET http://127.0.0.1:18778/` with accept, accept-encoding, accept-language,
cache-control, content-type, cookie, user-agent and referer, the representative
block in the experiment shrinks from 235 to 151 bytes. The savings equal the
sum of those eight name lengths, 84 bytes per request. Ordinary GETs without
custom headers and requests with unknown names have identical bytes. Smaller
blocks alone do not establish a throughput gain.

The actual encoder is exposed by a JSON-lines probe. Its independent Python
oracle checks all 52 unique static names, duplicate order, empty and UTF-8
values, unknown names and long blocks. It decodes each block three times with
zero dynamic-table capacity. Live hyper-h2 cases check exact ordered headers,
32 requests each, full bodies, CONTINUATION frames, table-size reduction and
all transmitted/received bytes (the separately validated teardown GOAWAY is
outside the measured interval). A corrupt static-name index must fail the
oracle even when the resulting HPACK remains syntactically valid.

```sh
cargo build --release --locked --example h2-request-encoding
cargo build --release --locked --bin shb
python3 -m venv /tmp/h2-name-oracle
/tmp/h2-name-oracle/bin/pip install hpack==4.1.0 h2==4.3.0
/tmp/h2-name-oracle/bin/python benchmarks/check-h2-request-encoding.py \
  --probe target/release/examples/h2-request-encoding \
  --shb target/release/shb
```

For timing, freeze production-only baseline and candidate executables built
separately with `--bin shb`. Building examples/tests in the same command can
unify extra dependency features and invalidate a comparison. Keep the server
fixed, run equal counted workloads, verify client and decoder-peer totals,
warm both variants, alternate pairs, and confirm in a separate reversed-order
series. Preserve every latency field, error, status and byte count.

Reference: [RFC 7541 Appendix A](https://www.rfc-editor.org/rfc/rfc7541.html#appendix-A)
and [literal fields without indexing](https://www.rfc-editor.org/rfc/rfc7541.html#section-6.2.2).

## Counted decoding-peer results

WSL2 6.18.54.1, Ryzen 9 3950X, Rust 1.99.1, Node 20.20.2/nghttp2 1.61.0.
One client worker on CPU 8, Node on CPU 0, 16 connections and 64 streams per
connection. Both executables use default features, fat LTO, one codegen unit,
and the same release compiler settings. Baseline: `b8766f9`.

The eight-header workload uses the exact fields in `h2-header-workloads.json`.
After 32,768 warmup requests per variant, three alternating pairs of 131,072
requests each gained a median **32.91% RPS**. An independent reversed-order
series with 262,144 requests per sample gained **33.29%**. All six pairs gained
29.61–37.86%; median server CPU/request fell **24.84%** in both series. Client
CPU/request fell 4.81%/6.01%. Mean latency fell 24.73%/24.94%; p99 fell
26.79%/38.41% and p99.9 fell 7.89%/25.57%. This is a result for this decoding
server and header workload, not a universal client-throughput claim.

Ordinary requests (identical bytes) had a median +0.06% RPS with individual
pairs from -9.04% to +9.98%. Unknown names (also identical bytes) had median
-2.42%, ranging -2.52% to +5.56%. These controls show the noise that prevents
small-effect claims here. An exploratory 44-name stress workload reduced its
block from 686 to 196 bytes and gained 107.37%, without independent confirmation;
its p99.9 was mixed. It is not the acceptance workload.

All 5,046,272 decoder-peer requests across these five series, including
warmups, matched client counts with zero errors, verified header values and
all sessions closed. Every common-header pair saved exactly 84 bytes/request.
The JSON output retains every latency percentile and min/max, including noise.

To reproduce after freezing both production binaries:

```sh
python3 benchmarks/compare-h2-header-names.py \
  --baseline /absolute/path/shb-baseline --candidate /absolute/path/shb-candidate \
  --output /tmp/h2-names-primary.jsonl --workload common --requests 131072
python3 benchmarks/compare-h2-header-names.py \
  --baseline /absolute/path/shb-baseline --candidate /absolute/path/shb-candidate \
  --output /tmp/h2-names-confirm.jsonl --workload common --requests 262144 --reverse
```

The driver refuses to overwrite output, hashes binaries/fixtures, validates
peer/client totals after every run, and retains complete reports. Choose fixed
available cores with `--client-cpu` and `--server-cpu` on other machines. Run
`ordinary` and `unknown` guards with the same configuration.

## Fixed hfast and protocol guards

With hfast production fixed at `ba937ac` (production-equivalent to the current
`589a7c7` test-only default), the same eight-header workload observed median
+10.19%/+6.95% RPS in alternating/reversed series and -8.82%/-6.03% client
CPU/request. Each sample completed 2,097,152/4,194,304 requests. hfast does not
decode these request fields, so this is supporting wire/copy evidence rather
than the decoding-server acceptance result.

Ordinary hfast H1/H2 guards had +1.50%/+1.48% median RPS, below the confidence
needed for a speed claim. An initial H3 guard lasted only about 0.5 seconds
per sample and showed -8.71%; reversed short confirmation changed to +2.68%.
The one targeted duration correction, 16,777,216 counted requests per sample
(about eight seconds), gave +10.04%, with all three pairs positive. No H3 code
changed and these unstable guard results establish no H3 gain or consistent
regression. No affinity sweep or repeated identical-binary retry was used.

Across all Node and hfast comparison/guard series, 181,665,792 responses
including warmups completed with zero errors. The independent oracle adds
544 responses per binary; the published-driver smoke adds 32,768. Every full
report remains in local c178 evidence. General QUIC loss recovery was not
revalidated by these ordinary guards.

Correctness: 513 unit and 62 integration tests pass in both debug and release;
strict all-target Clippy and rustfmt pass. The independent oracle passes 453
raw request blocks and 17 live cases per binary, including 2,240,128 body bytes.
It rejects a mutated reference from static name 15 to 16. CI runs this oracle
with pinned python-hpack 4.1.0 and hyper-h2 4.3.0.
