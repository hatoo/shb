# HTTP/2 literal Huffman status names

A server may encode `:status` as a literal name using HPACK's fixed Huffman
code. Previously, shb skipped that name and reported the otherwise valid
response as a failed request. The decoder now compares the five encoded bytes
directly. It allocates no string and keeps the indexed-name path intact.

This is a correctness repair, with no throughput improvement claimed.
[RFC 7541 sections 5.2 and 6.2](https://www.rfc-editor.org/rfc/rfc7541.html#section-5.2)
permit Huffman string literals for both names and values. Appendix B defines
one code; the encoded `:status` name is `b8 84 8d 36 a3`.

## Independent reproduction

The peer uses python-hpack's Huffman encoder and full decoder, with a zero
dynamic table. It forces literal names rather than letting an encoder choose
the usual static name reference. It validates every request and checks the
client's statuses, success/error totals, presence of latency data and exact
TCP byte totals. Teardown GOAWAY bytes are outside shb's reported send scope.

```sh
python3 -m venv /tmp/h2-status-venv
/tmp/h2-status-venv/bin/pip install hpack==4.1.0
/tmp/h2-status-venv/bin/python benchmarks/check-h2-status-names.py \
  --client /path/to/fixed-shb --out /tmp/fixed-status-results.json
# The parent revision's binary reproduces the unsupported representation:
/tmp/h2-status-venv/bin/python benchmarks/check-h2-status-names.py \
  --client /path/to/parent-shb --expect-unsupported \
  --out /tmp/parent-status-results.json
```

There are 59 cases: 51 valid responses and eight deliberately invalid ones.
The parent fails 32 valid Huffman-name cases; the fixed binary passes all 51
valid cases and retains all eight expected failures. Both independent fixed
runs reproduced this result. Plain and Huffman values, all three literal
representations, 201/404/503, indexed 200, informational 103, trailers and
HEADERS/CONTINUATION fragments are covered. Similar names and malformed input
must never become successful status responses. Ignored-field validation and
dynamic-table policy are unchanged.

## Rust regression coverage

Seven tests cover the two string encodings, all literal representations,
malformed input, every header-block and transport split, and TCP/TLS worker
accounting. The workers require exact status counts, wire byte totals, one
latency sample per completed response and no sample for a malformed response.
Informational responses and trailers do not change the final status.

Two new regressions fail against the original implementation. All 496 unit
tests and 62 executable tests pass in debug, release, Rust 1.91, musl and
without default features; the two pre-existing ignored tests remain unchanged.
Formatting and strict all-target Clippy pass. An independent hyper-h2 peer also
passes fragmented/coalesced large responses over TCP and TLS on both binaries.

## Ordinary HTTP/2 regression measurements

Immutable release builds (Rust 1.98.0, fat LTO, one codegen unit, default
features), fixed hfast `d2de04a`, one worker each, server/client CPUs 1/8.
Each run warmed up for 16,384 requests, then measured 2,097,152 requests.
Three alternating pairs were followed by three independently reversed pairs.
These ordinary indexed responses do not exercise the repaired representation.

| Workload | Primary median RPS change | Reversed median RPS change |
| --- | ---: | ---: |
| H2, 1 connection, 128 streams | +0.190% | +0.489% |
| H2, 128 connections, 1 stream | -0.009% | -2.229% |

All 50,331,648 measured and 393,216 warmup responses succeeded, with identical
paired send/receive byte totals and status counts. Every latency quantile and
CPU measurement was retained. Timing remains inconclusive in WSL2: for example,
c1p128 p99 increased 2.526% / 8.850% and p99.9 increased 5.881% / 1.093%; c128p1
p99 changed -0.967% / +2.612%. No speedup, latency equivalence, or confirmed
global regression is claimed. No controls, exclusions, affinity sweeps or lower
acceptance threshold were used. The reproducible result is the repaired
representation and its exact accounting, not a throughput improvement.
