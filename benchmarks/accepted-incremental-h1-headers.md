# Incremental HTTP/1 response headers

Baseline: `5b8846c59e281559276c641b4fd96e1a62a05ead` (merged latency selection).
Candidate: this change. Compiler: rustc 1.98.0, x86_64 Linux under WSL2,
release fat LTO / one codegen unit / default mimalloc, no additional RUSTFLAGS.
Scope: large fragmented HTTP/1 response headers. No general throughput claim.

## Implementation

Retain framing metadata from complete lines, and buffer only an incomplete
line. Search only new bytes for that line's newline; after finishing it, parse
the rest of the receive directly. Every completed field is interpreted once.
Status and connection metadata retain their original visibility boundary;
invalid complete fields still fail before the final header delimiter arrives.
Request accounting and latency collection are unchanged.

## Fixed-peer measurements

One immutable `h1-header-server.rs` binary served both immutable clients.
One client connection and thread on CPU4; peer on CPUs0,1. Five alternating
pairs plus five separately executed reverse-order confirmation pairs. Each
client has a warmup run before its measured fixed-count run. The peer builds
one response buffer at startup and reuses it. Sizes are approximate; the
actual wire sizes below are checked against every client's bytesReceived.

Each series has 1,515,520 measured successes and 35,840 warmup successes;
all request/status/byte totals match, with zero request/connect errors.
Ratios below compare medians within the same workload and series.

| Response | Wire bytes | Requests/run | Throughput, primary / confirmation | Client CPU, primary / confirmation |
| --- | ---: | ---: | ---: | ---: |
| Ordinary | 52 | 65,536 | -0.16% / +0.03% | +0.15% / -0.27% |
| 1 KiB fields | 1,024 | 65,536 | -0.23% / -0.56% | -0.17% / +0.46% |
| 64 KiB fields | 65,500 | 16,384 | +15.45% / +15.34% | -22.07% / -21.82% |
| 1 MiB fields | 1,048,570 | 2,048 | +981.25% / +976.93% | -92.32% / -92.49% |
| One 1 MiB line | 1,048,589 | 2,048 | +56.98% / +52.77% | -44.08% / -44.58% |

All ten pairs improve for each of the three large cases. Paired gains range
13.01–17.34%, 863.29–1088.85%, and 40.93–74.41%, respectively. These gains exceed
the known host noise; they do not establish that WSL is suitable for small
effects. Ordinary/1 KiB changes are inconclusive and the blocking raw peer
limits their rate. Client CPU is whole-process user+system CPU, including
startup/reporting; throughput is shb's reported measurement interval.
The peer's EOF-only telemetry can miss its last connection when terminated;
client exact counts/bytes and separate native worker tests are the accounting
checks. No timing observation was discarded for incomplete peer telemetry.

The unchanged merged hfast server (`dcb83ef`) also serves H1/H2/H3 correctness
runs: 5,505,024 measured successes plus 28,672 warmup successes, zero errors.
Its ordinary H1 throughput changes +6.41% in five pairs and -0.17% in a separate
five-pair confirmation with mixed directions. This does not establish an
ordinary-request speedup or resolve the known small-effect measurement limits.

## Work, memory and costs

Three independent count runs and three Callgrind runs per selected case agree
exactly. Unchanged immutable baseline counts were reused when the final metadata
layout was measured; both variants were rerun for every final timing pair. Callgrind measures the complete feed loop and includes cold parser
allocation, but excludes input construction and kernel work. Instrumented
copy/search counts come from separate builds. Requested capacities are not RSS.

For 1 MiB fields in 16 KiB receives: explicit copying 1,048,570 -> 3,402 bytes,
retained capacity 1,048,576 -> 78 bytes, field visits 631,076 -> 19,419, and
instructions -96.94%. For 64 KiB fields: copies 65,500 -> 162 bytes, capacity
65,536 -> 78, instructions -67.77%. With 1 KiB fields, instructions decrease
56.84% for 53-byte receives and 90.74% for one-byte receives.

Costs must accompany the gain:

- Parser size increases from 48 to 72 bytes on the tested compiler.
- A complete ordinary response costs 6.06% more replay instructions and
  3.00% / 6.54% more replay CPU in the two seven-pair series (about 48–51 -> 51–53 ns).
  A complete 1 KiB header costs 2.38% more instructions; its replay CPU changes
  -1.77% / +0.82%, so no small timing claim is made.
- A single 1 MiB line still needs retention. With 16 KiB receives its Vec capacity
  increases from 1,048,576 to 2,094,784 bytes because the initial fragment is
  shorter and subsequent growth doubles it. Search work falls from 34,078,720
  to 2,097,113 logical bytes; the change is not a universal memory reduction.
- 64 KiB/1 MiB one-byte-receive instruction audits were not run: the quadratic
  baseline is prohibitively expensive under instrumentation. Larger cases use
  53-byte/16 KiB receives; one-byte behavior is measured on short headers.

## Correctness

Frozen pre-change parser oracle; every three-part split of 26 wire fixtures
in GET and HEAD mode; seeded large pipelines; long status/header/chunk/trailer
lines; error timing, EOF and reset checks. Native TCP and TLS workers each run
GET and HEAD with exactly eight successes, eight positive latency samples and
expected statuses. The same worker tests pass against the baseline parser.

Full debug and release: 323 unit tests plus 51 integration tests pass per profile,
with two existing ignored tests. Rust1.91 HTTP/1 tests: 39 pass. Strict all-target
Clippy, formatting and release build pass. Container interoperability is gated
by the required GitHub `ci` check. General QUIC loss recovery remains outside
this change's claim.

## Reproduction

Build baseline and candidate in separate source and target directories, using
identical compiler/settings. Copy the release binaries to immutable paths.
The server requires only the standard library:

```sh
rustc --edition=2024 -O -C lto=fat -C codegen-units=1 \
  benchmarks/h1-header-server.rs -o /tmp/h1-header-server
python3 benchmarks/compare-h1-headers.py \
  /path/to/shb-baseline /path/to/shb-candidate /tmp/h1-header-server \
  /tmp/h1-primary.jsonl --pairs 5 --client-cpu 4 --server-cpus 0,1
python3 benchmarks/compare-h1-headers.py \
  /path/to/shb-baseline /path/to/shb-candidate /tmp/h1-header-server \
  /tmp/h1-confirmation.jsonl --pairs 5 --candidate-first \
  --client-cpu 4 --server-cpus 0,1
```

Use available CPUs on the test host. Outputs are exclusive-created JSONL files
with binary hashes, commands, all raw client reports, peer logs and summaries.
Do not run competing benchmarks/builds during measurements.

`h1-headers.rs` is the standalone full-parser replay harness. Compile an identical
copy against each revision's parse.rs using `rustc --edition=2024 -O -C lto=fat
-C codegen-units=1`, the release dependency directory (`-L dependency=...`), and
`--extern` paths for anyhow, memchr, libc and mimalloc. The path attribute selects
the tested production parser. Arguments are `fields|line header-bytes
receive-bytes repetitions`; output reports exact completions, parser size and
process CPU/wall time. Three warmups are the default. For deterministic events,
set `H1_WARMUPS=0` and run Callgrind with `--collect-atstart=no
--toggle-collect=measured_headers`. Counting instrumentation is kept in the
local c75 evidence rather than production code.

Detailed local evidence: shb/optimization-results/c75-record.md,
c75-v3-performance-summary.json, c75-v3-network-{primary,confirmation}.jsonl,
c75-v3-counts-results.json, c75-v3-instruction-summary.json and build manifests.
