# Experimental skipping of irrelevant HTTP/1 fields

**Status: AWAITING_PERFORMANCE_VALIDATION. No accepted throughput claim.**

Baseline: `fede6eb60b5ca38d8141ada641d437ccfaa4e8d6`. Both timing binaries use
rustc 1.98.0, release fat LTO, one codegen unit and default mimalloc, from
separate source/target directories. Fixed ordinary server: hfast `0c093376`.
Host: x86_64 WSL2. Client CPU4; fixed peers on CPUs0,1. No additional RUSTFLAGS.

## Change

An incomplete response field is discarded once its prefix cannot match
Content-Length, Connection or Transfer-Encoding. Classification needs at most
18 prefix bytes; later receives only search for the next LF. Blank/CR-only
prefixes, status lines, recognized fields, chunk sizes and trailers preserve
their existing buffering and validation. Complete fields use the same scanner.
Request/error accounting and timestamp/latency collection are unchanged.

## Correctness

328 unit tests and 51 integration tests pass in both debug and release; two
pre-existing tests remain ignored. Rust1.91: 42 standalone parser tests pass.
Formatting, strict all-target Clippy and release builds pass. A frozen c75
parser is the oracle for split boundaries, errors, EOF, reset and metadata.
New tests cover every relevant-name byte, case folding, arbitrary bytes,
4 MiB discarded lines and large recognized fields. Native TCP/TLS workers
check GET and HEAD, eight exact completions/statuses/positive latency samples,
and fragmented 1 MiB near-matching irrelevant names. GitHub CI remains required
before any future merge; this experimental branch has no PR.

## Work and memory

Three independent instrumented runs per variant/case agree. For four 1 MiB
ignored lines in 16 KiB receives, buffer copying falls from 4,194,148 bytes to
zero, plus 72 bytes of stack-prefix assembly in the candidate. Requested
retained capacity falls from 2,094,784 bytes to zero, and one allocation plus
seven reallocations becomes zero. A bytewise near-matching name uses at most
32 bytes of capacity instead of 1 MiB. Parser size stays 72 bytes. Recognized
fields still retain their full values; this does not shrink existing capacity.

Full feed-loop Callgrind instructions decrease 92.72% for a 1 MiB ignored line
in 16 KiB receives and 33.09% in 53-byte receives. Native replay CPU falls
70.26% / 70.49% and 28.30% / 28.50%, respectively, in seven alternating pairs
and seven independent reverse-order pairs. These are parser measurements,
not end-to-end throughput gains or kernel profiles.

Costs: complete ordinary responses use +0.28% instructions and +7.95% / +3.80%
replay CPU; complete 1 KiB heads use +0.08% instructions and +6.17% / +5.77%
replay CPU. One-byte ordinary receives use +47.81% instructions and +45.78% /
+42.26% CPU. A recognized 1 MiB field uses +0.01% / +2.36% instructions at
16 KiB / 53-byte receives; its 16 KiB timing changes +3.05% / -1.95%.

All three candidate instruction runs agree. One frozen baseline case varies
466 out of 11.83 million events (0.00394%); every observation is retained.
The first architecture re-entered the parser for skipped receives and was
superseded after exposing a 53-byte-fragment instruction regression.

## Network measurements and decision

Five alternating pairs and five separate reversed-order confirmation pairs,
with a warmup before each fixed-count run and an immutable raw response peer.
Both variants always use the same workload within a comparison. The table
uses the median of paired throughput changes; CPU compares whole-process
user+system CPU medians. No observations were discarded.

| Response | Paired throughput, primary / confirmation | Client CPU, primary / confirmation |
| --- | ---: | ---: |
| Ordinary | -0.10% / +0.15% | +0.24% / +0.25% |
| 1 KiB fields | -0.08% / +0.34% | +0.09% / -0.26% |
| 64 KiB fields | +1.66% / -0.29% | +0.20% / -0.52% |
| 1 MiB fields | -11.14% / -1.07% | +1.65% / +2.31% |
| One 64 KiB ignored line | +1.37% / +1.82% | -4.02% / -3.77% |
| One 1 MiB ignored line | +5.40% / -0.50% | -22.25% / -15.64% |
| 1 MiB near-matching ignored name | +6.76% / +12.57% | -21.07% / -17.71% |
| 1 MiB recognized Connection field | +1.95% / -0.08% | -0.98% / +0.39% |

For the plain 1 MiB line, ratios of unpaired throughput medians are +7.74% /
+0.41%, but paired medians are +5.40% / -0.50%. Near-matching names improve in
all ten pairs, yet the otherwise similar plain-name case fails independent
confirmation. That discrepancy and the multi-field/ordinary costs prevent a
verified throughput claim. The implementation remains experimental.

Across raw-peer and fixed-hfast runs: 392 client processes, 9,207,808 measured
successes plus 139,264 warmup successes, zero request/connect errors. Exact
H1 received-byte counts and all status totals pass; every raw-peer connection
was also logged. H2/H3 are accounting/interoperability controls. Ordinary
fixed-hfast H1 paired medians change -3.31% / +0.46%, also inconclusive.

No new identical-binary controls, affinity sweeps or unavailable counters were
retried. Remaining verification: on a stable host, rebuild both variants
against the current default; repeat ordinary, multi-field, plain/near-matching
long-line and recognized-field comparisons, including tiny receives. Require
independent end-to-end confirmation and assess the common-path CPU costs
before opening a performance PR.

## Reproduction

Build immutable clients in separate target directories and compile the same
`h1-header-server.rs` once for both variants:

```sh
rustc --edition=2024 -O -C lto=fat -C codegen-units=1 \
  benchmarks/h1-header-server.rs -o /tmp/h1-header-server
python3 benchmarks/compare-h1-headers.py \
  /path/to/baseline /path/to/candidate /tmp/h1-header-server \
  /tmp/h1-primary.jsonl --pairs 5 --client-cpu 4 --server-cpus 0,1
python3 benchmarks/compare-h1-headers.py \
  /path/to/baseline /path/to/candidate /tmp/h1-header-server \
  /tmp/h1-confirmation.jsonl --pairs 5 --candidate-first \
  --client-cpu 4 --server-cpus 0,1
```

Use available CPUs on the host. The script exclusively creates raw JSONL with
commands, binary hashes, reports, peer logs and ratios of medians. Compute
paired differences from matching case/pair records as in the table above.
Default case counts are fixed in the script: 65,536 ordinary/1 KiB, 16,384
64 KiB, and 2,048 1 MiB requests per measured process.

The standalone `h1-headers.rs` replay harness accepts
`fields|line|near|connection header-bytes receive-bytes repetitions`. Compile
the same harness against each production parser with identical release
dependency artifacts and flags. Callgrind uses `H1_WARMUPS=0`,
`--collect-atstart=no --toggle-collect=measured_headers`; instrumentation is
separate from production. Local c77 evidence includes manifests, scripts,
raw runs, source/patch archives and `c77-performance-summary.json` under
`shb/optimization-results/`.
