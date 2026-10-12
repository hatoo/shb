# Bounded QUIC ACK storage

`AckState` previously capped serialized ACKs at 32 ranges but retained every
received range until ACK-of-ACK. Increasing sparse packet numbers therefore
made storage grow with connection history and each newest insertion move the
entire vector. The new policy evicts the oldest range before inserting a 33rd.
The independent `ReceivedPackets` history still rejects duplicates, including
numbers below its monotone receive floor. Gaps, ACK eligibility, ACK delay,
packet-number reconstruction and request accounting retain their behavior.

This follows [RFC 9000 section 13.2.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2.3):
discarding ACK ranges is permitted when those packet numbers cannot be accepted
again. Discarded acknowledgments can cause retransmission after severe
reordering, but retransmitted data in new packets remains usable. Ordinary
in-order traffic retains one range.

## Evidence

Experiment c133, 2026-10-12, WSL2. Baseline: shb `f9809af`.
Matched standalone production release builds use default features, fat LTO and
one codegen unit. The fixed native peer derives from hfast `d710d80`.

For 65,536 increasing even packet numbers with no ACK-of-ACK:

| Metric | Baseline | Candidate |
| --- | ---: | ---: |
| Stored ranges | 65,536 | 32 |
| Vector capacity in bytes | 1,048,576 | 512 |
| Range entries moved by insertion | 2,147,450,880 | 2,031,120 |
| Serialized ranges | 32 | 32 |

Counts instrument the actual range algorithms in disposable sources, including
the receive-history gate. They exclude allocator-internal copying. No timing
from instrumented or test builds is used as production throughput evidence.

The network workload performs eight sequential HTTP/3 requests per measured
run. Before each response, the native peer sends 65,536 sparsely numbered
packets. The last packet in each batch also contains PING; the others contain
only a frozen ACK of the request. The peer verifies **every** injected packet
in the client's wire ACKs before advancing. It deliberately withholds ACK-of-ACK
within the burst, then returns the normal complete HTTP response.

| Series | Batch | Paired request-throughput changes | Median client CPU change |
| --- | ---: | --- | ---: |
| Primary, alternating order | 32 | +135.961%, +135.720%, +131.915% | -64.308% |
| Confirmation, reversed order | 16 | +98.065%, +99.071%, +95.053% | -57.213% |

Each series has three independent pairs, each preceded by a smaller warmup.
Baseline and candidate use identical workloads within a series. Across both
series: 120 exact HTTP successes including warmups, 6,389,760 verified sparse
packets, zero errors. These rates describe the controlled sparse-history case;
they do not establish a gain for ordinary small GETs.

Ordinary guards keep production hfast `d710d80` fixed: three alternating pairs
each at c1/p1 and c16/p64, 14,352,384 successes including warmups, zero errors.
Median throughput changes are +0.409% and +0.041%; c16/p64 pairs are mixed
(-1.064%, +0.467%, +0.041%). These small WSL effects establish neither an ordinary
throughput gain nor equivalence. No repeated identical-binary controls or
affinity sweeps were run.

Five storage/set/wire regressions fail on the baseline. The candidate adds those
five tests plus two protected-packet tests covering all packet-number spaces,
ACK-of-ACK, duplicate suppression, delayed stream suffixes and new-number
retransmissions. A set oracle covers 24,000 events. Debug, release, Rust 1.91
and musl each pass 483 unit tests and 62 integration tests, including independent
Quinn loss/reordering/replay tests; two existing tests remain ignored. Format
and Clippy pass. This is not a claim of complete QUIC recovery verification.

## Reproduction

Build both shb revisions in separate clean target directories using
`CARGO_INCREMENTAL=0 cargo build --release --locked`. Copy the executables to
immutable paths. Do not use binaries produced by `cargo test`, whose development
dependencies can change unified features. Verify the matching release inputs:

```sh
python3 benchmarks/check-release-inputs.py \
  /path/to/baseline-target/release /path/to/candidate-target/release \
  /new/matched-builds.json
python3 benchmarks/build-ack-storage-peer.py /path/to/hfast /new/peer-build
python3 benchmarks/compare-ack-storage.py \
  /path/to/baseline-shb /path/to/candidate-shb /new/peer-build/sparse-peer \
  /new/smoke-results smoke
python3 benchmarks/compare-ack-storage.py \
  /path/to/baseline-shb /path/to/candidate-shb /new/peer-build/sparse-peer \
  /new/primary-results primary
python3 benchmarks/compare-ack-storage.py \
  /path/to/baseline-shb /path/to/candidate-shb /new/peer-build/sparse-peer \
  /new/confirmation-results confirm
```

The peer builder needs Python 3.12+, Cargo and a local hfast repository containing
the pinned revision. It reads the Git archive, preserves all hfast working-tree
changes, and compiles only a disposable copy. The comparison needs `/usr/bin/time`
and `taskset`, and pins the peer/client to CPUs 6/8. Adjust those affinities
consistently on hosts where these CPUs are unavailable. Every output filename is
created exclusively; use a new output directory for another run. The comparison
records commands, binary hashes, exact success/status counts, CPU, RSS, timings,
and peer delivery assertions. Keep raw output out of Git.
