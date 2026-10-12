# QUIC send-buffer prefix cursor

`SendStream::on_acked` used to drain the acknowledged prefix of its `Vec`,
moving every remaining byte after each packet-sized ACK. A fully buffered
large upload therefore did quadratic copying. The cursor releases that prefix
logically. Writes compact only when the released prefix is at least as large
as the live suffix, so the total compaction work is bounded by released bytes.
Empty buffers clear immediately. Stream offsets, flow control, retransmissions,
FIN/reset handling, pooling, and the existing conservative sparse-ACK policy
are unchanged. HTTP/3's separate unsent request buffer is unchanged.

The send state grows from 80 to 88 bytes on x86-64. A rolling partial-ACK/append
workload can retain additional prefix capacity: the regression with a constant
4 KiB live window is bounded by 8 KiB capacity. A complete prebuffered upload
needs no buffer growth during ACK processing.

## Correctness

Seven focused regressions cover stable retransmission bytes after ACK, appending
after compaction, 1/1024/65536-byte progress, zero connection credit, sparse and
duplicate ACKs, overlapping late loss, exact FIN, resets, and pooled reuse.
The no-move assertion fails on the original implementation; the other six
behavioral tests pass on both. An independent Quinn test verifies patterned
bodies after loss and late duplicates with a large stream window and small
connection window. All latency/status/request/error counts remain asserted.

434 unit tests and 57 end-to-end tests pass in both debug and release, with two
pre-existing ignored tests. Formatting and strict all-target Clippy pass. Rust
1.91 and musl each pass 151 QUIC tests plus nine independent credit/recovery
tests. A separate generated replay matches the original SendStream's bytes,
offsets, credit, pending/settled state and reset sizes across 1,048,576 events.

## Fixed peer prerequisite

The original locked test dependency, quinn-proto 0.11.17, rejects 2,049 buffered
contiguous chunks as "too many gaps in stream buffer". A standalone replay
reproduces this after 2,359,296 contiguous bytes without shb or sockets; 0.11.19
accepts and reads the same 8,064,000 bytes. This is the documented
[upstream contiguous-chunk fix](https://github.com/quinn-rs/quinn/pull/2826).

The lockfile updates only this development dependency to 0.11.19. It does not
change the production client binary or its dependency fingerprints. Initial
network measurements using the old peer failed correctness and are excluded.
Every accepted comparison uses the same immutable 0.11.19 peer for both clients,
with the original body, windows, concurrency, counts and CPU affinity.

## Reproduction

Use isolated baseline and candidate worktrees and production target directories.
Build each with `CARGO_INCREMENTAL=0 cargo build --release --locked`, copy the
CLI to an immutable path, and compare the inputs using:

```sh
python3 benchmarks/check-release-inputs.py BASE_RELEASE CANDIDATE_RELEASE NEW_MANIFEST.json
```

Build the independent peer from the updated development lockfile, in a separate
target directory using `cargo test --release --locked --no-run`, then:

```sh
python3 benchmarks/build-h3-timeout-peer.py TEST_RELEASE \
  benchmarks/h3-request-body-peer.rs NEW_PEER NEW_PEER_MANIFEST.json
python3 benchmarks/compare-h3-request-bodies.py \
  --baseline BASE_CLI --candidate CANDIDATE_CLI --hfast FIXED_HFAST \
  --peer NEW_PEER --output NEW_RESULTS --cases benchmarks/quic-send-buffer-cases.json \
  --build-manifest NEW_MANIFEST.json --phase primary --prefix send-buffer --pairs 3
# After completion, repeat with --phase confirmation (reverses case/pair order).
```

Pass absolute paths. The runner verifies every complete patterned body before
200, exact request/status counts, zero unexpected errors, and latency reporting.
CPU measurements include the client's entire process lifetime. Each measurement
has a warmup. No builds or other measurements may overlap these comparisons.

The native replay compiles the actual production SendStream. Its separate count
binary instruments only explicit prefix compaction; do not use count timings:

```sh
python3 benchmarks/build-quic-send-buffer.py SOURCE_TREE PROD_RELEASE NEW_REPLAY_DIR
taskset -c 2 NEW_REPLAY_DIR/replay-count 8388608 1200 1
taskset -c 2 NEW_REPLAY_DIR/replay-native 8388608 1200 2
```

One fully buffered 8 MiB request, acknowledged in 1200-byte pieces, moves
29,316,115,920 prefix bytes on the original code and zero with the cursor.
The 1 MiB case moves 457,605,648 bytes versus zero. These deterministic counts
exclude required QUIC storage and packet construction and are not network
throughput claims.

## Complete-body network results

Baseline shb `89ccdb8`, fixed hfast `f99083b`, Rust 1.98.0, release fat LTO,
one codegen unit, default mimalloc, WSL2 6.18.40.1. Production compiler, flags,
profile, features and dependency fingerprints match. Client: CPU 2, one worker;
fixed peer: CPUs 0/1. Three alternating pairs, then three independent reversed
pairs, with warmups. Bodies are the named size plus seven bytes, using identical
deterministic data. The complete case definitions are in the adjacent JSON.

| Workload | Primary median RPS change | Confirmation | Client CPU change, both series |
|---|---:|---:|---:|
| 8 MiB, c1/p1, 16 MiB stream window | +1597.019% | +1710.798% | -96.878% / -97.037% |
| 8 MiB, c1/p8, 16 MiB stream window | +6124.140% | +5909.113% | -99.231% / -99.195% |
| 1 MiB, c1/p8, 16 MiB stream window | +144.870% | +149.761% | -80.554% / -80.982% |
| 1 MiB, c1/p8, 64 KiB stream window | -0.518% | -4.100% | -8.039% / -0.683% |
| 1 MiB, c1/p8, 2 KiB stream window | -2.781% | -1.242% | +1.348% / -0.551% |
| GET, c1/p1 | +0.574% | +1.377% | -0.874% / -1.426% |
| GET, c16/p128 | -0.734% | +0.504% | +0.884% / -0.336% |

Accept the fully buffered large-upload improvement. All six pairs for each of
the first three cases improve; the smallest 1 MiB gain is 135.577%. There is no
speed or equivalence claim for the remaining cases: the constrained-window
results vary in sign, and small effects remain unreliable on this WSL host.
The 64 KiB-window RPS deltas range from -14.089% to +13.781%.

The accepted primary and confirmation runs total 13,568,172 successes including
warmups, zero unexpected errors, and 5,234,506,932 independently validated body
bytes. Results apply to these workloads, not general HTTP/3 throughput or maximum
server capacity. Local raw reports, immutable build manifests, exclusions and
replays are indexed by `shb/optimization-results/c121-record.md` in the workspace.
