# Bound HTTP/3 GSO messages by the UDP payload ceiling

Sending 64 full QUIC datagrams in one UDP_SEGMENT message creates a 76,800-byte
payload. Linux rejects it with EMSGSIZE before sending any segment. The client
previously discarded that whole batch as if it were a failed path-MTU probe,
then waited for QUIC loss recovery. Cap the segment count by 65,507 divided by
the first segment's size before asking QUIC for further packet numbers. The
IPv4 ceiling is safe on IPv6 too; plain sends, shorter tails, the oversize
fallback, and the two-datagram PTO limit retain their existing behavior.

The Linux limit also applies with GSO: see
[__ip_append_data](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_output.c).
A direct loopback check confirmed IPv4 65,507 bytes succeeds /65,508 fails;
IPv6 65,527 succeeds /65,528 fails; 76,800 fails on both.

## Correctness

Four real-kernel tests use the production packet builder and io_uring SendMsg.
They decrypt every delivered packet, verify sequential packet numbers through
a width transition, exact 320,003-byte stream offsets/data and one FIN over
multiple batches, on IPv4/IPv6 and in probe/plain-send modes. The three GSO
cases fail on the original code with 76,032/76,160-byte messages. All four pass
with the cap. Existing independent Quinn tests cover patterned bodies, credit,
loss, reordered duplicates, STOP/reset, timeouts, and exact accounting.

365 unit +55 end-to-end tests pass in debug and release (two existing ignored).
Rust 1.91 passes 42 HTTP/3 tests and eight independent credit tests. Formatting
and strict all-target Clippy pass.

## Matched production measurements

WSL2 6.18.40.1, Rust 1.98.0, default mimalloc, release fat LTO/one codegen unit.
Baseline fe5b09e (production source identical to 71ce291), fixed hfast 074d9f6.
Compiler/profile/flags/features/transitive dependency fingerprints match.
CLI binaries were preserved before building test dependencies. One client worker
on CPU2, fixed peer on CPUs0/1, identical counts/windows/bodies, per-run warmups.
Three alternating pairs followed by three independently reversed pairs.

| Workload | Primary median RPS delta | Confirmation | Interpretation |
|---|---:|---:|---|
| get-c1-p1 | -1.249% | +1.158% | inconclusive |
| get-c16-p128 | -2.960% | +0.420% | inconclusive |
| post64K-p8 | +3.391% | +0.213% | inconclusive |
| blocked1M-p8 | -0.358% | +0.715% | inconclusive |
| blocked1M-p64 | +57.652% | +44.172% | confirmed for this workload |

All six blocked1M-p64 pairs improve: +34.618% to +60.786%. Client CPU changes
by -10.509% /+0.247% in the two series. No general throughput or
equivalence claim for other workloads. This case uses 128 requests, 64 parallel
streams, 1,048,583-byte nonrepeating bodies, 2,048-byte stream receive windows,
and a 16 MiB connection window. The independent Quinn peer validates every body
before returning 200. 13,592,736 measured/warmup successes, zero unexpected
errors, and 2,214,607,296 independently validated body bytes across accepted runs.

The first confirmation attempt overlapped a reproduction-only peer compilation.
The entire attempt is excluded, including favorable pairs. A separate clean
reversed confirmation is the one shown above. No A/A or affinity sweeps.

Separate diagnostic traces show default/fixed p64 lost packets 5,795/21,
PTOs 82/5, retransmitted stream bytes 6,638,487/12,661. Instrumented timings are
not performance evidence. The fixed trace still encounters receive-buffer
exhaustion; this change does not claim to eliminate all packet loss.

## Reproduction

Create isolated baseline and candidate worktrees and separate release targets.
Build each CLI with `CARGO_INCREMENTAL=0 cargo build --release --locked`, setting
`CARGO_TARGET_DIR` separately. Copy both binaries to immutable paths. Use
`benchmarks/check-release-inputs.py BASE_RELEASE FIX_RELEASE NEW_MANIFEST.json`
to verify matching inputs. Build hfast revision 074d9f6 as the fixed control peer.

In a third target directory, run `cargo test --release --locked --no-run` to
build locked dev dependencies. Then build the byte-checking peer:
```sh
python3 benchmarks/build-h3-timeout-peer.py /absolute/peer-target/release \
  /absolute/candidate/benchmarks/h3-request-body-peer.rs \
  /absolute/quinn-peer /absolute/peer-build.json
```

Run both orders, using absolute paths for binaries/artifacts and a new output prefix:
```sh
python3 benchmarks/compare-h3-request-bodies.py \
  --baseline /absolute/shb-baseline --candidate /absolute/shb-candidate \
  --hfast /absolute/hfast-fixed --peer /absolute/quinn-peer \
  --output /absolute/results --cases benchmarks/h3-gso-cases.json \
  --build-manifest /absolute/NEW_MANIFEST.json \
  --phase primary --prefix gso-limit --pairs 3
# Repeat with --phase confirmation after the first process finishes.
```

Local evidence is indexed by workspace shb/optimization-results/c97-record.md:
c97-performance-final.json, c97-fixed-matched-production.json,
c97-fixed-socket-primary-*, c97-fixed-clean-confirmation-*,
c97-confirmation-exclusion.json and c97-gso-red.log. Raw artifacts are not committed.
The diagnostic tooling is retained separately on local branch
codex/diag-h3-credit-batches-20261011 (17d1b62); the rejected cursor c15a6b5
and its original binaries/worktree remain unchanged.
