# Counted HTTP/2 GOAWAY cohort

This benchmark targets reconnecting HTTP/2 clients whose peer repeatedly accepts
only a prefix of the requests sent on a connection. It measures the complete
commands, including startup and reporting, using a single monotonic interval
from the first client launch through the last client exit. It does not add
overlapping individual request rates.

Eight independent `-c 1 -t 1 -p 4096` clients share one CPU. Each has a separate
native peer; four peers share each of two other CPUs. On each connection the peer
collects exactly `min(4096, remaining)` request headers before sending GOAWAY and
accepting `min(1024, remaining)` requests. The final partial connection is counted
too. All successful responses have status 200 and an empty body.

Every child must exit successfully and retain its full report. The controller
checks exact request/error/status/sample counts, ordered finite latency data,
accepted/rejected streams, complete bodies, all peer connections and TCP bytes
(including separately observed client teardown frames). Missing or invalid
children invalidate the whole cohort. Each process group is terminated on
failure. Raw reports, commands, binary hashes and CPU usage are retained.

Build immutable release binaries in separate worktrees with the same toolchain
and flags. For the original comparison, the baseline is commit
`3a13d87922f9fd92e19ea2de8c3375dcd7a48e11`. Build the peer in this worktree with:

```sh
cargo build --release --locked --example h2-goaway-peer
python3 -m unittest discover -s benchmarks -p 'test_h2_goaway_cohort.py'
python3 benchmarks/h2_goaway_cohort.py qualification \
  --baseline /absolute/path/to/frozen-baseline \
  --candidate /absolute/path/to/frozen-candidate \
  --peer /absolute/path/to/h2-goaway-peer \
  --client-cpu 8 --peer-cpus 1 2 --requests 4194304 --output /tmp/goaway-qualification
```

Choose three available distinct CPUs once, before qualification. Require at
least 0.85 aggregate client core, at most 0.80 core on either peer CPU and at
least 10 seconds per measured cohort. Change counts only to qualify duration,
then freeze the workload. The default warmup is 131072 requests per child.
`qualification` records both variants without enforcing those resource gates;
the subsequent phases enforce them.

Reuse the same arguments with `primary --pairs 4`, `confirm --pairs 3` and
`controls --pairs 2`, each with a fresh output directory. Primary alternates
AB/BA; confirmation starts BA; controls run the baseline under both labels.
Compare `requests_per_sec` from each cohort's `summary.json`, pairing labels
within a phase. Only run confirmation/controls if primary results are promising.
Never interpret short qualification or warmup rates as performance evidence.

## Original c310 results (WSL2, 2026-10-31)

Each measured cohort completed 33,554,432 requests/samples with zero unexpected
errors. Clients used 0.985–0.990 core; peers had ample headroom. Paired aggregate
throughput changes were:

| Phase | Changes | Median |
| --- | --- | --- |
| Primary | +4.089%, −0.420%, +6.471%, +5.738% | +4.913% |
| Separate confirmation | +5.299%, +5.288%, +2.445% | +5.288% |
| Identical baseline controls | −2.638%, −0.004% | −1.321% |

Median client CPU/request fell 4.886% in primary and 4.835% in confirmation.
The controls passed the original 3% engineering limit on the first attempt.
This is evidence for this saturated GOAWAY cohort. The earlier serial workload
used only about 0.20 client core and improved 0.786%, below the acceptance gate;
no ordinary HTTP/2 throughput gain is claimed.

The original immutable SHA256 values were:

- Baseline: `4cbe512d7a8672f675142ca83cf42aa956883e8ce61fbfdba144c0d6d9e58e66`
- Candidate: `d5ad7a0c6403fe342308f09f638903d6119e787be3ca6156ec00428f2778315e`
- Peer: `bdf51952709429c089482616bb039f6941e56d61cc42e7cc883261bd3082df4f`

The controller records hashes for each new run; exact binary identity across
different build paths/toolchains is not assumed. Detailed original evidence is
kept in the optimization workspace under `shb/optimization-results/c310/`.
