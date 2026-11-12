# Timing the native response reordering workload

The separate correctness suite in `native-reordering.md` establishes exact body,
FIN, credit and native queue exposure. Build its fixed peer once and retain its
manifest. Timing uses frozen production baseline/candidate executables; the
instrumented exposure observer must never be a timing input.

The controller launches the frozen peer and one serial native shb connection in
new network and PID namespaces. Python supervises processes without sending
datagrams. `measure-process.py` preserves stdin/stdout/stderr and collects child
CPU, elapsed time, context switches and peak RSS with `wait4`. CPU includes
startup and finalization; the shb report provides the request-window duration
and its unchanged latency samples. Peer thread snapshots surround the client
run and distinguish CPU work from waiting. RSS is retained, without asserting
that small differences are meaningful.

Example (Linux, Python 3.12+, `ip`, `unshare`, `taskset`; replace paths/hashes):

```sh
python3 -m unittest discover -s benchmarks -p test_measure_process.py -v
python3 -m unittest discover -s benchmarks -p test_native_measurements.py -v
python3 benchmarks/measure-native-reordering.py \
  --fixture-dir "$PWD/benchmarks" \
  --peer /absolute/frozen/native-reordering-peer --peer-sha256 FULL_SHA256 \
  --shb /absolute/frozen/shb-baseline --shb-sha256 FULL_SHA256 \
  --output /new/measurement --requests 512 --mode reverse \
  --size 525312 --chunk 1024 --client-cpu 2 --peer-cpus 4,6
```

Use `--namespace sudo` only where unprivileged namespaces are unavailable and
noninteractive sudo is configured. The fixed peer has two runtime workers.
Choose distinct physical cores once; do not search affinities for favorable
results. The controller caps requests, body size and runtime. Output directories
must be new. The PID namespace contains the supervisor, client and peer even
when they use separate process groups.

Require zero process, request, connection, receipt, packet-loss and UDP errors;
every completed request must contribute exactly one status 200 and latency
sample. The same receipt/schedule oracles validate complete body ACKs and prefix
release. Kernel namespace counters cover both endpoints, and live owned peer
socket snapshots provide additional drop evidence. Packet counts can differ
because ACK scheduling and frame packing respond to client speed; retain them
instead of assuming identical transport work. The fixed peer logs logical
chunk counts and datagram totals, not an exact per-run STREAM frame count.
The independent correctness qlog supplies frame-level exposure evidence.

Start with 128-request pilots, then choose a fixed count for both binaries.
Warm up both binaries, run three alternating pairs, and independently confirm
with three pairs in the opposite starting order. Use 525312-byte reverse bodies
for the affected comparison and the same-size ordered schedule as a separate
control. Never combine their rates into a speedup. Save full commands, reports,
resource files, transport ledgers, hashes and all failed runs. A loss or receipt
failure stops a campaign; changing its cause or methodology precedes any retry.

Client CPU savings plus fixed-peer CPU and ordered capacity help assess a
shifted bottleneck. No single-connection experiment proves the peer unsaturated
or an algorithm-only speedup. Ordinary H1/H2/H3, small responses and tail guards
remain distinct publication gates. Large reordered gains cannot establish
equivalence for a noisy small effect. Keep a runtime candidate experimental
until its required guards qualify; no automatic acceptance is performed here.
