# Receive-heap qualification

The receive heap already has affected large-reordering evidence. This campaign
addresses its remaining ordinary, small-response and tail guards. It makes no
automatic acceptance decision and does not rerun that large campaign.

Build baseline and candidate once with the same locked dependencies, compiler
and release settings. Keep both executables, the pinned native reordering peer,
and hfast immutable. `heap-guards.yml` records source/binary identities and builds
an untimed body/queue observer from the actual candidate revision. Its small
native matrix covers independent aioquic bytes/FIN, native exact counts/credit,
queue exposure, and specific missing-prefix/FIN/corruption failures. Run these
correctness checks before timing. No instrumented client produces timed traffic.

Run `sudo python benchmarks/heap_guards.py BASELINE CANDIDATE PEER HFAST NEW_OUTPUT`
on a dedicated Linux machine. This uses fresh network/PID namespaces per trial;
the output must not exist. It requires CPU 0 (the fixed hfast worker pins there)
and selects the first allowed CPU on a different physical core. Siblings and
actual process affinities are recorded. One peer worker occupies the server
core, so multiple producers are never oversubscribed onto it.

The fixed cells are H1/H2/H3 against hfast (13-byte body, 64 connections, one
client/server worker, 32 streams for H2/H3, batch linger 1, five seconds), plus
ordered/reverse native responses of 128/4096/16384 bytes in 64/256/256-byte
logical chunks (one connection/stream, 10000 requests). Every phase has separate
one-second or 128-request warmups. Samples remain enabled; at least 10000 timed
samples are required, providing only about ten observations beyond p99.9.
This minimum does not establish statistical precision by itself.

Each cell first runs three baseline/baseline pairs, AB/BA/AB. Every paired RPS
and client CPU/request difference must be within 3%, and p99/p99.9 within 10%.
These are predeclared engineering resolution bounds, not significance tests.
If they fail, defer that cell without an adjustment/retry or candidate timing.
If they pass, run baseline/candidate AB/BA/AB. All pairs must stay above -3% RPS,
below +3% client CPU/request, and below +10% p99/p99.9. Only passing cells receive
BA/AB/BA confirmation under the same limits. A failed screen is not proof of a
regression. All missing guards must qualify before considering a runtime PR.
The summary deliberately remains AWAITING_PERFORMANCE_VALIDATION pending review
of uncertainty, prior affected evidence and the correctness gates.

The driver stops on a process, accounting, receipt, native packet-loss, UDP error
or identity failure. It preserves raw commands, exits, reports, CPU, schedules,
peer receipts, socket evidence and failed attempts. The tests reject corrupt
sample/status counts, nonfinite tails, changed binaries, shared namespaces,
SMT placement, affinity escapes, hidden noisy pairs and process failures.

Client CPU includes startup/finalization; peer CPU includes its lifecycle.
Ordinary hfast measurements preserve all reported completions/samples and final
client drain but do not independently compare each timed body byte. Native
correctness uses the separate byte observer and independent reader. Ordinary
UDP counters do not expose QUIC packet-loss counts; native peer loss is checked
explicitly. This is loopback software evidence, not physical-NIC performance.
