# Independent receive-history checks

`check-quic-receive-history.py` runs an aioquic 1.3.0 server against the real
`shb` CLI. It checks duplicate suppression through authenticated wire traffic.
There is no production Rust change or throughput claim.

```sh
python3 -m venv /tmp/shb-history-venv
/tmp/shb-history-venv/bin/pip install aioquic==1.3.0
cargo build --release --locked
/tmp/shb-history-venv/bin/python -m unittest discover -s benchmarks -p 'test_quic_receive_history.py'
/tmp/shb-history-venv/bin/python benchmarks/check-quic-receive-history.py --shb ./target/release/shb > history.json
```

Use `--case ordinary`, `--case sparse`, or `--case key-update` to isolate a case.
The script exits nonzero on failure and retains its error, encrypted packet
bytes, packet numbers, delivery actions, ACK ranges, key generations, decoded
PATH_RESPONSE ledger and CLI report in JSON. CI uploads this file even on failure.
The fixture intentionally uses private aioquic APIs; its version is pinned and
checked. It requires Python 3.11 or newer.

Each case keeps the first of four real HTTP/3 GET requests open during the
schedule, then completes all four 8 KiB responses. Request, status, error and
explicit latency-sample counts must agree exactly. Successful requests alone
cannot establish correct replay handling: the fixture also requires one
PATH_RESPONSE for every deliberately delivered fresh PATH_CHALLENGE packet,
and none for a byte-for-byte replay. Sending the same challenge in a new packet
authorizes another response. aioquic's normal challenge validation remains active.

The ordinary case replays before and after ACK-of-ACK pruning, releases a late
unseen packet, retransmits a challenge in a new packet, and recovers a deliberately
lost challenge using a new packet number. The sparse case also leaves 40 packet
number gaps, reaching shb's 32-range wire ACK bound. Before testing pruning, the
peer serializes an ACK covering a client packet which acknowledged the old server
packet. The client's ACK of this new ACK+PING must then exclude the old number.
Thus the test observes pruning instead of inferring it from elapsed time.

The key-update case adds two observed crypto-generation transitions. It checks
authenticated client replies in both new phases, replay under the previous
generation, first delivery of an unseen previous-generation packet, and replay
after the original generation has expired. A PING following each replay acts as
a receive-loop barrier: its ACK confirms progress without overwriting any pending
PATH_RESPONSE. No arbitrary silence interval establishes replay success.

All scheduling is bounded (at most 256 reserved packets per connection), waits
and subprocesses have deadlines, and peer/event-loop failures reach the verdict.
Cleanup cancels fixture tasks and protocol timers, kills unfinished clients and
closes the server.
The tests exercise a small controlled loss/reordering schedule on loopback;
they do not establish general QUIC loss recovery or response-body verification.

Local validation used both Rust profiles (555 unit and 68 integration tests
passing per profile, two existing ignored), strict all-target Clippy, formatting,
16 fixture tests and all three wire cases on immutable default, fresh release and
debug binaries: 36 successful requests, 36 latency samples, zero unexpected errors.
The expected PATH_RESPONSE totals are 4, 4 and 6 per matrix, including 2 responses
to the original token only because its frame is retransmitted in a new packet.

Two disposable Rust mutants prove failure detection. Disabling the authenticated
receive-history guard redispatches the first replay and fails before pruning.
Resetting `ReceivedPackets` when an ACK range is pruned passes that first replay,
then fails on replay after observed ACK-of-ACK pruning. Both fail with an extra
authenticated PATH_RESPONSE (one expected, two observed), independently of the
aggregate request counts. Neither mutant is included in this change.
