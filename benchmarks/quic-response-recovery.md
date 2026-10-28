# QUIC recovery after a large response

`check-quic-response-recovery.py` verifies that recovery records survive a large
ACK-only flight. Aggregate HTTP success alone cannot expose discarded live
STREAM records when every request arrives on its first transmission.

The independent aioquic peer authenticates each client short packet before
delivery. A nonmutating decryption peek records packet numbers, key phases,
ACK ranges and exact STREAM offsets, bytes and FIN. Two selected request packets
are permanently dropped before aioquic updates receive, ACK or stream state.
Subsequent packets must reproduce the dropped bytes and final size with fresh
packet numbers. Different retransmission packetization and identical overlapping
bytes are allowed; missing FIN, changed bytes or an acknowledged dropped packet
fail the oracle.

Each case uses one connection and four sequential POST requests:

1. Acknowledge the first request, then return a 1 MiB response while suppressing
   native application ACKs. Send 32 PING/ACK barriers. Require ACK coverage of
   every response stream byte before sending FIN.
2. Drop the next complete request packet. Require at least 32 client ACK-only
   packets which the peer has never acknowledged. Send a late ACK for an old
   received packet, replay it, and obtain three PATH_RESPONSE packet numbers.
3. Acknowledge a later probe to cross the packet-loss threshold, leaving the
   request packet absent from the ACK ranges. Require exact byte/FIN recovery
   and independent HTTP header/body completion. Replay the ACK, repeat its
   ranges in a fresh packet, then acknowledge the retransmission.
4. Respond, repeat targeted loss/recovery for the third request, and complete
   a fourth request to check continued progress.

The `ordinary` case uses a singleton loss ACK. `sparse` uses two separated ACK
ranges. `key-update` also performs two confirmed key rotations, checking both
the dropped and recovered requests' authenticated phases. Recovery may also be
prompted by an earlier PTO; the verdict requires observed retransmission rather
than inferring its cause from timing. ACK barriers prove the client processed
each stage. Replayed server packets retain their original protected bytes.

All cases require exactly four successful requests, HTTP 200 statuses and live
latency samples, with zero request or connect errors. The JSON artifact includes
the wire ledger, explicit drops/replays, recovery evidence, response coverage,
key updates and the client report. Callback failures affect the verdict; bounded
waits, process termination and protocol timer/task cancellation cover failures.

Run with the same pinned peer used by CI:

```sh
python3 -m venv /tmp/shb-recovery-venv
/tmp/shb-recovery-venv/bin/pip install aioquic==1.3.0 pylsqpack==0.3.24
cargo build --release --locked
/tmp/shb-recovery-venv/bin/python -m unittest discover -s benchmarks -p 'test_quic_response_recovery.py'
/tmp/shb-recovery-venv/bin/python benchmarks/check-quic-response-recovery.py --shb ./target/release/shb > recovery.json
```

Use `--case ordinary`, `--case sparse` or `--case key-update` to select one case.
The fixture depends on aioquic 1.3.0 private packet/crypto APIs and rejects other
versions. Unit tests cover missing or changed retransmissions, FIN/overlap rules,
ACK authorization, authenticated barriers and cleanup failures. A disposable
Rust mutant which removes live `SentFrame::Stream` records for streams 4 and 8
before insertion into `SentPacket` must fail after the first targeted drop;
the unmodified client must pass.

This is a correctness gate, with no throughput claim. Its wall times and report
rates include deliberate waits and packet loss. Response ACK coverage proves
transport receipt, not a client-side body-content hash. These bounded schedules
do not establish general QUIC loss-recovery correctness. Production Rust code,
request accounting and latency measurement are unchanged.
