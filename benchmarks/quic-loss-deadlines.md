# Loss deadlines across QUIC packet-number spaces

The connection used to store one loss deadline. An ACK replaced it with the
result for just that ACK's packet-number space, including `None`. The timeout
loop also replaced it for Initial, Handshake and Data in sequence. Consequently,
an unrelated ACK or an empty Data space could cancel pending Handshake loss.
Discarding keys could instead leave a deadline for packets already discarded.

Each space now retains the deadline returned by its existing loss detector.
The connection selects the minimum of those three cached values. ACK processing
updates only its own space; timeout processing refreshes each examined space.
Key discard and Retry clear the corresponding deadline with the sent flight.
This follows the per-space loss-time model in
[RFC 9002 Appendix A.8–A.11](https://www.rfc-editor.org/rfc/rfc9002.html#appendix-A.8).
The existing packet-loss rules, RTT estimator, congestion callbacks, PTO logic,
idle/keepalive timers and request/latency accounting are unchanged.

Run the deterministic regressions in both profiles:

```sh
cargo test --locked --bin shb loss_deadlines
cargo test --release --locked --bin shb loss_deadlines
```

The tests call the real ACK, timeout and discard handlers with explicit packet
histories and instants. They never assign the cached deadlines. Coverage includes
all ordered pairs of spaces, ACK order, successive losses within/across spaces,
an increased RTT before expiry, sparse ACKs, ACK-only retirement, reordered and
late ACKs, duplicate callbacks, Handshake confirmation and authenticated versus
forged Retry. Some lifecycle states are seeded directly to isolate reset
behavior; these are not claims that such states were observed on the wire.

Nine of the initial ten tests failed against the unchanged production code at
`d36c84e`; all eleven final tests pass with the repair. With the tests' 100 ms
RTT sample, an unacknowledged Handshake packet has a 112.5 ms loss deadline.
If an unrelated ACK erased it, the next recovery opportunity could instead be
the 300 ms PTO. These are deterministic timer values, not measured network
latencies or an HTTP throughput improvement.

The full Rust suite additionally exercises independent Quinn handshakes,
packet loss, duplication and reordering. The independent aioquic
[`quic-response-recovery`](quic-response-recovery.md) fixture checks authenticated
request retransmission bytes/FIN, sparse ACKs and key updates. The native
[`h3-response-flight`](h3-response-flight.md) fixture requires complete response
receipts and exact request/error/latency-sample accounting. These bounded checks
do not establish general QUIC recovery correctness. Ordinary fixed-server
throughput comparisons remain subject to the host's measurement uncertainty.
