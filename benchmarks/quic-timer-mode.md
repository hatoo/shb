# Pending loss and QUIC probe timeouts

QUIC uses one recovery timer with two modes. A pending time-threshold loss
deadline takes priority over PTO, even if the calculated PTO deadline is earlier.
This is required by [RFC 9002 Section 6.2.1 and Appendix A.8–A.9](https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1).

`poll_timeout` used to minimize both deadlines. `handle_timeout` chose loss mode
only after loss expired, so an earlier PTO could allocate probes, reset the
CRYPTO send cursor and increase backoff while loss detection was still pending.
The connection now selects its cached loss deadline before calculating PTO.
An early timeout call cannot enter PTO mode while that loss deadline exists.
Idle and keepalive deadlines retain their independent priority. The loss
detector, PTO formula, congestion accounting and request/latency accounting are
unchanged; no additional sent-packet traversal is introduced.

Run the deterministic regressions:

```sh
cargo test --locked --bin shb timer_mode -- --nocapture
cargo test --release --locked --bin shb timer_mode -- --nocapture
```

The tests seed a settled 100 ms RTT and use the real ACK, timeout and packet
construction paths. They never assign cached loss deadlines. In the encrypted
Initial-flight case, packet 0 carries the ClientHello and packet 1 carries an ACK.
Acknowledging only packet 1 at 100 ms leaves packet 0 under time-threshold loss:

| Event | Before repair | With repair |
| --- | --- | --- |
| PTO calculation | 101 ms | 101 ms, suppressed by pending loss |
| Selected recovery deadline | 101 ms | 112.5 ms |
| Early timeout at 101 ms | 2 datagrams / 2,400 bytes, PTO count 1 | No datagrams, PTO count 0 |
| Loss expiry at 112.5 ms | Already sent premature probes | ClientHello becomes eligible for retransmission |

The repaired test also checks that the complete ClientHello is retransmitted in
one padded datagram at loss expiry, and an immediate repeated timeout does not
send it twice. Five of ten regressions fail on unmodified `676315f`; all ten pass
with the repair. Other cases cover every ordered pair of loss/PTO spaces,
late ACKs and key discard restoring PTO, simultaneous deadlines, RTT growth,
idle/keepalive priority, Handshake confirmation and anti-deadlock fallback.

These are fixed-history tests with seeded RTT and lifecycle states. The byte
counts come from actual encrypted datagrams produced by shb, not network
measurements or an independent reproduction of this precise packet history.
Independent Quinn impaired handshakes and the existing aioquic
[`quic-response-recovery`](quic-response-recovery.md) and native
[`h3-response-flight`](h3-response-flight.md) fixtures guard interoperability,
bytes/FIN, receipts and complete request/error/latency-sample accounting.
They do not prove general recovery correctness or an HTTP throughput gain.
