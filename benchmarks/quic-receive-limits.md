# QUIC receive flow control and final sizes

A peer could exceed the advertised stream limit, and connection-limit checks
ran after copying the STREAM payload and emitting completion events. RESET
final sizes did not consume connection credit. These are correctness and
resource-accounting defects, independent of ordinary request throughput.

The receive path now validates the end offset, final size, stream limit and
remaining connection credit before changing the stream or buffering its data.
RESET returns only the increase in its high-water offset, including gaps, so
repeated RESET and later STREAM frames cannot charge the same bytes twice.
Rejected new peer streams are not registered. Receive errors produce transport
CONNECTION_CLOSE with FLOW_CONTROL_ERROR (3), FINAL_SIZE_ERROR (6), or
FRAME_ENCODING_ERROR (7). An unsent MAX_DATA grant takes effect only when it
fits into a packet. Lost grants retain their existing retransmission behavior.
CRYPTO reassembly remains independent of application stream flow control.

The implementation follows [RFC 9000 section 4.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1),
[section 4.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.5), and
[section 19.8](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8).
It preserves the existing policy of ignoring data for fully retired requests;
changing canceled-stream state retention is separate work.

Regression tests cover stream/connection boundaries, zero-length frames with
large offsets, integer overflow, no buffer-capacity changes on rejection,
reordering/overlap/duplicates, FIN below high water, RESET before gaps fill,
peer-unidirectional RESET before data, repeated RESET, buffer reuse, packet
budgets, grant loss, and unauthenticated packets. Existing independent Quinn
credit-recovery tests exercise real encryption and loss/reordering.

`check-quic-receive-limits.py --shb ./target/release/shb` supplies 12 independent
wire cases using aioquic 1.3.0. It deliberately bypasses the peer's send limits
when writing frames, while keeping aioquic's TLS, encryption and close decoder.
It verifies exact request/error/status counts, success-latency presence, and
transport-close codes. It is included in the required CI job.

An actual-source allocation probe with a 64 KiB payload and an 8-byte window
observed 65,536 allocated bytes (in order) or 65,664 bytes (reordered) on the old
receive path, versus zero on the rejected new path. The valid 8-byte control
retains one 8-byte allocation and delivers all 8 bytes. These are deterministic
component allocation measurements, not an end-to-end throughput claim.

Normal-traffic guards used fresh frozen baseline `81afdc1` and candidate shb
release binaries, one fixed hfast `589a7c7` baseline, CPU affinity, warmups,
three alternating pairs and a separate three-pair reversed-order confirmation.
Workloads were 131,072 serial requests (c1/p1/t1) and 2,097,152 multiplexed
requests (c16/p64/t4), with identical options within each comparison.
All 27,131,904 requests including warmups succeeded, with no unexpected errors
or UDP error-counter increases; complete latency distributions were retained.

| Median paired change | Primary | Confirmation |
| --- | ---: | ---: |
| Serial requests/s | +1.183% | -1.861% |
| Serial client CPU/request | -0.717% | +2.030% |
| Multiplexed requests/s | -2.455% | -2.010% |
| Multiplexed client CPU/request | +1.739% | +0.893% |

The multiplexed guards show a small observed cost from this change; serial
results and tail latencies vary. WSL2 noise limits the interpretation of small
changes. This repair makes no throughput-improvement claim, and the allocation
result for invalid input must not be presented as an ordinary HTTP/3 speedup.
