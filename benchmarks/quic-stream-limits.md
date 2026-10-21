# QUIC incoming stream counts

The client advertises zero server bidirectional streams and, for HTTP/3, three
server unidirectional streams. Previously, STREAM and RESET_STREAM registered
any server-initiated ID in the peer stream vector. For example, IDs 1 and 15
were accepted even though neither was permitted by those transport parameters.

The connection now retains its advertised unidirectional count and checks the
direction and stream index before lookup, registration or payload buffering.
Invalid authenticated frames produce transport CONNECTION_CLOSE with
STREAM_LIMIT_ERROR (4). The check uses the stream ID divided by four, so sparse
IDs cannot bypass the cumulative limit and the maximum QUIC ID cannot overflow
a multiplied limit. Completing a stream does not replenish the limit.
Client-initiated response streams keep their existing receive path.

This follows [RFC 9000 section 4.6](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6)
and [section 19.11](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.11).
It is a correctness and resource-bound repair, with no ordinary throughput
improvement claim.

Eight new Rust regressions cover zero/one/three/larger/maximum counts, forbidden
bidirectional streams, implicit gaps, reordered opens, duplicate data and
resets, RESET-first streams, cumulative limits after completion, independent
outgoing credit, unchanged registration/capacity/accounting on rejection, and
authentication. A packet containing an invalid stream followed by a valid
response must close before reporting that response as successful.

`check-quic-receive-limits.py --shb ./target/release/shb` adds nine independent
aioquic cases to the twelve receive-credit/final-size cases. It checks the
actual advertised limits, authenticated close code, and exact CLI
request/error/status accounting and latency presence. The baseline fails the
new close assertion. Valid empty retransmissions on IDs 3/7/11 leave a normal
response intact. All cases run in the required CI job.

An actual-source probe, using the same System allocator and optimized compile
flags for both versions, measured one direct STREAM/RESET handler call after
connection setup. Invalid 64 KiB STREAM input allocated 66,048 bytes across
three allocations before the fix, versus a single 64-byte error allocation
after it. Invalid RESET allocated 512 bytes before, versus 64 bytes after.
Rejected input now creates no peer entries or payload storage and spends no
receive credit. Valid IDs 3/11 retain their original allocation counts and
bytes. These figures exclude transport-close reporting and packet processing;
they are component evidence, not an end-to-end performance measurement.
Retaining the limit grows Connection from 3,384 to 3,392 bytes on x86_64.

Ordinary guards compared frozen baseline `2a76484` and candidate binaries with
one fixed hfast `589a7c7`, identical release settings, CPU affinity, warmups,
three alternating pairs and three reversed-order confirmation pairs. Workloads
were 131,072 serial requests (c1/p1/t1) and 2,097,152 multiplexed requests
(c16/p64/t4). All 27,131,904 requests including warmups succeeded, with no
unexpected errors or UDP error-counter increases; complete reports were kept.

| Median paired change | Primary | Confirmation |
| --- | ---: | ---: |
| Serial requests/s | -0.241% | +0.025% |
| Serial client CPU/request | +0.372% | +0.185% |
| Multiplexed requests/s | -1.812% | +0.216% |
| Multiplexed client CPU/request | +2.703% | 0.000% |
| Multiplexed p99 | +3.490% | +1.330% |
| Multiplexed p99.9 | +5.874% | +8.675% |

The phases do not establish a throughput improvement or equivalence. Tail
latency costs are recorded, and WSL2 uncertainty limits small comparisons.
No identical-binary retries or affinity sweeps were used.
