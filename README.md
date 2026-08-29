# shb — Simple HTTP Benchmarker

[![CI](https://github.com/hatoo/shb/actions/workflows/ci.yml/badge.svg)](https://github.com/hatoo/shb/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/shb.svg)](https://crates.io/crates/shb)

An HTTP load generator for Linux built on `io_uring`, speaking HTTP/1.1, HTTP/2
and HTTP/3.

Every protocol is driven by a Sans-I/O state machine
([shiguredo_http11], [shiguredo_http2], [shiguredo_http3] and [quinn-proto] for
QUIC), so the whole client is one completion-driven event loop per thread with
no async runtime underneath.

[shiguredo_http11]: https://github.com/shiguredo/http11-rs
[shiguredo_http2]: https://github.com/shiguredo/http2-rs
[shiguredo_http3]: https://github.com/shiguredo/http3-rs
[quinn-proto]: https://github.com/quinn-rs/quinn

## Features

- **HTTP/1.1, HTTP/2 and HTTP/3** from a single binary
- **TLS** via [rustls] — `https://` for HTTP/1.1 and HTTP/2, and QUIC for HTTP/3
- **Multiplexing** — `-p` keeps N concurrent streams per connection on HTTP/2 and HTTP/3
- **curl-style request flags**: `-m` for the method, repeatable `-H` for
  headers, and `-d` for a body — including `@file` and `@-` (stdin)
- **Text or JSON output**, with an oha-style latency distribution
- **Ctrl-C prints the report** instead of throwing the run away

[rustls]: https://github.com/rustls/rustls

## Requirements

- **Linux 6.0 or newer.** shb uses io_uring multishot receive (6.0) and provided
  buffer rings (5.19) on every connection. The remaining tuning flags —
  `SINGLE_ISSUER`, `COOP_TASKRUN`, `DEFER_TASKRUN` (6.1) and `NO_SQARRAY` (6.6) —
  are applied when available and silently skipped otherwise.
- A recent stable Rust toolchain (edition 2024).

## Install

```console
$ cargo install shb
```

Or from git, for the latest commit:

```console
$ cargo install --git https://github.com/hatoo/shb
```

Or build from a checkout:

```console
$ cargo build --release
$ ./target/release/shb --help
```

## Usage

```console
$ shb http://127.0.0.1:8080/                      # 200 requests over 50 connections
$ shb -z 30s -c 100 http://127.0.0.1:8080/        # run for 30 seconds
$ shb --http2 -p 32 -c 16 https://example.com/    # HTTP/2, 32 streams per connection
$ shb --http3 -p 32 -c 16 https://example.com/    # HTTP/3 over QUIC
$ shb -m POST -H 'Content-Type: application/json' -d @body.json http://127.0.0.1:8080/api
$ shb --disable-keepalive -c 100 http://127.0.0.1:8080/       # a fresh connection per request
```

`-n` and `-z` are mutually exclusive, `-p` only applies to HTTP/2 and HTTP/3,
and `--disable-keepalive` only applies to HTTP/1.1.

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `-c, --connections` | `50` | Concurrent connections |
| `-n, --requests` | `200` | Total requests to send |
| `-z, --duration` | — | Run for a duration instead (`10s`, `1m30s`) |
| `-p, --parallel` | `1` | Concurrent streams per connection (HTTP/2 and HTTP/3) |
| `-t, --threads` | physical cores | Worker threads, capped at `--connections` |
| `-m, --method` | `GET` (`POST` with `-d`) | HTTP method |
| `-H, --header` | — | Extra header, repeatable: `-H 'Name: Value'` |
| `-d, --data` | — | Request body; `@file` reads a file, `@-` reads stdin |
| `--connect-timeout` | `5s` | Connection establishment timeout |
| `--disable-keepalive` | off | Reconnect for every request (HTTP/1.1 only) |
| `--http2` | off | Use HTTP/2 |
| `--http3` | off | Use HTTP/3 (requires an `https://` URL) |
| `-j, --json` | off | Print the report as JSON |

On `http://` URLs `--http2` uses prior knowledge (no `Upgrade` dance); on
`https://` the protocol is negotiated with ALPN.

<details>
<summary><code>shb -h</code></summary>

```console
$ shb -h
io_uring HTTP/1.1 / HTTP/2 / HTTP/3 benchmarker

Usage: shb [OPTIONS] <URL>

Arguments:
  <URL>  Target URL, e.g. http://127.0.0.1:8080/ or https://example.com/ (TLS trusts every certificate: this is a benchmarker)

Options:
  -c, --connections <CONNECTIONS>
          Number of concurrent connections [default: 50]
  -n, --requests <REQUESTS>
          Total number of requests [default: 200]
  -z, --duration <DURATION>
          Run for this long instead of a fixed request count (e.g. 10s, 1m30s)
  -m, --method <METHOD>
          HTTP method (defaults to GET, or POST when -d is given, like curl)
  -H, --header <HEADER>
          Custom HTTP header (repeatable). Example: -H "Accept: application/json"
  -d, --data <BODY>
          HTTP request body. @file reads the file, @- reads stdin (like curl; carriage returns and newlines are stripped from file/stdin data)
      --connect-timeout <CONNECT_TIMEOUT>
          Connection establishment timeout (e.g. 5s, 500ms) [default: 5s]
  -t, --threads <THREADS>
          Number of worker threads [default: 16]
  -j, --json
          Print the report as JSON
      --http2
          Use HTTP/2 (prior knowledge on http://, ALPN "h2" on https://)
      --http3
          Use HTTP/3 over QUIC (https:// URLs only)
      --disable-keepalive
          Close the connection after every response instead of reusing it (sends "Connection: close"; HTTP/1.1 only)
  -p, --parallel <PARALLEL>
          Number of concurrent streams per connection (HTTP/2 and HTTP/3) [default: 1]
  -h, --help
          Print help
```

The default for `-t` is the number of physical cores on the machine running
`shb`, so the value printed above (16) is whatever that host reported.

</details>

> **TLS certificates are never verified.** shb is a benchmarking tool, so it
> accepts any certificate — which is what you want against a test server with a
> self-signed cert, and what you must not rely on anywhere else.

## Output

```console
$ shb -z 3s -c 50 http://127.0.0.1:3000/
URL:          http://127.0.0.1:3000/
Protocol:     HTTP/1.1
Threads:      16
Connections:  50
Requests:     772063 (772063 ok, 0 errors, of which 0 connect) in 3.039s
Requests/sec: 254014.9
Transfer:     recv 31.49 MB/s (100368190 bytes), sent 9.69 MB/s (30884080 bytes)
Status codes:
  [200] 772063
Latency (ms):
  min 0.019  mean 0.194  max 1.869
Latency distribution:
  10% in 0.120 ms
  25% in 0.149 ms
  50% in 0.186 ms
  75% in 0.229 ms
  90% in 0.276 ms
  95% in 0.309 ms
  99% in 0.387 ms
  99.9% in 0.578 ms
  99.99% in 1.026 ms
```

`-j` prints the same run as JSON, with every latency in seconds:

```json
{
  "url": "http://127.0.0.1:3002/",
  "protocol": "HTTP/2",
  "threads": 8,
  "connections": 8,
  "durationSeconds": 2.001874342,
  "requests": { "total": 418121, "ok": 418121, "errors": 0, "connectErrors": 0 },
  "requestsPerSec": 208864.7580058749,
  "bytesReceived": 16307931,
  "bytesReceivedPerSec": 8146330.99483524,
  "bytesSent": 5438053,
  "bytesSentPerSec": 2716480.693072393,
  "statusCodes": { "200": 418121 },
  "latencySeconds": {
    "min": 0.00004768,
    "mean": 0.000606615342716582,
    "max": 0.00487591,
    "percentiles": {
      "p10": 0.000301916, "p25": 0.000400123, "p50": 0.000536069,
      "p75": 0.00072343,  "p90": 0.000981392, "p95": 0.001211524,
      "p99": 0.001806339, "p99.9": 0.002655211, "p99.99": 0.003518719
    }
  }
}
```

## Comparison with wrk and h2load

Measured against [sandbag] — a small local server that speaks all three
protocols — with 10 s per run, median of 3 runs, and 16 threads for every tool.
Numbers are requests/sec; higher is better.

| Protocol | Config | shb | [wrk] | [h2load] |
| --- | --- | ---: | ---: | ---: |
| HTTP/1.1 | 64 connections | **307,216** | 276,064 | 273,447 |
| HTTP/2 (h2c) | 32 conns × 32 streams | **752,609** | — | 144,617 |
| HTTP/2 (h2c) | 100 conns × 100 streams | **635,166** | — | 631,325 |
| HTTP/3 | 16 conns × 128 streams | **313,191** | — | 292,965 |

[sandbag]: https://github.com/hatoo/sandbag
[wrk]: https://github.com/wg/wrk
[h2load]: https://nghttp2.org/documentation/h2load-howto.html

```console
$ shb    -z 10s -c 64 -t 16 http://127.0.0.1:3000/
$ wrk    -d 10s -c 64 -t 16 http://127.0.0.1:3000/
$ h2load --h1 -D 10 -c 64 -t 16 http://127.0.0.1:3000/
```

**On HTTP/1.1 shb is ~11 % ahead** of both wrk and h2load, which land within
1 % of each other. With only 64 connections the throughput ceiling is set by how
fast each client turns a response around, and shb waits for a batch of
completions per `io_uring_enter` instead of one.

**On HTTP/2 the gap is about where the concurrency sits, not about a ceiling.**
Both tools reach ~635k req/s when the load is spread over 100 connections × 100
streams — a difference of under 1 %. At 32 × 32, though, h2load stays at ~145k
while shb reaches ~753k: h2load needs a large number of in-flight requests
before it saturates, whereas shb drives the same throughput from far fewer
connections.

**On HTTP/3 shb is ~7 % ahead** at each tool's best configuration. Both plateau
near 300k req/s, which is the server's HTTP/3 limit rather than either client's.

<details>
<summary>Environment and caveats</summary>

**Machine**

| | |
| --- | --- |
| CPU | AMD Ryzen 9 3950X — 16 cores / 32 threads |
| Memory | 31 GiB |
| OS | Ubuntu 24.04.4 LTS on **WSL2** (WSL 2.7.11.0) |
| Kernel | 6.18.40.1-microsoft-standard-WSL2+ |
| Rust | 1.98.0 |

**Tools**

- shb (this repo), built with `cargo build --release`.
- wrk 4.1.0 (Ubuntu package).
- h2load from nghttp2 1.71.0-DEV, built against ngtcp2 + nghttp3 + BoringSSL —
  the distro build of h2load has no HTTP/3 support.

**Server** — [sandbag] running on the same host: axum for HTTP/1.1 and h2c,
quinn + h3 with a self-signed certificate for HTTP/3, returning a 13-byte body.

**Caveats** — client and server share one machine over loopback, so every number
is shaped by that CPU contention as much as by the client itself, and WSL2's
virtualised network stack is not a bare-metal NIC. Treat the table as a relative
comparison under identical conditions, not as an absolute rate any of these
tools can sustain against a real server over a real network.

</details>

## How it works

Each worker thread owns one `io_uring` and its own set of connections, and
shares no mutable state with the others; the per-thread stats are merged once at
the end. Requests and connections are split evenly across threads, and the
thread count is clamped to the connection count so every thread gets at least
one connection.

Within a thread the loop is: submit, wait for completions, feed the bytes to the
protocol state machine, submit whatever it produced. A few things make that
cheap:

- **Connections are established through io_uring** (`Connect` linked to a
  `LinkTimeout`), so a slow peer never blocks the loop.
- **One multishot receive per connection** keeps delivering completions without
  being re-armed, into a **provided buffer ring** the kernel picks buffers from.
- **Sockets are registered files** and the ring itself is a registered fd, so
  neither is looked up per operation.
- **HTTP/1.1 decodes in place**: `mut_buf`/`advance_buf` let the socket write
  straight into the decoder's buffer, and TLS decrypts into it directly.
- **HTTP/3 sends with UDP GSO**, batching up to 64 QUIC packets into one
  `sendmsg` when the kernel supports it.
- **`-z` deadlines and QUIC timers are io_uring timeouts**, so an idle worker
  sleeps in the kernel rather than polling.

Ctrl-C sets an atomic flag that the workers notice within ~100 ms; they return
their statistics normally, so an interrupted run still prints its report. A
second Ctrl-C aborts immediately.

## Development

```console
$ cargo test          # end-to-end tests: the binary against local axum/quinn servers
$ cargo clippy --all-targets -- -D warnings
$ cargo fmt
```

The end-to-end tests start real servers — axum for HTTP/1.1 and h2c, and
quinn + h3 with a self-signed certificate for HTTP/3 — run the compiled binary
against them, and assert on its JSON report.

## License

MIT — see [LICENSE](LICENSE).
