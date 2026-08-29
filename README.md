# shb — Simple HTTP Benchmarker

[![CI](https://github.com/hatoo/shb/actions/workflows/ci.yml/badge.svg)](https://github.com/hatoo/shb/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/shb.svg)](https://crates.io/crates/shb)

An HTTP load generator for Linux built on `io_uring`, speaking HTTP/1.1, HTTP/2
and HTTP/3.

Protocol handling is Sans-I/O throughout — [shiguredo_http2], [shiguredo_http3]
and [quinn-proto] for QUIC, with [shiguredo_http11] building the HTTP/1.1
requests and a purpose-built scanner reading the responses — so the whole client
is one completion-driven event loop per thread with no async runtime
underneath.

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

Measured against nginx 1.31.4 returning a 13-byte body, with 10 s per run,
median of 3 runs (5 for HTTP/3, where the spread is wider), and 16 threads for
every tool. Numbers are requests/sec; higher is better.

| Protocol | Config | shb | [wrk] | [h2load] |
| --- | --- | ---: | ---: | ---: |
| HTTP/1.1 | 64 connections | **476,233** | 458,287 | 425,420 |
| HTTP/2 (h2c) | 32 conns × 32 streams | 889,303 | — | **923,191** |
| HTTP/2 (h2c) | 100 conns × 100 streams | 1,028,441 | — | **1,242,151** |
| HTTP/3 | 16 conns × 128 streams | 767,771 | — | **1,395,144** |

[wrk]: https://github.com/wg/wrk
[h2load]: https://nghttp2.org/documentation/h2load-howto.html

```console
$ shb    -z 10s -c 64 -t 16 http://127.0.0.1:3010/
$ wrk    -d 10s -c 64 -t 16 http://127.0.0.1:3010/
$ h2load --h1 -D 10 -c 64 -t 16 http://127.0.0.1:3010/
```

**On HTTP/1.1 shb is ahead of both** — 4 % over wrk and 12 % over h2load. Its
response path is a boundary scanner rather than a parser (see
[How it works](#how-it-works)), which is worth ~10 % on its own.

**On HTTP/2 h2load is 4 % ahead at 32 × 32 and 21 % ahead at 100 × 100**, and
**on HTTP/3 it is ~80 % ahead**. That gap is not in the io_uring layer — a CPU
profile of a saturated worker puts io_uring at 0.1–0.4 %. For those two
protocols shb leans on pure-Rust Sans-I/O crates where h2load has nghttp2,
nghttp3 and ngtcp2 in C, and HPACK/QPACK and the QUIC transport are where the
difference lives.

An earlier version of this table measured against a server that saturated
before any of the clients did, which flattered every number and reversed some
of these results. Picking a server with headroom is what made the comparison
mean anything.

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

- shb (this repo), built with `cargo build --profile dist` — the profile the
  released binaries use (LTO, one codegen unit). It measures within about 2 %
  of a plain `--release` build.
- wrk 4.1.0 (Ubuntu package).
- h2load from nghttp2 1.71.0-DEV, built against ngtcp2 + nghttp3 + BoringSSL —
  the distro build of h2load has no HTTP/3 support.

**Server** — nginx 1.31.4 (mainline, `--with-http_v3_module`) on the same host,
serving HTTP/1.1 and h2c on one cleartext socket and HTTP/3 on a QUIC socket
with a self-signed certificate. `return 200` keeps it off the disk entirely:

```nginx
worker_processes auto;
events { worker_connections 16384; }
http {
    access_log off;
    default_type text/plain;
    # Defaults that would otherwise let the server decide when a connection ends
    keepalive_requests 100000000;
    keepalive_timeout 300s;
    http2_max_concurrent_streams 256;

    server {
        listen 127.0.0.1:3010 reuseport;
        http2 on;                                    # h1 and h2c, one socket
        location / { return 200 "hello, world!"; }
    }
    server {
        listen 127.0.0.1:3453 quic reuseport;
        http3 on;
        ssl_certificate cert.pem; ssl_certificate_key key.pem;
        ssl_protocols TLSv1.3;
        location / { return 200 "hello, world!"; }
    }
}
```

The `keepalive_requests` default of 1000 matters: leaving it alone makes nginx
send a GOAWAY every 1000 requests, which costs h2load most of its HTTP/2
throughput.

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
- **HTTP/1.1 responses are scanned, not parsed**: a load generator only needs
  to know where one response ends and the next begins, so the scanner reads the
  status line, `Content-Length` and `Transfer-Encoding` and steps over every
  other header without looking at it. Lines are found with `memchr`, one
  case-insensitive byte decides whether a line is worth reading, nothing is
  allocated per response, and the scan runs straight over the receive buffer.
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
