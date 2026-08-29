# shb — Simple HTTP Benchmarker

[![CI](https://github.com/hatoo/shb/actions/workflows/ci.yml/badge.svg)](https://github.com/hatoo/shb/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/shb.svg)](https://crates.io/crates/shb)

An HTTP load generator for Linux built on `io_uring`, speaking HTTP/1.1, HTTP/2
and HTTP/3.

Protocol handling is Sans-I/O throughout, so the whole client is one
completion-driven event loop per thread with no async runtime underneath. All
three protocol stacks are written for this one job — see
[How it works](#how-it-works) — over [quinn-proto] for the QUIC transport.

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
  buffer rings (5.19) on every connection. The tuning flags — `SINGLE_ISSUER`,
  `COOP_TASKRUN`, `DEFER_TASKRUN` (6.1) and `NO_SQARRAY` (6.6) — are asked for
  together, and a ring is created without any of them if that fails.
- **Linux 6.12 gets more throughput.** Waiting for a batch of completions per
  `io_uring_enter` needs `min_wait_usec` to bound how long the kernel holds out
  for a batch it cannot fill. Without it each wait returns on the first
  completion, which is correct but pays a syscall per completion.
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
$ shb -z 3s -c 50 http://127.0.0.1:3010/
URL:          http://127.0.0.1:3010/
Protocol:     HTTP/1.1
Threads:      16
Connections:  50
Requests:     1070162 (1070162 ok, 0 errors, of which 0 connect) in 3.047s
Requests/sec: 351271.9
Transfer:     recv 53.93 MB/s (172296082 bytes), sent 13.40 MB/s (42807640 bytes)
Status codes:
  [200] 1070162
Latency (ms):
  min 0.016  mean 0.140  max 5.448
Latency distribution:
  10% in 0.070 ms
  25% in 0.093 ms
  50% in 0.123 ms
  75% in 0.162 ms
  90% in 0.222 ms
  95% in 0.278 ms
  99% in 0.453 ms
  99.9% in 0.845 ms
  99.99% in 1.452 ms
```

`-j` prints the same run as JSON, with every latency in seconds:

```json
{
  "url": "http://127.0.0.1:3010/",
  "protocol": "HTTP/2",
  "threads": 8,
  "connections": 8,
  "durationSeconds": 2.002848834,
  "requests": { "total": 722541, "ok": 722541, "errors": 0, "connectErrors": 0 },
  "requestsPerSec": 360757.1,
  "bytesReceived": 57803854,
  "bytesReceivedPerSec": 28860817.16140141,
  "bytesSent": 20233272,
  "bytesSentPerSec": 10102246.188790502,
  "statusCodes": { "200": 722541 },
  "latencySeconds": {
    "min": 0.000030961,
    "mean": 0.0001767384621343287,
    "max": 0.004210834,
    "percentiles": {
      "p10": 0.000103381, "p25": 0.000118051, "p50": 0.000152571,
      "p75": 0.000211807, "p90": 0.000294087, "p95": 0.000340413,
      "p99": 0.000424934, "p99.9": 0.000617066, "p99.99": 0.000876762
    }
  }
}
```

## Comparison with wrk and h2load

Measured against nginx 1.31.4 returning a 13-byte body, with 10 s per run,
median of 3 runs (5 for HTTP/2 and HTTP/3, where the spread is wider), and 16
threads for every tool. Numbers are requests/sec; higher is better.

| Protocol | Config | shb | [wrk] | [h2load] |
| --- | --- | ---: | ---: | ---: |
| HTTP/1.1 | 1000 connections | **993,170** | 856,476 | 796,238 |
| HTTP/2 (h2c) | 32 conns × 32 streams | **932,839** | — | 885,527 |
| HTTP/2 (h2c) | 100 conns × 100 streams | **1,255,321** | — | 1,205,942 |
| HTTP/3 | 32 conns × 32 streams | **2,054,015** | — | 1,466,884 |

[wrk]: https://github.com/wg/wrk
[h2load]: https://nghttp2.org/documentation/h2load-howto.html

```console
$ shb    -z 10s -c 1000 -t 16 http://127.0.0.1:3010/
$ wrk    -d 10s -c 1000 -t 16 http://127.0.0.1:3010/
$ h2load --h1 -D 10 -c 1000 -t 16 http://127.0.0.1:3010/
```

**On HTTP/1.1 shb is ahead of both** — 16 % over wrk and 25 % over h2load. Its
response path is a boundary scanner rather than a parser (see
[How it works](#how-it-works)), which is worth ~10 % on its own. The three land
much closer together at low connection counts, where the ceiling is a round
trip rather than the client: at 64 connections it is 476k / 458k / 425k.

**On HTTP/2 shb is 5 % ahead** at 32 × 32 and 4 % at 100 × 100. Like the
HTTP/1.1 path, its HTTP/2 stack is written for this one job: requests are a
single HPACK block encoded once at start-up, and responses are walked for
`:status` with every other field measured and skipped.

**On HTTP/3 shb is 40 % ahead**, and 26 % at 16 × 128. QPACK is where that
comes from: a profile of a saturated worker used to spend 47 % of its time
Huffman-decoding response header values, which the scanner now steps over
without reading. QUIC itself is still [quinn-proto], so the remaining cost is
mostly transport and crypto.

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
- **One `io_uring_enter` covers a batch of completions** rather than one each.
  A completion is what lets its connection issue the next request, so waiting
  on too many stalls the pipeline; a worker holds out for a quarter of its
  connections, capped at eight, and `min_wait_usec` caps how long the kernel
  waits for a batch that cannot be filled.
- **HTTP/1.1 responses are scanned, not parsed**: a load generator only needs
  to know where one response ends and the next begins, so the scanner reads the
  status line, `Content-Length`, `Transfer-Encoding` and `Connection`, and
  steps over every other header without looking at it. Lines are found with
  `memchr`, one case-insensitive byte decides whether a line is worth reading,
  nothing is allocated per response, and the scan runs straight over the
  receive buffer.
- **HTTP/2 requests are one pre-encoded HPACK block**, built once at start-up
  out of static-table indices and literals *without* indexing, so it never
  touches a dynamic table and the same bytes are memcpy'd for every stream on
  every connection. The client also advertises `SETTINGS_HEADER_TABLE_SIZE: 0`,
  which stops the peer indexing too — response decoding then needs no dynamic
  table, and only `:status` is decoded while every other field is measured and
  stepped over.
- **HTTP/3 does the same for QPACK**: the request field section is encoded
  once from static-table references, and `QPACK_MAX_TABLE_CAPACITY: 0` stops
  the peer inserting, so responses decode without a dynamic table and never
  block on one. Only `:status` is read; DATA and unknown frames are skipped by
  length.
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
