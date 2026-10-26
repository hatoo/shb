# shb — Simple HTTP Benchmarker

[![CI](https://github.com/hatoo/shb/actions/workflows/ci.yml/badge.svg)](https://github.com/hatoo/shb/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/shb.svg)](https://crates.io/crates/shb)

An HTTP load generator for Linux built on `io_uring`, speaking HTTP/1.1, HTTP/2
and HTTP/3 — and faster than the tools it stands beside on all three.

Against nginx on one 16-core machine, sixteen threads to every tool:

| Protocol | Config | shb | [wrk] | [h2load] |
| --- | --- | ---: | ---: | ---: |
| HTTP/1.1 | 1000 connections | **962,101** | 833,932 | 743,814 |
| HTTP/2 (h2c) | 100 conns × 100 streams | **1,505,202** | — | 1,184,362 |
| HTTP/3 | 32 conns × 32 streams | **2,412,605** | — | 1,294,761 |

Requests per second, measured on loopback with client and server sharing the
machine. See [Comparison](#comparison-with-wrk-and-h2load) for the full
results, single-thread measurements and reproduction commands.

The speed is in the shape of it. Protocol handling is Sans-I/O throughout, so
the whole client is one completion-driven event loop per thread with no async
runtime underneath. Every protocol stack is written for this one
job — HTTP/1.1, HTTP/2, HTTP/3, QPACK, HPACK and the QUIC transport itself —
see [How it works](#how-it-works). The only thing under them is [rustls], for
TLS and the QUIC key schedule.

## Features

- **Ahead of wrk and h2load on all three protocols** — see
  [Comparison](#comparison-with-wrk-and-h2load)
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

The [releases](https://github.com/hatoo/shb/releases) also carry prebuilt
`x86_64` and `aarch64` binaries. They are statically linked against musl, so
one binary runs whatever glibc the machine has rather than refusing to start on
anything older than the build machine's.


Or as a container image, which is that same static binary on `scratch` and
nothing else:

```console
$ docker run --rm --security-opt seccomp=unconfined \
    ghcr.io/hatoo/shb -z 10s -c 100 http://host.docker.internal:8080/
```

`--security-opt seccomp=unconfined` is not optional. Docker's default seccomp
profile denies `io_uring_setup`, which is the first thing shb does, and the
kernel's only way of saying so is `EPERM`; shb prints what to do about it and
stops.

Every build, released or not, replaces the system allocator with
[mimalloc](https://github.com/microsoft/mimalloc). That is what makes a musl
build worth having: musl's own allocator costs HTTP/2 31 % more userspace CPU
per request and 13 % of its throughput, and HTTP/3 10 % and 2 %. HTTP/1.1 does
not notice, since it spends 96 % of its time in the kernel. On glibc it
measures as no change in either direction. `cargo install shb
--no-default-features` opts out and uses the platform's allocator.

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
| `--batch-size` | worked out | How many completions a worker holds out for; see below |
| `--batch-linger` | `500` | Microseconds the kernel spends filling that batch; see below |
| `-m, --method` | `GET` (`POST` with `-d`) | HTTP method |
| `-H, --header` | — | Extra header, repeatable: `-H 'Name: Value'` |
| `-d, --data` | — | Request body; `@file` reads a file, `@-` reads stdin |
| `--connect-timeout` | `5s` | Connection establishment timeout |
| `--timeout` | off | Give up on a response after this long; the request counts as an error and its connection is replaced. On HTTP/2 the same goes for a connection that has carried nothing for this long while requests are still owed |
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
      --timeout <DURATION>
          How long to wait for a response before giving up on it (e.g. 30s). The request is counted as an error and its connection is replaced. Off by default, so a run against a server that stops answering waits rather than reporting
      --batch-size <COMPLETIONS>
          How many completions a worker holds out for, or 0 to work it out [default: 0]
      --batch-linger <MICROSECONDS>
          How long a worker may wait collecting completions, in microseconds [default: 500]
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
          Print help (see more with '--help')
```

The default for `-t` is the number of physical cores on the machine running
`shb`, so the value printed above (16) is whatever that host reported.

</details>

> **TLS certificates are never verified.** shb is a benchmarking tool, so it
> accepts any certificate — which is what you want against a test server with a
> self-signed cert, and what you must not rely on anywhere else.

Every connection does a full TLS handshake: session resumption is off, so a
`--disable-keepalive` run, or one that reconnects after a GOAWAY, costs the
server what a fresh client would — the same thing wrk and h2load measure.

### Batching

A worker waits for several completions at a time rather than one, so that one
`io_uring_enter` covers them all. Two things decide what that costs:
`--batch-size` is how many it holds out for, and `--batch-linger` is how long
the kernel spends trying to gather that many before giving up and returning
with whatever arrived.

The wait is only ever felt when the batch cannot be filled at once. That is
what makes it invisible in most runs and decisive in some: against a server
that is itself the bottleneck, completions trickle in and the wait fits inside
the server's own latency, saving the wakeups it batched away for nothing.
Against a server faster than shb can ask, it is the whole limit - a run's
throughput becomes what it has in flight divided by the wait, and the wait
shows up in the reported latencies as though the server had spent it.

Measured at `-t 16 -c 32 -p 32` against a server costing 0.05us a request:

| `--batch-linger` | requests/sec | p50 | shb CPU per request |
| --- | ---: | ---: | ---: |
| 500 (default) | 1,745,239 | 582us | 0.98us |
| 50 | 6,950,725 | 141us | 1.01us |
| 10 | 9,963,818 | 92us | 1.04us |

Against nginx over that same range the throughput barely moves and shb's own
CPU doubles, which is why the default is 500us. Lower it when the thing being
measured is faster than the wait.

How much it moves anything depends on the batch. At those settings, going from
500us to 10us is worth 14% at a batch of 2, 5.8x at 16 and 2.4x at 32. Left to
itself HTTP/1.1 and HTTP/3 never hold out for more than eight, and eight
arrive together, so the wait does nothing for them at any value - which is
what `--batch-size` is for. At 32 workers with one HTTP/3 connection each,
holding out for 16 completions reaches 6.7M requests a second with a 10us
wait, against 6.4M for the derived batch of 1.

The same example is the warning. That batch of 16 with the **default** wait
manages 1.7M: a batch raised without shortening the wait is the slowest thing
either flag can do, because every pass now waits the full 500us for a batch
nothing is going to fill. Raise them together or not at all.

## Output

```console
$ shb -z 3s -c 50 http://127.0.0.1:3010/
URL:          http://127.0.0.1:3010/
Protocol:     HTTP/1.1
Threads:      16
Connections:  50
Requests:     1210743 (1210743 ok, 0 errors, of which 0 connect) in 3.045s
Requests/sec: 397670.6
Transfer:     recv 61.06 MB/s (194929623 bytes), sent 15.17 MB/s (48430760 bytes)
Status codes:
  [200] 1210743
Latency (ms):
  min 0.016  mean 0.124  max 4.428
Latency distribution:
  10% in 0.066 ms
  25% in 0.089 ms
  50% in 0.113 ms
  75% in 0.144 ms
  90% in 0.186 ms
  95% in 0.223 ms
  99% in 0.344 ms
  99.9% in 0.643 ms
  99.99% in 1.452 ms
```

A request counts as an error when its stream is reset, its connection is
lost, or its response never comes. One that the server turns away
unprocessed — on a stream above the last one a GOAWAY says it acted on, or
reset with `REFUSED_STREAM` on HTTP/2 or `H3_REQUEST_REJECTED` on HTTP/3 —
is sent again and counted once, when it is answered, with its latency
measured from the resend. That is a server declining requests, however
many; a connection that closes without having answered anything is a server
declining the connection, and what it turned away on it counts as errors, so
that a server turning everything away ends a run rather than being asked
for ever.

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
  "latencySamples": 722541,
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

`latencySamples` is the number of recorded samples used for `latencySeconds`.
It equals `requests.ok`, including completed responses with HTTP error statuses.
Failed requests have no latency sample. With no successes it is zero and
`latencySeconds` is `null`. The count is read from the sample storage after the
run; it does not expose individual samples or change timestamp collection.

## Comparison with wrk and h2load

Measured on 2026-10-26 against nginx 1.31.8 returning a 13-byte body, with
10 s per run, median of 3 runs, and 16 threads for every tool. Clients run
sequentially, with their order rotated between rounds. Numbers are
requests/sec; higher is better. Per-run rates and commands are recorded in
[the measurement data](benchmarks/2026-10-26.json).

| Protocol | Config | shb | [wrk] | [h2load] |
| --- | --- | ---: | ---: | ---: |
| HTTP/1.1 | 1000 connections | **962,101** | 833,932 | 743,814 |
| HTTP/2 (h2c) | 32 conns × 32 streams | **1,047,612** | — | 859,901 |
| HTTP/2 (h2c) | 100 conns × 100 streams | **1,505,202** | — | 1,184,362 |
| HTTP/3 | 32 conns × 32 streams | **2,412,605** | — | 1,294,761 |
| HTTP/3 | 16 conns × 128 streams | **1,800,190** | — | 1,049,777 |

[wrk]: https://github.com/wg/wrk
[h2load]: https://nghttp2.org/documentation/h2load-howto.html

```console
$ shb    -z 10s -c 1000 -t 16 http://127.0.0.1:3010/
$ wrk    -d 10s -c 1000 -t 16 http://127.0.0.1:3010/
$ h2load --h1 -D 10 -c 1000 -t 16 http://127.0.0.1:3010/
```

Client and server share the same CPU budget. These figures measure the
combined system on this host; they do not isolate the client's maximum
throughput or CPU cost. The server configuration and TLS library also affect
the result, so comparisons need the same server for every client.

### Single-thread comparison

With one worker thread per client, using the same server and three 10-second
runs per tool:

| Protocol | Config | shb | [wrk] | [h2load] |
| --- | --- | ---: | ---: | ---: |
| HTTP/1.1 | 64 connections | **40,997** | 30,093 | 27,612 |
| HTTP/2 (h2c) | 4 conns × 32 streams | **333,345** | — | 224,449 |
| HTTP/3 | 4 conns × 32 streams | **634,545** | — | 221,040 |

The lower client thread count leaves more CPU available to nginx. This is a
separate workload, with fewer connections, rather than a scaling ratio for
the sixteen-thread table. No CPU affinity was set. In the single-thread
HTTP/2 case, shb ranged from 242,158 to 334,744 requests/sec across the three
runs; the table reports the median, not the fastest run.

<details>
<summary>Environment and caveats</summary>

**Machine**

| | |
| --- | --- |
| CPU | AMD Ryzen 9 3950X — 16 cores / 32 threads |
| Memory | 31 GiB |
| OS | Ubuntu 24.04.5 LTS on **WSL2** |
| Kernel | 6.18.54.1-microsoft-standard-WSL2 |
| Rust | 1.99.1 |

**Tools**

- shb at `9503fe9`, built with `cargo build --release --locked` (full LTO, one
  codegen unit). The `dist` profile additionally strips symbols. Released
  binaries add profile-guided optimisation; these measurements do not use PGO.
- wrk 4.1.0 (Ubuntu package).
- h2load from nghttp2 1.71.0-DEV, built against ngtcp2 1.25.90,
  nghttp3 1.18.90 and BoringSSL — the distro build of h2load has no HTTP/3 support.

**Server** — nginx 1.31.8 (mainline) built from source with
`--with-http_v3_module` against BoringSSL, on the same host, serving HTTP/1.1
and h2c on one cleartext socket and HTTP/3 on a QUIC socket with a self-signed
certificate. `worker_processes auto` starts 32 nginx workers on this host.
GSO uses nginx's default (`quic_gso off`). `return 200` keeps it off the disk
entirely; the complete config is [benchmarks/nginx.conf](benchmarks/nginx.conf):

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

### Reproducing the comparison

Run these commands from the repository root. The build script installs nginx
1.31.8 with HTTP/2 and HTTP/3 into `../nginx-h3`, alongside this checkout.
It pins BoringSSL to commit `533902fb2e8fd0586db7d58879d697721726605a`
and verifies the nginx source archive's SHA-256. This follows nginx's
[QUIC build instructions](https://nginx.org/en/docs/quic.html).

Build prerequisites on Ubuntu: `build-essential`, `cmake`, `ninja-build`,
`golang-go`, `git`, `curl`, `libpcre2-dev`, `zlib1g-dev` and `openssl`.
Python 3 runs the comparison script. Install `wrk` and an HTTP/3-enabled
[h2load] separately; check that `h2load --help` includes `--h3`.

```sh
bash scripts/build-benchmark-nginx.sh ../nginx-h3
cargo build --release --locked

# Self-signed certificate and the exact configuration used for the tables.
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj /CN=localhost \
  -keyout ../nginx-h3/key.pem -out ../nginx-h3/cert.pem
cp benchmarks/nginx.conf ../nginx-h3/benchmark.conf
../nginx-h3/sbin/nginx -p "$(realpath ../nginx-h3)/" -c benchmark.conf -t
../nginx-h3/sbin/nginx -p "$(realpath ../nginx-h3)/" -c benchmark.conf

python3 scripts/benchmark.py --h2load /path/to/http3-enabled/h2load \
  --output ../nginx-h3/results

# Stop only this benchmark server after measuring.
../nginx-h3/sbin/nginx -p "$(realpath ../nginx-h3)/" -c benchmark.conf -s quit
```

The server binds loopback TCP port 3010 and UDP port 3453. Leave both ports
free before starting it. If h2load uses shared ngtcp2/nghttp3 libraries outside
the system library path, set `LD_LIBRARY_PATH` to their directory.

The script runs all eight table configurations, rotates client order between
rounds, checks for request errors, and saves each command's stdout/stderr plus
per-run rates and medians in `summary.json`. It requires a new output directory
to preserve previous measurements. The defaults are three 10-second runs per
client and configuration; allow roughly ten minutes on an otherwise idle host.

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
  on too many stalls the pipeline; on HTTP/1.1 and HTTP/3 a worker holds out
  for a quarter of its connections, capped at eight, and on HTTP/2 — where
  every stream shares one socket and completions arrive together — for half of
  `-p`, capped at 32. Both halves of that are settable; see
  [Batching](#batching).
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
- **QUIC is shb's own**, because a benchmark client needs a fraction of what a
  general implementation carries. There is no server role, no connection
  migration, no datagram extension and one congestion controller. Packets are
  built straight into the datagram buffer the kernel will send, so a datagram
  costs no allocation; decoded frames borrow from the datagram rather than
  taking a reference count on it; and the streams a client opens are numbered
  in order, so they live in a ring indexed by arithmetic instead of a hash
  map. Against a profile of the same workload on quinn-proto that is 36 % less
  userspace CPU per request and 11 % more throughput. rustls still does the
  TLS handshake, the QUIC key schedule and the packet protection — that part
  is not worth anyone rewriting.
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
against them, and assert on its JSON report. quinn is a dependency of the tests
only, and deliberately so: since shb has its own QUIC, the end-to-end tests
answer it with somebody else's.

```console
$ scripts/docker-interop.sh   # nginx, Caddy, HAProxy, httpd, Envoy, ... in containers
$ scripts/interop.sh          # or: scripts/interop.sh h3
```

`scripts/docker-interop.sh` starts seventeen HTTP servers in containers —
nginx, Caddy, HAProxy, httpd, Envoy, Varnish, Traefik, Tomcat, OpenLiteSpeed,
Hypercorn, Node, Deno, Go, picoquic, H2O, nghttpx and Bun — and loads each
over every protocol it speaks, 84 combinations in all, including cleartext h2c
and HTTP/3 against eight separate QUIC implementations: nginx's own, quic-go,
Google's QUICHE, aioquic, picoquic, quicly, ngtcp2 and Bun's. Five of them
carry an image of their own. H2O and nghttpx are compiled from source, since
their projects publish none to run, and nghttpx earns its place as much for
HTTP/2, being the reference implementation, as for HTTP/3. Hypercorn, Node and
Go are a few lines each on an official base image, and they are there because
the suite had drifted towards C proxies sharing the same libraries, while
those three each implement HTTP/2 themselves.

nginx serves three endpoints besides the 13-byte one, to reach paths a
well-behaved page-sized response never does: a reply behind 48 KB of headers,
three times the default HTTP/2 frame size and so split across CONTINUATION
frames; a body larger than one receive buffer, TLS record or QUIC datagram;
and a location that takes the connection away part way through the run —
GOAWAY on HTTP/2 and HTTP/3, `Connection: close` on HTTP/1.1. The first and
last were checked to actually happen rather than assumed: two CONTINUATION
frames arrive, and ten GOAWAYs for ten connections. Those are servers we start
ourselves, so it runs in CI on every push, with 200 requests over 10
connections — enough to exercise
connection reuse rather than just the first exchange, and low enough that the
run measures protocol correctness rather than how much load each server can
take. That distinction has teeth: aioquic is a QUIC implementation written in
Python, and 50 concurrent handshakes cost it eight seconds where nginx needs
fifty milliseconds.

Local servers only exercise what they happen to do. `scripts/interop.sh` sends
one request to each of 44 public endpoints over every protocol it speaks, 82
checks in all, and reports whether the exchange completed. It runs weekly
rather than on every push: it depends on other people's servers, and on the
network. Any HTTP status counts
as a pass, since a 403 from a server that blocks unknown clients still means
the framing, header coding and TLS all worked — with one exception, a 1xx,
which means we stopped reading before the real response.

The endpoints are chosen by implementation, not by name recognition: twenty
sites behind the same CDN exercise one HTTP stack twenty times, and what finds
bugs is a different stack. HTTP/3 is where that matters most — quicly, ngtcp2,
picoquic, aioquic, quic-go, Cloudflare's quiche, msquic, mvfst, lsquic, XQUIC,
nginx's own, HAProxy's own and Google's QUICHE are thirteen separate QUIC
implementations, several of them run by the people who wrote the
specification. HTTP/2 covers nghttp2, H2O, Apache httpd, Traffic Server,
Jetty, Hypercorn, Proxygen, Caddy, HAProxy, Tengine, OpenResty and the large
CDN edges, plus a gRPC endpoint for the
trailers a plain GET never produces and an `Expect: 100-continue` request for a
real interim response; HTTP/1.1 adds cleartext, origins whose
ALPN offers only `http/1.1`, and one that offers no ALPN at all.

That breadth is what finds bugs. Widening this list is what caught an HTTP/3
connection being torn down by an ICMP reply to our own MTU probe, and a 103
Early Hints being recorded as the response status; an earlier round caught a
wrong Huffman table entry and a TLS buffer limit. None of them could be
reproduced against a local server.

Writing shb's own QUIC made that concrete. Five of its bugs only ever appeared
against somebody else's implementation, because a server on loopback does not
drop packets, does not reorder them, and does not send anything after a stream
ends: a probe sent on every pass rather than once per timeout, handshake bytes
dropped before they were acknowledged, a retired stream mistaken for one never
opened, loss detection outliving the keys it belonged to, and handshake data
fed to rustls in whatever order it arrived. The last of those was a deliberate
decision, written down as one — reordering is rare on a single path — and it
held right up until it met the internet, where a certificate chain spans
several packets.

Servers that were probed and simply worked are recorded in a `KNOWN_GOOD` list
in the same script rather than run — 288 more endpoints, most of them behind a
CDN already represented above. `EXTRA=1 scripts/interop.sh` includes them. It
is a list of servers shb is known to work with, and any line can be promoted
the day it stops passing.

## License

MIT — see [LICENSE](LICENSE).
