//! End-to-end tests: run the compiled shb binary against local test servers
//! and assert on the JSON report.
//!
//! - HTTP/1.1 and h2c (prior knowledge): one axum server (hyper auto mode)
//! - HTTP/3: quinn + h3 with an rcgen self-signed certificate, which the
//!   trust-everything client accepts
//!
//! Grouped by protocol, after the shared helpers and the argument checks that
//! need no server at all. Each protocol's own servers and helpers sit with the
//! tests that use them.

use std::net::SocketAddr;
use std::process::Command;
use std::sync::OnceLock;

use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::routing::any;

/// Status code by method so tests can verify the method actually reached the
/// server. A request carrying an `X-Echo` header must send a matching body,
/// and vice versa, so a single 200/201/... response proves both arrived.
async fn handler(method: Method, headers: HeaderMap, body: Bytes) -> (StatusCode, &'static str) {
    // A body too large to name in a header says how long it should be, which
    // is what proves a body that had to be split across flow-control windows
    // arrived whole rather than merely started
    if let Some(want) = headers.get("x-body-len") {
        let want: usize = std::str::from_utf8(want.as_bytes())
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(usize::MAX);
        return if body.len() == want {
            (StatusCode::OK, "body complete")
        } else {
            (StatusCode::BAD_REQUEST, "body truncated")
        };
    }
    // If the client sent our marker header, its value must equal the body
    if let Some(echo) = headers.get("x-echo") {
        if echo.as_bytes() != body.as_ref() {
            return (StatusCode::BAD_REQUEST, "header/body mismatch");
        }
    } else if !body.is_empty() {
        return (StatusCode::BAD_REQUEST, "unexpected body");
    }
    // A request naming the method it expects proves the method arrived
    // intact, which a status code alone cannot: an unknown method and a
    // mangled one both come back the same way otherwise.
    if let Some(want) = headers.get("x-expect-method") {
        return if want.as_bytes() == method.as_str().as_bytes() {
            (StatusCode::OK, "method matched")
        } else {
            (StatusCode::CONFLICT, "method mismatch")
        };
    }
    match method {
        // hyper strips the body for HEAD responses but keeps Content-Length,
        // which is exactly the case the h1 HEAD decoding must handle
        Method::GET | Method::HEAD => (StatusCode::OK, "hello world"),
        Method::POST => (StatusCode::CREATED, "created"),
        Method::DELETE => (StatusCode::NO_CONTENT, ""),
        _ => (StatusCode::METHOD_NOT_ALLOWED, ""),
    }
}

/// Every method in the IANA HTTP Method Registry
///
/// shb does not know what any of them mean - it validates the token and puts
/// it on the wire - but that is exactly why the list is worth walking: a
/// hyphen or an unusual length is the kind of thing a request builder gets
/// wrong, and a benchmark of a WebDAV or CalDAV server is a real use.
///
/// CONNECT is left out. It establishes a tunnel and takes an authority-form
/// target rather than a path, so there is nothing here for a load generator
/// to send and every protocol rejects it in the ordinary request shape.
const REGISTERED_METHODS: &[&str] = &[
    "ACL",
    "BASELINE-CONTROL",
    "BIND",
    "CHECKIN",
    "CHECKOUT",
    "COPY",
    "DELETE",
    "GET",
    "HEAD",
    "LABEL",
    "LINK",
    "LOCK",
    "MERGE",
    "MKACTIVITY",
    "MKCALENDAR",
    "MKCOL",
    "MKREDIRECTREF",
    "MKWORKSPACE",
    "MOVE",
    "OPTIONS",
    "ORDERPATCH",
    "PATCH",
    "POST",
    "PROPFIND",
    "PROPPATCH",
    "PUT",
    "QUERY",
    "REBIND",
    "REPORT",
    "SEARCH",
    "TRACE",
    "UNBIND",
    "UNCHECKOUT",
    "UNLINK",
    "UNLOCK",
    "UPDATE",
    "UPDATEREDIRECTREF",
    "VERSION-CONTROL",
];

/// Bound addresses of the shared test server: (IPv4, IPv6)
fn server_addrs() -> (SocketAddr, SocketAddr) {
    static SERVER: OnceLock<(SocketAddr, SocketAddr)> = OnceLock::new();
    *SERVER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async move {
                let app = Router::new()
                    .route("/", any(handler))
                    .route("/{*path}", any(handler));
                let v4 = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind v4");
                let v6 = tokio::net::TcpListener::bind("[::1]:0")
                    .await
                    .expect("bind v6");
                tx.send((
                    v4.local_addr().expect("v4 addr"),
                    v6.local_addr().expect("v6 addr"),
                ))
                .expect("send addrs");
                let _ = tokio::join!(axum::serve(v4, app.clone()), axum::serve(v6, app));
            });
        });
        rx.recv().expect("server startup")
    })
}

/// Run shb expecting success and return the parsed JSON report
fn shb_json(args: &[&str]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_shb"))
        .arg("-j")
        .args(args)
        .output()
        .expect("run shb");
    assert!(
        output.status.success(),
        "shb failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON report")
}

/// Run shb expecting failure and return stderr
fn shb_fail(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_shb"))
        .args(args)
        .output()
        .expect("run shb");
    assert!(!output.status.success(), "shb unexpectedly succeeded");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_all_ok(report: &serde_json::Value, n: u64, status: &str) {
    assert_eq!(report["requests"]["ok"], n, "report: {report}");
    assert_eq!(report["requests"]["errors"], 0, "report: {report}");
    assert_eq!(report["statusCodes"][status], n, "report: {report}");
}

/// Send every registered method and report the ones that did not arrive
///
/// The server answers 200 only when the method it saw equals the one the
/// request named, so this checks transmission rather than just that something
/// came back. Every failure is collected: which methods fail is the useful
/// part, not that one did.
fn assert_every_method_arrives(protocol: &[&str], url: &str) {
    let mut failed = Vec::new();
    for method in REGISTERED_METHODS {
        let expect = format!("x-expect-method: {method}");
        let mut args = protocol.to_vec();
        args.extend([
            "-m", method, "-H", &expect, "-n", "2", "-c", "1", "-t", "1", url,
        ]);
        let report = shb_json(&args);
        if report["requests"]["ok"] != 2 || report["statusCodes"]["200"] != 2 {
            failed.push(format!("{method} -> {}", report["statusCodes"]));
        }
    }
    assert!(
        failed.is_empty(),
        "methods that did not arrive: {failed:#?}"
    );
}

// ------------------------------------------------------------------------
// Arguments
//
// Rejected before anything is sent, so these need no server.
// ------------------------------------------------------------------------

#[test]
fn invalid_scheme_is_rejected() {
    let stderr = shb_fail(&["-n", "1", "ftp://127.0.0.1/"]);
    assert!(stderr.contains("http"), "stderr: {stderr}");
}

#[test]
fn invalid_method_is_rejected() {
    let stderr = shb_fail(&["-m", "GE T", "-n", "1", "http://127.0.0.1:9/"]);
    assert!(stderr.contains("method"), "stderr: {stderr}");
}

#[test]
fn invalid_header_format_is_rejected() {
    let stderr = shb_fail(&["-H", "no-colon-here", "-n", "1", "http://127.0.0.1:9/"]);
    assert!(stderr.contains("header"), "stderr: {stderr}");
}

#[test]
fn parallel_requires_a_multiplexed_protocol() {
    let stderr = shb_fail(&["-p", "4", "-n", "1", "http://127.0.0.1:9/"]);
    assert!(
        stderr.contains("--http2") || stderr.contains("proto"),
        "stderr: {stderr}"
    );
}

#[test]
fn http3_requires_https() {
    let stderr = shb_fail(&["--http3", "-n", "1", "http://127.0.0.1:9/"]);
    assert!(stderr.contains("https"), "stderr: {stderr}");
}

#[test]
fn disable_keepalive_conflicts_with_http2_and_http3() {
    let stderr = shb_fail(&["--disable-keepalive", "--http2", "http://127.0.0.1:1/"]);
    assert!(
        stderr.contains("cannot be used with"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn body_from_missing_file_is_rejected() {
    let stderr = shb_fail(&["-d", "@/no/such/shb/file", "-n", "1", "http://127.0.0.1:9/"]);
    assert!(stderr.contains("file"), "stderr: {stderr}");
}

#[test]
fn connect_error_is_counted() {
    // Port 9 (discard) is almost certainly closed
    let report = shb_json(&["-n", "4", "-c", "2", "-t", "1", "http://127.0.0.1:9/"]);
    assert_eq!(report["requests"]["errors"], 4, "report: {report}");
    assert_eq!(report["requests"]["connectErrors"], 4, "report: {report}");
}

// ------------------------------------------------------------------------
// HTTP/1.1
//
// Against the axum server, except for the keep-alive pair at the end,
// which needs a server that ignores Connection: close.
// ------------------------------------------------------------------------

#[test]
fn h1_get() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    let report = shb_json(&["-n", "50", "-c", "4", "-t", "2", &url]);
    assert_eq!(report["protocol"], "HTTP/1.1");
    assert_all_ok(&report, 50, "200");
}

#[test]
fn h1_url_without_path_defaults_to_root() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}");
    let report = shb_json(&["-n", "20", "-c", "2", "-t", "1", &url]);
    assert_all_ok(&report, 20, "200");
}

#[test]
fn h1_method_is_sent_to_the_server() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    let report = shb_json(&["-m", "POST", "-n", "30", "-c", "2", "-t", "1", &url]);
    assert_all_ok(&report, 30, "201");
    let report = shb_json(&["-m", "DELETE", "-n", "30", "-c", "2", "-t", "1", &url]);
    assert_all_ok(&report, 30, "204");
}

#[test]
fn h1_head_with_content_length_and_no_body() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    // Keep-alive HEAD responses regress easily: the decoder must know the
    // method to parse a header-only response with a Content-Length
    let report = shb_json(&["-m", "HEAD", "-n", "50", "-c", "2", "-t", "1", &url]);
    assert_all_ok(&report, 50, "200");
}

#[test]
fn h1_ipv6_literal() {
    let (_, v6) = server_addrs();
    let url = format!("http://[::1]:{}/", v6.port());
    let report = shb_json(&["-n", "20", "-c", "2", "-t", "1", &url]);
    assert_all_ok(&report, 20, "200");
}

#[test]
fn h1_duration_mode() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    let report = shb_json(&["-z", "300ms", "-c", "2", "-t", "1", &url]);
    assert_eq!(report["requests"]["errors"], 0, "report: {report}");
    assert!(
        report["requests"]["ok"].as_u64().unwrap() > 0,
        "report: {report}"
    );
}

#[test]
fn h1_custom_header_and_body() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    // The server returns 400 unless the X-Echo header matches the body
    let report = shb_json(&[
        "-m",
        "POST",
        "-H",
        "X-Echo: hello",
        "-d",
        "hello",
        "-n",
        "30",
        "-c",
        "2",
        "-t",
        "1",
        &url,
    ]);
    assert_all_ok(&report, 30, "201");
}

#[test]
fn h1_host_header_override() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    // Overriding Host must not break the request against this server
    let report = shb_json(&[
        "-H",
        "Host: example.com",
        "-n",
        "20",
        "-c",
        "2",
        "-t",
        "1",
        &url,
    ]);
    assert_all_ok(&report, 20, "200");
}

#[test]
fn h1_body_defaults_to_post() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    // -d without -m should send POST (curl semantics) -> 201
    let report = shb_json(&[
        "-H",
        "X-Echo: abc",
        "-d",
        "abc",
        "-n",
        "20",
        "-c",
        "2",
        "-t",
        "1",
        &url,
    ]);
    assert_all_ok(&report, 20, "201");
}

#[test]
fn h1_mismatched_body_is_rejected_by_server() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    // Echo header present but body differs -> server returns 400
    let report = shb_json(&[
        "-m",
        "POST",
        "-H",
        "X-Echo: hello",
        "-d",
        "world",
        "-n",
        "10",
        "-c",
        "2",
        "-t",
        "1",
        &url,
    ]);
    assert_eq!(report["statusCodes"]["400"], 10, "report: {report}");
}

#[test]
fn h1_body_from_file() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    let dir = std::env::temp_dir();
    let path = dir.join(format!("shb_body_{}.txt", std::process::id()));
    std::fs::write(&path, b"filebody").expect("write body file");
    let arg = format!("@{}", path.display());
    let report = shb_json(&[
        "-m",
        "POST",
        "-H",
        "X-Echo: filebody",
        "-d",
        &arg,
        "-n",
        "20",
        "-c",
        "2",
        "-t",
        "1",
        &url,
    ]);
    let _ = std::fs::remove_file(&path);
    assert_all_ok(&report, 20, "201");
}

#[test]
fn h1_body_from_file_strips_newlines() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    let dir = std::env::temp_dir();
    let path = dir.join(format!("shb_body_nl_{}.txt", std::process::id()));
    // curl strips CR/LF from @file data, so the server should receive " abc"
    std::fs::write(&path, b"a\r\nb\nc").expect("write body file");
    let arg = format!("@{}", path.display());
    let report = shb_json(&[
        "-m",
        "POST",
        "-H",
        "X-Echo: abc",
        "-d",
        &arg,
        "-n",
        "10",
        "-c",
        "2",
        "-t",
        "1",
        &url,
    ]);
    let _ = std::fs::remove_file(&path);
    assert_all_ok(&report, 10, "201");
}

/// A minimal HTTP/1.1 server that deliberately **ignores** `Connection: close`
/// and always answers keep-alive, so the tests can prove that
/// `--disable-keepalive` closes the connection on the client side rather than
/// relying on the server to cooperate.
struct StubbornServer {
    addr: SocketAddr,
    /// Accepted TCP connections
    conns: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Highest number of requests served on a single connection
    max_reqs_per_conn: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Whether any request carried a `Connection: close` header
    saw_close_header: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

fn start_stubborn_server() -> StubbornServer {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let conns = Arc::new(AtomicUsize::new(0));
    let max_reqs_per_conn = Arc::new(AtomicUsize::new(0));
    let saw_close_header = Arc::new(AtomicBool::new(false));

    let (c, m, h) = (
        Arc::clone(&conns),
        Arc::clone(&max_reqs_per_conn),
        Arc::clone(&saw_close_header),
    );
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            c.fetch_add(1, Ordering::Relaxed);
            let (m, h) = (Arc::clone(&m), Arc::clone(&h));
            std::thread::spawn(move || {
                let mut pending = Vec::new();
                let mut chunk = [0u8; 4096];
                let mut served = 0usize;
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => pending.extend_from_slice(&chunk[..n]),
                    }
                    // Answer every complete request head in the buffer. The
                    // tests only send bodyless requests, so the head is the
                    // whole request.
                    while let Some(end) = pending
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|i| i + 4)
                    {
                        let head = String::from_utf8_lossy(&pending[..end]).to_lowercase();
                        if head.contains("connection: close") {
                            h.store(true, Ordering::Relaxed);
                        }
                        pending.drain(..end);
                        served += 1;
                        // Publish per response, not at EOF: the test reads
                        // this right after shb exits, before the peer close
                        // is necessarily observed here
                        m.fetch_max(served, Ordering::Relaxed);
                        // No Connection header: HTTP/1.1 defaults to
                        // keep-alive, whatever the request asked for. A
                        // DELETE gets a 204 with no framing header at all,
                        // which is how nginx sends one
                        let response: &[u8] = if head.starts_with("delete ") {
                            b"HTTP/1.1 204 No Content\r\n\r\n"
                        } else {
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                        };
                        if stream.write_all(response).is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });

    StubbornServer {
        addr,
        conns,
        max_reqs_per_conn,
        saw_close_header,
    }
}

#[test]
fn h1_disable_keepalive_uses_one_connection_per_request() {
    use std::sync::atomic::Ordering;

    let server = start_stubborn_server();
    let url = format!("http://{}/", server.addr);
    let report = shb_json(&[
        "--disable-keepalive",
        "-n",
        "20",
        "-c",
        "1",
        "-t",
        "1",
        &url,
    ]);
    assert_all_ok(&report, 20, "200");

    assert!(
        server.saw_close_header.load(Ordering::Relaxed),
        "requests should carry Connection: close"
    );
    assert_eq!(
        server.max_reqs_per_conn.load(Ordering::Relaxed),
        1,
        "every connection should serve exactly one request"
    );
    // One connection per request, plus the one opened for the request that
    // the run ends on
    assert!(
        server.conns.load(Ordering::Relaxed) >= 20,
        "expected at least 20 connections, got {}",
        server.conns.load(Ordering::Relaxed)
    );
}

#[test]
fn h1_keepalive_reuses_the_connection_by_default() {
    use std::sync::atomic::Ordering;

    let server = start_stubborn_server();
    let url = format!("http://{}/", server.addr);
    let report = shb_json(&["-n", "20", "-c", "1", "-t", "1", &url]);
    assert_all_ok(&report, 20, "200");

    assert!(
        !server.saw_close_header.load(Ordering::Relaxed),
        "Connection: close should not be sent without --disable-keepalive"
    );
    assert_eq!(
        server.max_reqs_per_conn.load(Ordering::Relaxed),
        20,
        "all 20 requests should share one connection"
    );
}

/// A 204 has neither Content-Length nor Transfer-Encoding, and used to be
/// read as close-delimited for it, which put every request on a connection
/// of its own: 50 connections for `-c 1 -n 50` against nginx
#[test]
fn h1_a_204_without_content_length_keeps_its_connection() {
    use std::sync::atomic::Ordering;

    let server = start_stubborn_server();
    let url = format!("http://{}/", server.addr);
    let report = shb_json(&["-m", "DELETE", "-n", "20", "-c", "1", "-t", "1", &url]);
    assert_all_ok(&report, 20, "204");

    assert_eq!(
        server.max_reqs_per_conn.load(Ordering::Relaxed),
        20,
        "all 20 requests should share one connection"
    );
}

/// Every registered method reaches the server intact over HTTP/1.1
///
/// The server answers 200 only when the method it saw equals the one the
/// request said it was sending, so this checks transmission rather than
/// just that something arrived.
#[test]
fn h1_every_registered_method_arrives() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    assert_every_method_arrives(&[], &url);
}

// ------------------------------------------------------------------------
// HTTP/2
//
// Cleartext h2c with prior knowledge, against the same axum server.
// ------------------------------------------------------------------------

#[test]
fn h2_get() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    let report = shb_json(&["--http2", "-p", "4", "-n", "50", "-c", "2", "-t", "1", &url]);
    assert_eq!(report["protocol"], "HTTP/2");
    assert_all_ok(&report, 50, "200");
}

#[test]
fn h2_method_is_sent_to_the_server() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    let report = shb_json(&[
        "--http2", "-m", "POST", "-n", "30", "-c", "2", "-t", "1", &url,
    ]);
    assert_all_ok(&report, 30, "201");
}

#[test]
fn h2_custom_header_and_body() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    let report = shb_json(&[
        "--http2",
        "-m",
        "POST",
        "-H",
        "X-Echo: hi",
        "-d",
        "hi",
        "-n",
        "30",
        "-c",
        "2",
        "-t",
        "1",
        &url,
    ]);
    assert_all_ok(&report, 30, "201");
}

/// The same over HTTP/2, where the method is a pseudo-header rather than
/// the first word of a request line
#[test]
fn h2_every_registered_method_arrives() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    assert_every_method_arrives(&["--http2"], &url);
}

/// What a scripted HTTP/2 server does, beyond answering every request 200
///
/// hyper behind axum is a well-behaved peer, and the things the protocol
/// lets a server do to a client - shrink the header table, refuse streams,
/// go away - are the things it does not do on demand. This one does nothing
/// but those, on a raw socket, one thread per connection.
#[derive(Clone, Copy, Default)]
struct H2Script {
    /// Advertise SETTINGS_HEADER_TABLE_SIZE 0 and, once the client has
    /// acknowledged it, tear the connection down unless the next header block
    /// opens with the dynamic table size update RFC 7541 Section 4.2 says it
    /// must. That is what nghttp2 does.
    header_table_size_zero: bool,
    /// Act on this many streams per connection and no more: the first one
    /// past the line draws a GOAWAY naming the last one acted on, streams
    /// above it are never answered, and the connection closes once those
    /// below it have been. That is nginx's keepalive_requests.
    streams_per_connection: Option<u32>,
    /// Advertise this many concurrent streams and take that many of the
    /// HEADERS in one read, refusing the rest with RST_STREAM(REFUSED_STREAM)
    /// as a server does when a client opens more than it said it would take.
    /// Node with maxConcurrentStreams does this to a first flight.
    accept_per_read: Option<usize>,
}

fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut v = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn start_scripted_h2_server(script: H2Script) -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            std::thread::spawn(move || serve_scripted_h2(stream, script));
        }
    });
    addr
}

fn serve_scripted_h2(mut sock: std::net::TcpStream, script: H2Script) {
    use std::io::{Read, Write};
    const DATA: u8 = 0x0;
    const HEADERS: u8 = 0x1;
    const RST_STREAM: u8 = 0x3;
    const SETTINGS: u8 = 0x4;
    const PING: u8 = 0x6;
    const GOAWAY: u8 = 0x7;
    const WINDOW_UPDATE: u8 = 0x8;
    const FLAG_ACK: u8 = 0x1;
    const FLAG_END_STREAM: u8 = 0x1;
    const FLAG_END_HEADERS: u8 = 0x4;
    const NO_ERROR: u32 = 0x0;
    const REFUSED_STREAM: u32 = 0x7;
    const COMPRESSION_ERROR: u32 = 0x9;

    let goaway = |last: u32, code: u32| {
        let mut payload = last.to_be_bytes().to_vec();
        payload.extend_from_slice(&code.to_be_bytes());
        h2_frame(GOAWAY, 0, 0, &payload)
    };
    // The highest stream id this connection acts on
    let last_stream = script
        .streams_per_connection
        .map_or(u32::MAX, |n| (2 * n).saturating_sub(1));

    let mut settings = Vec::new();
    if script.header_table_size_zero {
        settings.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
    }
    if let Some(n) = script.accept_per_read {
        settings.extend_from_slice(&[0, 3]);
        settings.extend_from_slice(&(n as u32).to_be_bytes());
    }
    if sock
        .write_all(&h2_frame(SETTINGS, 0, 0, &settings))
        .is_err()
    {
        return;
    }

    let mut pending = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut preface_read = false;
    // The first header block after the client acknowledges our SETTINGS is
    // the one that owes the size update
    let mut size_update_due = false;
    // Streams whose request body has not finished arriving
    let mut awaiting_body: Vec<u32> = Vec::new();
    let mut goaway_sent = false;
    loop {
        match sock.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
        }
        if !preface_read {
            if pending.len() < 24 {
                continue;
            }
            assert_eq!(&pending[..24], b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            pending.drain(..24);
            preface_read = true;
        }
        let mut out = Vec::new();
        let mut pos = 0;
        let mut accepted_this_read = 0;
        while pending.len() - pos >= 9 {
            let h = &pending[pos..pos + 9];
            let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
            let (kind, flags) = (h[3], h[4]);
            let stream = u32::from_be_bytes([h[5] & 0x7f, h[6], h[7], h[8]]);
            if pending.len() < pos + 9 + len {
                break;
            }
            let payload = &pending[pos + 9..pos + 9 + len];
            pos += 9 + len;

            let respond = |out: &mut Vec<u8>, stream: u32| {
                out.extend_from_slice(&h2_frame(
                    HEADERS,
                    FLAG_END_HEADERS | FLAG_END_STREAM,
                    stream,
                    &[0x88],
                ));
            };
            match kind {
                SETTINGS if flags & FLAG_ACK != 0 => {
                    size_update_due = script.header_table_size_zero;
                }
                SETTINGS => out.extend_from_slice(&h2_frame(SETTINGS, FLAG_ACK, 0, &[])),
                PING if flags & FLAG_ACK == 0 => {
                    out.extend_from_slice(&h2_frame(PING, FLAG_ACK, 0, payload));
                }
                HEADERS => {
                    // The client sets neither PADDED nor PRIORITY, so the
                    // block starts at the payload. The update is 001xxxxx.
                    if std::mem::take(&mut size_update_due)
                        && payload.first().map(|b| b & 0xe0) != Some(0x20)
                    {
                        let _ = sock.write_all(&goaway(0, COMPRESSION_ERROR));
                        return;
                    }
                    if stream > last_stream {
                        if !goaway_sent {
                            out.extend_from_slice(&goaway(last_stream, NO_ERROR));
                            goaway_sent = true;
                        }
                        continue;
                    }
                    if script
                        .accept_per_read
                        .is_some_and(|n| accepted_this_read >= n)
                    {
                        out.extend_from_slice(&h2_frame(
                            RST_STREAM,
                            0,
                            stream,
                            &REFUSED_STREAM.to_be_bytes(),
                        ));
                        continue;
                    }
                    accepted_this_read += 1;
                    if flags & FLAG_END_STREAM != 0 {
                        respond(&mut out, stream);
                    } else {
                        awaiting_body.push(stream);
                    }
                }
                DATA if stream > last_stream => {}
                DATA => {
                    // Credit goes straight back, on both windows
                    let credit = (len as u32).to_be_bytes();
                    out.extend_from_slice(&h2_frame(WINDOW_UPDATE, 0, 0, &credit));
                    out.extend_from_slice(&h2_frame(WINDOW_UPDATE, 0, stream, &credit));
                    if flags & FLAG_END_STREAM != 0
                        && let Some(i) = awaiting_body.iter().position(|s| *s == stream)
                    {
                        awaiting_body.swap_remove(i);
                        respond(&mut out, stream);
                    }
                }
                _ => {}
            }
        }
        pending.drain(..pos);
        if sock.write_all(&out).is_err() {
            return;
        }
        if goaway_sent && awaiting_body.is_empty() {
            return;
        }
    }
}

/// Node with `headerTableSize: 0` answered the first flight of a run and
/// timed out on everything after it: its SETTINGS cut the table below the
/// 4096 an encoder starts with, and nghttp2 then rejects any header block
/// that does not open with the size update RFC 7541 Section 4.2 requires.
/// 50 ok of 100 with `-c 1 -p 10` before the update was sent.
#[test]
fn h2_shrinks_its_encoder_table_when_the_server_cuts_it() {
    let addr = start_scripted_h2_server(H2Script {
        header_table_size_zero: true,
        ..H2Script::default()
    });
    let url = format!("http://{addr}/");
    let report = shb_json(&[
        "--http2",
        "-p",
        "10",
        "-n",
        "100",
        "-c",
        "1",
        "-t",
        "1",
        "--timeout",
        "2s",
        &url,
    ]);
    assert_all_ok(&report, 100, "200");
}

/// A GOAWAY names the last stream the server acted on, and RFC 9113 Section
/// 8.7 says the ones above it may be sent again: they were never looked at.
/// They were being counted as errors when the server then closed - nginx
/// with keepalive_requests 20 failed 1100 of 2000 requests at 32 streams a
/// connection - so the server here does what nginx does and the run has to
/// come out whole.
#[test]
fn h2_resends_the_streams_a_goaway_left_unprocessed() {
    let addr = start_scripted_h2_server(H2Script {
        streams_per_connection: Some(20),
        ..H2Script::default()
    });
    let url = format!("http://{addr}/");
    let report = shb_json(&[
        "--http2",
        "-p",
        "32",
        "-n",
        "200",
        "-c",
        "1",
        "-t",
        "1",
        "--timeout",
        "2s",
        &url,
    ]);
    assert_all_ok(&report, 200, "200");
}

/// A GOAWAY does not end the streams below its line, and a request body
/// still leaving on one of them is still owed. The fill pass that pumps
/// bodies used to return at the GOAWAY before pumping, so a body waiting on
/// window credit never left, the server never answered, and the request
/// timed out: three of them per connection here, where the credit for a
/// body larger than the window arrives together with the GOAWAY.
#[test]
fn h2_finishes_sending_bodies_after_a_goaway() {
    let addr = start_scripted_h2_server(H2Script {
        streams_per_connection: Some(3),
        ..H2Script::default()
    });
    let url = format!("http://{addr}/");
    let path = std::env::temp_dir().join("shb-e2e-goaway-body.txt");
    std::fs::write(&path, vec![b'a'; 200_000]).unwrap();
    let report = shb_json(&[
        "--http2",
        "-m",
        "POST",
        "-d",
        &format!("@{}", path.display()),
        "-p",
        "32",
        "-n",
        "12",
        "-c",
        "1",
        "-t",
        "1",
        "--timeout",
        "2s",
        &url,
    ]);
    let _ = std::fs::remove_file(&path);
    assert_all_ok(&report, 12, "200");
}

/// A stream refused with REFUSED_STREAM was never acted on, and RFC 9113
/// Section 8.7 lets it be sent again; it was being counted as an error.
/// The first flight goes out before the server's SETTINGS can say how many
/// streams it takes, so a run at 100 streams against a server that takes 8
/// has 92 of them refused before anything else happens - Node with
/// maxConcurrentStreams: 8 reported 92 errors of 1000.
#[test]
fn h2_resends_the_streams_the_server_refused() {
    let addr = start_scripted_h2_server(H2Script {
        accept_per_read: Some(8),
        ..H2Script::default()
    });
    let url = format!("http://{addr}/");
    let report = shb_json(&[
        "--http2",
        "-p",
        "100",
        "-n",
        "1000",
        "-c",
        "1",
        "-t",
        "1",
        "--timeout",
        "2s",
        &url,
    ]);
    assert_all_ok(&report, 1000, "200");
}

/// Sending unprocessed requests again has to stop somewhere, or a server
/// that processes nothing keeps a counted run going for ever. A run may
/// retry as many requests as it was asked for plus one per completed
/// request, so this one ends with every request an error.
#[test]
fn h2_a_server_that_acts_on_nothing_still_ends_the_run() {
    let addr = start_scripted_h2_server(H2Script {
        streams_per_connection: Some(0),
        ..H2Script::default()
    });
    let url = format!("http://{addr}/");
    let report = shb_json(&[
        "--http2",
        "-p",
        "4",
        "-n",
        "20",
        "-c",
        "1",
        "-t",
        "1",
        "--timeout",
        "2s",
        &url,
    ]);
    assert_eq!(report["requests"]["ok"], 0, "report: {report}");
    assert_eq!(report["requests"]["errors"], 20, "report: {report}");
}

// ------------------------------------------------------------------------
// HTTP/3
//
// Against quinn + h3 with a self-signed certificate.
// ------------------------------------------------------------------------

/// Bound address of the shared HTTP/3 (QUIC) test server
fn h3_server_addr() -> SocketAddr {
    static SERVER: OnceLock<SocketAddr> = OnceLock::new();
    *SERVER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async move {
                let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                    .expect("self-signed cert");
                let cert = certified.cert.der().clone();
                let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
                    certified.signing_key.serialize_der(),
                );
                let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
                let mut tls = rustls::ServerConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .expect("tls versions")
                    .with_no_client_auth()
                    .with_single_cert(vec![cert], key.into())
                    .expect("server cert");
                tls.alpn_protocols = vec![b"h3".to_vec()];
                let quic_config =
                    quinn::crypto::rustls::QuicServerConfig::try_from(std::sync::Arc::new(tls))
                        .expect("quic server config");
                let mut server_config =
                    quinn::ServerConfig::with_crypto(std::sync::Arc::new(quic_config));
                // Windows small enough that a large request body cannot go out
                // in one go: the client has to send what fits, stop, and carry
                // on as credit arrives. Left at quinn's defaults, which are
                // megabytes, nothing here would ever block.
                let mut transport = quinn::TransportConfig::default();
                transport.receive_window(quinn::VarInt::from_u32(64 * 1024));
                transport.stream_receive_window(quinn::VarInt::from_u32(16 * 1024));
                server_config.transport_config(std::sync::Arc::new(transport));
                let endpoint =
                    quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().expect("addr"))
                        .expect("quic endpoint");
                tx.send(endpoint.local_addr().expect("local addr"))
                    .expect("send addr");
                while let Some(incoming) = endpoint.accept().await {
                    tokio::spawn(async move {
                        let Ok(conn) = incoming.await else { return };
                        let Ok(mut h3_conn) =
                            h3::server::Connection::new(h3_quinn::Connection::new(conn)).await
                        else {
                            return;
                        };
                        while let Ok(Some(resolver)) = h3_conn.accept().await {
                            tokio::spawn(async move {
                                let Ok((request, mut stream)) = resolver.resolve_request().await
                                else {
                                    return;
                                };
                                // Drain the request body for the echo check
                                let mut req_body = Vec::new();
                                while let Ok(Some(mut chunk)) = stream.recv_data().await {
                                    use bytes::Buf;
                                    while chunk.has_remaining() {
                                        let c = chunk.chunk().to_vec();
                                        let n = c.len();
                                        req_body.extend_from_slice(&c);
                                        chunk.advance(n);
                                    }
                                }
                                // Same rule as the axum server: a body too
                                // large to name in a header says how long it
                                // should be
                                let want_len = request
                                    .headers()
                                    .get("x-body-len")
                                    .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                                    .and_then(|v| v.parse::<usize>().ok());
                                let echo = request
                                    .headers()
                                    .get("x-echo")
                                    .map(|v| v.as_bytes().to_vec());
                                // Same rule as the axum server: a request that
                                // names its method proves the method arrived
                                let expect = request
                                    .headers()
                                    .get("x-expect-method")
                                    .map(|v| v.as_bytes().to_vec());
                                let (status, body) = match echo {
                                    _ if want_len == Some(req_body.len()) => {
                                        (http::StatusCode::OK, "body complete")
                                    }
                                    _ if want_len.is_some() => {
                                        (http::StatusCode::BAD_REQUEST, "body truncated")
                                    }
                                    Some(ref e) if *e != req_body => {
                                        (http::StatusCode::BAD_REQUEST, "")
                                    }
                                    None if !req_body.is_empty() => {
                                        (http::StatusCode::BAD_REQUEST, "")
                                    }
                                    _ if expect.is_some() => {
                                        if expect.as_deref()
                                            == Some(request.method().as_str().as_bytes())
                                        {
                                            (http::StatusCode::OK, "method matched")
                                        } else {
                                            (http::StatusCode::CONFLICT, "method mismatch")
                                        }
                                    }
                                    _ => match *request.method() {
                                        http::Method::GET | http::Method::HEAD => {
                                            (http::StatusCode::OK, "hello world")
                                        }
                                        http::Method::POST => {
                                            (http::StatusCode::CREATED, "created")
                                        }
                                        http::Method::DELETE => (http::StatusCode::NO_CONTENT, ""),
                                        _ => (http::StatusCode::METHOD_NOT_ALLOWED, ""),
                                    },
                                };
                                let response = http::Response::builder()
                                    .status(status)
                                    .body(())
                                    .expect("response");
                                if stream.send_response(response).await.is_err() {
                                    return;
                                }
                                if !body.is_empty() {
                                    let _ = stream
                                        .send_data(bytes::Bytes::from_static(body.as_bytes()))
                                        .await;
                                }
                                let _ = stream.finish().await;
                            });
                        }
                    });
                }
            });
        });
        rx.recv().expect("h3 server startup")
    })
}

#[test]
fn h3_get() {
    let addr = h3_server_addr();
    let url = format!("https://127.0.0.1:{}/", addr.port());
    let report = shb_json(&["--http3", "-p", "4", "-n", "50", "-c", "2", "-t", "1", &url]);
    assert_eq!(report["protocol"], "HTTP/3");
    assert_all_ok(&report, 50, "200");
}

#[test]
fn h3_method_is_sent_to_the_server() {
    let addr = h3_server_addr();
    let url = format!("https://127.0.0.1:{}/", addr.port());
    let report = shb_json(&[
        "--http3", "-m", "POST", "-n", "30", "-c", "2", "-t", "1", &url,
    ]);
    assert_all_ok(&report, 30, "201");
}

#[test]
fn h3_custom_header_and_body() {
    let addr = h3_server_addr();
    let url = format!("https://127.0.0.1:{}/", addr.port());
    let report = shb_json(&[
        "--http3",
        "-m",
        "POST",
        "-H",
        "X-Echo: h3body",
        "-d",
        "h3body",
        "-n",
        "20",
        "-c",
        "2",
        "-t",
        "1",
        &url,
    ]);
    assert_all_ok(&report, 20, "201");
}

/// And over HTTP/3, where the method goes through QPACK
#[test]
fn h3_every_registered_method_arrives() {
    let addr = h3_server_addr();
    let url = format!("https://{addr}/");
    assert_every_method_arrives(&["--http3"], &url);
}

/// A body larger than the 65535-byte window HTTP/2 starts with has to be cut
/// into DATA frames and resumed as the peer grants credit. Sending it in one
/// go, as it used to be, meant the request was never started at all and the
/// run stopped with no error and no end.
#[test]
fn h2_body_larger_than_the_initial_window() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    let path = std::env::temp_dir().join("shb-e2e-big-body.txt");
    let len = 200_000;
    std::fs::write(&path, vec![b'a'; len]).unwrap();
    let report = shb_json(&[
        "--http2",
        "-m",
        "POST",
        "-H",
        &format!("X-Body-Len: {len}"),
        "-d",
        &format!("@{}", path.display()),
        "-n",
        "6",
        "-c",
        "2",
        "-t",
        "1",
        &url,
    ]);
    assert_all_ok(&report, 6, "200");
}

/// And over HTTP/3, whose flow control is QUIC's rather than the protocol's.
/// This one cannot go in the container suite: Docker's UDP publishing drops a
/// GSO batch once a connection has this much to send, so it would measure
/// Docker rather than shb.
#[test]
fn h3_body_larger_than_the_initial_window() {
    let addr = h3_server_addr();
    let url = format!("https://127.0.0.1:{}/", addr.port());
    let path = std::env::temp_dir().join("shb-e2e-big-body-h3.txt");
    let len = 200_000;
    std::fs::write(&path, vec![b'a'; len]).unwrap();
    let report = shb_json(&[
        "--http3",
        "-m",
        "POST",
        "-H",
        &format!("X-Body-Len: {len}"),
        "-d",
        &format!("@{}", path.display()),
        "-n",
        "6",
        "-c",
        "2",
        "-t",
        "1",
        &url,
    ]);
    assert_all_ok(&report, 6, "200");
}

/// The same body over HTTP/1.1, where there is no flow control to cross
#[test]
fn h1_body_larger_than_the_h2_initial_window() {
    let (v4, _) = server_addrs();
    let url = format!("http://{v4}/");
    let path = std::env::temp_dir().join("shb-e2e-big-body-h1.txt");
    let len = 200_000;
    std::fs::write(&path, vec![b'a'; len]).unwrap();
    let report = shb_json(&[
        "-m",
        "POST",
        "-H",
        &format!("X-Body-Len: {len}"),
        "-d",
        &format!("@{}", path.display()),
        "-n",
        "6",
        "-c",
        "2",
        "-t",
        "1",
        &url,
    ]);
    assert_all_ok(&report, 6, "200");
}

/// A server that answers a POST as soon as it has the head, and reads the
/// body it was told the length of only afterwards, the way nginx answers a
/// location that returns a fixed status. Whatever follows that body has to be
/// another request line; a 400 says it was not.
fn start_eager_server() -> SocketAddr {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut pending = Vec::new();
                let mut chunk = vec![0u8; 64 * 1024];
                // Body bytes of the request already answered, still to discard
                let mut to_skip = 0usize;
                loop {
                    let take = to_skip.min(pending.len());
                    pending.drain(..take);
                    to_skip -= take;
                    // Body bytes where a request line should be are refused
                    // as soon as they are seen, as nginx refuses them: a
                    // server that waited for the end of the head instead
                    // would read the rest of the body as one, and answer
                    // nothing
                    if to_skip == 0 && pending.len() >= 5 && !pending.starts_with(b"POST ") {
                        let _ = stream.write_all(
                            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        break;
                    }
                    if to_skip == 0
                        && let Some(end) = pending
                            .windows(4)
                            .position(|w| w == b"\r\n\r\n")
                            .map(|i| i + 4)
                    {
                        let head = String::from_utf8_lossy(&pending[..end]).to_lowercase();
                        pending.drain(..end);
                        to_skip = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .and_then(|value| value.trim().parse().ok())
                            .unwrap_or(0);
                        if stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => pending.extend_from_slice(&chunk[..n]),
                    }
                }
            });
        }
    });
    addr
}

/// The response to a request arrives while the request itself is still being
/// sent, and the next request must still start where this one ends: nginx
/// used to get the tail of a 10 MB body spliced into the request after it,
/// answering -c 1 -n 5 with three 200s and two 400s
#[test]
fn h1_a_response_before_the_body_is_sent_does_not_corrupt_the_next_request() {
    let addr = start_eager_server();
    let url = format!("http://{addr}/");
    let path = std::env::temp_dir().join("shb-e2e-eager-body.txt");
    // More than the socket buffers on both sides hold, so the response is on
    // its way while the send still has most of the body to go
    std::fs::write(&path, vec![b'a'; 32 << 20]).unwrap();
    let report = shb_json(&[
        "--timeout",
        "5s",
        "-d",
        &format!("@{}", path.display()),
        "-n",
        "5",
        "-c",
        "1",
        "-t",
        "1",
        &url,
    ]);
    let _ = std::fs::remove_file(&path);
    assert_all_ok(&report, 5, "200");
}

/// A server that accepts and then says nothing at all
///
/// Without --timeout a run against one of these never ends: there is no error
/// to report and no response to count, so the loop waits for a reply that is
/// not coming. Every hang found this week looked like this from the outside.
fn silent_server_addr() -> SocketAddr {
    static SERVER: OnceLock<SocketAddr> = OnceLock::new();
    *SERVER.get_or_init(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept() {
                // Hold it open and never write: the point is a peer that is
                // there and answers nothing
                held.push(stream);
            }
        });
        addr
    })
}

#[test]
fn a_silent_server_ends_the_run_instead_of_hanging() {
    let addr = silent_server_addr();
    let url = format!("http://{addr}/");
    let report = shb_json(&["--timeout", "500ms", "-n", "2", "-c", "1", "-t", "1", &url]);
    assert_eq!(report["requests"]["ok"], 0, "report: {report}");
    assert_eq!(report["requests"]["errors"], 2, "report: {report}");
}

/// The same over HTTP/2, where the wait is for a response on a stream rather
/// than for bytes on the socket
#[test]
fn a_silent_server_ends_an_http2_run_too() {
    let addr = silent_server_addr();
    let url = format!("http://{addr}/");
    let report = shb_json(&[
        "--http2",
        "--timeout",
        "500ms",
        "-n",
        "2",
        "-c",
        "1",
        "-t",
        "1",
        &url,
    ]);
    assert_eq!(report["requests"]["ok"], 0, "report: {report}");
    assert_eq!(report["requests"]["errors"], 2, "report: {report}");
}

/// A UDP relay in front of the HTTP/3 server that loses, duplicates and
/// reorders datagrams
///
/// Loopback loses nothing, reorders nothing and delivers in microseconds, so
/// everything QUIC has for a network that misbehaves - loss detection, probe
/// timeouts, retransmission, reassembly out of order - sits untouched behind
/// tests that all pass on a perfect path. Most of the QUIC bugs found in this
/// stack showed up first against servers out on the internet, which is a slow
/// way to learn.
///
/// The impairment is driven by a seeded generator, so a run that fails fails
/// the same way again.
fn impaired_h3_addr(loss_pct: u32, dup_pct: u32, reorder_pct: u32, seed: u64) -> SocketAddr {
    use std::collections::HashMap;
    use std::net::UdpSocket;
    use std::sync::{Arc, Mutex};

    let upstream = h3_server_addr();
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("bind relay"));
    let addr = front.local_addr().expect("relay addr");

    // Deterministic and tiny; the sequence only has to be irregular
    struct Rng(u64);
    impl Rng {
        fn hits(&mut self, percent: u32) -> bool {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            percent > 0 && (self.0 >> 33) as u32 % 100 < percent
        }
    }

    // One datagram held back and released after the next one goes: reordering
    // without a timer to make the test flaky
    fn relay(
        send: impl Fn(&[u8]),
        rng: &mut Rng,
        held: &mut Option<Vec<u8>>,
        data: &[u8],
        loss: u32,
        dup: u32,
        reorder: u32,
    ) {
        if rng.hits(loss) {
            return;
        }
        if let Some(previous) = held.take() {
            send(data);
            send(&previous);
            return;
        }
        if rng.hits(reorder) {
            *held = Some(data.to_vec());
            return;
        }
        send(data);
        if rng.hits(dup) {
            send(data);
        }
    }

    let peers: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>> = Default::default();
    let f = Arc::clone(&front);
    let p = Arc::clone(&peers);
    std::thread::spawn(move || {
        let mut rng = Rng(seed | 1);
        let mut held = None;
        let mut buf = vec![0u8; 65535];
        while let Ok((n, from)) = f.recv_from(&mut buf) {
            let up = {
                let mut peers = p.lock().expect("peers");
                Arc::clone(peers.entry(from).or_insert_with(|| {
                    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("bind upstream"));
                    s.connect(upstream).expect("connect upstream");
                    // The other direction gets its own thread and its own
                    // sequence, so neither waits on the other
                    let back = Arc::clone(&s);
                    let out = Arc::clone(&f);
                    std::thread::spawn(move || {
                        let mut rng = Rng(seed.rotate_left(32) | 1);
                        let mut held = None;
                        let mut buf = vec![0u8; 65535];
                        while let Ok(m) = back.recv(&mut buf) {
                            relay(
                                |d| {
                                    let _ = out.send_to(d, from);
                                },
                                &mut rng,
                                &mut held,
                                &buf[..m],
                                loss_pct,
                                dup_pct,
                                reorder_pct,
                            );
                        }
                    });
                    s
                }))
            };
            relay(
                |d| {
                    let _ = up.send(d);
                },
                &mut rng,
                &mut held,
                &buf[..n],
                loss_pct,
                dup_pct,
                reorder_pct,
            );
        }
    });
    addr
}

/// Five per cent of datagrams never arrive, in both directions
#[test]
fn h3_gets_through_a_lossy_path() {
    let addr = impaired_h3_addr(5, 0, 0, 0x5eed);
    let url = format!("https://127.0.0.1:{}/", addr.port());
    let report = shb_json(&["--http3", "-n", "40", "-c", "2", "-t", "1", &url]);
    assert_all_ok(&report, 40, "200");
}

/// Datagrams arrive twice, or out of order, or not at all
#[test]
fn h3_gets_through_duplication_and_reordering() {
    let addr = impaired_h3_addr(2, 10, 10, 0xd0e5);
    let url = format!("https://127.0.0.1:{}/", addr.port());
    let report = shb_json(&["--http3", "-n", "40", "-c", "2", "-t", "1", &url]);
    assert_all_ok(&report, 40, "200");
}
