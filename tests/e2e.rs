//! End-to-end tests: run the compiled shb binary against local test servers
//! and assert on the JSON report.
//!
//! - HTTP/1.1 and h2c (prior knowledge): one axum server (hyper auto mode)
//! - HTTP/3: quinn + h3 with an rcgen self-signed certificate, which the
//!   trust-everything client accepts

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
    // If the client sent our marker header, its value must equal the body
    if let Some(echo) = headers.get("x-echo") {
        if echo.as_bytes() != body.as_ref() {
            return (StatusCode::BAD_REQUEST, "header/body mismatch");
        }
    } else if !body.is_empty() {
        return (StatusCode::BAD_REQUEST, "unexpected body");
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
fn connect_error_is_counted() {
    // Port 9 (discard) is almost certainly closed
    let report = shb_json(&["-n", "4", "-c", "2", "-t", "1", "http://127.0.0.1:9/"]);
    assert_eq!(report["requests"]["errors"], 4, "report: {report}");
    assert_eq!(report["requests"]["connectErrors"], 4, "report: {report}");
}

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
                let server_config =
                    quinn::ServerConfig::with_crypto(std::sync::Arc::new(quic_config));
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
                                let echo = request
                                    .headers()
                                    .get("x-echo")
                                    .map(|v| v.as_bytes().to_vec());
                                let (status, body) = match echo {
                                    Some(ref e) if *e != req_body => {
                                        (http::StatusCode::BAD_REQUEST, "")
                                    }
                                    None if !req_body.is_empty() => {
                                        (http::StatusCode::BAD_REQUEST, "")
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

#[test]
fn invalid_header_format_is_rejected() {
    let stderr = shb_fail(&["-H", "no-colon-here", "-n", "1", "http://127.0.0.1:9/"]);
    assert!(stderr.contains("header"), "stderr: {stderr}");
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

#[test]
fn body_from_missing_file_is_rejected() {
    let stderr = shb_fail(&["-d", "@/no/such/shb/file", "-n", "1", "http://127.0.0.1:9/"]);
    assert!(stderr.contains("file"), "stderr: {stderr}");
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
                        // keep-alive, whatever the request asked for
                        if stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .is_err()
                        {
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

#[test]
fn disable_keepalive_conflicts_with_http2_and_http3() {
    let stderr = shb_fail(&["--disable-keepalive", "--http2", "http://127.0.0.1:1/"]);
    assert!(
        stderr.contains("cannot be used with"),
        "unexpected stderr: {stderr}"
    );
}
