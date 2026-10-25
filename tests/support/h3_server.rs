use std::net::SocketAddr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Only the mixed-result accounting test uses this route and peer ledger.
pub static ACCOUNTING_REQUESTS: AtomicUsize = AtomicUsize::new(0);

/// Hex permits the independent peers to check NUL, CR/LF and non-UTF-8 bytes.
pub(super) fn expected_echo(headers: &http::HeaderMap) -> Option<Vec<u8>> {
    if let Some(hex) = headers.get("x-echo-hex") {
        let hex = hex.to_str().unwrap();
        assert_eq!(hex.len() % 2, 0);
        Some(
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect(),
        )
    } else {
        headers.get("x-echo").map(|v| v.as_bytes().to_vec())
    }
}

pub const STATIC_NAME_HEADERS: &[(&str, &str)] = &[
    ("accept", "application/custom"),
    ("accept-encoding", "identity"),
    ("cookie", "first=1"),
    ("user-agent", "qpack-test"),
    ("accept", "second"),
    ("cookie", "second=2"),
    ("x-frame-options", "custom"),
    ("origin", "https://example.com"),
    ("x-unknown", "literal"),
];

/// Bound address of the shared HTTP/3 (QUIC) test server
pub fn h3_server_addr() -> SocketAddr {
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
                                if request.uri().path() == "/latency-accounting" {
                                    assert!(stream.recv_data().await.unwrap().is_none());
                                    let index = ACCOUNTING_REQUESTS.fetch_add(1, Ordering::SeqCst);
                                    if index % 3 == 2 {
                                        stream.stop_stream(
                                            h3::error::Code::H3_GENERAL_PROTOCOL_ERROR,
                                        );
                                    } else {
                                        let status =
                                            if index.is_multiple_of(3) { 200 } else { 503 };
                                        stream
                                            .send_response(
                                                http::Response::builder()
                                                    .status(status)
                                                    .body(())
                                                    .unwrap(),
                                            )
                                            .await
                                            .unwrap();
                                        stream.finish().await.unwrap();
                                    }
                                    return;
                                }
                                // A response that takes longer than a run is
                                // willing to wait for
                                if request.uri().path() == "/slow" {
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                }
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
                                let echo = expected_echo(request.headers());
                                // Same rule as the axum server: a request that
                                // names its method proves the method arrived
                                let expect = request
                                    .headers()
                                    .get("x-expect-method")
                                    .map(|v| v.as_bytes().to_vec());
                                let static_names_match =
                                    STATIC_NAME_HEADERS.iter().all(|(name, _)| {
                                        let actual: Vec<_> = request
                                            .headers()
                                            .get_all(*name)
                                            .iter()
                                            .map(|v| v.as_bytes())
                                            .collect();
                                        let expected: Vec<_> = STATIC_NAME_HEADERS
                                            .iter()
                                            .filter(|(n, _)| n == name)
                                            .map(|(_, v)| v.as_bytes())
                                            .collect();
                                        actual == expected
                                    });
                                let (status, body) = match echo {
                                    _ if request.uri().path() == "/static-names"
                                        && !static_names_match =>
                                    {
                                        (http::StatusCode::BAD_REQUEST, "header mismatch")
                                    }
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
