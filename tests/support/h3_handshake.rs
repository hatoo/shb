//! Independent Quinn peer: one connection owns the whole request budget before
//! a second handshake fails. Both real responses must still be measured.

use std::sync::Arc;
use std::time::Duration;

#[test]
fn late_h3_handshake_refusal_preserves_both_responses_and_samples() {
    let (address, received) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key =
                rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
            let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key.into())
            .unwrap();
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap();
            let endpoint = quinn::Endpoint::server(
                quinn::ServerConfig::with_crypto(Arc::new(crypto)),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            address.send(endpoint.local_addr().unwrap()).unwrap();
            tokio::time::timeout(Duration::from_secs(15), async {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let refused = endpoint.accept().await.unwrap();
                let mut h3 = h3::server::Connection::<_, bytes::Bytes>::new(
                    h3_quinn::Connection::new(conn.clone()),
                )
                .await
                .unwrap();
                let (request, mut first) = h3
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                assert_eq!(request.method(), http::Method::GET);
                let (request, mut second) = h3
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                assert_eq!(request.method(), http::Method::GET);
                first
                    .send_response(http::Response::builder().status(200).body(()).unwrap())
                    .await
                    .unwrap();
                first.finish().await.unwrap();
                // The first connection has reserved both requests. A refusal
                // must not finish the run while the second response is held.
                refused.refuse();
                tokio::time::sleep(Duration::from_millis(250)).await;
                let delivered = second
                    .send_response(http::Response::builder().status(201).body(()).unwrap())
                    .await
                    .is_ok()
                    && second.finish().await.is_ok();
                conn.closed().await;
                delivered
            })
            .await
            .unwrap()
        })
    });
    let target = crate::target::parse_target(
        &format!("https://{}/", received.recv().unwrap()),
        "GET",
        &[],
        None,
        false,
    )
    .unwrap();
    let stats = crate::http3::run_worker(
        &target,
        2,
        crate::budget::Budget::Requests(2),
        Duration::from_secs(5),
        Some(Duration::from_secs(10)),
        2,
    )
    .unwrap();
    let delivered = server.join().unwrap();
    assert_eq!(
        (stats.completed, stats.errors, stats.connect_errors),
        (2, 0, 0)
    );
    assert!(delivered);
    assert_eq!(stats.latencies_ns.len(), 2);
    assert_eq!(stats.status_counts[200], 1);
    assert_eq!(stats.status_counts[201], 1);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), 2);
    assert!(*stats.latencies_ns.iter().max().unwrap() >= 200_000_000);
}
