use super::*;

#[path = "response_fixture.rs"]
mod fixture;

fn check(wire: Vec<u8>, cut: usize, successes: u64) {
    let (address_tx, address_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let peer = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let endpoint = quinn::Endpoint::server(
                    fixture::server_config(),
                    "127.0.0.1:0".parse().unwrap(),
                )
                .unwrap();
                address_tx.send(endpoint.local_addr().unwrap()).unwrap();
                let wire = Arc::new(wire);
                let accept = endpoint.clone();
                tokio::spawn(async move {
                    while let Some(incoming) = accept.accept().await {
                        let wire = Arc::clone(&wire);
                        tokio::spawn(async move {
                            if let Ok(conn) = incoming.await {
                                fixture::serve(conn, wire, cut, Duration::from_millis(2)).await;
                            }
                        });
                    }
                });
                let _ = tokio::time::timeout(Duration::from_secs(20), stop_rx).await;
                endpoint.close(0u32.into(), b"fixture complete");
            });
    });
    let addr = address_rx.recv().unwrap();
    let target =
        crate::target::parse_target(&format!("https://{addr}/"), "GET", &[], None, false).unwrap();
    let result = run_worker(
        &target,
        1,
        Budget::Requests(16),
        Duration::from_secs(5),
        Some(Duration::from_secs(5)),
        4,
    );
    let _ = stop_tx.send(());
    peer.join().unwrap();
    let stats = result.unwrap();
    assert_eq!(stats.completed, successes);
    assert_eq!(stats.errors, 16 - successes);
    assert_eq!(stats.connect_errors, 0);
    assert_eq!(stats.status_counts.iter().sum::<u64>(), successes);
    assert_eq!(stats.status_counts[200], successes);
    assert_eq!(stats.latencies_ns.len(), successes as usize);
    // The sample must include the deliberately delayed response tail.
    assert!(stats.latencies_ns.iter().all(|&ns| ns >= 1_000_000));
}

#[test]
fn fragmented_h3_responses_keep_exact_worker_samples() {
    let (wire, tail) = fixture::response(1200, 65536);
    check(wire, tail, 16);
    let (wire, tail) = fixture::response(0, 65536);
    check(wire, tail + 2, 16); // split the DATA length
}

#[test]
fn fragmented_invalid_h3_responses_record_errors_without_samples() {
    check(vec![1, 3, 1, 0, 0xd9], 1, 0); // forbidden dynamic QPACK table
    check(vec![1, 3, 0, 0], 1, 0); // FIN before the field section completes
}
