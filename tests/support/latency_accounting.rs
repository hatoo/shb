//! Reconcile the actual CLI report with independent response/error ledgers.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::Ordering;
use std::time::Duration;

pub fn assert_samples(report: &serde_json::Value) {
    let ok = report["requests"]["ok"].as_u64().unwrap();
    let errors = report["requests"]["errors"].as_u64().unwrap();
    assert_eq!(report["requests"]["total"], ok + errors, "{report}");
    assert_eq!(report["latencySamples"].as_u64(), Some(ok), "{report}");
    assert_eq!(
        report["statusCodes"]
            .as_object()
            .unwrap()
            .values()
            .map(|n| n.as_u64().unwrap())
            .sum::<u64>(),
        ok,
        "{report}"
    );
    assert_eq!(report["latencySeconds"].is_null(), ok == 0, "{report}");
}

#[test]
fn mixed_h1_responses_and_disconnects_preserve_samples_across_reconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let peer = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let mut seen = 0;
        while seen < 17 {
            let (mut socket, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline, "only {seen} requests");
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(e) => panic!("accept: {e}"),
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let n = socket.read(&mut buf).unwrap();
                assert!(n > 0, "incomplete request");
                request.extend_from_slice(&buf[..n]);
            }
            assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
            if seen % 3 != 2 {
                let status = if seen % 3 == 0 { 200 } else { 503 };
                write!(
                    socket,
                    "HTTP/1.1 {status} result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            }
            // Every third request closes with no response; all others finish.
            seen += 1;
        }
        seen
    });
    let report = super::shb_json(&["-n", "17", "-c", "1", "-t", "1", "--timeout", "5s", &url]);
    assert_eq!(peer.join().unwrap(), 17);
    assert_eq!(
        report["requests"],
        serde_json::json!({
            "ok": 12, "errors": 5, "connectErrors": 0, "total": 17,
        })
    );
    assert_eq!(
        report["statusCodes"],
        serde_json::json!({"200": 6, "503": 6})
    );
    assert_eq!(report["latencySamples"], 12);
}

#[test]
fn mixed_h3_responses_and_resets_preserve_samples_across_workers() {
    let report = super::shb_json(&[
        "--http3",
        "-n",
        "257",
        "-c",
        "7",
        "-p",
        "8",
        "-t",
        "3",
        "--timeout",
        "5s",
        &format!("https://{}/latency-accounting", super::h3_server_addr()),
    ]);
    assert_eq!(
        super::h3_server::ACCOUNTING_REQUESTS.load(Ordering::SeqCst),
        257
    );
    assert_eq!(report["threads"], 3);
    assert_eq!(
        report["requests"],
        serde_json::json!({
            "ok": 172, "errors": 85, "connectErrors": 0, "total": 257,
        })
    );
    assert_eq!(
        report["statusCodes"],
        serde_json::json!({"200": 86, "503": 86})
    );
    assert_eq!(report["latencySamples"], 172);
}

#[test]
fn multiplexing_and_uneven_worker_budgets_keep_every_sample() {
    for protocol in ["h1", "h2", "h3"] {
        let url = if protocol == "h3" {
            format!("https://{}/", super::h3_server_addr())
        } else {
            format!("http://{}/", super::server_addrs().0)
        };
        let mut args = vec!["-n", "257", "-c", "7", "-t", "3", "--timeout", "5s", &url];
        if protocol != "h1" {
            args.extend(["-p", "8"]);
            args.push(if protocol == "h2" {
                "--http2"
            } else {
                "--http3"
            });
        }
        let report = super::shb_json(&args);
        assert_eq!(report["threads"], 3);
        super::assert_all_ok(&report, 257, "200");
    }
}
