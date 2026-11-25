//! Raw wire ledger independent of the client's parser and request accounting.
//! Hold old response bodies over the issuing deadline while younger requests
//! complete, then require a complete drain or exactly charged failures.

use super::h2_peer::{h2_frame, tls_config};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(10);
const HOLD: Duration = Duration::from_millis(500);
const PING: &[u8] = b"draining";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Complete,
    MissingTail,
    RequestTimeout,
    Reset,
    Refused,
    Goaway,
    Disconnect,
    Cutoff,
    Upload,
}

fn frame(peer: &mut impl Read) -> io::Result<(u8, u8, u32, Vec<u8>)> {
    let mut header = [0; 9];
    peer.read_exact(&mut header)?;
    let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    assert!(len <= 16384);
    let mut payload = vec![0; len];
    peer.read_exact(&mut payload)?;
    Ok((
        header[3],
        header[4],
        u32::from_be_bytes(header[5..].try_into().unwrap()),
        payload,
    ))
}

fn eof(error: io::Error) {
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
        ),
        "{error}"
    );
}

fn exchange(peer: &mut (impl Read + Write), case: Case) -> u64 {
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    peer.write_all(&h2_frame(4, 0, 0, &[])).unwrap();
    peer.flush().unwrap();
    let mut requests = 0;
    let mut initial_ack = false;
    let upload = case == Case::Upload;
    let wanted = if upload { 2 } else { 6 };
    let mut uploaded = [0; 2];
    let mut ended = [false; 2];
    while requests < wanted || !initial_ack {
        let (kind, flags, id, payload) = frame(peer).unwrap();
        match (kind, flags, id) {
            (4, 0, 0) => {
                peer.write_all(&h2_frame(4, 1, 0, &[])).unwrap();
            }
            (4, 1, 0) => initial_ack = true,
            (1, _, id) => {
                requests += 1;
                assert_eq!(id, 2 * requests - 1);
                assert_eq!(flags & 5, if upload { 4 } else { 5 });
                if !upload && requests == 4 {
                    // Stream 1 declares a two-byte body, but only its first
                    // byte arrives. Streams 3 and 5 free two younger slots.
                    let mut response = h2_frame(1, 4, 1, &[0x88, 0x0f, 0x0d, 1, b'2']);
                    response.extend(h2_frame(0, 0, 1, b"a"));
                    for younger in [3, 5] {
                        response.extend(h2_frame(1, 5, younger, &[0x88]));
                    }
                    peer.write_all(&response).unwrap();
                }
            }
            (0, flags, id) if upload => {
                assert!(payload.iter().all(|&b| b == b'x'));
                uploaded[(id / 2) as usize] += payload.len();
                ended[(id / 2) as usize] |= flags & 1 != 0;
            }
            (8, 0, 0) => {}
            other => panic!("unexpected initial frame {other:?}"),
        }
        peer.flush().unwrap();
    }
    if matches!(case, Case::Cutoff | Case::RequestTimeout) {
        // No tail is sent: the ordinary duration cutoff must retain its old
        // behavior, reporting only the two responses it actually completed.
        loop {
            match frame(peer) {
                Ok((1, _, _, _)) => panic!("unexpected seventh request"),
                Ok(_) => {}
                Err(e) => {
                    eof(e);
                    return requests as u64;
                }
            }
        }
    }
    // This begins after all initial requests arrive, so the peer cannot
    // release before the worker's 350ms issuing deadline, even with a slow
    // connect or TLS handshake. The remaining 2s drain is a separate bound.
    std::thread::sleep(HOLD);
    if case == Case::Disconnect {
        return requests as u64;
    }

    let mut response = h2_frame(6, 0, 0, PING);
    response.extend(h2_frame(4, 0, 0, &[]));
    if upload {
        assert!(!ended.iter().any(|e| *e), "uploads must wait for credit");
        response.extend(h2_frame(8, 0, 0, &1_000_000u32.to_be_bytes()));
        for id in [1, 3] {
            response.extend(h2_frame(8, 0, id, &1_000_000u32.to_be_bytes()));
        }
    } else {
        match case {
            Case::Reset | Case::Refused => {
                let reason: u32 = if case == Case::Reset { 8 } else { 7 };
                response.extend(h2_frame(3, 0, 9, &reason.to_be_bytes()));
            }
            Case::Goaway => {
                let mut payload = 7u32.to_be_bytes().to_vec();
                payload.extend(0u32.to_be_bytes());
                response.extend(h2_frame(7, 0, 0, &payload));
            }
            _ => {}
        }
        if case != Case::MissingTail {
            response.extend(h2_frame(0, 1, 1, b"b"));
        }
        for id in [7, 9, 11] {
            if (case == Case::Goaway && id > 7)
                || (matches!(case, Case::Reset | Case::Refused) && id == 9)
            {
                continue;
            }
            response.extend(h2_frame(1, 5, id, &[0x88]));
        }
    }
    // Fragment even the control frame header. TLS preserves two records;
    // the raw socket may coalesce them, as real networks are allowed to do.
    peer.write_all(&response[..5]).unwrap();
    peer.flush().unwrap();
    peer.write_all(&response[5..]).unwrap();
    peer.flush().unwrap();
    let (mut ping_ack, mut settings_ack) = (false, false);
    loop {
        match frame(peer) {
            Ok((1, _, _, _)) => panic!("new request after issuing deadline"),
            Ok((6, 1, 0, payload)) => {
                assert_eq!(&payload, PING);
                ping_ack = true;
            }
            Ok((4, 1, 0, _)) => settings_ack = true,
            Ok((0, flags, id, payload)) if upload => {
                assert!(matches!(id, 1 | 3));
                assert!(payload.iter().all(|&b| b == b'x'));
                let slot = (id / 2) as usize;
                uploaded[slot] += payload.len();
                if flags & 1 != 0 {
                    assert!(!ended[slot]);
                    ended[slot] = true;
                    assert_eq!(uploaded[slot], 65536);
                    peer.write_all(&h2_frame(1, 5, id, &[0x88])).unwrap();
                    peer.flush().unwrap();
                }
            }
            Ok((kind, _, _, _)) => assert!(matches!(kind, 7 | 8)),
            Err(e) => {
                eof(e);
                break;
            }
        }
    }
    // GOAWAY retires its socket as soon as the final accepted stream ends;
    // its queued controls remain best effort, as in counted mode.
    if case != Case::Goaway {
        assert!(
            ping_ack && settings_ack,
            "drain must send control acknowledgments"
        );
    }
    if upload {
        assert_eq!(ended, [true; 2]);
    }
    requests as u64
}

fn configure(socket: &TcpStream) {
    socket.set_read_timeout(Some(WAIT)).unwrap();
    socket.set_write_timeout(Some(WAIT)).unwrap();
    socket.set_nodelay(true).unwrap();
}

fn check(case: Case, tls: bool, workers: usize) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + WAIT;
        let mut peers = Vec::new();
        while peers.len() < workers {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    configure(&socket);
                    peers.push(std::thread::spawn(move || {
                        if tls {
                            let mut session = rustls::ServerConnection::new(tls_config()).unwrap();
                            exchange(&mut rustls::Stream::new(&mut session, &mut socket), case)
                        } else {
                            exchange(&mut socket, case)
                        }
                    }));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "missing connection");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("{e}"),
            }
        }
        let seen: u64 = peers.into_iter().map(|p| p.join().unwrap()).sum();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "no reconnect during drain"
        );
        seen
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_shb"));
    command.args([
        "-j",
        "--http2",
        "-z",
        "350ms",
        "-c",
        &workers.to_string(),
        "-t",
        &workers.to_string(),
        "-p",
        if case == Case::Upload { "2" } else { "4" },
    ]);
    if case != Case::Cutoff {
        command.args(["--drain-timeout", "2s"]);
    }
    if case == Case::RequestTimeout {
        command.args(["--timeout", "600ms"]);
    }
    if case == Case::Upload {
        command.args(["-d", &"x".repeat(65536)]);
    }
    command.arg(format!("{}://{addr}/", if tls { "https" } else { "http" }));
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let end = Instant::now() + WAIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= end {
            child.kill().unwrap();
            panic!("unbounded drain: {case:?}/{tls}/{workers}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    super::latency_accounting::assert_samples(&report);
    let seen = server.join().unwrap();
    let (ok, errors) = match case {
        Case::Complete => (6, 0),
        Case::MissingTail | Case::Reset | Case::Refused => (5, 1),
        Case::Goaway => (4, 2),
        Case::Disconnect | Case::RequestTimeout => (2, 4),
        Case::Cutoff | Case::Upload => (2, 0),
    };
    let workers = workers as u64;
    assert_eq!(seen, if case == Case::Upload { 2 } else { 6 } * workers);
    assert_eq!(
        report["requests"],
        serde_json::json!({"ok":ok*workers,"errors":errors*workers,"total":(ok+errors)*workers,"connectErrors":0}),
        "{case:?}/{tls}"
    );
    if !matches!(case, Case::Cutoff | Case::Disconnect | Case::RequestTimeout) {
        assert!(
            report["latencySeconds"]["max"].as_f64().unwrap() >= HOLD.as_secs_f64(),
            "original request timestamps survive drain"
        );
    }
}

fn matrix(case: Case) {
    for tls in [false, true] {
        for workers in [1, 2] {
            check(case, tls, workers);
        }
    }
}

#[test]
fn complete_bodies_and_control_frames_drain() {
    matrix(Case::Complete);
}
#[test]
fn missing_final_byte_is_an_error_at_the_bound() {
    matrix(Case::MissingTail);
}
#[test]
fn resets_are_charged_once() {
    matrix(Case::Reset);
}
#[test]
fn refused_streams_are_errors_without_late_retries() {
    matrix(Case::Refused);
}
#[test]
fn goaway_finishes_accepted_streams_without_reconnecting() {
    matrix(Case::Goaway);
}
#[test]
fn connection_loss_does_not_reconnect() {
    matrix(Case::Disconnect);
}
#[test]
fn default_duration_retains_cutoff_behavior() {
    matrix(Case::Cutoff);
}
#[test]
fn upload_credit_continues_after_issuing_stops() {
    matrix(Case::Upload);
}

#[test]
fn request_timeouts_still_apply_while_draining() {
    matrix(Case::RequestTimeout);
}

#[test]
fn drain_option_requires_http2_and_duration() {
    for args in [
        vec!["--drain-timeout", "1s"],
        vec!["--drain-timeout", "1s", "-z", "1s"],
        vec!["--drain-timeout", "1s", "--http2"],
        vec!["--drain-timeout", "1s", "--http3", "-z", "1s"],
        vec!["--drain-timeout", "1s", "--http2", "-z", "1s", "-n", "10"],
    ] {
        let mut args = args;
        args.push("http://127.0.0.1:1/");
        assert!(!super::shb_fail(&args).is_empty());
    }
}
