//! Fixed barrier peer: each connection collects exactly min(window, remaining)
//! request HEADERS before returning GOAWAY and accepted responses. This prevents
//! scheduling from changing the amount of attempted work between client builds.
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

fn tls_config() -> Arc<rustls::ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certified.cert.der().clone()], key.into())
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}
fn frame(kind: u8, flags: u8, id: u32, body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut b = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, kind, flags];
    b.extend(id.to_be_bytes());
    b.extend(body);
    b
}
fn goaway(last: u32) -> Vec<u8> {
    let mut b = last.to_be_bytes().to_vec();
    b.extend([0; 4]);
    frame(7, 0, 0, &b)
}
fn serve(
    sock: &mut (impl Read + Write),
    wanted: usize,
    accepted: usize,
    length: usize,
    repeat: bool,
) -> serde_json::Value {
    let mut sent = frame(4, 0, 0, &[]);
    let mut bytes_sent = sent.len();
    sock.write_all(&sent).unwrap();
    sock.flush().unwrap();
    sent.clear();
    let mut pending = Vec::new();
    let mut buf = [0; 65536];
    let mut preface = false;
    let mut headers = 0;
    let mut bodies = BTreeMap::<u32, usize>::new();
    let mut ended = 0;
    let mut bytes_read = 0;
    let mut body_bytes = 0;
    let mut goaways = 0;
    let mut client_goaway_bytes = 0;
    let mut sent_answers = false;
    loop {
        let n = match sock.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => panic!("read: {e}"),
        };
        if n == 0 {
            assert!(sent_answers, "EOF before complete accepted bodies");
            break;
        }
        bytes_read += n;
        pending.extend(&buf[..n]);
        if !preface {
            if pending.len() < 24 {
                continue;
            }
            assert_eq!(&pending[..24], b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            pending.drain(..24);
            preface = true;
        }
        let mut consumed = 0;
        while pending.len() - consumed >= 9 {
            let h = &pending[consumed..];
            let size = ((h[0] as usize) << 16) | ((h[1] as usize) << 8) | h[2] as usize;
            if h.len() < 9 + size {
                break;
            }
            let (kind, flags) = (h[3], h[4]);
            let id = u32::from_be_bytes([h[5] & 127, h[6], h[7], h[8]]);
            let data = &h[9..9 + size];
            match kind {
                4 if flags & 1 == 0 => sent.extend(frame(4, 1, 0, &[])),
                6 if flags & 1 == 0 => sent.extend(frame(6, 1, 0, data)),
                1 => {
                    assert!(!sent_answers);
                    assert_eq!(id, 2 * headers as u32 + 1);
                    headers += 1;
                    assert!(headers <= wanted);
                    assert_eq!(flags & 4, 4, "request headers must be complete");
                    if (id as usize).div_ceil(2) <= accepted {
                        if flags & 1 != 0 {
                            assert_eq!(length, 0);
                            ended += 1;
                        } else {
                            assert!(length > 0);
                            assert!(bodies.insert(id, 0).is_none());
                        }
                    }
                }
                0 if (id as usize).div_ceil(2) <= accepted => {
                    assert_eq!(flags & 8, 0);
                    let offset = bodies
                        .get_mut(&id)
                        .expect("DATA requires accepted unfinished request");
                    for (i, &b) in data.iter().enumerate() {
                        assert_eq!(b, 33 + ((*offset + i) % 90) as u8, "body byte");
                    }
                    *offset += data.len();
                    body_bytes += data.len();
                    assert!(*offset <= length);
                    if flags & 1 != 0 {
                        assert_eq!(*offset, length);
                        bodies.remove(&id);
                        ended += 1;
                    }
                    if !data.is_empty() {
                        let credit = (data.len() as u32).to_be_bytes();
                        sent.extend(frame(8, 0, 0, &credit));
                        sent.extend(frame(8, 0, id, &credit));
                    }
                }
                0 => {
                    // Rejected DATA still consumes connection receive credit.
                    if !data.is_empty() {
                        sent.extend(frame(8, 0, 0, &(data.len() as u32).to_be_bytes()));
                    }
                }
                3 => panic!("unexpected reset"),
                7 => {
                    assert_eq!(id, 0);
                    assert!(size >= 8);
                    client_goaway_bytes += 9 + size;
                }
                4 | 8 => {}
                _ => panic!("unexpected frame {kind}"),
            }
            consumed += 9 + size;
        }
        pending.drain(..consumed);
        if headers == wanted && accepted < wanted && goaways == 0 {
            let last = 2 * accepted as u32 - 1;
            if repeat {
                sent.extend(goaway(0x7fffffff));
                goaways += 1;
            }
            sent.extend(goaway(last));
            goaways += 1;
            if repeat {
                sent.extend(goaway(last | 0x80000000));
                goaways += 1;
            }
        }
        if !sent_answers && headers == wanted && ended == accepted {
            assert!(bodies.is_empty());
            assert_eq!(body_bytes, accepted * length);
            for i in 0..accepted {
                sent.extend(frame(1, 5, 2 * i as u32 + 1, &[0x88]));
            }
            sent_answers = true;
        }
        bytes_sent += sent.len();
        sock.write_all(&sent).unwrap();
        sock.flush().unwrap();
        sent.clear();
    }
    assert!(pending.is_empty());
    assert_eq!(headers, wanted);
    assert_eq!(ended, accepted);
    assert_eq!(body_bytes, accepted * length);
    json!({"headers":headers,"accepted":accepted,"rejected":headers-accepted,"complete_bodies":ended,"body_bytes":body_bytes,"bytes_read":bytes_read,"bytes_sent":bytes_sent,"goaways":goaways,"client_goaway_bytes":client_goaway_bytes})
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let total: usize = args[1].parse().unwrap();
    let window: usize = args[2].parse().unwrap();
    let limit: usize = args[3].parse().unwrap();
    let length: usize = args[4].parse().unwrap();
    let tls = args[5] == "tls";
    let repeat = args[6] == "repeat";
    assert!(window >= limit && limit > 0 && total > 0);
    let config = tls.then(tls_config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    println!("{}", listener.local_addr().unwrap());
    std::io::stdout().flush().unwrap();
    let (mut done, mut connections) = (0, 0);
    while done < total {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let wanted = window.min(total - done);
        let accepted = limit.min(total - done);
        let summary = if let Some(config) = &config {
            let mut conn = rustls::ServerConnection::new(config.clone()).unwrap();
            serve(
                &mut rustls::Stream::new(&mut conn, &mut stream),
                wanted,
                accepted,
                length,
                repeat,
            )
        } else {
            serve(&mut stream, wanted, accepted, length, repeat)
        };
        done += accepted;
        connections += 1;
        println!("{summary}");
    }
    println!("{}", json!({"done":done,"connections":connections}));
}
