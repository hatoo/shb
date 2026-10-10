//! Independent wire fixture over Quinn; used only by tests and the replay peer.

use std::sync::Arc;
use std::time::Duration;

pub fn server_config() -> quinn::ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.der().clone()], key.into())
    .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(256u32.into());
    config.transport_config(Arc::new(transport));
    config
}

// Deliberately independent of the production H3/QPACK codecs.
fn integer(out: &mut Vec<u8>, value: usize) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16384 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    }
}

/// HEADERS, DATA, trailers, and the offset just before HEADERS completes.
pub fn response(header: usize, body: usize) -> (Vec<u8>, usize) {
    let mut section = vec![0, 0];
    if header > 0 {
        section.extend_from_slice(&[0x21, b'x']);
        if header < 127 {
            section.push(header as u8);
        } else {
            section.push(127);
            let mut rest = header - 127;
            while rest >= 128 {
                section.push((rest as u8 & 127) | 128);
                rest >>= 7;
            }
            section.push(rest as u8);
        }
        section.resize(section.len() + header, b'y');
    }
    section.push(0xd9); // static :status 200
    let mut wire = vec![1];
    integer(&mut wire, section.len());
    wire.extend_from_slice(&section);
    let cut = wire.len() - 1;
    wire.push(0);
    integer(&mut wire, body);
    wire.resize(wire.len() + body, b'z');
    wire.extend_from_slice(&[1, 2, 0, 0]); // empty trailers
    (wire, cut)
}

pub async fn serve(conn: quinn::Connection, wire: Arc<Vec<u8>>, cut: usize, delay: Duration) {
    let Ok(mut control) = conn.open_uni().await else {
        return;
    };
    if control.write_all(&[0, 4, 0]).await.is_err() {
        return;
    }
    // Keep the critical control stream open for the connection's lifetime.
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let wire = Arc::clone(&wire);
        tokio::spawn(async move {
            let Ok(request) = recv.read_to_end(1 << 20).await else {
                return;
            };
            assert!(!request.is_empty());
            if cut > 0 {
                if send.write_all(&wire[..cut]).await.is_err() {
                    return;
                }
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                } else {
                    tokio::task::yield_now().await;
                }
            }
            if send.write_all(&wire[cut..]).await.is_ok() {
                let _ = send.finish();
            }
        });
    }
    drop(control);
}
