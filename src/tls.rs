//! TLS layer (rustls, Sans I/O)
//!
//! shb is a benchmarker, so server authentication is deliberately out of
//! scope: every certificate is trusted.

use std::io::{Read, Write};
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

/// Shared TLS client configuration and the SNI name (one per run)
pub struct TlsSetup {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

/// Accept-everything certificate verifier
#[derive(Debug)]
struct TrustAll(Arc<CryptoProvider>);

impl ServerCertVerifier for TrustAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Build a trust-everything rustls client configuration
///
/// `alpn` is the single protocol to offer (`b"h3"`, `b"h2"` or `b"http/1.1"`).
pub fn client_config(alpn: &[u8]) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAll(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(Arc::new(config))
}

/// Build the shared client configuration for the TCP-based protocols
pub fn setup(host: &str, alpn: &[u8]) -> Result<TlsSetup> {
    let config = client_config(alpn)?;
    let server_name = ServerName::try_from(host.to_string()).context("invalid TLS server name")?;
    Ok(TlsSetup {
        config,
        server_name,
    })
}

/// Per-connection TLS session (Sans I/O)
///
/// Sits between the socket bytes (ciphertext) and the HTTP layer (plaintext):
/// - socket recv -> [`feed`] -> [`read_plaintext`] -> HTTP decoder
/// - HTTP bytes -> [`write_plaintext`] -> [`take_ciphertext`] -> socket send
pub struct TlsSession {
    conn: ClientConnection,
}

impl TlsSession {
    pub fn new(setup: &TlsSetup) -> Result<Self> {
        Ok(TlsSession {
            conn: ClientConnection::new(setup.config.clone(), setup.server_name.clone())
                .context("failed to create TLS session")?,
        })
    }

    /// Feed ciphertext received from the socket and process it
    ///
    /// Returns the number of decrypted plaintext bytes now available via
    /// [`read_plaintext`](Self::read_plaintext).
    /// Feed received ciphertext, handing the plaintext to `sink` as it appears
    ///
    /// rustls refuses more ciphertext once 16 KiB of decrypted plaintext is
    /// waiting - one maximum-sized TLS record - and that limit is not
    /// configurable. A server sending full-sized records therefore fills it
    /// part-way through a single receive, so the plaintext has to be taken out
    /// between reads rather than after the whole receive.
    pub fn feed_into(
        &mut self,
        mut data: &[u8],
        scratch: &mut [u8],
        mut sink: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        while !data.is_empty() {
            let n = self.conn.read_tls(&mut data).context("read_tls failed")?;
            if n == 0 {
                break;
            }
            self.conn
                .process_new_packets()
                .map_err(|e| anyhow::anyhow!("TLS error: {e}"))?;
            loop {
                let n = self.read_plaintext(scratch)?;
                if n == 0 {
                    break;
                }
                sink(&scratch[..n])?;
            }
        }
        Ok(())
    }

    /// Read decrypted plaintext into buf; Ok(0) means none is available
    pub fn read_plaintext(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.conn.reader().read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            // Peer closed without close_notify; the benchmarker handles EOF at
            // the socket level, so treat it as "no more plaintext" here
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
            Err(e) => Err(e).context("TLS plaintext read failed"),
        }
    }

    /// Queue plaintext to be encrypted and sent
    pub fn write_plaintext(&mut self, data: &[u8]) -> Result<()> {
        self.conn
            .writer()
            .write_all(data)
            .context("TLS plaintext write failed")
    }

    /// Drain pending ciphertext (handshake messages included) to send
    pub fn take_ciphertext(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while self.conn.wants_write() {
            self.conn.write_tls(&mut out).context("write_tls failed")?;
        }
        Ok(out)
    }
}
