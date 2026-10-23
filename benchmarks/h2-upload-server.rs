//! Independent h2 peer: respond only after exact bytes and END_STREAM.
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use clap::{Parser, ValueEnum};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{path::PathBuf, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Copy, ValueEnum)]
enum TlsVersion {
    Tls12,
    Tls13,
}

#[derive(Parser)]
struct Args {
    /// TCP port; zero asks the OS to choose an unused port.
    port: u16,
    /// File containing the exact expected upload bytes.
    body: PathBuf,
    #[arg(long, value_enum, requires_all = ["cert", "key"])]
    tls: Option<TlsVersion>,
    #[arg(long, requires = "tls")]
    cert: Option<PathBuf>,
    #[arg(long, requires = "tls")]
    key: Option<PathBuf>,
}

impl Args {
    fn tls_acceptor(&self) -> Result<Option<TlsAcceptor>> {
        let Some(version) = self.tls else {
            return Ok(None);
        };
        let version = match version {
            TlsVersion::Tls12 => &rustls::version::TLS12,
            TlsVersion::Tls13 => &rustls::version::TLS13,
        };
        let certs = CertificateDer::pem_file_iter(self.cert.as_ref().unwrap())?
            .collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_file(self.key.as_ref().unwrap())?;
        let mut config = rustls::ServerConfig::builder_with_protocol_versions(&[version])
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Some(TlsAcceptor::from(Arc::new(config))))
    }
}

async fn upload(
    request: http::Request<h2::RecvStream>,
    mut reply: h2::server::SendResponse<Bytes>,
    body: Arc<Vec<u8>>,
) -> Result<usize> {
    let expected = request
        .headers()
        .get("content-length")
        .map(|x| Ok::<_, anyhow::Error>(x.to_str()?.parse::<usize>()?))
        .transpose()?
        .unwrap_or(0);
    ensure!(
        expected == 0 || expected == body.len(),
        "unexpected content-length"
    );
    let mut stream = request.into_body();
    let mut offset = 0;
    while let Some(data) = stream.data().await {
        let data = data.context("DATA read")?;
        ensure!(
            data.len() <= expected - offset,
            "DATA exceeds content-length"
        );
        ensure!(
            data.as_ref() == &body[offset..offset + data.len()],
            "request DATA differs at byte {offset}"
        );
        offset += data.len();
        stream.flow_control().release_capacity(data.len())?;
    }
    ensure!(
        offset == expected,
        "body completed before its declared length"
    );
    ensure!(stream.trailers().await?.is_none(), "unexpected trailers");
    let response = http::Response::builder()
        .status(200)
        .header("content-length", "13")
        .body(())?;
    let mut send = reply.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"Hello, World!"), true)?;
    Ok(offset)
}

#[derive(Default)]
struct Ledger {
    requests: u64,
    body_bytes: u64,
    rejected: u64,
}

impl Ledger {
    fn finish(&mut self, result: Result<Result<usize>, tokio::task::JoinError>) {
        match result {
            Ok(Ok(bytes)) => {
                self.requests += 1;
                self.body_bytes += bytes as u64;
            }
            result => {
                self.rejected += 1;
                eprintln!("UPLOAD_ERROR {result:?}");
            }
        }
    }
}

async fn serve<T: AsyncRead + AsyncWrite + Unpin>(socket: T, body: Arc<Vec<u8>>, id: u64) {
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(4 * 1048576)
        .initial_connection_window_size(32 * 1048576)
        .max_concurrent_streams(1024)
        .max_frame_size(16384);
    let mut uploads = JoinSet::new();
    let mut ledger = Ledger::default();
    match builder.handshake::<_, Bytes>(socket).await {
        Ok(mut conn) => {
            loop {
                tokio::select! {
                    result = uploads.join_next(), if !uploads.is_empty() => {
                        ledger.finish(result.unwrap());
                    }
                    result = conn.accept() => match result {
                        Some(Ok((request, reply))) => {
                            uploads.spawn(upload(request, reply, body.clone()));
                        }
                        Some(Err(e)) => {
                            eprintln!("CONNECTION_ERROR {e}");
                            break;
                        }
                        None => break,
                    }
                }
            }
            // Dropping the transport wakes any incomplete DATA readers. Join
            // every stream before emitting its connection's final ledger.
            drop(conn);
        }
        Err(e) => eprintln!("CONNECTION_ERROR {e}"),
    }
    while let Some(result) = uploads.join_next().await {
        ledger.finish(result);
    }
    eprintln!(
        "LEDGER {{\"connection\":{id},\"requests\":{},\"body_bytes\":{},\"pending\":{},\"rejected\":{}}}",
        ledger.requests,
        ledger.body_bytes,
        uploads.len(),
        ledger.rejected,
    );
}

fn main() -> Result<()> {
    let args = Args::parse();
    let tls = args.tls_acceptor()?;
    let body = Arc::new(std::fs::read(&args.body)?);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?
        .block_on(async move {
            let listener = TcpListener::bind(("127.0.0.1", args.port)).await?;
            eprintln!("READY {}", listener.local_addr()?.port());
            let mut id = 0;
            loop {
                let (socket, _) = listener.accept().await?;
                socket.set_nodelay(true)?;
                let body = body.clone();
                let tls = tls.clone();
                id += 1;
                tokio::spawn(async move {
                    if let Some(tls) = tls {
                        match tls.accept(socket).await {
                            Ok(socket) if socket.get_ref().1.alpn_protocol() == Some(b"h2") => {
                                serve(socket, body, id).await;
                            }
                            Ok(_) => eprintln!("TLS_ERROR h2 ALPN required"),
                            Err(e) => eprintln!("TLS_ERROR {e}"),
                        }
                    } else {
                        serve(socket, body, id).await;
                    }
                });
            }
        })
}
