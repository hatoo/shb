//! Native response producer with an authenticated QUIC receipt ledger.
//! stdin `finish` closes the run; EOF, deadlines and task failures fail it.
use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use clap::{Parser, ValueEnum};
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{sync::watch, task::JoinSet};

#[path = "response_flight/transport.rs"]
mod transport;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Fault {
    None,
    Truncate,
    Corrupt,
    MissingFin,
    LateError,
}

#[derive(Clone, Parser)]
struct Args {
    #[arg(long)]
    requests: u64,
    #[arg(long)]
    body_bytes: usize,
    #[arg(long, default_value_t = 0)]
    port: u16,
    #[arg(long, default_value_t = 2)]
    workers: usize,
    #[arg(long, default_value_t = 30)]
    deadline_seconds: u64,
    /// Deliberate fixture failures, for oracle tests only.
    #[arg(long, value_enum, default_value_t = Fault::None)]
    fault: Fault,
}

#[derive(Default)]
struct Ledger {
    connections: AtomicU64,
    accepted: AtomicU64,
    validated: AtomicU64,
    finished: AtomicU64,
    acknowledged: AtomicU64,
    acknowledged_body_bytes: AtomicU64,
}

impl Ledger {
    fn snapshot(&self, args: &Args, errors: &[String]) -> serde_json::Value {
        let get = |x: &AtomicU64| x.load(Ordering::Relaxed);
        serde_json::json!({
            "connections": get(&self.connections), "accepted": get(&self.accepted),
            "validated": get(&self.validated), "finished": get(&self.finished),
            "acknowledged": get(&self.acknowledged),
            "acknowledgedBodyBytes": get(&self.acknowledged_body_bytes),
            "expectedRequests": args.requests, "bodyBytes": args.body_bytes,
            "fault": format!("{:?}", args.fault), "errors": errors,
        })
    }
    fn validate(&self, args: &Args) -> Result<()> {
        for (name, count) in [
            ("accepted", &self.accepted),
            ("validated", &self.validated),
            ("finished", &self.finished),
            ("acknowledged", &self.acknowledged),
        ] {
            ensure!(
                count.load(Ordering::Relaxed) == args.requests,
                "incomplete {name} count"
            );
        }
        ensure!(
            self.acknowledged_body_bytes.load(Ordering::Relaxed)
                == args.requests * args.body_bytes as u64,
            "incomplete acknowledged body bytes"
        );
        Ok(())
    }
}

fn patterned_body(len: usize) -> Bytes {
    (0..len)
        .map(|i| ((i * 31 + i / 251) % 256) as u8)
        .collect::<Vec<_>>()
        .into()
}

async fn response(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<transport::Bidi, Bytes>,
    body: Bytes,
    args: Arc<Args>,
    ledger: Arc<Ledger>,
) -> Result<()> {
    ensure!(request.method() == http::Method::GET, "expected GET");
    ensure!(
        request
            .uri()
            .path_and_query()
            .is_some_and(|p| p.as_str() == "/response"),
        "unexpected path"
    );
    ensure!(
        request.uri().scheme_str() == Some("https"),
        "unexpected scheme"
    );
    if let Some(length) = request.headers().get(http::header::CONTENT_LENGTH) {
        ensure!(length == "0", "unexpected request content-length");
    }
    ensure!(
        stream.recv_data().await?.is_none(),
        "unexpected request body"
    );
    ensure!(
        stream.recv_trailers().await?.is_none(),
        "unexpected request trailers"
    );
    ledger.validated.fetch_add(1, Ordering::Relaxed);
    let sent_body_bytes = body.len() as u64;
    stream
        .send_response(
            http::Response::builder()
                .status(200)
                .header("content-length", args.body_bytes)
                .body(())?,
        )
        .await?;
    stream.send_data(body).await?;
    if args.fault == Fault::MissingFin {
        std::future::pending::<()>().await;
    }
    // The adapter resolves finish only after all STREAM data and FIN have
    // been acknowledged, and rejects STOP_SENDING and transport errors.
    stream.finish().await.context("response receipt")?;
    if args.fault == Fault::LateError {
        bail!("injected late receipt failure");
    }
    ledger.acknowledged.fetch_add(1, Ordering::Relaxed);
    ledger
        .acknowledged_body_bytes
        .fetch_add(sent_body_bytes, Ordering::Relaxed);
    Ok(())
}

async fn serve(
    incoming: quinn::Incoming,
    body: Bytes,
    args: Arc<Args>,
    ledger: Arc<Ledger>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let conn = incoming.await.context("QUIC handshake")?;
    ledger.connections.fetch_add(1, Ordering::Relaxed);
    let mut h3 =
        h3::server::Connection::new(transport::Connection::new(conn.clone(), ledger.clone()))
            .await?;
    let mut jobs = JoinSet::new();
    let mut accepting = true;
    let mut stopping = *stop.borrow();
    let mut errors = Vec::new();
    loop {
        if (stopping || !accepting) && jobs.is_empty() {
            break;
        }
        tokio::select! {
            joined = jobs.join_next(), if !jobs.is_empty() => {
                match joined.unwrap() {
                    Ok(Ok(())) => {},
                    e => {
                        eprintln!("RESPONSE_ERROR {e:?}");
                        errors.push(format!("response task: {e:?}"));
                    },
                }
            }
            changed = stop.changed(), if !stopping => {
                changed.context("shutdown channel")?;
                stopping = true;
            }
            next = h3.accept(), if accepting => {
                match next {
                    Ok(Some(resolver)) => {
                        let index = ledger.accepted.fetch_add(1, Ordering::Relaxed);
                        ensure!(!stopping && index < args.requests, "unexpected extra request");
                        let (body, args, ledger) = (body.clone(), args.clone(), ledger.clone());
                        jobs.spawn(async move {
                            tokio::time::timeout(Duration::from_secs(args.deadline_seconds), async {
                                let (request, stream) = resolver.resolve_request().await?;
                                response(request, stream, body, args.clone(), ledger).await
                            }).await.context("response deadline")?
                        });
                    }
                    Ok(None) => accepting = false,
                    Err(e) => {
                        accepting = false;
                        let clean = matches!(conn.close_reason(), Some(quinn::ConnectionError::ApplicationClosed(ref c)) if c.error_code.into_inner() == 0 || c.error_code.into_inner() == 0x100);
                        if !clean { errors.push(format!("connection: {e}")); }
                    }
                }
            }
        }
    }
    ensure!(errors.is_empty(), "{}", errors.join("; "));
    Ok(())
}

fn endpoint(port: u16) -> Result<quinn::Endpoint> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(vec![certified.cert.der().clone()], key.into())?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1024u32.into());
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into()?));
    config.transport_config(Arc::new(transport));
    Ok(quinn::Endpoint::server(
        config,
        ([127, 0, 0, 1], port).into(),
    )?)
}

async fn run(args: Arc<Args>) -> Result<()> {
    let mut body = patterned_body(args.body_bytes);
    match args.fault {
        Fault::Truncate => body.truncate(body.len() - 1),
        Fault::Corrupt => {
            let mut changed = body.to_vec();
            changed[0] ^= 1;
            body = changed.into();
        }
        _ => {}
    }
    let endpoint = endpoint(args.port)?;
    let ledger = Arc::new(Ledger::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let (command_tx, mut command_rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = std::io::stdin().read_line(&mut line).map(|n| (n, line));
        let _ = command_tx.send(result);
    });
    println!(
        "{}",
        serde_json::json!({"ready": endpoint.local_addr()?, "bodyBytes": args.body_bytes, "expectedRequests": args.requests})
    );
    std::io::stdout().flush()?;
    let mut connections = JoinSet::new();
    let mut errors = Vec::new();
    let deadline = tokio::time::sleep(Duration::from_secs(args.deadline_seconds));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            command = &mut command_rx => {
                match command {
                    Ok(Ok((n, line))) if n > 0 && line == "finish\n" => {},
                    other => errors.push(format!("invalid finish command: {other:?}")),
                }
                break;
            }
            _ = &mut deadline => { errors.push("run deadline".into()); break; }
            incoming = endpoint.accept() => {
                match incoming {
                    Some(incoming) => { connections.spawn(serve(incoming, body.clone(), args.clone(), ledger.clone(), stop_rx.clone())); },
                    None => { errors.push("endpoint closed early".into()); break; },
                }
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                if let other @ (Ok(Err(_)) | Err(_)) = joined.unwrap() { errors.push(format!("connection task: {other:?}")); }
            }
        }
    }
    stop_tx.send(true)?;
    let drain = async {
        while let Some(joined) = connections.join_next().await {
            if let other @ (Ok(Err(_)) | Err(_)) = joined {
                errors.push(format!("connection task: {other:?}"));
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(args.deadline_seconds), drain)
        .await
        .is_err()
    {
        errors.push("shutdown deadline".into());
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    if let Err(e) = ledger.validate(&args) {
        errors.push(e.to_string());
    }
    println!("{}", ledger.snapshot(&args, &errors));
    ensure!(
        errors.is_empty(),
        "response flight failed: {}",
        errors.join("; ")
    );
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.requests > 0 && (1..=64 * 1048576).contains(&args.body_bytes),
        "positive requests and body of at most 64 MiB required"
    );
    ensure!(
        args.requests.checked_mul(args.body_bytes as u64).is_some(),
        "body byte count overflow"
    );
    ensure!(
        (1..=32).contains(&args.workers) && args.deadline_seconds > 0,
        "invalid runtime configuration"
    );
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.workers)
        .enable_all()
        .build()?
        .block_on(run(Arc::new(args)))
}
