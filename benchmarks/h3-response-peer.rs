//! Fixed Quinn peer: port header-value-bytes body-bytes split(0|1).
//! A split is two application writes with a yield between them; actual QUIC
//! read boundaries remain transport-dependent. No artificial delay for timing.

use std::sync::Arc;
use std::time::Duration;

#[path = "../src/http3/response_fixture.rs"]
mod fixture;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 5);
    let port: u16 = args[1].parse().unwrap();
    let header = args[2].parse().unwrap();
    let body = args[3].parse().unwrap();
    let split = args[4] == "1";
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            let endpoint =
                quinn::Endpoint::server(fixture::server_config(), ([127, 0, 0, 1], port).into())
                    .unwrap();
            let (wire, cut) = fixture::response(header, body);
            let wire = Arc::new(wire);
            println!("{}", endpoint.local_addr().unwrap());
            while let Some(incoming) = endpoint.accept().await {
                let wire = Arc::clone(&wire);
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        fixture::serve(conn, wire, if split { cut } else { 0 }, Duration::ZERO)
                            .await;
                    }
                });
            }
        });
}
