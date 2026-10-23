//! Fixed independent h2 0.4.19 peer: respond only after exact bytes and EOF.
use bytes::Bytes;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering::Relaxed},
};
use tokio::net::TcpListener;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let port: u16 = args[1].parse().unwrap();
    let body = Arc::new(std::fs::read(&args[2]).unwrap());
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
            eprintln!("READY {port}");
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                socket.set_nodelay(true).unwrap();
                let body = body.clone();
                tokio::spawn(async move {
                    let count = Arc::new(AtomicU64::new(0));
                    let bytes = Arc::new(AtomicU64::new(0));
                    let tasks = Arc::new(AtomicU64::new(0));
                    let mut builder = h2::server::Builder::new();
                    builder
                        .initial_window_size(4 * 1048576)
                        .initial_connection_window_size(32 * 1048576)
                        .max_concurrent_streams(1024)
                        .max_frame_size(16384);
                    let Ok(mut conn) = builder.handshake::<_, Bytes>(socket).await else {
                        return;
                    };
                    while let Some(result) = conn.accept().await {
                        let (request, mut reply) = match result {
                            Ok(v) => v,
                            Err(e) => {
                                eprintln!("CONNECTION_ERROR {e}");
                                break;
                            }
                        };
                        let body = body.clone();
                        let count = count.clone();
                        let bytes = bytes.clone();
                        let tasks = tasks.clone();
                        tasks.fetch_add(1, Relaxed);
                        tokio::spawn(async move {
                            let expected = request
                                .headers()
                                .get("content-length")
                                .map(|x| x.to_str().unwrap().parse::<usize>().unwrap())
                                .unwrap_or(0);
                            assert!(expected == 0 || expected == body.len());
                            let mut stream = request.into_body();
                            let mut offset = 0;
                            while let Some(data) = stream.data().await {
                                let data = data.expect("DATA read");
                                assert!(offset + data.len() <= expected);
                                assert!(
                                    data.as_ref() == &body[offset..offset + data.len()],
                                    "request DATA differs at byte {offset}"
                                );
                                offset += data.len();
                                stream.flow_control().release_capacity(data.len()).unwrap();
                            }
                            assert_eq!(
                                offset, expected,
                                "body completed before its declared length"
                            );
                            assert!(stream.trailers().await.unwrap().is_none());
                            let response = http::Response::builder()
                                .status(200)
                                .header("content-length", "13")
                                .body(())
                                .unwrap();
                            let mut send = reply.send_response(response, false).unwrap();
                            send.send_data(Bytes::from_static(b"Hello, World!"), true)
                                .unwrap();
                            bytes.fetch_add(offset as u64, Relaxed);
                            count.fetch_add(1, Relaxed);
                            tasks.fetch_sub(1, Relaxed);
                        });
                    }
                    eprintln!(
                        "LEDGER {{\"requests\":{},\"body_bytes\":{},\"pending\":{}}}",
                        count.load(Relaxed),
                        bytes.load(Relaxed),
                        tasks.load(Relaxed)
                    );
                });
            }
        });
}
