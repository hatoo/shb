//! Fixed raw HTTP/1 peer for response-header benchmarks.
//! Build with rustc --edition=2024 -O benchmarks/h1-header-server.rs.
//! Arguments: bind-address header-bytes fields|line|near|connection. Emits its port as JSON.
//! Use the same immutable peer binary for both client revisions.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let size: usize = args[2].parse().unwrap();
    let mut wire = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n".to_vec();
    if size > 64 {
        match args[3].as_str() {
            "fields" => {
                while wire.len() + 53 < size {
                    wire.extend_from_slice(
                        b"X-Field: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n",
                    );
                }
            }
            "line" | "near" | "connection" => {
                wire.extend_from_slice(match args[3].as_str() {
                    "near" => b"Transfer-Encoding-Extension: ",
                    "connection" => b"Connection: ",
                    _ => b"X-Long: ",
                });
                wire.resize(size.saturating_sub(4).max(wire.len()), b'x');
                wire.extend_from_slice(b"\r\n");
            }
            _ => panic!("pattern"),
        }
    }
    wire.extend_from_slice(b"\r\nhello, world!");
    let wire = Arc::new(wire);
    let listener = TcpListener::bind(&args[1]).unwrap();
    println!(
        "{{\"port\":{},\"wire_bytes\":{}}}",
        listener.local_addr().unwrap().port(),
        wire.len()
    );
    std::io::stdout().flush().unwrap();
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        stream.set_nodelay(true).unwrap();
        let response = wire.clone();
        std::thread::spawn(move || {
            let mut stream = BufReader::new(stream);
            let mut line = Vec::new();
            let mut requests = 0;
            loop {
                line.clear();
                match stream.read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                assert!(line.starts_with(b"GET / "));
                loop {
                    line.clear();
                    stream.read_until(b'\n', &mut line).unwrap();
                    if line == b"\r\n" {
                        break;
                    }
                    assert!(!line.is_empty());
                }
                if stream.get_mut().write_all(&response).is_err() {
                    break;
                }
                requests += 1;
            }
            eprintln!("{{\"served\":{requests}}}");
        });
    }
}
