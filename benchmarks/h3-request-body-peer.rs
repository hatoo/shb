// Use the independent byte-checking Quinn peer from the recovery tests.
#[allow(dead_code)]
#[path = "../tests/support/credit_recovery.rs"]
mod peer;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let len = args[1].parse().unwrap();
    let window = args.get(2).map_or(2048, |n| n.parse().unwrap());
    let connection_window = args.get(3).map_or(4096, |n| n.parse().unwrap());
    let mut body = peer::patterned_body(len);
    // shb's curl-compatible -d @file removes CR/LF. Keep the CLI fixture's
    // length exact; the in-process recovery tests still exercise every byte.
    for byte in &mut body {
        if matches!(*byte, b'\r' | b'\n') {
            *byte += 1;
        }
    }
    let server = peer::server_with_windows(body, window, connection_window, false);
    println!("{}", server.addr);
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    let responses = server.completed.load(std::sync::atomic::Ordering::SeqCst);
    println!(
        "{{\"responses\":{responses},\"validated_body_bytes\":{}}}",
        responses * len
    );
}
