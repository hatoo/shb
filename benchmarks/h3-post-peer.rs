// Share the independently implemented, byte-checking peer with the credit tests.
#[allow(dead_code)]
#[path = "../tests/support/credit_recovery.rs"]
mod peer;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let server = peer::server(args[1].parse().unwrap(), 2048, false);
    println!("{}", server.addr);
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    println!(
        "{{\"responses\":{}}}",
        server.completed.load(std::sync::atomic::Ordering::SeqCst)
    );
}
