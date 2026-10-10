#[path = "../tests/support/h3_timeout.rs"]
mod peer;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let mode = match args[1].as_str() {
        "hold" => peer::Mode::Hold(args[2].parse().unwrap()),
        "timeout" => peer::Mode::Timeout,
        "reset" => peer::Mode::ResetGoaway,
        _ => panic!("mode must be hold, timeout, or reset"),
    };
    let server = peer::server(mode);
    println!("{}", server.addr);
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    use std::sync::atomic::Ordering;
    println!(
        "{{\"responses\":{},\"connections\":{},\"cancellations\":{}}}",
        server.responses.load(Ordering::SeqCst),
        server.connections.load(Ordering::SeqCst),
        server.cancellations.load(Ordering::SeqCst)
    );
}
