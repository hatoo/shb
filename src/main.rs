mod buf_ring;
mod http1;
mod http2;
mod http3;
mod report;
mod shutdown;
mod stats;
mod target;
mod tls;
mod uring;

use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use clap::Parser;

use crate::report::{print_json_report, print_report};
use crate::stats::Stats;
use crate::target::parse_target;

#[derive(Parser)]
#[command(
    name = "shb",
    about = "io_uring HTTP/1.1 / HTTP/2 / HTTP/3 benchmarker"
)]
#[command(group = clap::ArgGroup::new("proto").args(["http2", "http3"]).multiple(false))]
pub struct Args {
    /// Target URL, e.g. http://127.0.0.1:8080/ or https://example.com/
    /// (TLS trusts every certificate: this is a benchmarker)
    pub url: String,

    /// Number of concurrent connections
    #[arg(short, long, default_value_t = 50, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
    pub connections: usize,

    /// Total number of requests
    #[arg(short = 'n', long, default_value_t = 200, conflicts_with = "duration")]
    pub requests: u64,

    /// Run for this long instead of a fixed request count (e.g. 10s, 1m30s)
    #[arg(short = 'z', long, value_parser = humantime::parse_duration)]
    pub duration: Option<Duration>,

    /// Connection establishment timeout (e.g. 5s, 500ms)
    #[arg(long, default_value = "5s", value_parser = humantime::parse_duration)]
    pub connect_timeout: Duration,

    /// Number of worker threads
    #[arg(short = 't', long, default_value_t = default_threads(), value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
    pub threads: usize,

    /// Print the report as JSON
    #[arg(short = 'j', long)]
    pub json: bool,

    /// Use HTTP/2 (prior knowledge on http://, ALPN "h2" on https://)
    #[arg(long)]
    pub http2: bool,

    /// Use HTTP/3 over QUIC (https:// URLs only)
    #[arg(long)]
    pub http3: bool,

    /// Number of concurrent streams per connection (HTTP/2 and HTTP/3)
    #[arg(
        short = 'p',
        long,
        default_value_t = 1,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..),
        requires = "proto"
    )]
    pub parallel: usize,
}

/// Default number of threads (number of physical CPU cores)
fn default_threads() -> usize {
    num_cpus::get_physical().max(1)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let target = parse_target(&args.url)?;

    // Print the report even when interrupted with Ctrl-C: the handler sets a
    // flag, workers notice it within ~100ms and return their stats normally
    shutdown::install();

    if args.http3 && !target.tls {
        bail!("--http3 requires an https:// URL");
    }

    // Shared TLS configuration for the TCP protocols (https URLs only); the
    // HTTP/3 worker builds its own QUIC TLS configuration
    let tls_setup = if target.tls && !args.http3 {
        let alpn: &[u8] = if args.http2 { b"h2" } else { b"http/1.1" };
        Some(tls::setup(&target.host, alpn)?)
    } else {
        None
    };

    let duration_limit = args.duration;

    // Each thread gets at least one connection
    let threads = args.threads.min(args.connections);

    // Distribute connections and requests across threads (remainder goes to the first threads)
    let conns_per_thread: Vec<usize> = (0..threads)
        .map(|i| args.connections / threads + usize::from(i < args.connections % threads))
        .collect();
    let requests_per_thread: Vec<u64> = if duration_limit.is_some() {
        // In duration mode the request count is unlimited
        vec![u64::MAX; threads]
    } else {
        (0..threads)
            .map(|i| {
                args.requests / threads as u64
                    + u64::from((i as u64) < args.requests % threads as u64)
            })
            .collect()
    };

    let bench_start = Instant::now();
    let results: Vec<Result<Stats>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|i| {
                let target = &target;
                let connections = conns_per_thread[i];
                let max_requests = requests_per_thread[i];
                let connect_timeout = args.connect_timeout;
                let http2 = args.http2;
                let http3 = args.http3;
                let parallel = args.parallel;
                let tls = tls_setup.as_ref();
                s.spawn(move || {
                    if http3 {
                        http3::run_worker(
                            target,
                            connections,
                            max_requests,
                            duration_limit,
                            connect_timeout,
                            parallel,
                        )
                    } else if http2 {
                        http2::run_worker(
                            target,
                            tls,
                            connections,
                            max_requests,
                            duration_limit,
                            connect_timeout,
                            parallel,
                        )
                    } else {
                        http1::run_worker(
                            target,
                            tls,
                            connections,
                            max_requests,
                            duration_limit,
                            connect_timeout,
                        )
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| match h.join() {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!("worker thread panicked")),
            })
            .collect()
    });
    let elapsed = bench_start.elapsed();

    let mut stats = Stats::default();
    for result in results {
        stats.merge(result?);
    }

    if args.json {
        print_json_report(&args, threads, &stats, elapsed)?;
    } else {
        print_report(&args, threads, &stats, elapsed);
    }
    Ok(())
}
