use std::time::Duration;

use anyhow::Result;

use crate::Args;
use crate::stats::{Stats, latency_summary};

fn protocol_name(args: &Args) -> &'static str {
    if args.http3 {
        "HTTP/3"
    } else if args.http2 {
        "HTTP/2"
    } else {
        "HTTP/1.1"
    }
}

pub fn print_report(args: &Args, threads: usize, stats: &Stats, elapsed: Duration) {
    let secs = elapsed.as_secs_f64();
    let total = stats.completed + stats.errors;
    println!("URL:          {}", args.url);
    println!("Protocol:     {}", protocol_name(args));
    println!("Threads:      {threads}");
    println!("Connections:  {}", args.connections);
    println!(
        "Requests:     {} ({} ok, {} errors, of which {} connect) in {:.3}s",
        total, stats.completed, stats.errors, stats.connect_errors, secs
    );
    println!("Requests/sec: {:.1}", stats.completed as f64 / secs);
    println!(
        "Transfer:     recv {:.2} MB/s ({} bytes), sent {:.2} MB/s ({} bytes)",
        stats.bytes_received as f64 / secs / (1024.0 * 1024.0),
        stats.bytes_received,
        stats.bytes_sent as f64 / secs / (1024.0 * 1024.0),
        stats.bytes_sent
    );

    let lines: Vec<String> = stats
        .status_counts
        .iter()
        .enumerate()
        .filter(|&(_, &n)| n > 0)
        .map(|(code, &n)| format!("  [{code}] {n}"))
        .collect();
    if !lines.is_empty() {
        println!("Status codes:");
        for line in lines {
            println!("{line}");
        }
    }

    if let Some(l) = latency_summary(&stats.latencies_ns) {
        println!("Latency (ms):");
        println!(
            "  min {:.3}  mean {:.3}  p50 {:.3}  p90 {:.3}  p99 {:.3}  max {:.3}",
            l.min * 1e3,
            l.mean * 1e3,
            l.p50 * 1e3,
            l.p90 * 1e3,
            l.p99 * 1e3,
            l.max * 1e3,
        );
    }
}

pub fn print_json_report(
    args: &Args,
    threads: usize,
    stats: &Stats,
    elapsed: Duration,
) -> Result<()> {
    let secs = elapsed.as_secs_f64();
    let status_codes: serde_json::Map<String, serde_json::Value> = stats
        .status_counts
        .iter()
        .enumerate()
        .filter(|&(_, &n)| n > 0)
        .map(|(code, &n)| (code.to_string(), n.into()))
        .collect();
    let latency = latency_summary(&stats.latencies_ns).map(|l| {
        serde_json::json!({
            "min": l.min,
            "mean": l.mean,
            "p50": l.p50,
            "p90": l.p90,
            "p99": l.p99,
            "max": l.max,
        })
    });
    let report = serde_json::json!({
        "url": args.url,
        "protocol": protocol_name(args),
        "threads": threads,
        "connections": args.connections,
        "durationSeconds": secs,
        "requests": {
            "total": stats.completed + stats.errors,
            "ok": stats.completed,
            "errors": stats.errors,
            "connectErrors": stats.connect_errors,
        },
        "requestsPerSec": stats.completed as f64 / secs,
        "bytesReceived": stats.bytes_received,
        "bytesReceivedPerSec": stats.bytes_received as f64 / secs,
        "bytesSent": stats.bytes_sent,
        "bytesSentPerSec": stats.bytes_sent as f64 / secs,
        "statusCodes": status_codes,
        "latencySeconds": latency,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
