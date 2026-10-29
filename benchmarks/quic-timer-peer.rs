//! Bounded JSON-lines adapter for the independent, logical-time QUIC oracle.
//! Only public production APIs: no assigned RTT, packet history or timer state.

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use std::time::Duration;

#[path = "../src/clock.rs"]
mod clock;
#[allow(dead_code)]
#[path = "../src/quic/mod.rs"]
mod quic;
#[allow(dead_code)]
#[path = "../src/tls.rs"]
mod tls;

use quic::conn::{Connection, Event, LocalParamsInput};

const MAX_LINE: usize = 32_768;
const MAX_COMMANDS: usize = 4096;
const MAX_TIME_US: u64 = 30_000_000;

fn number(input: &Value, key: &str) -> Result<u64> {
    input[key]
        .as_u64()
        .with_context(|| format!("missing {key}"))
}

fn bytes(input: &Value, key: &str, limit: usize) -> Result<Vec<u8>> {
    let value = input[key].as_str().context("expected hex string")?;
    ensure!(
        value.len() <= limit * 2 && value.len().is_multiple_of(2),
        "hex size"
    );
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect()
}

fn hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        write!(out, "{byte:02x}").unwrap();
    }
    out
}

fn main() -> Result<()> {
    let mut conn = Connection::connect(
        tls::client_config(b"quic-timer-oracle")?,
        "localhost",
        LocalParamsInput {
            initial_max_data: 1 << 20,
            initial_max_stream_data: 1 << 16,
            initial_max_streams_uni: 8,
            max_idle_timeout_ms: 60_000,
            handshake_timeout_ms: 10_000,
        },
    )?;
    let epoch = clock::Instant::now();
    let mut last = 0;
    let mut streams = 0;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    for _ in 0..MAX_COMMANDS {
        // Bound allocation before decoding, including a line with no newline.
        let mut line = Vec::new();
        loop {
            let available = input.fill_buf()?;
            if available.is_empty() {
                ensure!(line.is_empty(), "unterminated command");
                return Ok(());
            }
            let end = available.iter().position(|b| *b == b'\n').map(|n| n + 1);
            let n = end.unwrap_or(available.len());
            ensure!(line.len() + n <= MAX_LINE, "command too large");
            line.extend_from_slice(&available[..n]);
            input.consume(n);
            if end.is_some() {
                break;
            }
        }
        let value: Value = serde_json::from_slice(&line)?;
        let time = number(&value, "time_us")?;
        ensure!(
            last <= time && time <= MAX_TIME_US,
            "logical time out of bounds"
        );
        last = time;
        let now = epoch + Duration::from_micros(time);
        let mut opened = None;
        match value["op"].as_str().context("missing op")? {
            "poll" => {}
            "receive" => conn.handle_datagram(now, &mut bytes(&value, "wire", 1200)?)?,
            "timeout" => conn.handle_timeout(now),
            "request" => {
                ensure!(streams < 64, "stream limit");
                let data = bytes(&value, "data", 1024)?;
                let id = conn.open_bi().context("stream blocked")?;
                ensure!(conn.write(id, &data) == data.len(), "partial request write");
                conn.finish(id);
                streams += 1;
                opened = Some(id);
            }
            _ => bail!("unknown operation"),
        }
        let mut events = Vec::new();
        while let Some(event) = conn.poll_event() {
            ensure!(events.len() < 256, "event limit");
            events.push(match event {
                Event::Connected => json!({"type": "connected"}),
                Event::Readable(id) => {
                    let mut data = Vec::new();
                    conn.consume(id, |chunk| {
                        data.extend_from_slice(chunk);
                        Ok(())
                    })?;
                    ensure!(data.len() <= 65536, "response too large");
                    json!({"type": "data", "sid": id, "data": hex(&data)})
                }
                Event::Finished { id, reset: None } => json!({"type": "fin", "sid": id}),
                other => bail!("unexpected event: {other:?}"),
            });
        }
        let probing = conn.probing();
        let mut datagrams = Vec::new();
        for _ in 0..64 {
            let mut wire = Vec::new();
            let n = conn.poll_transmit(now, &mut wire, None)?;
            ensure!(n == wire.len() && n <= 1200, "invalid datagram size");
            if n == 0 {
                break;
            }
            datagrams.push(hex(&wire));
        }
        ensure!(datagrams.len() < 64, "datagram limit");
        let deadline = conn
            .poll_timeout()
            .map(|at| at.saturating_duration_since(epoch).as_micros() as u64);
        writeln!(
            output,
            "{}",
            json!({"time_us": time, "opened": opened,
            "events": events, "probing": probing, "datagrams": datagrams, "deadline_us": deadline})
        )?;
        output.flush()?;
    }
    bail!("command limit")
}
