//! JSON-lines adapter for the independent request-encoding oracle.
//! Uses the production sources; it is not part of the benchmark executable.

use std::io::{self, BufRead};

#[allow(dead_code)]
#[path = "../src/http3/qpack.rs"]
mod qpack;
#[allow(dead_code)]
#[path = "../src/status.rs"]
mod status;

fn main() -> anyhow::Result<()> {
    for line in io::stdin().lock().lines() {
        let input: serde_json::Value = serde_json::from_str(&line?)?;
        let output = {
            let headers: Vec<(String, String)> = serde_json::from_value(input["headers"].clone())?;
            let encoded = qpack::encode_request(
                input["method"].as_str().unwrap(),
                input["scheme"].as_str().unwrap(),
                input["authority"].as_str().unwrap(),
                input["path"].as_str().unwrap(),
                &headers,
                input["body_len"].as_u64().unwrap() as usize,
            );
            serde_json::json!({"encoded": encoded})
        };
        println!("{output}");
    }
    Ok(())
}
