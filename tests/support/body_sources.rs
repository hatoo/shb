use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn body_sources_preserve_exact_bytes_for_every_protocol_and_worker() {
    let cases = [
        Vec::new(),
        b"\r\n\n\r".to_vec(),
        b"abc\r\ndef\n".to_vec(),
        b"literal\r\nbody\n".to_vec(),
        (0..=u8::MAX).collect(),
        (0..=u8::MAX).filter(|b| *b != 13 && *b != 10).collect(),
        [vec![b'a'; 129], vec![b'\n']].concat(),
    ];
    for (index, input) in cases.iter().enumerate() {
        let path = std::env::temp_dir().join(format!(
            "shb-body-source-{}-{index}.bin",
            std::process::id()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(input).unwrap();
        drop(file);
        for source in ["file", "stdin", "literal"] {
            // Command arguments cannot contain NUL or arbitrary binary data.
            if source == "literal" && index >= 4 {
                continue;
            }
            let expected = if source == "literal" {
                input.clone()
            } else {
                input
                    .iter()
                    .copied()
                    .filter(|b| *b != 13 && *b != 10)
                    .collect()
            };
            let hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();
            for protocol in ["h1", "h2", "h3"] {
                let url = if protocol == "h3" {
                    format!("https://{}/", super::h3_server_addr())
                } else {
                    format!("http://{}/", super::server_addrs().0)
                };
                // n < threads exercises zero worker budgets; 9 is uneven.
                for count in [0, 1, 9] {
                    let body_arg = match source {
                        "file" => format!("@{}", path.display()),
                        "stdin" => "@-".to_owned(),
                        _ => String::from_utf8(input.clone()).unwrap(),
                    };
                    let mut command = Command::new(env!("CARGO_BIN_EXE_shb"));
                    command.args([
                        "-j",
                        "-t",
                        "4",
                        "-c",
                        "4",
                        "-n",
                        &count.to_string(),
                        "--timeout",
                        "5s",
                        "-d",
                        &body_arg,
                        "-H",
                        &format!("X-Echo-Hex: {hex}"),
                        &url,
                    ]);
                    if protocol != "h1" {
                        command.arg(if protocol == "h2" {
                            "--http2"
                        } else {
                            "--http3"
                        });
                    }
                    let mut child = command
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .unwrap();
                    let mut stdin = child.stdin.take().unwrap();
                    if source == "stdin" {
                        stdin.write_all(input).unwrap();
                    }
                    drop(stdin);
                    let output = child.wait_with_output().unwrap();
                    assert!(output.status.success(), "{command:?}: {output:?}");
                    assert!(output.stderr.is_empty(), "{command:?}: {output:?}");
                    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                    super::latency_accounting::assert_samples(&report);
                    assert_eq!(
                        report["requests"],
                        serde_json::json!({
                            "total":count, "ok":count, "errors":0, "connectErrors":0
                        }),
                        "{command:?}: {report}"
                    );
                    let statuses = if count == 0 {
                        serde_json::json!({})
                    } else {
                        serde_json::json!({"201":count})
                    };
                    assert_eq!(report["statusCodes"], statuses, "{command:?}: {report}");
                    assert_eq!(report["latencySeconds"].is_null(), count == 0, "{report}");
                }
            }
        }
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn body_read_errors_precede_target_validation_even_with_zero_budget() {
    for protocol in [&[][..], &["--http2"], &["--http3"]] {
        for count in ["0", "1"] {
            for source in ["@/no/such/shb/body-normalization-file", "@-"] {
                let mut command = Command::new(env!("CARGO_BIN_EXE_shb"));
                command.args(protocol).args([
                    "-n",
                    count,
                    "-c",
                    "1",
                    "-t",
                    "1",
                    "-d",
                    source,
                    "-m",
                    "GE T",
                    "https://127.0.0.1:9/",
                ]);
                // Reading a directory as stdin fails on Linux.
                command.stdin(std::fs::File::open(std::env::temp_dir()).unwrap());
                let output = command.output().unwrap();
                assert!(!output.status.success());
                let stderr = String::from_utf8(output.stderr).unwrap();
                let expected = if source == "@-" {
                    "Error: failed to read body from stdin"
                } else {
                    "Error: failed to read body file /no/such/shb/body-normalization-file"
                };
                assert_eq!(stderr.lines().next(), Some(expected));
            }
        }
    }
}
