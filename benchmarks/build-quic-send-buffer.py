#!/usr/bin/env python3
"""Build actual SendStream replay and separate deterministic copy counters.

Arguments: source worktree, production target/release, new output directory.
The native binary is uninstrumented. The count binary injects counters immediately
before actual Vec compaction; its timings are not performance evidence.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

tree, release, output = map(Path, sys.argv[1:])
output.mkdir()
source = (tree / "src/quic/stream.rs").read_text()
harness = Path(__file__).with_name("quic-send-buffer.rs").read_text()
manifest = {}
for mode in ["native", "count"]:
    directory = output / mode
    directory.mkdir()
    counted = source
    if mode == "count":
        if "self.buf.drain(..drop);" in counted:
            counted = counted.replace("self.buf.drain(..drop);", "crate::MOVED.fetch_add((self.buf.len() - drop) as u64, std::sync::atomic::Ordering::Relaxed);\n            self.buf.drain(..drop);", 1)
        else:
            assert "self.buf.copy_within(self.buf_start.., 0);" in counted
            counted = counted.replace("self.buf.copy_within(self.buf_start.., 0);", "crate::MOVED.fetch_add(live as u64, std::sync::atomic::Ordering::Relaxed);\n            self.buf.copy_within(self.buf_start.., 0);", 1)
    (directory / "stream.rs").write_text(counted)
    (directory / "main.rs").write_text(harness)
    command = ["rustc", "--edition=2024", "-O", "-Clto=fat", "-Ccodegen-units=1", "-Dwarnings", "-Ldependency=" + str(release / "deps")]
    if mode == "count":
        command += ["--cfg", "copy_counts"]
    for dependency in ["anyhow", "mimalloc"]:
        matches = list((release / "deps").glob("lib" + dependency + "-*.rlib"))
        assert len(matches) == 1, matches
        command += ["--extern", dependency + "=" + str(matches[0])]
    binary = output / ("replay-" + mode)
    command += [str(directory / "main.rs"), "-o", str(binary)]
    subprocess.run(command, check=True)
    binary.chmod(0o555)
    manifest[mode] = dict(command=command, sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
manifest["source_sha256"] = hashlib.sha256(source.encode()).hexdigest()
with (output / "build.json").open("x") as file:
    json.dump(manifest, file, indent=2)
