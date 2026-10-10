#!/usr/bin/env python3
"""Build the independent peer from this repository's locked release artifacts.

First run cargo test --release --locked --no-run. Then pass four paths:
  target/release benchmarks/h3-timeout-peer.rs /tmp/h3-peer /tmp/h3-peer-build.json
Select rustls by Quinn's dependency fingerprint when Cargo built it with more
than one feature set. The output binary and manifest must not already exist.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

release, source, binary, manifest = map(Path, sys.argv[1:])
assert not binary.exists() and not manifest.exists(), 'Do not overwrite immutable evidence'
deps = release / 'deps'
fingerprints = release / '.fingerprint'
quinn = list(fingerprints.glob('quinn-*/lib-quinn.json'))
assert len(quinn) == 1
expected = next(d[3] for d in json.loads(quinn[0].read_text())['deps'] if d[1] == 'rustls')
matching = [p.parent.name for p in fingerprints.glob('rustls-*/lib-rustls')
            if int.from_bytes(bytes.fromhex(p.read_text()), 'little') == expected]
assert len(matching) == 1
command = ['rustc', '--edition=2024', '-O', '-Clto=fat', '-Ccodegen-units=1',
           '-Dwarnings', '-Ldependency=' + str(deps)]
for lib in ['quinn', 'tokio', 'rustls', 'rcgen', 'h3', 'h3_quinn', 'http', 'bytes']:
    choices = [deps / ('lib' + matching[0] + '.rlib')] if lib == 'rustls' else list(deps.glob('lib' + lib + '-*.rlib'))
    assert len(choices) == 1, (lib, choices)
    command += ['--extern', lib + '=' + str(choices[0])]
command += [str(source), '-o', str(binary)]
subprocess.run(command, check=True)
binary.chmod(0o555)
with manifest.open('x') as f:
    json.dump({'command': command, 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}, f, indent=2)
