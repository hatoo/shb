#!/usr/bin/env python3
"""Build the fixed native sparse-packet peer from a local hfast Git repository.

Usage: build-ack-storage-peer.py /path/to/hfast /new/output/directory
The hfast working tree is never changed or read. Its pinned Git commit supplies
the transport; the small benchmark extension supplies the sparse workload.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

revision = 'd710d8098bc5693d91f5a11a5b185c759b44b786'
repo, output = map(Path, sys.argv[1:])
output = output.resolve()
output.mkdir(parents=True)  # Refuse to overwrite an existing experiment.
source = output / 'source'
source.mkdir()
here = Path(__file__).parent
archive = subprocess.check_output(['git', '-C', str(repo), 'archive', revision])
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    tar.extractall(source, filter='data')
(source / 'src/main.rs').write_text((here / 'ack-storage-peer-main.rs').read_text())
module = source / 'src/quic/mod.rs'
module.write_text(module.read_text().replace('pub mod endpoint;', '').replace('mod udp;', ''))
conn = source / 'src/quic/conn.rs'
code = conn.read_text().replace('pub struct Connection {', 'pub struct Connection {\n    probe_last_ack: Vec<(u64,u64)>,')
needle = '            tls,'
assert code.count(needle) == 1
code = code.replace(needle, '            probe_last_ack: Vec::new(),\n' + needle)
needle = '                let st = &mut self.spaces[space as usize];\n                st.largest_acked'
assert code.count(needle) == 1
code = code.replace(needle, '                if space == Space::Data { self.probe_last_ack = frame::AckRanges::new(largest, first_range, rest).collect(); }\n' + needle)
conn.write_text(code + '\n' + (here / 'ack-storage-peer-methods.rs').read_text())
env = dict(os.environ, CARGO_INCREMENTAL='0', CARGO_TARGET_DIR=str(output / 'target'))
command = ['cargo', 'build', '--release', '--locked']
subprocess.run(command, cwd=source, env=env, check=True)
binary = output / 'sparse-peer'
shutil.copy2(output / 'target/release/hfast', binary)
binary.chmod(0o555)
(output / 'manifest.json').write_text(json.dumps(dict(
    hfast=revision, command=command,
    sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
    source_sha256={str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted((source / 'src').rglob('*.rs'))},
), indent=2) + '\n')
print(binary)
