#!/usr/bin/env python3
"""Build an untimed shb observer from immutable Git objects.

The production heap candidate and its baseline binaries remain unchanged.
Record actual pending queue depth and check every HTTP/3 DATA body byte.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

import importlib.util
spec = importlib.util.spec_from_file_location('builder', Path(__file__).with_name('build-native-reordering.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('revision')
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', '--verify', args.revision + '^{commit}'], text=True).strip()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = output / 'source'
    source.mkdir()
    archive = subprocess.check_output(['git', '-C', str(repo), 'archive', revision])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(source, filter='data')
    stream = source / 'src/quic/stream.rs'
    builder.replace(stream, '    ready: Vec<u8>,', '    ready: Vec<u8>,\n    probe_pending_peak: usize,')
    builder.replace(stream, '            read_offset: 0,', '            read_offset: 0,\n            probe_pending_peak: 0,')
    builder.replace(stream, '        std::mem::take(&mut self.ready)', '''        eprintln!("NATIVE_EXPOSURE {}", serde_json::json!({
            "peak_pending": self.probe_pending_peak, "read_offset": self.read_offset,
            "ready": self.ready.len(), "pending": self.pending.len(),
            "final_size": self.final_size, "credited_bytes": self.received,
        }));
        std::mem::take(&mut self.ready)''')
    builder.replace(stream, '        Ok(new)\n    }\n\n    /// Move anything', '''        self.probe_pending_peak = self.probe_pending_peak.max(self.pending.len());
        Ok(new)
    }

    /// Move anything''')
    proto = source / 'src/http3/proto.rs'
    builder.replace(proto, '    status: u16,', '''    status: u16,
    probe_data: bool,
    probe_bytes: usize,''')
    builder.replace(proto, '        self.status\n', '''        eprintln!("NATIVE_BODY {}", serde_json::json!({"bytes": self.probe_bytes}));
        self.status
''')
    # Restrict this replacement to ResponseReader; UniReader also skips frames.
    text = proto.read_text()
    begin, rest = text.split('/// Reader for a peer-opened unidirectional stream', 1)
    marker = '                pos += take as usize;'
    assert begin.count(marker) == 1
    begin = begin.replace(marker, '''                if self.probe_data {
                    for (j, &byte) in buf[pos..pos + take as usize].iter().enumerate() {
                        let i = self.probe_bytes + j;
                        anyhow::ensure!(byte == ((i * 31 + i / 251) % 256) as u8,
                            "native response body mismatch at {}", i);
                    }
                    self.probe_bytes += take as usize;
                }
''' + marker)
    marker = '            self.skip = len;'
    assert begin.count(marker) == 1
    begin = begin.replace(marker, marker + '\n            self.probe_data = kind == FRAME_DATA;')
    proto.write_text(begin + '/// Reader for a peer-opened unidirectional stream' + rest)
    # Store the exact modified files and their Git originals without touching
    # the caller's index or worktree. The observer is never a timing input.
    import difflib
    patch = ''
    for file in (stream, proto):
        relative = file.relative_to(source).as_posix()
        original = subprocess.check_output(['git', '-C', str(repo), 'show', revision + ':' + relative], text=True)
        patch += ''.join(difflib.unified_diff(original.splitlines(True), file.read_text().splitlines(True),
                                            fromfile='a/' + relative, tofile='b/' + relative))
    (output / 'exposure.patch').write_text(patch)
    env = dict(os.environ, CARGO_INCREMENTAL='0', CARGO_TARGET_DIR=str(Path(os.environ.get('NATIVE_EXPOSURE_TARGET', output / 'target')).resolve()))
    command = ['cargo', 'build', '--release', '--locked', '--bin', 'shb']
    with (output / 'build.log').open('xb') as log:
        subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    binary = output / 'shb-exposure'
    shutil.copy2(Path(env['CARGO_TARGET_DIR']) / 'release/shb', binary)
    binary.chmod(0o555)
    (output / 'manifest.json').write_text(json.dumps(dict(revision=revision, timing_eligible=False,
        sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), command=command,
        patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
        compiler=subprocess.check_output(['rustc', '-Vv'], text=True)), indent=2) + '\n')
    print(binary)


if __name__ == '__main__':
    main()
