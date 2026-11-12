#!/usr/bin/env python3
"""Build a private Quinn scheduler and the existing HTTP/3 receipt peer.

No repository Cargo.toml, Cargo.lock, registry source or production source is
modified. Every input crate and Git revision is pinned; output must be new.
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
import tomllib

REVISION = '9fcad6b56c9d8b258e82fba93570ff6d2e8660b6'
QUINN_VERSION = '0.11.19'
QUINN_SHA256 = '0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe'


def replace(path, before, after):
    text = path.read_text()
    if text.count(before) != 1:
        raise ValueError(f'pinned source marker changed: {path}: {before!r}')
    path.write_text(text.replace(before, after, 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = output / 'source'
    source.mkdir()
    archive = subprocess.check_output(['git', '-C', str(here.parent), 'archive', REVISION])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(source, filter='data')
    lock = tomllib.loads((source / 'Cargo.lock').read_text())
    quinn = next(p for p in lock['package'] if p['name'] == 'quinn-proto')
    assert (quinn['version'], quinn['checksum']) == (QUINN_VERSION, QUINN_SHA256)
    subprocess.run(['cargo', 'fetch', '--locked'], cwd=source, check=True)
    cargo_home = Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo'))
    crates = list((cargo_home / 'registry/cache').glob(f'*/quinn-proto-{QUINN_VERSION}.crate'))
    crate = next(p for p in crates if hashlib.sha256(p.read_bytes()).hexdigest() == QUINN_SHA256)
    with tarfile.open(crate) as tar:
        tar.extractall(output, filter='data')
    private = output / f'quinn-proto-{QUINN_VERSION}'
    schedule = private / 'src/connection/native_schedule.rs'
    shutil.copy2(here / 'native-reordering/schedule.rs', schedule)
    buffer = private / 'src/connection/send_buffer.rs'
    replace(buffer, 'use crate::{VarInt, range_set::RangeSet};', '''use crate::{VarInt, range_set::RangeSet};
#[path = "native_schedule.rs"]
mod native_schedule;
use native_schedule::NativeSchedule;''')
    replace(buffer, '    retransmits: RangeSet,', '    retransmits: RangeSet,\n    native_schedule: Option<NativeSchedule>,')
    replace(buffer, '        self.unacked_len += data.len();', '''        let schedule = NativeSchedule::from_write(data.len(), self.offset, self.unsent);
        self.unacked_len += data.len();''')
    replace(buffer, '        self.unacked_segments.push_back(data);', '''        self.unacked_segments.push_back(data);
        if let Some(schedule) = schedule {
            assert!(self.native_schedule.is_none(), "one body per stream required");
            self.unsent = self.offset;
            self.native_schedule = Some(schedule);
        }''')
    replace(buffer, '        // Clamp the range to data which is still tracked', '''        if let Some(schedule) = &mut self.native_schedule { schedule.ack(range.clone()); }
        // Clamp the range to data which is still tracked''')
    replace(buffer, '        // Transmit new data', '''        if let Some(schedule) = &mut self.native_schedule {
            if let Some(range) = schedule.poll(max_len) {
                return (range, true);
            }
        }
        // Transmit new data''')
    replace(buffer, '        self.unsent != self.offset || !self.retransmits.is_empty()', '''        self.unsent != self.offset || !self.retransmits.is_empty()
            || self.native_schedule.as_ref().is_some_and(|s| s.has_pending())''')
    state = private / 'src/connection/streams/state.rs'
    replace(state, '        let finished = stream.ack(frame);', '''        let was_pending = stream.is_pending();
        let finished = stream.ack(frame);
        if !was_pending && stream.is_pending() {
            self.pending.push_pending(id, stream.priority);
        }''')
    # Keep the existing independent HTTP/3 server/request validation/receipt
    # lifecycle. Only add end-of-connection UDP/recovery evidence.
    peer = source / 'benchmarks/h3-response-flight-peer.rs'
    replace(peer, '    ensure!(errors.is_empty(), "{}", errors.join("; "));', '''    let stats = conn.stats();
    eprintln!("NATIVE_TRANSPORT {}", serde_json::json!({
        "sent_datagrams": stats.udp_tx.datagrams, "sent_bytes": stats.udp_tx.bytes,
        "received_datagrams": stats.udp_rx.datagrams, "received_bytes": stats.udp_rx.bytes,
        "lost_packets": stats.path.lost_packets,
        "congestion_events": stats.path.congestion_events,
    }));
    ensure!(errors.is_empty(), "{}", errors.join("; "));''')
    replace(peer, '    transport.max_concurrent_bidi_streams(1024u32.into());', '''    transport.max_concurrent_bidi_streams(1024u32.into());
    // Fix packet capacity and remove unrelated PMTU probes from loss controls.
    transport.mtu_discovery_config(None);''')
    manifest = source / 'Cargo.toml'
    manifest.write_text(manifest.read_text() + '\n[patch.crates-io]\nquinn-proto = { path = ' + json.dumps(str(private)) + ' }\n')
    # The only permissible lock change is replacing this one registry source
    # by the identical-version private path. All other packages stay locked.
    subprocess.run(['cargo', 'update', '--offline', '-p', 'quinn-proto'], cwd=source, check=True)
    changed_lock = tomllib.loads((source / 'Cargo.lock').read_text())
    stripped = lambda packages: [p for p in packages if p['name'] != 'quinn-proto']
    assert stripped(lock['package']) == stripped(changed_lock['package']), 'unrelated lock update'
    assert next(p for p in changed_lock['package'] if p['name'] == 'quinn-proto')['version'] == QUINN_VERSION
    wrapper = output / 'schedule-tests.rs'
    wrapper.write_text('#[allow(dead_code)]\n#[path = ' + json.dumps(str(schedule)) + '] mod schedule;\n')
    env = dict(os.environ, CARGO_INCREMENTAL='0',
               CARGO_TARGET_DIR=str(Path(os.environ.get('NATIVE_REORDER_TARGET', output / 'target')).resolve()))
    commands = [
        ['rustfmt', '--edition=2021', '--check', str(schedule)],
        ['clippy-driver', '--edition=2021', '--test', '-D', 'warnings', str(wrapper), '-o', str(output / 'schedule-clippy')],
        ['rustc', '--edition=2021', '--test', str(wrapper), '-o', str(output / 'schedule-tests')],
        [str(output / 'schedule-tests')],
        ['rustc', '--edition=2021', '--test', '-O', str(wrapper), '-o', str(output / 'schedule-tests-release')],
        [str(output / 'schedule-tests-release')],
        ['cargo', 'clippy', '--locked', '--example', 'h3-response-flight-peer', '--', '-D', 'warnings'],
        ['cargo', 'build', '--release', '--locked', '--example', 'h3-response-flight-peer'],
    ]
    for index, command in enumerate(commands):
        with (output / f'build-{index}.log').open('xb') as log:
            subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    binary = output / 'native-reordering-peer'
    shutil.copy2(Path(env['CARGO_TARGET_DIR']) / 'release/examples/h3-response-flight-peer', binary)
    binary.chmod(0o555)
    paths = [buffer, state, schedule, peer, manifest, source / 'Cargo.lock', wrapper]
    (output / 'manifest.json').write_text(json.dumps(dict(
        revision=REVISION, quinn_version=QUINN_VERSION, quinn_crate_sha256=QUINN_SHA256,
        sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), commands=commands,
        compiler=subprocess.check_output(['rustc', '-Vv'], text=True),
        input_sha256={str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
        builder_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    ), indent=2) + '\n')
    print(binary)


if __name__ == '__main__':
    main()
