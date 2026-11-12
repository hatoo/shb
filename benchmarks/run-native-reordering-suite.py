#!/usr/bin/env python3
"""Bounded live correctness suite, with retained evidence on any failure."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer', type=Path, required=True)
    parser.add_argument('--shb', type=Path, required=True)
    parser.add_argument('--exposure', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--namespace', choices=('user', 'sudo'), default='user')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    inputs = {k: dict(path=str(p.resolve()), sha256=hashlib.sha256(p.read_bytes()).hexdigest())
              for k, p in vars(args).items() if k in ('peer', 'shb', 'exposure')}
    (args.output / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    rows = []
    cases = [(reader, mode, 'none', 3)
             for mode in ('ordered', 'reverse', 'mixed', 'duplicates')
             for reader in ('aioquic', 'shb', 'exposure')]
    cases += [('aioquic', 'reverse', fault, 1)
              for fault in ('drop-once', 'missing-prefix', 'missing-fin', 'corrupt')]
    for reader, mode, fault, count in cases:
        name = f'{reader}-{mode}-{fault}'
        command = [sys.executable, str(here / 'check-native-reordering.py'),
                   '--peer', str(args.peer.resolve()), '--output', str((args.output / name).resolve()),
                   '--namespace', args.namespace, '--mode', mode, '--fault', fault, '--requests', str(count)]
        if reader in ('shb', 'exposure'):
            command += ['--shb', str((args.shb if reader == 'shb' else args.exposure).resolve())]
        if reader == 'exposure':
            command += ['--exposure']
        row = dict(case=name, command=command)
        try:
            with (args.output / (name + '.log')).open('xb') as log:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=60)
            row['exit'] = result.returncode
        except subprocess.TimeoutExpired:
            row.update(exit=None, error='controller deadline')
        rows.append(row)
        (args.output / 'suite.json').write_text(json.dumps(rows, indent=2) + '\n')
        print(json.dumps(dict(case=name, exit=row['exit'])), flush=True)
        # Preserve and stop on a genuine failure. Never retry until its cause
        # and the changed hypothesis/method are recorded.
        if row['exit'] != 0:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
