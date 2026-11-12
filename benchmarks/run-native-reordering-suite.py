#!/usr/bin/env python3
"""Bounded live correctness suite, with retained evidence on any failure."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from native_reordering import suite_cases, suite_coverage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer', type=Path, required=True)
    parser.add_argument('--shb', type=Path, required=True)
    parser.add_argument('--exposure', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--namespace', choices=('user', 'sudo'), default='user')
    parser.add_argument('--matrix', choices=('large', 'small'), default='large',
                        help='small: 128/64, 4096/256 and 16384/256 byte/chunk guards')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    inputs = {k: dict(path=str(p.resolve()), sha256=hashlib.sha256(p.read_bytes()).hexdigest())
              for k, p in vars(args).items() if k in ('peer', 'shb', 'exposure')}
    (args.output / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    rows = []
    cases = suite_cases(args.matrix)
    (args.output / 'plan.json').write_text(json.dumps(dict(matrix=args.matrix, cases=cases), indent=2) + '\n')
    results = []
    for case in cases:
        name, reader = case['case'], case['reader']
        command = [sys.executable, str(here / 'check-native-reordering.py'),
                   '--peer', str(args.peer.resolve()), '--output', str((args.output / name).resolve()),
                   '--namespace', args.namespace, '--mode', case['mode'], '--fault', case['fault'],
                   '--requests', str(case['requests']), '--size', str(case['body_bytes']), '--chunk', str(case['chunk'])]
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
        results.append(dict(case=name, summary=json.loads((args.output / name / 'summary.json').read_text())))
    coverage = suite_coverage(args.matrix, results)
    (args.output / 'coverage.json').write_text(json.dumps(coverage, indent=2) + '\n')


if __name__ == '__main__':
    main()
