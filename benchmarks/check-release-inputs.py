#!/usr/bin/env python3
"""Require matched production inputs before comparing two shb release binaries.

Pass the two clean CARGO_TARGET_DIR/release paths and a new JSON manifest path.
Build both with cargo build --release --locked, not cargo test: dev dependencies
can unify features differently even for the non-test binary cargo test creates.
"""
import hashlib
import json
from pathlib import Path
import sys


def inputs(release):
    fingerprints = list((release / ".fingerprint").glob("shb-*/bin-shb.json"))
    assert len(fingerprints) == 1, "Use clean, separate production target directories"
    data = json.loads(fingerprints[0].read_text())
    configuration = {name: data[name] for name in
                     ["rustc", "features", "profile", "rustflags", "config", "compile_kind"]}
    # Each direct dependency fingerprint includes its transitive dependencies.
    configuration["dependencies"] = {dep[1]: dep[3] for dep in data["deps"]}
    return dict(configuration=configuration,
                sha256=hashlib.sha256((release / "shb").read_bytes()).hexdigest(),
                release=str(release.resolve()))


def main():
    baseline, candidate, output = map(Path, sys.argv[1:])
    left, right = inputs(baseline), inputs(candidate)
    if left["configuration"] != right["configuration"]:
        print(json.dumps(dict(baseline=left, candidate=right), indent=2), file=sys.stderr)
        raise SystemExit("Mismatched build inputs: do not compare these binaries")
    with output.open("x") as file:
        json.dump(dict(baseline=left, candidate=right), file, indent=2)
    print("Production compiler, profile, flags, features and dependency fingerprints match")


if __name__ == "__main__":
    main()
