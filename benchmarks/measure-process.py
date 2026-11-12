#!/usr/bin/env python3
"""Transparent process supervisor: preserve stdio and collect exact wait4 usage."""
import json
import os
from pathlib import Path
import sys
import time


def main():
    output = Path(sys.argv[1])
    command = sys.argv[2:]
    if not command or output.exists() or output.with_suffix('.pid').exists():
        raise ValueError('new resource output and a command are required')
    start = time.monotonic_ns()
    pid = os.fork()
    if pid == 0:
        try:
            os.execvp(command[0], command)
        except BaseException as error:
            print(f'exec failed: {error!r}', file=sys.stderr, flush=True)
            os._exit(127)
    output.with_suffix('.pid').write_text(str(pid) + '\n')
    _, status, usage = os.wait4(pid, 0)
    elapsed = (time.monotonic_ns() - start) / 1e9
    code = os.waitstatus_to_exitcode(status)
    with output.open('x') as stream:
        json.dump(dict(pid=pid, command=command, exit=code, elapsed_s=elapsed,
                       user_s=usage.ru_utime, system_s=usage.ru_stime,
                       max_rss_kib=usage.ru_maxrss,
                       voluntary_switches=usage.ru_nvcsw,
                       involuntary_switches=usage.ru_nivcsw), stream, indent=2)
        stream.write('\n')
    return code if code >= 0 else 128 - code


if __name__ == '__main__':
    raise SystemExit(main())
