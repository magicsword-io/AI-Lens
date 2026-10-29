#!/usr/bin/env python3
"""Run the pinned Copilot/Agent Lens native harness in a loopback-only namespace.

Linux requires unshare/CAP_SYS_ADMIN (or a runner configured to permit unshare).
No credentials, user HOME replacement, provider account, build or install occurs.
All unrecognized arguments are forwarded to copilot_native_smoke.mjs, including
--binary, --cli, --sdk, --report and the deliberately failing --disable-policy.
Example: python3 scripts/copilot_native_offline.py --report .context/native.json
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def fail(check):
    print(json.dumps({'status': 'FAIL', 'failed_check': check}))
    return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument('--inside-network-namespace', action='store_true')
    options, forwarded = parser.parse_known_args()
    if sys.platform != 'linux':
        return fail('Linux network namespaces required')
    # Preserve only tool discovery. Resolve explicit binary override before dropping env.
    env = {'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}
    if 'AGENT_LENS_BIN' in os.environ and '--binary' not in forwarded and not any(
            arg.startswith('--binary=') for arg in forwarded):
        forwarded += ['--binary', str(Path(os.environ['AGENT_LENS_BIN']).resolve())]
    # Forward path options relative to the caller, not the repository cwd.
    for index, value in enumerate(forwarded):
        for option in ('--binary', '--cli', '--sdk', '--report'):
            if value == option and index + 1 < len(forwarded):
                forwarded[index + 1] = str(Path(forwarded[index + 1]).resolve())
            elif value.startswith(option + '='):
                forwarded[index] = option + '=' + str(Path(value.split('=', 1)[1]).resolve())
    if options.inside_network_namespace:
        import fcntl
        import socket
        import struct
        interfaces = {line.split(':')[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]}
        if interfaces != {'lo'}:
            return fail('network namespace has non-loopback interfaces')
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
                fcntl.ioctl(control, 0x8914, struct.pack('16sh', b'lo', 0x9))
        except OSError:
            return fail('cannot enable isolated loopback')
        node = shutil.which('node', path=env['PATH'])
        if node is None:
            return fail('node executable missing')
        os.execve(node, [node, str(ROOT / 'scripts/copilot_native_smoke.mjs'), *forwarded], env)
    unshare = shutil.which('unshare', path=env['PATH'])
    if unshare is None:
        return fail('unshare executable missing')
    command = [unshare, '-n', sys.executable, str(Path(__file__).resolve()),
               '--inside-network-namespace', *forwarded]
    with subprocess.Popen(command, cwd=ROOT, env=env, start_new_session=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        try:
            output, _ = process.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            return fail('native harness exceeded deadline')
        # Reap any vendor descendants even if a failed Node parent exited early.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        # Only forward the machine-readable summary; never dump native diagnostics.
        try:
            report = json.loads(output)
            if not isinstance(report, dict) or report.get('status') not in ('PASS', 'FAIL'):
                raise ValueError('invalid report')
        except (ValueError, TypeError):
            return fail('namespace or native harness startup failed')
        print(json.dumps(report, indent=2))
        return process.returncode if process.returncode >= 0 else 1


if __name__ == '__main__':
    sys.exit(main())
