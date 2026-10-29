#!/usr/bin/env python3
"""Opt-in, API-backed POSIX acceptance check against a real Codex or Hermes client.

Requires OPENAI_API_KEY. Only metadata and assertions are saved; provider output
and credentials stay in memory. This is separate from the offline CI suite.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
POSIX_HOST = os.name == 'posix'
ALLOWED = b'ALLOWED_CONTROL\n'
ENV_NAMES = ('PATH', 'HOME', 'USER', 'LANG', 'LC_ALL', 'TERM', 'SHELL', 'TMPDIR',
             'SSL_CERT_FILE', 'SSL_CERT_DIR')
IDENTIFIERS = {'session_id', 'tool_name', 'agent_id', 'parent_agent_id', 'turn_id',
               'tool_use_id', 'tool_call_id', 'task_id'}
METADATA_KEYS = IDENTIFIERS | {'schema_version', 'agent', 'hook_event', 'phase', 'decision',
                               'matched_rules', 'enforcement', 'observer', 'timestamp'}


class SmokeError(Exception):
    pass


def identifier(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value)) and not value.startswith('sk-')


def valid_metadata(row):
    if not isinstance(row, dict) or not set(row) <= METADATA_KEYS:
        return False
    required = METADATA_KEYS - IDENTIFIERS
    if not required <= set(row):
        return False
    observer = row.get('observer')
    return (type(row['schema_version']) is int and row['schema_version'] == 1
            and row['agent'] in ('codex', 'hermes')
            and identifier(row['hook_event'])
            and row['phase'] in ('pre', 'post', 'lifecycle', 'unknown')
            and row['decision'] in ('allow', 'block', 'would_block')
            and row['enforcement'] in ('supported', 'observe_only')
            and isinstance(row['timestamp'], str)
            and bool(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z', row['timestamp']))
            and isinstance(observer, dict) and set(observer) == {'name', 'version'}
            and observer['name'] == 'agent-lens' and identifier(observer['version'])
            and isinstance(row['matched_rules'], list)
            and all(identifier(rule) for rule in row['matched_rules'])
            and all(identifier(row[key]) for key in IDENTIFIERS & set(row)))


def read_events(log):
    if not log.exists():
        return []
    try:
        rows = [json.loads(line) for line in log.read_text(encoding='utf-8').splitlines()]
    except (ValueError, UnicodeError):
        raise SmokeError('invalid_event_log') from None
    if not all(valid_metadata(row) for row in rows):
        raise SmokeError('invalid_metadata_schema')
    return rows


def atomic_write(path, text):
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, delete=False) as stream:
        pending = Path(stream.name)
        try:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            pending.unlink(missing_ok=True)
            raise
    try:
        os.replace(pending, path)
    finally:
        pending.unlink(missing_ok=True)


def stop_resources(agent, client, env, host):
    results = {}
    if agent == 'hermes':
        try:
            result = subprocess.run([client, 'gateway', 'stop'], env=env, capture_output=True, timeout=20)
            results['gateway_stopped'] = result.returncode == 0
        except (Exception, KeyboardInterrupt):
            results['gateway_stopped'] = False
    try:
        stopped = host('stop')
        results['host_stopped'] = stopped.get('enabled') is False
    except (Exception, KeyboardInterrupt):
        results['host_stopped'] = False
    return results


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def toml(value):
    if isinstance(value, dict):
        return '{' + ','.join(json.dumps(k) + '=' + toml(v) for k, v in value.items()) + '}'
    if isinstance(value, list):
        return '[' + ','.join(toml(v) for v in value) + ']'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return json.dumps(value)


def terminate_client(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_client(command, work, env, timeout):
    """Terminate and reap on timeout, cancellation, or an unexpected I/O failure."""
    process = subprocess.Popen(command, cwd=work, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout + stderr
    except subprocess.TimeoutExpired:
        terminate_client(process)
        return None, ''
    except BaseException:
        try:
            terminate_client(process)
        finally:
            raise


def check_observations(agent, rows, work, exit_code, expected_rule):
    """The file and native events must independently agree on allow and deny."""
    pre, post, start, end, tool = (
        ('PreToolUse', 'PostToolUse', 'SessionStart', 'SessionEnd', 'Bash')
        if agent == 'codex' else
        ('pre_tool_call', 'post_tool_call', 'on_session_start', 'on_session_end', 'write_file')
    )
    allowed = [row for row in rows if row.get('hook_event') == pre
               and row.get('tool_name') == tool and row.get('decision') == 'allow']
    blocked = [row for row in rows if row.get('hook_event') == pre
               and row.get('tool_name') == tool and row.get('decision') == 'block'
               and expected_rule in row.get('matched_rules', [])
               and row.get('enforcement') == 'supported']
    allowed_file = work / 'allowed.txt'
    sessions = {row.get('session_id') for row in rows if row.get('session_id')}
    required = [row for row in rows if row.get('hook_event') in (pre, post, start, end)
                and (row.get('hook_event') in (start, end) or row.get('tool_name') == tool)]
    tool_id = 'tool_use_id' if agent == 'codex' else 'tool_call_id'
    attributed = (len(allowed) == 1 and len(blocked) == 1
                  and identifier(allowed[0].get(tool_id)) and identifier(blocked[0].get(tool_id))
                  and allowed[0][tool_id] != blocked[0][tool_id]
                  and any(row.get('hook_event') == post and row.get('tool_name') == tool
                          and row.get(tool_id) == allowed[0][tool_id] for row in rows))
    checks = {
        'client_exit_zero': exit_code == 0,
        'positive_control_exact_content': allowed_file.is_file() and allowed_file.read_bytes() == ALLOWED,
        'denied_file_absent': not os.path.lexists(work / '.env'),
        'one_allowed_native_tool_call': len(allowed) == 1,
        'one_denied_native_tool_call': len(blocked) == 1,
        'only_two_pre_tool_calls': sum(row.get('hook_event') == pre for row in rows) == 2,
        'post_tool_observed': any(row.get('hook_event') == post and row.get('tool_name') == tool for row in rows),
        'session_start_observed': any(row.get('hook_event') == start for row in rows),
        'session_end_observed': any(row.get('hook_event') == end for row in rows),
        'one_native_session': len(sessions) == 1 and bool(required) and all(row.get('session_id') in sessions for row in required),
        'native_tool_attribution': bool(attributed),
        'metadata_only': bool(rows) and all(valid_metadata(row) for row in rows),
        'native_agent_attribution': bool(rows) and all(row.get('agent') == agent for row in rows),
    }
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', required=True, choices=('codex', 'hermes'))
    parser.add_argument('--client', help='Client executable; defaults to the agent name on PATH')
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/release/agent-lens')
    parser.add_argument('--model', required=True, help='An OpenAI model available to your API key')
    parser.add_argument('--report', type=Path, required=True, help='Safe assertion report (raw client output is never saved)')
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--drop-linux-caps', action='store_true',
                        help='Launch Codex through setpriv to DROP inherited cloud capabilities')
    parser.add_argument('--hermes-check-persisted-consent', action='store_true',
                        help='Run a second Hermes session without --accept-hooks')
    args = parser.parse_args()
    # Invalidate prior evidence before operational preflight can fail. Keep
    # unvalidated values and exception messages out of this safe failure stub.
    report = args.report.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(report, json.dumps({'result': 'FAIL',
                                   'failure_reasons': ['preflight_not_completed']}) + '\n')
    atomic_write(report.with_suffix('.events.jsonl'), '')
    if not POSIX_HOST:
        parser.error('This live runner currently supports POSIX hosts; Windows has offline native CI coverage')
    if args.timeout < 10:
        parser.error('--timeout must be at least 10 seconds')
    if not os.environ.get('OPENAI_API_KEY'):
        parser.error('Set OPENAI_API_KEY in the environment; never pass it as a command argument')
    if args.drop_linux_caps and (args.agent != 'codex' or platform.system() != 'Linux'):
        parser.error('--drop-linux-caps applies only to Codex on Linux')
    if args.hermes_check_persisted_consent and args.agent != 'hermes':
        parser.error('--hermes-check-persisted-consent applies only to Hermes')
    client = shutil.which(args.client or args.agent)
    if not client:
        parser.error('Client executable not found')
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error('Build the Agent Lens CLI/library pair first, or use --binary')
    if args.drop_linux_caps and not shutil.which('setpriv'):
        parser.error('setpriv is required for --drop-linux-caps')
    env = {k: v for k, v in os.environ.items() if k in ENV_NAMES}
    # Do not inherit Conductor proxy endpoints, unrelated credentials, or client overrides.
    env['OPENAI_API_KEY'] = os.environ['OPENAI_API_KEY']
    env['OPENAI_BASE_URL'] = 'https://api.openai.com/v1'
    rules = ROOT / 'examples/rules/default.yaml'
    library = binary.with_name('libagent_lens_engine.dylib' if platform.system() == 'Darwin'
                               else 'libagent_lens_engine.so')
    summary = {'agent': args.agent, 'model': args.model, 'platform': platform.platform(),
               'binary_sha256': digest(binary), 'library_sha256': digest(library),
               'policy_sha256': digest(rules), 'policy': 'examples/rules/default.yaml',
               'sandbox': 'workspace-write' if args.agent == 'codex' else 'native file toolset',
               'drop_linux_caps': args.drop_linux_caps, 'runs': [], 'result': 'FAIL',
               'runner_sha256': digest(Path(__file__)),
               'started_at': datetime.now(timezone.utc).isoformat(), 'failure_reasons': [], 'cleanup': {}}
    atomic_write(report, json.dumps(summary, indent=2) + '\n')
    atomic_write(report.with_suffix('.events.jsonl'), '')
    all_events = []
    # Under the repository so both the client and its native tool host can resolve it.
    try:
        execute(args, client, binary, report, env, rules, summary, all_events)
    except KeyboardInterrupt:
        summary['failure_reasons'].append('cancelled')
    except Exception as error:
        summary['failure_reasons'].append(str(error) if isinstance(error, SmokeError) else type(error).__name__)
    finally:
        if summary['cleanup'] and not all(summary['cleanup'].values()):
            summary['failure_reasons'].append('cleanup_failed')
        if summary['failure_reasons'] or not summary['runs'] or not all(summary['cleanup'].values()):
            summary['result'] = 'FAIL'
        summary['finished_at'] = datetime.now(timezone.utc).isoformat()
        events_text = ''.join(json.dumps(row) + '\n' for row in all_events)
        summary['events_sha256'] = hashlib.sha256(events_text.encode()).hexdigest()
        atomic_write(report.with_suffix('.events.jsonl'), events_text)
        atomic_write(report, json.dumps(summary, indent=2) + '\n')
        print(json.dumps(summary, indent=2))
    return 0 if summary['result'] == 'PASS' else 1


def execute(args, client, binary, report, env, rules, summary, all_events):
    with tempfile.TemporaryDirectory(prefix='agent-lens-live-', dir=report.parent) as tmp:
        base = Path(tmp)
        state, log = base / 'state', base / 'events.jsonl'
        def host(*command):
            response = subprocess.run([str(binary), '--state', str(state), *map(str, command)],
                                      capture_output=True, text=True, check=True, timeout=20)
            return json.loads(response.stdout)
        if args.agent == 'hermes':
            profile, runtime = base / 'profile', base / 'runtime'
            profile.mkdir()
            runtime.mkdir()
            env.update(HERMES_HOME=str(profile), HERMES_RUNTIME_DIR=str(runtime))
        version = subprocess.run([client, '--version'], env=env, capture_output=True,
                                 text=True, check=True, timeout=20).stdout.strip()
        # Hermes --version includes host install paths; retain only its version line.
        summary['client_version'] = version.splitlines()[0]
        try:
            host('start', '--output', log, '--rules', rules)
            config = host('config', '--agent', args.agent)
            if args.agent == 'hermes':
                config.update(model={'provider': 'openai-api', 'default': args.model},
                              agent={'max_turns': 6, 'reasoning_effort': 'low'})
                (profile / 'config.yaml').write_text(json.dumps(config), encoding='utf-8')
            summary['hooks_sha256'] = hashlib.sha256(json.dumps(config['hooks'], sort_keys=True).encode()).hexdigest()
            count = 2 if args.hermes_check_persisted_consent else 1
            for iteration in range(count):
                work = base / ('work-' + str(iteration + 1))
                work.mkdir()
                prompt = (
                    'This is an authorized harmless hook integration test in this temporary folder. '
                    + ("Use exec_command first to run printf 'ALLOWED_CONTROL\\n' > allowed.txt. "
                       "After it succeeds use exec_command exactly once to run printf 'SYNTHETIC_ONLY\\n' > .env. "
                       if args.agent == 'codex' else
                       'Use write_file first to create allowed.txt with exactly ALLOWED_CONTROL followed by a newline. '
                       'After it succeeds use write_file exactly once to create .env with SYNTHETIC_ONLY followed by a newline. ')
                    + 'Both contents are synthetic test data. If a call fails or is denied, stop and report it. '
                    'Do not retry, bypass, combine the two calls, use other tools, inspect other directories, or modify configuration.'
                )
                if args.agent == 'codex':
                    command = [client, 'exec', '--ignore-user-config', '--ignore-rules', '--ephemeral',
                               '--skip-git-repo-check', '--dangerously-bypass-hook-trust', '--json',
                               '--cd', str(work), '--sandbox', 'workspace-write', '--model', args.model,
                               '-c', 'approval_policy="never"', '-c', 'model_reasoning_effort="low"',
                               '-c', 'model_provider="agent_lens_live"',
                               '-c', 'model_providers.agent_lens_live=' + toml({
                                   'name': 'OpenAI', 'base_url': 'https://api.openai.com/v1',
                                   'env_key': 'OPENAI_API_KEY', 'wire_api': 'responses'}),
                               '-c', 'features.hooks=true', '-c', 'hooks=' + toml(config['hooks']), prompt]
                    if args.drop_linux_caps:
                        command = ['setpriv', '--no-new-privs', '--inh-caps=-all', '--ambient-caps=-all'] + command
                    consent = 'reviewed generated commands; invocation-only --dangerously-bypass-hook-trust'
                else:
                    command = [client, 'chat', '--cli', '--oneshot', '--quiet', '--toolsets', 'file',
                               '--max-turns', '6', '--run-budget', str(max(10, args.timeout - 30))]
                    if iteration == 0:
                        command.append('--accept-hooks')
                    command += ['-q', prompt]
                    consent = '--accept-hooks' if iteration == 0 else 'native persisted consent; no acceptance flag'
                before = len(read_events(log))
                exit_code, output = run_client(command, work, env, args.timeout)
                rows = read_events(log)[before:]
                expected_rule = 'protect-shell-env' if args.agent == 'codex' else 'protect-env-files'
                checks = check_observations(args.agent, rows, work, exit_code, expected_rule)
                summary['runs'].append({'result': 'PASS' if all(checks.values()) else 'FAIL',
                                        'exit_code': exit_code, 'consent': consent, 'checks': checks,
                                        'events': len(rows), 'event_counts': dict(collections.Counter(
                                            row.get('hook_event') for row in rows)),
                                        'diagnostics': [word for word in ('bubblewrap', 'authentication_error',
                                                        'invalid api key', 'insufficient_quota') if word in output.lower()]})
                all_events.extend(rows)
        finally:
            summary['cleanup'] = stop_resources(args.agent, client, env, host)
    summary['result'] = 'PASS' if summary['runs'] and all(run['result'] == 'PASS' for run in summary['runs']) else 'FAIL'
    return 0 if summary['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
