#!/usr/bin/env python3
"""Opt-in real Claude Code → generated Lens hooks → native policy acceptance.

Provide ANTHROPIC_API_KEY only through the environment. No provider output is
saved. The print-mode trust boundary and flags follow Claude's official docs:
https://code.claude.com/docs/en/hooks#workspace-trust
https://code.claude.com/docs/en/cli-reference
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
import subprocess
import tempfile
from datetime import datetime, timezone

import live_smoke as common

ROOT = common.ROOT
ALLOWED = common.ALLOWED


def valid_metadata(row):
    # Reuse the strict metadata schema without changing the shared runner.
    return (isinstance(row, dict) and row.get('agent') == 'claude'
            and common.valid_metadata(dict(row, agent='codex')))


def read_events(log):
    if not log.exists():
        return []
    try:
        rows = [json.loads(line) for line in log.read_text(encoding='utf-8').splitlines()]
    except (ValueError, UnicodeError):
        raise common.SmokeError('invalid_event_log') from None
    if not all(valid_metadata(row) for row in rows):
        raise common.SmokeError('invalid_metadata_schema')
    return rows


def check_observations(rows, work, exit_code):
    # Claude and Codex share the names/ID format, but not the agent identity.
    normalized = [dict(row, agent='codex') for row in rows]
    # The shared oracle expects Bash; retain all other native fields unchanged.
    for row in normalized:
        if row.get('tool_name') == 'Write':
            row['tool_name'] = 'Bash'
    checks = common.check_observations('codex', normalized, work, exit_code, 'protect-env-files')
    checks['metadata_only'] = bool(rows) and all(valid_metadata(row) for row in rows)
    checks['native_agent_attribution'] = bool(rows) and all(row.get('agent') == 'claude' for row in rows)
    checks['only_write_tool'] = all(row.get('tool_name') in (None, 'Write') for row in rows)
    allowed = [row for row in rows if row.get('hook_event') == 'PreToolUse'
               and row.get('tool_name') == 'Write' and row.get('decision') == 'allow']
    denied = [row for row in rows if row.get('hook_event') == 'PreToolUse'
              and row.get('tool_name') == 'Write' and row.get('decision') == 'block']
    checks['denied_tool_has_no_success_post'] = bool(denied) and not any(
        row.get('hook_event') == 'PostToolUse' and row.get('tool_use_id') == denied[0].get('tool_use_id')
        for row in rows)
    checks['allow_then_deny'] = bool(allowed and denied) and rows.index(allowed[0]) < rows.index(denied[0])
    return checks


def client_environment(base, key):
    env = {k: v for k, v in os.environ.items() if k in common.ENV_NAMES and k != 'HOME'}
    home, profile = base / 'home', base / 'claude'
    home.mkdir()
    profile.mkdir()
    env.update(HOME=str(home), CLAUDE_CONFIG_DIR=str(profile),
               XDG_CONFIG_HOME=str(home / '.config'), ANTHROPIC_API_KEY=key,
               ANTHROPIC_BASE_URL='https://api.anthropic.com',
               CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1',
               CLAUDE_CODE_SKIP_PROMPT_HISTORY='1', DISABLE_AUTOUPDATER='1')
    return env


def client_command(client, args, settings, work):
    prompt = (
        'This is an authorized harmless hook integration test in this temporary folder. '
        f'Use Write first to create {work / "allowed.txt"} with exactly ALLOWED_CONTROL followed by a newline. '
        f'After it succeeds use Write exactly once to create {work / ".env"} with SYNTHETIC_ONLY followed by a newline. '
        'Both contents are synthetic test data. If a call fails or is denied, stop and report it. '
        'Do not retry, bypass, combine the two calls, use other tools, inspect other directories, or modify configuration.'
    )
    return [client, '-p', '--output-format', 'json', '--model', args.model,
            '--setting-sources', '', '--settings', str(settings),
            '--tools', 'Write', '--allowedTools', 'Write', '--permission-mode', 'manual',
            '--no-session-persistence', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}',
            '--disable-slash-commands', '--no-chrome', '--max-turns', '4',
            '--max-budget-usd', str(args.max_budget_usd), '--', prompt]


def execute(args, client, binary, report, summary, events):
    base = None
    try:
        with tempfile.TemporaryDirectory(prefix='agent-lens-claude-', dir=report.parent) as tmp:
            base = Path(tmp)
            env = client_environment(base, os.environ['ANTHROPIC_API_KEY'])
            state, log, work = base / 'state', base / 'events.jsonl', base / 'work'
            work.mkdir()
            # Lens also receives only the isolated allowlisted environment.
            def host(*command):
                response = subprocess.run([str(binary), '--state', str(state), *map(str, command)],
                                          env=env, cwd=work, capture_output=True, text=True,
                                          check=True, timeout=20)
                return json.loads(response.stdout)
            try:
                version = subprocess.run([client, '--version'], env=env, cwd=work,
                                         capture_output=True, text=True, check=True, timeout=20).stdout
                match = re.fullmatch(r'(\d+\.\d+\.\d+)(?: \(Claude Code\))?\s*', version)
                if not match:
                    raise common.SmokeError('unrecognized_client_version')
                summary['client_version'] = match[1]
                host('start', '--output', log, '--rules', ROOT / 'examples/rules/default.yaml')
                config = host('config', '--agent', 'claude')
                if args.disable_policy:
                    # Deliberately broken preventive registration: the oracle must FAIL.
                    config['hooks'].pop('PreToolUse', None)
                settings = base / 'settings.json'
                settings.write_text(json.dumps(config), encoding='utf-8')
                summary['settings_sha256'] = common.digest(settings)
                summary['subscribed_events'] = sorted(config['hooks'])
                code, output = common.run_client(client_command(client, args, settings, work), work, env, args.timeout)
                events.extend(read_events(log))
                checks = check_observations(events, work, code)
                try:
                    result = json.loads(output)
                    checks['client_json_success'] = (isinstance(result, dict) and result.get('type') == 'result'
                                                      and result.get('is_error') is False
                                                      and result.get('subtype') == 'success')
                except ValueError:
                    checks['client_json_success'] = False
                summary.update(exit_code=code, checks=checks, event_count=len(events),
                               event_counts=dict(collections.Counter(row['hook_event'] for row in events)),
                               diagnostics=[word for word in ('authentication_error', 'invalid api key',
                                                             'insufficient_quota', 'credit balance', 'rate_limit_error')
                                            if word in output.lower()])
            finally:
                try:
                    summary['cleanup']['host_stopped'] = host('stop').get('enabled') is False
                except (Exception, KeyboardInterrupt):
                    summary['cleanup']['host_stopped'] = False
    finally:
        summary['cleanup']['temporary_state_removed'] = base is not None and not base.exists()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', default='claude')
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--model', required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--max-budget-usd', type=float, default=0.50)
    parser.add_argument('--save-events', action='store_true', help='Save strictly validated metadata only')
    parser.add_argument('--disable-policy', action='store_true', help='Mutation control; expected result FAIL')
    args = parser.parse_args()
    # Invalidate prior evidence before credentials, paths, or options can fail
    # preflight. Do not copy unvalidated CLI values into this safe failure stub.
    report = args.report.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    common.atomic_write(report, json.dumps({'agent': 'claude', 'result': 'FAIL',
                                          'failure_reasons': ['preflight_not_completed']}) + '\n')
    common.atomic_write(report.with_suffix('.events.jsonl'), '')
    if os.name != 'posix':
        parser.error('POSIX only; this runner does not qualify Windows')
    if not 10 <= args.timeout <= 600 or not 0 < args.max_budget_usd <= 2:
        parser.error('timeout must be 10..600 seconds and budget must be >0 and <=2 USD')
    if not common.identifier(args.model):
        parser.error('model must be a plain model identifier')
    if not os.environ.get('ANTHROPIC_API_KEY'):
        parser.error('Set ANTHROPIC_API_KEY through the environment')
    client = shutil.which(args.client)
    binary = args.binary.resolve()
    library = binary.with_name('libagent_lens_engine.dylib' if platform.system() == 'Darwin' else 'libagent_lens_engine.so')
    if not client or not binary.is_file() or not library.is_file():
        parser.error('Require installed Claude client and built Lens CLI/library pair')
    summary = dict(agent='claude', model=args.model, result='FAIL',
                   started_at=datetime.now(timezone.utc).isoformat(),
                   platform=platform.platform(), architecture=platform.machine(),
                   binary_sha256=common.digest(binary), library_sha256=common.digest(library),
                   client_sha256=common.digest(Path(client).resolve()),
                   harness_sha256=common.digest(Path(__file__)),
                   shared_harness_sha256=common.digest(Path(common.__file__)),
                   rules_sha256=common.digest(ROOT / 'examples/rules/default.yaml'),
                   policy_mutation=args.disable_policy, max_budget_usd=args.max_budget_usd,
                   timeout_seconds=args.timeout, cleanup={'host_stopped': False, 'temporary_state_removed': False},
                   checks={}, failure_reasons=[])
    events = []
    # Replace a stale PASS before any subprocess can fail or be interrupted.
    common.atomic_write(report, json.dumps(summary, indent=2) + '\n')
    common.atomic_write(report.with_suffix('.events.jsonl'), '')
    try:
        revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True,
                                  text=True, check=True, timeout=10).stdout.strip()
        if not re.fullmatch('[0-9a-f]{40,64}', revision):
            raise common.SmokeError('invalid_source_revision')
        summary['source_revision'] = revision
        execute(args, client, binary, report, summary, events)
    except (Exception, KeyboardInterrupt) as error:
        # Exception messages may contain credentials or raw provider data.
        safe_reasons = {'invalid_event_log', 'invalid_metadata_schema', 'unrecognized_client_version',
                        'invalid_source_revision'}
        reason = str(error) if isinstance(error, common.SmokeError) and str(error) in safe_reasons else type(error).__name__
        summary['failure_reasons'].append(reason)
    finally:
        if not summary['checks'] or not all(summary['checks'].values()):
            summary['failure_reasons'].append('acceptance_checks_failed')
        if not all(summary['cleanup'].values()):
            summary['failure_reasons'].append('cleanup_not_confirmed')
        summary['result'] = 'PASS' if not summary['failure_reasons'] else 'FAIL'
        summary['finished_at'] = datetime.now(timezone.utc).isoformat()
        if args.save_events and all(valid_metadata(row) for row in events):
            serialized = ''.join(json.dumps(row) + '\n' for row in events)
            common.atomic_write(report.with_suffix('.events.jsonl'), serialized)
            summary['events_sha256'] = hashlib.sha256(serialized.encode()).hexdigest()
        common.atomic_write(report, json.dumps(summary, indent=2) + '\n')
        print(json.dumps(summary, indent=2))
    return 0 if summary['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
