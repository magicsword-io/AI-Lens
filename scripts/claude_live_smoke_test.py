#!/usr/bin/env python3
"""Offline runner/oracle regressions; these do not establish live acceptance."""
import argparse
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import claude_live_smoke as smoke


class ClaudeLiveSmokeTests(unittest.TestCase):
    def fixture(self):
        def row(event, phase, **fields):
            return dict(schema_version=1, agent='claude', hook_event=event, phase=phase,
                        decision='allow', matched_rules=[], enforcement='supported',
                        observer={'name': 'agent-lens', 'version': '0.2.0'},
                        timestamp='2026-10-29T12:00:00Z', session_id='session-1', **fields)
        rows = [row('SessionStart', 'lifecycle'),
                row('PreToolUse', 'pre', tool_name='Write', tool_use_id='tool-1'),
                row('PostToolUse', 'post', tool_name='Write', tool_use_id='tool-1'),
                row('PreToolUse', 'pre', tool_name='Write', tool_use_id='tool-2'),
                row('SessionEnd', 'lifecycle')]
        rows[3].update(decision='block', matched_rules=['protect-env-files'])
        return rows

    def test_accepts_complete_independent_observations(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'allowed.txt').write_bytes(smoke.ALLOWED)
            self.assertTrue(all(smoke.check_observations(self.fixture(), work, 0).values()))

    def test_rejects_missing_or_misattributed_native_evidence(self):
        mutations = [lambda rows: rows.pop(0), lambda rows: rows.pop(),
                     lambda rows: rows.pop(1), lambda rows: rows.pop(2), lambda rows: rows.pop(3),
                     lambda rows: rows[2].pop('tool_use_id'),
                     lambda rows: rows[3].update(tool_use_id='tool-1'),
                     lambda rows: rows[2].update(tool_use_id='wrong-tool'),
                     lambda rows: rows[3].update(decision='allow'),
                     lambda rows: rows[3].update(enforcement='observe_only'),
                     lambda rows: rows[3].update(matched_rules=[]),
                     lambda rows: rows[1].update(agent='codex'),
                     lambda rows: rows[2].update(session_id='other-session'),
                     lambda rows: rows[1].update(tool_input={'content': 'PRIVATE'}),
                     lambda rows: rows[1]['observer'].update(content='PRIVATE'),
                     lambda rows: rows.append(copy.deepcopy(rows[1])),
                     lambda rows: rows.insert(4, dict(rows[2], tool_use_id='tool-2')),
                     lambda rows: rows.reverse()]
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                (work / 'allowed.txt').write_bytes(smoke.ALLOWED)
                rows = self.fixture()
                mutation(rows)
                self.assertFalse(all(smoke.check_observations(rows, work, 0).values()))

    def test_filesystem_and_exit_oracles_are_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            self.assertFalse(all(smoke.check_observations(self.fixture(), work, 0).values()))
            (work / 'allowed.txt').write_bytes(b'ALLOWED_CONTROL')
            self.assertFalse(all(smoke.check_observations(self.fixture(), work, 0).values()))
            (work / 'allowed.txt').write_bytes(smoke.ALLOWED)
            self.assertFalse(all(smoke.check_observations(self.fixture(), work, None).values()))
            (work / '.env').write_text('SYNTHETIC_ONLY')
            self.assertFalse(all(smoke.check_observations(self.fixture(), work, 0).values()))
            (work / '.env').unlink()
            (work / '.env').symlink_to(work / 'absent')
            self.assertFalse(all(smoke.check_observations(self.fixture(), work, 0).values()))

    def test_metadata_schema_rejects_raw_and_secret_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'events'
            for text in ('broken', '{"tool_input":"PRIVATE"}', '[1,2]', 'null'):
                log.write_text(text)
                with self.subTest(text=text), self.assertRaises(smoke.common.SmokeError):
                    smoke.read_events(log)
            log.write_text('\n'.join(json.dumps(row) for row in self.fixture()))
            self.assertEqual(smoke.read_events(log), self.fixture())

    def test_environment_ignores_provider_proxy_and_other_secrets(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {
                'ANTHROPIC_BASE_URL': 'http://untrusted.invalid', 'ANTHROPIC_AUTH_TOKEN': 'PRIVATE',
                'CLAUDE_CODE_USE_BEDROCK': '1', 'HTTPS_PROXY': 'http://untrusted.invalid',
                'OPENAI_API_KEY': 'PRIVATE', 'CLAUDE_CONFIG_DIR': '/untrusted'}, clear=True):
            env = smoke.client_environment(Path(tmp), 'synthetic-key')
            self.assertEqual(env['ANTHROPIC_BASE_URL'], 'https://api.anthropic.com')
            self.assertEqual(env['ANTHROPIC_API_KEY'], 'synthetic-key')
            for key in ('ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_USE_BEDROCK', 'HTTPS_PROXY', 'OPENAI_API_KEY'):
                self.assertNotIn(key, env)
            self.assertTrue(Path(env['CLAUDE_CONFIG_DIR']).is_dir())
            self.assertEqual(env['HOME'], str(Path(tmp) / 'home'))

    def test_command_keeps_hooks_and_has_bounded_normal_permissions(self):
        args = argparse.Namespace(model='synthetic-model', max_budget_usd=0.5)
        command = smoke.client_command('claude', args, Path('/tmp/settings.json'), Path('/tmp/work'))
        for option in ('--bare', '--safe-mode', '--dangerously-skip-permissions'):
            self.assertNotIn(option, command)
        for option, value in (('--tools', 'Write'), ('--allowedTools', 'Write'),
                              ('--setting-sources', ''), ('--max-turns', '4'),
                              ('--max-budget-usd', '0.5'), ('--permission-mode', 'manual')):
            self.assertEqual(command[command.index(option) + 1], value)
        self.assertIn('--strict-mcp-config', command)
        self.assertIn('--no-session-persistence', command)

    def test_operational_error_cannot_leave_stale_pass_or_sensitive_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            binary = base / 'agent-lens'
            binary.write_text('binary')
            library = base / ('libagent_lens_engine.dylib' if smoke.platform.system() == 'Darwin' else 'libagent_lens_engine.so')
            library.write_text('library')
            report = base / 'result.json'
            report.write_text('{"result":"PASS"}')
            argv = ['claude_live_smoke.py', '--binary', str(binary), '--model', 'synthetic-model', '--report', str(report)]
            with mock.patch.object(sys, 'argv', argv), mock.patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'synthetic-key'}), mock.patch('claude_live_smoke.shutil.which', return_value=str(binary)), mock.patch('claude_live_smoke.execute', side_effect=OSError('PRIVATE')), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(smoke.main(), 1)
            self.assertEqual(json.loads(report.read_text())['result'], 'FAIL')
            self.assertNotIn('PRIVATE', report.read_text())
            self.assertEqual(report.with_suffix('.events.jsonl').read_text(), '')

    def test_preflight_failures_invalidate_previous_pass_before_exiting(self):
        cases = ('missing-credential', 'missing-binary', 'missing-client', 'missing-library',
                 'invalid-budget', 'invalid-model', 'invalid-timeout')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                binary = base / 'agent-lens'
                binary.write_text('binary')
                library = base / ('libagent_lens_engine.dylib' if smoke.platform.system() == 'Darwin' else 'libagent_lens_engine.so')
                library.write_text('library')
                report = base / 'result.json'
                report.write_text('{"result":"PASS"}')
                events = report.with_suffix('.events.jsonl')
                events.write_text('OLD_EVENTS')
                argv = ['claude_live_smoke.py', '--binary', str(binary), '--model',
                        'PRIVATE MODEL' if case == 'invalid-model' else 'synthetic-model',
                        '--report', str(report)]
                if case == 'invalid-budget':
                    argv += ['--max-budget-usd', '3']
                if case == 'invalid-timeout':
                    argv += ['--timeout', '0']
                if case == 'missing-binary':
                    binary.unlink()
                if case == 'missing-library':
                    library.unlink()
                env = {} if case == 'missing-credential' else {'ANTHROPIC_API_KEY': 'synthetic-key'}
                client = None if case == 'missing-client' else str(binary)
                with mock.patch.object(sys, 'argv', argv), mock.patch.dict(os.environ, env, clear=True), mock.patch('claude_live_smoke.shutil.which', return_value=client), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as caught:
                        smoke.main()
                self.assertEqual(caught.exception.code, 2)
                saved = json.loads(report.read_text())
                self.assertEqual(saved['result'], 'FAIL')
                self.assertEqual(saved['failure_reasons'], ['preflight_not_completed'])
                self.assertNotIn('PRIVATE MODEL', report.read_text())
                self.assertEqual(events.read_text(), '')

    def test_client_failure_stops_lens_and_removes_isolated_state(self):
        commands = []
        def run(command, **kwargs):
            commands.append(command)
            response = ('2.1.312 (Claude Code)\n' if command[-1] == '--version' else
                        json.dumps({'hooks': {'PreToolUse': []}}) if command[-3:] == ['config', '--agent', 'claude'] else
                        json.dumps({'enabled': command[-1] != 'stop'}))
            return subprocess.CompletedProcess(command, 0, stdout=response)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            summary = {'cleanup': {}}
            args = argparse.Namespace(disable_policy=False, model='synthetic-model',
                                      max_budget_usd=0.5, timeout=10)
            with mock.patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'synthetic-key'}), mock.patch('claude_live_smoke.subprocess.run', side_effect=run), mock.patch('claude_live_smoke.common.run_client', side_effect=OSError('PRIVATE')):
                with self.assertRaises(OSError):
                    smoke.execute(args, 'claude', base / 'lens', base / 'report.json', summary, [])
            self.assertTrue(summary['cleanup']['host_stopped'])
            self.assertTrue(summary['cleanup']['temporary_state_removed'])
            self.assertEqual(commands[-1][-1], 'stop')
            self.assertEqual(list(base.iterdir()), [])

    def test_real_child_timeout_is_reaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = smoke.common.run_client([sys.executable, '-c', 'import time; time.sleep(60)'], Path(tmp), {}, 0.05)
            self.assertEqual(result, (None, ''))


if __name__ == '__main__':
    unittest.main()
