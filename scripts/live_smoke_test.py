#!/usr/bin/env python3
"""Offline mutation tests for the live acceptance oracle; no clients or API calls."""
import copy
import contextlib
import io
import json
import os
import signal
import subprocess
import sys
from unittest import mock
from pathlib import Path
import tempfile
import unittest

import live_smoke
from live_smoke import ALLOWED, check_observations


class LiveOracleTest(unittest.TestCase):
    def fixture(self, agent):
        pre, post, start, end, tool, rule = (
            ('PreToolUse', 'PostToolUse', 'SessionStart', 'SessionEnd', 'Bash', 'protect-shell-env')
            if agent == 'codex' else
            ('pre_tool_call', 'post_tool_call', 'on_session_start', 'on_session_end', 'write_file', 'protect-env-files')
        )
        base = {'agent': agent, 'session_id': 'synthetic-session', 'decision': 'allow', 'matched_rules': [],
                'schema_version': 1, 'phase': 'pre', 'enforcement': 'observe_only',
                'timestamp': '2026-10-28T00:00:00Z', 'observer': {'name': 'agent-lens', 'version': '0.1.0'}}
        rows = [dict(base, hook_event=start), dict(base, hook_event=pre, tool_name=tool),
                dict(base, hook_event=post, tool_name=tool),
                dict(base, hook_event=pre, tool_name=tool, decision='block',
                     matched_rules=[rule], enforcement='supported'), dict(base, hook_event=end)]
        key = 'tool_use_id' if agent == 'codex' else 'tool_call_id'
        rows[1][key] = rows[2][key] = 'synthetic-allow'
        rows[3][key] = 'synthetic-deny'
        return rows, rule

    def test_positive_controls(self):
        for agent in ('codex', 'hermes'):
            with self.subTest(agent=agent), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                (work / 'allowed.txt').write_bytes(ALLOWED)
                rows, rule = self.fixture(agent)
                self.assertTrue(all(check_observations(agent, rows, work, 0, rule).values()))

    def test_absent_denied_file_alone_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows, rule = self.fixture('codex')
            checks = check_observations('codex', rows, Path(tmp), 0, rule)
            self.assertTrue(checks['denied_file_absent'])
            self.assertFalse(checks['positive_control_exact_content'])
            self.assertFalse(all(checks.values()))

    def test_corrupted_evidence_is_rejected(self):
        mutations = (
            lambda rows: rows.pop(),
            lambda rows: rows[3].update(matched_rules=['wrong-rule']),
            lambda rows: rows[3].update(decision='allow'),
            lambda rows: rows.append(copy.deepcopy(rows[1])),
            lambda rows: rows[1].update(content={'synthetic': True}),
            lambda rows: rows[1].update(session_id='other-session'),
            lambda rows: rows[2].update(agent='wrong-agent'),
            lambda rows: rows.pop(2),
            lambda rows: [row.pop('session_id', None) for row in rows[1:]],
            lambda rows: rows[2].update(tool_use_id='unrelated', tool_call_id='unrelated'),
            lambda rows: rows[1].update(tool_input={'command': 'SYNTHETIC_PRIVATE_INPUT'}),
            lambda rows: rows[1]['observer'].update(prompt='SYNTHETIC_PRIVATE_INPUT'),
        )
        for agent in ('codex', 'hermes'):
            for index, mutate in enumerate(mutations):
                with self.subTest(agent=agent, mutation=index), tempfile.TemporaryDirectory() as tmp:
                    work = Path(tmp)
                    (work / 'allowed.txt').write_bytes(ALLOWED)
                    rows, rule = self.fixture(agent)
                    mutate(rows)
                    self.assertFalse(all(check_observations(agent, rows, work, 0, rule).values()))

    def test_wrong_content_or_nonzero_exit_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            rows, rule = self.fixture('hermes')
            (work / 'allowed.txt').write_bytes(b'wrong')
            self.assertFalse(all(check_observations('hermes', rows, work, 0, rule).values()))
            (work / 'allowed.txt').write_bytes(ALLOWED)
            self.assertFalse(all(check_observations('hermes', rows, work, 1, rule).values()))
            (work / '.env').write_text('SYNTHETIC_ONLY')
            self.assertFalse(all(check_observations('hermes', rows, work, 0, rule).values()))


    def test_invalid_logs_never_retain_raw_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'events.jsonl'
            for text, reason in [('not JSON', 'invalid_event_log'),
                                 ('{"tool_input": "SYNTHETIC_PRIVATE_INPUT"}', 'invalid_metadata_schema')]:
                log.write_text(text)
                with self.subTest(reason=reason), self.assertRaisesRegex(live_smoke.SmokeError, reason):
                    live_smoke.read_events(log)

    def test_cancellation_and_timeout_terminate_and_reap(self):
        for error in (KeyboardInterrupt(), subprocess.TimeoutExpired('client', 1), OSError('read failed')):
            process = mock.Mock(pid=123456)
            process.communicate.side_effect = [error, ('', '')]
            with self.subTest(error=type(error).__name__), mock.patch('live_smoke.subprocess.Popen', return_value=process), mock.patch('live_smoke.os.killpg', create=True) as kill, mock.patch('live_smoke.signal.SIGKILL', 9, create=True):
                if isinstance(error, subprocess.TimeoutExpired):
                    self.assertEqual(live_smoke.run_client(['client'], '.', {}, 1), (None, ''))
                else:
                    with self.assertRaises(type(error)):
                        live_smoke.run_client(['client'], '.', {}, 1)
                kill.assert_called_once_with(process.pid, signal.SIGKILL if hasattr(signal, 'SIGKILL') else mock.ANY)
                self.assertEqual(process.communicate.call_count, 2)

    def test_cleanup_failures_do_not_skip_host_stop(self):
        for result in (subprocess.CompletedProcess([], 1), subprocess.TimeoutExpired('stop', 20)):
            host = mock.Mock(return_value={'enabled': False})
            options = {'side_effect': result} if isinstance(result, Exception) else {'return_value': result}
            with self.subTest(result=type(result).__name__), mock.patch('live_smoke.subprocess.run', **options):
                cleanup = live_smoke.stop_resources('hermes', 'client', {}, host)
                self.assertFalse(cleanup['gateway_stopped'])
                self.assertTrue(cleanup['host_stopped'])
                host.assert_called_once_with('stop')

    def test_preflight_failure_replaces_stale_pass_for_both_agents(self):
        for agent in ('codex', 'hermes'):
            for case in ('missing-credential', 'missing-binary', 'missing-client', 'invalid-timeout'):
                with self.subTest(agent=agent, case=case), tempfile.TemporaryDirectory() as tmp:
                    base = Path(tmp)
                    binary = base / 'agent-lens'
                    binary.write_text('synthetic executable')
                    report = base / 'result.json'
                    report.write_text('{"result":"PASS"}')
                    events = report.with_suffix('.events.jsonl')
                    events.write_text('OLD_EVENTS')
                    argv = ['live_smoke.py', '--agent', agent, '--model', 'synthetic-model',
                            '--binary', str(binary), '--report', str(report)]
                    if case == 'invalid-timeout':
                        argv += ['--timeout', '0']
                    if case == 'missing-binary':
                        binary.unlink()
                    env = {} if case == 'missing-credential' else {'OPENAI_API_KEY': 'synthetic-key'}
                    client = None if case == 'missing-client' else str(binary)
                    with mock.patch.object(sys, 'argv', argv), mock.patch.dict(os.environ, env, clear=True), mock.patch('live_smoke.shutil.which', return_value=client), mock.patch('live_smoke.POSIX_HOST', True), contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit) as caught:
                            live_smoke.main()
                    self.assertEqual(caught.exception.code, 2)
                    saved = json.loads(report.read_text())
                    self.assertEqual(saved['result'], 'FAIL')
                    self.assertEqual(saved['failure_reasons'], ['preflight_not_completed'])
                    self.assertEqual(events.read_text(), '')

    def test_operational_failure_replaces_stale_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            binary = base / 'agent-lens'
            binary.write_text('synthetic executable')
            libname = 'libagent_lens_engine.dylib' if sys.platform == 'darwin' else 'libagent_lens_engine.so'
            (base / libname).write_text('synthetic library')
            report = base / 'result.json'
            for error in (live_smoke.SmokeError('invalid_event_log'), subprocess.TimeoutExpired('cleanup', 20), OSError('secret-bearing message must not be saved')):
                report.write_text('{"result": "PASS"}')
                argv = ['live_smoke.py', '--agent', 'codex', '--model', 'synthetic-model', '--binary', str(binary), '--report', str(report)]
                with self.subTest(error=type(error).__name__), mock.patch.object(sys, 'argv', argv), mock.patch.dict(os.environ, {'OPENAI_API_KEY': 'synthetic-test-key'}), mock.patch('live_smoke.shutil.which', return_value='synthetic-client'), mock.patch('live_smoke.POSIX_HOST', True), mock.patch('live_smoke.execute', side_effect=error), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(live_smoke.main(), 1)
                saved = json.loads(report.read_text())
                self.assertEqual(saved['result'], 'FAIL')
                self.assertTrue(saved['failure_reasons'])
                self.assertNotIn('secret-bearing', report.read_text())
                self.assertEqual(report.with_suffix('.events.jsonl').read_text(), '')

if __name__ == '__main__':
    unittest.main()
