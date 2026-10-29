#!/usr/bin/env python3
"""Deliberately break isolated rule/test copies and require the replay oracle to fail."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import rules_smoke

SOURCE_ROOT = Path(__file__).resolve().parents[1]


class RuleOracleTests(unittest.TestCase):
    @contextlib.contextmanager
    def snapshot(self):
        with tempfile.TemporaryDirectory(prefix='lens oracle ') as temporary:
            base = Path(temporary)
            shutil.copytree(SOURCE_ROOT / 'examples', base / 'examples')
            with patch.object(rules_smoke, 'ROOT', base), patch.object(sys, 'argv', ['rules_smoke.py']):
                with contextlib.redirect_stdout(io.StringIO()):
                    yield base

    def test_seven_adapter_inventory_is_explicit(self):
        self.assertEqual(rules_smoke.EVENTS, {
            'claude': ('PreToolUse', 'PostToolUse'),
            'codex': ('PreToolUse', 'PostToolUse'),
            'hermes': ('pre_tool_call', 'post_tool_call'),
            'gemini': ('BeforeTool', 'AfterTool'),
            'cursor': ('preToolUse', 'postToolUse'),
            'copilot': ('preToolUse', 'postToolUse'),
            'cowork': ('PreToolUse', 'PostToolUse'),
        })

    def test_gemini_replays_native_mcp_names(self):
        for fixture, expected in [
            ('mcp__fetch__fetch', 'mcp_fetch_fetch'),
            ('mcp__playwright__browser_evaluate', 'mcp_playwright_browser_evaluate'),
            ('mcp__agents__delegate', 'mcp_agents_delegate'),
            ('mcp__server_name__tool__name', 'mcp_server_name_tool__name'),
            ('Bash', 'run_shell_command'),
        ]:
            self.assertEqual(rules_smoke.native_tool('gemini', fixture), expected)
            self.assertEqual(rules_smoke.native_tool('claude', fixture), fixture)

    def test_uncovered_quoted_yaml_id_is_rejected(self):
        with self.snapshot() as base:
            policy = base / 'examples/rules/restricted-tools.yaml'
            with policy.open('a') as stream:
                stream.write('\n  - id: "review-uncovered-valid-yaml"\n'
                             '    tool_pattern: "^REVIEW_NEVER_MATCH$"\n    action: audit\n')
            with self.assertRaisesRegex(AssertionError, 'rule coverage mismatch.*review-uncovered-valid-yaml'):
                rules_smoke.main()

    def test_weakened_block_rule_is_rejected(self):
        with self.snapshot() as base:
            policy = base / 'examples/rules/default.yaml'
            policy.write_text(policy.read_text().replace('action: block', 'action: audit', 1))
            with self.assertRaisesRegex(AssertionError, 'protect-env-files.*allow'):
                rules_smoke.main()

    def test_negative_control_checks_both_telemetry_and_native_response(self):
        for corruption in ('telemetry', 'response'):
            with self.subTest(corruption=corruption), self.snapshot():
                real_host = rules_smoke.host

                def corrupted_host(state, *args, payload=None):
                    response = real_host(state, *args, payload=payload)
                    if payload and payload.get('tool_input', {}).get('command') == 'git reset --soft HEAD~1':
                        if corruption == 'telemetry':
                            log = Path(state).parent / f'{Path(state).name}.jsonl'
                            lines = log.read_text().splitlines()
                            row = json.loads(lines[-1])
                            row['decision'] = 'block'
                            lines[-1] = json.dumps(row)
                            log.write_text('\n'.join(lines) + '\n')
                        else:
                            response = {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
                                        'permissionDecision': 'deny', 'permissionDecisionReason': 'Synthetic mutation'}}
                    return response

                with patch.object(rules_smoke, 'host', corrupted_host):
                    with self.assertRaisesRegex(AssertionError, 'destructive-git-hard-reset.*negative_pre'):
                        rules_smoke.main()


if __name__ == '__main__':
    unittest.main()
