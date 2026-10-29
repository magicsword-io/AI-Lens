#!/usr/bin/env python3
"""Replay every shipped rule through the native EXE/DLL; never execute fixture commands."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get('AGENT_LENS_BIN', ROOT / 'target/release' /
                          ('agent-lens.exe' if os.name == 'nt' else 'agent-lens'))).resolve()
EVENTS = {'claude': ('PreToolUse', 'PostToolUse'),
          'codex': ('PreToolUse', 'PostToolUse'),
          'hermes': ('pre_tool_call', 'post_tool_call'),
          'gemini': ('BeforeTool', 'AfterTool'),
          'cursor': ('preToolUse', 'postToolUse'),
          'copilot': ('preToolUse', 'postToolUse'),
          'cowork': ('PreToolUse', 'PostToolUse')}


def host(state, *args, payload=None):
    result = subprocess.run([str(BIN), '--state', str(state), *map(str, args)],
                            input=None if payload is None else json.dumps(payload),
                            text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, f'{args}: host failed: {result.stderr}'
    return json.loads(result.stdout)


def denied(response, agent):
    if agent == 'cursor':
        return response.get('permission') == 'deny' and bool(response.get('user_message'))
    if agent == 'copilot':
        return response.get('permissionDecision') == 'deny' and bool(response.get('permissionDecisionReason'))
    if agent == 'gemini':
        return response.get('decision') == 'deny' and bool(response.get('reason'))
    if agent == 'hermes':
        return response.get('action') == 'block' and bool(response.get('message'))
    return response.get('hookSpecificOutput', {}).get('permissionDecision') == 'deny'


def native_tool(agent, name):
    if agent == 'cursor':
        return 'MCP:' + name if name.startswith('mcp__') else {'Bash': 'Shell'}.get(name, name)
    if agent == 'copilot':
        return {'Read': 'view', 'Write': 'create', 'Edit': 'edit', 'MultiEdit': 'edit', 'Bash': 'bash', 'Task': 'task'}.get(name, name)
    if agent != 'gemini':
        return name
    if name.startswith('mcp__'):
        _, server, tool = name.split('__', 2)
        return f'mcp_{server}_{tool}'
    return {'Read': 'read_file', 'Write': 'write_file', 'Edit': 'replace',
            'MultiEdit': 'replace', 'Bash': 'run_shell_command'}.get(name, name)


def neutral(agent, event):
    return {'permission': 'allow'} if agent == 'cursor' and event == 'preToolUse' else {}


def native_payload(agent, event, tool):
    name = native_tool(agent, tool['tool_name'])
    args = tool['tool_input']
    if agent == 'copilot':
        args = {('path' if key == 'file_path' else key): value for key, value in args.items()}
        return {'sessionId': 'synthetic-rule-test', 'timestamp': 1793275200000,
                'toolName': name, 'toolArgs': json.dumps(args)}
    if agent == 'cursor':
        return {'hook_event_name': event, 'conversation_id': 'synthetic-rule-test',
                'tool_name': name, 'tool_input': args}
    return {'hook_event_name': event, 'session_id': 'synthetic-rule-test',
            'tool_name': name, 'tool_input': args}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, help='write synthetic assertion results as JSON')
    args = parser.parse_args()
    cases = json.loads((ROOT / 'examples' / 'rule-cases.json').read_text())
    assert cases['version'] == 1
    packs = sorted((ROOT / 'examples' / 'rules').glob('*.yaml'))
    results = []
    with tempfile.TemporaryDirectory(prefix='agent lens rules ') as temporary:
        base = Path(temporary)
        inventory = {(pack.name, rule_id) for pack in packs for rule_id in
                     host(base / 'inventory', 'rules-check', '--rules', pack)['rule_ids']}
        covered = {(case['pack'], case['rule_id']) for case in cases['cases']}
        assert inventory == covered, f'rule coverage mismatch: missing={inventory-covered}; stale={covered-inventory}'
        assert inventory, 'no rules tested'
        assert len({rule_id for _, rule_id in inventory}) == len(inventory), 'pack rule IDs collide when combined'
        combined = base / 'combined.yaml'
        combined.write_text('version: 1\nrules:\n' + ''.join(
            pack.read_text().split('\nrules:\n', 1)[1] for pack in packs))
        host(base / 'combined-state', 'rules-check', '--rules', combined)
        for pack in packs:
            state = base / pack.stem
            log = base / f'{pack.stem}.jsonl'
            host(state, 'rules-check', '--rules', pack)
            host(state, 'start', '--rules', pack, '--output', log)
            for case in (c for c in cases['cases'] if c['pack'] == pack.name):
                for agent, (pre, post) in EVENTS.items():
                    for scenario, event, tool in [('positive_pre', pre, case['hit']),
                                                   ('negative_pre', pre, case['miss']),
                                                   ('positive_post', post, case['hit'])]:
                        payload = native_payload(agent, event, tool)
                        response = host(state, 'hook', '--agent', agent, '--event', event, payload=payload)
                        row = json.loads(log.read_text().splitlines()[-1])
                        expected_match = scenario != 'negative_pre'
                        assert (case['rule_id'] in row['matched_rules']) == expected_match, (case['rule_id'], agent, scenario, row)
                        if expected_match:
                            expected = case['pre_decision']
                            if scenario == 'positive_post' and expected == 'block':
                                expected = 'would_block'
                            assert row['decision'] == expected, (case['rule_id'], scenario, row)
                            if expected == 'block':
                                assert denied(response, agent), (case['rule_id'], response)
                            else:
                                assert response == neutral(agent, event), (case['rule_id'], response)
                            if scenario == 'positive_post':
                                assert row['enforcement'] == 'observe_only'
                        else:
                            assert row['decision'] == 'allow', (case['rule_id'], agent, scenario, row)
                            assert response == neutral(agent, event), (case['rule_id'], agent, scenario, response)
                        assert 'content' not in row, 'rule matching enabled raw content capture'
                        results.append({'pack': pack.name, 'rule_id': case['rule_id'],
                                        'agent': agent, 'scenario': scenario, 'passed': True})
                print(f"PASS {pack.name}: {case['rule_id']} ({len(EVENTS)} agents; match, near-miss, post)")
            host(state, 'stop')
    report = {'schema_version': 1, 'synthetic': True, 'rule_count': len(inventory),
              'assertions': len(results), 'passed': len(results),
              'fixture_commands_executed': False, 'results': results}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(f'{len(inventory)} rules: {len(results)} native EXE/DLL replay scenarios passed. Fixture commands were NOT executed.')


if __name__ == '__main__':
    main()
