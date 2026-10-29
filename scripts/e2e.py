#!/usr/bin/env python3
"""Real executable -> dynamic library -> disk and protocol tests; no model/API calls.
This deliberately simulates the vendor host, not a real Claude/Codex session.
"""
import concurrent.futures
import ctypes
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get('AGENT_LENS_BIN', ROOT / 'target/release' / ('agent-lens.exe' if os.name == 'nt' else 'agent-lens'))).resolve()
LIB_NAME = 'agent_lens_engine.dll' if os.name == 'nt' else ('libagent_lens_engine.dylib' if sys.platform == 'darwin' else 'libagent_lens_engine.so')
checks = []


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)
    print('PASS', name)


def execute(state, *args, payload=None, code=0, binary=BIN):
    data = None if payload is None else (payload if isinstance(payload, str) else json.dumps(payload))
    result = subprocess.run([str(binary), '--state', str(state), *map(str, args)], input=data, text=True, capture_output=True, timeout=15)
    if result.returncode != code:
        raise AssertionError(f'{args}: expected exit {code}, got {result.returncode}; stderr={result.stderr}')
    return json.loads(result.stdout) if result.stdout.strip() else None


def event(path='src/main.rs', name='PreToolUse', **extra):
    return {'hook_event_name': name, 'session_id': 'test-session', 'tool_name': 'Read', 'tool_input': {'file_path': path}, **extra}


def main():
    with tempfile.TemporaryDirectory(prefix='agent lens ') as tmp:
        base = Path(tmp)
        state, log = base / "state's space", base / 'events.jsonl'
        rules = base / 'rules.yaml'
        rules.write_text('''version: 1
rules:
  - id: protect-env
    path_pattern: '(?i)(^|/)\\.env($|[./])'
    action: block
  - id: protect-shell-env
    content_pattern: '(?i)\\.env'
    tool_pattern: '^(Bash|terminal)$'
    action: block
  - id: audit-read
    tool_pattern: '^Read$'
    action: audit
''')
        run = lambda *a, **kw: execute(state, *a, **kw)
        check('AL-002 inactive hook returns neutral', run('hook', '--agent', 'claude', payload=event()) == {})
        # Experimental Cowork plugin wire, exercised through the real host/library.
        # This does not prove Claude Desktop loading, reachability or consent.
        check('AL-COW inactive is neutral', run('hook', '--agent', 'cowork', '--event', 'PreToolUse', payload=event('.env')) == {})
        check('AL-005 validate YAML via dynamic ABI', run('rules-check', '--rules', rules)['valid'])
        check('AL-002 start', run('start', '--rules', rules, '--output', log)['enabled'])
        check('AL-002 status', run('status')['config']['enabled'])
        for malformed in ['{"path":"/private/file"}', [], False, None]:
            before = log.read_bytes() if log.exists() else b''
            response = run('hook', '--agent', 'cowork', '--event', 'PreToolUse', payload=event(tool_input=malformed))
            after = log.read_bytes() if log.exists() else b''
            check(f'AL-COW malformed {type(malformed).__name__} denied without append', response['hookSpecificOutput']['permissionDecision'] == 'deny' and before == after)
        for name in ('', ' ', '\t'):
            before = log.read_bytes() if log.exists() else b''
            response = run('hook', '--agent', 'cowork', '--event', 'PreToolUse', payload=event(tool_name=name))
            after = log.read_bytes() if log.exists() else b''
            check('AL-COW empty tool name denied without append', response['hookSpecificOutput']['permissionDecision'] == 'deny' and before == after)
        cowork_config = run('config', '--agent', 'cowork')
        cowork_events = ('SessionStart', 'PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'SessionEnd')
        check('AL-COW five-event plugin inventory', set(cowork_config['hooks']) == set(cowork_events))
        for native_event in cowork_events:
            handler = cowork_config['hooks'][native_event][0]['hooks'][0]
            payload = json.loads((ROOT / 'examples/events' / {
                'SessionStart': 'cowork-session-start.json', 'PreToolUse': 'cowork-pre-tool.json',
                'PostToolUse': 'cowork-post-tool.json', 'PostToolUseFailure': 'cowork-tool-failure.json',
                'SessionEnd': 'cowork-session-end.json'}[native_event]).read_text())
            result = subprocess.run([handler['command'], *handler['args']], input=json.dumps(payload),
                                    text=True, capture_output=True, timeout=15)
            check(f'AL-COW {native_event} generated direct argv launches', result.returncode == 0)
            response = json.loads(result.stdout)
            row = json.loads(log.read_text().splitlines()[-1])
            check(f'AL-COW {native_event} identity/content boundary', row['agent'] == 'cowork' and row['hook_event'] == native_event and 'content' not in row)
            if native_event == 'PreToolUse':
                check('AL-COW native pre denial', response['hookSpecificOutput']['permissionDecision'] == 'deny')
                check('AL-COW direct command errors request block', handler['onFailure'] == 'block')
            else:
                check(f'AL-COW {native_event} observes', response == {} and row['enforcement'] == 'observe_only')
        check('AL-COW nearby allowed control', run('hook', '--agent', 'cowork', '--event', 'PreToolUse', payload=event('README.md')) == {})
        for agent in ('claude', 'codex'):
            response = run('hook', '--agent', agent, '--event', 'PreToolUse', payload=event())
            check(f'AL-003 {agent} allow has no denial', response.get('hookSpecificOutput', {}).get('permissionDecision') != 'deny')
            response = run('hook', '--agent', agent, '--event', 'PreToolUse', payload=event('.env'))
            check(f'AL-003 {agent} native deny', response['hookSpecificOutput']['permissionDecision'] == 'deny')
            # Independent vendor-host model: execute a harmless write only when
            # the returned native decision permits it, with positive control.
            marker = base / f'{agent}-side-effect'
            if response['hookSpecificOutput']['permissionDecision'] != 'deny':
                marker.write_text('would execute')
            check(f'AL-003 {agent} simulated denied side effect absent', not marker.exists())
            allowed = run('hook', '--agent', agent, payload=event('README.md'))
            if allowed.get('hookSpecificOutput', {}).get('permissionDecision') != 'deny':
                marker.write_text('allowed')
            check(f'AL-003 {agent} simulated positive control executes', marker.read_text() == 'allowed')
        hermes_input = event('.env', 'pre_tool_call')
        hermes_block = run('hook', '--agent', 'hermes', '--event', 'pre_tool_call', payload=hermes_input)
        check('AL-004 Hermes native pre-tool denial', hermes_block.get('action') == 'block' and bool(hermes_block.get('message')))
        check('AL-004 Hermes positive control defers permissions', run('hook', '--agent', 'hermes', payload=event('README.md', 'pre_tool_call')) == {})
        hermes_config = run('config', '--agent', 'hermes')
        hermes_handler = hermes_config['hooks']['pre_tool_call'][0]
        check('AL-004 Hermes config requests fail-closed on pre-tool errors', hermes_handler['fail_closed'] is True)
        # Model the documented native Hermes tokenizer: POSIX shlex, or on
        # Windows non-POSIX tokens with one layer of matching quotes removed.
        hermes_argv = shlex.split(hermes_handler['command'], posix=os.name != 'nt')
        if os.name == 'nt':
            hermes_argv = [arg[1:-1] if len(arg) >= 2 and arg[0] == arg[-1] and arg[0] in ('"', "'") else arg for arg in hermes_argv]
        hermes_native = subprocess.run(hermes_argv, input=json.dumps(hermes_input), text=True, capture_output=True, timeout=15)
        check('AL-004 Hermes exact argv command emits native block', hermes_native.returncode == 0 and json.loads(hermes_native.stdout)['action'] == 'block')
        gemini_pre = event('.env', 'BeforeTool', tool_name='read_file')
        check('AL-GEM-002 Gemini native denial', run('hook', '--agent', 'gemini', payload=gemini_pre) == {'decision': 'deny', 'reason': 'Blocked by Agent Lens policy'})
        check('AL-GEM-002 Gemini allowed tools defer native permissions', run('hook', '--agent', 'gemini', payload=event('README.md', 'BeforeTool', tool_name='read_file')) == {})
        run('hook', '--agent', 'gemini', payload=event('.env', 'AfterTool', tool_name='read_file', tool_response={'llmContent': 'SYNTHETIC_PRIVATE_RESPONSE'}))
        gemini_row = json.loads(log.read_text().splitlines()[-1])
        check('AL-GEM-001 Gemini post-tool cannot undo execution', gemini_row['decision'] == 'would_block' and gemini_row['enforcement'] == 'observe_only')
        check('AL-GEM-001 Gemini native metadata', gemini_row['agent'] == 'gemini' and gemini_row['session_id'] == 'test-session' and gemini_row['tool_name'] == 'read_file')
        check('AL-GEM-001 Gemini response content absent by default', 'SYNTHETIC_PRIVATE_RESPONSE' not in log.read_text())
        gemini_config = run('config', '--agent', 'gemini')
        check('AL-GEM-003 Gemini exact native event inventory', set(gemini_config['hooks']) == {'SessionStart', 'SessionEnd', 'BeforeAgent', 'AfterAgent', 'BeforeToolSelection', 'BeforeTool', 'AfterTool', 'Notification', 'PreCompress'})
        check('AL-GEM-003 Gemini shell override preserves native dialect', run('config', '--agent', 'gemini', '--shell', 'posix' if os.name == 'nt' else 'powershell') == gemini_config)
        check('AL-GEM-003 Gemini timeout is milliseconds', all(group[0]['hooks'][0]['timeout'] == 10000 for group in gemini_config['hooks'].values()))
        # Execute exactly the generated command through Gemini 0.66.0's host shell.
        command = gemini_config['hooks']['BeforeTool'][0]['hooks'][0]['command']
        shell_cmd = ['powershell', '-NoProfile', '-NonInteractive', '-Command', command] if os.name == 'nt' else ['bash', '-c', command]
        rendered = subprocess.run(shell_cmd, input=json.dumps(gemini_pre), text=True, capture_output=True, timeout=15)
        check('AL-GEM-003 Gemini generated command survives spaces and apostrophes', rendered.returncode == 0 and json.loads(rendered.stdout)['decision'] == 'deny')
        for invalid in ('invalid JSON', event(name='BeforeTool', tool_name='read_file', tool_input=[])):
            response = run('hook', '--agent', 'gemini', '--event', 'BeforeTool', payload=invalid)
            check('AL-GEM-002 Gemini invalid pre-tool input denies', response.get('decision') == 'deny' and bool(response.get('reason')))
        mismatch = run('hook', '--agent', 'gemini', '--event', 'AfterTool', payload=gemini_pre)
        check('AL-GEM-002 Gemini mismatched pre-tool envelope denies', mismatch.get('decision') == 'deny')
        run('hook', '--agent', 'claude', payload=event('.env', 'PostToolUse', tool_response='TEST_SENTINEL_SECRET'))
        rows = [json.loads(line) for line in log.read_text().splitlines()]
        check('AL-005 post event can only would_block', rows[-1]['decision'] == 'would_block')
        check('AL-006 content absent by default', all('content' not in row for row in rows))
        check('AL-006 tool content never appears by default', 'TEST_SENTINEL_SECRET' not in log.read_text())
        check('AL-005 matched rule IDs in JSONL', 'protect-env' in rows[1]['matched_rules'])
        check('AL-001 timestamp added by host', rows[0]['timestamp'].endswith('Z'))
        count = len(rows)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(lambda _: run('hook', '--agent', 'claude', payload=event()), range(24)))
        rows = [json.loads(line) for line in log.read_text().splitlines()]
        check('AL-002 concurrent append preserves every JSON record', len(rows) == count + 24)
        check('AL-002 stop', run('stop')['enabled'] is False)
        before = log.read_bytes()
        check('AL-002 stopped policy returns neutral', run('hook', '--agent', 'claude', payload=event('.env')) == {})
        check('AL-002 stopped hook writes nothing', log.read_bytes() == before)
        run('start', '--rules', rules, '--output', log, '--capture-content')
        run('hook', '--agent', 'codex', payload=event('README.md', 'PostToolUse', tool_response={'api_key': 'SENTINEL_KEY_VALUE'}))
        last = json.loads(log.read_text().splitlines()[-1])
        check('AL-006 content opt-in enabled', 'content' in last)
        check('AL-006 sensitive key value redacted', 'SENTINEL_KEY_VALUE' not in json.dumps(last))
        run('hook', '--agent', 'codex', payload=event('README.md', 'PostToolUse', tool_response='{"api_key":"SENTINEL_JSON_VALUE"}'))
        last = json.loads(log.read_text().splitlines()[-1])
        check('AL-006 JSON text credential redacted', 'SENTINEL_JSON_VALUE' not in json.dumps(last))
        rules.write_text('version: 1\nrules:\n  - id: bad\n    path_pattern: "["\n    action: block\n')
        deny = run('hook', '--agent', 'claude', '--event', 'PreToolUse', payload=event())
        check('AL-007 corrupt live rules deny known pre-action', deny['hookSpecificOutput']['permissionDecision'] == 'deny')
        hermes_deny = run('hook', '--agent', 'hermes', '--event', 'pre_tool_call', payload=hermes_input)
        check('AL-007 Hermes corrupt rules fail closed', hermes_deny['action'] == 'block')
        gemini_deny = run('hook', '--agent', 'gemini', '--event', 'BeforeTool', payload=gemini_pre)
        check('AL-GEM-002 Gemini corrupt rules deny', gemini_deny.get('decision') == 'deny')
        permission_deny = run('hook', '--agent', 'codex', '--event', 'PermissionRequest', payload=event(name='PermissionRequest'))
        check('AL-007 permission request errors deny with native schema', permission_deny['hookSpecificOutput']['decision']['behavior'] == 'deny')
        run('rules-check', '--rules', rules, code=1)
        check('AL-007 invalid rules observable management failure', True)
        rules.write_text('version: 1\nrules: []\n')
        deny = run('hook', '--agent', 'codex', '--event', 'PreToolUse', payload='invalid JSON')
        check('AL-007 malformed pre payload denied', deny['hookSpecificOutput']['permissionDecision'] == 'deny')
        deny = run('hook', '--agent', 'codex', '--event', 'PreToolUse', payload='x' * (1024 * 1024 + 1))
        check('AL-007 oversized pre payload denied', deny['hookSpecificOutput']['permissionDecision'] == 'deny')
        log.unlink()
        log.mkdir()
        deny = run('hook', '--agent', 'claude', '--event', 'PreToolUse', payload=event())
        check('AL-007 output failure denies known pre-action', deny['hookSpecificOutput']['permissionDecision'] == 'deny')
        deny = run('hook', '--agent', 'gemini', '--event', 'BeforeTool', payload=gemini_pre)
        check('AL-GEM-002 Gemini output failure denies', deny.get('decision') == 'deny')
        run('stop')
        check('AL-GEM-002 stopped Gemini returns neutral', run('hook', '--agent', 'gemini', payload=gemini_pre) == {})
        default_state, default_log = base / 'default-state', base / 'default.jsonl'
        execute(default_state, 'start', '--rules', ROOT / 'examples/rules/default.yaml', '--output', default_log)
        for tool, args in [('read_file', {'file_path': '/synthetic/.env'}),
                           ('write_file', {'file_path': '/synthetic/.env', 'content': 'synthetic'}),
                           ('replace', {'file_path': '/synthetic/.env', 'old_string': 'a', 'new_string': 'b'}),
                           ('run_shell_command', {'command': 'cat .env', 'dir_path': '/synthetic'})]:
            blocked = execute(default_state, 'hook', '--agent', 'gemini', payload=event(name='BeforeTool', tool_name=tool, tool_input=args))
            check(f'AL-GEM-004 default pack covers native {tool}', blocked.get('decision') == 'deny')
        execute(default_state, 'stop')
        integrity_state, integrity_log = base / 'integrity-state', base / 'integrity.jsonl'
        execute(integrity_state, 'start', '--rules', ROOT / 'examples/rules/agent-config-integrity.yaml', '--output', integrity_log)
        for path, expected in [('/synthetic/.gemini/settings.json', 'block'), ('/synthetic/GEMINI.md', 'allow'), ('/synthetic/settings.json', 'allow')]:
            execute(integrity_state, 'hook', '--agent', 'gemini', payload=event(path, 'BeforeTool', tool_name='replace'))
            row = json.loads(integrity_log.read_text().splitlines()[-1])
            check(f'AL-GEM-004 integrity native replace {path}', row['decision'] == expected and bool(row['matched_rules']) == (path != '/synthetic/settings.json'))
        execute(integrity_state, 'stop')
        restricted_state, restricted_log = base / 'restricted-state', base / 'restricted.jsonl'
        execute(restricted_state, 'start', '--rules', ROOT / 'examples/rules/restricted-tools.yaml', '--output', restricted_log)
        for tool, expected in [('mcp_playwright_browser_evaluate', 'deny'), ('mcp_playwright_browser_snapshot', None)]:
            response = execute(restricted_state, 'hook', '--agent', 'gemini', payload=event(name='BeforeTool', tool_name=tool, tool_input={'function': '() => 1'}))
            check(f'AL-GEM-004 native MCP name {tool}', response.get('decision') == expected)
        execute(restricted_state, 'stop')
        for agent in ('claude', 'codex'):
            snippet = run('config', '--agent', agent)
            check(f'AL-003 {agent} generated hooks include pre/post', all(k in snippet['hooks'] for k in ('PreToolUse', 'PostToolUse')))
            # Run exact rendered command through the real default host shell.
            command = snippet['hooks']['PreToolUse'][0]['hooks'][0]['command']
            shell_cmd = ['powershell', '-NoProfile', '-Command', command] if os.name == 'nt' else ['/bin/sh', '-c', command]
            rendered = subprocess.run(shell_cmd, input=json.dumps(event()), text=True, capture_output=True, timeout=15)
            check(f'AL-003 {agent} generated command executes with spaced state path', rendered.returncode == 0 and json.loads(rendered.stdout) == {})
        isolated = base / 'isolated'
        isolated.mkdir()
        isolated_bin = isolated / BIN.name
        shutil.copy2(BIN, isolated_bin)
        execute(base / 'missing-lib', 'rules-check', '--rules', rules, binary=isolated_bin, code=1)
        check('AL-001 EXE fails when companion library absent', True)
        # Exercise actual exported allocator/free pair and input rejection.
        lib = ctypes.CDLL(str(BIN.parent / LIB_NAME))
        lib.agent_lens_abi_version.restype = ctypes.c_uint32
        lib.agent_lens_process.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.agent_lens_process.restype = ctypes.c_void_p
        lib.agent_lens_free.argtypes = [ctypes.c_void_p]
        check('AL-001 ABI version', lib.agent_lens_abi_version() == 1)
        ptr = lib.agent_lens_process(None, 0)
        envelope = json.loads(ctypes.string_at(ptr))
        lib.agent_lens_free(ptr)
        check('AL-001 null ABI input rejected safely', envelope['ok'] is False)
        demo_log = base / 'demo.jsonl'
        check('AL-005 synthetic demo', run('demo', '--output', demo_log)['synthetic_events'] == 5)
        check('AL-005 demo records visibly synthetic', all(json.loads(line)['synthetic'] for line in demo_log.read_text().splitlines()))
    print(f'{len(checks)} executable/DLL assertions passed on {sys.platform}. Live-agent validation: NOT RUN.')


if __name__ == '__main__':
    main()
