#!/usr/bin/env python3
"""Real CLI/library Cursor and Copilot adapter replay; no vendor runtime or API."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ('agent_lens_engine.dll' if os.name == 'nt' else
           'libagent_lens_engine.dylib' if sys.platform == 'darwin' else 'libagent_lens_engine.so')
AGENTS = ('cursor', 'copilot')
SECRET = 'PRIVATE_NATIVE_SECRET'
BODY = 'SYNTHETIC_CAPTURE_BODY'
RAW_PATCH_SECRET = 'SYNTHETIC_PATCH_SECRET_1029'
PRIVACY_FORMS = ('object', 'string', 'escaped-key')
PRIVACY_SECRETS = ('SYNTHETIC_META_SECRET', 'SYNTHETIC_PRIVATE_KEY_SECRET',
                   'SYNTHETIC_AUTH_SECRET', 'SYNTHETIC_AUTH_MEMBER')
# Independent expected inventory and phases, never inferred from generated config.
CASES = {
    'cursor': (
        ('sessionStart', 'session-start', 'lifecycle'),
        ('sessionEnd', 'session-end', 'lifecycle'),
        ('preToolUse', 'pre-tool', 'pre'),
        ('postToolUse', 'post-tool', 'post'),
        ('postToolUseFailure', 'tool-failure', 'post'),
        ('subagentStart', 'subagent-start', 'lifecycle'),
        ('subagentStop', 'subagent-stop', 'lifecycle'),
        ('stop', 'stop', 'lifecycle'),
        ('preCompact', 'pre-compact', 'pre'),
        ('afterAgentResponse', 'agent-response', 'post'),
        ('workspaceOpen', 'workspace-open', 'lifecycle'),
    ),
    'copilot': (
        ('sessionStart', 'session-start', 'lifecycle'),
        ('sessionEnd', 'session-end', 'lifecycle'),
        ('preToolUse', 'pre-tool', 'pre'),
        ('postToolUse', 'post-tool', 'post'),
        ('postToolUseFailure', 'tool-failure', 'post'),
        ('errorOccurred', 'error', 'lifecycle'),
        ('userPromptSubmitted', 'user-prompt', 'pre'),
        ('agentStop', 'agent-stop', 'lifecycle'),
        ('subagentStart', 'subagent-start', 'lifecycle'),
        ('subagentStop', 'subagent-stop', 'lifecycle'),
        ('preCompact', 'pre-compact', 'pre'),
        ('notification', 'notification', 'lifecycle'),
    ),
}
FORMS = (('cursor', 'object'), ('copilot', 'object'), ('copilot', 'string'))
BAD = ('json', 'tool-name', 'tool-args', 'mismatch', 'oversize')
EXPECTED = {f'{mode}/{agent}/{event}' for mode in ('fixture', 'configured')
            for agent in AGENTS for event, _, _ in CASES[agent]}
EXPECTED.update(('config/cursor/posix', 'config/cursor/powershell', 'config/copilot/direct',
                 'config/copilot/shell-ignored', 'copilot/event-required', 'cursor/native-event',
                 'malformed/copilot/string', 'malformed/copilot/depth'))
EXPECTED.update(f'{mode}/cursor/{event}/{discriminator}' for mode in ('inactive', 'stopped')
                for event in ('preToolUse', 'subagentStart') for discriminator in ('explicit', 'native'))
EXPECTED.update(f'{mode}/copilot' for mode in ('inactive', 'stopped'))
EXPECTED.update(f'path/{agent}/{form}/{decision}' for agent, form in FORMS for decision in ('allow', 'deny'))
EXPECTED.update(f'shell/{tool}/{decision}' for tool in ('Shell', 'bash', 'powershell') for decision in ('allow', 'deny'))
EXPECTED.update(f'malformed/{agent}/{kind}' for agent in AGENTS for kind in BAD)
EXPECTED.update(f'capture/{agent}/{form}' for agent, form in FORMS)
EXPECTED.update(f'missing-library/{agent}' for agent in AGENTS)
EXPECTED.update(f'privacy/copilot/{form}/{mode}/{control}' for form in PRIVACY_FORMS
                for mode in ('metadata', 'capture') for control in ('repeated-secret', 'ordinary-id'))
EXPECTED.update(f'copilot/raw-patch/{case}' for case in (
    'allow', 'deny', 'post', 'metadata', 'capture',
    'truncated', 'other-tool', 'oversize', 'unknown-header'))
EXPECTED_COUNT = 112
INVENTORY_POLICY = 'version: 1\nrules: [{id: inventory, agents: [cursor, copilot], action: block}]\n'
PATH_POLICY = r'''version: 1
rules:
  - id: private-path
    path_pattern: '(^|/)\.env($|[./])'
    action: block
  - id: shell-marker
    tool_pattern: '^(Shell|bash|powershell)$'
    content_pattern: 'SMOKE_DENY'
    action: block
'''


class Failure(Exception):
    """Only authored labels, never exception text or CLI output."""


def require(label, condition):
    if not condition:
        raise Failure(label)


def encode(value):
    return json.dumps(value, separators=(',', ':')).encode('utf-8')


def rows(path):
    return [json.loads(line) for line in path.read_bytes().splitlines()] if path.exists() else []


def neutral(agent, event='preToolUse'):
    return {'permission': 'allow'} if agent == 'cursor' and event in ('preToolUse', 'subagentStart') else {}


def denial(agent, value):
    if agent == 'cursor':
        return (set(value) == {'permission', 'user_message', 'agent_message'} and value['permission'] == 'deny'
                and isinstance(value['user_message'], str) and bool(value['user_message'].strip())
                and value['agent_message'] == value['user_message'])
    return (set(value) == {'permissionDecision', 'permissionDecisionReason'} and value['permissionDecision'] == 'deny'
            and isinstance(value['permissionDecisionReason'], str) and bool(value['permissionDecisionReason'].strip()))


def fixture(agent, suffix):
    return json.loads((ROOT / 'examples' / 'events' / f'{agent}-{suffix}.json').read_text(encoding='utf-8'))


def pre(agent, form='object', path='/synthetic/public.txt'):
    payload = fixture(agent, 'pre-tool')
    args = {'path': path}
    payload['tool_input' if agent == 'cursor' else 'toolArgs'] = json.dumps(args) if form == 'string' else args
    return payload


def quoted(value, dialect):
    return "'" + value.replace("'", "''" if dialect == 'powershell' else "'\"'\"'") + "'"


class Smoke:
    def __init__(self, binary, directory):
        self.directory, self.passed = directory, []
        bundle = directory / "bundle's space"
        bundle.mkdir()
        self.binary = bundle / binary.name
        shutil.copy2(binary, self.binary)
        shutil.copy2(binary.parent / LIBRARY, bundle / LIBRARY)
        self.hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in
                       [('binary', self.binary), ('library', bundle / LIBRARY)]}
        self.state = directory / "state's space"
        self.log = directory / 'events.jsonl'
        self.rules = directory / "rules' file.yaml"
        self.configs = {}

    def check(self, label, condition):
        require(label, label in EXPECTED and label not in self.passed and condition)
        self.passed.append(label)

    def run(self, *args, payload=None, binary=None, state=None, argv=None):
        command = argv or [str(binary or self.binary), '--state', str(state or self.state), *map(str, args)]
        data = payload if isinstance(payload, bytes) else encode(payload) if payload is not None else None
        # Temporary streams bound captured output memory, including broken CLI output.
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            result = subprocess.run(command, input=data, stdout=stdout, stderr=stderr, timeout=20,
                                    cwd=self.directory, check=False)
            stdout.seek(0)
            stderr.seek(0)
            out, err = stdout.read(131073), stderr.read(131073)
        require('bounded-cli-output', len(out) <= 131072 and len(err) <= 131072)
        require('private-cli-output', all(value.encode() not in out + err for value in
                                         (SECRET, 'PRIVATE_BAD_JSON', *PRIVACY_SECRETS, RAW_PATCH_SECRET)))
        return result.returncode, out, err

    def json_run(self, *args, **kwargs):
        code, out, err = self.run(*args, **kwargs)
        require('cli-success', code == 0)
        value = json.loads(out)  # Also rejects duplicate final JSON objects/progress output.
        require('cli-json-object', isinstance(value, dict))
        return value

    def hook(self, agent, event, payload, **kwargs):
        args = ['hook', '--agent', agent]
        if event is not None:
            args += ['--event', event]
        return self.json_run(*args, payload=payload, **kwargs)

    def start(self, policy, capture=False):
        self.rules.write_text(policy, encoding='utf-8')
        args = ['start', '--output', self.log, '--rules', self.rules]
        if capture:
            args.append('--capture-content')
        require('state-start', self.json_run(*args).get('enabled') is True)

    def disabled(self, mode):
        before = self.log.read_bytes() if self.log.exists() else b''
        for event, suffix in [('preToolUse', 'pre-tool'), ('subagentStart', 'subagent-start')]:
            for discriminator in ('explicit', 'native'):
                result = self.hook('cursor', event if discriminator == 'explicit' else None, fixture('cursor', suffix))
                self.check(f'{mode}/cursor/{event}/{discriminator}', result == {'permission': 'allow'})
        self.check(f'{mode}/copilot', self.hook('copilot', 'preToolUse', pre('copilot')) == {})
        require('disabled-no-ledger-write', (self.log.read_bytes() if self.log.exists() else b'') == before)

    def configurations(self):
        native = 'powershell' if os.name == 'nt' else 'posix'
        for dialect in ('posix', 'powershell'):
            config = self.json_run('config', '--agent', 'cursor', '--shell', dialect)
            expected = {}
            for event, _, _ in CASES['cursor']:
                command = ('& ' if dialect == 'powershell' else '') + quoted(str(self.binary), dialect)
                command += f' --state {quoted(str(self.state), dialect)} hook --agent cursor --event {event}'
                handler = {'type': 'command', 'command': command, 'timeout': 10}
                if event == 'preToolUse':
                    handler['failClosed'] = True
                expected[event] = [handler]
            self.check(f'config/cursor/{dialect}', config == {'version': 1, 'hooks': expected})
            if dialect == native:
                self.configs['cursor'] = config
        config = self.json_run('config', '--agent', 'copilot')
        expected = {event: [{'type': 'command', 'exec': str(self.binary),
                            'args': ['--state', str(self.state), 'hook', '--agent', 'copilot', '--event', event],
                            'timeoutSec': 30}] for event, _, _ in CASES['copilot']}
        self.check('config/copilot/direct', config == {'version': 1, 'hooks': expected})
        self.check('config/copilot/shell-ignored', self.json_run('config', '--agent', 'copilot', '--shell', 'posix')
                   == self.json_run('config', '--agent', 'copilot', '--shell', 'powershell') == config)
        self.configs['copilot'] = config

    def fixtures(self):
        self.start(INVENTORY_POLICY)
        for mode in ('fixture', 'configured'):
            for agent in AGENTS:
                for event, suffix, phase in CASES[agent]:
                    payload = fixture(agent, suffix)
                    payload.update(prompt=BODY, api_key=SECRET)
                    count = len(rows(self.log))
                    if mode == 'fixture':
                        result = self.hook(agent, event, payload)
                    else:
                        handler = self.configs[agent]['hooks'][event][0]
                        if agent == 'copilot':
                            argv = [handler['exec'], *handler['args']]
                        elif os.name == 'nt':
                            argv = ['powershell', '-NoProfile', '-NonInteractive', '-Command', handler['command']]
                        else:
                            argv = ['sh', '-c', handler['command']]
                        result = self.json_run(argv=argv, payload=payload)
                    events = rows(self.log)
                    row = events[-1]
                    session = row.get('session_id') == f'synthetic-{agent}-session'
                    if event == 'workspaceOpen':
                        session = 'session_id' not in row
                    valid = (len(events) == count + 1 and row.get('agent') == agent and row.get('hook_event') == event
                             and row.get('phase') == phase and row.get('matched_rules') == ['inventory'] and session
                             and row.get('schema_version') == 1 and row.get('observer', {}).get('name') == 'agent-lens'
                             and row.get('timestamp', '').endswith('Z') and 'content' not in row)
                    if 'ToolUse' in event:
                        valid = valid and row.get('tool_name') == ('Read' if agent == 'cursor' else 'view')
                    valid = valid and row.get('decision') == ('block' if event == 'preToolUse' else 'would_block')
                    valid = valid and row.get('enforcement') == ('supported' if event == 'preToolUse' else 'observe_only')
                    valid = valid and (denial(agent, result) if event == 'preToolUse' else result == neutral(agent, event))
                    self.check(f'{mode}/{agent}/{event}', valid and 'SYNTHETIC_' not in json.dumps(row) and SECRET not in json.dumps(row))

    def policy_controls(self):
        self.start(PATH_POLICY)
        for agent, form in FORMS:
            for decision in ('allow', 'deny'):
                path = '/synthetic/public.txt' if decision == 'allow' else '/synthetic/.env'
                count = len(rows(self.log))
                result = self.hook(agent, 'preToolUse', pre(agent, form, path))
                events = rows(self.log)
                row = events[-1]
                self.check(f'path/{agent}/{form}/{decision}', len(events) == count + 1 and row['agent'] == agent
                           and row['hook_event'] == 'preToolUse' and row['decision'] == ('allow' if decision == 'allow' else 'block')
                           and row['matched_rules'] == ([] if decision == 'allow' else ['private-path'])
                           and (result == neutral(agent) if decision == 'allow' else denial(agent, result)))
        for agent, tool in [('cursor', 'Shell'), ('copilot', 'bash'), ('copilot', 'powershell')]:
            for decision in ('allow', 'deny'):
                payload = pre(agent)
                payload['tool_name' if agent == 'cursor' else 'toolName'] = tool
                args = {'command': 'echo SMOKE_DENY' if decision == 'deny' else 'echo SMOKE_SAFE'}
                payload['tool_input' if agent == 'cursor' else 'toolArgs'] = args if agent == 'cursor' else json.dumps(args)
                count = len(rows(self.log))
                result = self.hook(agent, 'preToolUse', payload)
                events = rows(self.log)
                row = events[-1]
                self.check(f'shell/{tool}/{decision}', len(events) == count + 1 and row['agent'] == agent and row['tool_name'] == tool
                           and row['decision'] == ('block' if decision == 'deny' else 'allow')
                           and row['matched_rules'] == (['shell-marker'] if decision == 'deny' else [])
                           and (denial(agent, result) if decision == 'deny' else result == neutral(agent)))

    def raw_patch(self):
        # Captured native shape: Copilot CLI 1.0.105 Windows ARM64 emitted
        # apply_patch toolArgs as freeform text, not a JSON-encoded object.
        original = fixture('copilot', 'raw-patch')
        require('raw-patch-fixture', original['toolName'] == 'apply_patch'
                and original['toolArgs'] == '*** Begin Patch\n*** Add File: copilot-allow-1029.txt\n+COPILOT_ALLOW_1029\n*** End Patch\n')
        self.start(PATH_POLICY)
        for case, event, blocked in [('allow', 'preToolUse', False), ('deny', 'preToolUse', True),
                                      ('post', 'postToolUse', True)]:
            payload = dict(original)
            if blocked:
                payload['toolArgs'] = payload['toolArgs'].replace('copilot-allow-1029.txt', '.env')
            count = len(rows(self.log))
            result = self.hook('copilot', event, payload)
            events = rows(self.log)
            row = events[-1]
            preventive = event == 'preToolUse'
            self.check(f'copilot/raw-patch/{case}', len(events) == count + 1 and row.get('agent') == 'copilot'
                       and row.get('hook_event') == event and row.get('tool_name') == 'apply_patch'
                       and row.get('session_id') == original['sessionId'] and 'content' not in row
                       and row.get('phase') == ('pre' if preventive else 'post')
                       and row.get('enforcement') == ('supported' if preventive else 'observe_only')
                       and row.get('decision') == ('block' if blocked and preventive else 'would_block' if blocked else 'allow')
                       and row.get('matched_rules') == (['private-path'] if blocked else [])
                       and (denial('copilot', result) if blocked and preventive else result == {}))
        for mode in ('metadata', 'capture'):
            self.start(PATH_POLICY, capture=mode == 'capture')
            payload = dict(original)
            payload['toolArgs'] = payload['toolArgs'].replace('*** End Patch', f'+api_key={RAW_PATCH_SECRET}\n*** End Patch')
            count = len(rows(self.log))
            result = self.hook('copilot', 'preToolUse', payload)
            events = rows(self.log)
            row = events[-1]
            metadata = {key: value for key, value in row.items() if key != 'content'}
            valid = (len(events) == count + 1 and result == {} and row.get('decision') == 'allow'
                     and row.get('matched_rules') == [] and RAW_PATCH_SECRET not in json.dumps(row)
                     and 'COPILOT_ALLOW_1029' not in json.dumps(metadata))
            if mode == 'capture':
                captured = row.get('content', {}).get('toolArgs')
                valid = (valid and isinstance(captured, str) and 'COPILOT_ALLOW_1029' in captured
                         and '[REDACTED]' in captured)
            else:
                valid = valid and 'content' not in row
            self.check(f'copilot/raw-patch/{mode}', valid)
        self.start(PATH_POLICY)
        for kind in ('truncated', 'other-tool', 'oversize', 'unknown-header'):
            payload = dict(original)
            if kind == 'truncated':
                payload['toolArgs'] = payload['toolArgs'].replace('*** End Patch\n', '')
            elif kind == 'other-tool':
                payload['toolName'] = 'view'
            elif kind == 'oversize':
                payload['toolArgs'] = '*** Begin Patch\n*** Add File: safe.txt\n+' + 'x' * (1024 * 1024) + '\n*** End Patch\n'
            else:
                payload['toolArgs'] = payload['toolArgs'].replace('*** Add File:', '*** Unknown File:')
            before = self.log.read_bytes()
            result = self.hook('copilot', 'preToolUse', payload)
            self.check(f'copilot/raw-patch/{kind}', denial('copilot', result) and self.log.read_bytes() == before)

    def malformed(self):
        for agent in AGENTS:
            for kind in BAD:
                payload = pre(agent)
                if kind == 'json':
                    payload = b'{PRIVATE_BAD_JSON'
                elif kind == 'tool-name':
                    del payload['tool_name' if agent == 'cursor' else 'toolName']
                elif kind == 'tool-args':
                    payload['tool_input' if agent == 'cursor' else 'toolArgs'] = []
                elif kind == 'mismatch':
                    payload['hook_event_name'] = 'postToolUse'
                else:
                    payload = b'x' * (1024 * 1024 + 1)
                before = self.log.read_bytes()
                result = self.hook(agent, 'preToolUse', payload)
                self.check(f'malformed/{agent}/{kind}', denial(agent, result) and self.log.read_bytes() == before)
        for kind, args in [('string', '{PRIVATE_BAD_JSON'), ('depth', '{"path":' + '[' * 65 + '0' + ']' * 65 + '}')]:
            payload = pre('copilot')
            payload['toolArgs'] = args
            before = self.log.read_bytes()
            result = self.hook('copilot', 'preToolUse', payload)
            self.check(f'malformed/copilot/{kind}', denial('copilot', result) and self.log.read_bytes() == before)
        before = self.log.read_bytes()
        code, out, _ = self.run('hook', '--agent', 'copilot', payload=pre('copilot'))
        self.check('copilot/event-required', code != 0 and not out.strip() and self.log.read_bytes() == before)
        count = len(rows(self.log))
        result = self.hook('cursor', None, pre('cursor'))
        self.check('cursor/native-event', result == {'permission': 'allow'} and len(rows(self.log)) == count + 1
                   and rows(self.log)[-1]['hook_event'] == 'preToolUse')

    def missing_library(self):
        missing = self.directory / "missing library's space"
        missing.mkdir()
        binary = missing / self.binary.name
        shutil.copy2(self.binary, binary)
        for agent in AGENTS:
            before = self.log.read_bytes()
            result = self.hook(agent, 'preToolUse', pre(agent), binary=binary)
            self.check(f'missing-library/{agent}', not (missing / LIBRARY).exists() and denial(agent, result) and self.log.read_bytes() == before)

    def capture(self):
        self.start(PATH_POLICY, capture=True)
        for agent, form in FORMS:
            payload = pre(agent, form)
            args = {'path': '/synthetic/.env', 'api_key': SECRET, 'ordinary': BODY}
            payload['tool_input' if agent == 'cursor' else 'toolArgs'] = json.dumps(args) if form == 'string' else args
            payload.update(api_key=SECRET, toolResult={'api_key': SECRET, 'textResultForLlm': BODY})
            if agent == 'cursor':
                payload['hook_event_name'] = 'postToolUse'
            count = len(rows(self.log))
            result = self.hook(agent, 'postToolUse', payload)
            events = rows(self.log)
            row = events[-1]
            self.check(f'capture/{agent}/{form}', result == {} and len(events) == count + 1 and row['agent'] == agent
                       and row['hook_event'] == 'postToolUse' and row['decision'] == 'would_block'
                       and row['enforcement'] == 'observe_only' and row['content']['api_key'] == '[REDACTED]'
                       and BODY in json.dumps(row['content']) and SECRET not in json.dumps(row)
                       and (isinstance(row['content']['toolArgs'], str) if form == 'string' else True))

    def structured_privacy(self):
        # N1: encoded toolArgs must get the same structured key filtering as
        # objects. Plain invented values avoid triggering credential regexes.
        arguments = {'path': '/synthetic/public.txt', 'api_key': PRIVACY_SECRETS[0],
                     'private_key': PRIVACY_SECRETS[1],
                     'auth': {'profile': {'opaque': PRIVACY_SECRETS[2]},
                              'members': [{'note': PRIVACY_SECRETS[3]}]},
                     'ordinary': 'VISIBLE_CONTROL'}
        expected_capture = {'path': '/synthetic/public.txt', 'api_key': '[REDACTED]',
                            'private_key': '[REDACTED]', 'auth': '[REDACTED]',
                            'ordinary': 'VISIBLE_CONTROL'}
        for mode in ('metadata', 'capture'):
            self.start(PATH_POLICY, capture=mode == 'capture')
            for form in PRIVACY_FORMS:
                encoded = json.dumps(arguments)
                if form == 'escaped-key':
                    encoded = encoded.replace('"private_key"', r'"\u0070rivate_key"')
                    encoded = encoded.replace('"api_key"', r'"\u0061pi_key"').replace('"auth"', r'"\u0061uth"')
                    require('escaped-key-fixture', r'\u0070rivate_key' in encoded and json.loads(encoded) == arguments)
                for control in ('repeated-secret', 'ordinary-id'):
                    payload = pre('copilot')
                    payload['toolArgs'] = arguments if form == 'object' else encoded
                    payload['sessionId'] = ('session-' + PRIVACY_SECRETS[0] if control == 'repeated-secret'
                                            else 'session-ordinary-native')
                    count = len(rows(self.log))
                    result = self.hook('copilot', 'preToolUse', payload)
                    events = rows(self.log)
                    row = events[-1]
                    metadata = {key: value for key, value in row.items() if key != 'content'}
                    safe_metadata = json.dumps(metadata)
                    valid = (result == {} and len(events) == count + 1 and row.get('agent') == 'copilot'
                             and row.get('hook_event') == 'preToolUse' and row.get('decision') == 'allow'
                             and row.get('matched_rules') == [] and row.get('tool_name') == 'view'
                             and all(secret not in safe_metadata for secret in PRIVACY_SECRETS)
                             and 'VISIBLE_CONTROL' not in safe_metadata)
                    valid = valid and ('session_id' not in row if control == 'repeated-secret'
                                       else row.get('session_id') == 'session-ordinary-native')
                    if mode == 'metadata':
                        valid = valid and 'content' not in row
                    else:
                        captured = row.get('content', {}).get('toolArgs')
                        valid = valid and isinstance(captured, dict if form == 'object' else str)
                        parsed = json.loads(captured) if isinstance(captured, str) else captured
                        # Retain wire representation and ordinary values, redact
                        # whole auth containers (including harmless-looking keys).
                        valid = valid and parsed == expected_capture
                        valid = valid and all(secret not in json.dumps(row) for secret in PRIVACY_SECRETS[1:])
                        # The original sessionId can remain in opt-in content;
                        # this regression concerns its filtered metadata copy.
                    self.check(f'privacy/copilot/{form}/{mode}/{control}', valid)

    def execute(self):
        self.disabled('inactive')
        self.configurations()
        self.fixtures()
        self.policy_controls()
        self.raw_patch()
        self.malformed()
        self.missing_library()
        self.capture()
        self.structured_privacy()
        require('state-stop', self.json_run('stop').get('enabled') is False)
        self.disabled('stopped')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target' / 'debug' / ('agent-lens.exe' if os.name == 'nt' else 'agent-lens'))
    parser.add_argument('--report', type=Path, help='write a safe synthetic summary JSON')
    args = parser.parse_args()
    passed, hashes, failure = [], {}, None
    try:
        require('expected-inventory', len(EXPECTED) == EXPECTED_COUNT and len(CASES['cursor']) == 11 and len(CASES['copilot']) == 12)
        with tempfile.TemporaryDirectory(prefix="agent lens native's ") as temporary:
            smoke = Smoke(args.binary.resolve(strict=True), Path(temporary).resolve())
            passed, hashes = smoke.passed, smoke.hashes
            smoke.execute()
            require('assertion-inventory', set(passed) == EXPECTED)
    except Failure as error:
        failure = str(error)
    except Exception as error:
        failure = 'harness-' + type(error).__name__
    report = {'result': 'FAIL' if failure else 'PASS', 'expected_assertions': EXPECTED_COUNT,
              'passed_assertions': len(passed), 'failure': failure, 'platform': sys.platform,
              'artifact_sha256': hashes, 'passed': passed,
              'limitations': 'Direct CLI/library callback and generated config replay only. No vendor dispatch, native tool side effect, account, API, or untested-platform enforcement claim.'}
    rendered = json.dumps(report, indent=2) + '\n'
    if args.report:
        try:
            args.report.write_text(rendered, encoding='utf-8')
        except OSError:
            report.update(result='FAIL', failure='report-write')
            rendered = json.dumps(report, indent=2) + '\n'
            failure = 'report-write'
    print(rendered, end='')
    return 1 if failure else 0


if __name__ == '__main__':
    raise SystemExit(main())
