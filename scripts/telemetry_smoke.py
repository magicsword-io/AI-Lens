#!/usr/bin/env python3
"""Offline real-CLI telemetry regression: synthetic data and loopback HTTP only."""
import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'examples' / 'telemetry'
OTLP = ('claude-code-otel', 'claude-cowork-otel', 'codex-otel', 'cursor-runtime', 'copilot-otel')
POLL = ('cursor-audit', 'copilot-audit', 'anthropic-compliance', 'openai-audit', 'google-gemini')
SOURCES = OTLP + POLL + ('copilot-session',)
SIGNALS = ('logs', 'metrics', 'traces')
REJECTS = ('json', 'shape', 'protobuf', 'content-type', 'oversize', 'chunked', 'gzip')
SENTINEL = 'PRIVATE_SMOKE_CONTENT'
FIXTURE_CASES = (
    ('claude-code-otel', 'otlp-claude-code-logs.json', 'logs', 'api_request', None),
    ('claude-cowork-otel', 'otlp-claude-cowork-logs.json', 'logs', 'tool_result', None),
    ('codex-otel', 'otlp-codex-logs.json', 'logs', 'codex.tool_result', None),
    ('cursor-runtime', 'otlp-cursor-logs.json', 'logs', 'cursor.api.request', None),
    ('copilot-otel', 'otlp-claude-code-traces.json', 'traces', 'claude_code.tool', None),
    ('cursor-audit', 'audit-cursor.json', None, 'login', 'cursor-event-1'),
    ('copilot-audit', 'audit-copilot.json', None, 'copilot.cfb_seat_added', 'github-event-1'),
    ('anthropic-compliance', 'audit-anthropic.json', None, 'claude_chat_created', 'activity-1'),
    ('openai-audit', 'audit-openai.json', None, 'project.created', 'audit-1'),
    ('google-gemini', 'audit-google.json', None, 'feature_utilization', '10001'),
    ('copilot-session', 'audit-copilot-session.json', None, 'request', 'session-event-1'),
)
EXPECTED = set(('inventory jsonl-valid jsonl-syntax-atomic jsonl-shape-atomic input-output '
                'input-output-hardlink partial-output bind-loopback listen-limit otlp-signal audit-signal audit-protobuf '
                'unknown-source listener-ready listener-exit poll-limit poll-first-page poll-resume '
                'poll-complete-noop poll-query poll-credential poll-privacy').split())
EXPECTED.update('fixture/' + s for s in SOURCES)
EXPECTED.update('no-listen/' + s for s in POLL + ('copilot-session',))
EXPECTED.update('no-poll/' + s for s in OTLP + ('copilot-session',))
EXPECTED.update(f'{mode}/{signal}' for mode in ('json-import', 'protobuf-import', 'http-json', 'http-protobuf') for signal in SIGNALS)
EXPECTED.update(f'{mode}/{kind}' for mode in ('reject', 'recover') for kind in REJECTS)
EXPECTED_COUNT = 71


class Failure(Exception):
    """Contains only an authored case label, never process output or credentials."""


def encode(value):
    return json.dumps(value, separators=(',', ':')).encode('utf-8')


def rows(path):
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def private_free(value):
    data = json.dumps(value)
    return 'PRIVATE' not in data and 'sk-proj-smoke-placeholder' not in data


def observation(event, source):
    return (event.get('schema') == 'agent-lens.telemetry.v1' and event.get('schema_version') == 1
            and event.get('source') == source and event.get('enforcement') == 'observe_only'
            and bool(event.get('observed_at')) and private_free(event))


def poison(value):
    if isinstance(value, list):
        return [poison(item) for item in value]
    if not isinstance(value, dict):
        return value
    out = {key: poison(item) for key, item in value.items()}
    out['unknown_content'] = SENTINEL
    if isinstance(out.get('attributes'), list):
        out['attributes'] += [
            {'key': 'prompt', 'value': {'stringValue': SENTINEL}},
            {'key': 'service.version', 'value': {'stringValue': 'sk-proj-smoke-placeholder'}},
        ]
    if 'logRecords' in out:
        for record in out['logRecords']:
            # Cursor uses an exact constant body as its event label; keep that label.
            record['tool_input'] = SENTINEL
    return out


# Independent wire encoder, using official opentelemetry-proto v1 field numbers:
# https://github.com/open-telemetry/opentelemetry-proto/tree/v1.9.0/opentelemetry/proto
# Export field1 -> Resource field2 -> Scope field2 -> record, for each signal.
def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def field(number, value, wire=2):
    if isinstance(value, str):
        value = value.encode('utf-8')
    body = varint(len(value)) + value if wire == 2 else varint(value) if wire == 0 else struct.pack('<Q', value)
    return varint(number * 8 + wire) + body


def wire_and_json(signal):
    attr = {'key': 'event.name', 'value': {'stringValue': 'smoke.log'}}
    if signal == 'logs':
        record = field(1, 10, 1) + field(2, 9, 0) + field(5, field(1, SENTINEL))
        record += field(6, field(1, 'event.name') + field(2, field(1, 'smoke.log')))
        data = {'timeUnixNano': '10', 'severityNumber': 9, 'body': {'stringValue': SENTINEL}, 'attributes': [attr]}
        root, scope, key = 'resourceLogs', 'scopeLogs', 'logRecords'
    elif signal == 'metrics':
        point = field(3, 10, 1) + field(6, 7, 1)  # NumberDataPoint.as_int: sfixed64.
        record = field(1, 'smoke.metric') + field(5, field(1, point))
        data = {'name': 'smoke.metric', 'gauge': {'dataPoints': [{'timeUnixNano': '10', 'asInt': '7'}]}}
        root, scope, key = 'resourceMetrics', 'scopeMetrics', 'metrics'
    else:
        record = field(1, b'\x11' * 16) + field(2, b'\x22' * 8) + field(5, 'smoke.span')
        record += field(7, 10, 1) + field(8, 20, 1) + field(15, field(2, SENTINEL) + field(3, 1, 0))
        data = {'name': 'smoke.span', 'traceId': '11' * 16, 'spanId': '22' * 8,
                'startTimeUnixNano': '10', 'endTimeUnixNano': '20', 'status': {'code': 1, 'message': SENTINEL}}
        root, scope, key = 'resourceSpans', 'scopeSpans', 'spans'
    return field(1, field(2, field(2, record))), {root: [{scope: [{key: [data]}]}]}


def wire_observation(event, signal):
    if not observation(event, 'codex-otel') or event.get('signal') != signal:
        return False
    if signal == 'logs':
        return event.get('event_name') == 'smoke.log' and event.get('timestamp_unix_nano') == '10' and event.get('severity_number') == 9
    if signal == 'metrics':
        return event.get('event_name') == 'smoke.metric' and event.get('metric', {}).get('value') == 7
    return (event.get('event_name') == 'smoke.span' and event.get('trace_id') == '11' * 16
            and event.get('span_id') == '22' * 8 and event.get('start_time_unix_nano') == '10'
            and event.get('end_time_unix_nano') == '20' and event.get('status_code') == 1)


class Smoke:
    def __init__(self, binary, directory):
        self.binary, self.directory, self.passed = binary, directory, []
        self.env = dict(os.environ)
        for name in ('OPENAI_ADMIN_KEY', 'ANTHROPIC_COMPLIANCE_ACCESS_KEY', 'GOOGLE_ACCESS_TOKEN', 'CURSOR_ADMIN_API_KEY', 'GITHUB_TOKEN'):
            self.env.pop(name, None)
        self.env['OPENAI_ADMIN_KEY'] = 'PRIVATE_ENV_MUST_NOT_BE_USED'

    def check(self, name, condition):
        if name not in EXPECTED or name in self.passed or not condition:
            raise Failure(name)
        self.passed.append(name)

    def command(self, *args):
        return [str(self.binary), '--state', str(self.directory / 'state'), 'telemetry', *map(str, args)]

    def run(self, *args):
        return subprocess.run(self.command(*args), env=self.env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=20, check=False)

    def imported(self, source, data, name, signal=None, fmt='json', output=None):
        path = self.directory / (name + '.input')
        path.write_bytes(data if isinstance(data, bytes) else encode(data))
        output = output or self.directory / (name + '.jsonl')
        args = ['import', '--source', source, '--input', path, '--output', output, '--format', fmt]
        if signal:
            args += ['--signal', signal]
        return self.run(*args), output, path

    def imports(self):
        result = self.run('sources')
        inventory = json.loads(result.stdout)['sources']
        expected_modes = {s: ['import', 'listen'] for s in OTLP}
        expected_modes.update({s: ['import', 'poll'] for s in POLL})
        expected_modes['copilot-session'] = ['import']
        self.check('inventory', result.returncode == 0 and len(inventory) == 11 and
                   {r['id']: r['modes'] for r in inventory} == expected_modes and
                   all(r['enforcement'] == 'observe_only' for r in inventory))
        for source, filename, signal, event_name, event_id in FIXTURE_CASES:
            data = poison(json.loads((FIXTURES / filename).read_text(encoding='utf-8')))
            result, output, _ = self.imported(source, data, source, signal)
            events = rows(output) if output.exists() else []
            valid = len(events) == 1 and observation(events[0], source) and events[0]['event_name'] == event_name
            if valid and event_id:
                valid = events[0].get('event_id') == event_id and 'timestamp' in events[0]
            if valid and source == 'cursor-runtime':
                valid = events[0]['attributes'].get('cursor.event.id') == 'customer-telemetry:v1:synthetic-001'
            self.check('fixture/' + source, result.returncode == 0 and valid and private_free(result.stdout.decode()))
        for signal in SIGNALS:
            binary, payload = wire_and_json(signal)
            json_result, json_output, _ = self.imported('codex-otel', payload, 'json-' + signal, signal)
            j = rows(json_output)
            self.check('json-import/' + signal, json_result.returncode == 0 and len(j) == 1 and wire_observation(j[0], signal))
            result, output, _ = self.imported('codex-otel', binary, 'binary-' + signal, signal, 'protobuf')
            b = rows(output)
            stable = lambda events: [{k: v for k, v in event.items() if k != 'observed_at'} for event in events]
            self.check('protobuf-import/' + signal, result.returncode == 0 and stable(b) == stable(j) and wire_observation(b[0], signal))
        payload = wire_and_json('logs')[1]
        line = encode(payload) + b'\n'
        result, output, _ = self.imported('codex-otel', line * 2, 'jsonl-valid', 'logs', 'jsonl')
        self.check('jsonl-valid', result.returncode == 0 and len(rows(output)) == 2 and all(wire_observation(r, 'logs') for r in rows(output)))
        for kind, bad in [('syntax', b'{PRIVATE'), ('shape', b'{"resourceLogs":{}}')]:
            output = self.directory / ('atomic-' + kind)
            seed = b'{"prior":"synthetic"}\n'
            output.write_bytes(seed)
            result, _, _ = self.imported('codex-otel', line + bad, kind, 'logs', 'jsonl', output)
            self.check('jsonl-' + kind + '-atomic', result.returncode != 0 and output.read_bytes() == seed and SENTINEL.encode() not in result.stderr)
        path = self.directory / 'same.json'
        path.write_bytes(encode(payload))
        before = path.read_bytes()
        result = self.run('import', '--source', 'codex-otel', '--signal', 'logs', '--input', path, '--output', path)
        self.check('input-output', result.returncode != 0 and path.read_bytes() == before)
        # A trailing newline would permit accidental append if only path names were checked.
        path.write_bytes(before + b'\n')
        alias = self.directory / 'hardlink-output.jsonl'
        os.link(path, alias)
        result = self.run('import', '--source', 'codex-otel', '--signal', 'logs', '--input', path, '--output', alias)
        self.check('input-output-hardlink', result.returncode != 0 and path.read_bytes() == before + b'\n'
                   and b'distinct files' in result.stderr)
        output = self.directory / 'partial.jsonl'
        output.write_bytes(b'{"incomplete":')
        result, _, _ = self.imported('codex-otel', payload, 'partial', 'logs', output=output)
        self.check('partial-output', result.returncode != 0 and output.read_bytes() == b'{"incomplete":')

    def restrictions(self):
        out = self.directory / 'restricted.jsonl'
        for source in POLL + ('copilot-session',):
            r = self.run('listen', '--source', source, '--bind', '127.0.0.1:0', '--output', out, '--max-requests', 1)
            self.check('no-listen/' + source, r.returncode != 0 and b'listener requires an OTLP source' in r.stderr and not out.exists())
        for source in OTLP + ('copilot-session',):
            r = self.run('poll', '--source', source, '--output', out, '--test-endpoint', 'http://127.0.0.1:1/audit')
            self.check('no-poll/' + source, r.returncode != 0 and b'source does not expose a supported polling API' in r.stderr and not out.exists())
        for label, extra in [('bind-loopback', ['--bind', '0.0.0.0:0']), ('listen-limit', ['--max-requests', '0'])]:
            r = self.run('listen', '--source', 'codex-otel', '--output', out, *extra)
            self.check(label, r.returncode != 0 and not out.exists())
        source_file = self.directory / 'json-logs.input'
        for label, source, extra in [('otlp-signal', 'codex-otel', []), ('audit-signal', 'openai-audit', ['--signal', 'logs']),
                                     ('audit-protobuf', 'openai-audit', ['--format', 'protobuf']), ('unknown-source', 'unknown', [])]:
            r = self.run('import', '--source', source, '--input', source_file, '--output', out, *extra)
            self.check(label, r.returncode != 0 and not out.exists())

    @contextmanager
    def listener(self, requests, output):
        with tempfile.TemporaryFile() as errors:
            process = subprocess.Popen(self.command('listen', '--source', 'codex-otel', '--bind', '127.0.0.1:0',
                                                   '--output', output, '--max-requests', requests),
                                       env=self.env, stdout=subprocess.PIPE, stderr=errors)
            ready = queue.Queue(maxsize=1)
            reader = threading.Thread(target=lambda: ready.put(process.stdout.readline(8193)), daemon=True)
            reader.start()
            try:
                line = ready.get(timeout=10)
                data = json.loads(line) if len(line) <= 8192 else {}
                address = data.get('listening', '').split(':')
                self.check('listener-ready', len(address) == 2 and address[0] == '127.0.0.1'
                           and data.get('source') == 'codex-otel' and data.get('enforcement') == 'observe_only')
                yield (address[0], int(address[1]))
                self.check('listener-exit', process.wait(timeout=10) == 0)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                process.stdout.close()
                reader.join(timeout=1)

    def http(self):
        output = self.directory / 'listener.jsonl'
        with self.listener(6 + 2 * len(REJECTS), output) as address:
            for signal in SIGNALS:
                binary, payload = wire_and_json(signal)
                for fmt, body in [('json', encode(payload)), ('protobuf', binary)]:
                    before = len(rows(output))
                    reply = exchange(address, signal, body, 'application/json' if fmt == 'json' else 'application/x-protobuf')
                    events = rows(output)
                    self.check('http-' + fmt + '/' + signal, reply[0] == 200 and reply[2] == (b'{}' if fmt == 'json' else b'')
                               and reply[1] == ('application/json' if fmt == 'json' else 'application/x-protobuf')
                               and len(events) == before + 1 and wire_observation(events[-1], signal))
            good = encode(wire_and_json('logs')[1])
            cases = [('json', b'{PRIVATE', 'application/json', {}), ('shape', b'{"resourceLogs":{}}', 'application/json', {}),
                     ('protobuf', b'\xff\xff', 'application/x-protobuf', {}), ('content-type', b'', 'text/plain', {}),
                     ('oversize', b'', 'application/json', {'Content-Length': str(8 * 1024 * 1024 + 1)}),
                     ('chunked', b'0\r\n\r\n', 'application/json', {'Transfer-Encoding': 'chunked'}),
                     ('gzip', b'not-gzip', 'application/json', {'Content-Encoding': 'gzip'})]
            for kind, body, mime, headers in cases:
                before = output.read_bytes()
                reply = exchange(address, 'logs', body, mime, headers)
                self.check('reject/' + kind, reply[0] == 400 and output.read_bytes() == before and b'PRIVATE' not in reply[2])
                reply = exchange(address, 'logs', good, 'application/json')
                events = rows(output)
                self.check('recover/' + kind, reply[0] == 200 and len(events) == len(before.splitlines()) + 1
                           and wire_observation(events[-1], 'logs'))

    def polling(self):
        output, checkpoint = self.directory / 'poll.jsonl', self.directory / 'checkpoint.json'
        with mock_audit() as (endpoint, requests):
            args = ['poll', '--source', 'openai-audit', '--output', output, '--checkpoint', checkpoint,
                    '--test-endpoint', endpoint, '--since', '2026-10-01T00:00:00Z', '--until', '2026-10-02T00:00:00Z', '--max-pages', 1]
            first = self.run(*args)
            self.check('poll-limit', first.returncode != 0 and b'page limit reached' in first.stderr)
            cp = json.loads(checkpoint.read_bytes())
            self.check('poll-first-page', [r['event_id'] for r in rows(output)] == ['page-1']
                       and cp['cursor'] == 'page-1' and cp['done'] is False and cp['output_len'] == output.stat().st_size)
            resumed = self.run(*args)
            cp = json.loads(checkpoint.read_bytes())
            self.check('poll-resume', resumed.returncode == 0 and cp['done'] is True and cp['cursor'] is None
                       and [r['event_id'] for r in rows(output)] == ['page-1', 'page-2'])
            before, saved = output.read_bytes(), checkpoint.read_bytes()
            finished = self.run(*args)
            self.check('poll-complete-noop', finished.returncode == 0 and len(requests) == 2
                       and output.read_bytes() == before and checkpoint.read_bytes() == saved)
            queries = [parse_qs(urlsplit(path).query) for path, _ in requests]
            self.check('poll-query', len(queries) == 2 and 'after' not in queries[0] and queries[1].get('after') == ['page-1']
                       and all(q.get('limit') == ['100'] and q.get('effective_at[gte]') == ['1790812800']
                               and q.get('effective_at[lte]') == ['1790899200'] for q in queries))
            self.check('poll-credential', len(requests) == 2 and all(auth == 'Bearer agent-lens-offline-test' for _, auth in requests))
            self.check('poll-privacy', all(observation(r, 'openai-audit') for r in rows(output))
                       and private_free(cp) and all(b'PRIVATE' not in r.stdout + r.stderr for r in (first, resumed, finished)))


def exchange(address, signal, body, mime, extra=None):
    headers = {'Host': '127.0.0.1', 'Content-Type': mime, 'Content-Length': str(len(body)), 'Connection': 'close'}
    headers.update(extra or {})
    request = (f'POST /v1/{signal} HTTP/1.1\r\n' + ''.join(f'{k}: {v}\r\n' for k, v in headers.items()) + '\r\n').encode() + body
    with socket.create_connection(address, timeout=8) as connection:
        connection.settimeout(8)
        connection.sendall(request)
        response = bytearray()
        while len(response) < 65536:
            try:
                chunk = connection.recv(4096)
            except ConnectionResetError:
                break  # Rejected requests may close with unread request body.
            if not chunk:
                break
            response.extend(chunk)
    if b'\r\n\r\n' not in response:
        raise Failure('http-response-header')
    header, content = bytes(response).split(b'\r\n\r\n', 1)
    lines = header.decode('ascii').split('\r\n')
    fields = dict(line.lower().split(': ', 1) for line in lines[1:])
    if len(content) != int(fields['content-length']):
        raise Failure('http-framing')
    return int(lines[0].split()[1]), fields['content-type'], content


@contextmanager
def mock_audit():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(8)

        def do_GET(self):
            requests.append((self.path, self.headers.get('Authorization')))
            page = 2 if parse_qs(urlsplit(self.path).query).get('after') == ['page-1'] else 1
            body = encode({'data': [{'id': f'page-{page}', 'type': 'project.created', 'effective_at': 1790812800,
                                    'prompt': SENTINEL, 'actor': {'type': 'session', 'session': {'user': {'id': 'synthetic-user', 'email': SENTINEL}}}}],
                           'has_more': page == 1, 'last_id': f'page-{page}'})
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}/audit', requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        if thread.is_alive():
            raise Failure('mock-server-cleanup')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target' / 'debug' / ('agent-lens.exe' if os.name == 'nt' else 'agent-lens'))
    parser.add_argument('--report', type=Path, help='write safe synthetic assertion summary JSON')
    args = parser.parse_args()
    passed, failure, digest = [], None, None
    try:
        if len(EXPECTED) != EXPECTED_COUNT or len(SOURCES) != 11:
            raise Failure('expected-inventory')
        binary = args.binary.resolve(strict=True)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix='agent lens telemetry ') as temporary:
            smoke = Smoke(binary, Path(temporary))
            passed = smoke.passed
            smoke.imports()
            smoke.restrictions()
            smoke.http()
            smoke.polling()
            if set(passed) != EXPECTED:
                raise Failure('assertion-inventory')
    except Failure as error:
        failure = str(error)
    except Exception as error:
        failure = 'harness-' + type(error).__name__  # Never print exception text or raw CLI output.
    report = {'result': 'FAIL' if failure else 'PASS', 'expected_assertions': EXPECTED_COUNT,
              'passed_assertions': len(passed), 'failure': failure, 'sources': list(SOURCES),
              'platform': sys.platform, 'binary_sha256': digest, 'passed': passed,
              'limitations': 'Synthetic local protocol replay only; no live vendor/account delivery or cross-platform validation claim.'}
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
