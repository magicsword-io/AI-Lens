#!/usr/bin/env python3
"""Verify checksum, extract the native ZIP, and run its EXE with its own DLL."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from windows_cleanup import TemporaryDirectory
import zipfile

root = Path(__file__).resolve().parents[1]
manifest = root / 'dist' / 'SHA256SUMS'
entries = manifest.read_text().splitlines()
assert entries, 'empty checksum manifest'
for entry in entries:
    expected, name = entry.split('  ', 1)
    archive = manifest.parent / name
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected, 'checksum mismatch'
    with TemporaryDirectory(prefix='agent lens package ') as temp:
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(temp)
            for info in bundle.infolist():
                if info.external_attr >> 16 & stat.S_IXUSR:
                    os.chmod(Path(temp) / info.filename, 0o755)
        package = Path(temp) / archive.stem
        assert (package / 'NOTICE').is_file(), 'license attribution missing from archive'
        assert 'Apache License' in (package / 'LICENSE').read_text(), 'Apache license missing'
        assert not (package / 'SECURITY.md').exists(), 'retired security policy still packaged'
        assert not (package / 'docs/telemetry-handoff.md').exists(), 'internal handoff still packaged'
        for evidence in sorted((root / 'docs/evidence').glob('*.json')):
            shipped = package / evidence.relative_to(root)
            assert shipped.is_file() and shipped.read_bytes() == evidence.read_bytes(), f'evidence missing or changed: {evidence.name}'
        binary = package / ('agent-lens.exe' if os.name == 'nt' else 'agent-lens')
        run = subprocess.run([str(binary), 'rules-check', '--rules', str(package / 'examples/rules/default.yaml')], capture_output=True, text=True, timeout=15)
        assert run.returncode == 0, run.stderr
        assert json.loads(run.stdout)['valid'] is True
        expected_packs = {case['pack'] for case in json.loads((root / 'examples/rule-cases.json').read_text())['cases']}
        actual_packs = {rules.name for rules in (package / 'examples' / 'rules').glob('*.yaml')}
        assert actual_packs == expected_packs, 'rule pack missing from archive'
        assert (package / 'examples/rule-cases.json').is_file(), 'missing educational fixtures'
        for rules in sorted((package / 'examples' / 'rules').glob('*.yaml')):
            run = subprocess.run([str(binary), 'rules-check', '--rules', str(rules)], capture_output=True, text=True, timeout=15)
            assert run.returncode == 0, f'{rules.name}: {run.stderr}'
            assert json.loads(run.stdout)['valid'] is True
        fixture = package / 'examples/events/gemini-pre-tool.json'
        assert fixture.is_file(), 'Gemini fixture missing from archive'
        state, log = Path(temp) / 'gemini-state', Path(temp) / 'gemini.jsonl'
        run = subprocess.run([str(binary), '--state', str(state), 'start', '--output', str(log),
                              '--rules', str(package / 'examples/rules/default.yaml')],
                             capture_output=True, text=True, timeout=15)
        assert run.returncode == 0, run.stderr
        run = subprocess.run([str(binary), '--state', str(state), 'hook', '--agent', 'gemini'],
                             input=fixture.read_text(), capture_output=True, text=True, timeout=15)
        assert run.returncode == 0, run.stderr
        assert json.loads(run.stdout).get('decision') == 'deny', 'packaged Gemini denial missing'
        row = json.loads(log.read_text().splitlines()[-1])
        assert row['agent'] == 'gemini' and row['decision'] == 'block'
        assert row['matched_rules'] == ['protect-env-files'] and 'content' not in row
        assert (package / 'examples/cowork-plugin/.claude-plugin/plugin.json').is_file(), 'Cowork manifest missing'
        assert (package / 'examples/cowork-plugin/README.md').is_file(), 'Cowork packaging guide missing'
        # Source-preview adapters must work using only extracted package files.
        for agent, event, fixture_name, decision_key in [
            ('cursor', 'preToolUse', 'cursor-pre-tool.json', 'permission'),
            ('copilot', 'preToolUse', 'copilot-pre-tool.json', 'permissionDecision'),
            ('cowork', 'PreToolUse', 'cowork-pre-tool.json', None),
        ]:
            fixture = package / 'examples/events' / fixture_name
            assert fixture.is_file(), f'{agent} fixture missing'
            run = subprocess.run([str(binary), '--state', str(state), 'hook', '--agent', agent, '--event', event],
                                 input=fixture.read_text(), capture_output=True, text=True, timeout=15)
            assert run.returncode == 0, run.stderr
            response = json.loads(run.stdout)
            native = response.get(decision_key) if decision_key else response.get('hookSpecificOutput', {}).get('permissionDecision')
            assert native == 'deny', f'packaged {agent} native denial missing'
            row = json.loads(log.read_text().splitlines()[-1])
            assert row['agent'] == agent and row['decision'] == 'block' and 'content' not in row
            run = subprocess.run([str(binary), '--state', str(state), 'config', '--agent', agent],
                                 capture_output=True, text=True, timeout=15)
            assert run.returncode == 0 and event in json.loads(run.stdout)['hooks']
        output = Path(temp) / 'packaged-demo.jsonl'
        run = subprocess.run([str(binary), 'demo', '--output', str(output)], capture_output=True, text=True, timeout=15)
        assert run.returncode == 0, run.stderr
        assert len(output.read_text().splitlines()) == 5
        # Exercise the shipped telemetry fixture with the extracted executable.
        telemetry = package / 'examples' / 'telemetry'
        assert (package / 'docs/telemetry-sources.md').is_file(), 'missing telemetry guide'
        assert {p.name for p in (telemetry / 'configs').iterdir()} == {
            'claude-code.env', 'claude-cowork.json', 'codex.toml',
            'cursor-export.json', 'copilot-otel.env', 'otel-collector.yaml',
        }, 'missing telemetry configuration example'
        telemetry_output = Path(temp) / 'packaged-telemetry.jsonl'
        run = subprocess.run([str(binary), 'telemetry', 'import', '--source', 'codex-otel',
                              '--signal', 'logs', '--input', str(telemetry / 'otlp-codex-logs.json'),
                              '--output', str(telemetry_output)],
                             capture_output=True, text=True, timeout=15)
        assert run.returncode == 0, run.stderr
        telemetry_rows = [json.loads(line) for line in telemetry_output.read_text().splitlines()]
        assert telemetry_rows and all(row['schema'] == 'agent-lens.telemetry.v1'
                                      and row['enforcement'] == 'observe_only'
                                      for row in telemetry_rows), 'packaged telemetry import failed'
        assert 'PRIVATE' not in telemetry_output.read_text(), 'packaged telemetry leaked fixture content'
    print(f'PASS packaged EXE/library/rules and SHA256: {name}')
