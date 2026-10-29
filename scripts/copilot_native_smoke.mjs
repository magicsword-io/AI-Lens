#!/usr/bin/env node
/**
 * Real Copilot CLI config/command hooks + native create tool, synthetic local model.
 * Pinned: CLI 1.0.105, SDK 1.0.28; no credentials or real provider calls.
 *
 * Setup (no lifecycle scripts, only isolated dependencies):
 * npm install --prefix .context/copilot-native/sdk --ignore-scripts --no-package-lock \
 *   --no-audit --no-fund --save-exact @github/copilot@1.0.105 @github/copilot-sdk@1.0.28
 * python3 scripts/copilot_native_offline.py --report .context/copilot-native/result.json
 * Requires an existing Agent Lens binary and adjacent engine library; does not build.
 * --binary PATH / AGENT_LENS_BIN selects an extracted package; --disable-policy
 * is an oracle mutation and MUST fail the blocked-file assertion.
 *
 * Linux only: refuses any network interface except loopback. The Python wrapper
 * creates that namespace; callers may instead supply their own isolated namespace.
 * All runtime state/transcripts are disposable and removed, never put in the report.
 * Official contracts: https://docs.github.com/en/copilot/reference/hooks-configuration
 * https://github.com/github/copilot-sdk/blob/e22b95e6ead5e1de7e9a68d3087b8d28dc5f364a/docs/auth/byok.md
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI_VERSION = '1.0.105', SDK_VERSION = '1.0.28';
const EVENTS = ['sessionStart', 'sessionEnd', 'preToolUse', 'postToolUse', 'postToolUseFailure',
  'errorOccurred', 'userPromptSubmitted', 'agentStop', 'subagentStart', 'subagentStop', 'preCompact', 'notification'];
const { values } = parseArgs({ options: {
  binary: { type: 'string', default: process.env.AGENT_LENS_BIN || path.join(ROOT, 'target/debug/agent-lens') },
  sdk: { type: 'string', default: path.join(ROOT, '.context/copilot-native/sdk/node_modules/@github/copilot-sdk') },
  cli: { type: 'string' },
  report: { type: 'string' },
  'disable-policy': { type: 'boolean', default: false },
  'isolated-child': { type: 'boolean', default: false },
} });

// Resolve caller-supplied paths before changing cwd or dropping environment.
for (const key of ['binary', 'sdk', 'cli', 'report']) if (values[key]) values[key] = path.resolve(values[key]);
if (!values['isolated-child']) {
  const env = {};
  if (process.env.PATH) env.PATH = process.env.PATH;
  const child = spawnSync(process.execPath,
    [fileURLToPath(import.meta.url), ...process.argv.slice(2), '--binary', values.binary,
      '--sdk', values.sdk, ...(values.cli ? ['--cli', values.cli] : []),
      ...(values.report ? ['--report', values.report] : []), '--isolated-child'],
    { cwd: ROOT, env, stdio: 'inherit', timeout: 110000 });
  if (child.error) console.error('Copilot native harness child could not complete.');
  process.exit(child.status ?? 1);
}

const report = { status: 'FAIL', evidence_level: 'native Copilot CLI config hooks and create tool with a synthetic loopback provider',
  copilot_cli: CLI_VERSION, copilot_sdk: SDK_VERSION, node: process.version,
  platform: process.platform, architecture: process.arch, mutation: values['disable-policy'], checks: [],
  not_tested: ['real provider or account', 'Windows/macOS', 'all lifecycle event delivery', 'vendor timeout behavior', 'Cowork Desktop'] };
let phase = 'network-isolation', base, binary, library, state, started = false;
let activeClient, activeServer;
function check(name, condition) {
  phase = name;
  assert.ok(condition, name);
  report.checks.push(name);
}
const digest = file => createHash('sha256').update(readFileSync(file)).digest('hex');
function host(...args) {
  phase = `host-${args[0]}`;
  const result = spawnSync(binary, ['--state', state, ...args],
    { cwd: base, env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 10000, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(result.status, 0);
  return JSON.parse(result.stdout);
}
const deadline = setTimeout(() => {
  // The wrapper's process-group timeout is the final cleanup bound.
  console.error('Copilot native harness exceeded its deadline.');
  process.exit(2);
}, 90000);
try {
  const interfaces = process.platform === 'linux' ? readFileSync('/proc/net/dev', 'utf8').trim()
    .split('\n').slice(2).map(line => line.split(':')[0].trim()) : [];
  check('loopback-only Linux namespace', interfaces.length === 1 && interfaces[0] === 'lo');
  phase = 'pinned-sdk';
  const packageInfo = JSON.parse(readFileSync(path.join(values.sdk, 'package.json'), 'utf8'));
  check('pinned SDK package', packageInfo.name === '@github/copilot-sdk' && packageInfo.version === SDK_VERSION);
  const cliCandidates = [path.join(path.dirname(values.sdk), `copilot-${process.platform}-${process.arch}`, 'copilot'),
    path.join(ROOT, '.context/copilot-native/package/package/copilot')];
  const cli = values.cli || cliCandidates.find(existsSync);
  check('vendor executable exists', Boolean(cli && existsSync(cli)));
  base = realpathSync(mkdtempSync(path.join(tmpdir(), "agent lens copilot 'quote' ")));
  const install = path.join(base, 'install');
  state = path.join(base, 'lens-state');
  mkdirSync(install);
  binary = path.join(install, 'agent-lens');
  library = path.join(install, 'libagent_lens_engine.so');
  copyFileSync(values.binary, binary);
  copyFileSync(path.join(path.dirname(values.binary), 'libagent_lens_engine.so'), library);
  report.binary_sha256 = digest(binary);
  report.library_sha256 = digest(library);
  report.vendor_cli_sha256 = digest(cli);
  const version = spawnSync(cli, ['--version'], { cwd: base, env: { PATH: process.env.PATH,
    COPILOT_HOME: path.join(base, 'version-state') }, encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
  check('pinned CLI executable version', version.status === 0 && /^GitHub Copilot CLI 1\.0\.105\./m.test(version.stdout));
  phase = 'import-sdk';
  const { CopilotClient, RuntimeConnection, approveAll } = await import(pathToFileURL(path.join(values.sdk, 'dist/index.js')).href);
  const log = path.join(base, 'events.jsonl'), rules = path.join(base, 'rules.yaml');
  // A path rule must stop the real create operation; no content-marker shortcut.
  writeFileSync(rules, 'version: 1\nrules:\n' +
    '- id: native-blocked-path\n  agents: [copilot]\n  events: [preToolUse]\n  tool_pattern: "^create$"\n  path_pattern: "(^|/)blocked[.]json$"\n  action: block\n' +
    '- id: native-post-observer\n  agents: [copilot]\n  events: [postToolUse]\n  tool_pattern: "^create$"\n  action: block\n');
  report.policy_sha256 = digest(rules);
  host('start', '--output', log, '--rules', rules); started = true;
  const config = host('config', '--agent', 'copilot');
  check('generated native registry', config.version === 1 &&
    JSON.stringify(Object.keys(config.hooks).sort()) === JSON.stringify([...EVENTS].sort()));
  for (const event of EVENTS) {
    const handler = config.hooks[event][0];
    check(`generated exec ${event}`, handler.exec === binary && handler.type === 'command' &&
      JSON.stringify(handler.args) === JSON.stringify(['--state', state, 'hook', '--agent', 'copilot', '--event', event]));
  }
  const rows = () => existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : [];
  const fixtureText = '{"message":"SYNTHETIC_NATIVE_COPILOT_BODY"}\n';
  const cases = [];
  report.cases = cases;
  async function runCase(name, filename) {
    phase = `${name}-setup`;
    const work = path.join(base, name), vendorState = path.join(base, `${name}-vendor-state`);
    mkdirSync(path.join(work, '.github/hooks'), { recursive: true });
    mkdirSync(vendorState);
    writeFileSync(path.join(work, '.github/hooks/lens.json'), JSON.stringify(config));
    const target = path.join(work, filename);
    let requests = 0, providerError = false, policyDenialSeen = false, failureDenialSeen = false;
    const server = http.createServer(async (request, response) => {
      try {
        if (request.method !== 'POST' || request.url !== '/v1/chat/completions') throw Error('unexpected request');
        const chunks = []; let size = 0;
        for await (const chunk of request) { size += chunk.length; if (size > 4 * 1024 * 1024) throw Error('body limit'); chunks.push(chunk); }
        const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (++requests > 2) throw Error('request limit');
        const tool = input.tools?.find(item => item.function?.name === 'create');
        if (!tool) throw Error('native create absent');
        if (requests === 1 && (!tool.function.parameters?.properties?.path || !tool.function.parameters?.properties?.file_text))
          throw Error('unexpected native create schema');
        if (requests === 2) {
          // Keep only fixed-string booleans. No request, session or transcript in report.
          const toolResults = input.messages.filter(item => item.role === 'tool').map(item => JSON.stringify(item.content)).join('\n');
          policyDenialSeen = toolResults.includes('Blocked by Agent Lens policy');
          failureDenialSeen = toolResults.includes('Agent Lens failed to evaluate or record this action. Check local diagnostics.');
        }
        const message = requests === 1 ? { role: 'assistant', content: null, tool_calls: [{
          id: 'synthetic-create', type: 'function', function: { name: 'create',
            arguments: JSON.stringify({ path: target, file_text: fixtureText }) },
        }] } : { role: 'assistant', content: 'Synthetic native check complete.' };
        const finish = requests === 1 ? 'tool_calls' : 'stop';
        if (input.stream) {
          response.writeHead(200, { 'content-type': 'text/event-stream' });
          const delta = requests === 1 ? { ...message, tool_calls: message.tool_calls.map((item, index) => ({ index, ...item })) } : message;
          for (const [data, reason] of [[delta, null], [{}, finish]]) response.write('data: ' + JSON.stringify({
            id: 'synthetic-completion', object: 'chat.completion.chunk', created: 1, model: 'synthetic-native',
            choices: [{ index: 0, delta: data, finish_reason: reason }],
          }) + '\n\n');
          response.end('data: [DONE]\n\n');
        } else {
          response.writeHead(200, { 'content-type': 'application/json' });
          response.end(JSON.stringify({ id: 'synthetic-completion', object: 'chat.completion', created: 1,
            model: 'synthetic-native', choices: [{ index: 0, message, finish_reason: finish }],
            usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }));
        }
      } catch { providerError = true; response.writeHead(400); response.end('{}'); }
    });
    server.requestTimeout = 10000; server.headersTimeout = 10000;
    activeServer = server;
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const env = { PATH: process.env.PATH, COPILOT_HOME: vendorState, XDG_CONFIG_HOME: vendorState,
      XDG_STATE_HOME: vendorState, XDG_CACHE_HOME: vendorState, GH_CONFIG_DIR: vendorState };
    const client = new CopilotClient({ connection: RuntimeConnection.forStdio({ path: cli,
      args: ['--disable-client-telemetry', '--disable-builtin-mcps'] }), baseDirectory: vendorState,
      workingDirectory: work, env, useLoggedInUser: false, logLevel: 'none' });
    activeClient = client;
    try {
      phase = `${name}-native-session`;
      const session = await client.createSession({ model: 'synthetic-native',
        provider: { type: 'openai', baseUrl: `http://127.0.0.1:${server.address().port}/v1`, wireApi: 'completions' },
        availableTools: ['create'], workingDirectory: work, trustWorkingDirectory: 'session', onPermissionRequest: approveAll });
      await session.sendAndWait({ prompt: 'Perform the synthetic create tool once.' }, 20000);
      await session.disconnect();
      check(`${name}: bounded synthetic model exchange`, requests === 2 && !providerError);
      const result = { name, model_requests: requests, file_created: existsSync(target), policy_denial_seen: policyDenialSeen,
        failure_denial_seen: failureDenialSeen };
      if (result.file_created) check(`${name}: exact harmless file content`, readFileSync(target, 'utf8') === fixtureText);
      cases.push(result);
      return result;
    } finally {
      await client.stop(); activeClient = undefined;
      server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); activeServer = undefined;
    }
  }
  const allowed = await runCase('allowed', 'allowed.json');
  check('native create positive control', allowed.file_created && !allowed.policy_denial_seen && !allowed.failure_denial_seen);
  let recorded = rows();
  check('native allowed pre-tool ledger', recorded.some(row => row.hook_event === 'preToolUse' &&
    row.tool_name === 'create' && row.decision === 'allow' && row.enforcement === 'supported'));
  check('native post-tool rule is observational', recorded.some(row => row.hook_event === 'postToolUse' &&
    row.tool_name === 'create' && row.decision === 'would_block' && row.enforcement === 'observe_only' &&
    row.matched_rules.includes('native-post-observer')));
  if (values['disable-policy']) host('stop');
  const denied = await runCase('denied', 'blocked.json');
  check('native blocked path has no side effect', !denied.file_created);
  check('native tool receives policy denial', denied.policy_denial_seen);
  recorded = rows();
  check('native blocked pre-tool ledger', recorded.some(row => row.hook_event === 'preToolUse' &&
    row.tool_name === 'create' && row.decision === 'block' && row.matched_rules.includes('native-blocked-path')));
  check('blocked tool has no success post event', recorded.filter(row => row.hook_event === 'postToolUse').length === 1);
  check('default ledger excludes content', recorded.every(row => !('input' in row) && !('payload' in row) && !('content' in row)) &&
    !readFileSync(log, 'utf8').includes('SYNTHETIC_NATIVE_COPILOT_BODY'));
  rmSync(library);
  const missing = await runCase('missing-library', 'missing-library.json');
  check('missing library prevents native create', !missing.file_created && missing.failure_denial_seen);
  check('post observation cannot undo allowed file', existsSync(path.join(base, 'allowed/allowed.json')));
  report.registered_events = EVENTS;
  report.observed_events = [...new Set(rows().map(row => row.hook_event))].sort();
  report.observed_event_count = rows().length;
  report.status = 'PASS';
} catch {
  // Vendor errors can quote requests/paths. Never publish raw errors or sessions.
  report.failed_check = phase;
  process.exitCode = 1;
} finally {
  try { if (activeClient) await activeClient.stop(); } catch { /* bounded by deadline */ }
  if (activeServer) { activeServer.closeAllConnections(); activeServer.close(); }
  if (started && binary && existsSync(binary)) {
    try { host('stop'); } catch { /* cleanup cannot mask the test failure */ }
  }
  if (base) rmSync(base, { recursive: true, force: true });
  clearTimeout(deadline);
}
report.checks_passed = report.checks.length;
const output = JSON.stringify(report, null, 2) + '\n';
if (values.report) writeFileSync(values.report, output);
process.stdout.write(output);
