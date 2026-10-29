#!/usr/bin/env node
/**
 * Offline native Gemini CLI hook-dispatch smoke test (not an authenticated CLI run).
 *
 * Setup from the repository root (Node >= 20):
 *   npm install --prefix .context/gemini-native --ignore-scripts --no-package-lock \
 *     --save-exact @google/gemini-cli-core@0.66.0
 *   cargo build --locked --workspace
 *   node scripts/gemini_native_smoke.mjs
 * Override with --binary PATH (or AGENT_LENS_BIN) and --core PACKAGE_DIRECTORY.
 * --disable-policy is an oracle mutation: it must exit nonzero on lost denial.
 *
 * The vendor HookSystem (registry, planner, runner, aggregator, event handler),
 * executeToolWithHooks, WriteFileTool and filesystem service are unmodified.
 * A minimal in-memory Config facade supplies only local settings and disables
 * telemetry. No Gemini Config initialization, provider client, auth, real user
 * settings, MCP connection, or model request is used. Events are explicitly fired.
 * JSON file writes avoid the vendor's optional LLM content-correction path.
 * The Config facade preserves the native Config's config = this compatibility
 * self-reference; no dispatcher or tool execution methods are mocked or replaced.
 */
import assert from 'node:assert/strict';
import { removeFileWithRetry } from './windows_cleanup.mjs';
import { createHash, randomUUID } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VERSION = '0.66.0';
const SOURCE = '970413207732f5d4d8c50540c7fc359c44fdaaf2';
const EVENTS = ['BeforeTool', 'AfterTool', 'BeforeAgent', 'AfterAgent',
  'BeforeToolSelection', 'SessionStart', 'SessionEnd', 'Notification', 'PreCompress'];
const { values } = parseArgs({ options: {
  binary: { type: 'string', default: process.env.AGENT_LENS_BIN || path.join(ROOT, 'target', 'debug',
    process.platform === 'win32' ? 'agent-lens.exe' : 'agent-lens') },
  core: { type: 'string', default: path.join(ROOT, '.context', 'gemini-native',
    'node_modules', '@google', 'gemini-cli-core') },
  'isolated-child': { type: 'boolean', default: false },
  'disable-policy': { type: 'boolean', default: false },
} });

// Do not forward API credentials or client-specific environment overrides into
// vendor modules or hook subprocesses. The child imports vendor code only after
// this re-exec. HOME/USERPROFILE are not changed to point at another profile.
if (!values['isolated-child']) {
  const env = {};
  for (const key of ['PATH', 'Path', 'SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'TEMP', 'TMP']) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  const child = spawnSync(process.execPath,
    [fileURLToPath(import.meta.url), ...process.argv.slice(2), '--binary', values.binary, '--isolated-child'],
    { cwd: ROOT, env, stdio: 'inherit', timeout: 120000 });
  if (child.error) console.error(child.error.message);
  process.exit(child.status ?? 1);
}

const digest = file => createHash('sha256').update(readFileSync(file)).digest('hex');
const core = path.resolve(values.core);
const sourceBinary = path.resolve(values.binary);
const libraryName = process.platform === 'win32' ? 'agent_lens_engine.dll' :
  process.platform === 'darwin' ? 'libagent_lens_engine.dylib' : 'libagent_lens_engine.so';
const sourceLibrary = path.join(path.dirname(sourceBinary), libraryName);
const packageInfo = JSON.parse(readFileSync(path.join(core, 'package.json'), 'utf8'));
assert.equal(packageInfo.name, '@google/gemini-cli-core');
assert.equal(packageInfo.version, VERSION, 'Install the exact pinned vendor version');
// Keep vendor diagnostics visible on stderr; stdout is one aggregate JSON report.
console.debug = (...args) => console.error(...args);
const load = relative => import(pathToFileURL(path.join(core, 'dist', 'src', relative)).href);
const [
  { HookSystem }, { HookRunner }, { HookAggregator },
  { HookEventName }, { executeToolWithHooks },
  { WriteFileTool }, { StandardFileSystemService }, { getShellConfiguration }, { resolveToRealPath },
] = await Promise.all([
  load('hooks/hookSystem.js'), load('hooks/hookRunner.js'),
  load('hooks/hookAggregator.js'), load('hooks/types.js'),
  load('core/coreToolHookTriggers.js'), load('tools/write-file.js'),
  load('services/fileSystemService.js'), load('utils/shell-utils.js'), load('utils/paths.js'),
]);
assert.deepEqual(Object.values(HookEventName).sort(), [...EVENTS, 'BeforeModel', 'AfterModel'].sort());

// Match the native tools' canonicalization, including macOS /tmp symlinks and
// Windows short names (RUNNER~1), so the exact fixture boundary compares like paths.
const base = resolveToRealPath(mkdtempSync(path.join(tmpdir(), "agent lens gemini 'quote' ")));
const state = path.join(base, 'state');
const log = path.join(base, 'events.jsonl');
const rules = path.join(base, 'rules.yaml');
const install = path.join(base, 'install');
const binary = path.join(install, path.basename(sourceBinary));
const library = path.join(install, libraryName);
const session = `gemini-native-${randomUUID()}`;
const checks = [];
function check(name, condition) {
  assert.ok(condition, name);
  checks.push(name);
}
function host(...args) {
  const result = spawnSync(binary, ['--state', state, ...args], {
    cwd: base, encoding: 'utf8', timeout: 15000,
  });
  assert.equal(result.status, 0, `Agent Lens ${args[0]} failed: ${result.error?.message ?? result.stderr}`);
  return JSON.parse(result.stdout);
}
let started = false;
try {
  mkdirSync(install);
  copyFileSync(sourceBinary, binary);
  copyFileSync(sourceLibrary, library);
  copyFileSync(path.join(ROOT, 'examples', 'rules', 'default.yaml'), rules);
  const binaryDigest = digest(binary);
  const libraryDigest = digest(library);
  const policyDigest = digest(rules);
  host('start', '--output', log, '--rules', rules);
  started = true;
  const snippet = host('config', '--agent', 'gemini');
  assert.deepEqual(Object.keys(snippet.hooks).sort(), [...EVENTS].sort(), 'exact supported config inventory');
  // HookRunner expands these macros even inside shell quotes. Generated literal
  // executable/state paths containing them must be rejected, never emitted.
  const macros = ['$GEMINI_PROJECT_DIR', '$GEMINI_CWD', '$GEMINI_PLANS_DIR',
    '$GEMINI_SESSION_ID', '$CLAUDE_PROJECT_DIR'];
  function rejectedConfig(candidateBinary, candidateState, label) {
    const result = spawnSync(candidateBinary,
      ['--state', candidateState, 'config', '--agent', 'gemini'],
      { cwd: base, encoding: 'utf8', timeout: 15000 });
    assert.equal(result.error, undefined, `${label}: configuration process must launch`);
    check(`${label}: config rejects macro path without stdout`,
      result.status !== null && result.status !== 0 && result.stdout === '');
  }
  for (const macro of macros) {
    rejectedConfig(binary, path.join(base, `state-${macro}`), `${macro} state`);
    const macroInstall = path.join(base, `install-${macro}`);
    mkdirSync(macroInstall);
    const macroBinary = path.join(macroInstall, path.basename(sourceBinary));
    copyFileSync(sourceBinary, macroBinary);
    copyFileSync(sourceLibrary, path.join(macroInstall, libraryName));
    rejectedConfig(macroBinary, state, `${macro} executable`);
  }
  const fsService = new StandardFileSystemService();
  const config = {
    sanitizationConfig: { enableEnvironmentVariableRedaction: true },
    isTrustedFolder: () => true,
    getProjectHooks: () => undefined, // Never load/persist user/project trust settings.
    getHooks: () => structuredClone(snippet.hooks),
    getExtensions: () => [],
    getDisabledHooks: () => [],
    storage: { getPlansDir: () => path.join(base, 'plans') },
    getSessionId: () => session,
    getWorkingDir: () => base,
    getTargetDir: () => base,
    getUsageStatisticsEnabled: () => false,
    getTelemetryEnabled: () => false,
    isPlanMode: () => false,
    getApprovalMode: () => 'default',
    validatePathAccess: file => path.dirname(file) === base ? null : 'Outside disposable fixture',
    getFileSystemService: () => fsService,
    getMemoryContextManager: () => undefined,
    getDebugMode: () => false,
    // A non-JSON fixture must fail rather than accidentally create a model client.
    getActiveModel: () => { throw new Error('Offline test must not request a model'); },
  };
  // Native Config implements AgentLoopContext with this same self-reference:
  // packages/core/src/config/config.ts at SOURCE, lines 758-759.
  config.config = config;
  const hookSystem = new HookSystem(config);
  config.getHookSystem = () => hookSystem;
  await hookSystem.initialize();
  const registry = hookSystem.getRegistry();
  check('vendor registry loads all nine generated hooks', registry.getAllHooks().length === EVENTS.length);
  await hookSystem.fireSessionStartEvent('startup');
  await hookSystem.fireBeforeAgentEvent('Synthetic offline hook-dispatch test');
  await hookSystem.fireToolNotificationEvent({
    type: 'info', title: 'Synthetic notification', prompt: 'Synthetic permission', urls: [],
  });
  await hookSystem.fireBeforeToolSelectionEvent({
    model: 'offline-fixture', contents: [{ role: 'user', parts: [{ text: 'synthetic' }] }],
    config: { tools: [{ functionDeclarations: [{ name: 'write_file', description: 'fixture' }] }] },
  });
  const tool = new WriteFileTool(config, undefined);
  const deniedPath = path.join(base, 'blocked.json');
  const allowedPath = path.join(base, 'allowed.json');
  const deniedInput = { file_path: deniedPath, content: '{"marker":"AGENT_LENS_BLOCK_DEMO"}' };
  const allowedInput = { file_path: allowedPath, content: '{"message":"allowed native control"}' };
  if (values['disable-policy']) host('stop'); // Deliberate mutation: the oracle MUST fail.
  const run = input => executeToolWithHooks(tool.build(input), 'write_file',
    new AbortController().signal, tool, undefined, undefined, config);
  const denied = await run(deniedInput);
  check('native vendor execution reports Agent Lens policy denial',
    denied.error?.type === 'execution_failed' && denied.error.message === 'Blocked by Agent Lens policy');
  check('blocked harmless file does not exist', !existsSync(deniedPath));
  const allowed = await run(allowedInput);
  check('native vendor write_file positive control succeeds', allowed.error === undefined);
  check('positive control creates the exact expected file', readFileSync(allowedPath, 'utf8') === allowedInput.content);
  await hookSystem.firePreCompressEvent('manual');
  await hookSystem.fireAfterAgentEvent('Synthetic offline hook-dispatch test', 'Complete', false);
  await hookSystem.fireSessionEndEvent('exit');
  const rows = readFileSync(log, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  check('all nine supported events recorded',
    JSON.stringify([...new Set(rows.map(row => row.hook_event))].sort()) === JSON.stringify([...EVENTS].sort()));
  check('exact event count (two BeforeTool, one AfterTool)', rows.length === 10 &&
    rows.filter(row => row.hook_event === 'BeforeTool').length === 2 &&
    rows.filter(row => row.hook_event === 'AfterTool').length === 1);
  check('native session identity preserved', rows.every(row => row.agent === 'gemini' && row.session_id === session));
  const preRows = rows.filter(row => row.hook_event === 'BeforeTool');
  check('telemetry records blocked and allowed tool decisions',
    preRows[0].decision === 'block' && preRows[0].matched_rules.includes('demo-marker') && preRows[1].decision === 'allow');
  check('metadata capture omits raw tool inputs and content', rows.every(row =>
    !('input' in row) && !('payload' in row) && !('content' in row)) &&
    !readFileSync(log, 'utf8').includes('AGENT_LENS_BLOCK_DEMO'));
  const failClosedReason = 'Agent Lens failed to evaluate or record this action. Check local diagnostics.';
  async function checkPreFailure(name, file) {
    const result = await run({ file_path: path.join(base, file), content: '{"message":"harmless failure probe"}' });
    check(`${name}: native tool reports hook denial`,
      result.error?.type === 'execution_failed' && result.error.message === failClosedReason);
    check(`${name}: harmless file absent`, !existsSync(path.join(base, file)));
  }
  const originalRules = readFileSync(rules);
  writeFileSync(rules, 'version: [invalid YAML policy shape]\nrules: []\n');
  await checkPreFailure('invalid policy', 'invalid-policy.json');
  writeFileSync(rules, originalRules);
  await removeFileWithRetry(library);
  await checkPreFailure('missing companion library', 'missing-library.json');
  const postHook = registry.getHooksForEvent('AfterTool')[0].config;
  const postFailure = await new HookRunner(config).executeHook(postHook, 'AfterTool', {
    session_id: session, transcript_path: '', cwd: base, hook_event_name: 'AfterTool',
    timestamp: new Date().toISOString(), tool_name: 'write_file', tool_input: allowedInput,
    tool_response: { llmContent: 'Synthetic already-completed operation' },
  });
  check('post-tool missing library is observable as native exit 1',
    postFailure.exitCode === 1 && postFailure.success === false);
  const aggregatedPostFailure = new HookAggregator().aggregateResults([postFailure], 'AfterTool');
  check('vendor treats post-tool exit 1 diagnostic as nonblocking warning',
    aggregatedPostFailure.finalOutput.getBlockingError().blocked === false &&
    postFailure.output.systemMessage.startsWith('Warning:'));
  check('post-tool failure cannot undo the completed positive control',
    readFileSync(allowedPath, 'utf8') === allowedInput.content);
  console.log(JSON.stringify({
    status: 'PASS', evidence_level: 'offline unmodified vendor HookSystem and native file tool; explicitly fired events',
    not_tested: ['authenticated Gemini CLI', 'model event emission', 'CLI settings loading and consent', 'other operating systems'],
    gemini_core: VERSION, source_commit: SOURCE, node: process.version,
    platform: process.platform, architecture: process.arch, shell: getShellConfiguration(),
    binary_sha256: binaryDigest, library_sha256: libraryDigest,
    policy_sha256: policyDigest,
    vendor_dispatcher_sha256: digest(path.join(core, 'dist/src/hooks/hookRunner.js')),
    vendor_tool_gate_sha256: digest(path.join(core, 'dist/src/core/coreToolHookTriggers.js')),
    registered_events: EVENTS, observed_event_count: rows.length,
    additional_failure_dispatches: 3,
    checks_passed: checks.length, checks,
  }, null, 2));
} finally {
  try {
    if (started) host('stop');
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}
