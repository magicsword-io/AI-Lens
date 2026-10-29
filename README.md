# AI Lens by MagicSword

See what AI coding agents ask their tools to do. AI Lens records local JSONL
telemetry and applies reviewable YAML rules through cooperative agent hooks.
Use it to explore agent behavior, test allowed and denied actions, and feed
selected metadata into your SIEM.

AI Lens is an educational project licensed under [Apache-2.0](LICENSE).
The executable remains `agent-lens`; library names, state paths, and JSON schema
IDs retain their existing names for compatibility.

[Agent setup](docs/agents.md) · [Rules](docs/rules.md) · [Telemetry sources](docs/telemetry-sources.md) · [Verification](docs/verification.md)

## What it hooks into

The current source has seven native adapters. These are cooperative hooks:
a denial takes effect only when the client invokes the hook and honors its
response. Coverage depends on the client version, tool, and execution host.

| Client | Adapter ID | Preventive events / scope |
| --- | --- | --- |
| Claude Code | `claude` | `PreToolUse`, `PermissionRequest` |
| Codex | `codex` | `PreToolUse`, `PermissionRequest` |
| Hermes | `hermes` | `pre_tool_call` via native shell hooks |
| Gemini CLI | `gemini` | `BeforeTool`; other registered events observe only |
| Cursor — preview | `cursor` | `preToolUse`; complete native-client acceptance pending |
| GitHub Copilot CLI — preview | `copilot` | `preToolUse`; Linux account-free CLI test available |
| Claude Cowork — preview | `cowork` | `PreToolUse` via a hooks-only plugin; Desktop/VM execution unvalidated |

Post-tool and lifecycle events are observational. Copilot hook timeouts fail
open upstream. Gemini `SessionEnd` delivery is best effort; Antigravity is
unsupported. The [adapter guide](docs/agents.md) lists exact event registries,
trust requirements, configuration paths, and failure behavior. The
[verification record](docs/verification.md) separates fixture checks from actual
client and OS evidence.

Eleven additional [telemetry sources](docs/telemetry-sources.md) cover runtime
OTel, enterprise audit feeds, and documented Copilot session exports. These
always produce `observe_only` records and never run blocking rules. Enterprise
admin/audit credentials are separate from ordinary model inference keys.

## Build and try it

Build from this repository with current stable Rust. This repository does not
yet publish migrated release downloads. Historical v0.2.0 packages from the
previous repository contain only Claude Code, Codex, Hermes, and Gemini CLI;
they do not contain the new preview adapters or telemetry commands.

```sh
git clone https://github.com/magicsword-io/AI-Lens.git
cd AI-Lens
cargo build --locked --workspace
./target/debug/agent-lens rules-check --rules examples/rules/default.yaml
./target/debug/agent-lens demo --output demo.jsonl --rules examples/rules/default.yaml
```

`demo` writes five synthetic events, needs no account, and installs no hooks.
Keep both build outputs together: `agent-lens` and `libagent_lens_engine.so`
(Linux), `libagent_lens_engine.dylib` (macOS), or `agent-lens.exe` and
`agent_lens_engine.dll` (Windows). Windows commands use
`.\target\debug\agent-lens.exe`.

Windows x64 binaries also require the latest
[Microsoft Visual C++ v14 x64 Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist#latest-supported-redistributable-version).
The ZIP does not bundle this runtime. A missing `VCRUNTIME140.dll` prevents the
process from starting, before Lens can return a hook decision.

To create a local package, install Python 3.9+ and run:

```sh
cargo build --locked --workspace --release
python3 scripts/package.py
```

Packages and checksums go to `dist/`. They are ZIPs with an adjacent engine
library, examples, and documentation; they are unsigned.

## Connect an agent

Choose absolute paths for your state, output, and rules. Replace the example
paths with your own and copy a reviewed policy into the rules location first.

```sh
./target/debug/agent-lens --state /absolute/path/lens-state start \
  --output /absolute/path/events.jsonl --rules /absolute/path/default.yaml
./target/debug/agent-lens --state /absolute/path/lens-state config --agent claude
./target/debug/agent-lens --state /absolute/path/lens-state status
```

`config` prints JSON for you to review and merge into the client's settings.
Use any adapter ID in the table above. It does not edit settings, install
clients, or approve trust. Preserve existing hooks and complete the client's
native trust/consent and restart flow. On Windows, Claude/Codex/Cursor can use
`--shell powershell`; other adapters use their documented native invocation.
See [agent setup](docs/agents.md) before installing a snippet.

Install hooks where the tools execute: a local registration does not cover a
separate VM, remote workspace, or cloud runner. Before relying on a rule, test an
allowed operation and a denied harmless operation through the actual client.
`status` reports local state, not whether the client invoked a hook.

```sh
./target/debug/agent-lens --state /absolute/path/lens-state stop
```

`stop` disables collection and policy evaluation for that state directory. It
leaves logs and installed client configuration in place; remove the client hooks
to uninstall the integration.

## Rules and events

The default policy demonstrates checks for `.env`, `.aws/credentials`, `id_rsa`,
and `id_ed25519`, plus literal `.env` matching in shell input. These examples
can miss indirect access and match harmless mentions. Optional policies cover
credential stores, destructive commands, execution/network activity, agent
configuration changes, and selected tools. Each file is a complete policy;
choose one with `start --rules PATH` or combine reviewed rule lists manually.

Rules use `audit` or `block` and selectors for agents, events, tool names,
recognized file paths, and content. Selectors within a rule must all match;
matching block rules take precedence. A matching block on an event that cannot
prevent execution is recorded as `would_block`. See the [rule reference](docs/rules.md)
and [30-rule catalog](docs/rule-catalog.md) for schema, examples, and limits.

Default logs contain selected metadata: agent, event, phase, decision, matched
rule IDs, enforcement support, and available native session/tool IDs. Raw
prompts and tool input/output are omitted; matching examines the original
callback in memory. Use the [SIEM guide](docs/siem.md) for field mapping.

## Import more telemetry

Try an account-free synthetic export:

```sh
./target/debug/agent-lens telemetry sources
./target/debug/agent-lens telemetry import \
  --source codex-otel --signal logs \
  --input examples/telemetry/otlp-codex-logs.json --output telemetry.jsonl
```

`telemetry config --source ID` prints collection guidance; `listen` receives
OTLP/HTTP on loopback; `poll` retrieves bounded audit snapshots with resumable
checkpoints. Use a production OpenTelemetry Collector for remote, authenticated,
TLS, or gRPC delivery. The local receiver requires uncompressed HTTP/1.1 with
`Content-Length`. Source labels do not authenticate producers.

Telemetry uses the separate `agent-lens.telemetry.v1` schema and drops raw
bodies and unknown fields. Tenant permissions, managed settings, and real export
delivery require their own acceptance checks. See the
[source and permission matrix](docs/telemetry-sources.md) and
[live test procedures](docs/live-testing.md).

## Privacy and limits

AI Lens provides no OS sandbox, tamper resistance, or complete agent visibility.
Rules cannot undo completed actions. Binaries, rules, state, and output are
trusted local files with the user's permissions.

`start --capture-content` opts into content capture with best-effort redaction.
Redaction and metadata filtering can miss secrets and unusual formats. Treat all
logs as sensitive, keep producer content capture off where possible, and choose
file permissions and retention deliberately. Do not commit live sessions,
credentials, or customer logs.

## Website and development

The MagicSword Astro site lives in [site/](site/). Run it with Node 24:
`cd site`, `npm ci`, then `npm run dev`. Publication depends on the new
repository's visibility and Pages configuration.

[Contributing](CONTRIBUTING.md) lists local checks and evidence expectations.
[Architecture](docs/architecture.md) explains the executable/library boundary.
[Live testing](docs/live-testing.md) describes paired side-effect tests; fixture
replays alone do not establish live-client compatibility. License information is in
[LICENSE](LICENSE) and [NOTICE](NOTICE).
