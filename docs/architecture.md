# Architecture

AI Lens has two Rust crates: a command-line host and a policy engine. An agent
runs the host once per registered command hook. Hook management starts no background process.

AI Lens v0.3.0 has seven native adapters: Claude Code, Codex,
Hermes, Gemini CLI, Cursor, Copilot CLI, and Cowork. Published v0.2.0 downloads
contain the first four. Native adapters normalize callbacks for policy evaluation
and return vendor denial responses at supported preventive hooks. Cowork is a
separate plugin adapter whose Desktop/VM execution remains unvalidated.

The experimental `telemetry` commands (included in v0.3.0) are a separate host-only
path: bounded imports, a foreground loopback OTLP/HTTP listener, and bounded
provider audit polling. They normalize selected metadata to
`agent-lens.telemetry.v1` JSONL, without loading the engine, reading hook state,
or evaluating block rules. Each batch is appended under an output lock and
synced before acknowledgment or checkpoint advancement. The listener's lifetime
belongs to its foreground process; hook `stop` does not stop that process.
See [telemetry sources](telemetry-sources.md) for protocol limits and recovery.

```text
agent callback JSON on stdin
        |
        v
agent-lens executable ---- active configuration + state lock
        |
        | dynamic load, versioned C ABI
        v
adjacent engine library
  normalize -> evaluate original input -> redact optional content
        |
        v
host appends one JSONL event -> returns vendor JSON on stdout
```

## Host lifecycle

`start` validates the rules and engine, resolves persisted paths to absolute
paths, and activates the chosen state directory. It does not install hooks or
keep a process running. `hook` reads that state on each invocation. `stop` disables
collection and enforcement; subsequent registered invocations can still launch
the executable. `status` reports the state selected by the same `--state` value.

A state lock serializes lifecycle transitions and hook handling for that state
directory. An output-file lock serializes appends and rejects incomplete trailing
records. Prefer one state directory per output stream to keep its policy and
lifecycle consistent. This is local process coordination, not distributed
locking or a guarantee for every network filesystem.
Operators own rotation and retention; stop collection before moving its output.

The host limits hook stdin to 1 MiB and sends diagnostics to stderr. It appends
newline-delimited JSON objects, never a JSON array. Event timestamps are host
processing times, not a trusted clock from the agent or proof of execution order.

## Dynamic engine boundary

The CLI loads a library beside its own executable:

| Platform | Host | Engine |
| --- | --- | --- |
| Windows | `agent-lens.exe` | `agent_lens_engine.dll` |
| Linux | `agent-lens` | `libagent_lens_engine.so` |
| macOS | `agent-lens` | `libagent_lens_engine.dylib` |

Both artifacts must match the host OS, architecture, and ABI. The CLI does not
statically link the engine. The engine also builds an `rlib` for Rust unit tests;
those tests alone cannot prove that the packaged library loads.

The C ABI exposes a version check, a JSON request/response call, and a paired
free function. The engine catches Rust unwinds at the FFI boundary. A library
allocation is released through that library's free function. ABI errors and
invalid response envelopes are host errors, not policy decisions.

The engine's internal request contains `agent`, an optional explicit `event`,
the parsed `payload`, `rules_yaml`, and `capture_content`. Its response contains
the normalized `event`, vendor `response`, and `blocked` flag. The host adds the
timestamp and handles disk I/O.

## Normalization and policy

Adapters preserve supported native event names, session IDs, and tool names.
Missing identifiers remain absent. AI Lens does not infer parent/child agent
lineage, substitute its own process ID for an agent PID, or copy arbitrary
payload fields into metadata.

The Cursor and Copilot native modules register 11 and 12 events respectively;
only camelCase `preToolUse` is enforceable. Cursor requires object `tool_input`;
Copilot accepts object `toolArgs` or one JSON-encoded object string. Copilot's
event is passed explicitly because its native callbacks do not guarantee an
event discriminator. Cowork registers five Claude-style events, with only
`PreToolUse` enforceable; its registry does not inherit every Claude Code event.

`config --agent` renders review-only hook configuration through the engine.
Cursor uses its version-1 command-string format. Copilot CLI and Cowork use
separate executable/argv fields in their own schemas; Cowork output belongs in
plugin `hooks/hooks.json`. These do not auto-install or approve anything.
`telemetry config --source` instead prints exporter/collection guidance, without
the engine or any enforcement capability.

Rules evaluate the original callback payload. A block match becomes `block` only for a
supported enforceable pre-tool event; otherwise it becomes `would_block`. Audit
matches are recorded without denying. Opt-in capture redacts content after
evaluation. [Rules](rules.md) documents the selector contract and its limitations.

## Failures and trust

Management failures use a nonzero exit and stderr diagnostics. During active
collection, processing failures attempt a vendor denial when the host knows it
is handling an enforceable pre-tool event. A launcher failure, killed process,
upstream timeout, or missing event classification can have different upstream
behavior. Test that behavior through the actual client; do not infer it from a
unit test or the existence of a log line.

Cursor pre-tool continuation, including inactive Lens state, explicitly returns
`permission: allow`; observational `subagentStart` does likewise. Its generated
pre-tool config uses `failClosed: true` and a ten-second timeout. Copilot uses a
30-second command timeout; upstream timeout behavior always fails open, although
nonzero command exits deny pre-tool use. Invalid/contaminated Copilot stdout can
produce default behavior. Cowork's plugin configuration requests preventive
`onFailure: block`; native Desktop handling and execution host need validation.
None of these settings establish that a client loaded the configuration.

Clients own trust, consent, hook activation and restart/reload behavior. The
executable, adjacent library, state and output must be reachable where the hook
runs, including client sandboxes. Local settings do not provide universal cloud
coverage. See [the per-client setup](agents.md) for exact scope and failure
contracts. OTLP/provider audit events cannot participate in this denial path.

The state, policy, binaries, and output are trusted local files with the user's
permissions. This architecture provides neither tamper resistance nor an OS
security boundary. See the [privacy and operational limits](../README.md#privacy-and-limits) and
[agent coverage notes](agents.md).

## Evidence

Unit tests cover pure adapter/policy/redaction logic. `scripts/e2e.py` drives built
processes through the dynamic library seam, lifecycle, protocol responses, and
JSONL output. CI repeats native builds and checks on Linux, Windows MSVC, and
macOS, then creates a ZIP and checksum manifest. These checks use synthetic
payloads; live agent registration and current vendor coverage need separate
client/version evidence.
