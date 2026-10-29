# Contributing

AI Lens is a small educational project. Good contributions make hook behavior
easier to understand and verify. For a substantial protocol or policy change,
open an issue describing the concrete event, expected decision, and supported
agent version before investing in a large patch.

## Development

Use current stable Rust and Python 3.9 or newer. The manifest's `rust-version`
target is not proof of a validated minimum toolchain. No live agent account is
required for the local suite.

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace
cargo build --locked --workspace --release
python scripts/telemetry_smoke.py --report telemetry-results.json
python scripts/e2e.py
python scripts/native_hooks_smoke.py --binary target/release/agent-lens --report native-hooks-results.json
python scripts/rules_smoke.py --report rule-results.json
python scripts/rules_oracle_test.py
python scripts/package.py
python scripts/package_smoke.py
```

The CLI and engine must both be built. Integration checks exercise a real CLI
process loading the adjacent library. Run the commands from the repository root;
use `python3` if that is your Python 3 executable. CI runs this sequence on Linux,
Windows MSVC, and macOS. Results from one OS do not establish another OS's behavior.

For optional API-backed acceptance against an installed Codex or Hermes client,
see [Live testing](docs/live-testing.md). This is separate from CI and uses real
provider tokens. Keep credentials in the environment and publish only the safe
assertion summary, never raw client sessions. Check the live runner's independent
oracle offline with `python scripts/live_smoke_test.py`. Claude Code has a separate POSIX runner
and offline oracle in [Live testing](docs/live-testing.md#claude-code-posix).

To exercise the pinned Gemini CLI hook system and real file tool without an
account, use Node 24 and build both native components first:

```sh
npm install --prefix .context/gemini-native --ignore-scripts --no-package-lock --save-exact @google/gemini-cli-core@0.66.0
node scripts/gemini_native_smoke.mjs
```

This uses a disposable directory and a minimal configuration facade; events are
explicitly fired. It does not initialize a provider client, load your Gemini
settings, or test trust/consent. `--binary PATH` selects an extracted package's
executable. `--disable-policy` is a deliberate mutation and must fail at the
native denial assertion. See [verification](docs/verification.md) for the
exact evidence boundary.

## Keep the boundary clear

The experimental `telemetry` commands have their own observation schema and no
engine policy evaluation. Keep provider adapters pure, allowlist metadata, and
exercise ingestion through the real executable with
`python scripts/telemetry_smoke.py`. The suite uses synthetic exports, independent
protobuf messages, loopback HTTP and dummy credentials; it proves neither tenant
permissions nor real producer delivery. Polling tests must pair failure/recovery
with successful page ingestion and checkpoint controls. Cite the current official
wire contract for provider changes; keep account requirements and live gaps in
[the source guide](docs/telemetry-sources.md).

- Keep adapters as pure JSON transformations; isolate loading, locking, files,
  and process I/O in the host. Use synchronous standard-library I/O unless a
  demonstrated need justifies another dependency.
- Validate YAML strictly. Make rule behavior deterministic and bound input and
  pattern sizes. Never echo matched content into rule IDs or denial reasons.
- Keep hook stdout protocol-only. A useful diagnostic belongs on stderr.
- Preserve metadata-only capture as the default. Use invented, harmless values
  in fixtures; never commit live sessions, credentials, or customer logs.
- Do not claim sandboxing, complete agent visibility, or prevention on post-tool
  and observe-only events. Cite upstream documentation for adapter changes.

## Show the behavior

Add a focused regression for a parser, policy, redaction, or lifecycle change.
For a blocking change, pair a denied harmless side effect with an allowed
positive control. For a loader change, invoke the built CLI with the real
library and exercise missing or incompatible library failures.

Every shipped YAML rule needs a matching case and nearby non-match in
`examples/rule-cases.json`. The catalog harness checks that inventory, replays
both cases through the executable/library for all seven source-preview adapters
(Claude Code, Codex, Hermes, Gemini CLI, Cursor, Copilot CLI, and Cowork), and
checks post-tool observational behavior. The source inventory is
30 rules × 7 adapters × 3 scenarios = **630 synthetic scenarios**. This is an
inventory, not a claim that an unrun suite passed. Preserve the historical
v0.2.0 four-adapter/360-scenario and v0.1.0 evidence counts.
Fixture commands are strings and are never executed.
The optional report contains synthetic results only; native CI uploads it.

In a pull request, explain the user-visible change, list exact checks and
results, and name gaps. Synthetic payload replay proves that payload's handling;
a live-client claim needs the client version, execution host, registered hook,
and observed outcome. Redact evidence before sharing it. The maintainers may
request additional platform checks before merging.

Gemini work is scoped to the CLI; Antigravity is unsupported. Keep its nine-event
registry explicit: only `BeforeTool` is enforceable, and model request/response
hooks are excluded to avoid per-request/response-chunk overhead. Cite the
[Gemini hook reference](https://geminicli.com/docs/hooks/reference/) and
[configuration/trust notes](docs/agents.md#gemini-cli). Keep historical v0.1.0
evidence counts intact. The pinned 0.66.0 native check covers the unmodified
vendor runtime/tool seam through full `HookSystem`, a minimal Config facade, and
explicitly fired events. It excludes actual CLI settings loading, trust/consent,
and provider sessions. Do not turn this into an authenticated Google live-client
claim or a guarantee of live event delivery: upstream shutdown does not wait for
`SessionEnd`, so that callback can be lost.

For the experimental native adapters, preserve explicit event inventories:
Cursor has 11 events, Copilot CLI has 12, and Cowork has five. Only their
`preToolUse` / `PreToolUse` event enforces policy; post/lifecycle matches remain
observational. Cursor emits explicit allow on pre-tool and subagent-start
continuation and generated `failClosed` for pre-tool failures. Copilot uses
CLI-only direct argv config and a 30-second timeout that **fails open upstream**.
Cowork uses a distinct hooks-only plugin and separately provisioned executable;
its documented hook contract does not establish Desktop/VM execution evidence.
See [agent setup](docs/agents.md) for current official references and trust,
restart, packaging and failure behavior. Do not substitute telemetry fixture
tests or SDK callback tests for an installed client's actual command-hook seam.

## License and security

Contributions are made under [Apache-2.0](LICENSE). Preserve third-party
attribution when applicable. See [NOTICE](NOTICE) for project license information. Report suspected
vulnerabilities privately through the repository's GitHub security advisory
feature when available; do not put secrets or sensitive logs in public issues.

For the account-free Linux native Copilot test (CLI 1.0.105, SDK 1.0.28), follow
[the native Copilot recipe](docs/live-testing.md#account-free-native-copilot-cli-linux).
It uses an isolated network namespace and synthetic loopback model responses,
the actual CLI configuration loader and `create` tool, and the real Lens
executable/library. `--disable-policy` must fail its absent-file oracle. This is
separate from `native_hooks_smoke.py` callback replay and does not validate a live
account, every lifecycle event, or Windows/macOS Copilot execution.
