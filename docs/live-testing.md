# Test a real agent

The offline CI suite tests the executable/library boundary and vendor protocol
replays. `scripts/live_smoke.py` additionally starts a real Codex or Hermes client
with the default policy and checks its actual filesystem side effects. This
optional test uses OpenAI API tokens and requires an installed client with native
command-hook support. The current live runner supports POSIX hosts.

Use a disposable development host. Build both Rust crates, or extract a release
ZIP and point `--binary` at its executable, beside the matching library. Install
Codex or Hermes normally before running the test. Neither the production EXE nor
this script installs clients or discovers their running sessions.

Provide your own key as `OPENAI_API_KEY` through your shell's secret mechanism.
Do not put it in YAML, command arguments, git, or a report. Select a model your
OpenAI API project can access; Hermes uses its `openai-api` provider with the same
key. The runner connects directly to `https://api.openai.com/v1`; it does not
inherit a proxy endpoint from the parent environment.

```sh
cargo build --locked --workspace --release
python3 scripts/live_smoke.py --agent codex --model gpt-5.4 \
  --report .context/live-codex.json
python3 scripts/live_smoke.py --agent hermes --model gpt-5.4-mini \
  --hermes-check-persisted-consent --report .context/live-hermes.json
```

Use `--client /absolute/path/to/hermes` or `--client /absolute/path/to/codex` for a
client outside PATH. Use `--binary /absolute/path/to/extracted/agent-lens` to test
a downloaded package. These paths are test-runner arguments; production hook
configuration only needs the AI Lens executable's absolute path.

The runner creates disposable state, work directories, and a Hermes profile next
to its report. It leaves the assertion report and metadata-only `.events.jsonl`
file, then removes the temporary files. Raw client output stays in memory. Records must match the metadata schema before
being saved; malformed logs produce a failed report. Timeout or cancellation
terminates and reaps the client process group. Cleanup failures fail the run,
and each started run replaces any prior report atomically.
Credential values are not included in the saved report. Treat even metadata as
local session data; share the aggregate assertion report after review.

## What a pass requires

The client must make two separate calls: create `allowed.txt` with an exact
synthetic sentinel, then attempt to create `.env` with synthetic text. It must
stop after the denial. The runner independently verifies:

- The client exits successfully and the allowed file has the exact contents.
- `.env` is absent, with exactly one native pre-tool block from the expected rule.
- Exactly one allowed and one blocked pre-tool call occurred for the intended tool.
- Post-tool and session start/end events were recorded for one native session,
  with the allowed pre/post calls linked by their native tool ID.
- All records identify the expected agent and omit raw content.

Codex tests the shell/unified-exec `Bash` surface and `protect-shell-env` rule.
Hermes tests `write_file` and `protect-env-files`. This proves these particular
paths, not every rule, tool, event, host OS, or bypass-resistant file protection.
No destructive commands, real credentials in test files, or network tools are
requested from the model. `python3 scripts/live_smoke_test.py` checks that the
oracle rejects missing positive controls and deliberately corrupted evidence.

## Native hook trust

Codex runs with `workspace-write` sandboxing and the generated hooks reviewed by
the test operator. This automation uses the documented
`--dangerously-bypass-hook-trust` flag for that invocation. It does not save hook
trust or alter your normal Codex settings. Interactive installations should use
`/hooks` to review and trust the definitions. The flag is **not** part of AI
Lens's generated production configuration and does not establish that interactive
onboarding was tested. See [official Codex hooks](https://learn.chatgpt.com/docs/hooks#review-and-trust-hooks).

Hermes uses native `--accept-hooks` for the reviewed, temporary profile. With
`--hermes-check-persisted-consent`, a second real session uses that same profile
without the acceptance flag. This checks that Hermes persisted its own consent;
AI Lens does not manufacture allowlist entries. The temporary profile and its
consent are deleted after the test.

## Linux cloud capability issue

On a previously tested Linux cloud host, inherited ambient capabilities caused `bwrap --help`
to fail. Codex then reported that bubblewrap was unavailable even after the
system package was installed. The first allowed action could not execute, so
those attempts correctly failed the acceptance check despite observing a denial.

Installing `bubblewrap` and dropping the inherited capabilities fixed the tested
launch, while preserving Codex's `workspace-write` sandbox:

```sh
python3 scripts/live_smoke.py --agent codex --model gpt-5.4 \
  --drop-linux-caps --report .context/live-codex.json
```

This optional flag runs Codex through
`setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all`. It lowers the child's
privileges and changes no global settings. It is specific to affected Linux
hosts and requires `setpriv`; do not disable the sandbox to make a test pass.

Ubuntu 24.04 can also deny user namespaces through AppArmor even with
`bubblewrap` installed and no inherited capabilities. A failed positive control
is not an enforcement pass. Check the [official sandbox prerequisites](https://learn.chatgpt.com/docs/sandboxing#prerequisites)
and use a preflighted test image; do not disable the sandbox to obtain a green
hook result. The October 29 ARM64 guest attempt remains blocked by that
prerequisite; the macOS live result is a separate pass.

Exact observed client versions, release digests, results, and remaining gaps are
in the [verification record](verification.md).

## Claude Code (POSIX)

Use an installed Claude Code client and `ANTHROPIC_API_KEY` from your shell's
secret mechanism. The separate runner uses a temporary home/config directory,
explicit generated hooks, an empty MCP configuration, normal permissions, and a
`Write` tool allowlist. It does not use `--bare`, which disables settings hooks.

```sh
python3 scripts/claude_live_smoke.py --binary target/release/agent-lens \
  --model claude-haiku-4-5 --report .context/claude-live.json
python3 scripts/claude_live_smoke_test.py
```

The default limit is four turns, 180 seconds, and an estimated $0.50 budget.
Choose a model available to your account. The independent oracle requires an
exact allowed file, an absent denied file, native pre/post/session events, and
matching tool IDs. Raw client output stays in memory; `--save-events` saves only
strictly validated metadata. The runner stops Lens and deletes temporary client
settings after the run. Windows and interactive trust onboarding are outside
this runner's scope.

Run again with `--disable-policy` and a different report path. This deliberately
removes the generated `PreToolUse` registration: the test must fail. Keep that
expected failure separate from the positive run.

## Account-free native Copilot CLI (Linux)

This test uses the actual CLI configuration loader and `create` tool with
synthetic loopback model responses, plus the real Lens executable/library.
Use a disposable Linux runner with network-namespace privileges and build both
workspace crates first:

```sh
npm install --prefix .context/copilot-native/sdk --ignore-scripts --no-package-lock \
  --no-audit --no-fund --save-exact @github/copilot@1.0.105 @github/copilot-sdk@1.0.28
python3 scripts/copilot_native_offline.py --binary target/debug/agent-lens
```

The harness requires `unshare` or its documented privilege equivalent. It
refuses namespaces with non-loopback interfaces and drops ambient credentials.
Its independent oracle checks exact allowed file contents, absent blocked JSON
file, policy/post-tool rows, and missing-library denial. Running again with
`--disable-policy` must exit 1 at `native blocked path has no side effect`.
That expected mutation failure proves the oracle detects a bypassed policy.
This does not validate provider access, every lifecycle event, timeouts, or
Windows/macOS Copilot execution. Callback replay in `native_hooks_smoke.py` is a
separate, weaker seam.

## Accept a real telemetry producer

Use one foreground listener per source, port, and output file. Review the
[source guide](telemetry-sources.md) and the matching template under
`examples/telemetry/configs/`, merge settings manually, and start a fresh,
authorized client session. Preserve approval, sandbox, and trust controls.
Perform a known harmless tool call and independently compare the client's own
output with received session/tool identifiers. Check that raw content is absent;
then stop the listener and verify exporter failure/recovery behavior.

Cowork and Cursor exports may originate in VM/cloud/server environments. Route
them through an authenticated HTTPS collector reachable from that environment,
then forward a dedicated pipeline to same-host Lens. Admin-UI JSON worksheets
are guidance, not vendor configuration files. Validate Collector configuration
against the installed version and verify uncompressed HTTP/1.1 with
`Content-Length` on the Lens-facing hop.

For audit feeds, use the source guide's enterprise/admin credentials and a small
explicit UTC window containing known activity. Ordinary inference keys do not
grant audit access. Verify positive controls, timestamp units/correlation,
content omission, pagination, provider lag, credential expiry, rate limits,
checkpoint recovery, and downstream deduplication in the authorized tenant.
A fixture/loopback pass does not establish any of those live-provider properties.


## Installed Desktop checks

The [installed-client follow-up](verification.md#installed-client-follow-up--october-29-2026)
records Cursor 3.27.22 on Windows ARM64 and Cowork through Claude Desktop 4.29.0
cloud tasks. Keep these client/runtime results separate from callback replay.

For Cursor, generate project hooks using the actual Windows Lens executable and
`--shell powershell`, preserve existing entries, and complete workspace trust.
Compare exact allowed file contents with an absent denied harmless path. A
Read precheck denial proves that Read was blocked; do not describe it as a Write
denial. Stop Lens, repeat with a distinct harmless control path, restore the same
policy, and require another denied side effect. Retain metadata-only logs and
independent file checks. Session IDs alone do not establish tool-call linkage.

For Cowork, start a fresh task after plugin installation. First establish the
actual execution host through an automatic neutral callback. A macOS Desktop
frontend can execute plugin hooks in a cloud Linux task; use that runtime's
binary and adjacent engine. The tested package used `scripts/runtime` and a
plugin-relative wrapper, avoiding hard-coded host paths. Compare an allowed
Write, denied Write, stopped-policy control, and restored-policy denial through
the real tool UI and independent files. Export the metadata ledger, verify native
session identifiers and content omission, and hash the exact tested plugin and
runtime files. Test any rebuilt packaging helper as its own artifact; a previous
plugin pass does not qualify a different ZIP.


The authenticated Copilot Windows follow-up used CLI 1.0.105 ARM64 with v0.3.1
x64 Lens under emulation. Keep the generated direct-exec hook configuration,
normal workspace trust, write approval, and workspace-path checks. Expose the
actual `apply_patch` tool and pair exact allowed contents with absent denied
paths, then repeat with policy stopped and restored. Preserve the artifact's CI
source identity and executable/library hashes. The successful run emitted six
event types; do not infer all-event or timeout coverage from it. See the
[verification record](verification.md#copilot-raw-patch-regression--v031-candidate).
