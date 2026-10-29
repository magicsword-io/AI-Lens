# Agent hook adapters

AI Lens v0.3.0 and the current source have seven native adapter IDs:
`claude`, `codex`, `hermes`, `gemini`, `cursor`, `copilot`, and `cowork`.
AI Lens prints configuration for review with `config --agent ID`.
Merge the resulting `hooks` entries into your existing configuration yourself.
The command does not edit agent files, enable hooks, approve trust, or start an
agent. Preserve existing entries when merging. Restart/reload the agent as its
own documentation requires.

Each configured event invokes the absolute AI Lens executable and state path
with `hook --agent AGENT --event EVENT`. The explicit event lets the host emit a
native denial for a known pre-tool event even if stdin is malformed. If the
payload supplies `hook_event_name`, it must match `--event` exactly, except the
documented Copilot `notification` callback's `Notification` discriminator. Unknown
agents, unregistered events, and mismatches are errors. Native command hooks
send one JSON object on stdin; stdout contains only a vendor response object.

A successful policy check normally returns `{}`. Cursor `preToolUse` and the
observational `subagentStart` instead receive documented `{"permission":"allow"}` responses,
including when Lens is stopped. These responses continue through the hook while
leaving the agent's own permission checks in control. A policy denial uses the
vendor's documented response shape.
Only the preventive events listed below are enforceable in the current source.
Other rule matches are recorded as `would_block`; completed actions are never
undone, and stop events never force an agent into another turn.

v0.3.0 packages include all seven adapters; Cursor, Copilot CLI, and Cowork
remain experimental. Historical v0.2.0 downloads contain only Claude Code, Codex,
Hermes, and Gemini CLI. Cowork's native
Desktop/VM execution is unvalidated. The v0.1.0 downloads contain the original
three adapters. Antigravity is not supported.

Native hooks can request blocking at the specific preventive events below.
The separate [OTLP and provider audit sources](telemetry-sources.md) are always
observation-only and never evaluate block rules. `--agent copilot` is not
`--source copilot-otel`, `copilot-audit`, or `copilot-session`; the same separation
applies to Cursor and Cowork.

## Claude Code

Merge the snippet into the `hooks` object in `.claude/settings.json` or your
user settings. AI Lens uses synchronous command hooks and subscribes to all
tool names by omitting a matcher. Existing agent permission and trust settings
still apply. The generated command uses your selected host shell; on Windows
use `config --agent claude --shell powershell`. The adapter explicitly emits
`"shell": "powershell"` for the host's PowerShell `&` command, and `"shell":
"bash"` for a POSIX command. This matters because Claude normally uses Git Bash
on Windows when it is installed, falling back to PowerShell only when it is not.
The explicit field keeps the selected command dialect and hook shell aligned.
Claude also supports shell-free exec form through `type: "command"` plus
`command: EXE` and `args: [...]`; there is no separate `type: "exec"`. The
current engine config API accepts a command string and therefore emits shell
form. The exact generated command must work in the specified shell.

Preventive events:

| Event | Native denial on stdout |
| --- | --- |
| `PreToolUse` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Blocked by Agent Lens policy"}}` |
| `PermissionRequest` | `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"Blocked by Agent Lens policy"}}}` |

`PermissionRequest` runs only when the agent requests approval; it is not a
replacement for `PreToolUse`. AI Lens does not auto-approve either event.

The explicit registry has 27 events:

| Phase | Events |
| --- | --- |
| pre | `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PreCompact`, `Elicitation` |
| post | `PostToolUse`, `PostToolUseFailure`, `PostToolBatch`, `PermissionDenied`, `PostCompact`, `ElicitationResult` |
| lifecycle | `SessionStart`, `Setup`, `InstructionsLoaded`, `Notification`, `SubagentStart`, `SubagentStop`, `TaskCreated`, `TaskCompleted`, `Stop`, `StopFailure`, `TeammateIdle`, `ConfigChange`, `CwdChanged`, `DirectoryAdded`, `FileChanged`, `SessionEnd` |

`WorktreeCreate` and `WorktreeRemove` are deliberately excluded: these replace
native worktree operations. `PreModelSwitch`, `PostModelSwitch`,
`UserPromptExpansion`, and `MessageDisplay` are outside this release. An event
being supported upstream does not imply AI Lens subscribes to it.

Source: [official Claude hook reference](https://code.claude.com/docs/en/hooks),
including [exec and shell form](https://code.claude.com/docs/en/hooks#exec-form-and-shell-form),
[command hook fields](https://code.claude.com/docs/en/hooks#command-hook-fields), [PreToolUse](https://code.claude.com/docs/en/hooks#pretooluse-decision-control)
and [PermissionRequest](https://code.claude.com/docs/en/hooks#permissionrequest-decision-control),
read 2026-10-28.

## Codex

Merge the generated snippet into `.codex/hooks.json` or `~/.codex/hooks.json`.
Codex also supports inline hooks in `config.toml`; the generated output uses the
native JSON form. User, project, managed, and plugin hook sources can all
contribute matching hooks. Review the exact hook definitions through Codex's
`/hooks` interface; changed definitions can require a new trust review. AI
Lens never changes trust settings.

Codex uses the same `PreToolUse` and `PermissionRequest` denial JSON shown above.
Shell and unified exec tools appear as `Bash`; patch edits appear as
`apply_patch`, with `tool_input.command`. MCP and other local function tools
use their own names and JSON arguments. Tool-specific coverage has upstream
exceptions; use the official tool coverage table for your client/version.
The legacy `notify`/`agent-turn-complete` surface is not this hook protocol.

The explicit registry has 12 events:

| Phase | Events |
| --- | --- |
| pre | `PreToolUse`, `PermissionRequest`, `PreCompact`, `UserPromptSubmit` |
| post | `PostToolUse`, `PostCompact` |
| lifecycle | `SessionStart`, `SessionEnd`, `SubagentStart`, `SubagentStop`, `Stop`, `Interrupt` |

Only `PreToolUse` and `PermissionRequest` are preventive here. `PostToolUse`
never reverses a tool. `Stop`/`SubagentStop` responses are `{}` to avoid unwanted
continuation. `SessionEnd` and `Interrupt` have a three-second timeout because
Codex caps them at three seconds; other commands use ten seconds. A busy state
lock or unavailable dependency can exceed those windows, so delivery is not
guaranteed.

Source: [official Codex hooks](https://learn.chatgpt.com/docs/hooks), especially
[tool coverage](https://learn.chatgpt.com/docs/hooks#tool-coverage) and
[PreToolUse](https://learn.chatgpt.com/docs/hooks#pretooluse), read 2026-10-28.
These command hooks target supported local Codex execution. Cloud orchestration
can have different managed MCP hook requirements.

## Hermes Agent

Current Hermes supports native shell hooks in profile `config.yaml`, plus
Python plugin callbacks. AI Lens uses native shell hooks, so no Python bridge
or custom plugin is necessary. JSON objects are valid YAML: merge the generated
`hooks` mapping into the profile's existing configuration. Example:

```yaml
hooks:
  pre_tool_call:
    - command: "'/absolute/path/agent-lens' --state '/absolute/state' hook --agent hermes --event pre_tool_call"
      timeout: 10
      fail_closed: true
  post_tool_call:
    - command: "'/absolute/path/agent-lens' --state '/absolute/state' hook --agent hermes --event post_tool_call"
      timeout: 10
```

Hermes splits a command into argv and launches a subprocess without a shell.
On POSIX this uses `shlex.split`; current Windows source uses Hermes's
`split_command_line` compatibility helper to preserve path backslashes. Do not
use PowerShell's `&` call operator, shell expansion, or shell pipelines in a
Hermes command. The host must render a native argv-compatible command even when
`--shell powershell` is selected. On Windows, wrap each executable/state path
in simple double quotes and preserve backslashes, including a final backslash.
Windows filenames cannot contain literal double quotes. POSIX apostrophe
escaping does not roundtrip through Hermes's Windows tokenizer, and Windows
`list2cmdline` escaping is also unsuitable for this intermediate command string:
the tokenizer does not undo its escaped backslashes before quotes. After the
native tokenizer produces argv, Python's subprocess layer handles Windows
process serialization itself. Review the final command on the actual platform.
The adapter rejects the PowerShell call operator to make a bad configuration
observable.

Hermes requires consent for each `(event, command)` pair. Unapproved hooks can
be skipped, and safe mode can disable hook callbacks. AI Lens does not grant
consent, install plugins, alter `hooks_auto_accept`, or change safe mode.

The shell stdin envelope contains `hook_event_name`, `tool_name`, `tool_input`,
`session_id`, `cwd`, `profile`, and `extra`. Native `args` becomes `tool_input`;
event-specific kwargs such as `result`, `user_message`, `task_id`, and
`tool_call_id` appear in `extra`. `tool_input` is null for non-tool events.
AI Lens also accepts documented Python callback `args` when replaying a
payload with an explicit event. It never substitutes `task_id` for `session_id`.

Only `pre_tool_call` is preventive. It runs synchronously before tool dispatch.
AI Lens returns `{"action":"block","message":"Blocked by Agent Lens policy"}`
to veto execution and `{}` to leave native processing in control. Upstream's
`_get_pre_tool_call_directive_details` recognizes a block only with a nonempty
message. The native shell parser translates this JSON into the plugin callback's
block directive. `fail_closed: true` requests upstream denial on subprocess
failure, timeout, nonzero exit without a directive, or malformed output.
The host also emits the canonical denial for recognized pre-tool failures.

The explicit registry has 22 events:

| Phase | Events |
| --- | --- |
| pre | `pre_tool_call`, `pre_llm_call`, `pre_api_request`, `pre_auxiliary_call`, `pre_approval_request`, `on_human_input_request` |
| post | `post_tool_call`, `post_llm_call`, `post_api_request`, `api_request_error`, `post_auxiliary_call`, `post_compaction`, `post_approval_response`, `on_human_input_resolved` |
| lifecycle | `on_session_start`, `on_session_end`, `on_session_finalize`, `on_session_reset`, `on_session_delete`, `subagent_start`, `subagent_stop`, `agent_loop_stopped` |

This excludes transform, streaming, gateway dispatch, verification, and unrelated
plugin hook families. Gateway `HOOK.yaml`/`handler.py` notification hooks are a
separate asynchronous surface and cannot provide this preventive guarantee.
Older Hermes versions lacking native shell hooks or `fail_closed` need a
separately reviewed integration; do not assume this snippet is compatible.

Sources, read 2026-10-28:

- [Official Hermes Event Hooks](https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks/)
- [Official observer contract](https://hermes-agent.nousresearch.com/docs/developer-guide/observer-hooks/)
- [Pinned shell-hook implementation](https://github.com/NousResearch/hermes-agent/blob/0c74cc682dc81bf78b78a1737b3ee77a820ccb79/agent/shell_hooks.py)
- [Pinned plugin dispatch](https://github.com/NousResearch/hermes-agent/blob/0c74cc682dc81bf78b78a1737b3ee77a820ccb79/hermes_cli/plugins.py)
- [Pinned Windows argv helper](https://github.com/NousResearch/hermes-agent/blob/0c74cc682dc81bf78b78a1737b3ee77a820ccb79/hermes_cli/_subprocess_compat.py)

## Gemini CLI

Gemini CLI is the fourth adapter, available in v0.2.0. Extract the matching
package and keep the executable beside its engine library. This integration is
for Gemini CLI only, not Antigravity.

From the extracted package directory, start a state directory and print the
configuration for review:

```sh
./agent-lens --state "$PWD/lens-state" start \
  --output "$PWD/events.jsonl" --rules "$PWD/examples/rules/default.yaml"
./agent-lens --state "$PWD/lens-state" config --agent gemini
```

On Windows, use PowerShell:

```powershell
$lensState = Join-Path $PWD 'lens-state'
$lensOutput = Join-Path $PWD 'events.jsonl'
$lensRules = Join-Path $PWD 'examples\rules\default.yaml'
.\agent-lens.exe --state $lensState start --output $lensOutput --rules $lensRules
.\agent-lens.exe --state $lensState config --agent gemini
```

Review the printed JSON and merge its `hooks` entries into user
`~/.gemini/settings.json` or a trusted project's `.gemini/settings.json`.
Preserve existing settings and hooks; do not overwrite the whole file with the
snippet. Each event contains a hook-definition array with a nested `hooks` array
of `type: "command"` entries. Generated timeouts are `10000` **milliseconds**
(ten seconds), not seconds. Tool hooks match all tool names.

The inspected Gemini runtime shell helper selects PowerShell on Windows and
`bash -c` on Unix in npm `@google/gemini-cli` 0.66.0 source
(`970413207732f5d4d8c50540c7fc359c44fdaaf2`). The helper prefers `pwsh.exe` on Windows and
falls back to `powershell.exe`. This describes runtime components, not a verified
whole-client integration. AI Lens renders the matching command dialect
independently of `--shell`; do not replace the Windows PowerShell call operator
with Hermes argv quoting. Unix commands use POSIX-compatible quoting.

Gemini substitutes five literal macros even inside quoted hook commands. To
avoid changing executable or state paths during dispatch, `config --agent gemini`
rejects either path when it contains `$GEMINI_PROJECT_DIR`, `$GEMINI_CWD`,
`$GEMINI_PLANS_DIR`, `$GEMINI_SESSION_ID`, or `$CLAUDE_PROJECT_DIR`. Choose
different executable and state paths; adding shell quotes does not prevent
this upstream substitution.

Open Gemini CLI in the intended workspace and review the definitions through
`/hooks panel`. Follow its normal project-hook review and any workspace trust
prompts; changed project hooks may require review again. Native hook enablement,
permissions, and trust still apply. AI Lens does not install Gemini, edit its
settings, grant trust, or bypass consent. A printed configuration and Lens
`status` output do not establish that the client invokes the hooks.

The explicit registry has nine events:

| Phase | Events | AI Lens enforcement |
| --- | --- | --- |
| pre | `BeforeTool` | Native tool denial |
| pre | `BeforeAgent`, `BeforeToolSelection`, `PreCompress` | Observe only |
| post | `AfterTool`, `AfterAgent` | Observe only |
| lifecycle | `SessionStart`, `SessionEnd`, `Notification` | Observe only |

`SessionEnd` delivery is best effort: upstream shutdown does not wait for the
hook to finish, so its callback can be lost. The configured nine-event inventory
is not a guarantee that every event will be observed in a live session.

Only `BeforeTool` is enforceable in AI Lens. A matching block rule returns:

```json
{"decision":"deny","reason":"Blocked by Agent Lens policy"}
```

A successful check returns `{}` and leaves native permissions in control; it
never auto-approves a tool. For a recognized `BeforeTool` invocation, the host
also returns a native denial on handled input, rule, or engine-output failures.
This does not guarantee denial if the client skips a hook, cannot launch it,
or times it out.

Other registered events return `{}` even for block matches, which are recorded
as `would_block`. AI Lens does not hide completed tool results, rewrite tool
inputs, reject responses, force another turn, or filter tool selection. Upstream
flow-control capabilities on other events do not expand this adapter's contract.
`BeforeModel` and `AfterModel` are deliberately excluded to avoid model-request
and response-chunk overhead.

Native `tool_name` values include `read_file`, `write_file`, `replace`, and
`run_shell_command`; their arguments arrive in `tool_input`. The current rules
include these names and the `gemini` selector. Configuration-integrity examples
include `.gemini/settings.json`, `.gemini/hooks/`, and `GEMINI.md`. Direct path
rules cover the native `file_path` arguments of `read_file`, `write_file`, and
`replace`. They do not interpret `read_many_files` include globs or expand them
into file paths; do not assume the direct-file policy covers that tool.

Gemini MCP tool names use single separators, such as `mcp_fetch_fetch` and
`mcp_playwright_browser_evaluate` (`mcp_server_tool`). The optional named-tool
rules accept these and the double-separator forms used by other adapters, such
as `mcp__fetch__fetch`. Source fixture aliases are illustrative; catalog replay
translates them to Gemini native names. Match your actual server/tool registry
rather than assuming an illustrated alias exists.

Before relying on the integration, use a disposable workspace to check an allowed
harmless tool call and a denied harmless side effect through your installed
client, then independently inspect the side effect and JSONL. Synthetic replay
and an offline upstream dispatcher check are distinct from authenticated Google
live-client acceptance; this documentation makes no such live-client claim.
The pinned 0.66.0 native check uses the unmodified vendor runtime/tool seam,
including the full `HookSystem`, with a minimal Config facade and explicitly
fired events. It excludes actual CLI settings loading, trust/consent, and a
provider-driven session. This check is configured in native CI on Linux, Windows,
and macOS; consult the [verification record](verification.md#gemini-cli-adapter-v020-2026-10-29)
and workflow results for observed outcomes. It does not establish whole-client
acceptance or delivery of the complete event inventory in a live session.

Public sources, reviewed 2026-10-29:

- [Gemini CLI hook reference](https://geminicli.com/docs/hooks/reference/)
- [Hook configuration, management, and security](https://geminicli.com/docs/hooks/)
- [Gemini CLI configuration](https://geminicli.com/docs/get-started/configuration/)
- [Trusted folders](https://geminicli.com/docs/cli/trusted-folders/)
- [Pinned native shell selection](https://github.com/google-gemini/gemini-cli/blob/970413207732f5d4d8c50540c7fc359c44fdaaf2/packages/core/src/utils/shell-utils.ts)

## Cursor — experimental

Build both workspace crates from this repository; keep the executable
and engine library adjacent. Activate an explicit state directory with `start`,
then print `config --agent cursor` using that same `--state` path. Review and merge
the version-1 `hooks` mapping into project `.cursor/hooks.json` or user
`~/.cursor/hooks.json`; do not replace existing hooks. Project commands run from
the project root; user commands run from `~/.cursor/`. Generated executable and
state paths are absolute. The CLI does not install Cursor or modify its settings.

The configuration uses a command string, ten-second `timeout`, an explicit
`--event` for each callback, and `failClosed: true` on `preToolUse`. For Windows
Desktop use PowerShell command quoting (`--shell powershell`); quoted executable
paths need the call operator. The published Desktop shell contract does not
establish Windows CLI execution behavior. Review the actual generated command on
your target platform rather than assuming shell dialects are interchangeable.

Complete normal workspace trust and hook review, then reload/restart the client
as required for its configuration source. Team/enterprise hooks may load
separately; the documented “Block until hooks are ready” setting addresses
startup loading. A printed config or Lens `status` does not establish registration
or first-prompt coverage. User home hooks do not automatically propagate to cloud.

The explicit registry has **11 events**:

| Phase | Events | AI Lens enforcement |
| --- | --- | --- |
| pre | `preToolUse` | Native tool denial |
| pre | `preCompact` | Observe only |
| post | `postToolUse`, `postToolUseFailure`, `afterAgentResponse` | Observe only |
| lifecycle | `sessionStart`, `sessionEnd`, `subagentStart`, `subagentStop`, `stop`, `workspaceOpen` | Observe only |

Only generic `preToolUse` is preventive here. Input requires `tool_name` and an
object `tool_input`. Cursor supplies `hook_event_name`; `workspaceOpen` can omit
session identifiers. Normal continuation is `{"permission":"allow"}`; denial is:

```json
{"permission":"deny","user_message":"Blocked by Agent Lens policy","agent_message":"Blocked by Agent Lens policy"}
```

`subagentStart` is deliberately observational but also returns explicit allow;
other observed events return `{}` without mutation or continuation instructions.
Dedicated shell/MCP/file gates, Tab events, prompt submission and thought streams
are excluded to avoid duplicate gates and content-heavy capture. Generic
`preToolUse` does not enforce `ask`, so Lens does not use it.

Cursor documents invalid permission responses/invalid JSON and exit 2 as blocking.
Crashes, timeouts and other failures normally fail open; generated `failClosed`
requests denial for the preventive hook. Client invocation, config loading and
failure handling still require testing on the installed version. Preserve stdout
as one protocol response, with diagnostics on stderr.

Native tool names include `Shell`, `Read`, `Write`, `Grep`, `Delete`, `Task`, and
`MCP:<tool_name>`. Match the actual tool registry and arguments. Cloud initial
read-only turns run no hooks; later cloud hooks require a writable environment.
Cloud also lacks several local lifecycle events. Do not extend local gate or
lifecycle coverage to all cloud sessions from this registry alone.

Official sources retrieved **2026-10-29**:
[Cursor hooks](https://cursor.com/docs/hooks.md),
[CLI parameters and trust](https://cursor.com/docs/cli/reference/parameters.md),
and [CLI permissions](https://cursor.com/docs/cli/reference/permissions.md).
The latter permission files are separate from hook configuration. Synthetic
adapter replay is not native Cursor enforcement evidence.

## GitHub Copilot CLI — experimental

Use the same activated state directory when printing `config --agent copilot`.
The generated version-1 JSON has `type: "command"`, an absolute `exec`, separate
`args` including each `--event`, and `timeoutSec: 30`. This direct argv form is
**CLI-only**; it avoids shell parsing. Do not join args into a shell command or
combine `exec` with shell-command fields. On Windows use the actual `.exe`.
The generated config is not a Copilot cloud, IDE, or SDK callback integration.

Review and merge into `.github/hooks/*.json` in the repository or
`~/.copilot/hooks/*.json` (`%USERPROFILE%\.copilot\hooks` on Windows;
`COPILOT_HOME` can change the user root). Supported inline settings are another
upstream option; `config.json` is no longer a hooks source. Preserve existing
hooks. Complete normal workspace admission/trust, then **restart Copilot CLI**
after configuration changes. AI Lens neither grants trust nor disables
client permissions. In sandboxed sessions, repository/user hook commands run
inside the sandbox: the executable, engine library and output directory must be
reachable under existing grants. Admin policy hooks have a separate host context.

The explicit camelCase registry has **12 events**:

| Phase | Events | AI Lens enforcement |
| --- | --- | --- |
| pre | `preToolUse` | Native tool denial |
| pre | `userPromptSubmitted`, `preCompact` | Observe only |
| post | `postToolUse`, `postToolUseFailure` | Observe only |
| lifecycle | `sessionStart`, `sessionEnd`, `errorOccurred`, `agentStop`, `subagentStart`, `subagentStop`, `notification` | Observe only |

The callback does not guarantee an event discriminator; the generated command
always passes `--event`. Lens accepts native `toolName` and object `toolArgs` or
one JSON-encoded object string, as shown in the official CLI guide. Malformed
strings, arrays/scalars and excessive nesting are rejected. PascalCase aliases
use a different snake_case protocol and are not accepted as equivalent events.
The documented `Notification` discriminator is accepted for native `notification`.

Only `preToolUse` is preventive. A successful policy check returns `{}` to leave
native approval in control; denial uses:

```json
{"permissionDecision":"deny","permissionDecisionReason":"Blocked by Agent Lens policy"}
```

Other registered events return `{}`. Lens does not use stop hooks to force another
turn or rewrite results/prompts. `permissionRequest`, `userPromptTransformed`,
and undocumented events are excluded. Built-in general-purpose subagents can
omit subagent lifecycle callbacks; detached session-end delivery can be lost.

**Copilot command-hook timeouts always fail open**, including admin policy hooks;
there is no documented timeout fail-closed setting. Crashes and nonzero command
exits deny `preToolUse`, but malformed/contaminated stdout can yield default
behavior. A host-generated denial only helps if it arrives before the upstream
timeout. The generated 30-second timeout is not an enforcement guarantee.
HTTP hook failure behavior is different; Lens generates command hooks.

Native tools include `bash`, `powershell`, `view`, `create`, `edit`, and
`apply_patch`. Keep native names in rules and review actual tool argument fields;
MCP names are not universally Claude-style `mcp__` names. Cloud hooks support a
different configuration subset without direct `exec`; do not copy this CLI
configuration into cloud and assume it is loaded.

Official sources retrieved **2026-10-29**:
[hook configuration](https://docs.github.com/en/copilot/reference/hooks-configuration),
[CLI setup and restart](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks),
and [CLI reference](https://docs.github.com/en/copilot/reference/cli-command-reference).
No installed-client allow/deny or timeout outcome is inferred from adapter tests.

## Claude Cowork — experimental plugin integration

`cowork` is a distinct native adapter, separate from `claude` and from
`claude-cowork-otel`. Official platform documentation explicitly says Cowork
loads `hooks/hooks.json`, and plugins may contain hooks without skills. This
supports the integration design; **native Desktop/VM execution remains
unvalidated**. Do not infer a minimum Cowork Desktop version or executable
reachability from a Claude Code version gate or a synthetic fixture.

The explicit registry has **five events**:

| Phase | Events | AI Lens enforcement |
| --- | --- | --- |
| pre | `PreToolUse` | Native tool denial |
| post | `PostToolUse`, `PostToolUseFailure` | Observe only |
| lifecycle | `SessionStart`, `SessionEnd` | Observe only |

Payloads use the documented Claude-style `hook_event_name`, `session_id`,
`tool_name`, and object `tool_input`. Only `PreToolUse` can deny, using the Claude
`hookSpecificOutput.permissionDecision: "deny"` response above. Other events
return `{}` and block matches are `would_block`. This limited registry does not
claim all Claude Code events occur in Cowork.

After building both crates and activating a state directory, print
`config --agent cowork` with that same state path. The output is the contents of
plugin **`hooks/hooks.json`**, with a top-level hooks map, matcher `.*`, absolute
executable `command` and separate `args`, including the explicit event. It uses
30-second timeouts and `onFailure: "block"` for the preventive hook. Preserve argv
boundaries; the presence of `args` selects direct execution, not a shell command.
On Windows the command must identify the actual executable, not a `.cmd` shim.
These are documented failure controls, pending actual Cowork runtime validation.

Use the hooks-only package example under [`examples/cowork-plugin`](../examples/cowork-plugin).
Its manifest lives at `.claude-plugin/plugin.json`; review the generated hooks
and package them according to that example. **Provision AI Lens and its
adjacent engine library separately** where hooks actually execute. Do not put
binaries in top-level `bin/`: ordinary account-uploaded Cowork rejects that plugin
layout. No skill is required and a ZIP upload cannot establish binary reachability.

For ordinary account installations, review the package through **Customize >
Plugins > Add > Upload plugin ZIP**, then follow the installed Desktop's plugin
activation/reload or restart flow and start a new task. Preserve organization
controls and normal consent. Third-party-provider Desktop has separate managed
plugin paths and documents on-device Windows execution in a particular setup;
those details do not prove the execution host for every local/cloud Cowork task.
Verify access to the executable, engine, state, rules and output in the actual
runtime before relying on a denial. `status` alone does not prove plugin loading.

Official sources retrieved **2026-10-29**:
[platform support](https://claude.com/docs/plugins/platform-support.md),
[Cowork plugin guide](https://claude.com/docs/cowork/guide/plugins.md),
[plugin installation](https://support.claude.com/en/articles/13837440-use-plugins-in-cowork.md),
[third-party Desktop hooks](https://claude.com/docs/third-party/claude-desktop/extensions.md#plugin-hooks),
and [linked hook schema](https://code.claude.com/docs/en/plugins/components#hooks).
Separate Enterprise inference webhooks are a hosted product integration; they
are not implemented by this local adapter. Cowork OTel and Compliance feeds
remain observational regardless of plugin availability.

## Evidence and limits

The registries in `crates/engine/src/adapters.rs` and its adapter modules drive
both parsing and printed configuration. Tests enumerate every subscribed event, reject explicit/native
event mismatches, validate vendor response shapes, and assert no registration
of operation-replacing hooks. `examples/events/*.json` are synthetic fixtures,
not captured user sessions. Normalization retains original input for policy
matching; the engine omits content by default and redacts opted-in content.
Native session/tool identifiers are optional, bounded, and never fabricated.

Synthetic tests and subprocess replay prove the adapter/host boundary. They do
not prove that an installed agent version invokes the hook, that trust/consent
was granted, or that every tool path is covered. This applies to the new Cursor,
Copilot CLI and Cowork source-preview adapters as well as existing integrations. Live agent
acceptance needs an allowed harmless operation and a denied harmless operation
whose side effect is independently checked, plus an observed post/lifecycle
event on the exact client version and platform. The separate [verification record](verification.md) distinguishes observed live-client
results from these synthetic adapter checks.
AI Lens is not a filesystem sandbox or an immutable security boundary.
