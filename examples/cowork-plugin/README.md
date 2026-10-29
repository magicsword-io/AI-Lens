# Cowork hooks-only plugin — experimental source preview

This skeleton contains only `.claude-plugin/plugin.json`. Generate
`hooks/hooks.json` for your own executable and state paths before packaging.
It has no hook stub, bundled binary, top-level `bin/`, or required skill.
Published v0.2.0 downloads do not include the `cowork` adapter; build both Rust
workspace crates from this repository and preserve the executable's
adjacent engine library.

Cowork is documented to load plugin hooks. This example implements that contract
with a distinct `cowork` adapter, but **native Desktop/VM execution is not yet
validated**. The manifest's version does not claim a new published release,
minimum Desktop version, or compatibility with every Cowork execution host.

## Generate and package

Provision the executable, adjacent engine library, rules, state and output
separately. Each absolute path must be reachable with appropriate permissions
where the installed Cowork runtime actually executes hooks. A host path that
exists in your terminal is not proof it exists in a VM or cloud task. Do not put
binaries in top-level `bin/`: ordinary account-uploaded Cowork rejects that layout.

From the repository root, the following POSIX example creates a temporary plugin
directory. Replace the four `/absolute/path` values first. Use a private output
location and rules appropriate to the disposable task you intend to test.

```sh
lens_exe=/absolute/path/agent-lens
lens_state=/absolute/path/lens-state
lens_rules=/absolute/path/default.yaml
lens_output=/absolute/path/events.jsonl

"$lens_exe" --state "$lens_state" start \
  --output "$lens_output" --rules "$lens_rules"

plugin_dir=$(mktemp -d "${TMPDIR:-/tmp}/agent-lens-cowork.XXXXXX")
mkdir -p "$plugin_dir/.claude-plugin" "$plugin_dir/hooks"
cp examples/cowork-plugin/.claude-plugin/plugin.json "$plugin_dir/.claude-plugin/plugin.json"
"$lens_exe" --state "$lens_state" config --agent cowork > "$plugin_dir/hooks/hooks.json"

# Review both JSON files and the generated absolute paths before packaging.
cat "$plugin_dir/.claude-plugin/plugin.json" "$plugin_dir/hooks/hooks.json"
(
  cd "$plugin_dir"
  zip -r agent-lens-cowork.zip .claude-plugin hooks
)
```

The ZIP contains `.claude-plugin/plugin.json` and `hooks/hooks.json` at their
expected root-relative locations, without an extra enclosing folder. Generated
config is deployment-specific; do not commit a copy with local paths. On Windows,
use the actual absolute `agent-lens.exe` and equivalent directory/ZIP operations;
ensure the ZIP includes the dot-prefixed manifest directory. The generated hook
uses direct executable/argv fields, so do not add shell quoting to the JSON args.

The config subscribes to exactly five events: `SessionStart`, `SessionEnd`,
`PreToolUse`, `PostToolUse`, and `PostToolUseFailure`. Each hook uses matcher `.*`,
the absolute executable, explicit `--event` arguments, and a 30-second timeout.
Only `PreToolUse` is preventive and requests `onFailure: "block"`. It returns
Claude-style `hookSpecificOutput.permissionDecision: "deny"` for a matching
block rule. Other events return `{}`; their block matches are observations.
These documented controls still need testing through the actual Desktop runtime.

## Install and confirm the runtime

For an ordinary account installation, follow **Customize > Plugins > Add >
Upload plugin ZIP** in the supported Claude interface. Review the requested
plugin and organization controls, then follow the installed Desktop's activation,
reload/restart flow and start a new Cowork task. AI Lens does not upload the
plugin, edit global settings, grant trust, or bypass managed policy.

Third-party-provider Desktop deployments have separate managed plugin paths and
documented host-execution details; do not apply those paths to every consumer,
local or cloud session. Confirm the installed Desktop and runtime versions,
plugin load state and access to the executable/library, state, rules and output.
Lens `status` only checks local state, not whether Cowork loaded or invoked hooks.

Before relying on enforcement, use a disposable task to compare an allowed
harmless operation with a denied harmless operation and independently inspect
the side effect and JSONL. Also check the client's behavior for missing binaries,
invalid stdout and timeouts. No such Desktop acceptance result is claimed here.
To deactivate Lens, run `stop` using the same state path; uninstall or disable
the plugin through the client to remove its callbacks.

This native plugin is separate from `claude-cowork-otel`, Anthropic Compliance
feeds, and hosted Enterprise inference webhooks. OTLP and audit ingestion are
always observation-only and cannot substitute for a native blocking gate.

Official references, retrieved **2026-10-29**:

- [Plugin platform support](https://claude.com/docs/plugins/platform-support.md)
- [Cowork plugin components](https://claude.com/docs/cowork/guide/plugins.md)
- [Install plugins in Cowork](https://support.claude.com/en/articles/13837440-use-plugins-in-cowork.md)
- [Linked hook package schema](https://code.claude.com/docs/en/plugins/components#hooks)
- [Third-party Desktop plugin hooks](https://claude.com/docs/third-party/claude-desktop/extensions.md#plugin-hooks)

See [agent setup](../../docs/agents.md#claude-cowork--experimental-plugin-integration)
for the full source and failure boundaries.
