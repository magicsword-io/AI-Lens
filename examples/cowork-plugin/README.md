# Cowork plugin

Bundle the Linux x64 release into a plugin for Cowork's cloud Linux runtime.
The Windows Desktop client can launch that runtime; its hooks do not execute
as native Windows processes. This package does not support a Windows or macOS
hook execution host.

## Download and install

Download [ai-lens-cowork-0.3.1.zip](https://github.com/magicsword-io/AI-Lens/releases/download/v0.3.1/ai-lens-cowork-0.3.1.zip)
and compare its hash with `SHA256SUMS` from the same release. Upload this ZIP
through **Customize → Plugins → Add → Upload plugin ZIP**, enable it, and start
a new Cowork task. No local Rust build is needed. Use this plugin regardless of
the OS running Claude Desktop: the hooks execute in Cowork's Linux x64 cloud.

## Build your own upload ZIP

Download `agent-lens-0.3.1-linux-x86_64.zip` and `SHA256SUMS` from the
[release](https://github.com/magicsword-io/AI-Lens/releases/tag/v0.3.1).
From this repository, copy that archive's hash from `SHA256SUMS`:

```sh
python3 scripts/package_cowork_plugin.py \
  --release-zip /path/to/agent-lens-0.3.1-linux-x86_64.zip \
  --sha256 HASH_FROM_SHA256SUMS \
  --output /path/to/ai-lens-cowork.zip
```

The helper reads local files only, refuses an existing output, and checks the
entire input checksum before packaging. Its input limits are 100 MiB compressed,
256 MiB expanded, 64 MiB per member and 512 members. Unsafe paths, duplicate
names, symlinks and special files are rejected. A matching hash proves agreement
with the supplied checksum; obtain that checksum from the trusted release.

The plugin ZIP has no enclosing folder or top-level `bin/` (ordinary account
uploads reject `bin/`). It contains:

- `.claude-plugin/plugin.json` and `hooks/hooks.json`;
- `scripts/lens-hook.sh`, default `scripts/rules.yaml`, and `scripts/provenance.json`;
- the unmodified executable and adjacent engine under `scripts/runtime/linux-x86_64/`;
- the release's `LICENSE` and `NOTICE`.

Provenance records the original release ZIP hash and the hashes of its selected
members. The launcher and hook configuration have their own hashes. Packaging
does not rebuild the application or grant execution trust.

## Install and try it

In Cowork, open **Customize → Plugins → Add → Upload plugin ZIP**. Upload the
plugin ZIP, enable it, and start a **new task**. Follow account and organization
consent normally. Disable older AI Lens test plugins first to avoid duplicate
callbacks. Keep the plugin installed while using its state: paths point into
the active plugin directory, not the original download folder.

In a disposable task, request an ordinary file write and a harmless `.env` file
write. Independently check both the actual files and the event log. The default
policy should allow the ordinary write and request denial for `.env`. Native
Cowork cloud testing observed `SessionStart`, `PreToolUse` and `PostToolUse`, an
allowed real `Write`, and a denied real `.env` `Write`. This does not establish
all-event delivery, every tool's path coverage, every client version or every
execution host.

## Runtime state and controls

The launcher requires `/bin/sh`, `uname`, `id`, GNU-compatible `stat`,
`sha256sum`, `dirname`, `mkdir`, `rmdir`, `chmod` and `sleep` in the Linux runtime.
It rejects another OS/architecture. Startup initializes metadata-only collection
once; callback stdin passes unchanged to the native executable, and initialization
adds no protocol stdout. A bounded directory lock serializes initialization.

State lives inside the task runtime, not on the Desktop host:

```text
/tmp/ai-lens-cowork-<uid>-<sha256-of-active-plugin-path-and-release-hash>/
  state/config.json
  events.jsonl
  initialized
```

The containing directory must be a real directory owned by the runtime user,
mode `0700`; state is `0700` and config `0600`. Unsafe existing paths fail instead
of being repaired. `/tmp` must be root-owned with sticky directory permissions.
A changed plugin path or release hash gets separate state. A new cloud runtime
may discard old state and logs; export evidence before the task ends.

To inspect or stop collection, find this plugin's runtime directory and use its
bundled executable with that exact state path:

```sh
PLUGIN=/absolute/path/to/the/active/ai-lens-cowork/plugin
RUNTIME=/tmp/ai-lens-cowork-UID-HASH
"$PLUGIN/scripts/runtime/linux-x86_64/agent-lens" --state "$RUNTIME/state" status
"$PLUGIN/scripts/runtime/linux-x86_64/agent-lens" --state "$RUNTIME/state" stop
```

A stopped config stays stopped: later callbacks do not enable it again. An
initialized config that disappears is an error, not a request to recreate it.
Use an explicit `start --output ... --rules ...` with the same paths to resume.
Disabling or uninstalling the plugin removes its callbacks; it does not erase
exported logs. The launcher is a cooperative hook boundary, not protection
against the same user changing plugin files or state.

The configuration subscribes to `SessionStart`, `SessionEnd`, `PreToolUse`,
`PostToolUse` and `PostToolUseFailure`, with matcher `.*` and a 30-second timeout.
Only `PreToolUse` requests preventive denial and sets `onFailure: "block"`.
Other callbacks are observational. Real-client missing-binary, malformed-response
and timeout behavior require their own checks; subscription alone is not proof.

This plugin is separate from Cowork OTel and Anthropic Compliance feeds. OTLP and
provider audit ingestion are observation-only. See the repository's
`docs/agents.md` and `docs/verification.md` for coverage and evidence.

Official references:
[plugin platform support](https://claude.com/docs/plugins/platform-support.md),
[Cowork plugins](https://claude.com/docs/cowork/guide/plugins.md),
[installing plugins](https://support.claude.com/en/articles/13837440-use-plugins-in-cowork.md).
