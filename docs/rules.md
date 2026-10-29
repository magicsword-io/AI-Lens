# Rules

A rules file is YAML with `version: 1` and a `rules` list. Start with
[the example policy](../examples/rules/default.yaml), then validate your changes:

```sh
agent-lens rules-check --rules examples/rules/default.yaml
```

`rules-check` returns `valid` and the `rule_ids` read by the actual YAML parser,
including quoted IDs. Validation does not activate collection. Use `start --rules PATH` to select the
file for a state directory, and validate edits before using them. Rules are
trusted local configuration; keep their directory and contents under review.

v0.3.0 packages include `cursor`, `copilot`, and
experimental `cowork` native hook selectors. Historical v0.2.0 ZIPs contain
four adapters; v0.1.0 does not accept `gemini`. Antigravity is unsupported.
OTLP and audit source names are not rule agent selectors: those feeds are
observation-only. See [native setup and limitations](agents.md).

## A concrete rule

```yaml
version: 1
rules:
  - id: protect-env-files
    description: Demonstrate a denial for direct file tools targeting .env files.
    agents: [claude, codex, hermes, gemini, cursor, copilot, cowork]
    tool_pattern: '^(Read|Write|Edit|MultiEdit|read_file|write_file|apply_patch|patch|replace|view|create|edit|str_replace_editor)$'
    path_pattern: '(?i)(^|/)\.env(\.[^/]*)?$'
    action: block
```

A direct file-tool input containing `/work/.env.local` matches both patterns.
`/work/env.example` does not. The engine searches recognized native path fields recursively for
path matches; an embedded patch is a single string, so a path inside its syntax
may not match this anchored pattern. Shell commands and embedded patch syntax
need separate, best-effort content rules and real payload tests. Gemini native
file tools include `read_file`, `write_file`, and `replace`; shell calls use
`run_shell_command`. Direct path rules cover these native file tools through
`file_path`; they do not interpret `read_many_files` include globs or expand
them into file paths. That tool is outside this direct-file coverage.

| Field | Meaning |
| --- | --- |
| `id` | Unique stable identifier; recorded in `matched_rules`. Avoid sensitive text. |
| `description` | Optional human-readable explanation; use generic text. |
| `agents` | Optional list of adapter names: `claude`, `codex`, `hermes`, `gemini`, `cursor`, `copilot`, `cowork` in v0.3.0 and the current source. |
| `events` | Optional list of exact native event names. |
| `tool_pattern` | Optional Rust regex over the tool name. |
| `path_pattern` | Optional Rust regex over lexically normalized native path fields. |
| `content_pattern` | Optional Rust regex over original callback JSON and its string values. |
| `action` | Required: `block` or `audit`. |

Present selectors combine with **AND**. Entries within `agents` or `events`
offer alternatives. An omitted selector does not restrict the rule. At least
one selector is required; selector-free rules are rejected to avoid an accidental
block-everything policy. Unknown fields, invalid patterns, unsupported versions,
and configured size-limit violations are errors. Limits include 128 rules,
256 KiB of YAML, 4,096 bytes per regex, and bounded regex compilation.

All matching rules contribute their IDs. Any matching `block` rule wins over
audit-only matches. There is no allow override and no first-match ordering.
No matches means allow; an audit match also allows, while retaining its ID.

## Outcomes depend on the hook

| Match | Hook capability | Decision |
| --- | --- | --- |
| No match, or audit matches only | Any | `allow` |
| Block match | Supported pre-tool denial | `block` |
| Block match | Post-tool, lifecycle, or observe-only | `would_block` |

Keep `events` absent when you want the same rule to show both preventive and
observational matches. Restrict it to a native pre-tool event when that is your
intent. Hermes supports synchronous denial for `pre_tool_call`; its other
registered events are observational. Gemini CLI supports denial only for
`BeforeTool`; its other eight registered events return neutral responses, even
when a block rule produces `would_block`. An event name alone cannot grant support
to a client version or execution surface that lacks the callback.

## Regex and path behavior

Patterns use Rust's [regex syntax](https://docs.rs/regex/latest/regex/#syntax),
not shell globs. `*` does not mean "any path"; use `.*` when appropriate. Regexes
are unanchored unless you add `^` and `$`. Single-quoted YAML strings make
backslashes literal, so `path_pattern: '\.env$'` matches a literal period.

Windows path separators are normalized to `/` and `.`/`..` components are
collapsed lexically for path matching. Patterns
are case-sensitive unless they opt into `(?i)`. This is textual matching:
AI Lens does not resolve symlinks, prove filesystem identity, expand shell
variables, or parse every shell, encoding, alias, or patch language. Recognized path keys include `path`, `file_path`, `filePath`, `paths`,
`target_file`, source/destination, directory, `cwd`, and `workdir`. Paths in
unknown field names require a content rule. A path field still does not prove
that a file was accessed. Unknown event names are rejected, not normalized to
a supported policy event.
A tool name is data supplied by
the integration, not proof of a tool's authenticity.

The shipped policy also has a shell-specific literal `.env` rule:

```yaml
- id: protect-shell-env
  tool_pattern: '(?i)^(bash|powershell|shell|terminal|exec_command|shell_command|run_command|run_shell_command)$'
  content_pattern: '(?i)(^|[^A-Za-z0-9_])\.env([^A-Za-z0-9_]|$)'
  action: block
```

This matches `cat .env` and `Get-Content .env.local`, but can also match a harmless
`echo .env`. It does not resolve variables, decode obfuscated names, or inspect
what a later script opens. A separate direct file-tool rule demonstrates
`.aws/credentials`, `id_rsa`, and `id_ed25519` path suffixes, including Windows
separator normalization. It excludes public-key suffixes such as `id_rsa.pub`;
it is not a catalog of every credential store or a complete shell-access policy.

For an educational content rule:

```yaml
version: 1
rules:
  - id: demo-marker
    content_pattern: 'AGENT_LENS_BLOCK_DEMO'
    action: block
```

Test that marker in a harmless synthetic tool input. This demonstrates policy
matching without pretending to detect all destructive commands. Matching uses
the original callback even when content capture is disabled; opt-in redaction runs
after the decision. Denial reasons must not include the matching input text.

## Change safely

Begin with `action: audit` and inspect `matched_rules`. Try an intended match,
a nearby non-match, a supported pre-tool callback, and a post-tool callback.
Then test a harmless denied side effect through your installed client and keep
an allowed positive control. Promote to `block` only when those outcomes match
your intent. A synthetic replay proves parser/rule behavior, not that a live
agent invokes the hook.
