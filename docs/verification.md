# Verification record

The sections below retain the original revision-specific evidence. The project
is now AI Lens by MagicSword under Apache-2.0; older names, licenses, repository
links, and artifact hashes describe their original runs.

## Migration validation — October 29, 2026

Production source `27a74aa` passed [native CI](https://github.com/MHaggis/expert-octo-adventure/actions/runs/40878613845)
on Windows x86_64 MSVC, Linux x86_64, and macOS ARM64. The migration changes
branding, licensing, documentation, packaging checks, and live-test runners;
production Rust source is unchanged. The [safe aggregate](evidence/validation-2026-10-29.json)
binds native and live results to their actual source, harness, and binary hashes.
Earlier evidence below keeps its original revision and naming.

| Check | Observed result |
| --- | --- |
| Local macOS build | fmt/clippy, 95 Rust tests, debug/release builds passed |
| Executable/library and policies | 94 integration assertions, 103 native-protocol assertions, 630 rule replays, 71 telemetry assertions passed |
| Documented callback inventory | All 98 subscriptions / 399 assertions passed on macOS 15.7.7 ARM64, Ubuntu 24.04 ARM64, and Windows build 26200 ARM64 running the x86_64 artifact |
| Real Claude Code 2.1.312 | 17 checks passed on macOS and Linux ARM64: exact allowed write, denied write absent, native tool IDs, post/session events, content omitted |
| Real Codex 0.159.2 | 13 checks passed on macOS with `workspace-write`; the current Ubuntu guest is blocked by its AppArmor user-namespace prerequisite |
| Actual OTel producers | Codex: 250 log records with hook-session correlation; Claude: 78 log/metric records with one accepted Write, one rejected Write, and one successful tool result |
| Independent review | No unresolved actionable finding; stale-PASS preflight bug fixed in both live runners and independently rechecked |
| Astro site | Four routes built, zero type diagnostics; all routes at 320/390/768/1440px checked; mobile navigation passed |

The callback inventory invokes generated commands with synthetic payloads. It
proves configuration, shell/argv, phase, policy, privacy, and native response
handling, not emission of every event by every vendor. The Claude mutation
removes `PreToolUse`: its expected failure confirmed that the blocked file was
created and the oracle rejected the run. Gemini and Copilot stopped-policy
mutations also failed at their intended denial/side-effect assertions.

The Windows guest exercises the x86_64 binary under ARM64 emulation; it is not a
native Windows ARM64 build. Its initial cleanup failures were isolated to transient Windows file deletion.
The repaired harness passed package extraction/cleanup, Gemini native runtime,
and the stopped-policy mutation on that guest; retries are Windows-only, capped
at one second, and still propagate permanent errors. Python 3.9 detached-finalizer
semantics have a dedicated regression. Published packages remain unsigned.

PE import inspection confirms that both Windows binaries require
`VCRUNTIME140.dll`. The tested Windows host already had the runtime; a
runtime-free Windows installation was not qualified. Install the
[documented Visual C++ runtime prerequisite](../README.md#download-and-try-it).
A native loader error occurs before Lens can emit a denial.

The user approved migration with explicit experimental limits. At that migration
checkpoint, Cursor/Cowork full native-client tests, Gemini whole-CLI trust/provider delivery, broader
Copilot event/platform behavior, enterprise audit permissions, remote Collector
routing, and SIEM delivery remain unverified. The current Linux Codex image
failure is infrastructure, not a hook pass: Ubuntu blocked user-namespace setup
before the positive control. No sandbox or AppArmor setting was weakened.
See [OpenAI's sandbox prerequisites](https://learn.chatgpt.com/docs/sandboxing#prerequisites)
before attempting that lane. The migrated repository is now public; native
GitHub Actions and Pages deployment passed on revision `0a49d88`.

## Installed-client follow-up — October 29, 2026

This follow-up includes Cursor and early Cowork checks with v0.3.0 artifacts
from `ff2fc329`, plus Copilot and Cowork checks with v0.3.1 CI-candidate artifacts
from `ede99fa`. Each report retains its actual source and binary hashes.
The [safe installed-client inventory](evidence/installed-clients-2026-10-29.json)
keeps prototype, packaged-helper, and passing v0.3.1 candidate records separate.

| Client / actual execution host | Observed behavior | Remaining evidence |
| --- | --- | --- |
| Cursor Desktop 3.27.22 ARM64; Windows 11 ARM64 build 26200.9168; x64 Lens under emulation | Generated PowerShell project hooks loaded; allowed Write; `.env` absent after `protect-env-files` blocked Read precheck; stopped-policy control write succeeded | Restored-policy Read reblock and absent test file confirmed; artifact hashes retained |
| Claude Desktop 4.29.0 Cowork; cloud Linux x86_64 `/home/claude` | Automatic exec/shell callbacks; bundled Linux Lens allowed Write, denied `.env` Write, allowed stopped-policy control, denied again after restore | v0.3.0 helper and separate v0.3.1 CI-candidate package passed; tagged builds remain distinct |
| Copilot CLI 1.0.105 ARM64; Windows | v0.3.0 failure reproduced; v0.3.1 actual `apply_patch` allow/deny, stopped-control, restored-deny passed | Exact CI-source `ede99fa` artifacts; six observed event types; Linux offline evidence remains separate |

Cursor emitted six observed event types: `workspaceOpen`, `preToolUse`,
`postToolUse`, `postToolUseFailure`, `afterAgentResponse`, and `stop`. Native
session IDs occur on tool callbacks; native tool-call IDs were not established.
The allowed file held `CURSOR_ALLOW_1029\r\n`; the stopped-policy control held
`DEMO_ONLY=CONTROL_1029\r\n`. These content nonces were absent from the inspected
metadata logs. Restoring policy blocked a second Read precheck at
`2026-10-29T17:50:55.522Z`; its test file remained absent and policy ended enabled.
The final 15-row ledger SHA256 is
`87cfdf7e2cb6cb3c1b5bd46bdb997406e2d9ca470df59c47492283b76ac2c3ff`.
The `.env` blocks occurred on Read prechecks, so they are not proof
that a denied Write was directly submitted in that case.

Cowork's runtime is established by automatic callbacks from a new Desktop task,
not by assuming that the macOS frontend executes hooks locally. A tested plugin
bundled the Linux x64 binary/library under `scripts/runtime`, then used a wrapper
to generate the five-event configuration on that host. The exported ledger has 18 rows: `SessionStart` 1,
`PreToolUse` 10, `PostToolUse` 6, and `PostToolUseFailure` 1. Two Write blocks
matched `protect-env-files`, with native session and tool-use IDs. The operator
independently confirmed both denied files absent and the stopped-policy control
present. That prototype did not observe `SessionEnd` or qualify a rebuilt
helper; the separate packaged-helper run below provides those additional checks.
Timeout/failure semantics remain outside both runs.
The prototype ledger SHA256 is
`9c7df9fdab045be9430b569ff066f29edcb4303c232954a31566494a3b0420d1`.
A separate run qualified the reusable packaged helper, ZIP SHA256
`f7775c49872a6deae87aefd57e84bb4c44cf8fa1f42c2be64525f3f93b4c9878`,
with generated launcher SHA256
`ff220848b6377e8ddcbf63386d4f5f652e19ba1698b2428a1b0ff3ea73aa7b38`.
It used the unchanged v0.3.0 Linux executable/library. Three temporary test
plugins were disabled before the fresh task, leaving the packaged plugin active.
Allowed Write, denied Write, stopped-policy control, and restored-policy denial
passed; native listing confirmed both denied files absent and control present.
Final state was enabled with content capture off.

The complete packaged-helper ledger contains 32 rows: `SessionStart` 2,
`PreToolUse` 16, `PostToolUse` 12, `SessionEnd` 1, and `PostToolUseFailure` 1
from a benign missing Read. All five registered events occurred in this exact
runtime; 30 rows allowed and two Write calls blocked. The 11,484-byte export
SHA256 is `d137975fbff6ddf4d0f2d4b9fbe6257ea708deb6bfda42f235314b494cb4ab10`.
The earlier 8,491-byte export is retained as an intermediate phase, not the final
inventory. This qualifies the packaged helper, not all client versions or the
new v0.3.1 binary. A separate candidate run below qualifies that binary; tagged
release builds retain their own provenance.

The separate v0.3.1 Cowork run used CI source `ede99fa` (tree-equivalent to
`b8c041`), package SHA256
`d3850bd03e2d3732665429d00d0e994e6cd963d386d37397d64e1b44e3da1879`.
Runtime inspection matched the packaged Linux executable, engine, and launcher
hashes retained in the safe aggregate. Actual Write allow, deny, stopped-policy
control, and restored-policy denial passed. Bash readback confirmed exact allowed
text; the control's requested contents were witnessed in the successful native
Write. Its later Bash readback was blocked by the expected `.env` policy and
was not bypassed. Independent Glob found only the control, with both denied
paths absent. Final policy was enabled with content capture off.

Its exact 18-row snapshot contains `SessionStart` 1, `PreToolUse` 10,
`PostToolUse` 6, and `PostToolUseFailure` 1: 16 allow and two Write blocks with
native session/tool-use IDs. Export SHA256 is
`5e04b827eb0e142c9c20896a5b0b3ad8d7e8abb7c919352a57fdd371cbf4fc06`.
`SessionEnd` is not in this snapshot; the earlier v0.3.0 all-five-event result is
separate. Neither candidate result is relabeled as a tagged-release artifact.

## Copilot raw-patch regression — v0.3.1 candidate

An authenticated Windows Copilot CLI 1.0.105 attempt using v0.3.0 could not
complete its allowed positive control: native `apply_patch` supplied a raw patch
string that the adapter rejected. This was a product compatibility defect, not
a successful deny test. The first client failure is preserved locally in
`copilot-allow-attempt4.log` and `copilot-native-shape.log`.

The candidate fix accepts only the exact bounded raw `apply_patch` dialect and
checks every Add/Update/Delete/Move target while preserving original input and
metadata privacy. Local macOS checks passed 99 Rust tests, 112 executable/library
assertions (nine new raw-patch cases), fmt, and clippy. The before-fix falsifier
failed as expected; `.context/native/copilot-raw-patch-regression.json` binds the
candidate source and harness hashes. These are local candidate results, not
release artifact or Windows installed-client proof. A separate Windows run below
provides the corrected installed-client evidence.

The authenticated Windows follow-up passed Copilot CLI 1.0.105 ARM64 on
Windows 11 ARM64 build 26200.9168 using the v0.3.1 x64 Lens package under
emulation. The artifact was built from CI source `ede99fa749e36d390122e5ebbdca66131af55a80`,
whose tree matches candidate `b8c041afd419331a6bf9b2a3959d99b824b57d5b`;
this is not relabeled as a build from the candidate commit. ZIP SHA256 is
`333fd10b7eeb0e573dfc119c4cc82f06a42c5096858f2b9335b0f13773c12890`.
The safe aggregate retains executable/library hashes and custody.

Actual `apply_patch` created the exact allowed text, denied a separate harmless
path, succeeded with policy stopped, and denied again after policy restoration.
Both denied paths were absent; final state was enabled with content capture off.
The 16-row metadata-only ledger has six event types: `sessionStart`,
`userPromptSubmitted`, `preToolUse`, `postToolUse`, `agentStop`, and `sessionEnd`;
14 rows allowed and two blocked under `protect-env-files`. Its SHA256 is
`4374aba661743c6ff4a8951a3dcca0813f7715020c0d7d28098ee1152850014d`.
Native session attribution was observed; tool-call IDs, all twelve events,
timeout handling, and other OS/client versions are not claimed.

## v0.1 behavior and evidence contract

This standalone proof of concept uses fresh Rust code, inspired by the cooperative
hook architecture discussed in magicsword-io/magicsword-deployer#255. It has no
Deployer dependency. The destination repository began with no commits or files.
Conventions: Rust 2021, synchronous standard IO, pure adapters/policy engine,
versioned C ABI, no async runtime. MIT source; no copied endpoint source.

Expected validation inventory (declared before execution):

| ID | Required behavior | Evidence |
| --- | --- | --- |
| AL-001 | Executable really loads companion library; matching ABI and paired allocator; missing library errors | Rust ABI test + Python subprocess/ctypes test |
| AL-002 | Start/stop/status; stopped hooks neutral; concurrent appends yield complete JSONL | Python subprocess test with 24 concurrent events |
| AL-003 | Claude/Codex allow and native PreToolUse deny; generated commands execute under host shell | Adapter unit tests + Python simulated vendor host positive/negative controls |
| AL-004 | Hermes integration reflects upstream capabilities; no invented denial | Adapter fixtures and upstream-source review; bridge tests where supplied |
| AL-005 | Strict YAML/regex validation; all selector semantics; block/audit; post events observational | Rust policy tests + Python event replay |
| AL-006 | Default content omission; explicit capture redacts known sensitive keys/patterns | Rust redaction tests + Python sentinel checks |
| AL-007 | Bad/oversized input, invalid policy, missing library or output errors observable; known pre-action errors deny | Rust parser/limits tests + Python subprocess checks |
| AL-008 | Native executable/library builds and protocol replay on Linux, Windows MSVC, macOS; ZIP + SHA256 | GitHub Actions matrix with retained downloadable artifacts |

The Python harness models a vendor honoring native JSON decisions and gates a
benign side effect on that decision. This proves the protocol seam, **not** a
live vendor invocation. Real client registration, trust approval, and live model
sessions must be verified separately on the operator's installed agent versions.
No client trust bypass, managed-hook installation or machine-wide settings changes
are part of these tests. Hermes capabilities are detailed in [agents.md](agents.md).

Repeat checks:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace --release
python3 scripts/e2e.py
python3 scripts/rules_smoke.py --report rule-results.json
python3 scripts/rules_oracle_test.py
python3 scripts/package.py
python3 scripts/package_smoke.py
```

An executable proof of concept is not an OS access-control product. No guarantee
covers unknown hooks, indirect shell reads, malicious agents, sandbox escapes,
symlink aliases, scripts that open secrets later, process injection, or tampering
by the same user. JSONL files are local evidence without cryptographic authenticity
or rotation; operators own permissions, retention, and SIEM transport.

## Recorded results: October 28, 2026

Core implementation `923d007361ba2ca21f4cccbdda7033a5fbdc4ae1` passed
[native CI on all three platforms](https://github.com/MHaggis/expert-octo-adventure/actions/runs/40785452149).
Observed Rust/Cargo: **1.99.1**. The declared Rust 1.85 minimum was not tested.
Native targets were Windows x86_64 MSVC, Linux x86_64 GNU, and macOS aarch64.
Other architectures and operating systems have not been validated.

Each native job passed formatting, clippy with warnings denied, **35 unit tests**,
debug/release builds, **44 executable/library assertions**, ZIP packaging,
checksum verification, and execution of the extracted package with its own
companion library. Those assertions include concurrent JSONL appends and
supported native denial shapes. They are synthetic protocol checks.

The optional catalog has **30 rules**
(default five plus 25 optional) with **270 replay scenarios**: matching,
near-miss, and post-tool cases for all three adapters. Local Linux replay and
extracted-package validation passed. The harness also validates a combined
policy and checks every shipped rule has fixture coverage using IDs from the
actual YAML parser. Near misses must produce both an `allow` telemetry decision
and an exact neutral native response. No fixture command was executed.

Repair revision `3d56fed43d7505fde7ca41b946bac9436a84e586` passed local formatting,
clippy, **36 Rust unit tests**, **44 executable/library assertions**, **270 rule
replays**, and extracted-package/checksum verification. Three permanent oracle
tests cover four deliberate mutations: an uncovered quoted YAML rule ID, a block
weakened to audit, corrupted near-miss telemetry, and a corrupted near-miss native
response. Each mutation is rejected for the intended assertion failure.

That exact repair revision then passed [native CI on all three
platforms](https://github.com/MHaggis/expert-octo-adventure/actions/runs/40787332262):
Windows x86_64 MSVC, Linux x86_64 GNU, and macOS aarch64. Each job passed the
36 unit tests, 44 executable/library assertions, 270 rule replays, all oracle
tests, and extracted-package execution. The three downloaded artifacts were
independently checked against their SHA256 manifests; each contained the native
executable/library pair, all six policies, fixtures, and documentation. Each
platform's report had all 270 expected unique cases and no executed fixture
commands. Credential-shaped content checks found no live keys in the public
text assets.

The [v0.1.0 release](https://github.com/MHaggis/expert-octo-adventure/releases/tag/v0.1.0)
contains those unchanged CI ZIPs, a combined `SHA256SUMS`, and three synthetic
rule-result reports. ZIP SHA256 values:

```text
2a37fc09a162f5aa1761191683fc2a7d9659211fb6bd4ea60b4867668f66eeaf  agent-lens-0.1.0-windows-x86_64.zip
2d48df452ea086b725c47a209f6109d426049b4b264ed723acb5bcdd444ee9a9  agent-lens-0.1.0-linux-x86_64.zip
b36fd56c13e2111b14ceb3d49d906b5efc43a50edb0d5579c4c078e85efcacd6  agent-lens-0.1.0-macos-aarch64.zip
```

### Live client check

A separate live **Claude Code 2.1.308** session on Linux x86_64 used temporary
settings, a temporary working directory, metadata-only capture, and a small
custom policy denying direct `Write` calls to `.env`. The actual client created
`allowed.txt`, then its `.env` Write was denied and that file remained absent.
The process exited successfully. Nine native hook events were observed across
`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolBatch`,
`Stop`, and `SessionEnd`, including one policy block. Test content was synthetic;
settings and working files were removed afterward. This is a representative
live denial check, not live coverage for all catalog rules or client versions.

Follow-up live checks on **2026-10-28** tested the unchanged **v0.1.0 Linux ZIP**
listed above, including its own executable and adjacent library, with the shipped
default policy. Both **Codex CLI 0.164.0** (`gpt-5.4`) and **Hermes Agent
v0.22.5+2471.g0c74cc6**, pinned to
`0c74cc682dc81bf78b78a1737b3ee77a820ccb79` (`gpt-5.4-mini` through `openai-api`),
passed the actual client → EXE → shared library → JSONL → native denial path.

| Client/run | Actual tool | Allowed sentinel | `.env` absent + native block | Native events |
| --- | --- | --- | --- | --- |
| Codex | `Bash` / unified exec | exact contents | `protect-shell-env` | 7 |
| Hermes, native consent flag | `write_file` | exact contents | `protect-env-files` | 17 |
| Hermes, persisted consent without flag | `write_file` | exact contents | `protect-env-files` | 17 |

Each run passed 13 assertions, including exactly two pre-tool calls, the expected
policy denial, positive filesystem control, post-tool and session start/end
events, one native session, correlated native tool IDs, expected agent attribution, and metadata-only
output. Hermes's second session reused its temporary profile without
`--accept-hooks`, proving native consent persisted for the configured commands.
Codex used the documented invocation-only `--dangerously-bypass-hook-trust` option
for reviewed generated commands; interactive `/hooks` approval was not tested.
Its tool sandbox remained `workspace-write` with approval policy `never`.

Earlier Codex attempts are retained as failed evidence: the original attempt
did not establish a positive control or hook delivery; later attempts delivered
events and one denial but could not execute the allowed write. This VM's inherited
ambient capabilities made `bwrap --help` fail, which Codex reported as bubblewrap
unavailable. Installing the system package and dropping inherited capabilities
with `setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all` resolved sandbox
startup. The successful packaged run used the Conductor-bundled Codex CLI after
this privilege reduction. No sandbox was disabled and no global agent settings
were changed. The separate official npm 0.164.0 package also passed an exploratory
live check against the locally built Agent Lens binary.

The [aggregate assertion evidence](evidence/live-linux-2026-10-28.json) contains
client versions and executable/library/policy hashes; raw sessions and credentials
are excluded. [Live testing](live-testing.md) documents the repeatable opt-in
runner. Eight offline tests exercise the acceptance oracle, including 24 corrupted
event cases across both agents, failed side-effect/exit controls, cancellation,
cleanup failures, malformed logs, and stale-PASS report replacement. These run
without API credentials in CI.

Hermes's frozen source install had an upstream-documented Pillow version override
that conflicts with browser-harness's declared requirement. Its file-tool checks
passed; browser functionality was not exercised. Windows/macOS CI replay is not a
live agent session, and the remaining catalog rules, tools, interactive onboarding,
and client versions still need their own live verification. These narrow tests
do not establish universal agent visibility or tamper-resistant enforcement.

### Independent review and distribution

An independent source reviewer reproduced three core defects involving tool-name
filtering before policy matching, quoted-JSON credential redaction, and stdin
read-error denial. All three were fixed and independently rechecked, including
35 unit tests, 44 executable/library assertions, and focused reproductions.
The review found no remaining actionable core defect in its bounded scope.

The same independent reviewer then found two defects in the optional catalog's
test oracle: quoted YAML IDs could escape the coverage inventory, and near-miss
controls did not require an allowed outcome. Both were repaired at `3d56fed`.
An isolated rebuild independently passed 36 Rust tests, 270 rule scenarios, the
three oracle tests/four deliberate mutations, and direct quoted-ID probes.
Final bounded review disposition: **READY**, with no unresolved finding in scope.

That revision was MIT-licensed. Installer signing, SIEM deployment, and vendor
settings installation are not implied by these results. Publishing a GitHub
Release does not itself enable GitHub Pages or change repository visibility.
CI ZIPs contain the native executable/library, policy
examples, synthetic rule fixtures and public documentation. Downloaded artifacts
include a SHA256 manifest. No live credentials or raw client transcripts are
included in source or packages.

### Website verification

The three-page static Astro site is separate from the runtime release. Local
checks used Node 24.22.1, Astro 7.4.4, and system Google Chrome through Playwright.
Type checking completed with zero errors/warnings/hints; production output
contains three pages under the `/expert-octo-adventure/` project base.

Browser checks passed 85 assertions covering all three routes, internal links
and fragments, clipboard controls, single page headings, mobile menu behavior,
and document overflow at desktop and phone widths. A mobile decorative-element
overflow was reproduced and fixed without hiding document overflow. Separate
checks covered all routes at 320, 390, 768, and 1440 pixels. All seven copyable
YAML policies in the built reference page validated through the real release
executable/library.

The Pages workflow builds relevant pushes and pull requests. Deployment is
skipped while the repository is private. The owner deferred public hosting;
making the repository public, selecting GitHub Actions as the Pages source,
and running the Website workflow remain publication steps. Local/browser
success is not a claim that a public Pages deployment has occurred.

## Gemini CLI adapter (v0.2.0, 2026-10-29)

The fourth adapter uses Gemini CLI's public native command-hook contract. Its
nine-event registry enforces only `BeforeTool`; other events remain observational.
`BeforeModel` and streaming `AfterModel` are excluded. Native settings use
millisecond timeouts and the platform shell. No private Ent implementation was
copied into this MIT project.

Local Linux validation passed formatting, clippy, **39 Rust unit tests**,
**68 executable/library assertions**, **360 catalog replays** (30 rules × four
adapters × matching/near-miss/post), **five rule-oracle tests**, and the existing
**eight offline live-runner regressions**. The extracted v0.2.0 ZIP passed
checksum, all-rule validation, synthetic demo, and a Gemini denial with metadata
checks using its own executable and library. Native GitHub CI runs these checks
on Windows MSVC, Linux, and macOS; inspect the corresponding workflow before
attributing a local result to another platform.

`scripts/gemini_native_smoke.mjs` additionally exercises the pinned public
`@google/gemini-cli-core` **0.66.0**, source
`970413207732f5d4d8c50540c7fc359c44fdaaf2`, without Google authentication or a
model request. It uses the unmodified vendor hook system, real subprocess
execution, real tool gate, `WriteFileTool`, and filesystem service in a disposable
workspace. A minimal configuration facade models the native configuration API;
it does not load a real user's settings or exercise CLI workspace trust.

The acceptance oracle checks an absent denied harmless JSON file, exact contents
of an allowed positive control, native denial JSON and audit metadata, all nine
explicitly fired events, corrupt-policy/missing-library denial, and observational
post-tool failure. A deliberate stopped-policy mutation must fail at the expected
denial assertion. This proves the tested vendor runtime/tool boundary, not
provider-driven event emission, CLI settings loading, consent, or an authenticated
Gemini CLI session. Those remain untested without a Google account.

The [safe local aggregate](evidence/gemini-native-linux-2026-10-29.json)
records **27 passing assertions** for the release executable/library. Native CI
also publishes its own per-platform aggregate with the exact binary hashes.

Configuration generation rejects literal executable/state paths containing
Gemini's five reserved hook macros, which upstream expands before shell parsing
even inside quotes. Native tests exercise all five in both state and relocated
executable paths. Gemini catalog fixtures use the vendor's single-underscore
MCP separator; the optional examples also preserve the other adapters' names.


## Native hooks and telemetry source preview (2026-10-29)

Branch `feat/telemetry-sources`, based on `11e9fcf`, adds eleven observation-only
telemetry sources and native Cursor, Copilot CLI and experimental Cowork
adapters. This is source-build work; published v0.2.0 ZIPs and the historical
results above are unchanged. No PR, release, merge, live enterprise collection
or Pages publication is included.

Local Linux checks passed on the final source/build:

| Check | Observed result |
| --- | --- |
| Rust fmt, clippy with warnings denied | Passed |
| Rust unit tests | 95 (45 host, 50 engine) passed |
| Executable/library integration | 94 assertions passed, including Cowork generated argv and malformed-pre denial/no append |
| Cursor/Copilot protocol/config suite | 103/103 passed, including all 23 registered fixtures and generated handlers |
| Rule catalog | 630/630 replays: 30 rules × seven adapters × matching/near-miss/post |
| Rule oracle / offline live oracle | Five / eight tests passed |
| Telemetry CLI | 71/71 passed: eleven source fixtures, JSON/protobuf, HTTP recovery, privacy and checkpoint resume |
| Gemini native runtime | 27/27 passed using the existing pinned 0.66.0 HookSystem/tool harness |
| Copilot native CLI | 31/31 passed on CLI 1.0.105 / SDK 1.0.28, with real configuration loading and create tool |
| Gemini/Copilot stopped-policy mutations | Both failed at the intended denial/side-effect assertion |
| Package | ZIP checksums, all rule packs, extracted Gemini/Cursor/Copilot/Cowork hooks, config, telemetry import and demo passed |
| Astro | Check: zero diagnostics; build: four routes; browser: 38 assertions |

The safe [telemetry aggregate](evidence/telemetry-linux-2026-10-29.json),
[adapter/config aggregate](evidence/native-hooks-linux-2026-10-29.json), and
[Copilot native aggregate](evidence/copilot-native-linux-2026-10-29.json)
record the tested release artifact hashes. The Linux release EXE SHA256 is
`fd14197e7b5791ca3d0ea300fa4a1425da84ba93e4317573a7292381e934eb8e`;
engine SHA256 is
`e3a5825011cb04e0e28012e62ce2f77dacce1e7026256a0de79497722282ae27`.
Separate review found and verified repairs for opened-file identity collisions,
directory durability before HTTP acknowledgments, protobuf allocation bounds,
encoded Copilot argument privacy and malformed Cowork inputs. Review disposition
was ready for an experimental branch handoff, with the native/tenant gaps below.

The first branch CI run exposed an incomplete HTTP rejection response on macOS
and a Windows mock-server deadlock. The receiver now half-closes its write side
before discarding at most 64 KiB within a single 250 ms cleanup budget. Rejection
status, ledger integrity and healthy-request recovery assertions remain strict.
Windows then exposed a checkpoint replacement failure: identity-guard handles
remained open across atomic persistence. Those handles now close after the
guarded append and before replacement; the sidecar stays locked throughout.
The polling fixture now uses an incomplete regular file to exercise the same
post-fetch failure on every OS, and mock accepts have a five-second bound.
Independent Linux hold-open, trickle, over-cap and recovery probes passed; these
do not substitute for the repaired branch's native CI results.

The Copilot harness runs the unmodified vendor executable in a Linux namespace
containing only loopback. A local server returns fixed synthetic model messages,
with no account or actual provider. A real `.github/hooks` configuration starts
the generated Lens command, which loads the real engine. The CLI's `create` tool
writes an allowed JSON control exactly; a path-rule denial leaves the blocked
JSON absent and reports policy denial. A post-tool block remains observational;
a missing engine prevents the next file write. Stopping policy must break the
absent-file assertion. The test observes seven lifecycle/tool event types; it
does not establish emission of all twelve registered events or timeout behavior.

Cursor and Cowork evidence is executable/library/configuration replay, not a
native tool side-effect test. Cowork plugin loading, Desktop/VM paths and app
version compatibility remain unvalidated. No authenticated enterprise audit API,
real OTLP exporter, hosted inference webhook, SIEM delivery, or real provider
session was used for this branch. CI adds native artifact checks on Windows,
macOS and Linux; consult the branch's actual workflow results before claiming a
platform pass. Setup and remaining acceptance steps are in the
[live test guide](live-testing.md) and [source guide](telemetry-sources.md).
