# AI telemetry sources — experimental source preview

This guide describes the current source build, researched on
**2026-10-29**. These commands are **not included in the v0.2.0 downloads**.
Provider documentation establishes an upstream contract, not proof of delivery
from an enterprise tenant. No live enterprise account, admin API, or managed
client export was used to validate this integration.

## Choose the evidence source

AI Lens brings several kinds of evidence into local observation JSONL. They
answer different questions:

- **Runtime OTel** describes the instrumented client's or provider's requests,
  tools, timing, costs, and sessions. Export is opt-in and can be delayed or lost.
- **Provider audit feeds** describe activity within an account or organization.
  Administrative changes are not a transcript of every agent tool call.
- **Native hooks** execute at specific client lifecycle points. Existing Lens
  hook adapters can request denial only at supported synchronous pre-tool hooks.
- **Local session history** is client-owned storage, often with prompts and file
  contents. A path on disk is not a documented, version-stable export schema or
  an organization-wide audit API.

Telemetry records use `schema: agent-lens.telemetry.v1` and
`enforcement: observe_only`. They do not run block rules, ask the client to deny
an action, or retroactively prevent anything. A provider's `approved` or
`decision` attribute describes that provider's observation, not Lens enforcement.

## Source and ingest matrix

Use `agent-lens telemetry sources` for the source inventory in the binary you
built. JSON imports mean the documented provider envelope or OTLP export message;
an arbitrary JSON file is not a supported provider contract. JSONL is one such
record or envelope per line. CSV exports need deliberate conversion first.

| Source ID | Evidence and principal access requirements | AI Lens input |
| --- | --- | --- |
| `claude-code-otel` | Claude Code runtime; authorized client use and shell/user or managed telemetry configuration | OTLP import or local HTTP listener |
| `claude-cowork-otel` | Cowork runtime; Team/Enterprise admin configures its own destination | OTLP import or HTTP listener behind a reachable collector |
| `codex-otel` | Codex runtime; authorized client use and user/managed `[otel]` configuration | OTLP import or local HTTP listener |
| `cursor-runtime` | Cursor server-side runtime export; Enterprise team admin | OTLP import or HTTP listener behind a public HTTPS/auth collector |
| `copilot-otel` | Supported Copilot client runtime; local config or enterprise-managed telemetry policy | OTLP import or local HTTP listener |
| `cursor-audit` | Cursor account/team changes; Enterprise and team Admin API access | Provider JSON/JSONL import; bounded API poll |
| `copilot-audit` | GitHub Copilot audit category; Business/Enterprise entitlement and audit-read access | Provider JSON/JSONL import; bounded API poll |
| `copilot-session` | GitHub streamed request/response records; eligible enterprise session-streaming preview | Provider JSON/JSONL import; no session-content API poll |
| `anthropic-compliance` | Anthropic Activity Feed; enabled Compliance API and `read:compliance_activities` | Provider JSON/JSONL import; bounded API poll |
| `openai-audit` | OpenAI API Platform user/configuration activity; organization Admin API key | Provider JSON/JSONL import; bounded API poll |
| `google-gemini` | Gemini usage in Workspace applications; supported Workspace edition and authorized Reports API access | Provider JSON/JSONL import; bounded API poll |

OTLP transport can carry logs, metrics, and traces in HTTP JSON or protobuf. This
does **not** mean every provider emits all three signals. Cowork's first-party
reference describes logs; Cursor documents logs and metrics, HTTP protobuf only;
Copilot CLI documents traces and metrics. Signal production, application coverage,
and content gates remain provider-specific.

## Build and ingest

From a checkout of this repository, build both workspace crates so the
CLI has its adjacent engine library. No client settings are changed by building
or printing configuration.

```sh
cargo build --locked --workspace
./target/debug/agent-lens telemetry sources
./target/debug/agent-lens telemetry config --source claude-code-otel
```

Start a foreground listener, then configure and launch the producer on the
appropriate host. Use separate listener ports and output files for different
sources: `--source` labels incoming data; it does not authenticate the producer.

```sh
./target/debug/agent-lens telemetry listen \
  --source claude-code-otel --bind 127.0.0.1:4318 \
  --output ./claude-code-telemetry.jsonl
```

The receiver binds a **literal loopback IP** and accepts HTTP/1.1
`POST /v1/logs`, `/v1/metrics`, and `/v1/traces` with `application/json` or
`application/x-protobuf`. Every request requires `Content-Length`; the limits
are **8 MiB body**, **16 KiB headers**, and a **5-second total read deadline**. Response close cleanup discards at most
64 KiB within one 250 ms budget; it never decodes or stores rejected bytes.
An over-budget sender can still lose its response when the connection closes.
Chunked transfer, gzip/compression, `Expect`, gRPC, TLS, and collector
authentication are unsupported. Configure a production collector to forward
uncompressed HTTP/1.1 requests with a content length.

Invalid framing or payloads return HTTP 400; output failures return HTTP 503.
HTTP 200 is sent only after the normalized batch is appended under a file lock
and synced. Batches are capped at 10,000 events and 32 MiB of normalized output.
An interrupted write or lost acknowledgment can still require recovery or
replay; this is not an exactly-once delivery guarantee.

Protobuf preflight rejects oversized collections before generated decoding:
at most 10,000 resources, scopes, records and metric points per request (each
counted separately), 10,000 entries per repeated field in a wire message,
100,000 repeated primitive values overall, and nesting depth 32. A conservative
64 MiB materialization accounting budget charges four times the wire bytes,
4 KiB per known message occurrence and 64 bytes per repeated primitive; it is
not an exact process-memory limit. Rich batches can be rejected below the
10,000-record cap. Unix output acknowledgments also sync the parent directory;
Windows uses file sync because portable directory fsync is unavailable in the
standard library. Validate persistence on your actual filesystem.

`--max-requests N` counts accepted connections, including invalid requests, and
bounds a local exercise; it is not an event-count or delivery guarantee. Stop the foreground
process to stop receiving. It is separate from the native-hook `start`/`stop`
lifecycle.

Import files that you obtained with authorization:

```sh
# An OTLP ExportLogsServiceRequest JSON object, not a vendor console-log line.
./target/debug/agent-lens telemetry import \
  --source codex-otel --signal logs --format json \
  --input ./otlp-logs.json --output ./codex-telemetry.jsonl

# A binary ExportTraceServiceRequest message, without a gRPC frame.
./target/debug/agent-lens telemetry import \
  --source copilot-otel --signal traces --format protobuf \
  --input ./otlp-traces.pb --output ./copilot-telemetry.jsonl

# A provider audit response page, including its data array.
./target/debug/agent-lens telemetry import \
  --source openai-audit --format json \
  --input ./audit-page.json --output ./openai-audit.jsonl
```

Imports default to `--format json`; OTLP imports require `--signal`, while
provider imports reject it. `--format jsonl` accepts one documented record or
envelope per nonempty line; protobuf applies only to OTLP. A whole input file is
capped at 8 MiB, 10,000 normalized events, and 32 MiB of normalized output.
Input and output must be different files. Import output is appended, so repeated
imports can duplicate observations.

The source-specific polling section below distinguishes upstream APIs from the
branch's implemented command. Polling is for bounded retrieval; it is not a
background service, OAuth login tool, or a provider subscription.

## Review configuration before applying it

Templates live in [`examples/telemetry/configs`](../examples/telemetry/configs).
`telemetry config` prints a JSON wrapper with `source` and `review_only: true`;
OTLP sources include the corresponding template as a string, while provider
sources point to import/poll guidance. The Collector YAML is a separate example.
These are examples for review, not installers. Preserve existing settings, use
normal admin permissions and trust workflows, and keep credentials outside the
repository and command-line arguments.

| File | How to use it |
| --- | --- |
| [`claude-code.env`](../examples/telemetry/configs/claude-code.env) | Review shell exports before applying to the shell launching Claude Code; logs and metrics, content off; beta traces shown separately |
| [`codex.toml`](../examples/telemetry/configs/codex.toml) | Manually merge the logs-only fragment into the intended user/managed config, preserving existing TOML tables |
| [`copilot-otel.env`](../examples/telemetry/configs/copilot-otel.env) | Review shell exports for Copilot CLI; enterprise-managed values can override them |
| [`claude-cowork.json`](../examples/telemetry/configs/claude-cowork.json) | Manual admin-UI worksheet; **not** a vendor JSON settings file; device content policy is deployed separately |
| [`cursor-export.json`](../examples/telemetry/configs/cursor-export.json) | Manual admin-UI worksheet; **not** an Admin API request or executable vendor configuration |
| [`otel-collector.yaml`](../examples/telemetry/configs/otel-collector.yaml) | Collector Contrib starting point for upstream TLS/auth or gRPC, forwarding uncompressed OTLP HTTP protobuf to same-host Lens |

The listener binds only to loopback. It has no gRPC server, TLS termination, or
collector authentication. Do not expose it as a public ingestion endpoint.
The Collector example has TLS and bearer-token authentication on its ingress,
with certificate/key/token **paths**, not credentials. It remains loopback-bound
until an operator deliberately provisions reachable ingress. Validate it against
your installed Collector version: current upstream calls the HTTP exporter
`otlp_http`; older versions use `otlphttp`. Its `compression: none` avoids requiring
gzip support from Lens. Confirm HTTP/1.1 forwarding with `Content-Length` against
your installed exporter; chunked forwarding is rejected. No Collector binary or
production ingress was tested here.

Cowork's exporter runs in its VM/cloud runtime. Cursor exports from its servers.
Their `127.0.0.1` is not the machine running Lens. For these sources use a reachable,
authenticated collector and run Lens alongside that collector, with a dedicated
pipeline per source. A shared destination without source routing can mislabel
records. Batch count limits do not bound individual event size; apply appropriate
size, retry, buffering, redaction, and retention controls in your collector.

## Verified provider contracts

All references in this section were retrieved **2026-10-29**. Where two official
pages differ in scope, the difference is stated rather than silently generalized.
Examples use protocol fields from these references, not guessed SDK methods.

### Claude Code OTel

[Official monitoring reference](https://code.claude.com/docs/en/monitoring-usage)
([retrieved Markdown](https://code.claude.com/docs/en/monitoring-usage.md)).

- Enable with `CLAUDE_CODE_ENABLE_TELEMETRY=1`; choose signal exporters and an
  explicit OTLP protocol. The reference documents `grpc`, `http/json`, and
  `http/protobuf`. Lens directly receives the two HTTP protocols only.
- Metrics include sessions, tokens, cost and tool activity; logs include prompt,
  tool-decision/result and API events. Logs default to 5-second export batches;
  metrics default to 60 seconds. These are batching defaults, not a delivery SLA.
- Traces are beta and require `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1` plus
  `OTEL_TRACES_EXPORTER=otlp`. Do not equate ingesting a synthetic span with
  validating a live Claude trace.
- Use shell, user, or managed settings. Current Claude Code ignores telemetry
  routing/content exporter variables in repository settings. Managed settings
  can pin endpoints and override developer values. This reference does not
  impose a separate enterprise license just for local OTel; client entitlement
  and organization policy still apply.
- Prompt/response/tool/raw-API content controls are separate. Keep
  `OTEL_LOG_USER_PROMPTS`, `OTEL_LOG_ASSISTANT_RESPONSES`, `OTEL_LOG_TOOL_DETAILS`,
  `OTEL_LOG_TOOL_CONTENT`, and `OTEL_LOG_RAW_API_BODIES` off. Identity and resource
  metadata can still be sensitive. Full raw API bodies can contain conversation
  history. OTel sent to your collector is distinct from Anthropic's operational
  telemetry and the Compliance API.

### Claude Cowork OTel — separate from Claude Code

[Monitoring reference](https://claude.com/docs/cowork/monitoring)
([retrieved Markdown](https://claude.com/docs/cowork/monitoring.md));
[availability and privacy help article](https://support.claude.com/en/articles/14477985-monitor-claude-cowork-activity-with-opentelemetry).

- Team and Enterprise admins configure Cowork's OTLP endpoint, protocol
  (`http/json` or `http/protobuf`), and optional authentication headers. UI
  placement is version-dependent: the reference says **Admin settings > Cowork**;
  Claude Code's reference describes a **Monitoring** form under Data and privacy.
  This is not the terminal or Code-tab configuration.
- The reference documents local desktop sessions, including Dispatch-started
  Cowork tasks, with Desktop **1.1.4173+**. The help article additionally documents
  cloud sessions on desktop/web/mobile, with Desktop **1.22209.3+** for cloud
  monitoring. Confirm your deployed client and rollout; do not assume local-only
  topology covers the cloud. The reference says to start a new session after
  settings change. No precise end-to-end delivery SLA is established here.
- Logs use resource `service.name=cowork`; event names include `user_prompt`,
  `assistant_response`, `tool_result`, `api_request`, `api_error`, and
  `tool_decision`. `prompt.id` correlates events within one prompt; `session.id`
  identifies the session. Do not relabel these as `claude_code.*`.
- Set the managed device policy `otlpContentCapture` to the empty list `[]` for
  metadata only, then restart Desktop. An empty string is not the same setting.
  Current defaults omit content, but some older first-party Desktop versions
  export content when the policy is absent. User email, connected-folder paths,
  and API error text may still appear with content disabled.
- The help article says web/mobile, cloud scheduled tasks, and unified chats
  moved to cloud carry metadata only and are not controlled by this device
  policy. Third-party deployments have separate identity/tracing configuration;
  do not infer first-party Cowork traces or metrics from that separate contract.
- OTel does not grant access to transcripts. Compliance session retrieval is a
  separate Enterprise API with separate permissions and content implications.

### Codex OTel

[Monitoring and privacy](https://learn.chatgpt.com/docs/agent-approvals-security#monitoring-and-telemetry),
[advanced configuration](https://learn.chatgpt.com/docs/config-file/config-advanced#observability-and-telemetry),
[configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference).
These pages were searched and fetched with the OpenAI Docs MCP.

- Local Codex log export is opt-in via `[otel]`; `exporter` defaults to none.
  The reference supports `otlp-http` (`protocol = "binary"` or `"json"`) and
  `otlp-grpc`, plus separate `trace_exporter` and `metrics_exporter` settings.
  HTTP log endpoints include `/v1/logs`; this differs from a generic OTLP base URL.
- Representative logs include `codex.conversation_starts`, `codex.api_request`,
  `codex.sse_event`, `codex.user_prompt`, `codex.tool_decision`, and
  `codex.tool_result`. Events batch asynchronously and flush at shutdown; there
  is no latency SLA in the fetched reference.
- `log_user_prompt = false` redacts prompts, but tool-result snippets and error
  details can still contain content. Lens drops raw bodies and unapproved fields.
- Anonymous analytics and local session history are separate controls. In Codex
  CLI, `analytics.enabled = false` also disables custom OTLP metrics exporters;
  the template leaves analytics policy alone and exports logs only.
- Authorized Codex client access and permission to configure its user/managed
  settings are required. Project configuration cannot override telemetry routing
  ([enterprise cookbook](https://learn.chatgpt.com/docs/enterprise/security-cookbook#configure-3)).
  A local export does not establish visibility into every cloud session, ChatGPT,
  or API Platform administrative action.

### Cursor audit and runtime

[Audit scope](https://cursor.com/docs/enterprise/compliance-and-monitoring.md),
[team Admin API](https://cursor.com/docs/account/teams/admin-api.md#get-audit-logs),
[runtime OTel export](https://cursor.com/docs/enterprise/opentelemetry-export.md),
[OTel wire reference](https://cursor.com/docs/enterprise/opentelemetry-export/wire.md).

- **Audit:** Enterprise plan, admin access, Team API key for
  `GET https://api.cursor.com/teams/audit-logs`. Authenticate with HTTP Basic,
  API key as username and empty password. Events are flat objects with `event_id`,
  `timestamp`, `event_type`, `application_type`, and `event_data`; page envelope
  is `events` plus `pagination.hasNextPage`. Advance numeric `page` (1-based).
  Default window is 7 days, maximum window 30 days, maximum page size 500;
  rate limit is 20 requests/minute/team. Do not confuse this with the separate
  POST daily-usage endpoint or the differently shaped streamed audit envelope.
- Audit covers sign-ins, membership, settings and administrative changes, not
  prompts, agent output, generated code, or all runtime actions. Its docs do not
  establish a fixed appearance delay. The UI can export CSV; Lens imports JSON.
  Emails are not stable identifiers and are excluded by the metadata projection.
- **Runtime:** Enterprise admins configure **Team Settings > OpenTelemetry
  Export**. Cursor sends server-side **OTLP HTTP protobuf**, logs and metrics,
  to a public HTTPS endpoint with authentication. It does not send gRPC or JSON.
  Enter a base URL without `/v1`; Cursor appends `/v1/logs` and `/v1/metrics`.
  Lens therefore needs a secure reachable collector in front of it.
- Export starts within about a minute of enabling. Logs may arrive more than
  once; use `cursor.event.id` for downstream deduplication. Metrics are deltas.
  Some tool I/O exports only when a turn ends, so occurrence and receipt times
  differ. Lens preserves observations; it does not aggregate metric deltas.
- Conversation content is a separate opt-in family covering Cloud Agents and
  Grok Bot; its documented coverage excludes IDE/CLI/desktop conversations.
  Review per-family switches and `auto_enable_new_families`. Hooks and local
  history remain distinct surfaces, not inputs implicitly accepted by
  `cursor-runtime`.

### GitHub Copilot audit, streamed sessions, and OTel

[Audit log guide](https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-for-enterprise/review-audit-logs),
[agentic event schema](https://docs.github.com/en/copilot/reference/enterprise-administrators/agentic-audit-log-events),
[session data](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/session-data),
[OTel overview](https://docs.github.com/en/copilot/concepts/enterprise/opentelemetry),
[CLI OTel settings](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference#opentelemetry-monitoring).

- **Audit:** Copilot Business/Enterprise, with enterprise owner or delegated
  **Read enterprise audit logs** permission; organization API access requires
  the corresponding organization audit permission. Audit retention is 180 days.
  `action:copilot` filters plan, seat, and policy events. `actor:Copilot` finds
  agent-performed GitHub actions, which can have other action categories such
  as `pull_request.create`. They are not interchangeable filters. The branch's
  `copilot-audit` category filter must not be read as complete agent activity.
- **Streamed sessions:** separate opt-in audit-log streaming, currently public
  preview for enterprises using Enterprise Managed Users or Enterprise Cloud
  with data residency. The documented JSON record has `type` (`request` or
  `response`), `event_id`, `@timestamp` (Unix milliseconds), `user_id`,
  `enterprise_id`, `endpoint`, `github_request_id`, and a JSON-encoded `body`;
  optional `truncated` marks the 1 MB document limit. Lens discards the body.
  These are exports from the configured destination, not local CLI transcripts
  or records promised by the normal audit REST endpoint. See
  [streaming setup](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#enabling-audit-log-streaming-of-copilot-agent-session-events).
- **OTel:** supported clients export traces, metrics and events. Copilot CLI
  documents `COPILOT_OTEL_ENABLED=true`, `COPILOT_OTEL_EXPORTER_TYPE=otlp-http`,
  an `OTEL_EXPORTER_OTLP_ENDPOINT`, and `http/json` or `http/protobuf` protocol.
  Its documented default is HTTP JSON. The provided template chooses protobuf.
  Keep `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=false`. Enterprise
  managed values take precedence over local settings/environment. Fine-grained
  identity/content controls depend on client/harness; VS Code's local harness
  differs from Agent Host. No delivery SLA is established by these references.
- **Local history:** CLI/app history lives under `~/.copilot/session-state/` with
  a separate SQLite session index; IDE storage is IDE-specific. Synced local
  sessions are private by default, and enabling sync does not give admins access.
  Neither that location nor an SDK event type proves a stable on-disk import
  contract. Lens does not crawl session folders or open the SQLite database.

### Anthropic Compliance Activity Feed

[Activity Feed](https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed),
[access setup](https://platform.claude.com/docs/en/manage-claude/compliance-api-access),
[complete API schema](https://platform.claude.com/docs/en/api/compliance/activities/list).

- Claude Enterprise and eligible standalone Claude Console organizations have
  self-service access. Primary/organization owners create appropriately scoped
  Compliance Access Keys in claude.ai. Console admins can create Admin API keys
  for Activity Feed access **after** enabling Compliance API; keys created before
  enablement do not acquire `read:compliance_activities` automatically. A normal
  model API key is not evidence of compliance permission.
- `GET https://api.anthropic.com/v1/compliance/activities` uses `x-api-key` and
  `anthropic-version: 2023-06-01`. Required scope: `read:compliance_activities`.
  Reading chats/files/transcripts requires separate scopes and is outside this
  source. No content-retrieval or delete endpoint is needed.
- Response: `data[]`, `has_more`, `first_id`, `last_id`. Each activity has `id`,
  `created_at` (RFC 3339), `type`, nullable organization identifiers, an `actor`
  union, and event-specific fields. Actor types include `user_actor` (`user_id`),
  `api_actor` (`api_key_id`), and `admin_api_key_actor` (`admin_api_key_id`). Key
  identifiers are not key material. Unknown event/actor types can be added.
- Results are **newest first**. `after_id=last_id` goes to the next **older** page;
  `before_id=first_id` goes toward newer pages. Default limit 100; maximum 5,000.
  Time filters are dotted `created_at.gte`, `.gt`, `.lte`, `.lt`, not OpenAI's
  bracket syntax. Repeat `activity_types[]`, `actor_ids[]`, `organization_ids[]`
  for multiple filters. Treat cursors as opaque.
- Activities become queryable within 1 minute and are retained 6 years. Recording
  starts at enablement and is not backfilled; disabling stops new recording.
  Access Transparency, if enrolled, is a documented exception. User-actor
  attribution can also describe automation acting on the user's behalf; a
  `*_viewed` event means an app loaded content, not proof a human read it.
- Feed metadata contains identities/IPs and object IDs. It is distinct from the
  Compliance content endpoints and Cowork/Code OTel. Since September 24, 2026,
  file/artifact title/name fields on activities are empty/null/omitted; do not
  invent them or fetch document content to enrich the feed.

### OpenAI API Platform audit logs

[Administration overview](https://developers.openai.com/api/reference/administration/overview),
[Admin APIs guide](https://developers.openai.com/api/docs/guides/admin-apis),
[List audit logs reference](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/audit_logs/methods/list).
All three were fetched with the OpenAI Docs MCP.

- This source is **API Platform organization administration**, not ChatGPT
  Enterprise compliance transcripts, Codex runtime OTel, usage billing, or a
  log of every inference request. It lists user actions/configuration changes.
- Use an organization Admin API key, not a project inference key. Provision it
  through an authorized organization administrator. The fetched pages do not
  establish a universal plan entitlement, fixed appearance delay, or retention
  SLA; confirm these with the organization before depending on them.
- `GET https://api.openai.com/v1/organization/audit_logs` uses bearer auth.
  JSON response contains `data[]`, `first_id`, `last_id`, and `has_more`.
  Pagination uses `after`/`before`, not Anthropic's `after_id`.
  `effective_at[gte]` / `[lte]` filter Unix seconds; event timestamps are
  `effective_at`. Events have `id`, `type`, actor details and type-specific data.
- Actors can identify users, API-key owners or sessions with IP/location
  metadata. Lens preserves selected identifiers and omits raw event details;
  no prompt-content retrieval is implied. Use direct documented HTTP contracts;
  SDK names vary across SDK versions and are not needed for Lens setup.

### Google Workspace Gemini activity

[Activity event reference](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gemini-in-workspace-apps),
[Reports activities.list](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list),
[admin access and fields](https://support.google.com/a/answer/14521388?hl=en),
[lag and retention](https://support.google.com/a/answer/7061566?hl=en).

- This is Gemini **in Workspace applications**, not Gemini CLI hooks, consumer
  app transcripts, Vertex AI, or the Gemini developer API. The exact Reports
  application name is **`gemini_in_workspace_apps`**, not `gemini`.
- Admin console search requires **Audit & Investigation** privilege; advanced
  investigation capabilities vary by Workspace edition. API use requires an
  eligible edition, enabled Admin SDK API, an authorized administrator/OAuth
  identity, and `https://www.googleapis.com/auth/admin.reports.audit.readonly`.
  An OAuth scope alone does not grant admin privileges. If using service-account
  delegation, provision it through the normal Workspace admin process. Lens
  consumes an existing access token; it does not implement OAuth consent,
  domain-wide delegation setup, or token refresh.
- Query `GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/gemini_in_workspace_apps`.
  Response `items[]` contains activity IDs (`time`, `uniqueQualifier`, application,
  customer), actor metadata and `events[]`. `nextPageToken` becomes `pageToken`.
  `startTime`/`endTime` use RFC 3339. Event type `ai_usage_event`, name
  `feature_utilization`, and parameters such as `action`/application describe
  feature use. Counts are not model token counts or complete conversations.
- Logs are available from 2025-06-20, with a rolling history up to 180 days.
  Google lists near-real-time lag (a couple of minutes), with possible delays
  and rare missing events; do not treat an empty page as proof of no usage.
- The documented utilization schema describes metadata, not prompt/email bodies.
  Identities and device/IP data remain sensitive. `includeSensitiveInfo` on
  activities.list is not supported for this application; do not enable it.

## Polling and operational boundaries

`telemetry poll` implements exactly these five read-only GET sources. It does not
poll OTel, Copilot session content, or undocumented transcript endpoints.

| Source | Default credential environment variable | Scope / continuation |
| --- | --- | --- |
| `openai-audit` | `OPENAI_ADMIN_KEY` | Key's API Platform organization; `last_id` → `after` |
| `anthropic-compliance` | `ANTHROPIC_COMPLIANCE_ACCESS_KEY` | Key's authorized organizations; `last_id` → `after_id` (older pages) |
| `cursor-audit` | `CURSOR_ADMIN_API_KEY` | Team key; `pagination.page` / `hasNextPage` |
| `copilot-audit` | `GITHUB_TOKEN` | Exactly one of `--organization` / `--enterprise`; validated Link cursor |
| `google-gemini` | `GOOGLE_ACCESS_TOKEN` | Existing OAuth access token's authorized Workspace scope; `nextPageToken` |

Supply only an **environment variable name** with `--token-env`, never the secret
itself. Provision credentials through an approved secret manager. Non-GitHub
sources reject `--organization` and `--enterprise`; these are not generic tenant
selectors. Confirm the key's actual organization scope before collecting.

```sh
# OPENAI_ADMIN_KEY must already be provisioned in this process.
./target/debug/agent-lens telemetry poll --source openai-audit \
  --token-env OPENAI_ADMIN_KEY --output ./openai-audit.jsonl \
  --checkpoint ./openai-audit.checkpoint.json --max-pages 10

# Replace YOUR-ORG with the authorized GitHub organization slug.
./target/debug/agent-lens telemetry poll --source copilot-audit \
  --organization YOUR-ORG --output ./copilot-audit.jsonl \
  --since 2026-10-01T00:00:00Z --until 2026-10-02T00:00:00Z \
  --checkpoint ./copilot-october-01.checkpoint.json
```

The second example retrieves historical data, not current usage. The GitHub poll
uses `action:copilot`, `include=all`, ascending order. The adapter keeps only
`copilot.*` actions; it excludes agent-performed actions in other categories even
if their actor is Copilot. Only the official `api.github.com` endpoints are used;
GitHub Enterprise Server and alternative regional API hosts are not configured
by this preview.

Each invocation is a **fixed snapshot**, not a daemon. `--since` and `--until`
accept RFC 3339; defaults are the last seven days ending when the snapshot is
created. The checkpoint freezes those dates. Cursor windows cannot exceed 30
days. A new time window needs a new checkpoint. Reusing a completed checkpoint
performs no collection; changing its source, tenant, output or explicit date
arguments is rejected.

- Polls request 100 provider rows per page, allow 1–1000 `--max-pages` (default
  100), and cap 10,000 normalized events per invocation. Reaching the page limit
  returns an error; resume the **same arguments and checkpoint** to continue.
  Without a checkpoint, rerunning can replay the snapshot from the beginning.
- Production origins/paths are fixed HTTPS endpoints. Redirects and ambient
  proxy routing are disabled. Responses are capped at 8 MiB; request timeout is
  30 seconds, connect timeout 10 seconds. No OAuth login, token refresh, or
  automatic retry is implemented.
- Authentication, rate-limit and server errors return sanitized status errors.
  After fixing the cause, rerun the same checkpoint. Cursor limits the upstream
  endpoint to 20 requests/minute/team; a long immediate run can hit this limit
  and need a later resume. Lens does not automatically pace requests.
- Each page advances its checkpoint only after output append/sync. Earlier pages
  remain if a later page fails. A crash between append and checkpoint save can
  replay a page: delivery is **at least once**, not exactly once. Deduplicate by
  source and `event_id`, plus `event_index` for multiple Google events per activity.
- Output length checks detect missing/truncated committed output, not arbitrary
  content replacement. Checkpoints are local recovery state, not a tamper-proof
  integrity mechanism. Preserve output and checkpoint together and keep secrets
  out of both.

Occurrence time and `observed_at` are distinct. Delayed provider records can fall
inside an already completed window, so schedule overlapping subsequent windows
and deduplicate downstream. Anthropic's older-page cursor is not a high-water
mark for new arrivals. An empty completed snapshot does not prove no activity.

For synthetic local tests only, `--test-endpoint` accepts an HTTP literal
loopback IP URL without credentials, query, or fragment. It always uses a dummy
credential and refuses `--token-env`; it never reads production token variables.
It is not a way to configure an alternative production API host.

## Privacy, limits, and verification

Lens applies a metadata allowlist, dropping raw log bodies, prompts/responses,
tool arguments/results, arbitrary nested fields, and strings matching known
credential patterns. This is a deliberately lossy projection. It is not a DLP
system, complete anonymizer, transcript store, or tamper-evident audit ledger.
Unknown fields are not automatically safe. Even allowed model/tool names and
session/account identifiers may contain sensitive information.

The projection cannot undo exposure in the original input file, producer,
collector buffers, debug logs, or another destination. Keep source content
capture off and review upstream defaults. Limit file access, rotate outputs,
choose retention deliberately, and add trusted collector/host identity outside
untrusted producer attributes. Preserve provider documentation and software
versions when using these observations as evidence.

Local fixture/import/HTTP tests establish parser and transport behavior for the
tested messages. They do not establish tenant entitlements, managed-setting
application, producer authentication, cloud reachability, rate limits, live
client fidelity, full event coverage, or production delivery. Synthetic fixtures
must not be counted as observed employee activity. No enterprise live test or
production deployment is claimed for this preview.

### Collector reference contracts

Retrieved 2026-10-29 from the official OpenTelemetry repositories:

- [OTLP receiver](https://github.com/open-telemetry/opentelemetry-collector/blob/main/receiver/otlpreceiver/README.md)
- [OTLP HTTP exporter](https://github.com/open-telemetry/opentelemetry-collector/blob/main/exporter/otlphttpexporter/README.md)
- [Bearer-token authenticator](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/bearertokenauthextension/README.md)

These define the example Collector components. Deployers must validate the
configuration, certificate trust, secrets, source separation and overload behavior
against their installed Collector release before using it with real data.
