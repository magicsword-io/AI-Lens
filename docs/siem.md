# Sending events to a SIEM

AI Lens writes local JSONL: one complete JSON object per line. Configure your
existing log shipper to tail that file and parse each line as JSON. AI Lens
does not provide a network sender, delivery acknowledgment, rotation service,
or retention policy. Stop collection before moving or rotating the file.

Use a private output path. Ship the metadata-only stream first; opt-in captured
content remains sensitive despite best-effort redaction. Apply access control,
transport security, retention, and deletion in your collector and SIEM.

## Field mapping

The table below describes native hook events. Experimental `telemetry` imports,
OTLP reception, and audit polling use the distinct
`schema: agent-lens.telemetry.v1`. Route those to a separate dataset or branch
your parser on `schema`. They always use `enforcement: observe_only`, with
`source`, `signal`, `event_name`, and host `observed_at`. Source timestamps retain
their native units (`timestamp_unit` or `timestamp_unix_nano`); do not assume all
`timestamp` fields have the hook schema's meaning. Audit `event_id` plus source
and tenant scope supports deduplication; Google also needs `event_index`, and
Cursor OTel exposes `attributes["cursor.event.id"]` when present. Poll/retry
delivery is at least once. See [the telemetry guide](telemetry-sources.md) for
the exact projection and source-specific limits. Provider decision attributes
are observations and do not prove Lens enforcement.

| Field | Suggested mapping | Interpretation |
| --- | --- | --- |
| `schema_version` | Integer | Event shape version; currently `1`. |
| `timestamp` | Date/time | Host processing time; map to your event timestamp. |
| `agent` | Keyword | Adapter name. |
| `hook_event` | Keyword | Native event name, not a universal taxonomy. |
| `phase` | Keyword | `pre`, `post`, `lifecycle`, or `unknown`. |
| `decision` | Keyword | `allow`, `block`, or `would_block`. |
| `matched_rules` | Keyword array | Matching policy IDs; empty when none match. |
| `enforcement` | Keyword | `supported` or `observe_only` for this event. |
| `session_id` | Optional keyword | Native opaque identifier when supplied. |
| `agent_id`, `parent_agent_id` | Optional keywords | Native identifiers only; no inferred relationship. |
| `turn_id`, `tool_use_id`, `tool_call_id` | Optional keywords | Native turn/tool identifiers when supplied and privacy-filtered. |
| `task_id` | Optional keyword | Native Hermes task identifier when supplied and privacy-filtered. |
| `tool_name` | Optional keyword | Native tool name when supplied. |
| `content` | Optional JSON | Only with explicit content capture; restrict access. |
| `observer` | Object | Host name/version metadata; distinct from the observed agent. |
| `synthetic` | Optional boolean | `true` on demo records; exclude from live activity counts. |

Add host identity, source path, agent/client version, and ingestion time at the
collector. Keep those collector fields distinct from agent-supplied metadata.
Session IDs are not globally unique host identities; do not invent process or
parent/child lineage from a tool name or a shared session label.

## Queries

These examples assume your collector has already parsed JSON and mapped the
fields above. Adapt the index/table names and array handling to your ingestion
pipeline. They are query recipes, not a shipped SIEM integration.

Count requested denials by agent in Splunk:

```spl
index=agent_lens sourcetype=agent_lens:jsonl decision=block
| stats count by agent, tool_name
```

Find rules that match without preventive enforcement in Splunk:

```spl
index=agent_lens sourcetype=agent_lens:jsonl decision=would_block
| mvexpand matched_rules
| stats count by agent, hook_event, matched_rules
```

Filter in Elastic/Kibana with keyword mappings:

```text
schema_version: 1 and decision: "block" and enforcement: "supported"
```

For a local sanity check before forwarding:

```sh
python -c 'import collections,json,sys; print(collections.Counter(json.loads(line)["decision"] for line in open(sys.argv[1], encoding="utf-8") if line.strip()))' events.jsonl
```

## Interpret the stream conservatively

`block` records a requested vendor denial. Confirm prevention with the client's
observed result or an independent side-effect check. `would_block` is useful
for tuning, but it never counts as a prevented action. An audit rule appears in
`matched_rules` on an `allow` event.

Missing events can mean idle agents, stopped collection, missing registration,
unsupported tool paths, or a failed hook/collector. Pair a known harmless
positive-control event with monitoring of hook stderr and collector health.
The JSONL file has no tamper-evidence or delivery guarantee; it is not a complete
record of all agent activity. Keep raw payloads and credentials out of incident
tickets and public examples.
