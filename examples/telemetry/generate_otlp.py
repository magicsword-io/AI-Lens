#!/usr/bin/env python3
"""Generate synthetic, metadata-only OTLP examples; no account or network needed."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TIME = "1793275200000000000"


def attrs(**values):
    def value(v):
        kind = "boolValue" if isinstance(v, bool) else "intValue" if isinstance(v, int) else "stringValue"
        return {kind: str(v) if kind == "intValue" else v}
    return [{"key": k, "value": value(v)} for k, v in values.items()]


def write(name, signal, service, records, scope=None):
    resource, scopes, items = {
        "logs": ("resourceLogs", "scopeLogs", "logRecords"),
        "metrics": ("resourceMetrics", "scopeMetrics", "metrics"),
        "traces": ("resourceSpans", "scopeSpans", "spans"),
    }[signal]
    payload = {
        "_fixture": "SYNTHETIC: invented vendor-shaped protocol example; not a captured live session.",
        resource: [{"resource": {"attributes": attrs(**{"service.name": service})},
                    scopes: [{"scope": {"name": scope or service}, items: records}]}],
    }
    (ROOT / (name + ".json")).write_text(json.dumps(payload, indent=2) + "\n")


for name, service, event in [
    ("claude-code", "claude-code", "api_request"),
    ("claude-cowork", "cowork", "tool_result"),
    ("codex", "codex", "codex.tool_result"),
]:
    write("otlp-" + name + "-logs", "logs", service, [{
        "timeUnixNano": TIME, "severityNumber": 9, "severityText": "INFO",
        "attributes": attrs(**{"event.name": event, "session.id": "synthetic-session-001",
                               "model": "synthetic-model", "tool_name": "Read", "success": True,
                               "duration_ms": 12, "input_tokens": 24}),
    }])

write("otlp-cursor-logs", "logs", "cursor", [{
    "timeUnixNano": TIME, "severityNumber": 9, "body": {"stringValue": "api_request"},
    "attributes": attrs(**{"cursor.event.id": "customer-telemetry:v1:synthetic-001",
                           "cursor.request.id": "synthetic-request-001", "cursor.model.name": "synthetic-model",
                           "cursor.api.request.input_tokens": 24}),
}], "cursor.telemetry")

write("otlp-cursor-metrics", "metrics", "cursor", [{
    "name": "cursor.token.usage", "unit": "{token}",
    "sum": {"aggregationTemporality": 1, "isMonotonic": True, "dataPoints": [{
        "timeUnixNano": TIME, "asInt": "24", "attributes": attrs(**{"cursor.token.type": "input"}),
    }]},
}], "cursor.telemetry")

write("otlp-codex-metrics", "metrics", "codex", [{
    "name": "codex.tool.call.duration_ms", "unit": "ms",
    "histogram": {"aggregationTemporality": 2, "dataPoints": [{
        "timeUnixNano": TIME, "count": "2", "sum": 30, "min": 10, "max": 20,
        "explicitBounds": [10, 20], "bucketCounts": ["1", "1", "0"],
        "attributes": attrs(tool="shell", success=True),
    }]},
}])

write("otlp-claude-code-traces", "traces", "claude-code", [{
    "name": "claude_code.tool", "traceId": "11111111111111111111111111111111",
    "spanId": "2222222222222222", "parentSpanId": "3333333333333333",
    "startTimeUnixNano": TIME, "endTimeUnixNano": "1793275200012000000", "kind": 1,
    "status": {"code": 1}, "attributes": attrs(tool_name="Read", **{"session.id": "synthetic-session-001"}),
}])
