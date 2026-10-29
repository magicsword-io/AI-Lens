//! Pure, metadata-only OTLP normalization. Vendor content fields are never copied.
use anyhow::{bail, ensure, Context, Result};
use opentelemetry_proto::tonic::collector::{
    logs::v1::ExportLogsServiceRequest, metrics::v1::ExportMetricsServiceRequest,
    trace::v1::ExportTraceServiceRequest,
};
use prost::Message;
use serde_json::{json, Value};

use super::model::{attributes, base, copy_text, text};

#[path = "wire.rs"]
mod wire;

const MAX_RECORDS: usize = 10_000;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Default)]
struct Output {
    records: Vec<Value>,
    bytes: usize,
}
const METRIC_TYPES: [&str; 5] = [
    "gauge",
    "sum",
    "histogram",
    "summary",
    "exponentialHistogram",
];

fn keys(signal: &str) -> Result<(&'static str, &'static str, &'static str)> {
    match signal {
        "logs" => Ok(("resourceLogs", "scopeLogs", "logRecords")),
        "metrics" => Ok(("resourceMetrics", "scopeMetrics", "metrics")),
        "traces" => Ok(("resourceSpans", "scopeSpans", "spans")),
        _ => bail!("unsupported OTLP signal"),
    }
}

/// Decode an OTLP/HTTP body, without a network client or an async runtime.
/// Content-Encoding decompression belongs to the bounded HTTP host.
pub fn decode(signal: &str, content_type: &str, bytes: &[u8]) -> Result<Value> {
    keys(signal)?;
    ensure!(bytes.len() <= MAX_BYTES, "OTLP body exceeds 8 MiB");
    let mime = content_type.split(';').next().unwrap_or("").trim();
    if mime.eq_ignore_ascii_case("application/json") {
        // Keep unknown JSON fields until normalization; never expose serde's input excerpts.
        return serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid OTLP JSON"));
    }
    ensure!(
        mime.eq_ignore_ascii_case("application/x-protobuf"),
        "unsupported OTLP content type"
    );
    // Reject allocation amplification before either prost or serde materializes it.
    wire::preflight(signal, bytes)?;
    let result = match signal {
        "logs" => serde_json::to_value(
            ExportLogsServiceRequest::decode(bytes).context("invalid OTLP logs protobuf")?,
        ),
        "metrics" => serde_json::to_value(
            ExportMetricsServiceRequest::decode(bytes).context("invalid OTLP metrics protobuf")?,
        ),
        "traces" => serde_json::to_value(
            ExportTraceServiceRequest::decode(bytes).context("invalid OTLP traces protobuf")?,
        ),
        _ => unreachable!(),
    };
    result.context("cannot represent OTLP protobuf")
}

fn object(value: &Value) -> Result<()> {
    ensure!(value.is_object(), "OTLP message must be an object");
    Ok(())
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    match value.get(key) {
        None => Ok(&[]),
        Some(Value::Array(items)) => {
            ensure!(
                items.len() <= MAX_RECORDS,
                "OTLP collection exceeds 10000 entries"
            );
            Ok(items)
        }
        _ => bail!("OTLP {key} must be an array"),
    }
}

fn metadata(value: &Value) -> Result<Value> {
    if value.is_null() {
        return Ok(json!({}));
    }
    object(value)?;
    for item in array(value, "attributes")? {
        object(item)?;
        ensure!(
            item.get("key").is_some_and(Value::is_string),
            "OTLP attribute key must be a string"
        );
        if let Some(v) = item.get("value").filter(|v| !v.is_null()) {
            object(v)?;
        }
    }
    let mut attrs = attributes(&value["attributes"]);
    // OTLP JSON represents int64 as strings; generated protobuf serde uses numbers.
    for item in array(value, "attributes")? {
        if let Some(key) = item["key"].as_str().filter(|key| attrs.get(*key).is_some()) {
            if let Some(raw) = item["value"].get("intValue") {
                if let Some(n) = raw
                    .as_i64()
                    .or_else(|| raw.as_str().and_then(|s| s.parse::<i64>().ok()))
                {
                    attrs[key] = json!(n);
                } else if let Some(map) = attrs.as_object_mut() {
                    map.remove(key);
                }
            }
        }
    }
    Ok(attrs)
}

/// Normalize supported sources into observation records. A metric datapoint is
/// one record; the whole request fails if any recognized container is malformed.
pub fn normalize(source: &str, signal: &str, payload: &Value) -> Result<Vec<Value>> {
    ensure!(
        matches!(
            source,
            "claude-code-otel"
                | "claude-cowork-otel"
                | "codex-otel"
                | "cursor-runtime"
                | "copilot-otel"
        ),
        "unsupported OTLP source"
    );
    let (resources, scopes, records) = keys(signal)?;
    object(payload)?;
    for other in ["resourceLogs", "resourceMetrics", "resourceSpans"] {
        ensure!(
            other == resources || payload.get(other).is_none(),
            "OTLP signal does not match payload"
        );
    }
    let mut output = Output::default();
    let mut containers = 0usize;
    let mut records_seen = 0usize;
    for resource in array(payload, resources)? {
        object(resource)?;
        let resource_attrs = metadata(&resource["resource"])?;
        for scope in array(resource, scopes)? {
            object(scope)?;
            containers += 1;
            ensure!(containers <= MAX_RECORDS, "OTLP scope count exceeds 10000");
            let scope_attrs = metadata(&scope["scope"])?;
            for record in array(scope, records)? {
                records_seen += 1;
                ensure!(
                    records_seen <= MAX_RECORDS,
                    "OTLP record count exceeds 10000"
                );
                object(record)?;
                if signal == "metrics" {
                    normalize_metric(source, record, &resource_attrs, &scope_attrs, &mut output)?;
                } else {
                    let attrs = metadata(record)?;
                    let name = if signal == "logs" {
                        text(&record["eventName"])
                            .or_else(|| text(&attrs["event.name"]))
                            .or_else(|| constant_event(source, &record["body"]))
                    } else {
                        text(&record["name"])
                    };
                    let mut event = base(
                        source,
                        signal,
                        name.as_deref().unwrap_or(if signal == "logs" {
                            "otel.log"
                        } else {
                            "otel.span"
                        }),
                    );
                    common(&mut event, record, &resource_attrs, &scope_attrs, attrs);
                    if signal == "logs" {
                        unsigned(
                            &mut event,
                            "severity_number",
                            record.get("severityNumber"),
                            false,
                        );
                        // Severity is an enum-like field, not arbitrary log text.
                        if let Some(level) = record["severityText"].as_str().filter(|s| {
                            matches!(
                                *s,
                                "TRACE" | "DEBUG" | "INFO" | "WARN" | "WARNING" | "ERROR" | "FATAL"
                            )
                        }) {
                            event["severity_text"] = json!(level);
                        }
                    } else {
                        identifier(&mut event, "parent_span_id", &record["parentSpanId"], 16);
                        timestamp(
                            &mut event,
                            "end_time_unix_nano",
                            record.get("endTimeUnixNano"),
                        );
                        unsigned(&mut event, "span_kind", record.get("kind"), false);
                        if let Some(status) = record.get("status").filter(|s| !s.is_null()) {
                            object(status)?;
                            unsigned(
                                &mut event,
                                "status_code",
                                Some(status.get("code").unwrap_or(&Value::from(0))),
                                true,
                            );
                        }
                    }
                    push(&mut output, event)?;
                }
            }
        }
    }
    Ok(output.records)
}

// Some SDKs put the event label in body. Only exact, documented constants
// are interpreted; arbitrary strings and all structured bodies stay private.
fn constant_event(source: &str, body: &Value) -> Option<String> {
    let label = body.get("stringValue")?.as_str()?;
    let (prefix, name) = if source == "cursor-runtime" {
        let name = match label {
            "api_request" => "api.request",
            "api_error" => "api.error",
            "api_correction_not_billed_errored"
            | "api_correction_not_billed_aborted_before_timeout" => "api.correction",
            "skill_activated" => "skill.activated",
            "hook_execution_complete" => "hook.execution_complete",
            "plugin_installed" => "plugin.installed",
            "cloud_agent_pull_request_opened"
            | "cloud_agent_pull_request_merged"
            | "cloud_agent_pull_request_closed"
            | "cloud_agent_pull_request_creation_failed" => "cloud_agent.pull_request",
            "cloud_agent_setup_started"
            | "cloud_agent_setup_completed"
            | "cloud_agent_setup_failed" => "cloud_agent.setup",
            "cloud_agent_commit" => "cloud_agent.commit",
            "cloud_agent_artifact_created" => "cloud_agent.artifact",
            "cloud_agent_mcp_auth_error" => "cloud_agent.mcp_auth_error",
            "cloud_agent_review_followup" => "cloud_agent.review_followup",
            "grok_bot_mcp_tool_call" => "grok_bot.mcp_tool_call",
            "grok_bot_shell_command" => "grok_bot.shell_command",
            "grok_bot_browser_navigation" => "grok_bot.browser_navigation",
            "grok_bot_computer_use_session" => "grok_bot.computer_use_session",
            "grok_bot_tool_result" => "grok_bot.tool_result",
            "grok_bot_tool_decision" => "grok_bot.tool_decision",
            "grok_bot_file_transfer" => "grok_bot.file_transfer",
            "grok_bot_message_delivery" => "grok_bot.message_delivery",
            "grok_bot_routine_run" => "grok_bot.routine_run",
            "grok_bot_guardrail" => "grok_bot.guardrail",
            "grok_bot_delegation" => "grok_bot.delegation",
            _ => return None,
        };
        ("cursor.", name)
    } else if source == "claude-code-otel" || source == "claude-cowork-otel" {
        let name = label.strip_prefix("claude_code.").unwrap_or(label);
        if !matches!(
            name,
            "user_prompt"
                | "assistant_response"
                | "tool_result"
                | "tool_decision"
                | "api_request"
                | "api_error"
                | "api_refusal"
                | "api_request_body"
                | "api_response_body"
        ) {
            return None;
        }
        (
            if source == "claude-code-otel" {
                "claude_code."
            } else {
                ""
            },
            name,
        )
    } else {
        return None;
    };
    Some(format!("{prefix}{name}"))
}

fn push(output: &mut Output, event: Value) -> Result<()> {
    ensure!(
        output.records.len() < MAX_RECORDS,
        "OTLP record count exceeds 10000"
    );
    let size = serde_json::to_vec(&event)?.len() + 1;
    ensure!(
        size <= MAX_OUTPUT_BYTES.saturating_sub(output.bytes),
        "normalized OTLP output exceeds 32 MiB"
    );
    output.bytes += size;
    output.records.push(event);
    Ok(())
}

fn common(event: &mut Value, record: &Value, resource: &Value, scope: &Value, attrs: Value) {
    event["resource_attributes"] = resource.clone();
    event["scope_attributes"] = scope.clone();
    event["attributes"] = attrs;
    timestamp(event, "timestamp_unix_nano", record.get("timeUnixNano"));
    timestamp(
        event,
        "observed_time_unix_nano",
        record.get("observedTimeUnixNano"),
    );
    timestamp(
        event,
        "start_time_unix_nano",
        record.get("startTimeUnixNano"),
    );
    identifier(event, "trace_id", &record["traceId"], 32);
    identifier(event, "span_id", &record["spanId"], 16);
}

fn identifier(event: &mut Value, key: &str, value: &Value, len: usize) {
    if let Some(id) = value.as_str().filter(|s| {
        s.len() == len && s.bytes().all(|c| c.is_ascii_hexdigit()) && s.bytes().any(|c| c != b'0')
    }) {
        event[key] = json!(id.to_ascii_lowercase());
    }
}

fn uint(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

fn timestamp(event: &mut Value, key: &str, value: Option<&Value>) {
    if let Some(n) = value.and_then(uint).filter(|n| *n != 0) {
        // Preserve nanosecond precision for downstream JavaScript consumers.
        event[key] = json!(n.to_string());
    }
}

fn unsigned(event: &mut Value, key: &str, value: Option<&Value>, include_zero: bool) {
    if let Some(n) = value.and_then(uint).filter(|n| include_zero || *n != 0) {
        event[key] = json!(n);
    }
}

fn numeric(value: &Value) -> Option<Value> {
    if value.is_number() {
        if value.is_f64() {
            let n = value.as_f64()?;
            if n.fract() == 0.0 && n >= i64::MIN as f64 && n < -(i64::MIN as f64) {
                return Some(json!(n as i64));
            }
        }
        return Some(value.clone());
    }
    let s = value.as_str()?;
    if let Ok(n) = s.parse::<i64>() {
        return Some(json!(n));
    }
    if let Ok(n) = s.parse::<u64>() {
        return Some(json!(n));
    }
    let n = s.parse::<f64>().ok()?;
    n.is_finite().then(|| json!(n))
}

fn numbers(target: &mut Value, input: &Value, fields: &[&str]) {
    for key in fields {
        if let Some(n) = input.get(*key).and_then(numeric) {
            target[*key] = n;
        }
    }
}

fn numeric_array(target: &mut Value, input: &Value, key: &str, counts: bool) -> Result<()> {
    let mut values = Vec::new();
    for v in array(input, key)? {
        let n = if counts {
            uint(v).map(|n| json!(n))
        } else {
            numeric(v)
        };
        let Some(n) = n else {
            bail!("invalid OTLP numeric array");
        };
        values.push(n);
    }
    if !values.is_empty() {
        target[key] = Value::Array(values);
    }
    Ok(())
}

fn normalize_metric(
    source: &str,
    record: &Value,
    resource: &Value,
    scope: &Value,
    output: &mut Output,
) -> Result<()> {
    let kinds: Vec<_> = METRIC_TYPES
        .iter()
        .filter(|k| record.get(**k).is_some())
        .collect();
    ensure!(
        kinds.len() <= 1,
        "OTLP metric has multiple aggregation types"
    );
    let Some(kind) = kinds.first().copied() else {
        return Ok(());
    };
    let data = &record[*kind];
    object(data)?;
    let name = text(&record["name"]).unwrap_or_else(|| "otel.metric".to_owned());
    for point in array(data, "dataPoints")? {
        object(point)?;
        let attrs = metadata(point)?;
        let mut event = base(source, "metrics", &name);
        common(&mut event, point, resource, scope, attrs);
        let mut metric = json!({"type": kind, "name": name});
        copy_text(&mut metric, "unit", record.get("unit"));
        unsigned(
            &mut metric,
            "aggregation_temporality",
            data.get("aggregationTemporality"),
            false,
        );
        if *kind == "sum" {
            // Missing bool is protobuf's false default.
            metric["is_monotonic"] = json!(data["isMonotonic"].as_bool().unwrap_or(false));
        }
        match *kind {
            "gauge" | "sum" => {
                ensure!(
                    !(point.get("asInt").is_some() && point.get("asDouble").is_some()),
                    "OTLP point has multiple numeric values"
                );
                if let Some(n) = point
                    .get("asInt")
                    .or_else(|| point.get("asDouble"))
                    .and_then(numeric)
                {
                    metric["value"] = n;
                }
            }
            "histogram" | "summary" | "exponentialHistogram" => {
                unsigned(
                    &mut metric,
                    "count",
                    Some(point.get("count").unwrap_or(&Value::from(0))),
                    true,
                );
                numbers(&mut metric, point, &["sum", "min", "max"]);
                if *kind == "histogram" {
                    numeric_array(&mut metric, point, "bucketCounts", true)?;
                    numeric_array(&mut metric, point, "explicitBounds", false)?;
                } else if *kind == "summary" {
                    if point.get("sum").is_none() {
                        metric["sum"] = json!(0);
                    }
                    let mut quantiles = Vec::new();
                    for q in array(point, "quantileValues")? {
                        object(q)?;
                        let mut value = json!({});
                        for key in ["quantile", "value"] {
                            if q.get(key).is_none() {
                                value[key] = json!(0);
                            }
                        }
                        numbers(&mut value, q, &["quantile", "value"]);
                        if value.as_object().is_some_and(|o| o.len() == 2) {
                            quantiles.push(value);
                        }
                    }
                    if !quantiles.is_empty() {
                        metric["quantileValues"] = json!(quantiles);
                    }
                } else {
                    for key in ["scale", "zeroThreshold", "zeroCount"] {
                        if point.get(key).is_none() {
                            metric[key] = json!(0);
                        }
                    }
                    numbers(&mut metric, point, &["scale", "zeroThreshold"]);
                    unsigned(&mut metric, "zeroCount", point.get("zeroCount"), true);
                    for side in ["positive", "negative"] {
                        if let Some(buckets) = point.get(side).filter(|v| !v.is_null()) {
                            object(buckets)?;
                            let mut value = json!({});
                            if buckets.get("offset").is_none() {
                                value["offset"] = json!(0);
                            }
                            numbers(&mut value, buckets, &["offset"]);
                            numeric_array(&mut value, buckets, "bucketCounts", true)?;
                            metric[side] = value;
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
        unsigned(&mut metric, "flags", point.get("flags"), false);
        event["metric"] = metric;
        push(output, event)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::{
        common::v1::{any_value, AnyValue, KeyValue},
        logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
        metrics::v1::{
            metric, number_data_point, Gauge, Metric, NumberDataPoint, ResourceMetrics,
            ScopeMetrics,
        },
        trace::v1::{ResourceSpans, ScopeSpans, Span, Status},
    };

    fn payload(signal: &str, records: Vec<Value>) -> Value {
        let (resources, scopes, key) = keys(signal).unwrap();
        json!({resources: [{scopes: [{key: records}]}]})
    }

    fn fixture(name: &str) -> Value {
        let raw = match name {
            "claude" => include_str!("../../../../examples/telemetry/otlp-claude-code-logs.json"),
            "cowork" => include_str!("../../../../examples/telemetry/otlp-claude-cowork-logs.json"),
            "codex" => include_str!("../../../../examples/telemetry/otlp-codex-logs.json"),
            "cursor" => include_str!("../../../../examples/telemetry/otlp-cursor-logs.json"),
            "cursor-metrics" => {
                include_str!("../../../../examples/telemetry/otlp-cursor-metrics.json")
            }
            "metrics" => include_str!("../../../../examples/telemetry/otlp-codex-metrics.json"),
            "traces" => include_str!("../../../../examples/telemetry/otlp-claude-code-traces.json"),
            _ => unreachable!(),
        };
        serde_json::from_str(raw).unwrap()
    }

    fn stable(mut records: Vec<Value>) -> Vec<Value> {
        for event in &mut records {
            event.as_object_mut().unwrap().remove("observed_at");
        }
        records
    }

    #[test]
    fn positive_vendor_logs_and_cursor_dedupe() {
        for (source, name, expected) in [
            ("claude-code-otel", "claude", "api_request"),
            ("claude-cowork-otel", "cowork", "tool_result"),
            ("codex-otel", "codex", "codex.tool_result"),
            ("cursor-runtime", "cursor", "cursor.api.request"),
        ] {
            let events = normalize(source, "logs", &fixture(name)).unwrap();
            assert_eq!(events.len(), 1);
            let event = &events[0];
            assert_eq!(event["source"], source);
            assert_eq!(event["event_name"], expected);
            assert_eq!(event["enforcement"], "observe_only");
            assert_eq!(event["timestamp_unix_nano"], "1793275200000000000");
            assert_eq!(event["severity_number"], 9);
            if source == "cursor-runtime" {
                assert_eq!(
                    event["attributes"]["cursor.event.id"],
                    "customer-telemetry:v1:synthetic-001"
                );
            } else {
                assert_eq!(event["attributes"]["input_tokens"], 24);
            }
        }
    }

    #[test]
    fn metrics_and_trace_positive_controls() {
        let histogram = normalize("codex-otel", "metrics", &fixture("metrics")).unwrap();
        assert_eq!(histogram[0]["metric"]["count"], 2);
        assert_eq!(histogram[0]["metric"]["sum"], 30);
        assert_eq!(histogram[0]["metric"]["bucketCounts"], json!([1, 1, 0]));
        let sum = normalize("cursor-runtime", "metrics", &fixture("cursor-metrics")).unwrap();
        assert_eq!(sum[0]["metric"]["value"], 24);
        assert_eq!(sum[0]["metric"]["is_monotonic"], true);
        let spans = normalize("claude-code-otel", "traces", &fixture("traces")).unwrap();
        assert_eq!(spans[0]["event_name"], "claude_code.tool");
        assert_eq!(spans[0]["trace_id"], "11111111111111111111111111111111");
        assert_eq!(spans[0]["span_id"], "2222222222222222");
        assert_eq!(spans[0]["parent_span_id"], "3333333333333333");
        assert_eq!(spans[0]["status_code"], 1);
        assert_eq!(spans[0]["start_time_unix_nano"], "1793275200000000000");
        assert_eq!(spans[0]["end_time_unix_nano"], "1793275200012000000");
        assert!(normalize("copilot-otel", "traces", &fixture("traces")).is_ok());
    }

    #[test]
    fn all_metric_aggregations_keep_only_numeric_payload() {
        let cases = [
            ("gauge", json!({"asDouble": 1.25})),
            ("sum", json!({"asInt": "-42"})),
            (
                "summary",
                json!({"count": "3", "sum": 12, "quantileValues": [{"quantile": 0.5, "value": 4, "secret": "PRIVATE"}]}),
            ),
            (
                "exponentialHistogram",
                json!({"count": "3", "sum": 12, "scale": -1, "zeroCount": "1", "zeroThreshold": 0.01, "positive": {"offset": -2, "bucketCounts": ["1", "1"], "raw": "PRIVATE"}}),
            ),
        ];
        for (kind, point) in cases {
            let input = payload(
                "metrics",
                vec![json!({"name": "synthetic.metric", kind: {"dataPoints": [point]}})],
            );
            let events = normalize("codex-otel", "metrics", &input).unwrap();
            assert_eq!(events.len(), 1);
            let metric = &events[0]["metric"];
            assert_eq!(metric["type"], kind);
            match kind {
                "gauge" => assert_eq!(metric["value"], 1.25),
                "sum" => assert_eq!(metric["value"], -42),
                "summary" => assert_eq!(
                    metric["quantileValues"],
                    json!([{"quantile": 0.5, "value": 4}])
                ),
                _ => assert_eq!(
                    metric["positive"],
                    json!({"offset": -2, "bucketCounts": [1, 1]})
                ),
            }
            assert!(!events[0].to_string().contains("PRIVATE"));
        }
    }

    #[test]
    fn protobuf_and_http_json_logs_equal() {
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs {
                    log_records: vec![LogRecord {
                        time_unix_nano: 1793275200000000000,
                        severity_number: 9,
                        event_name: "codex.tool_result".into(),
                        trace_id: vec![17; 16],
                        span_id: vec![34; 8],
                        attributes: vec![KeyValue {
                            key: "input_tokens".into(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::IntValue(42)),
                            }),
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let binary = decode("logs", "application/x-protobuf", &request.encode_to_vec()).unwrap();
        let mut json_input = serde_json::to_value(&request).unwrap();
        json_input["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"][0]["value"]
            ["intValue"] = json!("42");
        let json = decode(
            "logs",
            "Application/JSON; charset=utf-8",
            &serde_json::to_vec(&json_input).unwrap(),
        )
        .unwrap();
        assert_eq!(
            stable(normalize("codex-otel", "logs", &binary).unwrap()),
            stable(normalize("codex-otel", "logs", &json).unwrap())
        );
        assert_eq!(
            normalize("codex-otel", "logs", &json).unwrap()[0]["attributes"]["input_tokens"],
            42
        );
    }

    #[test]
    fn protobuf_metrics_and_traces_equal_sparse_json() {
        let metrics = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![ScopeMetrics {
                    metrics: vec![Metric {
                        name: "codex.tool.call".into(),
                        data: Some(metric::Data::Gauge(Gauge {
                            data_points: vec![NumberDataPoint {
                                value: Some(number_data_point::Value::AsInt(7)),
                                ..Default::default()
                            }],
                        })),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let binary = decode(
            "metrics",
            "application/x-protobuf",
            &metrics.encode_to_vec(),
        )
        .unwrap();
        let json = payload(
            "metrics",
            vec![json!({"name": "codex.tool.call", "gauge": {"dataPoints": [{"asInt": "7"}]}})],
        );
        assert_eq!(
            stable(normalize("codex-otel", "metrics", &binary).unwrap()),
            stable(normalize("codex-otel", "metrics", &json).unwrap())
        );
        let traces = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        name: "gen_ai.chat".into(),
                        trace_id: vec![17; 16],
                        span_id: vec![34; 8],
                        start_time_unix_nano: 1,
                        end_time_unix_nano: 2,
                        status: Some(Status {
                            code: 2,
                            message: "PRIVATE_ERROR".into(),
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let binary = decode("traces", "application/x-protobuf", &traces.encode_to_vec()).unwrap();
        let json = payload(
            "traces",
            vec![
                json!({"name": "gen_ai.chat", "traceId": "11111111111111111111111111111111", "spanId": "2222222222222222", "startTimeUnixNano": "1", "endTimeUnixNano": "2", "status": {"code": 2}}),
            ],
        );
        let events = normalize("copilot-otel", "traces", &binary).unwrap();
        assert_eq!(
            stable(events.clone()),
            stable(normalize("copilot-otel", "traces", &json).unwrap())
        );
        assert!(!events[0].to_string().contains("PRIVATE_ERROR"));
    }

    #[test]
    fn protobuf_roundtrip_all_metric_kinds_and_zero_defaults() {
        // Serde constructs the generated message from numeric JSON, then prost
        // supplies the real wire encoding. Compare to sparse OTLP JSON inputs.
        for (kind, point) in [
            ("gauge", json!({"asDouble": 7})),
            ("sum", json!({"asInt": 7})),
            (
                "histogram",
                json!({"count": 2, "sum": 12, "bucketCounts": [2], "explicitBounds": []}),
            ),
            (
                "summary",
                json!({"count": 2, "sum": 12, "quantileValues": [{"quantile": 0.5, "value": 6}]}),
            ),
            (
                "exponentialHistogram",
                json!({"count": 2, "sum": 12, "positive": {"bucketCounts": [2]}}),
            ),
        ] {
            let metric_json = json!({"name": "synthetic.metric", kind: {"dataPoints": [point]}});
            let mut full = metric_json.clone();
            // These generated point types lack serde(default), unlike Gauge.
            // Construct their complete wire shape before protobuf encoding.
            let defaults = match kind {
                "summary" => serde_json::to_value(
                    opentelemetry_proto::tonic::metrics::v1::SummaryDataPoint::default(),
                )
                .unwrap(),
                "exponentialHistogram" => serde_json::to_value(
                    opentelemetry_proto::tonic::metrics::v1::ExponentialHistogramDataPoint::default(
                    ),
                )
                .unwrap(),
                _ => json!({}),
            };
            let mut full_point = defaults;
            full_point
                .as_object_mut()
                .unwrap()
                .extend(point.as_object().unwrap().clone());
            if kind == "exponentialHistogram" {
                full_point["positive"]["offset"] = json!(0);
            }
            full[kind]["dataPoints"][0] = full_point;
            let metric: Metric = serde_json::from_value(full).unwrap();
            assert!(
                metric.data.is_some(),
                "generated metric must have data: {kind}"
            );
            let request = ExportMetricsServiceRequest {
                resource_metrics: vec![ResourceMetrics {
                    scope_metrics: vec![ScopeMetrics {
                        metrics: vec![metric],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
            };
            let decoded = decode(
                "metrics",
                "application/x-protobuf",
                &request.encode_to_vec(),
            )
            .unwrap();
            let sparse = payload("metrics", vec![metric_json]);
            assert_eq!(
                stable(normalize("codex-otel", "metrics", &decoded).unwrap()),
                stable(normalize("codex-otel", "metrics", &sparse).unwrap()),
                "{kind}"
            );
        }
    }

    #[test]
    fn malformed_metrics_and_non_numeric_values_do_not_escape() {
        for record in [
            json!({"gauge": []}),
            json!({"gauge": {"dataPoints": {}}}),
            json!({"gauge": {"dataPoints": [null]}}),
            json!({"gauge": {}, "sum": {}}),
            json!({"gauge": {"dataPoints": [{"asInt": 1, "asDouble": 2}]}}),
            json!({"histogram": {"dataPoints": [{"bucketCounts": ["PRIVATE"]}]}}),
            json!({"summary": {"dataPoints": [{"quantileValues": [false]}]}}),
            json!({"exponentialHistogram": {"dataPoints": [{"positive": []}]}}),
        ] {
            assert!(normalize("codex-otel", "metrics", &payload("metrics", vec![record])).is_err());
        }
        let input = payload(
            "metrics",
            vec![json!({"gauge": {"dataPoints": [{"asDouble": "PRIVATE"}]}})],
        );
        let events = normalize("codex-otel", "metrics", &input).unwrap();
        assert!(events[0]["metric"].get("value").is_none());
        assert!(!events[0].to_string().contains("PRIVATE"));
    }

    #[test]
    fn sensitive_and_unknown_fields_never_survive() {
        for signal in ["logs", "metrics", "traces"] {
            let attrs = json!([
                {"key": "model", "value": {"stringValue": "synthetic-model"}},
                {"key": "prompt", "value": {"stringValue": "PRIVATE_PROMPT"}},
                {"key": "tool_input", "value": {"stringValue": "PRIVATE_ARGS"}},
                {"key": "tool_result", "value": {"stringValue": "PRIVATE_OUTPUT"}},
                {"key": "user.email", "value": {"stringValue": "PRIVATE_EMAIL"}},
                {"key": "future_metadata", "value": {"stringValue": "PRIVATE_UNKNOWN"}},
                {"key": "session.id", "value": {"stringValue": "sk-proj-PRIVATE_KEY"}}
            ]);
            let mut record = json!({"name": "synthetic.event", "attributes": attrs, "body": {"stringValue": "PRIVATE_BODY"},
                "tool_parameters": "PRIVATE_ARGS", "events": [{"name": "PRIVATE_EVENT"}], "links": [{"traceState": "PRIVATE_STATE"}],
                "status": {"code": 2, "message": "PRIVATE_ERROR"}, "unknown": "PRIVATE_UNKNOWN"});
            if signal == "metrics" {
                record["gauge"] = json!({"dataPoints": [{"asInt": "5", "attributes": attrs, "exemplars": [{"value": "PRIVATE_EXEMPLAR"}]}]});
            }
            let mut input = payload(signal, vec![record]);
            let (root, scope, _) = keys(signal).unwrap();
            input[root][0]["resource"] = json!({"attributes": attrs});
            input[root][0][scope][0]["scope"] =
                json!({"name": "PRIVATE_SCOPE_NAME", "attributes": attrs});
            let events = normalize("codex-otel", signal, &input).unwrap();
            assert_eq!(events[0]["attributes"]["model"], "synthetic-model");
            assert_eq!(events[0]["resource_attributes"]["model"], "synthetic-model");
            assert!(!events[0].to_string().contains("PRIVATE"));
        }
    }

    #[test]
    fn cursor_conversation_content_body_is_not_an_event_label() {
        let input = payload(
            "logs",
            vec![
                json!({"eventName": "cursor.conversation.user_message", "body": {"stringValue": "PRIVATE_PROMPT"}}),
            ],
        );
        let events = normalize("cursor-runtime", "logs", &input).unwrap();
        assert_eq!(events[0]["event_name"], "cursor.conversation.user_message");
        assert!(!events[0].to_string().contains("PRIVATE"));
        assert_eq!(
            constant_event(
                "cursor-runtime",
                &json!({"stringValue": "cloud_agent_setup_completed"})
            ),
            Some("cursor.cloud_agent.setup".into())
        );
        assert_eq!(
            constant_event(
                "cursor-runtime",
                &json!({"stringValue": "grok_bot_tool_decision"})
            ),
            Some("cursor.grok_bot.tool_decision".into())
        );
        assert!(constant_event(
            "cursor-runtime",
            &json!({"stringValue": "cloud_agent_setup_PRIVATE"})
        )
        .is_none());
        let unknown = payload(
            "logs",
            vec![json!({"body": {"stringValue": "PRIVATE_UNKNOWN"}})],
        );
        assert_eq!(
            normalize("cursor-runtime", "logs", &unknown).unwrap()[0]["event_name"],
            "otel.log"
        );
    }

    #[test]
    fn malformed_resource_scope_and_record_shapes_fail() {
        for input in [
            json!([]),
            json!({"resourceLogs": {}}),
            json!({"resourceLogs": [null]}),
            json!({"resourceLogs": [{"resource": []}]}),
            json!({"resourceLogs": [{"scopeLogs": {}}]}),
            json!({"resourceLogs": [{"scopeLogs": [false]}]}),
            json!({"resourceLogs": [{"scopeLogs": [{"scope": []}]}]}),
            json!({"resourceLogs": [{"scopeLogs": [{"logRecords": {}}]}]}),
            payload("logs", vec![json!(null)]),
            payload("logs", vec![json!({"attributes": {}})]),
            payload("logs", vec![json!({"attributes": [null]})]),
            payload(
                "logs",
                vec![json!({"attributes": [{"key": 3, "value": {}}]})],
            ),
        ] {
            assert!(normalize("codex-otel", "logs", &input).is_err(), "{input}");
        }
        assert!(normalize("codex-otel", "logs", &payload("traces", vec![])).is_err());
        assert!(normalize("unknown", "logs", &json!({})).is_err());
        assert!(normalize("codex-otel", "unknown", &json!({})).is_err());
    }

    #[test]
    fn empty_exports_and_unknown_future_fields_are_allowed() {
        for signal in ["logs", "metrics", "traces"] {
            assert!(
                normalize("codex-otel", signal, &json!({"futureField": "PRIVATE"}))
                    .unwrap()
                    .is_empty()
            );
            assert!(normalize(
                "codex-otel",
                signal,
                &decode(signal, "application/x-protobuf", &[]).unwrap()
            )
            .unwrap()
            .is_empty());
        }
    }

    #[test]
    fn invalid_transport_and_oversize_bodies_fail_without_echoing_input() {
        for (signal, mime, bytes) in [
            ("logs", "application/json", b"PRIVATE_BROKEN".as_slice()),
            ("logs", "application/x-protobuf", &[255, 255]),
            ("logs", "text/plain", b"{}"),
            ("unknown", "application/json", b"{}"),
        ] {
            let err = decode(signal, mime, bytes).unwrap_err().to_string();
            assert!(!err.contains("PRIVATE"));
        }
        assert!(decode("logs", "application/json", &vec![b' '; MAX_BYTES + 1]).is_err());
    }

    #[test]
    fn event_limit_applies_across_scopes_and_metric_points() {
        let input = json!({"resourceLogs": [{"scopeLogs": [{"logRecords": vec![json!({}); 5000]}, {"logRecords": vec![json!({}); 5001]}]}]});
        assert!(normalize("codex-otel", "logs", &input)
            .unwrap_err()
            .to_string()
            .contains("10000"));
        let input = payload(
            "metrics",
            vec![
                json!({"name": "synthetic", "gauge": {"dataPoints": vec![json!({"asInt": "1"}); 10001]}}),
            ],
        );
        assert!(normalize("codex-otel", "metrics", &input).is_err());
        let boundary = payload("logs", vec![json!({}); 10000]);
        assert_eq!(
            normalize("codex-otel", "logs", &boundary).unwrap().len(),
            10000
        );
    }

    #[test]
    fn resource_fanout_is_bounded_before_return() {
        let attrs: Vec<_> = [
            "service.name",
            "service.version",
            "model",
            "session.id",
            "conversation.id",
            "tool.name",
            "app.version",
            "environment",
            "organization.id",
            "user.id",
        ]
        .iter()
        .map(|key| json!({"key": key, "value": {"stringValue": "x".repeat(500)}}))
        .collect();
        let mut input = payload("logs", vec![json!({}); 7000]);
        input["resourceLogs"][0]["resource"] = json!({"attributes": attrs});
        assert!(serde_json::to_vec(&input).unwrap().len() < 100_000);
        assert!(normalize("codex-otel", "logs", &input)
            .unwrap_err()
            .to_string()
            .contains("32 MiB"));
    }
}
