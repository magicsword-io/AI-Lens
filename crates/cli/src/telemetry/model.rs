//! Common observation envelope and intentionally narrow metadata projection.
use serde_json::{json, Map, Value};

pub fn base(source: &str, signal: &str, event_name: &str) -> Value {
    json!({
        "schema": "agent-lens.telemetry.v1", "schema_version": 1,
        "source": source, "signal": signal,
        "event_name": text(&json!(event_name)).unwrap_or_else(|| "unknown".into()),
        "enforcement": "observe_only",
        "observed_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "observer": {"name":"agent-lens", "version":env!("CARGO_PKG_VERSION")},
    })
}

/// Scalar metadata only. This is a heuristic, not a content-redaction guarantee.
pub fn text(value: &Value) -> Option<String> {
    let s = match value {
        Value::String(s) => s.clone(),
        Value::Number(_) | Value::Bool(_) => value.to_string(),
        _ => return None,
    };
    let lower = s.to_ascii_lowercase();
    if s.is_empty()
        || s.len() > 512
        || s.chars().any(char::is_control)
        || [
            "sk-",
            "ghp_",
            "github_pat_",
            "gho_",
            "ghu_",
            "ghs_",
            "akia",
            "bearer ",
            "authorization",
            "password=",
            "password:",
            "api_key=",
            "token=",
            "-----begin",
        ]
        .iter()
        .any(|p| lower.contains(p))
    {
        return None;
    }
    Some(s)
}

pub fn copy_text(event: &mut Value, key: &str, value: Option<&Value>) {
    if let Some(s) = value.and_then(text) {
        event[key] = json!(s);
    }
}

fn allowed_attribute(key: &str) -> bool {
    matches!(
        key,
        "service.name"
            | "service.version"
            | "deployment.environment"
            | "environment"
            | "event.name"
            | "event_name"
            | "event.type"
            | "event_type"
            | "session.id"
            | "session_id"
            | "conversation.id"
            | "conversation_id"
            | "thread.id"
            | "thread_id"
            | "user.id"
            | "user_id"
            | "organization.id"
            | "model"
            | "model.name"
            | "gen_ai.request.model"
            | "gen_ai.response.model"
            | "gen_ai.system"
            | "gen_ai.operation.name"
            | "gen_ai.usage.input_tokens"
            | "gen_ai.usage.output_tokens"
            | "app.version"
            | "os.type"
            | "host.arch"
            | "tool"
            | "tool.name"
            | "tool_name"
            | "tool.id"
            | "tool_id"
            | "tool_use_id"
            | "success"
            | "status"
            | "status_code"
            | "http.response.status_code"
            | "decision"
            | "approved"
            | "approval_policy"
            | "sandbox_policy"
            | "duration_ms"
            | "duration"
            | "cost_usd"
            | "input_tokens"
            | "output_tokens"
            | "cache_read_tokens"
            | "cache_creation_tokens"
            | "token_type"
            | "type"
            | "auth_mode"
            | "originator"
            | "session_source"
            | "source"
            | "hook_name"
            | "attempt"
            | "reasoning_effort"
            | "error.type"
            | "kind"
            | "count"
            | "prompt.id"
            | "request_id"
            | "client_request_id"
            | "agent_id"
            | "event.timestamp"
            | "event.sequence"
            | "prompt_length"
            | "response_length"
            | "cursor.event.id"
            | "cursor.team.id"
            | "cursor.surface"
            | "cursor.entrypoint"
            | "cursor.project.id"
            | "cursor.user.id"
            | "cursor.user.account_id"
            | "cursor.source_event.id"
            | "cursor.request.id"
            | "cursor.conversation.id"
            | "cursor.usage_event.id"
            | "cursor.token.type"
            | "cursor.model.name"
            | "cursor.api.status"
            | "cursor.api.billable"
            | "cursor.tool.kind"
            | "cursor.tool.name"
            | "cursor.tool.status"
            | "cursor.mcp.server.name"
            | "cursor.api.request.input_tokens"
            | "cursor.api.request.output_tokens"
            | "cursor.api.request.cache_read_tokens"
            | "cursor.api.request.cache_creation_tokens"
            | "cursor.api.correction.kind"
    )
}

/// OTLP KeyValue array (or already flattened metadata object), excluding content.
pub fn attributes(input: &Value) -> Value {
    let mut out = Map::new();
    let mut add = |key: &str, value: &Value| {
        if !allowed_attribute(key) || out.len() >= 64 {
            return;
        }
        let scalar = value
            .as_object()
            .and_then(|v| {
                [
                    "stringValue",
                    "intValue",
                    "doubleValue",
                    "boolValue",
                    "string_value",
                    "int_value",
                    "double_value",
                    "bool_value",
                ]
                .iter()
                .find_map(|key| v.get(*key))
            })
            .unwrap_or(value);
        if text(scalar).is_some() {
            out.insert(key.into(), scalar.clone());
        }
    };
    match input {
        Value::Array(items) => {
            for item in items.iter().take(1024) {
                if let (Some(key), Some(value)) =
                    (item.get("key").and_then(Value::as_str), item.get("value"))
                {
                    add(key, value);
                }
            }
        }
        Value::Object(items) => {
            for (key, value) in items.iter().take(1024) {
                add(key, value);
            }
        }
        _ => {}
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_expected_metadata_survives() {
        let input = json!([
            {"key":"model","value":{"stringValue":"test-model"}},
            {"key":"success","value":{"boolValue":true}},
            {"key":"prompt","value":{"stringValue":"PRIVATE_PROMPT"}},
            {"key":"tool_parameters","value":{"stringValue":"PRIVATE_ARGS"}},
            {"key":"session.id","value":{"stringValue":"sk-proj-fixture-not-a-key"}}
        ]);
        assert_eq!(
            attributes(&input),
            json!({"model":"test-model","success":true})
        );
        assert_eq!(
            attributes(&json!({"input_tokens":42,"raw":"PRIVATE"})),
            json!({"input_tokens":42})
        );
    }
    #[test]
    fn bounds_and_credentials_are_not_echoed() {
        for s in [
            "Bearer private",
            "sk-ant-fixture",
            "ghp_fixture",
            "password=private",
            "line\nbreak",
        ] {
            assert!(text(&json!(s)).is_none());
        }
        assert!(text(&json!("x".repeat(513))).is_none());
        assert!(text(&json!({"raw":"private"})).is_none());
        assert_eq!(
            base("codex-otel", "logs", "event")["enforcement"],
            "observe_only"
        );
    }
}
