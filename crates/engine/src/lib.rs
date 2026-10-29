//! Pure normalization, policy evaluation, and privacy filtering for Agent Lens.

pub mod adapters;
mod ffi;
mod policy;
mod redact;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, Write};

const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    agent: String,
    event: Option<String>,
    payload: Value,
    rules_yaml: String,
    #[serde(default)]
    capture_content: bool,
}

/// Validate policy syntax and resource limits, returning the parsed rule IDs.
pub fn validate_rules(rules_yaml: &str) -> Result<Vec<String>> {
    policy::Policy::parse(rules_yaml).map(|policy| policy.rule_ids())
}

/// Process a vendor hook without filesystem, clock, network, or environment access.
/// The host adds timestamps and persists the resulting event.
pub fn process(request: &Value) -> Result<Value> {
    // Inspect before cloning/deserializing to bound nesting, strings, and work.
    check_json_bounds(request, MAX_PAYLOAD_BYTES + policy::MAX_POLICY_BYTES + 4096)?;
    let request: Request = serde_json::from_value(request.clone())
        .map_err(|_| anyhow::anyhow!("invalid engine request"))?;
    if !request.payload.is_object() {
        bail!("payload must be a JSON object");
    }
    check_json_bounds(&request.payload, MAX_PAYLOAD_BYTES)?;
    let policy = policy::Policy::parse(&request.rules_yaml)?;
    let normalized =
        adapters::normalize(&request.agent, request.event.as_deref(), &request.payload)
            .map_err(|_| anyhow::anyhow!("unsupported agent or invalid hook payload"))?;
    check_json_bounds(&normalized.input, MAX_PAYLOAD_BYTES)?;
    // Copilot may encode native arguments as JSON text. Policy retains the
    // original callback; privacy must inspect the equivalent structured values
    // so sensitive-key filtering is identical for both documented wire forms.
    let mut privacy_input = None;
    if request.agent == "copilot" {
        if let Some(arguments) = adapters::copilot_tool_args(&normalized.input)? {
            let mut input = normalized.input.clone();
            input["toolArgs"] = arguments;
            privacy_input = Some(input);
        }
    }
    let privacy_input = privacy_input.as_ref().unwrap_or(&normalized.input);
    let matches = policy.evaluate(&request.agent, &normalized)?;
    let enforceable = normalized.enforceable && normalized.phase == "pre";
    let blocked = matches.block && enforceable;
    let decision = if blocked {
        "block"
    } else if matches.block {
        "would_block"
    } else {
        "allow"
    };
    let phase = match normalized.phase.as_str() {
        "pre" | "post" | "lifecycle" => normalized.phase.as_str(),
        _ => "unknown",
    };
    let mut event = json!({
        "schema_version": 1,
        "agent": request.agent,
        "hook_event": safe_metadata(&normalized.hook_event, privacy_input).unwrap_or("unknown"),
        "phase": phase,
        "decision": decision,
        "matched_rules": matches.ids,
        "enforcement": if enforceable { "supported" } else { "observe_only" },
    });
    if let Some(session_id) = normalized
        .session_id
        .as_deref()
        .and_then(|id| safe_metadata(id, privacy_input))
    {
        event["session_id"] = json!(session_id);
    }
    if let Some(tool_name) = normalized
        .tool_name
        .as_deref()
        .and_then(|name| safe_metadata(name, privacy_input))
    {
        event["tool_name"] = json!(tool_name);
    }
    for field in [
        "agent_id",
        "parent_agent_id",
        "turn_id",
        "tool_use_id",
        "tool_call_id",
        "task_id",
    ] {
        if field == "task_id" && request.agent != "hermes" {
            continue;
        }
        // Preserve native names and values; never derive parent/session identity.
        let native = request.payload.get(field).or_else(|| {
            (request.agent == "hermes" && matches!(field, "task_id" | "tool_call_id" | "turn_id"))
                .then(|| {
                    request
                        .payload
                        .get("extra")
                        .and_then(|extra| extra.get(field))
                })
                .flatten()
        });
        if let Some(value) = native
            .and_then(Value::as_str)
            .and_then(|value| safe_metadata(value, privacy_input))
        {
            event[field] = json!(value);
        }
    }
    // AL-006: raw input never enters metadata; content requires explicit opt-in.
    if request.capture_content {
        let mut content = redact::redact(privacy_input);
        if request.agent == "copilot" && normalized.input["toolArgs"].is_string() {
            // Preserve the native field's type, after structured sanitization.
            content["toolArgs"] = json!(serde_json::to_string(&content["toolArgs"])?);
        }
        event["content"] = content;
    }
    // Static text deliberately excludes rule descriptions and matched input.
    let response = adapters::response(
        &request.agent,
        &normalized.hook_event,
        blocked,
        "Blocked by Agent Lens policy",
    );
    Ok(json!({"event": event, "response": response, "blocked": blocked}))
}

fn safe_identifier(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
        && !redact::contains_credential(value))
    .then_some(value)
}

fn safe_metadata<'a>(value: &'a str, input: &Value) -> Option<&'a str> {
    safe_identifier(value).filter(|value| !redact::references_sensitive_value(value, input))
}

fn check_json_bounds(value: &Value, max_bytes: usize) -> Result<()> {
    let mut pending = vec![(value, 0)];
    let mut nodes = 0;
    let mut string_bytes = 0usize;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > MAX_DEPTH {
            bail!("JSON structure exceeds engine limits");
        }
        match value {
            Value::Object(object) => {
                string_bytes = string_bytes.saturating_add(object.keys().map(String::len).sum());
                pending.extend(object.values().map(|v| (v, depth + 1)));
            }
            Value::Array(array) => pending.extend(array.iter().map(|v| (v, depth + 1))),
            Value::String(string) => string_bytes = string_bytes.saturating_add(string.len()),
            _ => {}
        }
        if string_bytes > max_bytes || pending.len() > MAX_NODES {
            bail!("JSON input exceeds engine limits");
        }
    }
    struct BoundedWriter(usize);
    impl Write for BoundedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(bytes.len())
                .ok_or_else(|| io::Error::other("JSON input exceeds engine limits"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(BoundedWriter(max_bytes), value)
        .context("JSON input exceeds engine limits")
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: &str = "version: 1\nrules:\n  - id: deny-private\n    tool_pattern: '^Write$'\n    content_pattern: 'private'\n    action: block\n";

    fn request(event: &str, input: Value) -> Value {
        json!({
            "agent": "claude", "event": event,
            "payload": {"hook_event_name": event, "session_id": "session-123", "tool_name": "Write", "tool_input": input},
            "rules_yaml": BLOCK, "capture_content": false,
        })
    }

    #[test]
    fn copilot_encoded_args_have_object_equivalent_structured_privacy() {
        for encoded in [false, true] {
            for capture in [false, true] {
                let raw = r#"{"path":"/public/file","api_key":"SYNTHETIC_META_SECRET","\u0070rivate_key":"SYNTHETIC_CAPTURE_SECRET","auth":{"nested":"SYNTHETIC_AUTH_SECRET"},"ordinary":"VISIBLE_CONTROL"}"#;
                let args: Value = serde_json::from_str(raw).unwrap();
                let result = process(&json!({
                    "agent":"copilot", "event":"preToolUse", "rules_yaml":"version: 1\nrules: []",
                    "capture_content":capture,
                    "payload":{"sessionId":"session-SYNTHETIC_META_SECRET", "toolName":"view", "toolArgs":if encoded { json!(raw) } else { args }},
                })).unwrap();
                assert!(result["event"].get("session_id").is_none());
                let text = result.to_string();
                for sensitive in ["SYNTHETIC_CAPTURE_SECRET", "SYNTHETIC_AUTH_SECRET"] {
                    assert!(
                        !text.contains(sensitive),
                        "encoded={encoded}, capture={capture}"
                    );
                }
                assert_eq!(text.contains("VISIBLE_CONTROL"), capture);
                if capture {
                    assert_eq!(result["event"]["content"]["toolArgs"].is_string(), encoded);
                    assert!(!result["event"]["content"]["toolArgs"]
                        .to_string()
                        .contains("SYNTHETIC_META_SECRET"));
                }
            }
        }
    }

    #[test]
    fn validation_inventory_uses_yaml_structure_including_quoted_ids() {
        for yaml in [
            "version: 1\nrules:\n- id: \"quoted-rule\"\n  agents: [claude]\n  action: audit\n",
            "version: 1\nrules: [{id: 'quoted-rule', agents: [claude], action: audit}]",
        ] {
            assert_eq!(validate_rules(yaml).unwrap(), vec!["quoted-rule"]);
        }
    }

    #[test]
    fn al005_pre_block_and_positive_control() {
        let denied = process(&request("PreToolUse", json!({"file_path": "private.txt"}))).unwrap();
        assert_eq!(denied["blocked"], true);
        assert_eq!(denied["event"]["decision"], "block");
        assert_eq!(denied["event"]["matched_rules"], json!(["deny-private"]));
        let allowed = process(&request("PreToolUse", json!({"file_path": "public.txt"}))).unwrap();
        assert_eq!(allowed["blocked"], false);
        assert_eq!(allowed["event"]["decision"], "allow");
    }

    #[test]
    fn policy_uses_original_tool_names_before_metadata_filtering() {
        for name in [
            "custom/tool".to_string(),
            "custom tool".to_string(),
            "x".repeat(129),
        ] {
            let mut input = request("PreToolUse", json!({}));
            input["payload"]["tool_name"] = json!(name);
            input["rules_yaml"] = json!(format!(
                "version: 1\nrules: [{{id: names, tool_pattern: '^{}$', action: block}}]",
                name
            ));
            let denied = process(&input).unwrap();
            assert_eq!(denied["blocked"], true);
            assert!(denied["event"].get("tool_name").is_none());
            input["payload"]["tool_name"] = json!("ordinary_tool");
            assert_eq!(process(&input).unwrap()["blocked"], false);
        }
    }

    #[test]
    fn al005_post_match_is_observation_only() {
        let result = process(&request("PostToolUse", json!({"content": "private"}))).unwrap();
        assert_eq!(result["blocked"], false);
        assert_eq!(result["event"]["decision"], "would_block");
        assert_eq!(result["event"]["enforcement"], "observe_only");
    }

    #[test]
    fn al006_default_omits_content_and_untrusted_metadata() {
        let mut input = request("PreToolUse", json!({"prompt": "private SECRET_CONTENT"}));
        input["payload"]["arbitrary_metadata"] = json!("SECRET_CONTENT");
        input["payload"]["session_id"] = json!("Bearer SECRET_CONTENT");
        input["payload"]["tool_name"] = json!("Write\nSECRET_CONTENT");
        let result = process(&input).unwrap();
        assert!(result["event"].get("content").is_none());
        assert!(result["event"].get("session_id").is_none());
        assert!(result["event"].get("tool_name").is_none());
        assert!(!result.to_string().contains("SECRET_CONTENT"));
    }

    #[test]
    fn al006_matching_precedes_redaction() {
        let mut input = request("PreToolUse", json!({"password": "private"}));
        input["capture_content"] = json!(true);
        let result = process(&input).unwrap();
        assert_eq!(result["blocked"], true);
        assert_eq!(
            result["event"]["content"]["tool_input"]["password"],
            "[REDACTED]"
        );
        assert!(!result.to_string().contains("\"private\""));
    }

    #[test]
    fn invalid_requests_and_resource_exhaustion_are_errors() {
        assert!(process(&json!({})).is_err());
        let mut input = request("PreToolUse", json!({"body": "x".repeat(MAX_PAYLOAD_BYTES)}));
        assert!(process(&input).is_err());
        input["payload"] = json!([]);
        assert!(process(&input).is_err());
        let mut nested = Value::Null;
        for _ in 0..MAX_DEPTH + 1 {
            nested = json!([nested]);
        }
        assert!(process(&request("PreToolUse", json!({"nested": nested}))).is_err());
    }

    #[test]
    fn metadata_credentials_are_omitted_even_when_identifier_shaped() {
        assert!(safe_identifier("sk-proj-abcdefghijklmno").is_none());
        assert!(safe_identifier(&"x".repeat(129)).is_none());
        assert_eq!(
            safe_identifier("mcp__tools__read"),
            Some("mcp__tools__read")
        );
    }

    #[test]
    fn al006_credential_metadata_is_filtered_in_real_process_path() {
        for credential in [
            "sk-proj-syntheticfixture123456",
            "ghp_syntheticfixture1234567890",
            "password:syntheticfixture",
            "AKIAABCDEFGHIJKLMNOP",
        ] {
            let mut input = request("PreToolUse", json!({"value": "public"}));
            input["payload"]["session_id"] = json!(credential);
            input["payload"]["tool_name"] = json!(credential);
            let output = process(&input).unwrap();
            assert!(output["event"].get("session_id").is_none());
            assert!(output["event"].get("tool_name").is_none());
            assert!(!output.to_string().contains(credential));
        }
    }

    #[test]
    fn al006_sensitive_key_values_cannot_be_repeated_in_metadata() {
        let mut input = request("PreToolUse", json!({"api_key": "syntheticfixture"}));
        input["payload"]["session_id"] = json!("session-syntheticfixture");
        input["payload"]["tool_name"] = json!("syntheticfixture");
        input["payload"]["agent_id"] = json!("agent-syntheticfixture");
        let output = process(&input).unwrap();
        assert!(output["event"].get("session_id").is_none());
        assert!(output["event"].get("tool_name").is_none());
        assert!(!output.to_string().contains("syntheticfixture"));
    }

    #[test]
    fn native_correlation_ids_are_optional_filtered_and_never_invented() {
        let fields = [
            "agent_id",
            "parent_agent_id",
            "turn_id",
            "tool_use_id",
            "tool_call_id",
        ];
        let mut input = request("SubagentStart", json!({}));
        for field in fields {
            input["payload"][field] = json!(format!("native-{field}-123"));
        }
        input["payload"]["cwd"] = json!("/private/project");
        input["payload"]["pid"] = json!(12345);
        let output = process(&input).unwrap();
        for field in fields {
            assert_eq!(output["event"][field], input["payload"][field]);
        }
        assert!(output["event"].get("cwd").is_none());
        assert!(output["event"].get("pid").is_none());
        let absent = process(&request("SubagentStart", json!({}))).unwrap();
        for field in fields {
            assert!(absent["event"].get(field).is_none());
        }
        input["payload"]["agent_id"] = json!("sk-proj-syntheticfixture123456");
        input["payload"]["parent_agent_id"] = json!("/private/path");
        let unsafe_ids = process(&input).unwrap();
        assert!(unsafe_ids["event"].get("agent_id").is_none());
        assert!(unsafe_ids["event"].get("parent_agent_id").is_none());

        let hermes = process(&json!({
            "agent": "hermes", "event": "on_session_start",
            "payload": {"extra": {"task_id": "task-123", "tool_call_id": "call-123", "turn_id": "turn-123"}},
            "rules_yaml": "version: 1\nrules: []",
        })).unwrap();
        assert_eq!(hermes["event"]["task_id"], "task-123");
        assert_eq!(hermes["event"]["tool_call_id"], "call-123");
        assert_eq!(hermes["event"]["turn_id"], "turn-123");
        assert!(hermes["event"].get("session_id").is_none());
        assert!(hermes["event"].get("agent_id").is_none());
    }

    #[test]
    fn al005_lifecycle_and_unsupported_pre_events_never_block() {
        for event in ["SessionStart", "UserPromptSubmit", "Stop"] {
            let mut input = request(event, json!({"value": "private"}));
            input["rules_yaml"] =
                json!("version: 1\nrules: [{id: observe, agents: [claude], action: block}]");
            let output = process(&input).unwrap();
            assert_eq!(output["blocked"], false);
            assert_eq!(output["event"]["decision"], "would_block");
            assert_eq!(output["event"]["enforcement"], "observe_only");
            assert_eq!(output["response"], json!({}));
        }
    }

    #[test]
    fn al005_audit_matches_remain_allowed() {
        let mut input = request("PreToolUse", json!({"value": "private"}));
        input["rules_yaml"] =
            json!("version: 1\nrules: [{id: observe, agents: [claude], action: audit}]");
        let output = process(&input).unwrap();
        assert_eq!(output["blocked"], false);
        assert_eq!(output["event"]["decision"], "allow");
        assert_eq!(output["event"]["matched_rules"], json!(["observe"]));
        assert_eq!(output["response"], json!({}));
    }

    #[test]
    fn gemini_rules_block_only_before_tool_and_redact_output() {
        for (name, expected) in [
            ("BeforeTool", "block"),
            ("AfterTool", "would_block"),
            ("BeforeAgent", "would_block"),
            ("AfterAgent", "would_block"),
        ] {
            let input = json!({"agent":"gemini","event":name,
                "payload":{"session_id":"gemini-session", "tool_name":"replace", "tool_input":{"file_path":"/work/.env"},
                    "tool_response":{"api_key":"SYNTHETIC_PRIVATE_VALUE"}},
                "rules_yaml":"version: 1\nrules: [{id: gemini-env, agents: [gemini], path_pattern: '\\.env$', action: block}]",
                "capture_content":true});
            let output = process(&input).unwrap();
            assert_eq!(output["event"]["agent"], "gemini");
            assert_eq!(output["event"]["session_id"], "gemini-session");
            assert_eq!(output["event"]["decision"], expected);
            assert_eq!(output["blocked"], name == "BeforeTool");
            if name != "BeforeTool" {
                assert_eq!(output["response"], json!({}));
            }
            assert!(!output.to_string().contains("SYNTHETIC_PRIVATE_VALUE"));
        }
    }

    #[test]
    fn escaped_payload_and_node_counts_are_bounded() {
        let quoted = json!({"value": "\"".repeat(MAX_PAYLOAD_BYTES / 2)});
        assert!(check_json_bounds(&quoted, MAX_PAYLOAD_BYTES).is_err());
        let nodes = json!(vec![Value::Null; MAX_NODES]);
        assert!(check_json_bounds(&nodes, MAX_PAYLOAD_BYTES).is_err());
        assert!(check_json_bounds(&json!({"safe": "fixture"}), MAX_PAYLOAD_BYTES).is_ok());
    }
}
