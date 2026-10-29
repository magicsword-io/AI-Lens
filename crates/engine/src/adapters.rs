//! Vendor wire protocols. Registration is an explicit, reviewed event allowlist.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

mod native;

pub use native::config_argv;
pub(crate) use native::copilot_tool_args;

#[derive(Debug, Clone)]
pub struct Normalized {
    pub hook_event: String,
    pub phase: String,
    pub enforceable: bool,
    pub session_id: Option<String>,
    pub tool_name: Option<String>,
    /// Original payload, including prompts and post-tool output, for policy/redaction.
    pub input: Value,
}

#[derive(Debug, Clone, Copy)]
pub struct EventSpec {
    pub name: &'static str,
    pub phase: &'static str,
    pub enforceable: bool,
}

const fn event(name: &'static str, phase: &'static str, enforceable: bool) -> EventSpec {
    EventSpec {
        name,
        phase,
        enforceable,
    }
}

// Do not subscribe to WorktreeCreate/Remove: they replace native operations.
// Model-switch and content-transform hooks are deliberately outside v0.1.
const CLAUDE: &[EventSpec] = &[
    event("SessionStart", "lifecycle", false),
    event("Setup", "lifecycle", false),
    event("InstructionsLoaded", "lifecycle", false),
    event("UserPromptSubmit", "pre", false),
    event("PreToolUse", "pre", true),
    event("PermissionRequest", "pre", true),
    event("PostToolUse", "post", false),
    event("PostToolUseFailure", "post", false),
    event("PostToolBatch", "post", false),
    event("PermissionDenied", "post", false),
    event("Notification", "lifecycle", false),
    event("SubagentStart", "lifecycle", false),
    event("SubagentStop", "lifecycle", false),
    event("TaskCreated", "lifecycle", false),
    event("TaskCompleted", "lifecycle", false),
    event("Stop", "lifecycle", false),
    event("StopFailure", "lifecycle", false),
    event("TeammateIdle", "lifecycle", false),
    event("ConfigChange", "lifecycle", false),
    event("CwdChanged", "lifecycle", false),
    event("DirectoryAdded", "lifecycle", false),
    event("FileChanged", "lifecycle", false),
    event("PreCompact", "pre", false),
    event("PostCompact", "post", false),
    event("SessionEnd", "lifecycle", false),
    event("Elicitation", "pre", false),
    event("ElicitationResult", "post", false),
];

// Cowork documents hooks-only plugins using the Claude command-hook wire format.
// Keep a small separate registry until actual Desktop lifecycle delivery is measured.
const COWORK: &[EventSpec] = &[
    event("SessionStart", "lifecycle", false),
    event("PreToolUse", "pre", true),
    event("PostToolUse", "post", false),
    event("PostToolUseFailure", "post", false),
    event("SessionEnd", "lifecycle", false),
];

const CODEX: &[EventSpec] = &[
    event("SessionStart", "lifecycle", false),
    event("SessionEnd", "lifecycle", false),
    event("SubagentStart", "lifecycle", false),
    event("SubagentStop", "lifecycle", false),
    event("PreToolUse", "pre", true),
    event("PermissionRequest", "pre", true),
    event("PostToolUse", "post", false),
    event("PreCompact", "pre", false),
    event("PostCompact", "post", false),
    event("UserPromptSubmit", "pre", false),
    event("Stop", "lifecycle", false),
    event("Interrupt", "lifecycle", false),
];

// Native shell-hook events; not the asynchronous gateway HOOK.yaml surface.
const HERMES: &[EventSpec] = &[
    event("pre_tool_call", "pre", true),
    event("post_tool_call", "post", false),
    event("pre_llm_call", "pre", false),
    event("post_llm_call", "post", false),
    event("pre_api_request", "pre", false),
    event("post_api_request", "post", false),
    event("api_request_error", "post", false),
    event("pre_auxiliary_call", "pre", false),
    event("post_auxiliary_call", "post", false),
    event("on_session_start", "lifecycle", false),
    event("on_session_end", "lifecycle", false),
    event("on_session_finalize", "lifecycle", false),
    event("on_session_reset", "lifecycle", false),
    event("on_session_delete", "lifecycle", false),
    event("subagent_start", "lifecycle", false),
    event("subagent_stop", "lifecycle", false),
    event("post_compaction", "post", false),
    event("agent_loop_stopped", "lifecycle", false),
    event("pre_approval_request", "pre", false),
    event("post_approval_response", "post", false),
    event("on_human_input_request", "pre", false),
    event("on_human_input_resolved", "post", false),
];

// Gemini CLI command hooks. Model hooks are deliberately excluded: AfterModel
// fires per streaming chunk. Only BeforeTool is an enforcement surface here.
const GEMINI: &[EventSpec] = &[
    event("SessionStart", "lifecycle", false),
    event("BeforeAgent", "pre", false),
    event("BeforeToolSelection", "pre", false),
    event("BeforeTool", "pre", true),
    event("AfterTool", "post", false),
    event("AfterAgent", "post", false),
    event("Notification", "lifecycle", false),
    event("PreCompress", "pre", false),
    event("SessionEnd", "lifecycle", false),
];

/// The same registry drives parsing, configuration, and coverage tests.
pub fn events(agent: &str) -> Result<&'static [EventSpec]> {
    match agent {
        "claude" => Ok(CLAUDE),
        "cowork" => Ok(COWORK),
        "codex" => Ok(CODEX),
        "hermes" => Ok(HERMES),
        "gemini" => Ok(GEMINI),
        "cursor" | "copilot" => native::events(agent),
        _ => bail!("unsupported agent"),
    }
}

pub fn normalize(agent: &str, explicit_event: Option<&str>, payload: &Value) -> Result<Normalized> {
    if matches!(agent, "cursor" | "copilot") {
        return native::normalize(agent, explicit_event, payload);
    }
    let registry = events(agent)?;
    let object = payload
        .as_object()
        .context("payload must be a JSON object")?;
    let native_event = match object.get("hook_event_name") {
        Some(value) => Some(value.as_str().context("hook_event_name must be a string")?),
        None => None,
    };
    if let (Some(explicit), Some(native)) = (explicit_event, native_event) {
        if explicit != native {
            bail!("explicit event does not match native hook_event_name");
        }
    }
    let name = explicit_event
        .or(native_event)
        .context("missing hook event")?;
    let spec = registry
        .iter()
        .find(|e| e.name == name)
        .context("unregistered hook event")?;
    // Policy sees the original bounded name; privacy filtering belongs at output.
    let tool_name = payload
        .get("tool_name")
        .and_then(Value::as_str)
        .map(str::to_owned);
    // A malformed policy-bearing tool call must not silently become an empty input.
    if spec.enforceable {
        if !payload.get("tool_name").is_some_and(Value::is_string) {
            bail!("pre-tool event requires tool_name");
        }
        let tool_input = payload
            .get("tool_input")
            .or_else(|| (agent == "hermes").then(|| payload.get("args")).flatten());
        if tool_input.is_none_or(Value::is_null) {
            bail!("pre-tool event requires tool_input");
        }
        if agent == "gemini" && !tool_input.is_some_and(Value::is_object) {
            bail!("Gemini BeforeTool requires object tool_input");
        }
    }
    if agent == "cowork"
        && spec.enforceable
        && (!tool_name
            .as_deref()
            .is_some_and(|name| !name.trim().is_empty())
            || !payload.get("tool_input").is_some_and(Value::is_object))
    {
        bail!("Cowork PreToolUse requires a nonempty tool name and object tool_input");
    }
    Ok(Normalized {
        hook_event: name.to_owned(),
        phase: spec.phase.to_owned(),
        enforceable: spec.enforceable,
        session_id: optional_identifier(payload.get("session_id")),
        tool_name,
        input: payload.clone(),
    })
}

fn optional_identifier(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        })
        .map(str::to_owned)
}

/// Do not override native approval. Cursor's permission hooks require an explicit
/// continuation object; other supported hooks use empty JSON for no decision.
pub fn response(agent: &str, event: &str, blocked: bool, reason: &str) -> Value {
    if matches!(agent, "cursor" | "copilot") {
        return native::response(agent, event, blocked, reason);
    }
    if !blocked {
        return json!({});
    }
    // Hermes ignores an empty block message. Keep the native denial valid.
    let reason = if reason.trim().is_empty() {
        "Blocked by Agent Lens policy"
    } else {
        reason
    };
    match (agent, event) {
        ("claude" | "codex" | "cowork", "PreToolUse") => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }),
        ("claude" | "codex", "PermissionRequest") => json!({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": "deny", "message": reason},
            }
        }),
        ("hermes", "pre_tool_call") => json!({"action": "block", "message": reason}),
        ("gemini", "BeforeTool") => json!({"decision": "deny", "reason": reason}),
        // A completed tool cannot be undone; Stop's block means continue the loop.
        _ => json!({}),
    }
}

/// Render a native snippet for manual review/merge. Does not register any hooks.
pub fn config(agent: &str, command: &str) -> Result<Value> {
    let registry = events(agent)?;
    if matches!(agent, "copilot" | "cowork") {
        bail!("direct-exec agent requires config_argv with executable and argument array");
    }
    if command.trim().is_empty() || command.chars().any(char::is_control) {
        bail!("hook command must be nonempty and contain no control characters");
    }
    if agent == "hermes" && command.trim_start().starts_with('&') {
        bail!("Hermes requires an argv command, without PowerShell's call operator");
    }
    if agent == "cursor" {
        return native::cursor_config(command);
    }
    let mut hooks = Map::new();
    for spec in registry {
        let command = format!("{command} --event {}", spec.name);
        let handler = if agent == "hermes" {
            let mut handler = json!({"command": command, "timeout": 10});
            if spec.enforceable {
                handler["fail_closed"] = json!(true);
            }
            json!([handler])
        } else {
            let timeout = if agent == "gemini" {
                // Gemini uses milliseconds; Claude/Codex use seconds.
                10_000
            } else if agent == "codex" && matches!(spec.name, "SessionEnd" | "Interrupt") {
                3
            } else {
                10
            };
            let mut handler = json!({"type": "command", "command": command, "timeout": timeout});
            if agent == "gemini" {
                handler["name"] = json!("agent-lens");
            }
            if agent == "claude" {
                // Claude otherwise defaults to Git Bash on Windows when present.
                handler["shell"] = json!(if command.trim_start().starts_with('&') {
                    "powershell"
                } else {
                    "bash"
                });
            }
            json!([{"hooks": [handler]}])
        };
        hooks.insert(spec.name.to_owned(), handler);
    }
    Ok(json!({"hooks": hooks}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn cowork_pretool_malformed_arguments_and_empty_names_are_rejected() {
        for input in [
            json!("{\"path\":\"/private/file\"}"),
            json!([]),
            json!(false),
            json!(null),
        ] {
            assert!(normalize(
                "cowork",
                Some("PreToolUse"),
                &json!({"tool_name":"Read", "tool_input":input})
            )
            .is_err());
        }
        for name in ["", " ", "\t"] {
            assert!(normalize(
                "cowork",
                Some("PreToolUse"),
                &json!({"tool_name":name, "tool_input":{}})
            )
            .is_err());
        }
        assert!(normalize(
            "cowork",
            Some("PreToolUse"),
            &json!({"tool_name":"Read", "tool_input":{"path":"/public/file"}})
        )
        .is_ok());
    }

    #[test]
    fn cowork_plugin_contract_is_small_explicit_and_uses_direct_exec() {
        let expected = [
            (
                "SessionStart",
                include_str!("../../../examples/events/cowork-session-start.json"),
            ),
            (
                "PreToolUse",
                include_str!("../../../examples/events/cowork-pre-tool.json"),
            ),
            (
                "PostToolUse",
                include_str!("../../../examples/events/cowork-post-tool.json"),
            ),
            (
                "PostToolUseFailure",
                include_str!("../../../examples/events/cowork-tool-failure.json"),
            ),
            (
                "SessionEnd",
                include_str!("../../../examples/events/cowork-session-end.json"),
            ),
        ];
        let names: Vec<_> = events("cowork").unwrap().iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            expected.iter().map(|(name, _)| *name).collect::<Vec<_>>()
        );
        let args = vec![
            "--state".into(),
            "/tmp/state with ' quote".into(),
            "hook".into(),
            "--agent".into(),
            "cowork".into(),
        ];
        let config = config_argv("cowork", "/tmp/Agent Lens/agent-lens", &args).unwrap();
        assert!(config.get("version").is_none());
        assert_eq!(config["hooks"].as_object().unwrap().len(), expected.len());
        for (name, text) in expected {
            let payload: Value = serde_json::from_str(text).unwrap();
            let normalized = normalize("cowork", Some(name), &payload).unwrap();
            assert_eq!(normalized.input, payload);
            assert_eq!(normalized.enforceable, name == "PreToolUse");
            let command = &config["hooks"][name][0]["hooks"][0];
            assert_eq!(command["command"], "/tmp/Agent Lens/agent-lens");
            assert_eq!(command["args"][1], args[1]);
            assert_eq!(command["args"][5], "--event");
            assert_eq!(command["args"][6], name);
            assert!(command.get("shell").is_none());
            assert_eq!(command["timeout"], 30);
            if normalized.enforceable {
                assert_eq!(command["onFailure"], "block");
                assert_eq!(
                    response("cowork", name, true, "policy"),
                    response("claude", name, true, "policy")
                );
            } else {
                assert!(command.get("onFailure").is_none());
                assert_eq!(response("cowork", name, true, "policy"), json!({}));
            }
        }
        for name in ["PermissionRequest", "Stop", "WorktreeCreate"] {
            assert!(normalize("cowork", Some(name), &json!({})).is_err());
        }
        assert!(self::config("cowork", "shell command").is_err());
    }

    #[test]
    fn native_pretool_denial_shapes_and_no_permission_override() {
        for agent in ["claude", "codex"] {
            assert_eq!(
                response(agent, "PreToolUse", true, "rule-1"),
                json!({
                    "hookSpecificOutput": {"hookEventName":"PreToolUse", "permissionDecision":"deny", "permissionDecisionReason":"rule-1"}
                })
            );
            assert_eq!(
                response(agent, "PermissionRequest", true, "rule-1"),
                json!({
                    "hookSpecificOutput": {"hookEventName":"PermissionRequest", "decision":{"behavior":"deny", "message":"rule-1"}}
                })
            );
            assert_eq!(response(agent, "PreToolUse", false, ""), json!({}));
        }
        assert_eq!(
            response("hermes", "pre_tool_call", true, "rule-1"),
            json!({"action":"block", "message":"rule-1"})
        );
        assert!(!response("hermes", "pre_tool_call", true, "")["message"]
            .as_str()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn gemini_native_contract_has_millisecond_timeout_and_no_model_side_effects() {
        assert_eq!(
            response("gemini", "BeforeTool", true, "policy"),
            json!({"decision":"deny","reason":"policy"})
        );
        assert_eq!(response("gemini", "BeforeTool", false, ""), json!({}));
        assert!(!response("gemini", "BeforeTool", true, "")["reason"]
            .as_str()
            .unwrap()
            .is_empty());
        let config = config("gemini", "'agent-lens' hook --agent gemini").unwrap();
        assert_eq!(config["hooks"].as_object().unwrap().len(), 9);
        for spec in events("gemini").unwrap() {
            let handler = &config["hooks"][spec.name][0]["hooks"][0];
            assert_eq!(handler["timeout"], 10_000);
            assert_eq!(handler["name"], "agent-lens");
            assert!(handler.get("shell").is_none());
            assert_eq!(spec.enforceable, spec.name == "BeforeTool");
        }
        for name in ["BeforeModel", "AfterModel"] {
            assert!(config["hooks"].get(name).is_none());
            assert!(normalize("gemini", Some(name), &json!({})).is_err());
        }
        for invalid in [json!("cat .env"), json!([]), json!(null)] {
            assert!(normalize(
                "gemini",
                Some("BeforeTool"),
                &json!({"tool_name":"read_file","tool_input":invalid})
            )
            .is_err());
        }
    }

    #[test]
    fn every_event_roundtrips_and_config_matches_registry() {
        for agent in ["claude", "codex", "hermes", "gemini"] {
            let config = config(
                agent,
                "'path with spaces/agent-lens' --state '/tmp/state' hook",
            )
            .unwrap();
            let registry = events(agent).unwrap();
            assert_eq!(config["hooks"].as_object().unwrap().len(), registry.len());
            let mut names = HashSet::new();
            for spec in registry {
                assert!(names.insert(spec.name));
                let payload = json!({"hook_event_name":spec.name, "tool_name":"Bash", "tool_input":{"command":"echo ok"}});
                let normalized = normalize(agent, None, &payload).unwrap();
                assert_eq!(normalized.hook_event, spec.name);
                assert_eq!(normalized.phase, spec.phase);
                assert_eq!(normalized.enforceable, spec.enforceable);
                let handler = if agent == "hermes" {
                    &config["hooks"][spec.name][0]
                } else {
                    &config["hooks"][spec.name][0]["hooks"][0]
                };
                assert_eq!(
                    handler["command"],
                    format!(
                        "'path with spaces/agent-lens' --state '/tmp/state' hook --event {}",
                        spec.name
                    )
                );
                assert!(handler.get("async").is_none());
                if !spec.enforceable {
                    assert_eq!(response(agent, spec.name, true, "rule-1"), json!({}));
                }
            }
        }
    }

    #[test]
    fn event_mismatch_and_unregistered_event_rejected() {
        for (agent, pre, post) in [
            ("claude", "PreToolUse", "PostToolUse"),
            ("codex", "PreToolUse", "PostToolUse"),
            ("hermes", "pre_tool_call", "post_tool_call"),
            ("gemini", "BeforeTool", "AfterTool"),
        ] {
            let payload = json!({"hook_event_name":pre, "tool_name":"Bash", "tool_input":{}});
            assert!(normalize(agent, Some(post), &payload).is_err());
            assert!(normalize(agent, Some("typo"), &json!({})).is_err());
            assert!(normalize(agent, Some(pre), &json!({"hook_event_name":3})).is_err());
            assert!(normalize(agent, None, &json!({})).is_err());
        }
        for event in [
            "WorktreeCreate",
            "WorktreeRemove",
            "PreModelSwitch",
            "PostModelSwitch",
            "UserPromptExpansion",
            "MessageDisplay",
        ] {
            assert!(normalize("claude", Some(event), &json!({})).is_err());
        }
        assert!(events("unsupported-agent").is_err());
        assert!(normalize("codex", None, &json!({"type":"agent-turn-complete"})).is_err());
    }

    #[test]
    fn native_identity_and_full_policy_input_preserved() {
        let payload = json!({"hook_event_name":"PostToolUse", "session_id":"native-session:123", "tool_name":"mcp__fs__read", "tool_input":{"path":"C:\\repo\\.env"}, "tool_response":{"text":"secret"}, "prompt":"native prompt", "agent_id":"native-child"});
        let event = normalize("codex", None, &payload).unwrap();
        assert_eq!(event.session_id.as_deref(), Some("native-session:123"));
        assert_eq!(event.tool_name.as_deref(), Some("mcp__fs__read"));
        assert_eq!(event.input, payload);
        assert!(!event.enforceable);
        let absent = normalize("claude", Some("SessionStart"), &json!({"task_id":"not-a-session", "session_id":"has whitespace", "tool_name":"x".repeat(129)})).unwrap();
        assert!(absent.session_id.is_none());
        // Tool names remain original for policy; engine output filters metadata.
        assert_eq!(absent.tool_name, Some("x".repeat(129)));
    }

    #[test]
    fn native_fixtures_and_plugin_args_parse() {
        for (agent, fixture) in [
            (
                "gemini",
                include_str!("../../../examples/events/gemini-pre-tool.json"),
            ),
            (
                "claude",
                include_str!("../../../examples/events/claude-pre-tool.json"),
            ),
            (
                "codex",
                include_str!("../../../examples/events/codex-pre-tool.json"),
            ),
            (
                "hermes",
                include_str!("../../../examples/events/hermes-pre-tool.json"),
            ),
        ] {
            let payload: Value = serde_json::from_str(fixture).unwrap();
            let event = normalize(agent, None, &payload).unwrap();
            assert!(event.enforceable);
            assert_eq!(event.phase, "pre");
        }
        let event = normalize(
            "hermes",
            Some("pre_tool_call"),
            &json!({"tool_name":"terminal", "args":{"command":"echo ok"}, "task_id":"only-task"}),
        )
        .unwrap();
        assert!(event.session_id.is_none());
        assert_eq!(event.input["args"]["command"], "echo ok");
    }

    #[test]
    fn post_and_lifecycle_fixtures_are_observe_only() {
        for (agent, phase, fixture) in [
            (
                "claude",
                "post",
                include_str!("../../../examples/events/claude-post-tool.json"),
            ),
            (
                "gemini",
                "post",
                include_str!("../../../examples/events/gemini-post-tool.json"),
            ),
            (
                "gemini",
                "lifecycle",
                include_str!("../../../examples/events/gemini-session-start.json"),
            ),
            (
                "codex",
                "post",
                include_str!("../../../examples/events/codex-post-tool.json"),
            ),
            (
                "hermes",
                "post",
                include_str!("../../../examples/events/hermes-post-tool.json"),
            ),
            (
                "claude",
                "lifecycle",
                include_str!("../../../examples/events/claude-session-start.json"),
            ),
            (
                "codex",
                "lifecycle",
                include_str!("../../../examples/events/codex-session-start.json"),
            ),
            (
                "hermes",
                "lifecycle",
                include_str!("../../../examples/events/hermes-session-start.json"),
            ),
        ] {
            let payload: Value = serde_json::from_str(fixture).unwrap();
            let event = normalize(agent, None, &payload).unwrap();
            assert_eq!(event.phase, phase);
            assert!(!event.enforceable);
            assert_eq!(event.input, payload);
            assert_eq!(
                response(agent, &event.hook_event, true, "rule-1"),
                json!({})
            );
        }
    }

    #[test]
    fn claude_shell_matches_supplied_command_dialect() {
        let posix = config("claude", "'agent-lens' hook --agent claude").unwrap();
        let windows = config(
            "claude",
            "& 'C:\\Agent Lens\\agent-lens.exe' hook --agent claude",
        )
        .unwrap();
        for event in events("claude").unwrap() {
            assert_eq!(posix["hooks"][event.name][0]["hooks"][0]["shell"], "bash");
            assert_eq!(
                windows["hooks"][event.name][0]["hooks"][0]["shell"],
                "powershell"
            );
        }
    }

    #[test]
    fn malformed_payload_and_config_commands_rejected() {
        assert!(normalize("claude", Some("SessionStart"), &json!([])).is_err());
        for agent in ["claude", "codex", "hermes", "gemini"] {
            assert!(config(agent, "").is_err());
            assert!(config(agent, "bad\ncommand").is_err());
            assert!(config(agent, "bad\0command").is_err());
            let pre = match agent {
                "hermes" => "pre_tool_call",
                "gemini" => "BeforeTool",
                _ => "PreToolUse",
            };
            assert!(normalize(agent, Some(pre), &json!({"tool_name":"Bash"})).is_err());
            assert!(normalize(agent, Some(pre), &json!({"tool_input":{}})).is_err());
        }
        assert!(config("hermes", "& 'agent-lens.exe'").is_err());
        let hermes_config = config("hermes", "'agent-lens' hook --agent hermes").unwrap();
        assert_eq!(
            hermes_config["hooks"]["pre_tool_call"][0]["fail_closed"],
            true
        );
        assert!(hermes_config["hooks"]["post_tool_call"][0]
            .get("fail_closed")
            .is_none());
        let config = config("codex", "agent-lens hook --agent codex").unwrap();
        assert_eq!(config["hooks"]["SessionEnd"][0]["hooks"][0]["timeout"], 3);
        assert_eq!(config["hooks"]["Interrupt"][0]["hooks"][0]["timeout"], 3);
    }
}
