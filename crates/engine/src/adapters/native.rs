//! Native Cursor command hooks and Copilot CLI camelCase command hooks.
//! Contracts checked 2026-10-29:
//! https://cursor.com/docs/hooks.md
//! https://docs.github.com/en/copilot/reference/hooks-configuration
//! https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks
use super::{event, optional_identifier, EventSpec, Normalized};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Map, Value};

// Only generic preToolUse enforces policy. Stop/subagent callbacks are observed
// without followups or context injection. Dedicated tool gates duplicate generic
// hooks; Tab, prompt mutation and thinking payload hooks are outside this scope.
const CURSOR: &[EventSpec] = &[
    event("sessionStart", "lifecycle", false),
    event("sessionEnd", "lifecycle", false),
    event("preToolUse", "pre", true),
    event("postToolUse", "post", false),
    event("postToolUseFailure", "post", false),
    event("subagentStart", "lifecycle", false),
    event("subagentStop", "lifecycle", false),
    event("stop", "lifecycle", false),
    event("preCompact", "pre", false),
    event("afterAgentResponse", "post", false),
    event("workspaceOpen", "lifecycle", false),
];

// camelCase only: PascalCase aliases select a different input protocol. There is
// no documented postCompact here. No permissionRequest or prompt-transform hook.
const COPILOT: &[EventSpec] = &[
    event("sessionStart", "lifecycle", false),
    event("sessionEnd", "lifecycle", false),
    event("preToolUse", "pre", true),
    event("postToolUse", "post", false),
    event("postToolUseFailure", "post", false),
    event("errorOccurred", "lifecycle", false),
    event("userPromptSubmitted", "pre", false),
    event("agentStop", "lifecycle", false),
    event("subagentStart", "lifecycle", false),
    event("subagentStop", "lifecycle", false),
    event("preCompact", "pre", false),
    event("notification", "lifecycle", false),
];

pub(super) fn events(agent: &str) -> Result<&'static [EventSpec]> {
    match agent {
        "cursor" => Ok(CURSOR),
        "copilot" => Ok(COPILOT),
        _ => bail!("unsupported native agent"),
    }
}

pub(super) fn normalize(
    agent: &str,
    explicit: Option<&str>,
    payload: &Value,
) -> Result<Normalized> {
    let object = payload
        .as_object()
        .context("payload must be a JSON object")?;
    let native = object
        .get("hook_event_name")
        .map(|v| v.as_str().context("hook_event_name must be a string"))
        .transpose()?;
    if let (Some(explicit), Some(native)) = (explicit, native) {
        // The native camelCase notification schema alone includes this Pascal
        // discriminator. It does not switch the rest of its fields to snake_case.
        let notification =
            agent == "copilot" && explicit == "notification" && native == "Notification";
        ensure!(
            explicit == native || notification,
            "explicit event does not match native hook_event_name"
        );
    }
    let name = if agent == "copilot" {
        // pre/post callbacks share the same fields. Never infer an event from
        // toolName or accept a PascalCase alias with the wrong field dialect.
        explicit.context("Copilot CLI requires an explicit hook event")?
    } else {
        explicit.or(native).context("missing hook event")?
    };
    let spec = events(agent)?
        .iter()
        .find(|spec| spec.name == name)
        .context("unregistered hook event")?;
    let (tool_key, session_key) = if agent == "copilot" {
        ("toolName", "sessionId")
    } else {
        ("tool_name", "conversation_id")
    };
    let tool_name = payload.get(tool_key).and_then(Value::as_str);
    if spec.enforceable {
        ensure!(
            tool_name.is_some_and(|s| !s.trim().is_empty()),
            "pre-tool event requires a nonempty native tool name"
        );
        if agent == "copilot" {
            copilot_tool_args(payload)?.context("Copilot preToolUse requires toolArgs")?;
        } else {
            ensure!(
                payload.get("tool_input").is_some_and(Value::is_object),
                "Cursor preToolUse requires object tool_input"
            );
        }
    }
    Ok(Normalized {
        hook_event: name.to_owned(),
        phase: spec.phase.to_owned(),
        enforceable: spec.enforceable,
        session_id: optional_identifier(payload.get(session_key)),
        tool_name: tool_name.map(str::to_owned),
        // Do not replace toolArgs with parsed JSON: policy and redaction retain
        // the entire original callback, including prompts and post-tool results.
        input: payload.clone(),
    })
}

/// Parse only Copilot's native toolArgs, never arbitrary strings in a callback.
/// Official CLI examples use a JSON string; SDK/native schemas also allow an
/// object. The native apply_patch tool additionally sends its patch verbatim.
pub(crate) fn copilot_tool_args(payload: &Value) -> Result<Option<Value>> {
    let Some(raw) = payload.get("toolArgs") else {
        return Ok(None);
    };
    let parsed = match raw {
        Value::String(text) => {
            ensure!(
                text.len() <= crate::MAX_PAYLOAD_BYTES,
                "Copilot toolArgs exceeds byte limit"
            );
            if payload.get("toolName").and_then(Value::as_str) == Some("apply_patch")
                && text.starts_with("*** Begin Patch")
            {
                return copilot_patch_args(text).map(Some);
            }
            serde_json::from_str(text)
                .map_err(|_| anyhow::anyhow!("invalid Copilot toolArgs JSON"))?
        }
        Value::Object(_) => {
            crate::check_json_bounds(raw, crate::MAX_PAYLOAD_BYTES)?;
            raw.clone()
        }
        _ => bail!("Copilot toolArgs must be an object or a JSON-encoded object"),
    };
    ensure!(
        parsed.is_object(),
        "Copilot toolArgs JSON must encode an object"
    );
    crate::check_json_bounds(&parsed, crate::MAX_PAYLOAD_BYTES)?;
    Ok(Some(parsed))
}

/// Extract the native patch's declared targets without treating added/context
/// text as a path. The original callback remains the content/redaction input.
fn copilot_patch_args(text: &str) -> Result<Value> {
    fn target<'a>(line: &'a str, prefix: &str) -> Result<&'a str> {
        let path = line.strip_prefix(prefix).context("invalid patch header")?;
        ensure!(
            !path.is_empty()
                && path.len() <= 4096
                && path.trim() == path
                && !path.chars().any(char::is_control),
            "invalid patch target"
        );
        Ok(path)
    }

    let mut lines = text.lines().peekable();
    ensure!(
        lines.next() == Some("*** Begin Patch"),
        "invalid patch start"
    );
    let mut paths = Vec::new();
    loop {
        let header = lines.next().context("missing patch end")?;
        if header == "*** End Patch" {
            ensure!(
                !paths.is_empty() && lines.next().is_none(),
                "invalid patch end"
            );
            break;
        }
        let kind = if header.starts_with("*** Add File: ") {
            paths.push(target(header, "*** Add File: ")?);
            "add"
        } else if header.starts_with("*** Delete File: ") {
            paths.push(target(header, "*** Delete File: ")?);
            "delete"
        } else if header.starts_with("*** Update File: ") {
            paths.push(target(header, "*** Update File: ")?);
            if lines
                .peek()
                .is_some_and(|line| line.starts_with("*** Move to: "))
            {
                paths.push(target(lines.next().unwrap(), "*** Move to: ")?);
            }
            "update"
        } else {
            bail!("unsupported patch section");
        };
        let mut update_body = false;
        while let Some(line) = lines.peek().copied() {
            if line.starts_with("*** ") && line != "*** End of File" {
                break;
            }
            lines.next();
            match kind {
                "add" => ensure!(line.starts_with('+'), "invalid added patch line"),
                "delete" => bail!("unexpected deleted patch body"),
                "update" => {
                    if line == "*** End of File" {
                        ensure!(update_body, "empty patch update");
                        ensure!(
                            lines.peek().is_some_and(|line| line.starts_with("*** ")),
                            "misplaced patch end-of-file"
                        );
                        break;
                    }
                    ensure!(
                        line.is_empty()
                            || line.starts_with([' ', '+', '-'])
                            || line == "@@"
                            || line.starts_with("@@ "),
                        "invalid updated patch line"
                    );
                    update_body |= line != "@@" && !line.starts_with("@@ ");
                }
                _ => unreachable!(),
            }
        }
        ensure!(kind != "update" || update_body, "empty patch update");
    }
    let parsed = json!({"paths": paths, "patch": text});
    crate::check_json_bounds(&parsed, crate::MAX_PAYLOAD_BYTES)?;
    Ok(parsed)
}

pub(super) fn response(agent: &str, event: &str, blocked: bool, reason: &str) -> Value {
    let reason = if reason.trim().is_empty() {
        "Blocked by Agent Lens policy"
    } else {
        reason
    };
    match (agent, event, blocked) {
        ("cursor", "preToolUse", true) => {
            json!({"permission": "deny", "user_message": reason, "agent_message": reason})
        }
        // Cursor permission responses require this enum. It means continue
        // through the hook, rather than overriding the agent's approval policy.
        ("cursor", "preToolUse", false) | ("cursor", "subagentStart", _) => {
            json!({"permission": "allow"})
        }
        ("copilot", "preToolUse", true) => {
            json!({"permissionDecision": "deny", "permissionDecisionReason": reason})
        }
        _ => json!({}),
    }
}

pub(super) fn cursor_config(command: &str) -> Result<Value> {
    let mut hooks = Map::new();
    for spec in CURSOR {
        let mut handler = json!({"type": "command", "command": format!("{command} --event {}", spec.name), "timeout": 10});
        if spec.enforceable {
            handler["failClosed"] = json!(true);
        }
        hooks.insert(spec.name.into(), json!([handler]));
    }
    Ok(json!({"version": 1, "hooks": hooks}))
}

/// Copilot CLI and Cowork direct execution; preserve every argv element without shell
/// quoting or joining. Other agents retain the existing shell-command API.
pub fn config_argv(agent: &str, executable: &str, args: &[String]) -> Result<Value> {
    ensure!(
        matches!(agent, "copilot" | "cowork"),
        "direct executable hook configuration requires Copilot CLI or Cowork"
    );
    ensure!(
        !executable.trim().is_empty()
            && executable.len() <= 4096
            && !executable.chars().any(char::is_control),
        "invalid hook executable"
    );
    ensure!(args.len() <= 128, "too many hook arguments");
    let mut bytes = executable.len();
    for arg in args {
        ensure!(
            !arg.chars().any(char::is_control),
            "hook arguments contain control characters"
        );
        ensure!(
            arg != "--event" && !arg.starts_with("--event="),
            "hook event is supplied by the native registry"
        );
        bytes = bytes
            .checked_add(arg.len())
            .context("hook argument size overflow")?;
        ensure!(bytes <= 65536, "hook arguments exceed byte limit");
    }
    let mut hooks = Map::new();
    for spec in super::events(agent)? {
        let mut argv = args.to_vec();
        argv.extend(["--event".into(), spec.name.into()]);
        let handler = if agent == "cowork" {
            // An args array selects direct execution in the documented Claude
            // hook contract. Provision this executable separately from the plugin.
            let mut command =
                json!({"type":"command", "command":executable, "args":argv, "timeout":30});
            if spec.enforceable {
                command["onFailure"] = json!("block");
            }
            json!([{"matcher":".*", "hooks":[command]}])
        } else {
            json!([{"type":"command", "exec":executable, "args":argv, "timeoutSec":30}])
        };
        hooks.insert(spec.name.into(), handler);
    }
    Ok(if agent == "cowork" {
        json!({"hooks": hooks})
    } else {
        json!({"version": 1, "hooks": hooks})
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters;

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!("../../../../examples/events/", $name, ".json"))
        };
    }

    // Independently authored native inventory: never derive expected event names
    // or phases from the production registry. Every subscription has a fixture.
    const CURSOR_CASES: &[(&str, &str, &str)] = &[
        (
            "sessionStart",
            "lifecycle",
            fixture!("cursor-session-start"),
        ),
        ("sessionEnd", "lifecycle", fixture!("cursor-session-end")),
        ("preToolUse", "pre", fixture!("cursor-pre-tool")),
        ("postToolUse", "post", fixture!("cursor-post-tool")),
        (
            "postToolUseFailure",
            "post",
            fixture!("cursor-tool-failure"),
        ),
        (
            "subagentStart",
            "lifecycle",
            fixture!("cursor-subagent-start"),
        ),
        (
            "subagentStop",
            "lifecycle",
            fixture!("cursor-subagent-stop"),
        ),
        ("stop", "lifecycle", fixture!("cursor-stop")),
        ("preCompact", "pre", fixture!("cursor-pre-compact")),
        (
            "afterAgentResponse",
            "post",
            fixture!("cursor-agent-response"),
        ),
        (
            "workspaceOpen",
            "lifecycle",
            fixture!("cursor-workspace-open"),
        ),
    ];
    const COPILOT_CASES: &[(&str, &str, &str)] = &[
        (
            "sessionStart",
            "lifecycle",
            fixture!("copilot-session-start"),
        ),
        ("sessionEnd", "lifecycle", fixture!("copilot-session-end")),
        ("preToolUse", "pre", fixture!("copilot-pre-tool")),
        ("postToolUse", "post", fixture!("copilot-post-tool")),
        (
            "postToolUseFailure",
            "post",
            fixture!("copilot-tool-failure"),
        ),
        ("errorOccurred", "lifecycle", fixture!("copilot-error")),
        (
            "userPromptSubmitted",
            "pre",
            fixture!("copilot-user-prompt"),
        ),
        ("agentStop", "lifecycle", fixture!("copilot-agent-stop")),
        (
            "subagentStart",
            "lifecycle",
            fixture!("copilot-subagent-start"),
        ),
        (
            "subagentStop",
            "lifecycle",
            fixture!("copilot-subagent-stop"),
        ),
        ("preCompact", "pre", fixture!("copilot-pre-compact")),
        (
            "notification",
            "lifecycle",
            fixture!("copilot-notification"),
        ),
    ];

    #[test]
    fn explicit_native_inventory_fixtures_metadata_and_observation_boundaries() {
        for (agent, cases, expected_count) in
            [("cursor", CURSOR_CASES, 11), ("copilot", COPILOT_CASES, 12)]
        {
            assert_eq!(cases.len(), expected_count);
            let names: Vec<_> = adapters::events(agent)
                .unwrap()
                .iter()
                .map(|e| e.name)
                .collect();
            assert_eq!(names, cases.iter().map(|c| c.0).collect::<Vec<_>>());
            for &(name, phase, fixture) in cases {
                let payload: Value = serde_json::from_str(fixture).unwrap();
                let normalized = adapters::normalize(agent, Some(name), &payload).unwrap();
                assert_eq!(normalized.hook_event, name);
                assert_eq!(normalized.phase, phase);
                assert_eq!(normalized.enforceable, name == "preToolUse");
                assert_eq!(normalized.input, payload);
                let session = format!("synthetic-{agent}-session");
                assert_eq!(
                    normalized.session_id.as_deref(),
                    if name == "workspaceOpen" {
                        None
                    } else {
                        Some(session.as_str())
                    }
                );
                if name.contains("ToolUse") {
                    assert_eq!(
                        normalized.tool_name.as_deref(),
                        Some(if agent == "cursor" { "Read" } else { "view" })
                    );
                }
                let output = crate::process(&json!({"agent": agent, "event": name, "payload": payload,
                    "rules_yaml": format!("version: 1\nrules: [{{id: native, agents: [{agent}], action: block}}]"),
                    "capture_content": false})).unwrap();
                assert_eq!(output["blocked"], name == "preToolUse");
                assert_eq!(
                    output["event"]["decision"],
                    if name == "preToolUse" {
                        "block"
                    } else {
                        "would_block"
                    }
                );
                assert_eq!(
                    output["event"]["enforcement"],
                    if name == "preToolUse" {
                        "supported"
                    } else {
                        "observe_only"
                    }
                );
                assert!(output["event"].get("content").is_none());
                assert!(!output.to_string().contains("SYNTHETIC_"));
                if name != "preToolUse" {
                    assert_eq!(
                        output["response"],
                        if agent == "cursor" && name == "subagentStart" {
                            json!({"permission":"allow"})
                        } else {
                            json!({})
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn native_denial_and_neutral_continuation_are_exact() {
        assert_eq!(
            adapters::response("cursor", "preToolUse", true, "policy"),
            json!({"permission":"deny", "user_message":"policy", "agent_message":"policy"})
        );
        assert_eq!(
            adapters::response("copilot", "preToolUse", true, "policy"),
            json!({"permissionDecision":"deny", "permissionDecisionReason":"policy"})
        );
        for (agent, cases) in [("cursor", CURSOR_CASES), ("copilot", COPILOT_CASES)] {
            for &(name, _, _) in cases {
                let neutral = adapters::response(agent, name, false, "ignored");
                assert_eq!(
                    neutral,
                    if agent == "cursor" && matches!(name, "preToolUse" | "subagentStart") {
                        json!({"permission":"allow"})
                    } else {
                        json!({})
                    }
                );
            }
            let denial = adapters::response(agent, "preToolUse", true, " \n");
            let key = if agent == "cursor" {
                "user_message"
            } else {
                "permissionDecisionReason"
            };
            assert_eq!(denial[key], "Blocked by Agent Lens policy");
        }
    }

    #[test]
    fn native_configuration_uses_flat_cursor_and_exact_copilot_argv() {
        for command in [
            "'path with spaces/agent-lens' hook --agent cursor",
            "& 'C:\\Agent Lens\\agent-lens.exe' hook --agent cursor",
        ] {
            let config = adapters::config("cursor", command).unwrap();
            assert_eq!(config["version"], 1);
            assert_eq!(
                config["hooks"].as_object().unwrap().len(),
                CURSOR_CASES.len()
            );
            for &(name, _, _) in CURSOR_CASES {
                let handler = &config["hooks"][name][0];
                let mut expected = json!({"type":"command", "command":format!("{command} --event {name}"), "timeout":10});
                if name == "preToolUse" {
                    expected["failClosed"] = json!(true);
                }
                assert_eq!(handler, &expected);
            }
        }
        let args: Vec<String> = [
            "--state",
            "C:\\state path\\quote'\"$value;literal",
            "hook",
            "--agent",
            "copilot",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        for executable in [
            "/path with spaces/agent-lens",
            "C:\\Agent Lens\\agent-lens.exe",
        ] {
            let config = adapters::config_argv("copilot", executable, &args).unwrap();
            assert_eq!(config["version"], 1);
            assert_eq!(
                config["hooks"].as_object().unwrap().len(),
                COPILOT_CASES.len()
            );
            for &(name, _, _) in COPILOT_CASES {
                let mut expected_args = args.clone();
                expected_args.extend(["--event".into(), name.into()]);
                assert_eq!(
                    config["hooks"][name],
                    json!([{"type":"command", "exec":executable, "args":expected_args, "timeoutSec":30}])
                );
            }
        }
        assert!(adapters::config("copilot", "agent-lens hook").is_err());
        assert!(adapters::config_argv("cursor", "agent-lens", &[]).is_err());
        for bad in ["", " ", "bad\nexe", "bad\0exe"] {
            assert!(adapters::config("cursor", bad).is_err());
            assert!(adapters::config_argv("copilot", bad, &[]).is_err());
        }
        for args in [
            vec!["bad\0arg".into()],
            vec!["--event".into()],
            vec!["--event=preToolUse".into()],
            vec!["x".repeat(65536)],
            vec![String::new(); 129],
        ] {
            assert!(adapters::config_argv("copilot", "agent-lens", &args).is_err());
        }
    }

    #[test]
    fn event_identity_is_explicit_and_no_unsupported_aliases_are_guessed() {
        let cursor: Value = serde_json::from_str(fixture!("cursor-pre-tool")).unwrap();
        let copilot: Value = serde_json::from_str(fixture!("copilot-pre-tool")).unwrap();
        assert_eq!(
            adapters::normalize("cursor", None, &cursor)
                .unwrap()
                .hook_event,
            "preToolUse"
        );
        assert!(adapters::normalize("cursor", Some("postToolUse"), &cursor).is_err());
        assert!(adapters::normalize("copilot", None, &copilot).is_err());
        assert!(adapters::normalize(
            "copilot",
            None,
            &json!({"hook_event_name":"preToolUse", "toolName":"view", "toolArgs":{}})
        )
        .is_err());
        for (agent, names) in [
            (
                "cursor",
                &[
                    "PreToolUse",
                    "beforeSubmitPrompt",
                    "afterAgentThought",
                    "beforeTabFileRead",
                    "beforeShellExecution",
                    "postCompact",
                ][..],
            ),
            (
                "copilot",
                &[
                    "PreToolUse",
                    "PostToolUse",
                    "Notification",
                    "permissionRequest",
                    "userPromptTransformed",
                    "postCompact",
                ][..],
            ),
        ] {
            for name in names {
                assert!(adapters::normalize(agent, Some(name), &json!({})).is_err());
            }
            assert!(adapters::normalize(agent, Some("sessionStart"), &json!([])).is_err());
            assert!(adapters::normalize(
                agent,
                Some("sessionStart"),
                &json!({"hook_event_name":1})
            )
            .is_err());
        }
        let note: Value = serde_json::from_str(fixture!("copilot-notification")).unwrap();
        assert!(adapters::normalize("copilot", Some("notification"), &note).is_ok());
        assert!(adapters::normalize("copilot", Some("sessionStart"), &note).is_err());
        let cursor = adapters::normalize(
            "cursor",
            Some("sessionEnd"),
            &json!({"session_id":"wrong-source", "generation_id":"not-session"}),
        )
        .unwrap();
        assert!(cursor.session_id.is_none());
        let copilot = adapters::normalize(
            "copilot",
            Some("sessionEnd"),
            &json!({"session_id":"wrong-dialect"}),
        )
        .unwrap();
        assert!(copilot.session_id.is_none());
    }

    #[test]
    fn malformed_pretool_calls_never_become_empty_policy_inputs() {
        for (agent, tool_key, args_key) in [
            ("cursor", "tool_name", "tool_input"),
            ("copilot", "toolName", "toolArgs"),
        ] {
            for name in [json!(null), json!(3), json!(""), json!("  "), json!([])] {
                assert!(adapters::normalize(
                    agent,
                    Some("preToolUse"),
                    &json!({tool_key:name, args_key:{}})
                )
                .is_err());
            }
            assert!(
                adapters::normalize(agent, Some("preToolUse"), &json!({tool_key:"read"})).is_err()
            );
            assert!(adapters::normalize(agent, Some("preToolUse"), &json!({args_key:{}})).is_err());
            for args in [
                json!(null),
                json!(3),
                json!(false),
                json!([]),
                json!("PRIVATE_BAD_JSON"),
                json!("[]"),
                json!("null"),
                json!("42"),
            ] {
                let error = adapters::normalize(
                    agent,
                    Some("preToolUse"),
                    &json!({tool_key:"read", args_key:args}),
                )
                .unwrap_err();
                assert!(!error.to_string().contains("PRIVATE_BAD_JSON"));
            }
            assert!(adapters::normalize(
                agent,
                Some("preToolUse"),
                &json!({tool_key:"read", args_key:{}})
            )
            .is_ok());
        }
        assert!(adapters::normalize(
            "copilot",
            Some("preToolUse"),
            &json!({"tool_name":"Read", "tool_input":{}})
        )
        .is_err());
        let text = r#"{"path":"/synthetic/file"}"#;
        let input = json!({"toolName":"view", "toolArgs":text});
        assert_eq!(
            adapters::normalize("copilot", Some("preToolUse"), &input)
                .unwrap()
                .input,
            input
        );
        assert!(adapters::normalize(
            "cursor",
            Some("preToolUse"),
            &json!({"tool_name":"Read", "tool_input":text})
        )
        .is_err());
    }

    #[test]
    fn copilot_apply_patch_observed_freeform_preserves_original_input() {
        // Copilot CLI 1.0.105 Windows ARM64 emitted this exact freeform shape.
        let patch = "*** Begin Patch\n*** Add File: copilot-allow-1029.txt\n+COPILOT_ALLOW_1029\n*** End Patch\n";
        let raw = json!({"toolName":"apply_patch", "toolArgs":patch,
            "sessionId":"copilot-patch-session", "nativeExtra":"preserved"});
        let normalized = adapters::normalize("copilot", Some("preToolUse"), &raw).unwrap();
        assert_eq!(normalized.input, raw);
        assert_eq!(normalized.tool_name.as_deref(), Some("apply_patch"));
        assert_eq!(
            normalized.session_id.as_deref(),
            Some("copilot-patch-session")
        );
        for other in ["view", "edit", "Apply_Patch", "apply_patch "] {
            let mut wrong_tool = raw.clone();
            wrong_tool["toolName"] = json!(other);
            assert!(adapters::normalize("copilot", Some("preToolUse"), &wrong_tool).is_err());
        }
    }

    #[test]
    fn copilot_apply_patch_malformed_and_oversized_remain_errors() {
        for patch in [
            "PRIVATE_BAD_PATCH",
            "*** Begin Patch\n*** Add File: safe.txt\n+PRIVATE_BAD_PATCH\n",
            "*** Add File: safe.txt\n+PRIVATE_BAD_PATCH\n*** End Patch\n",
            "*** Begin Patch\n*** Add File: \n+PRIVATE_BAD_PATCH\n*** End Patch\n",
            "*** Begin Patch\n*** Unknown File: safe.txt\n+PRIVATE_BAD_PATCH\n*** End Patch\n",
            "*** Begin Patch\n*** Move to: private.txt\n*** End Patch\n",
            "*** Begin Patch\n*** Add File: safe.txt\nPRIVATE_BAD_PATCH\n*** End Patch\n",
            "*** Begin Patch\n*** Delete File: safe.txt\n+PRIVATE_BAD_PATCH\n*** End Patch\n",
            "*** Begin Patch\n*** Add File: safe.txt\n+safe\n*** End Patch\nPRIVATE_BAD_PATCH",
            "[]",
            "null",
            "42",
            "\"PRIVATE_BAD_PATCH\"",
        ] {
            let error = adapters::normalize(
                "copilot",
                Some("preToolUse"),
                &json!({"toolName":"apply_patch", "toolArgs":patch}),
            )
            .unwrap_err();
            assert!(!error.to_string().contains("PRIVATE_BAD_PATCH"));
        }
        let oversized = format!(
            "*** Begin Patch\n*** Add File: safe.txt\n+{}\n*** End Patch\n",
            "x".repeat(crate::MAX_PAYLOAD_BYTES)
        );
        assert!(adapters::normalize(
            "copilot",
            Some("preToolUse"),
            &json!({"toolName":"apply_patch", "toolArgs":oversized})
        )
        .is_err());
    }

    #[test]
    fn embedded_copilot_arguments_have_engine_byte_node_and_depth_bounds() {
        for text in [
            " ".repeat(crate::MAX_PAYLOAD_BYTES + 1),
            format!("{{\"path\":{}0{}}}", "[".repeat(65), "]".repeat(65)),
            format!(
                "{{\"paths\":[{}]}}",
                vec!["null"; crate::MAX_NODES].join(",")
            ),
        ] {
            assert!(adapters::normalize(
                "copilot",
                Some("preToolUse"),
                &json!({"toolName":"view", "toolArgs":text})
            )
            .is_err());
        }
        assert!(adapters::normalize(
            "copilot",
            Some("preToolUse"),
            &json!({"toolName":"view", "toolArgs":"{\"path\":\"safe\"}"})
        )
        .is_ok());
    }
}
