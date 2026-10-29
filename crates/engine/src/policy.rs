use crate::adapters::Normalized;
use anyhow::{bail, Result};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;

pub(crate) const MAX_POLICY_BYTES: usize = 256 * 1024;
const MAX_RULES: usize = 128;
const MAX_PATTERN_BYTES: usize = 4096;
const MAX_REGEX_BYTES: usize = 256 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    rules: Vec<RuleSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    id: String,
    description: Option<String>,
    agents: Option<Vec<String>>,
    events: Option<Vec<String>>,
    tool_pattern: Option<String>,
    path_pattern: Option<String>,
    content_pattern: Option<String>,
    action: Action,
}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Action {
    Block,
    Audit,
}

struct Rule {
    id: String,
    agents: Option<Vec<String>>,
    events: Option<Vec<String>>,
    tool: Option<Regex>,
    path: Option<Regex>,
    content: Option<Regex>,
    action: Action,
}

pub(crate) struct Policy {
    rules: Vec<Rule>,
}

pub(crate) struct Matches {
    pub ids: Vec<String>,
    pub block: bool,
}

impl Policy {
    pub fn rule_ids(&self) -> Vec<String> {
        self.rules.iter().map(|rule| rule.id.clone()).collect()
    }

    pub fn parse(yaml: &str) -> Result<Self> {
        if yaml.len() > MAX_POLICY_BYTES {
            bail!("policy exceeds byte limit");
        }
        // Parser diagnostics can quote YAML source, so never return them verbatim.
        let document: Document = serde_yaml::from_str(yaml)
            .map_err(|_| anyhow::anyhow!("invalid policy YAML or schema"))?;
        if document.version != 1 {
            bail!("unsupported policy version");
        }
        if document.rules.len() > MAX_RULES {
            bail!("policy exceeds rule limit");
        }
        let mut ids = HashSet::new();
        let mut rules = Vec::with_capacity(document.rules.len());
        for spec in document.rules {
            if !valid_identifier(&spec.id, 64) || crate::redact::contains_credential(&spec.id) {
                bail!("invalid rule identifier");
            }
            if !ids.insert(spec.id.clone()) {
                bail!("duplicate rule identifier");
            }
            if spec.description.as_ref().is_some_and(|s| s.len() > 2048) {
                bail!("rule description exceeds limit");
            }
            if let Some(agents) = &spec.agents {
                if agents.is_empty()
                    || agents.len() > 7
                    || agents.iter().any(|a| {
                        !matches!(
                            a.as_str(),
                            "claude"
                                | "codex"
                                | "hermes"
                                | "gemini"
                                | "cursor"
                                | "copilot"
                                | "cowork"
                        )
                    })
                {
                    bail!("invalid agent selector");
                }
            }
            if let Some(events) = &spec.events {
                if events.is_empty()
                    || events.len() > 64
                    || events.iter().any(|e| !valid_identifier(e, 128))
                {
                    bail!("invalid event selector");
                }
            }
            if spec.agents.is_none()
                && spec.events.is_none()
                && spec.tool_pattern.is_none()
                && spec.path_pattern.is_none()
                && spec.content_pattern.is_none()
            {
                bail!("rule must have at least one selector");
            }
            rules.push(Rule {
                id: spec.id,
                agents: spec.agents,
                events: spec.events,
                tool: compile(spec.tool_pattern)?,
                path: compile(spec.path_pattern)?,
                content: compile(spec.content_pattern)?,
                action: spec.action,
            });
        }
        Ok(Self { rules })
    }

    pub fn evaluate(&self, agent: &str, event: &Normalized) -> Result<Matches> {
        let serialized = serde_json::to_string(&event.input)
            .map_err(|_| anyhow::anyhow!("cannot evaluate hook input"))?;
        let mut strings = Vec::new();
        input_strings(&event.input, &mut strings);
        // Copilot CLI can JSON-encode toolArgs. Parse only that native field,
        // retaining the raw callback for content matching and output redaction.
        let arguments = if agent == "copilot" {
            crate::adapters::copilot_tool_args(&event.input)?
        } else {
            None
        };
        let mut path_strings = Vec::new();
        input_paths(&event.input, false, &mut path_strings);
        if let Some(arguments) = &arguments {
            input_paths(arguments, false, &mut path_strings);
            input_strings(arguments, &mut strings);
        }
        let paths: Vec<String> = path_strings.iter().map(|s| lexical_path(s)).collect();
        let mut matches = Matches {
            ids: Vec::new(),
            block: false,
        };
        for rule in &self.rules {
            if rule
                .agents
                .as_ref()
                .is_some_and(|agents| !agents.iter().any(|a| a == agent))
                || rule
                    .events
                    .as_ref()
                    .is_some_and(|events| !events.contains(&event.hook_event))
                || rule.tool.as_ref().is_some_and(|regex| {
                    !event
                        .tool_name
                        .as_ref()
                        .is_some_and(|name| regex.is_match(name))
                })
                || rule
                    .path
                    .as_ref()
                    .is_some_and(|regex| !paths.iter().any(|path| regex.is_match(path)))
                || rule.content.as_ref().is_some_and(|regex| {
                    !regex.is_match(&serialized) && !strings.iter().any(|s| regex.is_match(s))
                })
            {
                continue;
            }
            matches.ids.push(rule.id.clone());
            // AL-005: audit never overrides a matching block, in either order.
            matches.block |= rule.action == Action::Block;
        }
        Ok(matches)
    }
}

fn valid_identifier(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
}

fn compile(pattern: Option<String>) -> Result<Option<Regex>> {
    pattern
        .map(|pattern| {
            if pattern.trim().is_empty() || pattern.len() > MAX_PATTERN_BYTES {
                bail!("empty or oversized rule pattern");
            }
            RegexBuilder::new(&pattern)
                .size_limit(MAX_REGEX_BYTES)
                .dfa_size_limit(MAX_REGEX_BYTES)
                .nest_limit(64)
                .build()
                .map_err(|_| anyhow::anyhow!("invalid or excessive rule regex"))
        })
        .transpose()
}

fn input_strings<'a>(value: &'a Value, strings: &mut Vec<&'a str>) {
    match value {
        Value::String(string) => strings.push(string),
        Value::Array(array) => array.iter().for_each(|v| input_strings(v, strings)),
        Value::Object(object) => object.values().for_each(|v| input_strings(v, strings)),
        _ => {}
    }
}

// Direct path fields only: embedded shell syntax requires a content rule.
fn input_paths<'a>(value: &'a Value, path_field: bool, paths: &mut Vec<&'a str>) {
    match value {
        Value::String(path) if path_field => paths.push(path),
        Value::Array(array) => array.iter().for_each(|v| input_paths(v, path_field, paths)),
        Value::Object(object) => {
            for (key, value) in object {
                let key: String = key
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .map(|c| c.to_ascii_lowercase())
                    .collect();
                let path_field = matches!(
                    key.as_str(),
                    "path"
                        | "paths"
                        | "filepath"
                        | "filepaths"
                        | "filename"
                        | "filenames"
                        | "file"
                        | "files"
                        | "targetfile"
                        | "targetpath"
                        | "sourcepath"
                        | "destinationpath"
                        | "source"
                        | "destination"
                        | "directory"
                        | "directories"
                        | "cwd"
                        | "workingdirectory"
                        | "workdir"
                );
                input_paths(value, path_field, paths);
            }
        }
        _ => {}
    }
}

fn lexical_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let prefix = if path.starts_with("//") {
        "//"
    } else if path.starts_with('/') {
        "/"
    } else {
        ""
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => match parts.last() {
                Some(last) if *last != ".." && !last.ends_with(':') => {
                    parts.pop();
                }
                _ if prefix.is_empty() && parts.is_empty() => parts.push(part),
                Some(last) if *last == ".." => parts.push(part),
                _ => {}
            },
            _ => parts.push(part),
        }
    }
    format!("{}{}", prefix, parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(input: Value) -> Normalized {
        Normalized {
            hook_event: "PreToolUse".into(),
            phase: "pre".into(),
            enforceable: true,
            session_id: None,
            tool_name: Some("Write".into()),
            input,
        }
    }

    #[test]
    fn strict_yaml_rejects_invalid_schema_and_unbounded_rules() {
        for yaml in [
            "version: 2\nrules: []",
            "version: 1\nrules: []\nextra: true",
            "version: 1\nversion: 1\nrules: []",
            "version: 1\nrules: [{id: x, action: allow, agents: [claude]}]",
            "version: 1\nrules: [{id: x, action: block}]",
            "version: 1\nrules: [{id: x, action: block, agents: []}]",
            "version: 1\nrules: [{id: x, action: block, agents: [typo]}]",
            "version: 1\nrules: [{id: x, action: block, events: []}]",
            "version: 1\nrules: [{id: x, action: block, content_pattern: ''}]",
            "version: 1\nrules: [{id: x, action: block, content_pattern: '['}]",
            "version: 1\nrules: [{id: x, action: block, agents: [claude], typo: yes}]",
            "version: 1\nrules: [{id: 'secret content', action: block, agents: [claude]}]",
            "version: 1\nrules: [{id: x, action: block, agents: [claude]}, {id: x, action: audit, agents: [claude]}]",
        ] {
            assert!(Policy::parse(yaml).is_err(), "unexpectedly accepted schema");
        }
        assert!(Policy::parse("version: 1\nrules: []").is_ok());
        let excessive = format!(
            "version: 1\nrules:\n{}",
            (0..=MAX_RULES)
                .map(|i| format!("- {{id: r{i}, agents: [claude], action: audit}}\n"))
                .collect::<String>()
        );
        assert!(Policy::parse(&excessive).is_err());
        assert!(Policy::parse(&" ".repeat(MAX_POLICY_BYTES + 1)).is_err());
    }

    #[test]
    fn all_selectors_are_anded_and_original_windows_paths_normalized() {
        let policy = Policy::parse(
            "version: 1\nrules:\n- id: win-private\n  agents: [claude]\n  events: [PreToolUse]\n  tool_pattern: '^Write$'\n  path_pattern: '(?i)^C:/private/token.txt$'\n  content_pattern: 'sensitive'\n  action: block\n",
        ).unwrap();
        let hit =
            event(json!({"file_path": "C:\\safe\\..\\private\\token.txt", "text": "sensitive"}));
        assert!(policy.evaluate("claude", &hit).unwrap().block);
        assert!(!policy.evaluate("codex", &hit).unwrap().block);
        let mut miss = event(json!({"file_path": "C:/public/token.txt", "text": "sensitive"}));
        assert!(!policy.evaluate("claude", &miss).unwrap().block);
        miss.input = hit.input.clone();
        miss.tool_name = Some("Read".into());
        assert!(!policy.evaluate("claude", &miss).unwrap().block);
        miss.tool_name = Some("Write".into());
        miss.hook_event = "PostToolUse".into();
        assert!(!policy.evaluate("claude", &miss).unwrap().block);
        miss.hook_event = "PreToolUse".into();
        miss.input["text"] = json!("ordinary");
        assert!(!policy.evaluate("claude", &miss).unwrap().block);
    }

    #[test]
    fn audit_and_block_precedence_are_order_independent() {
        for actions in [["audit", "block"], ["block", "audit"]] {
            let yaml = format!("version: 1\nrules:\n- {{id: first, agents: [claude], action: {}}}\n- {{id: second, agents: [claude], action: {}}}", actions[0], actions[1]);
            let matched = Policy::parse(&yaml)
                .unwrap()
                .evaluate("claude", &event(json!({})))
                .unwrap();
            assert!(matched.block);
            assert_eq!(matched.ids, ["first", "second"]);
        }
        let audit =
            Policy::parse("version: 1\nrules: [{id: audit, agents: [claude], action: audit}]")
                .unwrap();
        let matched = audit.evaluate("claude", &event(json!({}))).unwrap();
        assert!(!matched.block);
        assert_eq!(matched.ids, ["audit"]);
    }

    #[test]
    fn content_matches_unescaped_strings_and_errors_do_not_quote_secrets() {
        let policy = Policy::parse(
            "version: 1\nrules: [{id: lines, content_pattern: 'first\\nsecond', action: block}]",
        )
        .unwrap();
        assert!(
            policy
                .evaluate("claude", &event(json!({"content": "first\nsecond"})))
                .unwrap()
                .block
        );
        let error = Policy::parse(
            "version: 1\nrules: [{id: x, content_pattern: '[PRIVATE_SECRET', action: block}]",
        )
        .err()
        .unwrap()
        .to_string();
        assert!(!error.contains("PRIVATE_SECRET"));
    }

    #[test]
    fn regex_resource_limits_and_backreferences_are_rejected() {
        for pattern in [
            "(a)\\1".into(),
            "a".repeat(MAX_PATTERN_BYTES + 1),
            "a{100000000}".into(),
        ] {
            let yaml = format!(
                "version: 1\nrules: [{{id: x, content_pattern: '{pattern}', action: block}}]"
            );
            assert!(Policy::parse(&yaml).is_err());
        }
    }

    #[test]
    fn lexical_paths_keep_root_and_relative_parent_semantics() {
        assert_eq!(lexical_path("/safe/../private/./file"), "/private/file");
        assert_eq!(lexical_path("/../../private"), "/private");
        assert_eq!(lexical_path("../../private"), "../../private");
        assert_eq!(
            lexical_path("\\\\server\\share\\file"),
            "//server/share/file"
        );
    }

    #[test]
    fn path_rules_match_nested_path_fields_but_not_arbitrary_content() {
        let policy = Policy::parse(
            "version: 1\nrules: [{id: paths, path_pattern: '^/private/file$', action: block}]",
        )
        .unwrap();
        for input in [
            json!({"tool_input": {"filePath": "/private/file"}}),
            json!({"tool_input": {"paths": ["/public/file", "/private/file"]}}),
            json!({"tool_input": {"edits": [{"file_path": "/private/file"}]}}),
        ] {
            assert!(policy.evaluate("claude", &event(input)).unwrap().block);
        }
        for input in [
            json!({"prompt": "/private/file"}),
            json!({"tool_input": {"command": "cat /private/file"}}),
            json!({"tool_input": {"path": "/public/file"}}),
        ] {
            assert!(!policy.evaluate("claude", &event(input)).unwrap().block);
        }
    }

    #[test]
    fn shipped_integrity_rule_protects_native_hook_writes_without_blocking_reads() {
        let policy = Policy::parse(include_str!(
            "../../../examples/rules/agent-config-integrity.yaml"
        ))
        .unwrap();
        for agent in ["cursor", "copilot", "cowork"] {
            for path in [
                "/work/.cursor/hooks.json",
                "C:\\Users\\demo\\.github\\hooks\\lens.json",
                "/work/.copilot/hooks/lens.json",
            ] {
                for (tool, blocked) in [("Write", true), ("Read", false)] {
                    let (native_tool, payload, name) = if agent == "copilot" {
                        let native = if blocked { "create" } else { "view" };
                        (
                            native,
                            json!({"toolName":native, "toolArgs":json!({"path":path}).to_string()}),
                            "preToolUse",
                        )
                    } else {
                        (
                            tool,
                            json!({"tool_name":tool, "tool_input":{"file_path":path}}),
                            if agent == "cursor" {
                                "preToolUse"
                            } else {
                                "PreToolUse"
                            },
                        )
                    };
                    let call = crate::adapters::normalize(agent, Some(name), &payload).unwrap();
                    assert_eq!(call.tool_name.as_deref(), Some(native_tool));
                    assert_eq!(
                        policy.evaluate(agent, &call).unwrap().block,
                        blocked,
                        "{agent} {native_tool} {path}"
                    );
                }
            }
        }
    }

    #[test]
    fn seven_native_agents_are_valid_selectors_with_strict_inventory() {
        let all = "claude, codex, hermes, gemini, cursor, copilot, cowork";
        assert!(Policy::parse(&format!(
            "version: 1\nrules: [{{id: seven, agents: [{all}], action: audit}}]"
        ))
        .is_ok());
        assert!(Policy::parse(&format!(
            "version: 1\nrules: [{{id: eight, agents: [{all}, cursor], action: audit}}]"
        ))
        .is_err());
        for wrong in ["cursor-runtime", "copilot-otel", "copilot-cli", "Cursor"] {
            assert!(Policy::parse(&format!(
                "version: 1\nrules: [{{id: native, agents: [{wrong}], action: block}}]"
            ))
            .is_err());
        }
    }

    #[test]
    fn native_cursor_and_copilot_path_rules_block_with_near_miss_controls() {
        for agent in ["cursor", "copilot"] {
            let tool = if agent == "cursor" { "Read" } else { "view" };
            let yaml = format!("version: 1\nrules: [{{id: private, agents: [{agent}], events: [preToolUse], tool_pattern: '^{tool}$', path_pattern: '(?i)^C:/private/token.txt$', action: block}}]");
            for encoded in [false, true] {
                for (path, expected) in [
                    (r"C:\safe\..\private\token.txt", true),
                    (r"C:\public\token.txt", false),
                ] {
                    let args = json!({"path": path});
                    let payload = if agent == "cursor" {
                        json!({"tool_name":tool, "tool_input":args, "conversation_id":"cursor-native"})
                    } else {
                        json!({"toolName":tool, "toolArgs":if encoded { json!(args.to_string()) } else { args }, "sessionId":"copilot-native"})
                    };
                    let output = crate::process(&json!({"agent":agent,"event":"preToolUse", "payload":payload, "rules_yaml":yaml})).unwrap();
                    assert_eq!(
                        output["blocked"], expected,
                        "{agent} {path} encoded={encoded}"
                    );
                    assert_eq!(output["event"]["session_id"], format!("{agent}-native"));
                    assert!(!output.to_string().contains("token.txt"));
                    if !expected {
                        assert_eq!(
                            output["response"],
                            if agent == "cursor" {
                                json!({"permission":"allow"})
                            } else {
                                json!({})
                            }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn copilot_parsing_is_scoped_to_tool_args_and_keeps_raw_content() {
        let policy = Policy::parse(
            "version: 1\nrules: [{id: path, path_pattern: '^/private/file$', action: block}]",
        )
        .unwrap();
        for args in [
            json!({"path":"/private/file"}),
            json!(r#"{"path":"/private/file"}"#),
            json!(r#"{"edits":[{"filePath":"/private/file"}]}"#),
        ] {
            let raw = json!({"toolName":"edit", "toolArgs":args, "toolResult":{"textResultForLlm":"RAW_RESULT"}});
            let normalized =
                crate::adapters::normalize("copilot", Some("preToolUse"), &raw).unwrap();
            assert!(policy.evaluate("copilot", &normalized).unwrap().block);
            assert_eq!(normalized.input, raw);
        }
        for input in [
            json!({"toolName":"bash", "toolArgs":r#"{"command":"cat /private/file"}"#}),
            json!({"toolName":"view", "toolArgs":r#"{"path":"/public/file"}"#, "prompt":r#"{"path":"/private/file"}"#}),
            json!({"toolName":"view", "toolArgs":{}, "toolResult":r#"{"path":"/private/file"}"#}),
        ] {
            let normalized =
                crate::adapters::normalize("copilot", Some("preToolUse"), &input).unwrap();
            assert!(!policy.evaluate("copilot", &normalized).unwrap().block);
        }
        // No recursive JSON parsing for another vendor's unknown string fields.
        let cursor = crate::adapters::normalize(
            "cursor",
            Some("preToolUse"),
            &json!({"tool_name":"Read", "tool_input":{}, "toolArgs":r#"{"path":"/private/file"}"#}),
        )
        .unwrap();
        assert!(!policy.evaluate("cursor", &cursor).unwrap().block);
        let content = Policy::parse(
            "version: 1\nrules: [{id: decoded, content_pattern: 'first\\nsecond', action: block}]",
        )
        .unwrap();
        let copilot = crate::adapters::normalize(
            "copilot",
            Some("preToolUse"),
            &json!({"toolName":"bash", "toolArgs":r#"{"command":"first\nsecond"}"#}),
        )
        .unwrap();
        assert!(content.evaluate("copilot", &copilot).unwrap().block);
    }

    #[test]
    fn native_tool_result_credentials_are_redacted_and_only_pretool_can_block() {
        for agent in ["cursor", "copilot"] {
            for name in ["preToolUse", "postToolUse", "postToolUseFailure"] {
                let payload = if agent == "cursor" {
                    json!({"tool_name":"Read", "tool_input":{"file_path":"/private/file"}, "tool_output":"{\"api_key\":\"SYNTHETIC_PRIVATE_VALUE\"}"})
                } else {
                    json!({"toolName":"view", "toolArgs":"{\"path\":\"/private/file\",\"api_key\":\"SYNTHETIC_PRIVATE_VALUE\"}", "toolResult":{"textResultForLlm":"RAW_RESULT", "api_key":"SYNTHETIC_PRIVATE_VALUE"}})
                };
                let output = crate::process(&json!({"agent":agent, "event":name, "payload":payload,
                    "rules_yaml":"version: 1\nrules: [{id: private, path_pattern: '^/private/file$', action: block}]", "capture_content":true})).unwrap();
                assert_eq!(output["blocked"], name == "preToolUse");
                assert_eq!(
                    output["event"]["decision"],
                    if name == "preToolUse" {
                        "block"
                    } else {
                        "would_block"
                    }
                );
                assert!(!output.to_string().contains("SYNTHETIC_PRIVATE_VALUE"));
                if name != "preToolUse" {
                    assert_eq!(output["response"], json!({}));
                }
            }
        }
    }
}
