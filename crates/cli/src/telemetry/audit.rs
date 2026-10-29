//! Metadata-only imports of documented audit exports (never a policy decision).
//!
//! Contracts checked 2026-10-29:
//! https://cursor.com/docs/enterprise/compliance-and-monitoring.md#log-format
//! https://cursor.com/docs/account/teams/admin-api.md#get-audit-logs
//! https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization
//! https://docs.github.com/en/copilot/reference/enterprise-administrators/agentic-audit-log-events
//! https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed
//! https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/audit_logs/methods/list
//! https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities
//! https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gemini-in-workspace-apps
use super::model::{base, copy_text, text};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

const LIMIT: usize = 10_000;

pub fn normalize(source: &str, payload: &Value) -> Result<Vec<Value>> {
    ensure!(
        matches!(
            source,
            "cursor-audit"
                | "copilot-audit"
                | "copilot-session"
                | "anthropic-compliance"
                | "openai-audit"
                | "google-gemini"
        ),
        "unsupported audit source; cursor-runtime requires OTLP --signal logs or metrics"
    );
    let rows = records(source, payload)?;
    ensure!(rows.len() <= LIMIT, "audit input exceeds 10000 records");
    let mut out = Vec::new();
    for row in rows {
        ensure!(row.is_object(), "audit record must be an object");
        match source {
            "cursor-audit" => out.push(cursor(row)?),
            "copilot-audit" => {
                if let Some(event) = github(row)? {
                    out.push(event);
                }
            }
            "copilot-session" => out.push(session(row)?),
            "anthropic-compliance" => out.push(anthropic(row)?),
            "openai-audit" => out.push(openai(row)?),
            "google-gemini" => google(row, &mut out)?,
            _ => unreachable!(),
        }
        ensure!(out.len() <= LIMIT, "audit output exceeds 10000 records");
    }
    Ok(out)
}

fn records<'a>(source: &str, value: &'a Value) -> Result<Vec<&'a Value>> {
    if let Some(rows) = value.as_array() {
        return Ok(rows.iter().collect());
    }
    ensure!(value.is_object(), "expected audit object or array");
    let (envelope, identity) = match source {
        "cursor-audit" => ("events", "event_id"),
        "google-gemini" => ("items", "id"),
        "openai-audit" | "anthropic-compliance" => ("data", "id"),
        _ => return Ok(vec![value]),
    };
    if let Some(rows) = value.get(envelope) {
        ensure!(
            ["data", "events", "items"]
                .iter()
                .filter(|key| value.get(**key).is_some())
                .count()
                == 1,
            "ambiguous audit page containers"
        );
        ensure!(
            value.get(identity).is_none(),
            "ambiguous audit envelope and record"
        );
        return Ok(rows
            .as_array()
            .context("audit page records must be an array")?
            .iter()
            .collect());
    }
    // Google omits items on an empty page; require its official discriminator.
    if source == "google-gemini" && value["kind"] == "admin#reports#activities" {
        ensure!(
            value.get("id").is_none(),
            "ambiguous Google activities page"
        );
        return Ok(vec![]);
    }
    Ok(vec![value])
}

fn required(row: &Value, key: &str) -> Result<String> {
    row.get(key)
        .filter(|v| v.is_string())
        .and_then(text)
        .context("audit record lacks a safe required string")
}

fn name(row: &Value, key: &str) -> Result<String> {
    let s = required(row, key)?;
    ensure!(
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)),
        "invalid audit event type"
    );
    Ok(s)
}

fn rfc3339(row: &Value, key: &str) -> Result<Value> {
    let s = required(row, key)?;
    ensure!(
        chrono::DateTime::parse_from_rfc3339(&s).is_ok(),
        "invalid audit timestamp"
    );
    Ok(json!(s))
}

fn unix(row: &Value, key: &str) -> Result<Value> {
    let n = row
        .get(key)
        .and_then(Value::as_u64)
        .context("invalid audit Unix timestamp")?;
    Ok(json!(n))
}

fn event(source: &str, signal: &str, action: &str, id: String, timestamp: Value) -> Value {
    let mut out = base(source, signal, action);
    out["event_id"] = json!(id);
    out["timestamp"] = timestamp;
    out
}

fn fields(out: &mut Value, row: &Value, pairs: &[(&str, &str)]) {
    for (target, source) in pairs {
        copy_text(out, target, row.get(*source));
    }
}

fn cursor(row: &Value) -> Result<Value> {
    let action = name(row, "event_type")?;
    let mut out = event(
        "cursor-audit",
        "audit",
        &action,
        required(row, "event_id")?,
        rfc3339(row, "timestamp")?,
    );
    fields(
        &mut out,
        row,
        &[
            ("actor_id", "user_id"),
            ("application_type", "application_type"),
        ],
    );
    if let Some(data) = row.get("event_data") {
        ensure!(data.is_object(), "Cursor event_data must be an object");
        // No user_email, old/new values, commands, tokens, or free-form payloads.
        let mut metadata = json!({});
        fields(
            &mut metadata,
            data,
            &[
                ("team_id", "team_id"),
                ("invite_id", "invite_id"),
                ("sand_agent_id", "sand_agent_id"),
                ("role", "role"),
                ("login_type", "login_type"),
            ],
        );
        if let Some(success) = data.get("success").and_then(Value::as_bool) {
            metadata["success"] = json!(success);
        }
        out["attributes"] = metadata;
    }
    Ok(out)
}

fn github(row: &Value) -> Result<Option<Value>> {
    let action = name(row, "action")?;
    let timestamp = if row.get("@timestamp").is_some() {
        unix(row, "@timestamp")?
    } else {
        unix(row, "created_at")?
    };
    let id = required(row, "_document_id")?;
    // Copilot has a documented audit category; other organization activity is outside scope.
    if !action.starts_with("copilot.") {
        return Ok(None);
    }
    let mut out = event("copilot-audit", "audit", &action, id, timestamp);
    out["timestamp_unit"] = json!("unix_milliseconds");
    fields(
        &mut out,
        row,
        &[
            ("actor_id", "actor_id"),
            ("organization_id", "org_id"),
            ("enterprise_id", "business_id"),
            ("resource_id", "repo_id"),
            ("operation_type", "operation_type"),
        ],
    );
    Ok(Some(out))
}

fn session(row: &Value) -> Result<Value> {
    let action = name(row, "type")?;
    ensure!(
        matches!(action.as_str(), "request" | "response"),
        "Copilot streamed usage type must be request or response"
    );
    ensure!(
        row.get("user_id").is_some_and(Value::is_u64)
            && row.get("enterprise_id").is_some_and(Value::is_u64),
        "Copilot streamed usage requires numeric user/enterprise IDs"
    );
    // body is a JSON-encoded string containing raw request/response content. Never parse or retain it.
    ensure!(
        row.get("body").is_some_and(Value::is_string),
        "Copilot streamed usage requires a body string"
    );
    let endpoint = required(row, "endpoint")?;
    let mut out = event(
        "copilot-session",
        "audit",
        &action,
        required(row, "event_id")?,
        unix(row, "@timestamp")?,
    );
    out["timestamp_unit"] = json!("unix_milliseconds");
    fields(
        &mut out,
        row,
        &[("actor_id", "user_id"), ("enterprise_id", "enterprise_id")],
    );
    out["request_id"] = json!(required(row, "github_request_id")?);
    // Preserve path-only endpoints, never arbitrary URLs, query strings or user text.
    if endpoint.starts_with('/')
        && endpoint
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
    {
        out["endpoint"] = json!(endpoint);
    }
    if let Some(truncated) = row.get("truncated") {
        ensure!(
            truncated.is_boolean(),
            "Copilot truncated flag must be boolean"
        );
        out["truncated"] = truncated.clone();
    }
    Ok(out)
}

fn anthropic(row: &Value) -> Result<Value> {
    let action = name(row, "type")?;
    let mut out = event(
        "anthropic-compliance",
        "audit",
        &action,
        required(row, "id")?,
        rfc3339(row, "created_at")?,
    );
    let actor = row
        .get("actor")
        .filter(|v| v.is_object())
        .context("Compliance activity requires actor")?;
    let kind = name(actor, "type")?;
    out["actor_type"] = json!(kind);
    let id_key = match kind.as_str() {
        "user_actor" => "user_id",
        "api_actor" => "api_key_id",
        "admin_api_key_actor" => "admin_api_key_id",
        "scim_directory_sync_actor" => "directory_id",
        _ => "",
    };
    // Key IDs are identifiers, never key material. Unknown actor variants retain type only.
    if !id_key.is_empty() {
        copy_text(&mut out, "actor_id", actor.get(id_key));
    }
    fields(
        &mut out,
        row,
        &[
            ("organization_id", "organization_id"),
            ("organization_uuid", "organization_uuid"),
            ("chat_id", "claude_chat_id"),
            ("project_id", "claude_project_id"),
            ("file_id", "claude_file_id"),
        ],
    );
    Ok(out)
}

fn openai(row: &Value) -> Result<Value> {
    let action = name(row, "type")?;
    let mut out = event(
        "openai-audit",
        "audit",
        &action,
        required(row, "id")?,
        unix(row, "effective_at")?,
    );
    out["timestamp_unit"] = json!("unix_seconds");
    if let Some(actor) = row.get("actor").filter(|v| !v.is_null()) {
        ensure!(actor.is_object(), "OpenAI audit actor must be an object");
        copy_text(&mut out, "actor_type", actor.get("type"));
        for pointer in [
            "/session/user/id",
            "/api_key/user/id",
            "/api_key/service_account/id",
            "/api_key/id",
        ] {
            if let Some(id) = actor.pointer(pointer).and_then(text) {
                out["actor_id"] = json!(id);
                break;
            }
        }
    }
    copy_text(&mut out, "project_id", row.pointer("/project/id"));
    copy_text(
        &mut out,
        "resource_id",
        row.get(&action).and_then(|v| v.get("id")),
    );
    Ok(out)
}

fn google(row: &Value, out: &mut Vec<Value>) -> Result<()> {
    let id = row
        .get("id")
        .filter(|v| v.is_object())
        .context("Google activity requires id object")?;
    ensure!(
        id["applicationName"] == "gemini_in_workspace_apps",
        "Google activity is not Gemini for Workspace"
    );
    let unique = required(id, "uniqueQualifier")?;
    let time = rfc3339(id, "time")?;
    let events = row
        .get("events")
        .and_then(Value::as_array)
        .context("Google activity requires events array")?;
    ensure!(
        !events.is_empty() && out.len().saturating_add(events.len()) <= LIMIT,
        "invalid Google activity event count"
    );
    for (index, item) in events.iter().enumerate() {
        let action = name(item, "name")?;
        let mut e = event(
            "google-gemini",
            "audit",
            &action,
            unique.clone(),
            time.clone(),
        );
        // uniqueQualifier identifies the activity, not individual events within it.
        e["event_index"] = json!(index);
        copy_text(&mut e, "actor_id", row.pointer("/actor/profileId"));
        copy_text(&mut e, "customer_id", id.get("customerId"));
        copy_text(&mut e, "event_type", item.get("type"));
        out.push(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_official_fixtures_preserve_identity_and_drop_content() {
        for (source, fixture, id) in [
            (
                "cursor-audit",
                include_str!("../../../../examples/telemetry/audit-cursor.json"),
                "cursor-event-1",
            ),
            (
                "copilot-audit",
                include_str!("../../../../examples/telemetry/audit-copilot.json"),
                "github-event-1",
            ),
            (
                "copilot-session",
                include_str!("../../../../examples/telemetry/audit-copilot-session.json"),
                "session-event-1",
            ),
            (
                "anthropic-compliance",
                include_str!("../../../../examples/telemetry/audit-anthropic.json"),
                "activity-1",
            ),
            (
                "openai-audit",
                include_str!("../../../../examples/telemetry/audit-openai.json"),
                "audit-1",
            ),
            (
                "google-gemini",
                include_str!("../../../../examples/telemetry/audit-google.json"),
                "10001",
            ),
        ] {
            let input: Value = serde_json::from_str(fixture).unwrap();
            let events = normalize(source, &input).unwrap();
            assert_eq!(events.len(), 1, "{source}");
            assert_eq!(events[0]["event_id"], id);
            assert_eq!(events[0]["enforcement"], "observe_only");
            assert!(events[0].get("timestamp").is_some());
            assert!(!events[0].to_string().contains("PRIVATE"));
            // Host-split JSONL and direct arrays use the same pure adapter.
            let rows = records(source, &input).unwrap();
            assert_eq!(normalize(source, &json!([rows[0]])).unwrap().len(), 1);
            assert_eq!(normalize(source, rows[0]).unwrap().len(), 1);
        }
    }

    #[test]
    fn refuses_malformed_ambiguous_and_oversized_input() {
        for value in [
            json!(null),
            json!("body"),
            json!({}),
            json!({"data":{}}),
            json!({"id":"a", "data":[]}),
            json!({"id":"a","type":"project.created","effective_at":"now"}),
            json!({"id":"a","type":"project.created","effective_at":-1}),
        ] {
            assert!(normalize("openai-audit", &value).is_err());
        }
        assert!(normalize("openai-audit", &json!(vec![json!({}); LIMIT + 1])).is_err());
        assert!(normalize("unknown", &json!([])).is_err());
        assert!(normalize("cursor-runtime", &json!([])).is_err());
        assert!(
            normalize("google-gemini", &json!({"kind":"admin#reports#activities"}))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn github_filters_and_google_expands_without_losing_activity_id() {
        assert!(normalize(
            "copilot-audit",
            &json!({"action":"repo.create","_document_id":"r","@timestamp":123})
        )
        .unwrap()
        .is_empty());
        let mut value: Value = serde_json::from_str(include_str!(
            "../../../../examples/telemetry/audit-google.json"
        ))
        .unwrap();
        value["items"][0]["events"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"second","type":"activity"}));
        let events = normalize("google-gemini", &value).unwrap();
        assert_eq!(events[1]["event_id"], "10001");
        assert_eq!(events[1]["event_index"], 1);
    }
}
