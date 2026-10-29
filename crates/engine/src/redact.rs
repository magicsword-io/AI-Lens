use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

const REDACTED: &str = "[REDACTED]";

// Fixed, bounded regex programs. Policy matching always uses the original input.
static CREDENTIALS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
        r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+",
        r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{8,}",
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,})",
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        r"\b(?:xox[baprs]-[A-Za-z0-9-]{8,}|glpat-[A-Za-z0-9_-]{8,})",
        r#"(?i)\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|aws[_-]?secret[_-]?access[_-]?key|authorization|cookie)["']?\s*[:=]\s*(?:"(?:\\.|[^"\\\r\n])*"|'[^'\r\n]*'|[^\s,;\]}]+)"#,
        r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@",
    ]
    .into_iter()
    .map(|pattern| Regex::new(pattern).expect("fixed credential regex must compile"))
    .collect()
});

/// Conservatively detect credentials in metadata as well as captured content.
pub(crate) fn contains_credential(value: &str) -> bool {
    CREDENTIALS.iter().any(|regex| regex.is_match(value))
}

/// Prevent a secret stored under a sensitive key from being copied into an ID.
pub(crate) fn references_sensitive_value(candidate: &str, input: &Value) -> bool {
    fn visit(candidate: &str, input: &Value, sensitive: bool) -> bool {
        match input {
            Value::String(value) => sensitive && !value.is_empty() && candidate.contains(value),
            Value::Number(value) if sensitive => candidate.contains(&value.to_string()),
            Value::Object(object) => object
                .iter()
                .any(|(key, value)| visit(candidate, value, sensitive || sensitive_key(key))),
            Value::Array(array) => array.iter().any(|value| visit(candidate, value, sensitive)),
            _ => false,
        }
    }
    visit(candidate, input, false)
}

pub(crate) fn redact(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| {
                    let value = if sensitive_key(key) {
                        Value::String(REDACTED.into())
                    } else {
                        redact(value)
                    };
                    // Credential-shaped object keys are content too.
                    (redact_text(key), value)
                })
                .collect(),
        ),
        Value::Array(array) => Value::Array(array.iter().map(redact).collect()),
        Value::String(string) => Value::String(redact_text(string)),
        other => other.clone(),
    }
}

fn sensitive_key(key: &str) -> bool {
    let key: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    matches!(key.as_str(), "key" | "auth" | "bearer")
        || [
            "password",
            "passwd",
            "secret",
            "secrets",
            "token",
            "tokens",
            "apikey",
            "privatekey",
            "sshkey",
            "signingkey",
            "encryptionkey",
            "passphrase",
            "credential",
            "credentials",
            "authorization",
            "authentication",
            "cookie",
            "connectionstring",
            "accesskey",
            "accesskeyid",
        ]
        .iter()
        .any(|suffix| key.ends_with(suffix))
}

fn redact_text(value: &str) -> String {
    CREDENTIALS.iter().fold(value.to_owned(), |text, regex| {
        regex.replace_all(&text, REDACTED).into_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn al006_sensitive_keys_redact_every_value_type_recursively() {
        let input = json!({
            "PASSWORD": "synthetic-one",
            "nested": [{"api-Key": 12345, "clientSecret": {"part": "synthetic-two"}}],
            "auth": {"Authorization": "synthetic-three", "refresh_token": ["synthetic-four"]},
            "private_key": null,
            "safe": "ordinary tool output",
        });
        let output = redact(&input);
        assert_eq!(output["PASSWORD"], REDACTED);
        assert_eq!(output["nested"][0]["api-Key"], REDACTED);
        assert_eq!(output["nested"][0]["clientSecret"], REDACTED);
        // A sensitive container is removed in full, including every descendant.
        assert_eq!(output["auth"], REDACTED);
        assert_eq!(output["private_key"], REDACTED);
        assert_eq!(output["safe"], "ordinary tool output");
        assert!(!output.to_string().contains("synthetic-"));
    }

    #[test]
    fn credentials_in_unstructured_content_and_object_keys_are_redacted() {
        let examples = [
            "Bearer syntheticcredential",
            "Basic c3ludGhldGljOmZpeHR1cmU=",
            "sk-proj-syntheticfixture123456",
            "ghp_syntheticfixture1234567890",
            "github_pat_syntheticfixture1234567890",
            "AKIAABCDEFGHIJKLMNOP",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.signature",
            "xoxb-synthetic-fixture12345",
            "glpat-syntheticfixture12345",
            "password='synthetic secret'",
            "API_KEY=syntheticfixture",
            "https://fixture:syntheticpassword@example.invalid/path",
            "-----BEGIN PRIVATE KEY-----\nsyntheticfixture\n-----END PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----\nsyntheticfixture",
        ];
        for credential in examples {
            assert!(
                contains_credential(credential),
                "fixture credential undetected"
            );
            let output =
                redact(&json!({"text": format!("before {credential} after"), credential: "value"}));
            assert!(!output.to_string().contains(credential));
            assert!(output.to_string().contains(REDACTED));
        }
        assert!(!contains_credential("ordinary tool output"));
        assert_eq!(
            redact(&json!({"safe": "ordinary tool output", "count": 3})),
            json!({"safe": "ordinary tool output", "count": 3})
        );
    }

    #[test]
    fn quoted_json_credentials_in_tool_output_are_redacted() {
        for text in [
            r#"{"api_key":"SYNTHETIC_JSON_CREDENTIAL"}"#,
            r#"{"api_key":"prefix\"SYNTHETIC_JSON_CREDENTIAL"}"#,
            r#"prefix {"password" : "SYNTHETIC_JSON_CREDENTIAL"} suffix"#,
            "'token': 'SYNTHETIC_JSON_CREDENTIAL'",
            r#"{"client_secret":"SYNTHETIC_JSON_CREDENTIAL with spaces"}"#,
        ] {
            assert!(contains_credential(text));
            assert!(!redact_text(text).contains("SYNTHETIC_JSON_CREDENTIAL"));
        }
        assert_eq!(
            redact_text(r#"{"message":"ordinary"}"#),
            r#"{"message":"ordinary"}"#
        );
    }

    #[test]
    fn structured_redaction_is_idempotent() {
        let input = json!({"api_key": "synthetic", "text": "token=synthetic", "safe": [true, 42]});
        let once = redact(&input);
        assert_eq!(redact(&once), once);
    }
}
