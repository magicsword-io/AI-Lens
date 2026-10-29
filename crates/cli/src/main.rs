mod loader;
mod state;
mod telemetry;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use loader::Engine;
use serde_json::{json, Value};
use state::{absolute, Config, State};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

const MAX_INPUT: u64 = 1024 * 1024;
#[derive(Parser)]
#[command(
    version,
    about = "See what AI agents do. Learn with JSONL telemetry and cooperative hook policies."
)]
struct Cli {
    #[arg(long, global = true, default_value = ".agent-lens")]
    state: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, ValueEnum)]
enum Agent {
    Claude,
    Codex,
    Hermes,
    Gemini,
    Cursor,
    Copilot,
    Cowork,
}
impl Agent {
    fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Hermes => "hermes",
            Self::Gemini => "gemini",
            Self::Cursor => "cursor",
            Self::Copilot => "copilot",
            Self::Cowork => "cowork",
        }
    }
}
#[derive(Clone, Copy, ValueEnum)]
enum Shell {
    Posix,
    Powershell,
}
#[derive(Subcommand)]
enum Command {
    /// Import, receive, or poll observation-only AI telemetry sources.
    Telemetry(telemetry::Args),
    /// Enable collection/enforcement. No background daemon is needed.
    Start {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        rules: PathBuf,
        #[arg(long)]
        capture_content: bool,
    },
    /// Disable collection and enforcement for this state directory.
    Stop,
    /// Show persisted state (does not claim that an agent is registered).
    Status,
    /// Native agent callback: one bounded JSON object on stdin.
    Hook {
        #[arg(long)]
        agent: Agent,
        #[arg(long)]
        event: Option<String>,
    },
    /// Print a configuration snippet to review and merge into agent settings.
    Config {
        #[arg(long)]
        agent: Agent,
        #[arg(long)]
        shell: Option<Shell>,
    },
    /// Validate YAML rule syntax, selectors and regexes using the DLL.
    RulesCheck {
        #[arg(long)]
        rules: PathBuf,
    },
    /// Replay synthetic events into a separate JSONL file, without an agent.
    Demo {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        rules: Option<PathBuf>,
    },
}

fn rules(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(262145).read_to_end(&mut bytes)?;
    if bytes.len() > 262144 {
        bail!("rules file exceeds 256 KiB");
    }
    Ok(String::from_utf8(bytes)?)
}
fn validate(engine: &Engine, yaml: &str) -> Result<Value> {
    engine.call(&json!({"operation":"validate_rules","rules_yaml":yaml}))
}
fn timestamp(event: &mut Value) {
    event["timestamp"] =
        json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    event["observer"] = json!({"name":"agent-lens","version":env!("CARGO_PKG_VERSION")});
}

fn quote(value: &str, shell: Shell) -> Result<String> {
    if value.contains(['\r', '\n', '\0']) {
        bail!("command paths must not contain control characters");
    }
    Ok(match shell {
        Shell::Posix => format!("'{}'", value.replace('\'', "'\"'\"'")),
        Shell::Powershell => format!("'{}'", value.replace('\'', "''")),
    })
}

fn gemini_quote(value: &str, shell: Shell) -> Result<String> {
    // Gemini expands these macros before shell parsing, including inside quotes.
    // Emitting one in a literal path could silently select an inactive state.
    if [
        "$GEMINI_PROJECT_DIR",
        "$GEMINI_CWD",
        "$GEMINI_PLANS_DIR",
        "$GEMINI_SESSION_ID",
        "$CLAUDE_PROJECT_DIR",
    ]
    .iter()
    .any(|name| value.contains(name))
    {
        bail!("Gemini expands reserved hook variables in paths; choose executable and state paths without those variables");
    }
    quote(value, shell)
}

fn hermes_quote(value: &str, windows: bool) -> Result<String> {
    if windows {
        if value.contains('"') || value.chars().any(char::is_control) {
            bail!("invalid native Windows argv path");
        }
        // Hermes Windows split_command_line uses shlex(posix=False), then
        // removes outer quotes. Backslashes must remain unchanged here.
        Ok(format!("\"{value}\""))
    } else {
        quote(value, Shell::Posix)
    }
}

fn run(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::Telemetry(args) => telemetry::run(args)?,
        Command::Start {
            output,
            rules: policy,
            capture_content,
        } => {
            let engine = Engine::load()?;
            let policy = fs::canonicalize(policy).context("rules path must exist")?;
            validate(&engine, &rules(&policy)?)?;
            let output = state::output_path(output)?;
            if output == policy {
                bail!("output must differ from rules file");
            }
            let state = State::open(&cli.state)?;
            if output.starts_with(&state.dir) {
                bail!("choose an output outside the state directory");
            }
            let file =
                state::private_file(&output).context("output parent must exist and be writable")?;
            state::lock(&file)?;
            // Prove a write handle before activating; empty logs are valid JSONL.
            file.sync_all()?;
            state.write(&Config {
                enabled: true,
                output,
                rules: policy,
                capture_content: *capture_content,
            })?;
            println!(
                "{}",
                json!({"enabled":true,"state":state.dir,"capture_content":capture_content})
            );
        }
        Command::Stop => {
            let state = State::open(&cli.state)?;
            if let Some(mut config) = state.config()? {
                config.enabled = false;
                state.write(&config)?;
            }
            println!("{}", json!({"enabled":false,"state":state.dir}));
        }
        Command::Status => {
            let state = State::open(&cli.state)?;
            println!(
                "{}",
                json!({"state":state.dir,"config":state.config()?,"note":"state only; agent registration and delivery are not probed"})
            );
        }
        Command::RulesCheck { rules: path } => {
            let result = validate(&Engine::load()?, &rules(path)?)?;
            println!("{result}");
        }
        Command::Config { agent, shell } => {
            // Hermes invokes argv directly; Gemini selects its own host shell.
            // Both need the native dialect even when --shell was supplied.
            let native_shell = if cfg!(windows) && !matches!(agent, Agent::Hermes) {
                Shell::Powershell
            } else {
                Shell::Posix
            };
            let shell = if matches!(agent, Agent::Gemini) {
                native_shell
            } else {
                shell.unwrap_or(native_shell)
            };
            let exe = std::env::current_exe()?;
            let dir = absolute(&cli.state)?;
            let exe_text = exe.to_str().context("executable path is not UTF-8")?;
            let dir_text = dir.to_str().context("state path is not UTF-8")?;
            if matches!(agent, Agent::Copilot | Agent::Cowork) {
                // Copilot CLI and Cowork support direct execution with argument arrays.
                let result = Engine::load()?.call(&json!({
                    "operation":"config", "agent":agent.name(), "executable":exe_text,
                    "args":["--state",dir_text,"hook","--agent",agent.name()]
                }))?;
                println!("{}", serde_json::to_string_pretty(&result)?);
                return Ok(());
            }
            let command = if matches!(agent, Agent::Gemini) {
                let prefix = if matches!(shell, Shell::Powershell) {
                    "& "
                } else {
                    ""
                };
                format!(
                    "{prefix}{} --state {} hook --agent gemini",
                    gemini_quote(exe_text, shell)?,
                    gemini_quote(dir_text, shell)?
                )
            } else if matches!(agent, Agent::Hermes) {
                format!(
                    "{} --state {} hook --agent hermes",
                    hermes_quote(exe_text, cfg!(windows))?,
                    hermes_quote(dir_text, cfg!(windows))?
                )
            } else {
                let prefix = if matches!(shell, Shell::Powershell) {
                    "& "
                } else {
                    ""
                };
                format!(
                    "{prefix}{} --state {} hook --agent {}",
                    quote(exe_text, shell)?,
                    quote(dir_text, shell)?,
                    agent.name()
                )
            };
            let result = Engine::load()?
                .call(&json!({"operation":"config","agent":agent.name(),"command":command}))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Hook { agent, event } => {
            hook(cli, *agent, event.as_deref())?;
        }
        Command::Demo {
            output,
            rules: path,
        } => {
            let engine = Engine::load()?;
            let yaml = match path {
                Some(path) => rules(path)?,
                None => include_str!("../../../examples/rules/default.yaml").to_string(),
            };
            validate(&engine, &yaml)?;
            for (agent, event, payload) in [
                (
                    "claude",
                    "SessionStart",
                    json!({"session_id":"demo-claude"}),
                ),
                (
                    "claude",
                    "PreToolUse",
                    json!({"session_id":"demo-claude","tool_name":"Read","tool_input":{"file_path":"src/main.rs"}}),
                ),
                (
                    "claude",
                    "PreToolUse",
                    json!({"session_id":"demo-claude","tool_name":"Read","tool_input":{"file_path":".env"}}),
                ),
                (
                    "codex",
                    "PreToolUse",
                    json!({"session_id":"demo-codex","tool_name":"Bash","tool_input":{"command":"cat .env"}}),
                ),
                (
                    "codex",
                    "PostToolUse",
                    json!({"session_id":"demo-codex","tool_name":"Read","tool_input":{"file_path":".env"},"tool_response":"API_KEY=demonstration-only"}),
                ),
            ] {
                let mut result = engine.call(&json!({"agent":agent,"event":event,"payload":payload,"rules_yaml":yaml,"capture_content":true}))?;
                timestamp(&mut result["event"]);
                result["event"]["synthetic"] = json!(true);
                state::append(output, &result["event"])?;
            }
            println!("{}", json!({"synthetic_events":5,"output":output}));
        }
    }
    Ok(())
}

fn error_response(agent: Agent, event: Option<&str>, payload: Option<&Value>) -> Option<Value> {
    // A known pre-action must get its native deny even if the DLL/rules/log fails.
    let supplied = payload.and_then(|p| p["hook_event_name"].as_str());
    let known = [event, supplied];
    let reason = "Agent Lens failed to evaluate or record this action. Check local diagnostics.";
    match agent {
        Agent::Claude | Agent::Codex | Agent::Cowork if known.contains(&Some("PreToolUse")) => {
            Some(
                json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":reason}}),
            )
        }
        Agent::Claude | Agent::Codex if known.contains(&Some("PermissionRequest")) => Some(
            json!({"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":reason}}}),
        ),
        Agent::Gemini if known.contains(&Some("BeforeTool")) => {
            Some(json!({"decision":"deny","reason":reason}))
        }
        Agent::Hermes if known.contains(&Some("pre_tool_call")) => {
            Some(json!({"action":"block","message":reason}))
        }
        Agent::Cursor if known.contains(&Some("preToolUse")) => {
            Some(json!({"permission":"deny","user_message":reason,"agent_message":reason}))
        }
        Agent::Copilot if known.contains(&Some("preToolUse")) => {
            Some(json!({"permissionDecision":"deny","permissionDecisionReason":reason}))
        }
        _ => None,
    }
}
fn hook(cli: &Cli, agent: Agent, event: Option<&str>) -> Result<()> {
    let response = hook_response(cli, agent, event, io::stdin())?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

fn neutral_response(agent: Agent, event: Option<&str>, payload: Option<&Value>) -> Value {
    let native = payload
        .and_then(|p| p.get("hook_event_name"))
        .and_then(Value::as_str);
    if matches!(agent, Agent::Cursor)
        && [event, native]
            .iter()
            .any(|name| matches!(name, Some("preToolUse" | "subagentStart")))
    {
        // Cursor requires a valid permission schema even while Lens is inactive.
        json!({"permission":"allow"})
    } else {
        json!({})
    }
}

fn hook_response(cli: &Cli, agent: Agent, event: Option<&str>, reader: impl Read) -> Result<Value> {
    let mut raw = Vec::new();
    let read_result = reader.take(MAX_INPUT + 1).read_to_end(&mut raw);
    let payload = if raw.len() <= MAX_INPUT as usize {
        serde_json::from_slice::<Value>(&raw).ok()
    } else {
        None
    };
    let result = (|| -> Result<Value> {
        let state = State::open(&cli.state)?;
        let Some(config) = state.config()? else {
            return Ok(neutral_response(agent, event, payload.as_ref()));
        };
        if !config.enabled {
            return Ok(neutral_response(agent, event, payload.as_ref()));
        }
        read_result.context("cannot read callback input")?;
        let payload = payload
            .as_ref()
            .context("invalid or oversized callback JSON")?;
        let engine = Engine::load()?;
        let mut result = engine.call(&json!({"agent":agent.name(),"event":event,"payload":payload,"rules_yaml":rules(&config.rules)?,"capture_content":config.capture_content}))?;
        timestamp(&mut result["event"]);
        state::append(&config.output, &result["event"])?;
        Ok(result["response"].clone())
    })();
    match result {
        Ok(response) => Ok(response),
        Err(_) => {
            // Parsing errors may contain raw input. Do not echo them into agent
            // transcripts, CI logs or terminal history.
            eprintln!("agent-lens: hook evaluation/telemetry failed; check state, rules, companion library and output permissions");
            if let Some(response) = error_response(agent, event, payload.as_ref()) {
                Ok(response)
            } else {
                bail!("hook failed without a supported pre-action deny protocol");
            }
        }
    }
}
fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(&cli) {
        eprintln!("agent-lens: {err:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stdin_errors_deny_active_pre_actions_and_remain_neutral_when_stopped() {
        struct BrokenReader;
        impl Read for BrokenReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("injected read failure"))
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let cli = Cli {
            state: temp.path().join("state"),
            command: Command::Status,
        };
        for enabled in [true, false] {
            {
                let state = State::open(&cli.state).unwrap();
                state
                    .write(&Config {
                        enabled,
                        output: temp.path().join("unused.jsonl"),
                        rules: temp.path().join("unused.yaml"),
                        capture_content: false,
                    })
                    .unwrap();
            }
            for (agent, event) in [
                (Agent::Claude, "PreToolUse"),
                (Agent::Cowork, "PreToolUse"),
                (Agent::Codex, "PermissionRequest"),
                (Agent::Hermes, "pre_tool_call"),
                (Agent::Gemini, "BeforeTool"),
                (Agent::Cursor, "preToolUse"),
                (Agent::Copilot, "preToolUse"),
            ] {
                let response = hook_response(&cli, agent, Some(event), BrokenReader).unwrap();
                if enabled {
                    assert_eq!(response, error_response(agent, Some(event), None).unwrap());
                } else {
                    assert_eq!(response, neutral_response(agent, Some(event), None));
                }
            }
        }
    }

    #[test]
    fn gemini_reserved_macros_cannot_redirect_literal_paths() {
        for shell in [Shell::Posix, Shell::Powershell] {
            for name in [
                "GEMINI_PROJECT_DIR",
                "GEMINI_CWD",
                "GEMINI_PLANS_DIR",
                "GEMINI_SESSION_ID",
                "CLAUDE_PROJECT_DIR",
            ] {
                assert!(gemini_quote(&format!("/tmp/literal-${name}"), shell).is_err());
                assert!(gemini_quote(
                    &format!(r"C:\Agent Lens\${name}-suffix\agent-lens.exe"),
                    shell
                )
                .is_err());
            }
            assert_eq!(
                gemini_quote("/tmp/literal-$ordinary", shell).unwrap(),
                "'/tmp/literal-$ordinary'"
            );
            assert_eq!(
                gemini_quote("/tmp/O'Brien", shell).unwrap(),
                quote("/tmp/O'Brien", shell).unwrap()
            );
        }
    }

    #[test]
    fn native_hermes_windows_paths_keep_apostrophes_and_backslashes() {
        let path = r"C:\Users\O'Brien\state dir\";
        assert_eq!(hermes_quote(path, true).unwrap(), format!("\"{path}\""));
        assert!(hermes_quote("bad\"path", true).is_err());
        assert!(hermes_quote("bad\npath", true).is_err());
        assert_eq!(
            hermes_quote("/tmp/O'Brien", false).unwrap(),
            "'/tmp/O'\"'\"'Brien'"
        );
    }
}
