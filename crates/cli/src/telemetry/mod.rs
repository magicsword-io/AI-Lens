//! Observation-only telemetry sources, separate from cooperative enforcement.
mod audit;
mod model;
mod otlp;
pub mod poll;
mod receiver;

use anyhow::{bail, Context, Result};
use clap::{Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub const MAX_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
pub const OTLP_SOURCES: &[&str] = &[
    "claude-code-otel",
    "claude-cowork-otel",
    "codex-otel",
    "cursor-runtime",
    "copilot-otel",
];
pub const POLL_SOURCES: &[&str] = &[
    "cursor-audit",
    "copilot-audit",
    "anthropic-compliance",
    "openai-audit",
    "google-gemini",
];

#[derive(clap::Args)]
pub struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Json,
    Jsonl,
    Protobuf,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Signal {
    Logs,
    Metrics,
    Traces,
}
impl Signal {
    pub fn name(self) -> &'static str {
        match self {
            Self::Logs => "logs",
            Self::Metrics => "metrics",
            Self::Traces => "traces",
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// List source IDs and implemented collection modes; no account probe.
    Sources,
    /// Normalize an explicit export. Raw bodies and unknown fields are omitted.
    Import {
        #[arg(long)]
        source: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value = "json")]
        format: Format,
        #[arg(long, value_enum)]
        signal: Option<Signal>,
    },
    /// Receive OTLP/HTTP on loopback in the foreground. Ctrl+C stops the listener.
    Listen(receiver::Args),
    /// Fetch a bounded snapshot using a provider admin/read-only credential.
    Poll(poll::Args),
    /// Print a template to review; never changes provider or client settings.
    Config {
        #[arg(long)]
        source: String,
    },
}

pub fn validate_source(source: &str) -> Result<()> {
    if !OTLP_SOURCES.contains(&source)
        && !POLL_SOURCES.contains(&source)
        && source != "copilot-session"
    {
        bail!("unknown telemetry source; run telemetry sources");
    }
    Ok(())
}

pub fn normalize(source: &str, signal: Option<Signal>, payload: &Value) -> Result<Vec<Value>> {
    validate_source(source)?;
    if OTLP_SOURCES.contains(&source) {
        let signal = signal.context("OTLP imports require --signal logs, metrics, or traces")?;
        otlp::normalize(source, signal.name(), payload)
    } else {
        if signal.is_some() {
            bail!("--signal applies only to OTLP sources");
        }
        audit::normalize(source, payload)
    }
}

/// Acknowledgment/checkpoint callers may advance only after this durable append.
/// A crash after output but before a checkpoint can replay events (at least once).
pub fn append_events(path: &Path, events: &[Value]) -> Result<usize> {
    append_events_avoiding(path, events, &[])
}

/// Compare open handles so hard links cannot bypass path-name collision checks.
pub fn distinct_files(left: &File, right: &File) -> Result<()> {
    let left = same_file::Handle::from_file(left.try_clone()?)?;
    let right = same_file::Handle::from_file(right.try_clone()?)?;
    if left == right {
        bail!("telemetry input, output, checkpoint and lock must be distinct files");
    }
    Ok(())
}

fn append_events_avoiding(path: &Path, events: &[Value], protected: &[&File]) -> Result<usize> {
    if events.len() > 10_000 {
        bail!("telemetry batch exceeds 10000 events");
    }
    let mut bytes = Vec::new();
    for event in events {
        let encoded = serde_json::to_vec(event)?;
        if bytes.len().saturating_add(encoded.len() + 1) > MAX_OUTPUT_BYTES {
            bail!("normalized telemetry batch exceeds 32 MiB");
        }
        bytes.extend_from_slice(&encoded);
        bytes.push(b'\n');
    }
    let mut file = crate::state::private_file(path).context("cannot open telemetry output")?;
    for guard in protected {
        distinct_files(&file, guard)?;
    }
    crate::state::lock(&file)?;
    let len = file.metadata()?.len();
    if len > 0 {
        file.seek(SeekFrom::End(-1))?;
        let mut last = [0];
        file.read_exact(&mut last)?;
        if last != *b"\n" {
            bail!("telemetry output has an incomplete final record; choose a new output file");
        }
    }
    file.seek(SeekFrom::End(0))?;
    file.write_all(&bytes)?;
    file.sync_data()?;
    // A new filename needs its directory entry synced as well as its contents.
    // Windows does not expose portable directory fsync through std::fs.
    #[cfg(unix)]
    File::open(path.parent().context("output has no parent")?)?.sync_all()?;
    Ok(events.len())
}

fn source_inventory() -> Value {
    let otlp = OTLP_SOURCES.iter().map(|source| json!({
        "id":source,"modes":["import","listen"],"transport":"OTLP/HTTP JSON or protobuf; no gRPC",
        "status":"experimental; synthetic transport tested; account delivery not verified",
        "enforcement":"observe_only"
    }));
    let polls = POLL_SOURCES.iter().map(|source| {
        json!({
            "id":source,"modes":["import","poll"],"enforcement":"observe_only",
            "status":"experimental; provider-shaped fixtures and mock HTTP; tenant access required"
        })
    });
    json!({"sources":otlp.chain(polls).chain(std::iter::once(json!({
        "id":"copilot-session","modes":["import"],"enforcement":"observe_only",
        "status":"documented streamed request/response exports; local session directories unsupported"
    }))).collect::<Vec<_>>(),"note":"Collection capabilities only, not a claim of vendor delivery or complete visibility. See docs/telemetry-sources.md."})
}

fn config(source: &str) -> Result<Value> {
    validate_source(source)?;
    let (format, template) = match source {
        "claude-code-otel" => (
            "environment",
            include_str!("../../../../examples/telemetry/configs/claude-code.env"),
        ),
        "claude-cowork-otel" => (
            "admin UI worksheet, not a vendor config file",
            include_str!("../../../../examples/telemetry/configs/claude-cowork.json"),
        ),
        "codex-otel" => (
            "toml",
            include_str!("../../../../examples/telemetry/configs/codex.toml"),
        ),
        "cursor-runtime" => (
            "admin UI worksheet, not a vendor config file",
            include_str!("../../../../examples/telemetry/configs/cursor-export.json"),
        ),
        "copilot-otel" => (
            "environment",
            include_str!("../../../../examples/telemetry/configs/copilot-otel.env"),
        ),
        _ => {
            return Ok(
                json!({"source":source,"review_only":true,"documentation":"docs/telemetry-sources.md","next_step":"Use telemetry poll --help or import an explicitly exported JSON/JSONL file. No settings changed."}),
            )
        }
    };
    Ok(
        json!({"source":source,"review_only":true,"format":format,"template":template,
        "note":"Review endpoint, privacy, plan and permissions before applying manually. Cloud/VM clients cannot reach the host listener through their own localhost."}),
    )
}

pub fn run(args: &Args) -> Result<()> {
    match &args.command {
        Commands::Sources => println!("{}", serde_json::to_string_pretty(&source_inventory())?),
        Commands::Config { source } => {
            println!("{}", serde_json::to_string_pretty(&config(source)?)?)
        }
        Commands::Listen(args) => receiver::run(args)?,
        Commands::Poll(args) => poll::run(args)?,
        Commands::Import {
            source,
            input,
            output,
            format,
            signal,
        } => {
            validate_source(source)?;
            let input = fs::canonicalize(input).context("telemetry input must exist")?;
            let output = crate::state::output_path(output)?;
            if input == output {
                bail!("telemetry input and output must differ");
            }
            let mut bytes = Vec::new();
            let mut input_file = File::open(input)?;
            Read::by_ref(&mut input_file)
                .take((MAX_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > MAX_BYTES {
                bail!("telemetry import exceeds 8 MiB; split the export");
            }
            let mut events = Vec::new();
            let mut output_bytes = 0usize;
            let mut collect = |payload: Value| -> Result<()> {
                let batch = normalize(source, *signal, &payload)?;
                for event in batch {
                    output_bytes =
                        output_bytes.saturating_add(serde_json::to_vec(&event)?.len() + 1);
                    if events.len() >= 10_000 || output_bytes > MAX_OUTPUT_BYTES {
                        bail!("telemetry import exceeds normalized batch limits");
                    }
                    events.push(event);
                }
                Ok(())
            };
            match format {
                Format::Json => collect(
                    serde_json::from_slice(&bytes)
                        .map_err(|_| anyhow::anyhow!("invalid telemetry JSON"))?,
                )?,
                Format::Jsonl => {
                    for line in bytes
                        .split(|b| *b == b'\n')
                        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
                    {
                        collect(
                            serde_json::from_slice(line)
                                .map_err(|_| anyhow::anyhow!("invalid telemetry JSONL record"))?,
                        )?;
                    }
                }
                Format::Protobuf => {
                    if !OTLP_SOURCES.contains(&source.as_str()) {
                        bail!("protobuf applies only to OTLP sources");
                    }
                    let signal = signal.context("protobuf imports require --signal")?;
                    collect(otlp::decode(
                        signal.name(),
                        "application/x-protobuf",
                        &bytes,
                    )?)?;
                }
            }
            let written = append_events_avoiding(&output, &events, &[&input_file])?;
            println!(
                "{}",
                json!({"source":source,"events_written":written,"enforcement":"observe_only"})
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn append_rejects_partial_logs_and_preserves_the_original() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        fs::write(&path, b"partial").unwrap();
        assert!(append_events(&path, &[json!({"ok":true})]).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"partial");
        fs::write(&path, b"").unwrap();
        assert_eq!(append_events(&path, &[json!({"ok":true})]).unwrap(), 1);
        assert_eq!(fs::read(&path).unwrap(), b"{\"ok\":true}\n");
    }
    #[test]
    fn append_compares_open_file_identity_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("source.json");
        let alias = dir.path().join("output.jsonl");
        let original = b"{\"source\":true}\n";
        fs::write(&input, original).unwrap();
        fs::hard_link(&input, &alias).unwrap();
        let guard = File::open(&input).unwrap();
        assert!(append_events_avoiding(&alias, &[json!({"event":true})], &[&guard]).is_err());
        assert_eq!(fs::read(&input).unwrap(), original);
        let separate = dir.path().join("separate.jsonl");
        assert_eq!(
            append_events_avoiding(&separate, &[json!({"event":true})], &[&guard]).unwrap(),
            1
        );
        assert_eq!(fs::read(&input).unwrap(), original);
        assert_eq!(fs::read(separate).unwrap(), b"{\"event\":true}\n");
    }
    #[test]
    fn source_inventory_is_explicit_and_configs_are_review_only() {
        let inventory = source_inventory();
        assert_eq!(inventory["sources"].as_array().unwrap().len(), 11);
        for item in inventory["sources"].as_array().unwrap() {
            let source = item["id"].as_str().unwrap();
            validate_source(source).unwrap();
            assert_eq!(config(source).unwrap()["review_only"], true);
        }
        assert!(validate_source("unknown").is_err());
    }
}
