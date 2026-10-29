//! Bounded, read-only snapshots. Credentials never appear in URLs or diagnostics.
//! Provider contracts (checked 2026-10-29):
//! https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/audit_logs/methods/list
//! https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization
//! https://docs.github.com/en/rest/enterprise-admin/audit-log#get-the-audit-log-for-an-enterprise
//! https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list
//! https://cursor.com/docs/account/teams/admin-api.md#get-audit-logs
//! https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed
use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;

#[derive(clap::Args)]
pub struct Args {
    #[arg(long)]
    pub source: String,
    #[arg(long)]
    pub output: PathBuf,
    /// Environment variable NAME, never a raw credential. Defaults depend on source.
    #[arg(long)]
    pub token_env: Option<String>,
    /// GitHub organization slug (mutually exclusive with enterprise).
    #[arg(long)]
    pub organization: Option<String>,
    /// GitHub enterprise slug (mutually exclusive with organization).
    #[arg(long)]
    pub enterprise: Option<String>,
    /// Inclusive RFC3339 lower bound; defaults to seven days before until.
    #[arg(long)]
    pub since: Option<String>,
    /// Inclusive RFC3339 upper bound; defaults to now and is frozen in checkpoints.
    #[arg(long)]
    pub until: Option<String>,
    /// Resume this fixed snapshot; use a new checkpoint for a new time window.
    #[arg(long)]
    pub checkpoint: Option<PathBuf>,
    #[arg(long, default_value_t = 100)]
    pub max_pages: usize,
    /// Offline tests only: HTTP loopback IP URL; uses a dummy token, never environment credentials.
    #[arg(long)]
    pub test_endpoint: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u8,
    binding: Value,
    start: String,
    end: String,
    cursor: Option<String>,
    done: bool,
    output_len: u64,
    seen: Vec<String>,
}

struct Provider {
    source: String,
    endpoint: Url,
    token_env: &'static str,
}

impl Provider {
    fn new(args: &Args) -> Result<Self> {
        let (endpoint, token_env) = match args.source.as_str() {
            "openai-audit" => ("https://api.openai.com/v1/organization/audit_logs".into(), "OPENAI_ADMIN_KEY"),
            "anthropic-compliance" => ("https://api.anthropic.com/v1/compliance/activities".into(), "ANTHROPIC_COMPLIANCE_ACCESS_KEY"),
            "google-gemini" => ("https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/gemini_in_workspace_apps".into(), "GOOGLE_ACCESS_TOKEN"),
            "cursor-audit" => ("https://api.cursor.com/teams/audit-logs".into(), "CURSOR_ADMIN_API_KEY"),
            "copilot-audit" => {
                let (kind, slug) = match (&args.organization, &args.enterprise) {
                    (Some(s), None) => ("orgs", s), (None, Some(s)) => ("enterprises", s),
                    _ => bail!("Copilot audit requires exactly one of --organization or --enterprise"),
                };
                ensure!(!slug.is_empty() && slug.len() <= 100 && slug.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'), "invalid GitHub scope slug");
                (format!("https://api.github.com/{kind}/{slug}/audit-log"), "GITHUB_TOKEN")
            }
            _ => bail!("source does not expose a supported polling API; use telemetry import"),
        };
        if args.source != "copilot-audit" {
            ensure!(
                args.organization.is_none() && args.enterprise.is_none(),
                "organization/enterprise flags apply only to Copilot audit"
            );
        }
        let endpoint = if let Some(endpoint) = &args.test_endpoint {
            ensure!(
                args.token_env.is_none(),
                "test endpoint uses a dummy credential; omit --token-env"
            );
            let url = Url::parse(endpoint).map_err(|_| anyhow!("invalid test endpoint"))?;
            let loopback = match url.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                _ => false,
            };
            ensure!(url.scheme() == "http" && loopback && url.username().is_empty() && url.password().is_none()
                && url.query().is_none() && url.fragment().is_none(), "test endpoint must be HTTP on a loopback IP with no credentials, query, or fragment");
            url
        } else {
            Url::parse(&endpoint).expect("constant official endpoint")
        };
        Ok(Self {
            source: args.source.clone(),
            endpoint,
            token_env,
        })
    }

    fn url(&self, cp: &Checkpoint) -> Result<Url> {
        let mut url = self.endpoint.clone();
        let mut q = url.query_pairs_mut();
        let start =
            DateTime::parse_from_rfc3339(&cp.start).context("invalid checkpoint start time")?;
        let end = DateTime::parse_from_rfc3339(&cp.end).context("invalid checkpoint end time")?;
        match self.source.as_str() {
            "openai-audit" => {
                q.append_pair("limit", "100")
                    .append_pair(
                        "effective_at[gte]",
                        &(start.timestamp() + i64::from(start.timestamp_subsec_nanos() > 0))
                            .to_string(),
                    )
                    .append_pair("effective_at[lte]", &end.timestamp().to_string());
                if let Some(c) = &cp.cursor {
                    q.append_pair("after", c);
                }
            }
            "anthropic-compliance" => {
                q.append_pair("limit", "100")
                    .append_pair("created_at.gte", &cp.start)
                    .append_pair("created_at.lte", &cp.end);
                if let Some(c) = &cp.cursor {
                    q.append_pair("after_id", c);
                }
            }
            "google-gemini" => {
                q.append_pair("maxResults", "100")
                    .append_pair("startTime", &cp.start)
                    .append_pair("endTime", &cp.end);
                if let Some(c) = &cp.cursor {
                    q.append_pair("pageToken", c);
                }
            }
            "cursor-audit" => {
                q.append_pair("pageSize", "100")
                    .append_pair("startTime", &cp.start)
                    .append_pair("endTime", &cp.end)
                    .append_pair("page", cp.cursor.as_deref().unwrap_or("1"));
            }
            "copilot-audit" => {
                q.append_pair("per_page", "100")
                    .append_pair("include", "all")
                    .append_pair("order", "asc")
                    .append_pair(
                        "phrase",
                        &format!("action:copilot created:>={} created:<={}", cp.start, cp.end),
                    );
                if let Some(c) = &cp.cursor {
                    q.append_pair("after", c);
                }
            }
            _ => unreachable!(),
        }
        drop(q);
        Ok(url)
    }

    fn next(
        &self,
        page: &Value,
        link: Option<&str>,
        current: Option<&str>,
    ) -> Result<Option<String>> {
        match self.source.as_str() {
            "openai-audit" | "anthropic-compliance" => {
                ensure!(
                    page.get("data").is_some_and(Value::is_array),
                    "provider page requires data array"
                );
                let more = page
                    .get("has_more")
                    .and_then(Value::as_bool)
                    .context("provider page requires has_more")?;
                if !more {
                    return Ok(None);
                }
                let next =
                    cursor(page.get("last_id"))?.context("provider continuation lacks last_id")?;
                ensure!(
                    page["data"]
                        .as_array()
                        .unwrap()
                        .last()
                        .and_then(|v| v["id"].as_str())
                        == Some(next.as_str()),
                    "provider last_id does not match final record"
                );
                Ok(Some(next))
            }
            "google-gemini" => {
                ensure!(
                    page["kind"] == "admin#reports#activities",
                    "invalid Google activities page"
                );
                cursor(page.get("nextPageToken"))
            }
            "cursor-audit" => {
                let pagination = &page["pagination"];
                let page_number = pagination["page"]
                    .as_u64()
                    .context("Cursor page number missing")?;
                let expected = current
                    .unwrap_or("1")
                    .parse::<u64>()
                    .context("invalid Cursor page cursor")?;
                ensure!(
                    page_number == expected,
                    "Cursor returned an unexpected page"
                );
                let more = pagination["hasNextPage"]
                    .as_bool()
                    .context("Cursor pagination flag missing")?;
                if more {
                    Ok(Some(
                        page_number
                            .checked_add(1)
                            .context("Cursor page overflow")?
                            .to_string(),
                    ))
                } else {
                    Ok(None)
                }
            }
            "copilot-audit" => {
                ensure!(page.is_array(), "GitHub audit response must be an array");
                let mut next = None;
                for part in link
                    .unwrap_or("")
                    .split(',')
                    .filter(|s| !s.trim().is_empty())
                {
                    let (target, params) = part
                        .split_once(';')
                        .context("malformed GitHub pagination link")?;
                    if !params
                        .split(';')
                        .any(|p| matches!(p.trim(), "rel=\"next\"" | "rel=next"))
                    {
                        continue;
                    }
                    ensure!(next.is_none(), "ambiguous GitHub next links");
                    let target = target
                        .trim()
                        .strip_prefix('<')
                        .and_then(|s| s.strip_suffix('>'))
                        .context("malformed GitHub next link")?;
                    let url =
                        Url::parse(target).map_err(|_| anyhow!("malformed GitHub next link"))?;
                    ensure!(
                        url.origin() == self.endpoint.origin()
                            && url.path() == self.endpoint.path()
                            && url.username().is_empty()
                            && url.password().is_none()
                            && url.fragment().is_none(),
                        "unsafe GitHub next link"
                    );
                    let cursors: Vec<_> = url.query_pairs().filter(|(k, _)| k == "after").collect();
                    ensure!(
                        cursors.len() == 1 && !url.query_pairs().any(|(k, _)| k == "before"),
                        "GitHub next link requires one after cursor"
                    );
                    next = cursor(Some(&json!(cursors[0].1)))?;
                }
                // Extract only the cursor; all origin/path/filter parameters are rebuilt locally.
                Ok(next)
            }
            _ => unreachable!(),
        }
    }
}

fn cursor(value: Option<&Value>) -> Result<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s))
            if !s.is_empty() && s.len() <= 2048 && !s.chars().any(char::is_control) =>
        {
            Ok(Some(s.clone()))
        }
        _ => bail!("invalid provider continuation cursor"),
    }
}

fn token(args: &Args, provider: &Provider) -> Result<String> {
    if args.test_endpoint.is_some() {
        return Ok("agent-lens-offline-test".into());
    }
    let name = args.token_env.as_deref().unwrap_or(provider.token_env);
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "invalid token environment variable name"
    );
    let value = std::env::var(name).map_err(|_| {
        anyhow!("required credential environment variable is missing or non-Unicode")
    })?;
    ensure!(
        !value.is_empty()
            && value.len() <= 8192
            && value.bytes().all(|b| b.is_ascii_graphic())
            && (provider.source != "cursor-audit" || !value.contains(':')),
        "credential is empty or invalid for HTTP authentication"
    );
    Ok(value)
}

fn fetch(
    agent: &ureq::Agent,
    provider: &Provider,
    cp: &Checkpoint,
    token: &str,
) -> Result<(Value, Option<String>)> {
    let url = provider.url(cp)?;
    let request = agent
        .get(url.as_str())
        .header("Accept", "application/json")
        .header("User-Agent", "agent-lens-telemetry");
    let request = match provider.source.as_str() {
        "cursor-audit" => request.header(
            "Authorization",
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{token}:"))
            ),
        ),
        "anthropic-compliance" => request
            .header("x-api-key", token)
            .header("anthropic-version", "2023-06-01"),
        "copilot-audit" => request
            .header("Authorization", format!("Bearer {token}"))
            .header("X-GitHub-Api-Version", "2022-11-28"),
        _ => request.header("Authorization", format!("Bearer {token}")),
    };
    let mut response = request.call().map_err(|_| {
        anyhow!(
            "audit request failed (transport or timeout); checkpoint unchanged; retry explicitly"
        )
    })?;
    let status = response.status().as_u16();
    ensure!(
        status == 200,
        "audit HTTP status {status}; checkpoint unchanged; check credentials/scope or retry later"
    );
    let links: Vec<_> = response
        .headers()
        .get_all("link")
        .iter()
        .map(|h| h.to_str())
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| anyhow!("invalid pagination header"))?;
    let link = if links.is_empty() {
        None
    } else {
        Some(links.join(","))
    };
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("cannot read provider response; checkpoint unchanged"))?;
    ensure!(
        bytes.len() <= 8 * 1024 * 1024,
        "provider response exceeds 8 MiB"
    );
    let page = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow!("provider returned malformed JSON; checkpoint unchanged"))?;
    Ok((page, link))
}

fn save(path: &Path, cp: &Checkpoint) -> Result<()> {
    let mut temp =
        tempfile::NamedTempFile::new_in(path.parent().context("checkpoint has no parent")?)?;
    serde_json::to_writer(&mut temp, cp)?;
    temp.write_all(b"\n")?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|_| anyhow!("cannot persist checkpoint; output may replay on retry"))?;
    #[cfg(unix)]
    fs::File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

pub fn run(args: &Args) -> Result<()> {
    ensure!(
        (1..=1000).contains(&args.max_pages),
        "max-pages must be between 1 and 1000"
    );
    let provider = Provider::new(args)?;
    let output = crate::state::output_path(&args.output)?;
    let checkpoint = args
        .checkpoint
        .as_deref()
        .map(crate::state::output_path)
        .transpose()?;
    ensure!(
        checkpoint.as_ref() != Some(&output),
        "checkpoint and output must differ"
    );
    let output_guard = open_existing(&output)?;
    let checkpoint_guard = checkpoint
        .as_deref()
        .map(open_existing)
        .transpose()?
        .flatten();
    if let (Some(output), Some(checkpoint)) = (&output_guard, &checkpoint_guard) {
        super::distinct_files(output, checkpoint)?;
    }
    // Keep a stable sidecar inode locked across atomic checkpoint replacement.
    let _lock = if let Some(path) = &checkpoint {
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock_path = crate::state::output_path(Path::new(&lock_name))?;
        ensure!(
            lock_path != output,
            "checkpoint lock and output must differ"
        );
        let file = crate::state::private_file(&lock_path)?;
        for other in output_guard.iter().chain(checkpoint_guard.iter()) {
            super::distinct_files(&file, other)?;
        }
        crate::state::lock(&file)?;
        Some(file)
    } else {
        None
    };
    // Windows cannot replace an open checkpoint with MoveFileEx. Initial
    // identity checks are complete; reopen it only around each guarded append.
    // The separate sidecar remains locked throughout checkpoint replacement.
    drop(checkpoint_guard);
    let binding = json!({"source":args.source,"organization":args.organization,"enterprise":args.enterprise,
        "output":output,"endpoint":provider.endpoint.as_str(),"since":args.since,"until":args.until});
    let mut cp = if let Some(path) = checkpoint.as_ref().filter(|p| p.exists()) {
        ensure!(
            fs::metadata(path)?.len() <= 4 * 1024 * 1024,
            "checkpoint too large"
        );
        let cp: Checkpoint =
            serde_json::from_slice(&fs::read(path)?).map_err(|_| anyhow!("invalid checkpoint"))?;
        ensure!(
            cp.version == 1 && cp.binding == binding && cp.seen.len() <= 10_000,
            "checkpoint does not match this snapshot/output"
        );
        cursor(cp.cursor.as_ref().map(|s| json!(s)).as_ref())?;
        let retained = fs::metadata(&output).map(|m| m.len()).unwrap_or(0);
        ensure!(
            retained >= cp.output_len,
            "checkpoint output was removed or truncated"
        );
        cp
    } else {
        let end = args
            .until
            .as_deref()
            .map(DateTime::parse_from_rfc3339)
            .transpose()
            .map_err(|_| anyhow!("until must be RFC3339"))?
            .map(|v| v.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let start = args
            .since
            .as_deref()
            .map(DateTime::parse_from_rfc3339)
            .transpose()
            .map_err(|_| anyhow!("since must be RFC3339"))?
            .map(|v| v.with_timezone(&Utc))
            .unwrap_or(end - chrono::Duration::days(7));
        ensure!(start <= end, "since must not be after until");
        ensure!(
            provider.source != "cursor-audit" || end - start <= chrono::Duration::days(30),
            "Cursor supports at most 30 days per snapshot"
        );
        Checkpoint {
            version: 1,
            binding,
            start: start.to_rfc3339_opts(SecondsFormat::AutoSi, true),
            end: end.to_rfc3339_opts(SecondsFormat::AutoSi, true),
            cursor: None,
            done: false,
            output_len: 0,
            seen: vec![],
        }
    };
    if cp.done {
        return Ok(());
    }
    let credential = token(args, &provider)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .timeout_connect(Some(Duration::from_secs(10)))
        .proxy(None)
        .build()
        .into();
    let mut seen: HashSet<String> = cp.seen.iter().cloned().collect();
    let mut count = 0usize;
    for _ in 0..args.max_pages {
        ensure!(
            seen.insert(cp.cursor.clone().unwrap_or_default()),
            "repeated pagination cursor; checkpoint unchanged"
        );
        let (page, link) = fetch(&agent, &provider, &cp, &credential)?;
        let next = provider.next(&page, link.as_deref(), cp.cursor.as_deref())?;
        ensure!(
            !next.as_ref().is_some_and(|c| seen.contains(c)),
            "repeated pagination cursor; checkpoint unchanged"
        );
        let events = super::audit::normalize(&args.source, &page)?;
        count = count.saturating_add(events.len());
        ensure!(
            count <= 10_000,
            "poll exceeds 10000 events per invocation; resume with checkpoint"
        );
        // Host locks output and syncs it before returning. A crash between append and
        // checkpoint persistence can replay the last page: event IDs permit deduplication.
        {
            let current_checkpoint = checkpoint
                .as_deref()
                .map(open_existing)
                .transpose()?
                .flatten();
            let protected: Vec<_> = _lock.iter().chain(current_checkpoint.iter()).collect();
            super::append_events_avoiding(&output, &events, &protected)?;
        }
        cp.output_len = match fs::metadata(&output) {
            Ok(metadata) => metadata.len(),
            Err(error) if events.is_empty() && error.kind() == std::io::ErrorKind::NotFound => {
                cp.output_len
            }
            Err(_) => bail!("cannot verify durable output; checkpoint unchanged"),
        };
        cp.cursor = next;
        cp.done = cp.cursor.is_none();
        cp.seen = seen.iter().cloned().collect();
        ensure!(cp.seen.len() <= 10_000, "snapshot exceeds 10000 pages");
        if let Some(path) = &checkpoint {
            save(path, &cp)?;
        }
        if cp.done {
            return Ok(());
        }
    }
    bail!("page limit reached; resume the same checkpoint to continue this snapshot")
}

fn open_existing(path: &Path) -> Result<Option<fs::File>> {
    match fs::File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("cannot open telemetry file identity guard"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::BufRead,
        net::TcpListener,
        sync::{Arc, Mutex},
        thread,
    };

    fn args(dir: &Path, source: &str) -> Args {
        Args {
            source: source.into(),
            output: dir.join("out.jsonl"),
            token_env: None,
            organization: if source == "copilot-audit" {
                Some("synthetic-org".into())
            } else {
                None
            },
            enterprise: None,
            since: Some("2026-10-01T00:00:00Z".into()),
            until: Some("2026-10-02T00:00:00Z".into()),
            checkpoint: Some(dir.join("checkpoint.json")),
            max_pages: 100,
            test_endpoint: None,
        }
    }
    fn page(id: &str, more: bool) -> String {
        json!({"data":[{"id":id,"type":"project.created","effective_at":1790812800}],"has_more":more,"last_id":id}).to_string()
    }
    type Requests = Arc<Mutex<Vec<String>>>;
    fn server(replies: Vec<(u16, String, String)>) -> (String, Requests, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/audit", listener.local_addr().unwrap());
        let recorded: Requests = Arc::default();
        let capture = recorded.clone();
        let server_endpoint = endpoint.clone();
        let handle = thread::spawn(move || {
            for (status, headers, body) in replies {
                let headers = headers.replace("TEST_ENDPOINT", &server_endpoint);
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "expected audit request did not arrive"
                            );
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("audit test accept failed: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    request.push_str(&line);
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                capture.lock().unwrap().push(request);
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}", body.len()).unwrap();
            }
        });
        (endpoint, recorded, handle)
    }

    #[test]
    fn http_pagination_checkpoint_resume_and_completed_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let (url, requests, handle) = server(vec![
            (200, String::new(), page("audit-1", true)),
            (200, String::new(), page("audit-2", false)),
        ]);
        let mut a = args(dir.path(), "openai-audit");
        a.test_endpoint = Some(url);
        a.max_pages = 1;
        assert!(run(&a).unwrap_err().to_string().contains("page limit"));
        let cp: Value =
            serde_json::from_slice(&fs::read(a.checkpoint.as_ref().unwrap()).unwrap()).unwrap();
        assert_eq!(cp["cursor"], "audit-1");
        assert_eq!(fs::read_to_string(&a.output).unwrap().lines().count(), 1);
        run(&a).unwrap();
        run(&a).unwrap();
        handle.join().unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET /audit?"));
        assert!(requests[0]
            .to_lowercase()
            .contains("authorization: bearer agent-lens-offline-test"));
        assert!(!requests[0].contains("after="));
        assert!(requests[1].contains("after=audit-1"));
        assert!(requests[0].contains("effective_at%5Bgte%5D="));
        assert_eq!(fs::read_to_string(&a.output).unwrap().lines().count(), 2);
        a.since = Some("2026-10-01T01:00:00Z".into());
        assert!(run(&a).unwrap_err().to_string().contains("does not match"));
    }

    #[test]
    fn hard_linked_output_checkpoint_and_lock_are_rejected_before_polling() {
        for (left, right) in [
            ("out.jsonl", "checkpoint.json"),
            ("out.jsonl", "checkpoint.json.lock"),
            ("checkpoint.json", "checkpoint.json.lock"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let original = b"{\"fixture\":true}\n";
            fs::write(dir.path().join(left), original).unwrap();
            fs::hard_link(dir.path().join(left), dir.path().join(right)).unwrap();
            let a = args(dir.path(), "openai-audit");
            assert!(run(&a).unwrap_err().to_string().contains("distinct files"));
            assert_eq!(fs::read(dir.path().join(left)).unwrap(), original);
            assert_eq!(fs::read(dir.path().join(right)).unwrap(), original);
        }
    }

    #[test]
    fn auth_http_errors_redirects_and_malformed_json_do_not_advance_checkpoint() {
        for (status, headers, body) in [
            (401, "", "PRIVATE_BODY"),
            (429, "", "PRIVATE_BODY"),
            (500, "", "PRIVATE_BODY"),
            (302, "Location: http://127.0.0.1:1/leak\r\n", "PRIVATE_BODY"),
            (200, "", "PRIVATE_BODY"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (url, _, handle) = server(vec![(status, headers.into(), body.into())]);
            let mut a = args(dir.path(), "openai-audit");
            a.test_endpoint = Some(url);
            let error = format!("{:#}", run(&a).unwrap_err());
            handle.join().unwrap();
            assert!(!error.contains("PRIVATE") && !error.contains("http://"));
            assert!(!a.checkpoint.unwrap().exists());
            assert!(!a.output.exists());
        }
        let dir = tempfile::tempdir().unwrap();
        let mut a = args(dir.path(), "openai-audit");
        a.token_env = Some("AGENT_LENS_DEFINITELY_UNSET_AUDIT_TEST".into());
        assert!(token(&a, &Provider::new(&a).unwrap()).is_err());
    }

    #[test]
    fn redirect_cannot_forward_authentication_to_another_listener() {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let headers = format!(
            "Location: http://{}/steal\r\n",
            destination.local_addr().unwrap()
        );
        let (url, requests, handle) = server(vec![(302, headers, String::new())]);
        let dir = tempfile::tempdir().unwrap();
        let mut a = args(dir.path(), "openai-audit");
        a.test_endpoint = Some(url);
        assert!(run(&a).is_err());
        handle.join().unwrap();
        assert!(requests.lock().unwrap()[0]
            .to_lowercase()
            .contains("authorization: bearer agent-lens-offline-test"));
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(!a.checkpoint.unwrap().exists());
    }

    #[test]
    fn repeated_cursor_and_partial_error_keep_last_durable_page() {
        for second in [
            (200, String::new(), page("audit-1", true)),
            (503, String::new(), "PRIVATE_BODY".into()),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (url, _, handle) =
                server(vec![(200, String::new(), page("audit-1", true)), second]);
            let mut a = args(dir.path(), "openai-audit");
            a.test_endpoint = Some(url);
            assert!(run(&a).is_err());
            handle.join().unwrap();
            let cp: Value =
                serde_json::from_slice(&fs::read(a.checkpoint.unwrap()).unwrap()).unwrap();
            assert_eq!(cp["cursor"], "audit-1");
            assert_eq!(cp["done"], false);
            assert_eq!(fs::read_to_string(a.output).unwrap().lines().count(), 1);
        }
    }

    #[test]
    fn failed_output_does_not_create_or_advance_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let (url, requests, handle) = server(vec![(200, String::new(), page("audit-1", false))]);
        let mut a = args(dir.path(), "openai-audit");
        a.test_endpoint = Some(url);
        // Opening this ordinary file succeeds on every OS; appending the fetched
        // page must then fail because the existing final record is incomplete.
        // A directory instead fails before HTTP on Windows and deadlocks a mock
        // that expects a request before join.
        fs::write(&a.output, b"incomplete-record").unwrap();
        assert!(run(&a)
            .unwrap_err()
            .to_string()
            .contains("incomplete final record"));
        handle.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 1);
        assert_eq!(fs::read(&a.output).unwrap(), b"incomplete-record");
        assert!(!a.checkpoint.unwrap().exists());
    }

    #[test]
    fn output_failure_preserves_existing_checkpoint_and_lock_excludes_other_pollers() {
        let dir = tempfile::tempdir().unwrap();
        let (url, _, handle) = server(vec![
            (200, String::new(), page("audit-1", true)),
            (200, String::new(), page("audit-2", false)),
        ]);
        let mut a = args(dir.path(), "openai-audit");
        a.test_endpoint = Some(url);
        a.max_pages = 1;
        assert!(run(&a).is_err());
        let path = a.checkpoint.as_ref().unwrap();
        let before = fs::read(path).unwrap();
        let mut output = fs::OpenOptions::new().append(true).open(&a.output).unwrap();
        output.write_all(b"incomplete-record").unwrap();
        drop(output);
        assert!(run(&a).is_err());
        handle.join().unwrap();
        assert_eq!(fs::read(path).unwrap(), before);
        let lock_path = PathBuf::from(format!("{}.lock", path.display()));
        let lock = crate::state::private_file(&lock_path).unwrap();
        crate::state::lock(&lock).unwrap();
        assert!(run(&a).unwrap_err().to_string().contains("lock"));
    }

    #[test]
    fn each_provider_paginates_over_http() {
        for (source, fixture, query) in [
            (
                "anthropic-compliance",
                include_str!("../../../../examples/telemetry/audit-anthropic.json"),
                "after_id=activity-1",
            ),
            (
                "cursor-audit",
                include_str!("../../../../examples/telemetry/audit-cursor.json"),
                "page=2",
            ),
            (
                "google-gemini",
                include_str!("../../../../examples/telemetry/audit-google.json"),
                "pageToken=opaque-token",
            ),
            (
                "copilot-audit",
                include_str!("../../../../examples/telemetry/audit-copilot.json"),
                "after=opaque%2Bcursor",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut first: Value = serde_json::from_str(fixture).unwrap();
            let mut second = first.clone();
            let headers = match source {
                "anthropic-compliance" => {
                    first["has_more"] = json!(true);
                    ""
                }
                "cursor-audit" => {
                    first["pagination"]["hasNextPage"] = json!(true);
                    second["pagination"]["page"] = json!(2);
                    ""
                }
                "google-gemini" => {
                    first["nextPageToken"] = json!("opaque-token");
                    ""
                }
                _ => "Link: <TEST_ENDPOINT?after=opaque%2Bcursor>; rel=\"next\"\r\n",
            };
            let (url, requests, handle) = server(vec![
                (200, headers.into(), first.to_string()),
                (200, String::new(), second.to_string()),
            ]);
            let mut a = args(dir.path(), source);
            a.test_endpoint = Some(url);
            run(&a).unwrap();
            handle.join().unwrap();
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 2);
            assert!(requests[1].contains(query), "{source}");
            assert_eq!(fs::read_to_string(&a.output).unwrap().lines().count(), 2);
            fs::write(&a.output, "").unwrap();
            assert!(run(&a).unwrap_err().to_string().contains("truncated"));
        }
    }

    #[test]
    fn endpoint_constraints_and_import_only_sources() {
        let dir = tempfile::tempdir().unwrap();
        for endpoint in [
            "https://127.0.0.1/",
            "http://localhost/",
            "http://example.com/",
            "http://127.0.0.1.evil.test/",
            "http://127.0.0.1/?secret=x",
            "http://127.0.0.1/#x",
            "http://user:pass@127.0.0.1/",
            "http://[::2]/",
        ] {
            let mut a = args(dir.path(), "openai-audit");
            a.test_endpoint = Some(endpoint.into());
            assert!(Provider::new(&a).is_err(), "{endpoint}");
        }
        for source in ["cursor-runtime", "copilot-session", "unknown"] {
            assert!(Provider::new(&args(dir.path(), source)).is_err());
        }
        let mut a = args(dir.path(), "copilot-audit");
        a.enterprise = Some("synthetic-enterprise".into());
        assert!(Provider::new(&a).is_err());
        a.organization = None;
        assert_eq!(
            Provider::new(&a).unwrap().endpoint.path(),
            "/enterprises/synthetic-enterprise/audit-log"
        );
    }

    #[test]
    fn provider_headers_and_continuations_match_contracts() {
        let dir = tempfile::tempdir().unwrap();
        for (source, body, header, query) in [
            (
                "anthropic-compliance",
                include_str!("../../../../examples/telemetry/audit-anthropic.json"),
                "x-api-key: agent-lens-offline-test",
                "created_at.gte=",
            ),
            (
                "cursor-audit",
                include_str!("../../../../examples/telemetry/audit-cursor.json"),
                "authorization: basic ",
                "page=1",
            ),
            (
                "google-gemini",
                include_str!("../../../../examples/telemetry/audit-google.json"),
                "authorization: bearer ",
                "startTime=",
            ),
            (
                "copilot-audit",
                include_str!("../../../../examples/telemetry/audit-copilot.json"),
                "x-github-api-version: 2022-11-28",
                "phrase=action%3Acopilot",
            ),
        ] {
            let (url, requests, handle) = server(vec![(200, String::new(), body.into())]);
            let mut a = args(dir.path(), source);
            a.test_endpoint = Some(url);
            a.checkpoint = None;
            run(&a).unwrap();
            handle.join().unwrap();
            let request = requests.lock().unwrap()[0].to_lowercase();
            assert!(request.contains(header));
            assert!(request.contains(&query.to_lowercase()));
            if source == "anthropic-compliance" {
                assert!(request.contains("anthropic-version: 2023-06-01"));
            }
            if source == "cursor-audit" {
                assert!(request.contains(
                    &base64::engine::general_purpose::STANDARD
                        .encode("agent-lens-offline-test:")
                        .to_lowercase()
                ));
            }
        }
        let a = args(dir.path(), "copilot-audit");
        let provider = Provider::new(&a).unwrap();
        let link = format!(
            "<{}?after=opaque%2Bcursor&order=desc>; rel=\"next\"",
            provider.endpoint
        );
        assert_eq!(
            provider.next(&json!([]), Some(&link), None).unwrap(),
            Some("opaque+cursor".into())
        );
        for link in [
            "<https://evil.test/steal?after=abc>; rel=\"next\"",
            "<https://api.github.com/wrong?after=abc>; rel=\"next\"",
            "<https://api.github.com/orgs/synthetic-org/audit-log?after=a&after=b>; rel=\"next\"",
        ] {
            assert!(provider.next(&json!([]), Some(link), None).is_err());
        }
        let google = Provider::new(&args(dir.path(), "google-gemini")).unwrap();
        assert_eq!(
            google
                .next(
                    &json!({"kind":"admin#reports#activities","nextPageToken":"token-2"}),
                    None,
                    None
                )
                .unwrap(),
            Some("token-2".into())
        );
        let cursor = Provider::new(&args(dir.path(), "cursor-audit")).unwrap();
        assert_eq!(
            cursor
                .next(
                    &json!({"pagination":{"page":1,"hasNextPage":true}}),
                    None,
                    None
                )
                .unwrap(),
            Some("2".into())
        );
        assert!(cursor
            .next(
                &json!({"pagination":{"page":1,"hasNextPage":true}}),
                None,
                Some("2")
            )
            .is_err());
    }
}
