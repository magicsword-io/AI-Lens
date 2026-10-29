//! Small local OTLP/HTTP receiver. Use a production Collector for TLS/gRPC/auth.
use super::{append_events, otlp, MAX_BYTES, OTLP_SOURCES};
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(clap::Args)]
pub struct Args {
    #[arg(long)]
    source: String,
    /// Literal loopback IP and port only. Use a collector for remote sources.
    #[arg(long, default_value = "127.0.0.1:4318")]
    bind: SocketAddr,
    #[arg(long)]
    output: PathBuf,
    /// Exit after this many connections; intended for repeatable local tests.
    #[arg(long)]
    max_requests: Option<u32>,
}

struct Request {
    signal: String,
    content_type: String,
    body: Vec<u8>,
}

fn read_deadline(stream: &mut TcpStream, bytes: &mut [u8], deadline: Instant) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("request timeout")?;
        stream.set_read_timeout(Some(remaining))?;
        let read = stream.read(&mut bytes[offset..])?;
        if read == 0 {
            bail!("incomplete HTTP request");
        }
        offset += read;
    }
    Ok(())
}

fn request(stream: &mut TcpStream) -> Result<Request> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 16384 {
            bail!("HTTP headers exceed 16 KiB");
        }
        let mut byte = [0];
        read_deadline(stream, &mut byte, deadline)?;
        header.push(byte[0]);
    }
    let text = std::str::from_utf8(&header).context("invalid HTTP header")?;
    let mut lines = text.split("\r\n");
    let parts = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != "POST" || parts[2] != "HTTP/1.1" {
        bail!("only HTTP/1.1 POST is supported");
    }
    let signal = match parts[1] {
        "/v1/logs" => "logs",
        "/v1/metrics" => "metrics",
        "/v1/traces" => "traces",
        _ => bail!("unknown OTLP route"),
    }
    .to_owned();
    let mut content_type = None;
    let mut length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (key, value) = line.split_once(':').context("invalid HTTP header")?;
        let value = value.trim();
        match key.to_ascii_lowercase().as_str() {
            "content-length" => {
                if length.is_some() {
                    bail!("duplicate content length");
                }
                length = Some(value.parse::<usize>().context("invalid content length")?);
            }
            "content-type" => {
                if content_type.is_some() {
                    bail!("duplicate content type");
                }
                let value = value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                if !matches!(
                    value.as_str(),
                    "application/json" | "application/x-protobuf"
                ) {
                    bail!("unsupported OTLP content type");
                }
                content_type = Some(value);
            }
            "transfer-encoding" => {
                bail!("chunked HTTP is unsupported; configure a collector with content length")
            }
            "content-encoding" if !value.eq_ignore_ascii_case("identity") => {
                bail!("compressed OTLP is unsupported; configure compression none")
            }
            "expect" => bail!("HTTP expect is unsupported"),
            _ => {}
        }
    }
    let length = length.context("content length required")?;
    if length > MAX_BYTES {
        bail!("OTLP request exceeds 8 MiB");
    }
    let content_type = content_type.context("OTLP content type required")?;
    let mut body = vec![0; length];
    read_deadline(stream, &mut body, deadline)?;
    Ok(Request {
        signal,
        content_type,
        body,
    })
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) -> Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write!(stream,"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len())?;
    stream.write_all(body)?;
    stream.flush()?;
    // Closing a socket with unread request bytes can reset TCP and discard the
    // response on macOS. Send FIN first, then give the peer a bounded chance to
    // read it and close. Unsupported bodies are discarded, never decoded.
    stream.shutdown(Shutdown::Write)?;
    let deadline = Instant::now() + Duration::from_millis(250);
    let mut remaining = 64 * 1024;
    let mut buffer = [0; 4096];
    while remaining > 0 {
        let Some(timeout) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        if stream.set_read_timeout(Some(timeout)).is_err() {
            break;
        }
        let capacity = remaining.min(buffer.len());
        match stream.read(&mut buffer[..capacity]) {
            Ok(0) | Err(_) => break,
            Ok(read) => remaining -= read,
        }
    }
    Ok(())
}

fn handle(stream: &mut TcpStream, source: &str, output: &std::path::Path) -> Result<()> {
    let request = match request(stream) {
        Ok(r) => r,
        Err(_) => {
            respond(
                stream,
                "400 Bad Request",
                "application/json",
                b"{\"error\":\"invalid or unsupported OTLP HTTP request\"}",
            )?;
            return Ok(());
        }
    };
    let result = otlp::decode(&request.signal, &request.content_type, &request.body)
        .and_then(|value| otlp::normalize(source, &request.signal, &value));
    let events = match result {
        Ok(events) => events,
        Err(_) => {
            respond(
                stream,
                "400 Bad Request",
                "application/json",
                b"{\"error\":\"invalid OTLP payload\"}",
            )?;
            return Ok(());
        }
    };
    if append_events(output, &events).is_err() {
        respond(
            stream,
            "503 Service Unavailable",
            "application/json",
            b"{\"error\":\"telemetry output unavailable; batch not acknowledged\"}",
        )?;
        return Ok(());
    }
    // Empty protobuf Export*ServiceResponse is the valid success acknowledgment.
    let body: &[u8] = if request.content_type == "application/json" {
        b"{}"
    } else {
        b""
    };
    respond(stream, "200 OK", &request.content_type, body)
}

pub fn run(args: &Args) -> Result<()> {
    if !OTLP_SOURCES.contains(&args.source.as_str()) {
        bail!("listener requires an OTLP source; run telemetry sources");
    }
    if !args.bind.ip().is_loopback() {
        bail!("listener must bind a literal loopback IP; use a collector for remote delivery");
    }
    if args.max_requests == Some(0) {
        bail!("max requests must be positive");
    }
    let output = crate::state::output_path(&args.output)?;
    append_events(&output, &[])?;
    let listener = TcpListener::bind(args.bind).context("cannot bind OTLP listener")?;
    println!(
        "{}",
        json!({"listening":listener.local_addr()?,"source":args.source,"enforcement":"observe_only"})
    );
    std::io::stdout().flush()?;
    for (count, stream) in listener.incoming().enumerate() {
        let mut stream = stream?;
        if handle(&mut stream, &args.source, &output).is_err() {
            eprintln!("telemetry connection failed; sender should retry unacknowledged batches");
        }
        if args
            .max_requests
            .is_some_and(|max| count + 1 >= max as usize)
        {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn exchange(bytes: Vec<u8>, output: PathBuf) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle(&mut stream, "codex-otel", &output).unwrap();
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(&bytes).unwrap();
        let mut response = Vec::new();
        // Keep the request half open, as HTTP clients do while awaiting a reply.
        // An abortive close must not masquerade as a complete HTTP response.
        stream.read_to_end(&mut response).unwrap();
        drop(stream);
        worker.join().unwrap();
        response
    }
    #[test]
    fn receiver_rejects_bad_http_and_never_writes_the_payload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        for request in [
            "GET /v1/logs HTTP/1.1\r\n\r\n",
            "POST /v1/logs HTTP/1.1\r\nContent-Length: 0\r\nContent-Type: text/plain\r\n\r\n",
            "POST /v1/logs HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            "POST /v1/logs HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "POST /v1/logs HTTP/1.1\r\nContent-Encoding: gzip\r\n\r\nunread rejected body",
            "POST /v1/logs HTTP/1.1\r\nContent-Length: 8388609\r\n\r\n",
        ] {
            assert!(
                exchange(request.as_bytes().to_vec(), path.clone()).starts_with(b"HTTP/1.1 400")
            );
            assert!(!path.exists());
        }
    }
    #[test]
    fn response_cleanup_does_not_wait_indefinitely_for_a_peer_to_close() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (done, completion) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            respond(&mut stream, "400 Bad Request", "application/json", b"{}").unwrap();
            done.send(()).unwrap();
        });
        let mut peer = TcpStream::connect(addr).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).unwrap();
        assert!(response.ends_with(b"\r\n\r\n{}"));
        // The peer deliberately remains open after seeing FIN.
        completion.recv_timeout(Duration::from_secs(5)).unwrap();
        worker.join().unwrap();
    }
    #[test]
    fn failed_disk_write_is_never_acknowledged() {
        let dir = tempfile::tempdir().unwrap();
        let body = b"{\"resourceLogs\":[]}";
        let mut request=format!("POST /v1/logs HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",body.len()).into_bytes();
        request.extend_from_slice(body);
        assert!(exchange(request, dir.path().to_path_buf()).starts_with(b"HTTP/1.1 503"));
    }
}
