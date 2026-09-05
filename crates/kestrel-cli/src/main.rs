#![deny(clippy::undocumented_unsafe_blocks)]
use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::io::Write;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::Message};

// ---------------------------------------------------------------------------
// Helpers: human size parsing, cpus -> cpu.max
// ---------------------------------------------------------------------------

/// Parse human-readable memory size like "512m", "1.5g", "1024", "1kB".
/// Returns bytes as i64. Supports k,m,g,t (case-insensitive), optional trailing 'b',
/// float values.
pub fn parse_human_size(s: &str) -> Result<i64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty size string");
    }
    // Find split between numeric part and suffix
    let mut num_end = 0;
    for (i, c) in s.char_indices() {
        if c.is_ascii_digit() || c == '.' || c == '-' {
            num_end = i + c.len_utf8();
        } else {
            break;
        }
    }
    if num_end == 0 {
        anyhow::bail!("invalid size: {s:?}");
    }
    let num_str = &s[..num_end];
    let suffix = s[num_end..].trim().to_ascii_lowercase();
    let suffix = suffix.trim_end_matches('b');
    let num: f64 = num_str
        .parse()
        .with_context(|| format!("invalid size number: {num_str:?}"))?;
    let mult: f64 = match suffix {
        "" => 1.0,
        "k" | "kb" => 1024.0,
        "m" | "mb" => 1024.0 * 1024.0,
        "g" | "gb" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        other => anyhow::bail!("unknown size suffix: {other:?} in {s:?}"),
    };
    let bytes = (num * mult).round() as i64;
    if bytes < 0 {
        anyhow::bail!("size must be non-negative: {s:?}");
    }
    Ok(bytes)
}

/// Convert --cpus value like "1.5" into cpu.max string "150000 100000" or "max 100000".
/// Period defaults to 100000 (cgroup v2 default).
pub fn cpus_to_cpu_max(cpus_str: &str, period: u64) -> Result<String> {
    let cpus: f64 = cpus_str
        .parse()
        .with_context(|| format!("invalid --cpus value: {cpus_str:?}"))?;
    if cpus <= 0.0 {
        return Ok(format!("max {period}"));
    }
    let quota = (cpus * period as f64).round() as i64;
    Ok(format!("{quota} {period}"))
}

fn parse_port_mapping(s: &str) -> Result<(u16, u16)> {
    // Accept "host:container" or "hostPort:containerPort"
    if let Some((h, c)) = s.split_once(':') {
        let hp: u16 = h
            .parse()
            .with_context(|| format!("invalid host port: {h:?}"))?;
        let cp: u16 = c
            .parse()
            .with_context(|| format!("invalid container port: {c:?}"))?;
        Ok((hp, cp))
    } else {
        let p: u16 = s.parse().with_context(|| format!("invalid port: {s:?}"))?;
        Ok((p, p))
    }
}

// ---------------------------------------------------------------------------
// Global CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "kestrel", version, about = "kestrel container runtime CLI", long_about = None)]
struct Cli {
    /// Daemon address (http://host:port or unix socket path). Env KESTREL_HOST overrides.
    #[arg(
        long,
        global = true,
        env = "KESTREL_HOST",
        default_value = "http://127.0.0.1:7777"
    )]
    host: String,

    /// Verbose output
    #[arg(long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create and start a container (create+start+attach, optionally --rm)
    Run(RunArgs),
    /// Create a container (does not start)
    Create(CreateArgs),
    /// Start a created container
    Start { id: String },
    /// Stop a running container (SIGTERM -> SIGKILL)
    Stop {
        id: String,
        #[arg(long = "time", short = 't', default_value_t = 10)]
        timeout: u64,
    },
    /// Kill a container with a signal
    Kill {
        id: String,
        #[arg(default_value = "SIGTERM")]
        signal: String,
        #[arg(long)]
        all: bool,
    },
    /// Delete a container
    #[command(alias = "rm")]
    Delete {
        id: String,
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// Execute a command inside a running container
    Exec(ExecArgs),
    /// List containers
    Ps(PsArgs),
    /// Fetch logs
    Logs(LogsArgs),
    /// Inspect a container (full JSON)
    Inspect(InspectArgs),
    /// Stream container stats
    Stats(StatsArgs),
    /// List images
    Images,
    /// Pull an image
    Pull { reference: String },
    /// Remove image
    Rmi { reference: String },
    /// Show image history/layers
    History { reference: String },
    /// Namespace introspection
    Ns(NsArgs),
    /// Diff filesystem vs image
    Diff { id: String },
    /// Show copy-up events
    Copyups { id: String },
    /// Show PSI pressure
    Pressure(PressureArgs),
    /// Show capabilities
    Caps { id: String },
    /// Show seccomp profile + violations
    Seccomp { id: String },
    /// Network subcommands
    Net(NetArgs),
    /// Explain container creation steps
    Explain { id: String },
    /// Restart container (stop+start)
    Restart { id: String },
    /// Pause container (cgroup freeze)
    Pause { id: String },
    /// Unpause container
    Unpause { id: String },
    /// Generate shell completions
    Completion {
        #[arg(value_enum)]
        shell: ShellArg,
    },
    /// Show server topology (bridges, veth, NAT)
    Topology,
}

#[derive(ValueEnum, Clone)]
enum ShellArg {
    Bash,
    Zsh,
    Fish,
    Elvish,
    Powershell,
}

impl From<ShellArg> for Shell {
    fn from(s: ShellArg) -> Shell {
        match s {
            ShellArg::Bash => Shell::Bash,
            ShellArg::Zsh => Shell::Zsh,
            ShellArg::Fish => Shell::Fish,
            ShellArg::Elvish => Shell::Elvish,
            ShellArg::Powershell => Shell::PowerShell,
        }
    }
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Run detached (do not attach)
    #[arg(short = 'd', long)]
    detach: bool,
    /// Container name
    #[arg(long)]
    name: Option<String>,
    #[arg(short = 'p', long = "publish")]
    publish: Vec<String>,
    #[arg(short = 'v', long = "volume")]
    volume: Vec<String>,
    #[arg(short = 'e', long = "env")]
    env: Vec<String>,
    /// Automatically remove container on exit
    #[arg(long)]
    rm: bool,
    #[arg(long)]
    memory: Option<String>,
    #[arg(long = "memory-reservation")]
    memory_reservation: Option<String>,
    #[arg(long)]
    cpus: Option<String>,
    #[arg(long = "cpu-shares")]
    cpu_shares: Option<u64>,
    #[arg(long = "pids-limit")]
    pids_limit: Option<i64>,
    #[arg(long = "cap-add")]
    cap_add: Vec<String>,
    #[arg(long = "cap-drop")]
    cap_drop: Vec<String>,
    #[arg(long)]
    network: Option<String>,
    #[arg(long)]
    user: Option<String>,
    #[arg(long)]
    workdir: Option<String>,
    #[arg(long)]
    hostname: Option<String>,
    #[arg(long = "read-only")]
    read_only: bool,
    #[arg(long = "security-opt")]
    security_opt: Vec<String>,
    /// Allocate a TTY
    #[arg(short = 't', long = "tty")]
    tty: bool,
    /// Keep STDIN open
    #[arg(short = 'i', long = "interactive")]
    interactive: bool,

    /// Image reference
    image: String,
    /// Command override
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    cmd: Vec<String>,
}

#[derive(Parser, Debug)]
struct CreateArgs {
    #[arg(long)]
    name: Option<String>,
    #[arg(short = 'p', long = "publish")]
    publish: Vec<String>,
    #[arg(short = 'v', long = "volume")]
    volume: Vec<String>,
    #[arg(short = 'e', long = "env")]
    env: Vec<String>,
    #[arg(long)]
    memory: Option<String>,
    #[arg(long = "memory-reservation")]
    memory_reservation: Option<String>,
    #[arg(long)]
    cpus: Option<String>,
    #[arg(long = "cpu-shares")]
    cpu_shares: Option<u64>,
    #[arg(long = "pids-limit")]
    pids_limit: Option<i64>,
    #[arg(long = "cap-add")]
    cap_add: Vec<String>,
    #[arg(long = "cap-drop")]
    cap_drop: Vec<String>,
    #[arg(long)]
    network: Option<String>,
    #[arg(long)]
    user: Option<String>,
    #[arg(long)]
    workdir: Option<String>,
    #[arg(long)]
    hostname: Option<String>,
    #[arg(long = "read-only")]
    read_only: bool,
    #[arg(long = "security-opt")]
    security_opt: Vec<String>,
    #[arg(short = 't', long = "tty")]
    tty: bool,
    image: String,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    cmd: Vec<String>,
}

#[derive(Parser, Debug)]
struct ExecArgs {
    id: String,
    #[arg(short = 'i', long)]
    interactive: bool,
    #[arg(short = 't', long)]
    tty: bool,
    #[arg(long = "user")]
    user: Option<String>,
    #[arg(short = 'e', long = "env")]
    env: Vec<String>,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    cmd: Vec<String>,
}

#[derive(Parser, Debug)]
struct PsArgs {
    #[arg(short = 'a', long = "all")]
    all: bool,
    #[arg(long)]
    filter: Vec<String>,
    #[arg(long, default_value = "table")]
    format: String,
    #[arg(long)]
    quiet: bool,
}

#[derive(Parser, Debug)]
struct LogsArgs {
    id: String,
    #[arg(short = 'f', long)]
    follow: bool,
    #[arg(long)]
    tail: Option<usize>,
    #[arg(long)]
    since: Option<String>,
}

#[derive(Parser, Debug)]
struct InspectArgs {
    id: String,
    #[arg(long)]
    format: Option<String>,
}

#[derive(Parser, Debug)]
struct StatsArgs {
    #[arg(long = "no-stream")]
    no_stream: bool,
    ids: Vec<String>,
}

#[derive(Parser, Debug)]
struct NsArgs {
    /// Container ID, or "tree" for host-wide graph
    target: Option<String>,
}

#[derive(Parser, Debug)]
struct PressureArgs {
    id: String,
    #[arg(long)]
    watch: bool,
}

#[derive(Parser, Debug)]
struct NetArgs {
    #[command(subcommand)]
    command: NetCommand,
}

#[derive(Subcommand, Debug)]
enum NetCommand {
    Topology,
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

fn base_url(host: &str) -> String {
    // If host is a unix socket path (starts with / or unix://), we still use http fallback
    if host.starts_with('/') || host.starts_with("unix://") {
        // reqwest cannot do UDS without custom connector; fallback to tcp
        eprintln!("warning: unix socket {host} requested; using the daemon's TCP fallback at http://127.0.0.1:7777");
        return "http://127.0.0.1:7777".to_string();
    }
    let mut h = host.trim_end_matches('/').to_string();
    if !h.starts_with("http://") && !h.starts_with("https://") {
        h = format!("http://{h}");
    }
    h
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .expect("build reqwest client")
}

#[derive(Serialize)]
struct CreateRequest<'a> {
    image: Option<&'a str>,
    cmd: Option<&'a Vec<String>>,
    env: Option<&'a Vec<String>>,
    tty: bool,
    memory_bytes: Option<i64>,
    pids_limit: Option<i64>,
    network_mode: Option<&'a str>,
    published_ports: Vec<(u16, u16)>,
}

fn build_create_request<'a>(
    image: &'a str,
    cmd: &'a Vec<String>,
    args: &'a RunArgs,
) -> Result<(CreateRequest<'a>, Vec<(u16, u16)>)> {
    let memory_bytes = if let Some(m) = &args.memory {
        Some(parse_human_size(m)?)
    } else {
        None
    };
    let _cpu_max = if let Some(c) = &args.cpus {
        let s = cpus_to_cpu_max(c, 100_000)?;
        // For daemon we translate cpus into memory_bytes/pids but currently only those fields exist.
        // We log the derived cpu.max for visibility.
        eprintln!("info: --cpus {c} => cpu.max {s}");
        None::<String>
    } else {
        None
    };
    let mut ports = Vec::new();
    for p in &args.publish {
        ports.push(parse_port_mapping(p)?);
    }
    let cmd_opt = if cmd.is_empty() { None } else { Some(cmd) };
    let env_opt = if args.env.is_empty() {
        None
    } else {
        Some(&args.env)
    };
    Ok((
        CreateRequest {
            image: Some(image),
            cmd: cmd_opt,
            env: env_opt,
            tty: args.tty,
            memory_bytes,
            pids_limit: args.pids_limit,
            network_mode: args.network.as_deref(),
            published_ports: ports.clone(),
        },
        ports,
    ))
}

fn build_create_request_from_create<'a>(
    image: &'a str,
    cmd: &'a Vec<String>,
    args: &'a CreateArgs,
) -> Result<CreateRequest<'a>> {
    let memory_bytes = if let Some(m) = &args.memory {
        Some(parse_human_size(m)?)
    } else {
        None
    };
    if let Some(c) = &args.cpus {
        let s = cpus_to_cpu_max(c, 100_000)?;
        eprintln!("info: --cpus {c} => cpu.max {s}");
    }
    let mut ports = Vec::new();
    for p in &args.publish {
        ports.push(parse_port_mapping(p)?);
    }
    let cmd_opt = if cmd.is_empty() { None } else { Some(cmd) };
    let env_opt = if args.env.is_empty() {
        None
    } else {
        Some(&args.env)
    };
    Ok(CreateRequest {
        image: Some(image),
        cmd: cmd_opt,
        env: env_opt,
        tty: args.tty,
        memory_bytes,
        pids_limit: args.pids_limit,
        network_mode: args.network.as_deref(),
        published_ports: ports,
    })
}

// ---------------------------------------------------------------------------
// Command impls
// ---------------------------------------------------------------------------

async fn do_create(host: &str, req: CreateRequest<'_>) -> Result<String> {
    let url = format!("{}/containers", base_url(host));
    let resp = client()
        .post(&url)
        .json(&req)
        .send()
        .await
        .context("POST /containers")?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("create failed {}: {body}", status);
    }
    let v: serde_json::Value = serde_json::from_str(&body)?;
    let id = v
        .get("id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow::anyhow!("no id in response: {body}"))?;
    Ok(id.to_string())
}

async fn do_start(host: &str, id: &str) -> Result<()> {
    let url = format!("{}/containers/{id}/start", base_url(host));
    let resp = client().post(&url).send().await.context("POST start")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("start failed {}: {body}", status);
    }
    Ok(())
}

async fn do_delete(host: &str, id: &str, force: bool) -> Result<()> {
    let url = if force {
        format!("{}/containers/{id}?force=true", base_url(host))
    } else {
        format!("{}/containers/{id}", base_url(host))
    };
    let resp = client().delete(&url).send().await.context("DELETE")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("delete failed {}: {body}", status);
    }
    Ok(())
}

async fn do_ps(host: &str, args: &PsArgs) -> Result<()> {
    let url = format!("{}/containers", base_url(host));
    let resp = client().get(&url).send().await.context("GET /containers")?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("ps failed {}: {body}", status);
    }
    let value: serde_json::Value = serde_json::from_str(&body)?;
    let arr = if value.is_array() {
        value.as_array().cloned().unwrap_or_default()
    } else if let Some(v) = value.get("containers").and_then(|x| x.as_array()) {
        v.clone()
    } else {
        vec![value.clone()]
    };

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&arr)?);
        return Ok(());
    }
    if args.quiet {
        for c in &arr {
            if let Some(id) = c.get("id").and_then(|x| x.as_str()) {
                println!("{id}");
            }
        }
        return Ok(());
    }
    // table
    println!(
        "{:<16} {:<10} {:<8} {:<20} COMMAND",
        "CONTAINER ID", "STATUS", "PID", "IMAGE"
    );
    for c in &arr {
        let id = c.get("id").and_then(|x| x.as_str()).unwrap_or("-");
        let short = if id.len() > 12 { &id[..12] } else { id };
        let status = c.get("status").and_then(|x| x.as_str()).unwrap_or("-");
        let pid = c
            .get("pid")
            .map(|x| x.to_string())
            .unwrap_or_else(|| "-".to_string());
        let image = c
            .get("image")
            .or_else(|| c.get("bundle"))
            .map(|x| x.to_string())
            .unwrap_or_else(|| "-".to_string());
        // truncate image display
        let image_disp = image.trim_matches('"');
        println!(
            "{:<16} {:<10} {:<8} {:<20} ",
            short,
            status,
            pid,
            truncate(image_disp, 20)
        );
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n - 1])
    }
}

async fn do_logs(host: &str, args: &LogsArgs) -> Result<()> {
    let mut url = format!("{}/containers/{}/logs", base_url(host), args.id);
    let mut qs = Vec::new();
    if args.follow {
        qs.push("follow=true".to_string());
    }
    if let Some(t) = args.tail {
        qs.push(format!("tail={t}"));
    }
    if let Some(s) = &args.since {
        qs.push(format!("since={}", urlencoding(s)));
    }
    if !qs.is_empty() {
        url.push('?');
        url.push_str(&qs.join("&"));
    }
    if args.follow {
        // SSE streaming: just stream bytes to stdout
        let resp = client().get(&url).send().await.context("GET logs")?;
        if !resp.status().is_success() {
            let st = resp.status();
            let b = resp.text().await.unwrap_or_default();
            anyhow::bail!("logs failed {st}: {b}");
        }
        let mut stream = resp.bytes_stream();
        use futures_util::StreamExt;
        let mut stdout = std::io::stdout();
        while let Some(chunk) = stream.next().await {
            let bytes = chunk?;
            stdout.write_all(&bytes)?;
            stdout.flush()?;
        }
        return Ok(());
    }
    let resp = client().get(&url).send().await.context("GET logs")?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("logs failed {}: {body}", status);
    }
    print!("{body}");
    // ensure trailing newline
    if !body.ends_with('\n') && !body.is_empty() {
        println!();
    }
    Ok(())
}

fn urlencoding(s: &str) -> String {
    // minimal url encode
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn do_inspect(host: &str, id: &str) -> Result<serde_json::Value> {
    let url = format!("{}/containers/{id}", base_url(host));
    let resp = client().get(&url).send().await.context("GET inspect")?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("inspect failed {}: {body}", status);
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body.clone()));
    Ok(v)
}

async fn fetch_json(host: &str, path: &str) -> Result<serde_json::Value> {
    let resp = client()
        .get(format!("{}{}", base_url(host), path))
        .send()
        .await
        .with_context(|| format!("GET {path}"))?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("GET {path} failed {status}: {body}");
    }
    Ok(serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body)))
}

fn render_template(template: &str, value: &serde_json::Value) -> String {
    let mut output = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        output.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find("}}") else {
            output.push_str(&rest[start..]);
            return output;
        };
        let expression = after_start[..end].trim();
        let path = expression.strip_prefix('.').unwrap_or(expression);
        let resolved = path
            .split('.')
            .filter(|part| !part.is_empty())
            .try_fold(value, |current, part| current.get(part));
        if let Some(resolved) = resolved {
            let rendered = match resolved {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            output.push_str(&rendered);
        }
        rest = &after_start[end + 2..];
    }
    output.push_str(rest);
    output
}

async fn do_explain(host: &str, id: &str) -> Result<()> {
    let inspect = fetch_json(host, &format!("/containers/{id}")).await?;
    println!(
        "Container {}",
        inspect.get("id").and_then(|v| v.as_str()).unwrap_or(id)
    );
    println!(
        "  state: {}",
        inspect.get("status").unwrap_or(&serde_json::Value::Null)
    );
    if let Some(pid) = inspect.get("pid") {
        println!("  pid: {pid}");
    }
    for (label, path) in [
        ("namespaces", "/namespaces"),
        ("cgroup resources", "/cgroup"),
        ("mounts", "/mounts"),
        ("network", "/network"),
    ] {
        match fetch_json(host, &format!("/containers/{id}{path}")).await {
            Ok(value) => {
                println!("\n{label}:");
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
            Err(error) => eprintln!("  {label}: unavailable ({error})"),
        }
    }
    Ok(())
}

fn websocket_url(host: &str, path: &str) -> String {
    let base = base_url(host);
    let base = base
        .strip_prefix("http://")
        .or_else(|| base.strip_prefix("https://"))
        .unwrap_or(&base);
    let scheme = if host.starts_with("https://") {
        "wss"
    } else {
        "ws"
    };
    format!("{scheme}://{base}{path}")
}

async fn stream_attach(host: &str, id: &str, send_input: bool) -> Result<()> {
    let url = websocket_url(host, &format!("/containers/{id}/attach"));
    let (socket, _) = connect_async(&url)
        .await
        .with_context(|| format!("connecting to attach websocket {url}"))?;
    let (mut sink, mut stream) = socket.split();
    let input_task = if send_input {
        Some(tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 8192];
            loop {
                let n = match stdin.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if sink
                    .send(Message::Binary(buf[..n].to_vec().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = sink.close().await;
        }))
    } else {
        None
    };

    let mut stdout = tokio::io::stdout();
    while let Some(message) = stream.next().await {
        match message.context("reading attach websocket")? {
            Message::Binary(bytes) => {
                stdout.write_all(&bytes).await?;
                stdout.flush().await?;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    if let Some(task) = input_task {
        task.abort();
    }
    Ok(())
}

async fn tokio_tungstenite_attempt(
    host: &str,
    id: &str,
    cmd: &[String],
    tty: bool,
    send_input: bool,
) -> Result<Option<i32>> {
    let url = websocket_url(host, &format!("/containers/{id}/exec"));
    let (mut socket, _) = connect_async(&url)
        .await
        .with_context(|| format!("connecting to exec websocket {url}"))?;
    socket
        .send(Message::Text(
            serde_json::json!({ "cmd": cmd, "tty": tty })
                .to_string()
                .into(),
        ))
        .await
        .context("sending exec init message")?;
    let (mut sink, mut stream) = socket.split();
    let input_task = if send_input {
        Some(tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 8192];
            loop {
                let n = match stdin.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if sink
                    .send(Message::Binary(buf[..n].to_vec().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = sink.close().await;
        }))
    } else {
        None
    };

    let mut stdout = tokio::io::stdout();
    let mut exit_code = None;
    while let Some(message) = stream.next().await {
        match message.context("reading exec websocket")? {
            Message::Binary(bytes) => {
                stdout.write_all(&bytes).await?;
                stdout.flush().await?;
            }
            Message::Text(text) => {
                let value: serde_json::Value = serde_json::from_str(&text)
                    .with_context(|| format!("parsing exec control message: {text}"))?;
                match value.get("type").and_then(|v| v.as_str()) {
                    Some("exit") => {
                        exit_code = value
                            .get("exit_code")
                            .and_then(|v| v.as_i64())
                            .map(|v| v as i32);
                        break;
                    }
                    Some("error") => anyhow::bail!(
                        "exec failed: {}",
                        value
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown error")
                    ),
                    _ => {}
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    if let Some(task) = input_task {
        task.abort();
    }
    Ok(exit_code)
}

async fn do_stats(host: &str, args: &StatsArgs) -> Result<()> {
    let ids = if args.ids.is_empty() {
        // list all
        let url = format!("{}/containers", base_url(host));
        let resp = client()
            .get(&url)
            .send()
            .await
            .context("GET containers for stats")?;
        let body = resp.text().await?;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
        let arr = if v.is_array() {
            v.as_array().cloned().unwrap_or_default()
        } else {
            vec![]
        };
        arr.iter()
            .filter_map(|c| c.get("id").and_then(|x| x.as_str()).map(|s| s.to_string()))
            .collect::<Vec<_>>()
    } else {
        args.ids.clone()
    };

    let print_once = |id: &str,
                      cgroup_body: &serde_json::Value,
                      pressure_body: Option<&serde_json::Value>| {
        println!("== {} ==", id);
        println!(
            "{}",
            serde_json::to_string_pretty(cgroup_body).unwrap_or_else(|_| cgroup_body.to_string())
        );
        if let Some(p) = pressure_body {
            println!(
                "pressure: {}",
                serde_json::to_string_pretty(p).unwrap_or_else(|_| p.to_string())
            );
        }
    };

    loop {
        for id in &ids {
            let cgroup_url = format!("{}/containers/{id}/cgroup", base_url(host));
            let pressure_url = format!("{}/containers/{id}/pressure", base_url(host));
            let cgroup_resp = client().get(&cgroup_url).send().await;
            let pressure_resp = client().get(&pressure_url).send().await;
            let cgroup_json: serde_json::Value = match cgroup_resp {
                Ok(r) if r.status().is_success() => {
                    let t = r.text().await.unwrap_or_default();
                    serde_json::from_str(&t).unwrap_or(serde_json::Value::String(t))
                }
                Ok(r) => serde_json::json!({"error": r.status().to_string()}),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            let pressure_json: Option<serde_json::Value> = match pressure_resp {
                Ok(r) if r.status().is_success() => {
                    let t = r.text().await.unwrap_or_default();
                    Some(serde_json::from_str(&t).unwrap_or(serde_json::Value::String(t)))
                }
                _ => None,
            };
            print_once(id, &cgroup_json, pressure_json.as_ref());
        }
        if args.no_stream {
            break;
        }
        // Stream mode continuously refreshes until interrupted.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Ok(())
}

async fn do_images(host: &str) -> Result<()> {
    let url = format!("{}/images", base_url(host));
    let resp = client().get(&url).send().await.context("GET /images")?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("images failed {}: {body}", status);
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body.clone()));
    // pretty table if possible
    if let Some(arr) = v.get("images").and_then(|x| x.as_array()) {
        println!("{:<40} {:<16} {:<8} SIZE", "REFERENCE", "DIGEST", "LAYERS");
        for img in arr {
            let reference = img.get("reference").and_then(|x| x.as_str()).unwrap_or("-");
            let digest = img
                .get("manifest_digest")
                .and_then(|x| x.as_str())
                .unwrap_or("-");
            let short = if digest.len() > 16 {
                &digest[..16]
            } else {
                digest
            };
            let layers = img
                .get("layer_count")
                .map(|x| x.to_string())
                .unwrap_or_else(|| "-".to_string());
            let size = img
                .get("size_bytes")
                .map(|x| x.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "{:<40} {:<16} {:<8} {}",
                truncate(reference, 40),
                short,
                layers,
                size
            );
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&v)?);
    }
    Ok(())
}

async fn do_pull(host: &str, reference: &str) -> Result<()> {
    let url = format!("{}/images/pull", base_url(host));
    let resp = client()
        .post(&url)
        .json(&serde_json::json!({ "reference": reference }))
        .send()
        .await
        .context("POST /images/pull")?;
    if !resp.status().is_success() && resp.status().as_u16() != 200 {
        // pull endpoint returns SSE 200; reqwest will handle as stream
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("pull failed {}: {body}", status);
    }
    // SSE stream: print each event line
    let mut stream = resp.bytes_stream();
    use futures_util::StreamExt;
    let mut stdout = std::io::stdout();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk?;
        let text = String::from_utf8_lossy(&bytes);
        for line in text.lines() {
            if line.starts_with("data:") {
                let data = line.trim_start_matches("data:").trim();
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) {
                    if let Some(t) = v.get("type").and_then(|x| x.as_str()) {
                        match t {
                            "LayerStart" => {
                                if let (Some(d), Some(idx), Some(total)) = (
                                    v.get("digest").and_then(|x| x.as_str()),
                                    v.get("index").and_then(|x| x.as_u64()),
                                    v.get("total").and_then(|x| x.as_u64()),
                                ) {
                                    writeln!(
                                        stdout,
                                        "pulling layer {}/{} {}",
                                        idx + 1,
                                        total,
                                        &d[..12.min(d.len())]
                                    )?;
                                }
                            }
                            "LayerDownloaded" => {
                                writeln!(
                                    stdout,
                                    "downloaded {} ({} bytes)",
                                    v.get("digest").and_then(|x| x.as_str()).unwrap_or(""),
                                    v.get("bytes").map(|x| x.to_string()).unwrap_or_default()
                                )?;
                            }
                            "LayerExtracted" => {
                                writeln!(
                                    stdout,
                                    "extracted {}",
                                    v.get("chain_id").and_then(|x| x.as_str()).unwrap_or("")
                                )?;
                            }
                            "Complete" => {
                                writeln!(stdout, "pull complete: {:?}", v.get("chain_ids"))?;
                            }
                            "Error" => {
                                writeln!(
                                    stdout,
                                    "error: {}",
                                    v.get("message").and_then(|x| x.as_str()).unwrap_or("")
                                )?;
                            }
                            _ => {
                                writeln!(stdout, "{data}")?;
                            }
                        }
                    } else {
                        writeln!(stdout, "{data}")?;
                    }
                } else {
                    writeln!(stdout, "{data}")?;
                }
            } else if !line.trim().is_empty() {
                writeln!(stdout, "{line}")?;
            }
        }
        stdout.flush()?;
    }
    Ok(())
}

async fn do_rmi(host: &str, reference: &str) -> Result<()> {
    // Need to encode reference for URL path (slashes)
    let encoded = urlencoding(reference);
    // kestreld expects /images/{reference} where reference may contain slashes – axum captures remainder?
    // Use raw reference with path param encoding: just pass as is with proper escaping.
    // The route is /images/{reference} so a slash would split; but images with slashes need encoding.
    // We'll try without encoding first.
    let url = format!("{}/images/{}", base_url(host), encoded);
    let resp = client().delete(&url).send().await.context("DELETE image")?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        // try with raw reference (no encoding) as fallback
        let url2 = format!("{}/images/{}", base_url(host), reference);
        let resp2 = client()
            .delete(&url2)
            .send()
            .await
            .context("DELETE image fallback")?;
        let s2 = resp2.status();
        let b2 = resp2.text().await?;
        if !s2.is_success() {
            anyhow::bail!("rmi failed {}: {body} / fallback {}: {b2}", status, s2);
        }
        println!("{b2}");
        return Ok(());
    }
    println!("{body}");
    Ok(())
}

async fn do_history(host: &str, reference: &str) -> Result<()> {
    let encoded = urlencoding(reference);
    let url = format!("{}/images/{}/layers", base_url(host), encoded);
    let resp = client().get(&url).send().await.context("GET history")?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        // fallback raw
        let url2 = format!("{}/images/{}/layers", base_url(host), reference);
        let resp2 = client()
            .get(&url2)
            .send()
            .await
            .context("GET history fallback")?;
        let s2 = resp2.status();
        let b2 = resp2.text().await?;
        if !s2.is_success() {
            anyhow::bail!("history failed {}: {body} / fallback {}: {b2}", status, s2);
        }
        let v: serde_json::Value =
            serde_json::from_str(&b2).unwrap_or(serde_json::Value::String(b2.clone()));
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body.clone()));
    if let Some(arr) = v.get("layers").and_then(|x| x.as_array()) {
        println!(
            "{:<20} {:<16} {:<10} MEDIA TYPE",
            "CHAIN_ID", "DIGEST", "SIZE"
        );
        for l in arr {
            let chain = l.get("chain_id").and_then(|x| x.as_str()).unwrap_or("-");
            let digest = l.get("digest").and_then(|x| x.as_str()).unwrap_or("-");
            let size = l
                .get("size")
                .map(|x| x.to_string())
                .unwrap_or_else(|| "-".to_string());
            let mt = l.get("media_type").and_then(|x| x.as_str()).unwrap_or("-");
            println!(
                "{:<20} {:<16} {:<10} {}",
                truncate(chain, 20),
                truncate(digest, 16),
                size,
                mt
            );
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&v)?);
    }
    Ok(())
}

async fn do_ns(host: &str, args: &NsArgs) -> Result<()> {
    match args.target.as_deref() {
        None => {
            // list help
            eprintln!("usage: kestrel ns <container-id> | kestrel ns tree");
            std::process::exit(2);
        }
        Some("tree") => {
            let url = format!("{}/system/namespaces", base_url(host));
            let resp = client()
                .get(&url)
                .send()
                .await
                .context("GET /system/namespaces")?;
            let status = resp.status();
            let body = resp.text().await?;
            if !status.is_success() {
                anyhow::bail!("ns tree failed: {body}");
            }
            let v: serde_json::Value =
                serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body.clone()));
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Some(id) => {
            let url = format!("{}/containers/{id}/namespaces", base_url(host));
            let resp = client().get(&url).send().await.context("GET namespaces")?;
            let status = resp.status();
            let body = resp.text().await?;
            if !status.is_success() {
                anyhow::bail!("ns failed: {body}");
            }
            let v: serde_json::Value =
                serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body.clone()));
            if let Some(arr) = v.get("namespaces").and_then(|x| x.as_array()) {
                println!("{:<10} {:<20} SHARED_WITH", "TYPE", "INODE");
                for ns in arr {
                    let t = ns.get("ns_type").and_then(|x| x.as_str()).unwrap_or("-");
                    let inode = ns
                        .get("inode")
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    let shared = ns
                        .get("shared_with")
                        .and_then(|x| x.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_default();
                    println!("{:<10} {:<20} {}", t, inode, shared);
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&v)?);
            }
        }
    }
    Ok(())
}

async fn do_generic_get(host: &str, path: &str) -> Result<()> {
    let url = format!("{}{}", base_url(host), path);
    let resp = client()
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {path}"))?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("GET {path} failed {}: {body}", status);
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body.clone()));
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    }

    let host = cli.host.clone();
    match cli.command {
        Commands::Run(args) => {
            let image = args.image.clone();
            let cmd = args.cmd.clone();
            let rm = args.rm;
            let tty = args.tty;
            // Build request
            let (req, _ports) = build_create_request(&image, &cmd, &args)?;
            let id = do_create(&host, req).await?;
            println!("{id}");
            do_start(&host, &id).await?;
            if !args.detach {
                stream_attach(&host, &id, tty && args.interactive).await?;
                let inspect = fetch_json(&host, &format!("/containers/{id}")).await?;
                let code = inspect
                    .get("exit_code")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                if rm {
                    do_delete(&host, &id, true).await?;
                }
                if code != 0 {
                    std::process::exit(code as i32);
                }
            } else if rm {
                eprintln!(
                    "warning: --rm with -d requires daemon-side cleanup after the process exits"
                );
            }
        }
        Commands::Create(args) => {
            let image = args.image.clone();
            let cmd = args.cmd.clone();
            let req = build_create_request_from_create(&image, &cmd, &args)?;
            let id = do_create(&host, req).await?;
            println!("{id}");
        }
        Commands::Start { id } => {
            do_start(&host, &id).await?;
            println!("{id}");
        }
        Commands::Stop { id, timeout: _ } => {
            let url = format!("{}/containers/{id}/stop", base_url(&host));
            let resp = client().post(&url).send().await.context("POST stop")?;
            let status = resp.status();
            let body = resp.text().await?;
            if !status.is_success() {
                anyhow::bail!("stop failed: {body}");
            }
            println!("{id}");
        }
        Commands::Kill { id, signal, all: _ } => {
            let url = format!(
                "{}/containers/{id}/kill?signal={}",
                base_url(&host),
                urlencoding(&signal)
            );
            let resp = client().post(&url).send().await.context("POST kill")?;
            let status = resp.status();
            let body = resp.text().await?;
            if !status.is_success() {
                anyhow::bail!("kill failed: {body}");
            }
            println!("{id}");
        }
        Commands::Delete { id, force } => {
            do_delete(&host, &id, force).await?;
            println!("{id}");
        }
        Commands::Exec(args) => {
            if args.cmd.is_empty() {
                anyhow::bail!("exec requires a command");
            }
            let code =
                tokio_tungstenite_attempt(&host, &args.id, &args.cmd, args.tty, args.interactive)
                    .await?
                    .unwrap_or(0);
            if code != 0 {
                std::process::exit(code);
            }
        }
        Commands::Ps(args) => {
            do_ps(&host, &args).await?;
        }
        Commands::Logs(args) => {
            do_logs(&host, &args).await?;
        }
        Commands::Inspect(args) => {
            let value = do_inspect(&host, &args.id).await?;
            if let Some(fmt) = args.format {
                println!("{}", render_template(&fmt, &value));
            } else {
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
        }
        Commands::Stats(args) => {
            do_stats(&host, &args).await?;
        }
        Commands::Images => {
            do_images(&host).await?;
        }
        Commands::Pull { reference } => {
            do_pull(&host, &reference).await?;
        }
        Commands::Rmi { reference } => {
            do_rmi(&host, &reference).await?;
        }
        Commands::History { reference } => {
            do_history(&host, &reference).await?;
        }
        Commands::Ns(args) => {
            do_ns(&host, &args).await?;
        }
        Commands::Diff { id } => {
            // No dedicated diff endpoint; try copyups/layers as approximation
            eprintln!("diff: no dedicated endpoint; showing copyups + layers for {id}");
            let _ = do_generic_get(&host, &format!("/containers/{id}/copyups")).await;
            let _ = do_generic_get(&host, &format!("/containers/{id}/layers")).await;
        }
        Commands::Copyups { id } => {
            do_generic_get(&host, &format!("/containers/{id}/copyups")).await?;
        }
        Commands::Pressure(args) => {
            if args.watch {
                loop {
                    do_generic_get(&host, &format!("/containers/{}/pressure", args.id)).await?;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            } else {
                do_generic_get(&host, &format!("/containers/{}/pressure", args.id)).await?;
            }
        }
        Commands::Caps { id } => {
            do_generic_get(&host, &format!("/containers/{id}/caps")).await?;
        }
        Commands::Seccomp { id } => {
            do_generic_get(&host, &format!("/containers/{id}/seccomp")).await?;
        }
        Commands::Net(args) => match args.command {
            NetCommand::Topology => {
                do_generic_get(&host, "/system/topology").await?;
            }
        },
        Commands::Topology => {
            do_generic_get(&host, "/system/topology").await?;
        }
        Commands::Explain { id } => {
            do_explain(&host, &id).await?;
        }
        Commands::Restart { id } => {
            let stop_url = format!("{}/containers/{id}/stop", base_url(&host));
            let start_url = format!("{}/containers/{id}/start", base_url(&host));
            let r1 = client()
                .post(&stop_url)
                .send()
                .await
                .context("POST stop for restart")?;
            let s1 = r1.status();
            let b = r1.text().await.unwrap_or_default();
            if !s1.is_success() {
                anyhow::bail!("restart stop failed: {b}");
            }
            let r2 = client()
                .post(&start_url)
                .send()
                .await
                .context("POST start for restart")?;
            let s2 = r2.status();
            let b2 = r2.text().await.unwrap_or_default();
            if !s2.is_success() {
                anyhow::bail!("restart start failed: {b2}");
            }
            println!("{id}");
        }
        Commands::Pause { id } => {
            let url = format!("{}/containers/{id}/pause", base_url(&host));
            let resp = client().post(&url).send().await.context("POST pause")?;
            let status = resp.status();
            let body = resp.text().await?;
            if !status.is_success() {
                anyhow::bail!("pause failed: {body}");
            }
            println!("{id}");
        }
        Commands::Unpause { id } => {
            let url = format!("{}/containers/{id}/unpause", base_url(&host));
            let resp = client().post(&url).send().await.context("POST unpause")?;
            let status = resp.status();
            let body = resp.text().await?;
            if !status.is_success() {
                anyhow::bail!("unpause failed: {body}");
            }
            println!("{id}");
        }
        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            generate(
                Shell::from(shell),
                &mut cmd,
                "kestrel",
                &mut std::io::stdout(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_human_size() {
        assert_eq!(parse_human_size("512m").unwrap(), 512 * 1024 * 1024);
        assert_eq!(
            parse_human_size("1.5g").unwrap(),
            (1.5_f64 * 1024.0 * 1024.0 * 1024.0).round() as i64
        );
        assert_eq!(parse_human_size("1024").unwrap(), 1024);
        assert_eq!(parse_human_size("1k").unwrap(), 1024);
        assert_eq!(parse_human_size("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_human_size("256M").unwrap(), 256 * 1024 * 1024);
        assert_eq!(
            parse_human_size("1.5g").unwrap(),
            parse_human_size("1536m").unwrap()
        );
    }

    #[test]
    fn test_cpus_to_cpu_max() {
        assert_eq!(cpus_to_cpu_max("1.5", 100_000).unwrap(), "150000 100000");
        assert_eq!(cpus_to_cpu_max("1", 100_000).unwrap(), "100000 100000");
        assert_eq!(cpus_to_cpu_max("0.5", 100_000).unwrap(), "50000 100000");
        assert_eq!(cpus_to_cpu_max("0", 100_000).unwrap(), "max 100000");
    }

    #[test]
    fn test_parse_port_mapping() {
        assert_eq!(parse_port_mapping("8080:80").unwrap(), (8080, 80));
        assert_eq!(parse_port_mapping("3000").unwrap(), (3000, 3000));
    }

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }
}
