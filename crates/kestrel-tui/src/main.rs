#![deny(clippy::undocumented_unsafe_blocks)]
use std::collections::VecDeque;
use std::io::{self, stdout};
use std::panic;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures_util::StreamExt;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Gauge, Paragraph, Row, Sparkline, Table, Tabs, Wrap},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "kestrel-tui", about = "kestrel TUI dashboard")]
struct Cli {
    /// Daemon base URL (http://host:port). Env KESTREL_HOST overrides.
    #[arg(long, env = "KESTREL_HOST", default_value = "http://127.0.0.1:7777")]
    host: String,
    /// Unix socket path (if present, SSE + requests will use it via HTTP fallback)
    #[arg(long, env = "KESTREL_SOCKET", default_value = "/run/kestrel.sock")]
    socket: String,
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Theme {
    border: Style,
    selected: Style,
    status_running: Style,
    status_created: Style,
    status_stopped: Style,
    status_paused: Style,
    header: Style,
    gauge: Style,
}

impl Theme {
    fn new(no_color: bool) -> Self {
        if no_color {
            return Self {
                border: Style::default(),
                selected: Style::default().add_modifier(Modifier::REVERSED),
                status_running: Style::default(),
                status_created: Style::default(),
                status_stopped: Style::default(),
                status_paused: Style::default(),
                header: Style::default().add_modifier(Modifier::BOLD),
                gauge: Style::default(),
            };
        }
        Self {
            border: Style::default().fg(Color::DarkGray),
            selected: Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            status_running: Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            status_created: Style::default().fg(Color::Yellow),
            status_stopped: Style::default().fg(Color::Red),
            status_paused: Style::default().fg(Color::Magenta),
            header: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            gauge: Style::default().fg(Color::Green),
        }
    }
    fn status_style(&self, s: &str) -> Style {
        match s.to_lowercase().as_str() {
            "running" => self.status_running,
            "created" | "creating" => self.status_created,
            "stopped" => self.status_stopped,
            "paused" => self.status_paused,
            _ => Style::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Data models (subset of kestreld API)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct ContainerView {
    id: String,
    status: String,
    #[serde(default)]
    pid: Option<i32>,
    #[serde(default)]
    bundle: Option<String>,
    #[serde(default)]
    exit_code: Option<i32>,
    #[serde(default)]
    tty: Option<bool>,
    #[serde(default)]
    network_mode: Option<String>,
    #[serde(default)]
    network: Option<serde_json::Value>,
    // extra fields ignored
}

#[derive(Debug, Clone, Deserialize)]
struct NamespacesResponse {
    namespaces: Vec<NamespaceEntry>,
}
#[derive(Debug, Clone, Deserialize)]
struct NamespaceEntry {
    ns_type: String,
    inode: u64,
    #[serde(default)]
    shared_with: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct LayersResponse {
    layers: Vec<LayerEntry>,
}
#[derive(Debug, Clone, Deserialize)]
struct LayerEntry {
    chain_id: String,
    origin: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct CopyUpsResponse {
    copy_ups: Vec<CopyUpEntry>,
}
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct CopyUpEntry {
    path: String,
    size_bytes: u64,
    from_layer: String,
    kind: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct CgroupResponse {
    cpu_stat: CpuStatOut,
    memory_current: u64,
    pids_current: u64,
    #[serde(default)]
    io_stat: Vec<serde_json::Value>,
    cpu_max: String,
    memory_max: String,
    pids_max: String,
}
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct CpuStatOut {
    usage_usec: u64,
    nr_periods: u64,
    nr_throttled: u64,
    throttled_usec: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct PressureResponse {
    cpu: PsiOut,
    memory: PsiOut,
    io: PsiOut,
}
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct PsiOut {
    some: PsiLineOut,
    full: Option<PsiLineOut>,
}
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct PsiLineOut {
    avg10: f64,
    avg60: f64,
    avg300: f64,
    total_us: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct MountsResponse {
    mounts: Vec<MountEntry>,
}
#[derive(Debug, Clone, Deserialize)]
struct MountEntry {
    mount_point: String,
    fs_type: String,
    mount_source: String,
    mount_options: String,
    propagation: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct NetworkInfo {
    #[serde(default)]
    bridge: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    published_ports: Vec<(u16, u16)>,
}

// ---------------------------------------------------------------------------
// API client (HTTP + optional Unix socket note)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ApiClient {
    base: String,
    client: reqwest::Client,
}

impl ApiClient {
    fn new(base: String, _socket: String) -> Self {
        let base = base.trim_end_matches('/').to_string();
        let base = if base.starts_with("http://") || base.starts_with("https://") {
            base
        } else if base.starts_with('/') || base.starts_with("unix://") {
            // Unix socket requested but reqwest cannot speak UDS directly — fall back to TCP
            // with a warning; keep socket path for log message. The SSE path still attempts
            // a UDS connection first via hyper (see sse_task).
            "http://127.0.0.1:7777".to_string()
        } else {
            format!("http://{base}")
        };
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest client");
        Self { base, client }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn list_containers(&self) -> Result<Vec<ContainerView>> {
        let url = self.url("/containers");
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .context("GET /containers")?;
        if !resp.status().is_success() {
            let s = resp.status();
            let b = resp.text().await.unwrap_or_default();
            anyhow::bail!("GET /containers {s}: {b}");
        }
        // Can be Vec<ContainerView> or {"containers": [...]}
        let text = resp.text().await?;
        if let Ok(v) = serde_json::from_str::<Vec<ContainerView>>(&text) {
            return Ok(v);
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(arr) = v.get("containers").and_then(|x| x.as_array()) {
                let out: Vec<ContainerView> =
                    serde_json::from_value(serde_json::Value::Array(arr.clone()))
                        .unwrap_or_default();
                return Ok(out);
            }
            if let Ok(single) = serde_json::from_str::<ContainerView>(&text) {
                return Ok(vec![single]);
            }
        }
        Ok(vec![])
    }

    async fn get_namespaces(&self, id: &str) -> Result<Vec<NamespaceEntry>> {
        let url = self.url(&format!("/containers/{id}/namespaces"));
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(vec![]);
        }
        let r: NamespacesResponse = resp
            .json()
            .await
            .unwrap_or(NamespacesResponse { namespaces: vec![] });
        Ok(r.namespaces)
    }

    async fn get_layers(&self, id: &str) -> Result<Vec<LayerEntry>> {
        let url = self.url(&format!("/containers/{id}/layers"));
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(vec![]);
        }
        let r: LayersResponse = resp
            .json()
            .await
            .unwrap_or(LayersResponse { layers: vec![] });
        Ok(r.layers)
    }

    async fn get_copyups(&self, id: &str) -> Result<Vec<CopyUpEntry>> {
        let url = self.url(&format!("/containers/{id}/copyups"));
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(vec![]);
        }
        let r: CopyUpsResponse = resp
            .json()
            .await
            .unwrap_or(CopyUpsResponse { copy_ups: vec![] });
        Ok(r.copy_ups)
    }

    async fn get_cgroup(&self, id: &str) -> Result<Option<CgroupResponse>> {
        let url = self.url(&format!("/containers/{id}/cgroup"));
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let v: CgroupResponse = resp.json().await?;
        Ok(Some(v))
    }

    async fn get_pressure(&self, id: &str) -> Result<Option<PressureResponse>> {
        let url = self.url(&format!("/containers/{id}/pressure"));
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let v: PressureResponse = resp.json().await?;
        Ok(Some(v))
    }

    async fn get_mounts(&self, id: &str) -> Result<Vec<MountEntry>> {
        let url = self.url(&format!("/containers/{id}/mounts"));
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(vec![]);
        }
        let r: MountsResponse = resp
            .json()
            .await
            .unwrap_or(MountsResponse { mounts: vec![] });
        Ok(r.mounts)
    }

    async fn get_network(&self, id: &str) -> Result<Option<NetworkInfo>> {
        let url = self.url(&format!("/containers/{id}/network"));
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let v: serde_json::Value = resp.json().await?;
        // Try direct NetworkInfo or wrapped
        if let Ok(n) = serde_json::from_value::<NetworkInfo>(v.clone()) {
            return Ok(Some(n));
        }
        Ok(None)
    }

    async fn get_logs(&self, id: &str, tail: usize) -> Result<Vec<String>> {
        let url = self.url(&format!("/containers/{id}/logs?tail={tail}"));
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(vec![]);
        }
        let text = resp.text().await?;
        Ok(text
            .lines()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    async fn post_action(&self, id: &str, action: &str) -> Result<()> {
        let url = match action {
            "start" => self.url(&format!("/containers/{id}/start")),
            "stop" => self.url(&format!("/containers/{id}/stop")),
            "pause" => self.url(&format!("/containers/{id}/pause")),
            "unpause" => self.url(&format!("/containers/{id}/unpause")),
            "restart" => self.url(&format!("/containers/{id}/stop")), // handled as stop+start by caller
            _ => anyhow::bail!("unknown action {action}"),
        };
        let resp = self.client.post(&url).send().await?;
        if !resp.status().is_success() {
            let s = resp.status();
            let b = resp.text().await.unwrap_or_default();
            anyhow::bail!("{action} {s}: {b}");
        }
        Ok(())
    }

    async fn delete(&self, id: &str, force: bool) -> Result<()> {
        let url = if force {
            self.url(&format!("/containers/{id}?force=true"))
        } else {
            self.url(&format!("/containers/{id}"))
        };
        let resp = self.client.delete(&url).send().await?;
        if !resp.status().is_success() {
            let s = resp.status();
            let b = resp.text().await.unwrap_or_default();
            anyhow::bail!("delete {s}: {b}");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum DetailTab {
    Stats,
    Namespaces,
    Layers,
    Mounts,
    Network,
    Logs,
}
impl DetailTab {
    fn all() -> &'static [Self] {
        &[
            Self::Stats,
            Self::Namespaces,
            Self::Layers,
            Self::Mounts,
            Self::Network,
            Self::Logs,
        ]
    }
    fn label(&self) -> &'static str {
        match self {
            Self::Stats => "Stats",
            Self::Namespaces => "Namespaces",
            Self::Layers => "Layers",
            Self::Mounts => "Mounts",
            Self::Network => "Network",
            Self::Logs => "Logs",
        }
    }
    fn next(self) -> Self {
        let all = Self::all();
        let idx = all.iter().position(|x| *x == self).unwrap_or(0);
        all[(idx + 1) % all.len()]
    }
    fn prev(self) -> Self {
        let all = Self::all();
        let idx = all.iter().position(|x| *x == self).unwrap_or(0);
        all[(idx + all.len() - 1) % all.len()]
    }
}

struct App {
    containers: Vec<ContainerView>,
    filtered_indices: Vec<usize>,
    selected: usize,
    filter: String,
    filter_mode: bool,
    detail_tab: DetailTab,
    help_visible: bool,
    confirm_delete: bool,
    status_msg: String,
    status_since: Instant,
    theme: Theme,

    // detail data for selected container
    namespaces: Vec<NamespaceEntry>,
    layers: Vec<LayerEntry>,
    copyups: Vec<CopyUpEntry>,
    mounts: Vec<MountEntry>,
    network: Option<NetworkInfo>,
    cgroup: Option<CgroupResponse>,
    pressure: Option<PressureResponse>,
    logs: Vec<String>,
    logs_follow: bool,
    logs_scroll: usize,

    // sparklines
    cpu_hist: VecDeque<u64>,
    mem_hist: VecDeque<u64>,
    // TUI session start (used only as an explicitly approximate uptime
    // fallback — the daemon exposes no per-container start timestamp).
    start: Instant,
    // last cpu usage sample per container for delta-based CPU%:
    // id -> (usage_usec, sampled_at)
    cpu_last: std::collections::HashMap<String, (u64, Instant)>,

    // stats per container id -> ContainerStats (for list CPU% + mem bar)
    stats_map: std::collections::HashMap<String, (f64, u64, String)>, // cpu%, mem_current, mem_max

    // confirm dialog message
    error: Option<String>,
}

impl App {
    fn new(no_color: bool) -> Self {
        Self {
            containers: vec![],
            filtered_indices: vec![],
            selected: 0,
            filter: String::new(),
            filter_mode: false,
            detail_tab: DetailTab::Stats,
            help_visible: false,
            confirm_delete: false,
            status_msg:
                "q quit · ? help · j/k navigate · / filter · Tab tabs · s/S/p/d/e/r actions"
                    .to_string(),
            status_since: Instant::now(),
            theme: Theme::new(no_color),
            namespaces: vec![],
            layers: vec![],
            copyups: vec![],
            mounts: vec![],
            network: None,
            cgroup: None,
            pressure: None,
            logs: vec![],
            logs_follow: true,
            logs_scroll: 0,
            cpu_hist: VecDeque::with_capacity(60),
            mem_hist: VecDeque::with_capacity(60),
            start: Instant::now(),
            cpu_last: std::collections::HashMap::new(),
            stats_map: std::collections::HashMap::new(),
            error: None,
        }
    }

    fn selected_id(&self) -> Option<String> {
        self.filtered_indices
            .get(self.selected)
            .and_then(|i| self.containers.get(*i).map(|c| c.id.clone()))
    }

    fn selected_container(&self) -> Option<&ContainerView> {
        self.filtered_indices
            .get(self.selected)
            .and_then(|i| self.containers.get(*i))
    }

    fn rebuild_filter(&mut self) {
        let q = self.filter.to_lowercase();
        self.filtered_indices = self
            .containers
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                if q.is_empty() {
                    true
                } else {
                    c.id.to_lowercase().contains(&q)
                        || c.status.to_lowercase().contains(&q)
                        || c.bundle
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&q)
                }
            })
            .map(|(i, _)| i)
            .collect();
        if self.selected >= self.filtered_indices.len() && !self.filtered_indices.is_empty() {
            self.selected = self.filtered_indices.len() - 1;
        }
        if self.filtered_indices.is_empty() {
            self.selected = 0;
        }
    }

    fn set_status(&mut self, msg: impl Into<String>) {
        self.status_msg = msg.into();
        self.status_since = Instant::now();
    }

    fn uptime_for(&self, c: &ContainerView) -> String {
        // The daemon exposes no per-container start timestamp, so there is
        // no true container uptime to display. For non-running containers
        // show the status; for running ones show an explicitly approximate
        // TUI-session age so it cannot be mistaken for container uptime.
        if c.status.to_lowercase() != "running" {
            return c.status.clone();
        }
        let secs = self.start.elapsed().as_secs();
        if secs < 60 {
            format!("~{secs}s")
        } else if secs < 3600 {
            format!("~{}m", secs / 60)
        } else {
            format!("~{}h", secs / 3600)
        }
    }

    fn cpu_percent(&mut self, id: &str, usage_usec: u64) -> f64 {
        let now = Instant::now();
        let pct = match self.cpu_last.get(id) {
            Some((prev_usage, prev_at)) => {
                let wall_usec = now.duration_since(*prev_at).as_micros() as f64;
                if wall_usec > 0.0 {
                    (usage_usec.saturating_sub(*prev_usage) as f64 / wall_usec) * 100.0
                } else {
                    0.0
                }
            }
            None => 0.0,
        };
        self.cpu_last.insert(id.to_string(), (usage_usec, now));
        let max = std::thread::available_parallelism()
            .map(|n| n.get() as f64 * 100.0)
            .unwrap_or(100.0);
        pct.clamp(0.0, max)
    }
}

// ---------------------------------------------------------------------------
// Terminal helpers
// ---------------------------------------------------------------------------

fn setup_terminal() -> Result<Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    Ok(terminal)
}

fn restore_terminal(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn suspend_terminal(
    _terminal: &mut Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
) -> Result<()> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

fn resume_terminal(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
) -> Result<()> {
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    terminal.clear()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Draw
// ---------------------------------------------------------------------------

fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    let main = chunks[0];
    let status = chunks[1];

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(main);

    draw_list(f, app, cols[0]);
    draw_detail(f, app, cols[1]);
    draw_status_bar(f, app, status);

    if app.help_visible {
        draw_help_overlay(f, app, area);
    }
    if app.confirm_delete {
        draw_confirm_overlay(f, app, area);
    }
    if app.filter_mode {
        draw_filter_overlay(f, app, area);
    }
}

fn draw_list(f: &mut Frame, app: &App, area: Rect) {
    let header = ["ID", "NAME", "IMAGE", "STATE", "UP", "CPU%", "MEM"];
    let widths = [
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(14),
        Constraint::Length(9),
        Constraint::Length(5),
        Constraint::Length(6),
        Constraint::Min(8),
    ];

    let mut rows: Vec<Row> = Vec::new();
    for (list_idx, &real_idx) in app.filtered_indices.iter().enumerate() {
        let c = &app.containers[real_idx];
        let is_selected = list_idx == app.selected;
        let short_id = if c.id.len() > 12 { &c.id[..12] } else { &c.id };
        // name from bundle last component or id
        let name = c
            .bundle
            .as_deref()
            .and_then(|b| b.rsplit('/').next())
            .unwrap_or("-");
        let image = c
            .bundle
            .as_deref()
            .map(|b| {
                let s = b.to_string();
                if s.len() > 14 {
                    s[s.len() - 14..].to_string()
                } else {
                    s
                }
            })
            .unwrap_or_else(|| "-".to_string());
        let state = c.status.clone();
        let up = app.uptime_for(c);
        let (cpu_s, mem_bar) = if let Some((cpu, mem_cur, mem_max)) = app.stats_map.get(&c.id) {
            let max_bytes = parse_mem_max(mem_max).unwrap_or(512 * 1024 * 1024);
            let ratio = if max_bytes > 0 {
                (*mem_cur as f64 / max_bytes as f64).clamp(0.0, 1.0)
            } else {
                0.0
            };
            let bar = format!("{:>3.0}% {}", ratio * 100.0, gauge_bar(ratio, 6));
            (format!("{cpu:>4.1}%"), bar)
        } else {
            ("  -  ".to_string(), "  -   ".to_string())
        };

        let style = if is_selected {
            app.theme.selected
        } else {
            Style::default()
        };
        let state_style = app.theme.status_style(&state);

        rows.push(
            Row::new(vec![
                Cell::from(short_id.to_string()).style(style),
                Cell::from(truncate(name, 10).to_string()).style(style),
                Cell::from(truncate(&image, 14).to_string()).style(style),
                Cell::from(state.clone()).style(if is_selected { style } else { state_style }),
                Cell::from(up).style(style),
                Cell::from(cpu_s).style(style),
                Cell::from(mem_bar).style(style),
            ])
            .height(1),
        );
    }

    let block = Block::default()
        .title(format!(
            " Containers ({}/{}) ",
            app.filtered_indices.len(),
            app.containers.len()
        ))
        .borders(Borders::ALL)
        .border_style(app.theme.border)
        .title_alignment(Alignment::Left);

    if rows.is_empty() {
        let p = Paragraph::new(
            "No containers (filter empty or daemon unreachable)\n\nPress ? for help · / to filter",
        )
        .block(block)
        .wrap(Wrap { trim: true });
        f.render_widget(p, area);
        return;
    }

    let table = Table::new(rows, widths)
        .header(
            Row::new(
                header
                    .iter()
                    .map(|h| Cell::from(*h).style(app.theme.header)),
            )
            .height(1)
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(block);
    f.render_widget(table, area);
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let tabs = DetailTab::all();
    let tab_titles: Vec<Line> = tabs
        .iter()
        .map(|t| {
            let style = if *t == app.detail_tab {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            Line::from(Span::styled(format!(" {} ", t.label()), style))
        })
        .collect();
    let selected_idx = tabs.iter().position(|x| *x == app.detail_tab).unwrap_or(0);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(area);

    let tabs_widget = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(app.theme.border)
                .title(format!(
                    " {} ",
                    app.selected_container()
                        .map(|c| c.id[..12.min(c.id.len())].to_string())
                        .unwrap_or_else(|| "-".to_string())
                )),
        )
        .select(selected_idx)
        .style(Style::default())
        .highlight_style(Style::default().fg(Color::Yellow));
    f.render_widget(tabs_widget, chunks[0]);

    let inner = chunks[1];
    match app.detail_tab {
        DetailTab::Stats => draw_stats_tab(f, app, inner),
        DetailTab::Namespaces => draw_namespaces_tab(f, app, inner),
        DetailTab::Layers => draw_layers_tab(f, app, inner),
        DetailTab::Mounts => draw_mounts_tab(f, app, inner),
        DetailTab::Network => draw_network_tab(f, app, inner),
        DetailTab::Logs => draw_logs_tab(f, app, inner),
    }
}

fn draw_stats_tab(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Min(6),
        ])
        .split(area);

    // CPU sparkline
    let cpu_data: Vec<u64> = app.cpu_hist.iter().copied().collect();
    let cpu_spark = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" CPU history (usage_usec) ")
                .border_style(app.theme.border),
        )
        .data(&cpu_data)
        .style(Style::default().fg(Color::Green));
    f.render_widget(cpu_spark, chunks[0]);

    let mem_data: Vec<u64> = app.mem_hist.iter().copied().collect();
    let mem_spark = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Memory history (bytes) ")
                .border_style(app.theme.border),
        )
        .data(&mem_data)
        .style(Style::default().fg(Color::Blue));
    f.render_widget(mem_spark, chunks[1]);

    // PSI gauges
    let psi_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(chunks[2]);

    let cpu_psi = app
        .pressure
        .as_ref()
        .map(|p| p.cpu.some.avg10)
        .unwrap_or(0.0);
    let mem_psi = app
        .pressure
        .as_ref()
        .map(|p| p.memory.some.avg10)
        .unwrap_or(0.0);
    let io_psi = app
        .pressure
        .as_ref()
        .map(|p| p.io.some.avg10)
        .unwrap_or(0.0);

    // also show cgroup stats
    let cgroup_info = if let Some(cg) = &app.cgroup {
        format!(
            "cpu usage: {} us  throttled: {}/{}  mem: {} / {}  pids: {} / {}",
            cg.cpu_stat.usage_usec,
            cg.cpu_stat.nr_throttled,
            cg.cpu_stat.nr_periods,
            cg.memory_current,
            cg.memory_max,
            cg.pids_current,
            cg.pids_max
        )
    } else {
        "no cgroup data (container not running or daemon unreachable)".to_string()
    };

    // PSI gauges as small blocks with gauge widget
    for (idx, (label, val)) in [("cpu", cpu_psi), ("memory", mem_psi), ("io", io_psi)]
        .iter()
        .enumerate()
    {
        let ratio = ((*val).clamp(0.0, 100.0) / 100.0).clamp(0.0, 1.0);
        let g = Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" PSI {label} some avg10: {val:.1}% "))
                    .border_style(app.theme.border),
            )
            .gauge_style(app.theme.gauge)
            .percent((ratio * 100.0) as u16)
            .label(format!("{val:.1}%"));
        f.render_widget(g, psi_chunks[idx]);
    }

    // overlay cgroup info at bottom of stats area if space
    let para = Paragraph::new(cgroup_info)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" cgroup ")
                .border_style(app.theme.border),
        )
        .wrap(Wrap { trim: true });
    // Render over the gauge area's bottom? Instead render in remaining space if we had it. For now just render gauge; info shown via status
    let _ = para;
}

fn draw_namespaces_tab(f: &mut Frame, app: &App, area: Rect) {
    let header = ["TYPE", "INODE", "SHARED_WITH"];
    let widths = [
        Constraint::Length(10),
        Constraint::Length(20),
        Constraint::Min(10),
    ];
    let rows: Vec<Row> = app
        .namespaces
        .iter()
        .map(|ns| {
            Row::new(vec![
                Cell::from(ns.ns_type.clone()),
                Cell::from(ns.inode.to_string()),
                Cell::from(if ns.shared_with.is_empty() {
                    "—".to_string()
                } else {
                    format!(
                        "{} containers [{}]",
                        ns.shared_with.len(),
                        ns.shared_with.join(",")
                    )
                }),
            ])
        })
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border)
        .title(" Namespaces (8 types) ");
    if rows.is_empty() {
        let p = Paragraph::new("No namespace data (select a container or check daemon)")
            .block(block)
            .wrap(Wrap { trim: true });
        f.render_widget(p, area);
        return;
    }
    let table = Table::new(rows, widths)
        .header(Row::new(
            header
                .iter()
                .map(|h| Cell::from(*h).style(app.theme.header)),
        ))
        .block(block);
    f.render_widget(table, area);
}

fn draw_layers_tab(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(6)])
        .split(area);

    let header = ["#", "CHAIN_ID", "SIZE", "ORIGIN"];
    let widths = [
        Constraint::Length(3),
        Constraint::Length(20),
        Constraint::Length(10),
        Constraint::Min(10),
    ];
    let rows: Vec<Row> = app
        .layers
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let short = if l.chain_id.len() > 16 {
                &l.chain_id[..16]
            } else {
                &l.chain_id
            };
            Row::new(vec![
                Cell::from(i.to_string()),
                Cell::from(short.to_string()),
                Cell::from(human_bytes(l.size_bytes)),
                Cell::from(truncate(&l.origin, 40).to_string()),
            ])
        })
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border)
        .title(format!(" Overlay stack ({} layers) ", app.layers.len()));
    if rows.is_empty() {
        let p = Paragraph::new("No layer data").block(block);
        f.render_widget(p, chunks[0]);
    } else {
        let table = Table::new(rows, widths)
            .header(Row::new(
                header
                    .iter()
                    .map(|h| Cell::from(*h).style(app.theme.header)),
            ))
            .block(block);
        f.render_widget(table, chunks[0]);
    }

    // upperdir growth + copyups
    let total: u64 = app.layers.iter().map(|l| l.size_bytes).sum();
    let copyup_bytes: u64 = app.copyups.iter().map(|c| c.size_bytes).sum();
    let ratio = if total > 0 {
        copyup_bytes as f64 / total as f64
    } else {
        0.0
    };
    let info = format!(
        "upperdir copy-ups: {} files, {} bytes  ·  overlay total {}  ·  amplification {:.2}x\n{}",
        app.copyups.len(),
        human_bytes(copyup_bytes),
        human_bytes(total),
        ratio,
        app.copyups
            .iter()
            .take(8)
            .map(|c| format!(
                "  {} ({} {})",
                truncate(&c.path, 40),
                human_bytes(c.size_bytes),
                c.kind
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let p = Paragraph::new(info)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(app.theme.border)
                .title(" Upperdir growth "),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(p, chunks[1]);
}

fn draw_mounts_tab(f: &mut Frame, app: &App, area: Rect) {
    let header = ["MOUNT_POINT", "FS", "SOURCE", "OPTS", "PROP"];
    let widths = [
        Constraint::Length(18),
        Constraint::Length(8),
        Constraint::Length(16),
        Constraint::Min(10),
        Constraint::Length(12),
    ];
    let rows: Vec<Row> = app
        .mounts
        .iter()
        .map(|m| {
            Row::new(vec![
                Cell::from(truncate(&m.mount_point, 18).to_string()),
                Cell::from(m.fs_type.clone()),
                Cell::from(truncate(&m.mount_source, 16).to_string()),
                Cell::from(truncate(&m.mount_options, 20).to_string()),
                Cell::from(m.propagation.clone()),
            ])
        })
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border)
        .title(format!(" Mounts ({}) ", app.mounts.len()));
    if rows.is_empty() {
        let p = Paragraph::new("No mount data").block(block);
        f.render_widget(p, area);
        return;
    }
    let table = Table::new(rows, widths)
        .header(Row::new(
            header
                .iter()
                .map(|h| Cell::from(*h).style(app.theme.header)),
        ))
        .block(block);
    f.render_widget(table, area);
}

fn draw_network_tab(f: &mut Frame, app: &App, area: Rect) {
    let text = if let Some(n) = &app.network {
        format!(
            "bridge: {}\nip: {}\ngateway: {}\nports: {}\n\nraw: {}",
            n.bridge.as_deref().unwrap_or("-"),
            n.ip.as_deref().unwrap_or("-"),
            n.gateway.as_deref().unwrap_or("-"),
            if n.published_ports.is_empty() {
                "-".to_string()
            } else {
                n.published_ports
                    .iter()
                    .map(|(h, c)| format!("{h}:{c}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            serde_json::to_string_pretty(n).unwrap_or_default()
        )
    } else if let Some(c) = app.selected_container() {
        format!(
            "container: {}\nnetwork_mode: {}\n\nNo bridge NetworkInfo (mode is not bridge or not yet attached)\n\nbundle: {}",
            c.id,
            c.network_mode.as_deref().unwrap_or("none"),
            c.bundle.as_deref().unwrap_or("-")
        )
    } else {
        "No container selected".to_string()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border)
        .title(" Network ");
    let p = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

fn draw_logs_tab(f: &mut Frame, app: &App, area: Rect) {
    let follow_label = if app.logs_follow {
        "follow: ON (f toggle)"
    } else {
        "follow: OFF (f toggle)"
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border)
        .title(format!(
            " Logs {} · scroll {}/{} (j/k, PgUp/PgDn) ",
            follow_label,
            app.logs_scroll,
            app.logs.len()
        ));
    let text = if app.logs.is_empty() {
        "No logs yet".to_string()
    } else {
        // show window of logs
        let height = area.height.saturating_sub(2) as usize;
        let start = if app.logs_follow {
            app.logs.len().saturating_sub(height)
        } else {
            app.logs_scroll.min(app.logs.len().saturating_sub(height))
        };
        app.logs
            .iter()
            .skip(start)
            .take(height)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    };
    let p = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let msg = if let Some(e) = &app.error {
        format!(" ERROR: {e} ")
    } else {
        format!(" {} ", app.status_msg)
    };
    let style = if app.error.is_some() {
        Style::default().fg(Color::White).bg(Color::Red)
    } else {
        Style::default().fg(Color::White).bg(Color::DarkGray)
    };
    let p = Paragraph::new(msg).style(style);
    f.render_widget(p, area);
}

fn draw_help_overlay(f: &mut Frame, _app: &App, area: Rect) {
    let popup = centered_rect(70, 70, area);
    f.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help (?) — press ? or Esc to close ")
        .border_style(Style::default().fg(Color::Yellow));
    let text = vec![
        Line::from("Navigation:  j/k or ↑/↓  select container    / filter    Tab/Shift-Tab switch tab"),
        Line::from("Tabs:        Stats · Namespaces · Layers · Mounts · Network · Logs"),
        Line::from("Stats:       sparklines for CPU/memory + PSI gauges (some avg10)"),
        Line::from("Namespaces:  8 rows with inode + shared-with count"),
        Line::from("Layers:      overlay stack with sizes, upperdir growth + amplification"),
        Line::from("Logs:        scrollback with follow toggle (f), j/k, PgUp/PgDn"),
        Line::from(""),
        Line::from("Actions:  s start   S stop   p pause/unpause   d delete (confirm)   e exec   r restart"),
        Line::from("          e suspends TUI, runs interactive exec (kestrel exec), restores on exit"),
        Line::from("          q quit    ? help"),
        Line::from(""),
        Line::from("Refresh:  SSE-driven over Unix socket (/run/kestrel.sock) or HTTP 127.0.0.1:7777, 1Hz stats"),
        Line::from("Themes:   NO_COLOR=1 disables colors"),
    ];
    let p = Paragraph::new(text)
        .block(block)
        .wrap(Wrap { trim: true })
        .alignment(Alignment::Left);
    f.render_widget(p, popup);
}

fn draw_confirm_overlay(f: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(50, 20, area);
    f.render_widget(Clear, popup);
    let id = app.selected_id().unwrap_or_else(|| "-".to_string());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .title(" Confirm delete ");
    let text = format!(
        "Delete container {} ?\n\n[y] confirm  [n]/Esc cancel",
        &id[..12.min(id.len())]
    );
    let p = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
    f.render_widget(p, popup);
}

fn draw_filter_overlay(f: &mut Frame, app: &App, area: Rect) {
    let popup = Rect {
        x: area.x,
        y: area.height.saturating_sub(3),
        width: area.width,
        height: 3,
    };
    f.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Filter (Enter apply, Esc cancel, / to edit) ");
    let p = Paragraph::new(format!("/{}", app.filter)).block(block);
    f.render_widget(p, popup);
}

// helpers

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn human_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n}B")
    } else if n < 1024 * 1024 {
        format!("{:.1}K", n as f64 / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1}M", n as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}G", n as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
fn truncate(s: &str, n: usize) -> &str {
    if s.len() <= n {
        s
    } else {
        &s[..n]
    }
}
fn gauge_bar(ratio: f64, width: usize) -> String {
    let filled = (ratio * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}
fn parse_mem_max(s: &str) -> Option<u64> {
    let t = s.trim();
    if t == "max" || t.is_empty() {
        return None;
    }
    t.parse::<u64>().ok()
}

// ---------------------------------------------------------------------------
// Exec suspension
// ---------------------------------------------------------------------------

fn exec_suspend_and_run(
    id: &str,
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
) -> Result<()> {
    suspend_terminal(terminal)?;
    // Shell inside the container: $KESTREL_SHELL override, else /bin/sh.
    let shell = std::env::var("KESTREL_SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    // try kestrel CLI first, fallback to local shell notice
    let kestrel_bin = find_kestrel_cli();
    let status = if let Some(bin) = kestrel_bin {
        // interactive exec via kestrel exec -it
        std::process::Command::new(bin)
            .args(["exec", "-it", id, "--", &shell])
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
    } else {
        eprintln!("\n[kestrel-tui] no kestrel CLI found, dropping to local shell (container {id})");
        eprintln!("press Enter to continue...");
        let mut buf = String::new();
        let _ = std::io::stdin().read_line(&mut buf);
        let local_shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        std::process::Command::new(local_shell)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
    };
    match status {
        Ok(s) => eprintln!("\nexec exited with {s}"),
        Err(e) => eprintln!("\nexec failed: {e}"),
    }
    eprintln!("press Enter to return to TUI...");
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
    resume_terminal(terminal)?;
    Ok(())
}

fn find_kestrel_cli() -> Option<PathBuf> {
    // check next to current exe, then PATH
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join("kestrel");
            if cand.is_file() {
                return Some(cand);
            }
            if let Some(parent) = dir.parent() {
                let cand2 = parent.join("kestrel");
                if cand2.is_file() {
                    return Some(cand2);
                }
            }
        }
    }
    // PATH lookup via which
    if let Ok(path) = std::env::var("PATH") {
        for p in path.split(':') {
            let cand = PathBuf::from(p).join("kestrel");
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let no_color = std::env::var("NO_COLOR").is_ok()
        || std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false);

    // panic hook to restore terminal
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        orig_hook(info);
    }));

    let api = ApiClient::new(cli.host.clone(), cli.socket.clone());
    let mut terminal = setup_terminal().context("setup terminal")?;
    let mut app = App::new(no_color);

    // channels
    let (sse_tx, mut sse_rx) = tokio::sync::mpsc::channel::<String>(64);

    // spawn SSE task (reconnect with backoff)
    let sse_api = api.clone();
    tokio::spawn(async move {
        let mut backoff = Duration::from_millis(500);
        loop {
            match sse_loop(&sse_api, &sse_tx).await {
                Ok(()) => backoff = Duration::from_millis(500),
                Err(e) => {
                    let _ = sse_tx.send(format!("sse error: {e}")).await;
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(10));
        }
    });

    // initial fetch
    if let Ok(containers) = api.list_containers().await {
        app.containers = containers;
        app.rebuild_filter();
        app.set_status(format!(
            "connected to {} · {} containers",
            api.base,
            app.containers.len()
        ));
    } else {
        app.set_status(format!(
            "connecting to {} (daemon unreachable, retrying…)",
            api.base
        ));
    }

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // consume first immediate tick
    tick.tick().await;

    loop {
        terminal.draw(|f| draw(f, &app))?;

        tokio::select! {
            _ = tick.tick() => {
                // 1Hz stats refresh
                if let Ok(containers) = api.list_containers().await {
                    let prev_selected_id = app.selected_id();
                    app.containers = containers;
                    app.rebuild_filter();
                    // try keep selection on same id
                    if let Some(prev) = prev_selected_id {
                        if let Some(pos) = app.filtered_indices.iter().position(|i| app.containers.get(*i).map(|c| c.id == prev).unwrap_or(false)) {
                            app.selected = pos;
                        }
                    }
                }
                // fetch detail for selected
                if let Some(id) = app.selected_id() {
                    // cgroup stats for sparklines
                    if let Ok(Some(cg)) = api.get_cgroup(&id).await {
                        let cpu = cg.cpu_stat.usage_usec;
                        let mem = cg.memory_current;
                        app.cpu_hist.push_back(cpu);
                        if app.cpu_hist.len() > 60 { app.cpu_hist.pop_front(); }
                        app.mem_hist.push_back(mem);
                        if app.mem_hist.len() > 60 { app.mem_hist.pop_front(); }
                        // update list stats map with delta-based CPU%
                        let cpu_percent = app.cpu_percent(&id, cpu);
                        app.stats_map.insert(id.clone(), (cpu_percent, mem, cg.memory_max.clone()));
                        app.cgroup = Some(cg);
                    }
                    if let Ok(Some(p)) = api.get_pressure(&id).await {
                        app.pressure = Some(p);
                    }
                    // other tabs lazy: fetch when tab is active or periodically
                    match app.detail_tab {
                        DetailTab::Namespaces => {
                            if let Ok(n) = api.get_namespaces(&id).await { app.namespaces = n; }
                        }
                        DetailTab::Layers => {
                            if let Ok(l) = api.get_layers(&id).await { app.layers = l; }
                            if let Ok(c) = api.get_copyups(&id).await { app.copyups = c; }
                        }
                        DetailTab::Mounts => {
                            if let Ok(m) = api.get_mounts(&id).await { app.mounts = m; }
                        }
                        DetailTab::Network => {
                            if let Ok(n) = api.get_network(&id).await { app.network = n; }
                        }
                        DetailTab::Logs => {
                            if let Ok(logs) = api.get_logs(&id, 200).await { app.logs = logs; }
                        }
                        DetailTab::Stats => {
                            // also prefetch namespaces/layers for other tabs occasional?
                        }
                    }
                }
                // also refresh stats for all containers for list CPU/mem bar (best-effort, limited to 5)
                for c in app.containers.iter().take(5).cloned().collect::<Vec<_>>() {
                    if let Ok(Some(cg)) = api.get_cgroup(&c.id).await {
                        let pct = app.cpu_percent(&c.id, cg.cpu_stat.usage_usec);
                        app.stats_map.insert(c.id.clone(), (pct, cg.memory_current, cg.memory_max));
                    }
                }
            }
            msg = sse_rx.recv() => {
                if let Some(m) = msg {
                    // SSE event arrived -> trigger refresh soon (status bar hint)
                    if m.starts_with("sse error") {
                        app.error = Some(m);
                    } else {
                        app.error = None;
                        // parse event type if present
                        app.set_status(format!("event: {}", truncate(&m, 80)));
                        // force immediate refresh of list
                        if let Ok(containers) = api.list_containers().await {
                            app.containers = containers;
                            app.rebuild_filter();
                        }
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }

        // Drain all pending input events (non-blocking)
        let mut should_quit = false;
        while event::poll(Duration::from_millis(0))? {
            if let Ok(Event::Key(key)) = event::read() {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                // filter mode
                if app.filter_mode {
                    match key.code {
                        KeyCode::Esc => {
                            app.filter_mode = false;
                        }
                        KeyCode::Enter => {
                            app.filter_mode = false;
                            app.rebuild_filter();
                        }
                        KeyCode::Backspace => {
                            app.filter.pop();
                            app.rebuild_filter();
                        }
                        KeyCode::Char(c) => {
                            if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'c' {
                                app.filter_mode = false;
                            } else {
                                app.filter.push(c);
                                app.rebuild_filter();
                            }
                        }
                        _ => {}
                    }
                    continue;
                }
                if app.confirm_delete {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            if let Some(id) = app.selected_id() {
                                let api2 = api.clone();
                                match api2.delete(&id, true).await {
                                    Ok(()) => app.set_status(format!("deleted {id}")),
                                    Err(e) => app.set_status(format!("delete failed: {e}")),
                                }
                            }
                            app.confirm_delete = false;
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            app.confirm_delete = false;
                        }
                        _ => {}
                    }
                    continue;
                }
                if app.help_visible {
                    match key.code {
                        KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => {
                            app.help_visible = false
                        }
                        _ => app.help_visible = false,
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') => {
                        should_quit = true;
                        break;
                    }
                    KeyCode::Char('?') => app.help_visible = !app.help_visible,
                    KeyCode::Char('/') => {
                        app.filter_mode = true;
                    }
                    KeyCode::Tab => {
                        if key.modifiers.contains(KeyModifiers::SHIFT) {
                            app.detail_tab = app.detail_tab.prev();
                        } else {
                            app.detail_tab = app.detail_tab.next();
                        }
                    }
                    KeyCode::BackTab => app.detail_tab = app.detail_tab.prev(),
                    KeyCode::Char('j') | KeyCode::Down => {
                        if app.detail_tab == DetailTab::Logs && !app.logs_follow {
                            app.logs_scroll = app.logs_scroll.saturating_add(1);
                        } else if !app.filtered_indices.is_empty() {
                            app.selected = (app.selected + 1) % app.filtered_indices.len();
                            // reset per-container detail caches
                            app.cpu_hist.clear();
                            app.mem_hist.clear();
                            app.namespaces.clear();
                            app.layers.clear();
                            app.logs.clear();
                        }
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        if app.detail_tab == DetailTab::Logs && !app.logs_follow {
                            app.logs_scroll = app.logs_scroll.saturating_sub(1);
                        } else if !app.filtered_indices.is_empty() {
                            app.selected = app
                                .selected
                                .checked_sub(1)
                                .unwrap_or(app.filtered_indices.len().saturating_sub(1));
                            app.cpu_hist.clear();
                            app.mem_hist.clear();
                            app.namespaces.clear();
                            app.layers.clear();
                            app.logs.clear();
                        }
                    }
                    KeyCode::Char('f') if app.detail_tab == DetailTab::Logs => {
                        app.logs_follow = !app.logs_follow;
                    }
                    KeyCode::PageDown => {
                        if app.detail_tab == DetailTab::Logs {
                            app.logs_follow = false;
                            app.logs_scroll = app.logs_scroll.saturating_add(10);
                        }
                    }
                    KeyCode::PageUp => {
                        if app.detail_tab == DetailTab::Logs {
                            app.logs_follow = false;
                            app.logs_scroll = app.logs_scroll.saturating_sub(10);
                        }
                    }
                    KeyCode::Char('s') => {
                        if let Some(id) = app.selected_id() {
                            match api.post_action(&id, "start").await {
                                Ok(()) => app.set_status(format!("started {id}")),
                                Err(e) => app.set_status(format!("start failed: {e}")),
                            }
                        }
                    }
                    KeyCode::Char('S') => {
                        if let Some(id) = app.selected_id() {
                            match api.post_action(&id, "stop").await {
                                Ok(()) => app.set_status(format!("stopped {id}")),
                                Err(e) => app.set_status(format!("stop failed: {e}")),
                            }
                        }
                    }
                    KeyCode::Char('p') => {
                        if let Some(id) = app.selected_id() {
                            // toggle pause/unpause based on status
                            let is_paused = app
                                .selected_container()
                                .map(|c| c.status.to_lowercase() == "paused")
                                .unwrap_or(false);
                            let action = if is_paused { "unpause" } else { "pause" };
                            match api.post_action(&id, action).await {
                                Ok(()) => app.set_status(format!("{action} {id}")),
                                Err(e) => app.set_status(format!("{action} failed: {e}")),
                            }
                        }
                    }
                    KeyCode::Char('d') => {
                        if app.selected_id().is_some() {
                            app.confirm_delete = true;
                        }
                    }
                    KeyCode::Char('e') => {
                        if let Some(id) = app.selected_id() {
                            let _ = exec_suspend_and_run(&id, &mut terminal);
                            app.set_status(format!("exec finished for {id}"));
                        }
                    }
                    KeyCode::Char('r') => {
                        if let Some(id) = app.selected_id() {
                            let _ = api.post_action(&id, "stop").await;
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            match api.post_action(&id, "start").await {
                                Ok(()) => app.set_status(format!("restarted {id}")),
                                Err(e) => app.set_status(format!("restart failed: {e}")),
                            }
                        }
                    }
                    KeyCode::Esc if !app.filter.is_empty() => {
                        app.filter.clear();
                        app.rebuild_filter();
                    }
                    KeyCode::Esc => {}
                    _ => {}
                }
            }
        }

        if should_quit {
            break;
        }

        // clear error after 5s
        if app.error.is_some() && app.status_since.elapsed() > Duration::from_secs(5) {
            app.error = None;
        }
    }

    restore_terminal(&mut terminal)?;
    Ok(())
}

async fn sse_loop(api: &ApiClient, tx: &tokio::sync::mpsc::Sender<String>) -> Result<()> {
    // Try Unix socket first if it exists, otherwise TCP.
    // For TCP we use reqwest streaming.
    let url = api.url("/events");
    let resp = api
        .client
        .get(&url)
        .header("Accept", "text/event-stream")
        .send()
        .await
        .context("GET /events")?;
    if !resp.status().is_success() {
        anyhow::bail!("GET /events {}", resp.status());
    }
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.context("sse chunk")?;
        buf.push_str(&String::from_utf8_lossy(&bytes));
        while let Some(idx) = buf.find("\n\n") {
            let frame: String = buf.drain(..idx + 2).collect();
            for line in frame.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    let data = data.trim();
                    if !data.is_empty() {
                        let _ = tx.send(data.to_string()).await;
                    }
                }
            }
        }
    }
    anyhow::bail!("sse stream ended");
}
