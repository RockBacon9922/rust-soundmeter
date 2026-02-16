use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::Local;
use clap::{ArgAction, Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use futures::executor;
use hidapi::{DeviceInfo, HidApi, HidDevice};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use russh::keys::ssh_key;
use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, Handle, Msg, Server as _, Session};
use russh::{Channel, ChannelId, CryptoVec};
use tokio::sync::{Mutex, broadcast};

const DEFAULT_VID: u16 = 0x64BD;
const DEFAULT_PID: u16 = 0x74E3;
const HID_READ_TIMEOUT_MS: i32 = 200;
const MAX_FRAME_BYTES: usize = 64;
const MAX_UI_FRAMES: usize = 200;
const CHART_DB_MAX: f32 = 120.0;
const CHART_DB_MIN: f32 = 20.0;
const DEMO_SAMPLE_MS: u64 = 120;
const BIG_TEXT_UPDATE_MS: u64 = 400;
const RMS_WINDOW_SAMPLES: usize = 32;
const RESET_FLASH_MS: u64 = 900;
const GRAPH_FILL_CHAR: char = '═';
const GRAPH_CENTER_CHAR: char = '│';

#[derive(Clone, Copy, Debug)]
struct UiSettings {
    limit_db: f32,
    graph_min_db: f32,
    graph_max_db: f32,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            limit_db: 85.0,
            graph_min_db: CHART_DB_MIN,
            graph_max_db: CHART_DB_MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MenuField {
    Limit,
    GraphMin,
    GraphMax,
    ViewMode,
    ResetDefaults,
}

impl MenuField {
    fn next(self) -> Self {
        match self {
            Self::Limit => Self::GraphMin,
            Self::GraphMin => Self::GraphMax,
            Self::GraphMax => Self::ViewMode,
            Self::ViewMode => Self::ResetDefaults,
            Self::ResetDefaults => Self::Limit,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DisplayMode {
    Rms,
    Peak,
}

impl DisplayMode {
    fn toggle(self) -> Self {
        match self {
            Self::Rms => Self::Peak,
            Self::Peak => Self::Rms,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Rms => "RMS",
            Self::Peak => "PEAK",
        }
    }

    fn unit_label(self) -> &'static str {
        match self {
            Self::Rms => "dB RMS",
            Self::Peak => "dB PEAK",
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "ssh-soundmeter")]
#[command(about = "USB sound meter reverse-engineering + ratatui console")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List HID devices and highlight likely sound meter candidates.
    Scan {
        /// Optional Vendor ID (hex, example: 0x64BD).
        #[arg(long)]
        vid: Option<String>,
        /// Optional Product ID (hex, example: 0x74E3).
        #[arg(long)]
        pid: Option<String>,
    },
    /// Dump raw HID traffic. Optionally send a periodic TX probe.
    Sniff {
        #[arg(long, default_value = "0x64BD")]
        vid: String,
        #[arg(long, default_value = "0x74E3")]
        pid: String,
        /// Optional hex payload to send repeatedly, e.g. "00 01 02 03".
        #[arg(long)]
        tx: Option<String>,
        /// Interval in ms for optional TX polling frame.
        #[arg(long, default_value_t = 1000)]
        tx_interval_ms: u64,
    },
    /// Live text UI suitable for local terminals and SSH sessions.
    Tui {
        #[arg(long, default_value = "0x64BD")]
        vid: String,
        #[arg(long, default_value = "0x74E3")]
        pid: String,
        /// Render synthetic measurements without a physical device.
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        demo: bool,
        /// Optional poll frame; if omitted, passively reads only.
        #[arg(long)]
        tx: Option<String>,
        #[arg(long, default_value_t = 500)]
        tx_interval_ms: u64,
    },
    /// Run a built-in SSH server that serves the TUI to remote clients.
    ServeSsh {
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Accept any username/password/public-key. Enabled by default.
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        open_access: bool,
        /// Optional username if open_access is disabled.
        #[arg(long)]
        username: Option<String>,
        /// Optional password if open_access is disabled.
        #[arg(long)]
        password: Option<String>,
        /// Enable mDNS service advertisement for local discovery.
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        mdns: bool,
        /// mDNS hostname/instance prefix (advertises `<name>.local`).
        #[arg(long, default_value = "soundmeter")]
        mdns_name: String,
        #[arg(long, default_value = "0x64BD")]
        vid: String,
        #[arg(long, default_value = "0x74E3")]
        pid: String,
        /// Render synthetic measurements without a physical device.
        #[arg(long, default_value_t = false, action = ArgAction::Set)]
        demo: bool,
        #[arg(long)]
        tx: Option<String>,
        #[arg(long, default_value_t = 500)]
        tx_interval_ms: u64,
    },
}

#[derive(Clone, Debug)]
struct Frame {
    decoded: Option<String>,
    db: Option<f32>,
    rms_db: Option<f32>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Scan { vid, pid }) => cmd_scan(vid, pid),
        Some(Command::Sniff {
            vid,
            pid,
            tx,
            tx_interval_ms,
        }) => cmd_sniff(vid, pid, tx, tx_interval_ms),
        Some(Command::Tui {
            vid,
            pid,
            demo,
            tx,
            tx_interval_ms,
        }) => cmd_tui(vid, pid, demo, tx, tx_interval_ms),
        Some(Command::ServeSsh {
            host,
            port,
            open_access,
            username,
            password,
            mdns,
            mdns_name,
            vid,
            pid,
            demo,
            tx,
            tx_interval_ms,
        }) => cmd_serve_ssh(
            host,
            port,
            open_access,
            username,
            password,
            mdns,
            mdns_name,
            vid,
            pid,
            demo,
            tx,
            tx_interval_ms,
        ),
        None => cmd_tui(
            format!("0x{DEFAULT_VID:04X}"),
            format!("0x{DEFAULT_PID:04X}"),
            false,
            None,
            500,
        ),
    }
}

fn cmd_scan(vid: Option<String>, pid: Option<String>) -> Result<()> {
    let filter_vid = parse_hex_u16_opt(vid)?;
    let filter_pid = parse_hex_u16_opt(pid)?;

    let api = HidApi::new().context("failed to initialize hidapi")?;
    let mut count = 0usize;

    for dev in api.device_list() {
        if let Some(v) = filter_vid
            && dev.vendor_id() != v
        {
            continue;
        }
        if let Some(p) = filter_pid
            && dev.product_id() != p
        {
            continue;
        }

        count += 1;
        print_device(
            dev,
            dev.vendor_id() == DEFAULT_VID && dev.product_id() == DEFAULT_PID,
        );
    }

    if count == 0 {
        println!("No matching HID devices found.");
    }
    Ok(())
}

fn cmd_sniff(vid: String, pid: String, tx: Option<String>, tx_interval_ms: u64) -> Result<()> {
    let vid = parse_hex_u16(&vid)?;
    let pid = parse_hex_u16(&pid)?;
    let tx_frame = tx.as_deref().map(parse_hex_bytes).transpose()?;
    let api = HidApi::new().context("failed to initialize hidapi")?;
    let dev = open_hid_device(&api, vid, pid)?;
    println!("Connected to VID=0x{vid:04X} PID=0x{pid:04X}");

    let mut last_tx = Instant::now()
        .checked_sub(Duration::from_millis(tx_interval_ms))
        .unwrap_or_else(Instant::now);
    let mut buf = [0u8; MAX_FRAME_BYTES];

    loop {
        if let Some(frame) = &tx_frame
            && last_tx.elapsed() >= Duration::from_millis(tx_interval_ms)
        {
            write_frame(&dev, frame)?;
            println!(
                "{} TX {}",
                Local::now().format("%H:%M:%S%.3f"),
                fmt_hex(frame)
            );
            last_tx = Instant::now();
        }

        match dev.read_timeout(&mut buf, HID_READ_TIMEOUT_MS) {
            Ok(n) if n > 0 => {
                let data = &buf[..n];
                let decoded = decode_frame(data);
                match decoded {
                    Some(parsed) => {
                        println!(
                            "{} RX {} | {}",
                            Local::now().format("%H:%M:%S%.3f"),
                            fmt_hex(data),
                            parsed
                        );
                    }
                    None => {
                        println!(
                            "{} RX {}",
                            Local::now().format("%H:%M:%S%.3f"),
                            fmt_hex(data)
                        );
                    }
                }
            }
            Ok(_) => {}
            Err(e) => eprintln!("read error: {e}"),
        }
    }
}

fn cmd_tui(
    vid: String,
    pid: String,
    demo: bool,
    tx: Option<String>,
    tx_interval_ms: u64,
) -> Result<()> {
    let vid = parse_hex_u16(&vid)?;
    let pid = parse_hex_u16(&pid)?;
    let tx_frame = tx.as_deref().map(parse_hex_bytes).transpose()?;
    let maybe_dev = if demo {
        None
    } else {
        let api = HidApi::new().context("failed to initialize hidapi")?;
        Some(open_hid_device(&api, vid, pid)?)
    };

    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)
        .context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;
    terminal.clear()?;

    let result = run_tui_loop(
        &mut terminal,
        maybe_dev.as_ref(),
        vid,
        pid,
        demo,
        tx_frame.as_deref(),
        tx_interval_ms,
    );

    disable_raw_mode().ok();
    crossterm::execute!(
        io::stdout(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )
    .ok();

    result
}

fn run_tui_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    dev: Option<&HidDevice>,
    vid: u16,
    pid: u16,
    demo: bool,
    tx_frame: Option<&[u8]>,
    tx_interval_ms: u64,
) -> Result<()> {
    let mut buf = [0u8; MAX_FRAME_BYTES];
    let mut frames: VecDeque<Frame> = VecDeque::with_capacity(MAX_UI_FRAMES);
    let mut last_tx = Instant::now()
        .checked_sub(Duration::from_millis(tx_interval_ms))
        .unwrap_or_else(Instant::now);
    let mut last_decode = if demo {
        String::from("demo mode active")
    } else {
        String::from("n/a")
    };
    let mut display_mode = DisplayMode::Peak;
    let mut latest_peak_db: Option<f32> = None;
    let mut display_peak_db: Option<f32> = None;
    let mut latest_rms_db: Option<f32> = None;
    let mut display_rms_db: Option<f32> = None;
    let mut last_big_update = Instant::now()
        .checked_sub(Duration::from_millis(BIG_TEXT_UPDATE_MS))
        .unwrap_or_else(Instant::now);
    let mut rolling_rms = RollingRms::new(RMS_WINDOW_SAMPLES);
    let mut settings = load_ui_settings().unwrap_or_default();
    let mut show_menu = false;
    let mut selected_field = MenuField::Limit;
    let mut reset_flash_until: Option<Instant> = None;
    let demo_start = Instant::now();
    let mut last_demo_emit = Instant::now()
        .checked_sub(Duration::from_millis(DEMO_SAMPLE_MS))
        .unwrap_or_else(Instant::now);

    loop {
        if !demo
            && let Some(tx) = tx_frame
            && last_tx.elapsed() >= Duration::from_millis(tx_interval_ms)
        {
            if let Some(dev) = dev
                && let Err(e) = write_frame(dev, tx)
            {
                frames.push_front(Frame {
                    decoded: Some(format!("TX error: {e}")),
                    db: None,
                    rms_db: None,
                });
            } else {
                frames.push_front(Frame {
                    decoded: Some("TX probe".to_string()),
                    db: None,
                    rms_db: None,
                });
            }
            while frames.len() > MAX_UI_FRAMES {
                frames.pop_back();
            }
            last_tx = Instant::now();
        }

        if demo {
            if last_demo_emit.elapsed() >= Duration::from_millis(DEMO_SAMPLE_MS) {
                let db = synthetic_db(demo_start);
                let rms_db = rolling_rms.push_db(db);
                let decoded = Some(format!("demo current={db:.1} dB rms={rms_db:.1} dB"));
                last_decode = decoded.clone().unwrap_or_else(|| "n/a".to_string());
                latest_peak_db = Some(db);
                latest_rms_db = Some(rms_db);
                frames.push_front(Frame {
                    decoded,
                    db: Some(db),
                    rms_db: Some(rms_db),
                });
                while frames.len() > MAX_UI_FRAMES {
                    frames.pop_back();
                }
                last_demo_emit = Instant::now();
            }
        } else if let Some(dev) = dev {
            match dev.read_timeout(&mut buf, HID_READ_TIMEOUT_MS) {
                Ok(n) if n > 0 => {
                    let data = buf[..n].to_vec();
                    let db = extract_db(&data);
                    let decoded = decode_frame(&data);
                    if let Some(ref d) = decoded {
                        last_decode = d.clone();
                    }
                    let mut rms_db = None;
                    if let Some(v) = db {
                        latest_peak_db = Some(v);
                        let rms = rolling_rms.push_db(v);
                        latest_rms_db = Some(rms);
                        rms_db = Some(rms);
                    }
                    frames.push_front(Frame { decoded, db, rms_db });
                    while frames.len() > MAX_UI_FRAMES {
                        frames.pop_back();
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    frames.push_front(Frame {
                        decoded: Some(format!("Read error: {e}")),
                        db: None,
                        rms_db: None,
                    });
                    while frames.len() > MAX_UI_FRAMES {
                        frames.pop_back();
                    }
                }
            }
        }

        if last_big_update.elapsed() >= Duration::from_millis(BIG_TEXT_UPDATE_MS)
            && (latest_rms_db.is_some() || latest_peak_db.is_some())
        {
            display_peak_db = latest_peak_db;
            display_rms_db = latest_rms_db;
            last_big_update = Instant::now();
        }

        draw_ui(
            terminal,
            vid,
            pid,
            &last_decode,
            display_peak_db,
            display_rms_db,
            display_mode,
            &frames,
            false,
            settings,
            show_menu,
            selected_field,
            reset_flash_until,
            None,
        )?;

        if event::poll(Duration::from_millis(10)).context("event poll failed")? {
            match event::read().context("event read failed")? {
                Event::Key(k) => {
                    let is_quit = k.code == KeyCode::Char('q');
                    let is_ctrl_c =
                        k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL);
                    match k.code {
                        KeyCode::Char('m') => show_menu = !show_menu,
                        KeyCode::Tab => {
                            if show_menu {
                                selected_field = selected_field.next();
                            }
                        }
                        KeyCode::Char('+') | KeyCode::Char('=') => {
                            if show_menu {
                                let did_reset = adjust_setting(
                                    &mut settings,
                                    &mut display_mode,
                                    selected_field,
                                    1.0,
                                );
                                if did_reset {
                                    reset_flash_until =
                                        Some(Instant::now() + Duration::from_millis(RESET_FLASH_MS));
                                }
                                autosave_ui_settings(settings, &mut last_decode);
                            }
                        }
                        KeyCode::Char('-') => {
                            if show_menu {
                                let did_reset = adjust_setting(
                                    &mut settings,
                                    &mut display_mode,
                                    selected_field,
                                    -1.0,
                                );
                                if did_reset {
                                    reset_flash_until =
                                        Some(Instant::now() + Duration::from_millis(RESET_FLASH_MS));
                                }
                                autosave_ui_settings(settings, &mut last_decode);
                            }
                        }
                        _ => {}
                    }
                    if is_quit || is_ctrl_c {
                        break;
                    }
                }
                Event::Resize(_, _) => {
                    terminal.autoresize().ok();
                    terminal.clear().ok();
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn open_hid_device(api: &HidApi, vid: u16, pid: u16) -> Result<HidDevice> {
    api.open(vid, pid)
        .with_context(|| format!("failed opening HID device VID=0x{vid:04X} PID=0x{pid:04X}"))
}

fn write_frame(dev: &HidDevice, frame: &[u8]) -> Result<()> {
    if frame.is_empty() {
        bail!("TX frame cannot be empty");
    }
    dev.write(frame)
        .with_context(|| format!("failed writing HID frame {}", fmt_hex(frame)))?;
    Ok(())
}

fn decode_frame(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }

    if let Some(db) = extract_db(bytes) {
        return Some(format!("current={db:.1} dB"));
    }

    let ascii = bytes
        .iter()
        .copied()
        .filter(|b| b.is_ascii_graphic() || *b == b' ')
        .collect::<Vec<_>>();
    if ascii.len() >= 4
        && let Ok(s) = String::from_utf8(ascii)
    {
        let cleaned = s.trim().to_string();
        if !cleaned.is_empty() {
            return Some(format!("ascii='{cleaned}'"));
        }
    }

    None
}

fn extract_db(bytes: &[u8]) -> Option<f32> {
    for window in bytes.windows(2) {
        let raw = u16::from_le_bytes([window[0], window[1]]);
        let db = raw as f32 / 10.0;
        if (20.0..140.0).contains(&db) {
            return Some(db);
        }
    }
    None
}

fn parse_hex_u16_opt(s: Option<String>) -> Result<Option<u16>> {
    s.as_deref().map(parse_hex_u16).transpose()
}

fn parse_hex_u16(s: &str) -> Result<u16> {
    let normalized = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(normalized, 16).with_context(|| format!("invalid hex u16: {s}"))
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for token in s.split_whitespace() {
        let tok = token
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        let b = u8::from_str_radix(tok, 16).with_context(|| format!("invalid byte: {token}"))?;
        out.push(b);
    }
    if out.is_empty() {
        bail!("hex byte list is empty");
    }
    Ok(out)
}

fn fmt_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::from("(empty)");
    }
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn print_device(dev: &DeviceInfo, is_default_target: bool) {
    let marker = if is_default_target {
        "[target?]"
    } else {
        "         "
    };
    println!(
        "{marker} VID=0x{:04X} PID=0x{:04X} usage_page=0x{:04X} interface={}",
        dev.vendor_id(),
        dev.product_id(),
        dev.usage_page(),
        dev.interface_number()
    );
    println!("          path={}", dev.path().to_string_lossy());
    if let Some(p) = dev.product_string() {
        println!("          product={p}");
    }
    if let Some(m) = dev.manufacturer_string() {
        println!("          manufacturer={m}");
    }
    let _ = io::stdout().flush();
}

fn cmd_serve_ssh(
    host: String,
    port: u16,
    open_access: bool,
    username: Option<String>,
    password: Option<String>,
    mdns: bool,
    mdns_name: String,
    vid: String,
    pid: String,
    demo: bool,
    tx: Option<String>,
    tx_interval_ms: u64,
) -> Result<()> {
    let vid = parse_hex_u16(&vid)?;
    let pid = parse_hex_u16(&pid)?;
    let tx_frame = tx.as_deref().map(parse_hex_bytes).transpose()?;
    let cfg = SshServeConfig {
        host,
        port,
        open_access,
        username,
        password,
        mdns,
        mdns_name,
        vid,
        pid,
        demo,
        tx_frame,
        tx_interval_ms,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;
    runtime.block_on(run_ssh_server(cfg))
}

#[derive(Clone, Debug)]
struct SshServeConfig {
    host: String,
    port: u16,
    open_access: bool,
    username: Option<String>,
    password: Option<String>,
    mdns: bool,
    mdns_name: String,
    vid: u16,
    pid: u16,
    demo: bool,
    tx_frame: Option<Vec<u8>>,
    tx_interval_ms: u64,
}

struct MdnsRegistration {
    daemon: ServiceDaemon,
    service_fullname: String,
}

impl MdnsRegistration {
    fn shutdown_graceful(self) {
        if let Ok(rx) = self.daemon.unregister(&self.service_fullname) {
            let _ = rx.recv_timeout(Duration::from_secs(2));
        }
        if let Ok(rx) = self.daemon.shutdown() {
            let _ = rx.recv_timeout(Duration::from_secs(2));
        }
    }
}

#[derive(Debug)]
struct UiState {
    frames: VecDeque<Frame>,
    last_decode: String,
    latest_peak_db: Option<f32>,
    display_peak_db: Option<f32>,
    latest_rms_db: Option<f32>,
    display_rms_db: Option<f32>,
    display_mode: DisplayMode,
    last_big_update: Instant,
    settings: UiSettings,
    show_menu: bool,
    selected_field: MenuField,
    reset_flash_until: Option<Instant>,
}

type SshTerminal = Terminal<CrosstermBackend<SshTerminalHandle>>;

#[derive(Clone)]
struct SshTerminalHandle {
    handle: Handle,
    channel_id: ChannelId,
    sink: Vec<u8>,
}

impl std::io::Write for SshTerminalHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sink.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let handle = self.handle.clone();
        let channel_id = self.channel_id;
        let data: CryptoVec = self.sink.clone().into();
        executor::block_on(async move {
            let _ = handle.data(channel_id, data).await;
        });
        self.sink.clear();
        Ok(())
    }
}

struct SshClient {
    terminal: SshTerminal,
    state: UiState,
}

#[derive(Clone)]
struct SshAppServer {
    clients: Arc<Mutex<HashMap<usize, SshClient>>>,
    id: usize,
    cfg: SshServeConfig,
}

impl SshAppServer {
    fn new(cfg: SshServeConfig) -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
            cfg,
        }
    }
}

impl russh::server::Server for SshAppServer {
    type Handler = Self;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        let s = self.clone();
        self.id += 1;
        s
    }
}

impl russh::server::Handler for SshAppServer {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _: &str) -> Result<Auth, Self::Error> {
        if self.cfg.open_access {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if self.cfg.open_access {
            return Ok(Auth::Accept);
        }
        if self.cfg.username.as_deref() == Some(user)
            && self.cfg.password.as_deref() == Some(password)
        {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        if self.cfg.open_access {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let terminal_handle = SshTerminalHandle {
            handle: session.handle(),
            channel_id: channel.id(),
            sink: Vec::new(),
        };
        let backend = CrosstermBackend::new(terminal_handle);
        let mut terminal = Terminal::new(backend).context("failed creating SSH terminal")?;
        terminal.clear()?;

        let mut client = SshClient {
            terminal,
            state: UiState {
                frames: VecDeque::with_capacity(MAX_UI_FRAMES),
                last_decode: if self.cfg.demo {
                    String::from("demo mode active")
                } else {
                    String::from("waiting for device data...")
                },
                latest_peak_db: None,
                display_peak_db: None,
                latest_rms_db: None,
                display_rms_db: None,
                display_mode: DisplayMode::Peak,
                last_big_update: Instant::now()
                    .checked_sub(Duration::from_millis(BIG_TEXT_UPDATE_MS))
                    .unwrap_or_else(Instant::now),
                // Keep SSH client settings session-local so one client's changes
                // do not carry over to other sessions.
                settings: UiSettings::default(),
                show_menu: false,
                selected_field: MenuField::Limit,
                reset_flash_until: None,
            },
        };
        draw_ui(
            &mut client.terminal,
            self.cfg.vid,
            self.cfg.pid,
            &client.state.last_decode,
            client.state.display_peak_db,
            client.state.display_rms_db,
            client.state.display_mode,
            &client.state.frames,
            true,
            client.state.settings,
            client.state.show_menu,
            client.state.selected_field,
            client.state.reset_flash_until,
            Some(&self.cfg.host),
        )?;

        self.clients.lock().await.insert(self.id, client);
        Ok(true)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_success(channel);
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        col_width: u32,
        row_height: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_success(channel);
        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.get_mut(&self.id) {
            let width = col_width.clamp(1, u16::MAX as u32) as u16;
            let height = row_height.clamp(1, u16::MAX as u32) as u16;
            client.terminal.resize(ratatui::layout::Rect {
                x: 0,
                y: 0,
                width,
                height,
            })?;
            client.terminal.clear()?;
            draw_ui(
                &mut client.terminal,
                self.cfg.vid,
                self.cfg.pid,
                &client.state.last_decode,
                client.state.display_peak_db,
                client.state.display_rms_db,
                client.state.display_mode,
                &client.state.frames,
                true,
                client.state.settings,
                client.state.show_menu,
                client.state.selected_field,
                client.state.reset_flash_until,
                Some(&self.cfg.host),
            )?;
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _: ChannelId,
        col_width: u32,
        row_height: u32,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.get_mut(&self.id) {
            let width = col_width.clamp(1, u16::MAX as u32) as u16;
            let height = row_height.clamp(1, u16::MAX as u32) as u16;
            client.terminal.resize(ratatui::layout::Rect {
                x: 0,
                y: 0,
                width,
                height,
            })?;
            client.terminal.clear()?;
            draw_ui(
                &mut client.terminal,
                self.cfg.vid,
                self.cfg.pid,
                &client.state.last_decode,
                client.state.display_peak_db,
                client.state.display_rms_db,
                client.state.display_mode,
                &client.state.frames,
                true,
                client.state.settings,
                client.state.show_menu,
                client.state.selected_field,
                client.state.reset_flash_until,
                Some(&self.cfg.host),
            )?;
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if data.contains(&b'q') || data.contains(&3) {
            self.clients.lock().await.remove(&self.id);
            let _ = session.close(channel);
            return Ok(());
        }
        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.get_mut(&self.id) {
            for b in data {
                match *b {
                    b'm' | b'M' => client.state.show_menu = !client.state.show_menu,
                    b'\t' => {
                        if client.state.show_menu {
                            client.state.selected_field = client.state.selected_field.next();
                        }
                    }
                    b'+' | b'=' => {
                        if client.state.show_menu {
                            let did_reset = adjust_setting(
                                &mut client.state.settings,
                                &mut client.state.display_mode,
                                client.state.selected_field,
                                1.0,
                            );
                            if did_reset {
                                client.state.reset_flash_until =
                                    Some(Instant::now() + Duration::from_millis(RESET_FLASH_MS));
                            }
                            client.state.last_decode = "updated session settings".to_string();
                        }
                    }
                    b'-' => {
                        if client.state.show_menu {
                            let did_reset = adjust_setting(
                                &mut client.state.settings,
                                &mut client.state.display_mode,
                                client.state.selected_field,
                                -1.0,
                            );
                            if did_reset {
                                client.state.reset_flash_until =
                                    Some(Instant::now() + Duration::from_millis(RESET_FLASH_MS));
                            }
                            client.state.last_decode = "updated session settings".to_string();
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    async fn channel_close(&mut self, _: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        self.clients.lock().await.remove(&self.id);
        Ok(())
    }
}

async fn run_ssh_server(cfg: SshServeConfig) -> Result<()> {
    let host_key = load_or_create_ssh_host_key()?;
    let ssh_cfg = russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![host_key],
        ..Default::default()
    };
    let ssh_cfg = Arc::new(ssh_cfg);

    let mut server = SshAppServer::new(cfg.clone());
    let clients = server.clients.clone();
    let mdns_registration = if cfg.mdns {
        Some(setup_mdns(&cfg)?)
    } else {
        None
    };

    let (frame_tx, _) = broadcast::channel::<Frame>(512);
    spawn_hid_worker(
        cfg.vid,
        cfg.pid,
        cfg.demo,
        cfg.tx_frame.clone(),
        cfg.tx_interval_ms,
        frame_tx.clone(),
    );

    let host_for_ui = cfg.host.clone();
    tokio::spawn(async move {
        let mut rx = frame_tx.subscribe();
        while let Ok(frame) = rx.recv().await {
            let mut lock = clients.lock().await;
            for client in lock.values_mut() {
                client.state.frames.push_front(frame.clone());
                if let Some(decoded) = &frame.decoded {
                    client.state.last_decode = decoded.clone();
                }
                if let Some(peak_db) = frame.db {
                    client.state.latest_peak_db = Some(peak_db);
                }
                if let Some(rms_db) = frame.rms_db {
                    client.state.latest_rms_db = Some(rms_db);
                }
                if client.state.last_big_update.elapsed()
                    >= Duration::from_millis(BIG_TEXT_UPDATE_MS)
                    && (client.state.latest_rms_db.is_some() || client.state.latest_peak_db.is_some())
                {
                    client.state.display_peak_db = client.state.latest_peak_db;
                    client.state.display_rms_db = client.state.latest_rms_db;
                    client.state.last_big_update = Instant::now();
                }
                while client.state.frames.len() > MAX_UI_FRAMES {
                    client.state.frames.pop_back();
                }
                let _ = draw_ui(
                    &mut client.terminal,
                    cfg.vid,
                    cfg.pid,
                    &client.state.last_decode,
                    client.state.display_peak_db,
                    client.state.display_rms_db,
                    client.state.display_mode,
                    &client.state.frames,
                    true,
                    client.state.settings,
                    client.state.show_menu,
                    client.state.selected_field,
                    client.state.reset_flash_until,
                    Some(&host_for_ui),
                );
            }
        }
    });

    if cfg.open_access {
        println!(
            "SSH server listening on {}:{} (open access enabled, demo={})",
            cfg.host, cfg.port, cfg.demo
        );
    } else {
        println!(
            "SSH server listening on {}:{} (user='{}', demo={})",
            cfg.host,
            cfg.port,
            cfg.username.as_deref().unwrap_or("<unset>"),
            cfg.demo
        );
    }
    let connect_host = if cfg.host == "0.0.0.0" {
        "<server-ip>"
    } else {
        cfg.host.as_str()
    };
    println!(
        "Connect with: ssh -p {} {}@{}",
        cfg.port,
        cfg.username.as_deref().unwrap_or("soundmeter"),
        connect_host
    );
    if cfg.mdns {
        println!("mDNS advertised host: {}.local", cfg.mdns_name);
        println!(
            "Try: ssh -p {} {}@{}.local",
            cfg.port,
            cfg.username.as_deref().unwrap_or("soundmeter"),
            cfg.mdns_name
        );
    }
    println!("Press 'q' in the SSH session to close that client.");

    let result = server
        .run_on_address(ssh_cfg, (cfg.host.as_str(), cfg.port))
        .await;
    if let Some(mdns) = mdns_registration {
        mdns.shutdown_graceful();
    }
    result?;
    Ok(())
}

fn setup_mdns(cfg: &SshServeConfig) -> Result<MdnsRegistration> {
    let mdns = ServiceDaemon::new().context("failed to start mDNS daemon")?;
    let service_type = "_ssh._tcp.local.";
    let instance_name = cfg.mdns_name.clone();
    let host_name = format!("{}.local.", cfg.mdns_name);
    let ip_addr = discover_local_ip();
    let properties = [("app", "ssh-soundmeter"), ("proto", "ssh")];
    let service_info = ServiceInfo::new(
        service_type,
        &instance_name,
        &host_name,
        ip_addr.to_string(),
        cfg.port,
        &properties[..],
    )
    .context("failed to build mDNS service info")?;
    let service_fullname = service_info.get_fullname().to_string();
    mdns.register(service_info)
        .context("failed to register mDNS service")?;
    Ok(MdnsRegistration {
        daemon: mdns,
        service_fullname,
    })
}

fn discover_local_ip() -> std::net::IpAddr {
    let fallback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return fallback,
    };
    if socket.connect("8.8.8.8:80").is_ok() {
        if let Ok(addr) = socket.local_addr() {
            let ip = addr.ip();
            if !ip.is_loopback() {
                return ip;
            }
        }
    }
    fallback
}

fn spawn_hid_worker(
    vid: u16,
    pid: u16,
    demo: bool,
    tx_frame: Option<Vec<u8>>,
    tx_interval_ms: u64,
    frame_tx: broadcast::Sender<Frame>,
) {
    std::thread::spawn(move || {
        let mut rolling_rms = RollingRms::new(RMS_WINDOW_SAMPLES);
        if demo {
            let demo_start = Instant::now();
            loop {
                let db = synthetic_db(demo_start);
                let rms_db = rolling_rms.push_db(db);
                let _ = frame_tx.send(Frame {
                    decoded: Some(format!("demo current={db:.1} dB rms={rms_db:.1} dB")),
                    db: Some(db),
                    rms_db: Some(rms_db),
                });
                std::thread::sleep(Duration::from_millis(DEMO_SAMPLE_MS));
            }
        }

        let api = match HidApi::new() {
            Ok(api) => api,
            Err(e) => {
                let _ = frame_tx.send(Frame {
                    decoded: Some(format!("HID init error: {e}")),
                    db: None,
                    rms_db: None,
                });
                return;
            }
        };
        let dev = match api.open(vid, pid) {
            Ok(dev) => dev,
            Err(e) => {
                let _ = frame_tx.send(Frame {
                    decoded: Some(format!(
                        "Device open error VID=0x{vid:04X} PID=0x{pid:04X}: {e}"
                    )),
                    db: None,
                    rms_db: None,
                });
                return;
            }
        };

        let mut buf = [0u8; MAX_FRAME_BYTES];
        let mut last_tx = Instant::now()
            .checked_sub(Duration::from_millis(tx_interval_ms))
            .unwrap_or_else(Instant::now);

        loop {
            if let Some(frame) = &tx_frame
                && last_tx.elapsed() >= Duration::from_millis(tx_interval_ms)
            {
                let event = match dev.write(frame) {
                    Ok(_) => Frame {
                        decoded: Some("TX probe".to_string()),
                        db: None,
                        rms_db: None,
                    },
                    Err(e) => Frame {
                        decoded: Some(format!("TX error: {e}")),
                        db: None,
                        rms_db: None,
                    },
                };
                let _ = frame_tx.send(event);
                last_tx = Instant::now();
            }

            match dev.read_timeout(&mut buf, HID_READ_TIMEOUT_MS) {
                Ok(n) if n > 0 => {
                    let bytes = buf[..n].to_vec();
                    let decoded = decode_frame(&bytes);
                    let db = extract_db(&bytes);
                    let rms_db = db.map(|v| rolling_rms.push_db(v));
                    let _ = frame_tx.send(Frame { decoded, db, rms_db });
                }
                Ok(_) => {}
                Err(e) => {
                    let _ = frame_tx.send(Frame {
                        decoded: Some(format!("Read error: {e}")),
                        db: None,
                        rms_db: None,
                    });
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    });
}

fn draw_ui<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    _vid: u16,
    _pid: u16,
    last_decode: &str,
    display_peak_db: Option<f32>,
    display_rms_db: Option<f32>,
    display_mode: DisplayMode,
    frames: &VecDeque<Frame>,
    ssh_mode: bool,
    settings: UiSettings,
    show_menu: bool,
    selected_field: MenuField,
    reset_flash_until: Option<Instant>,
    ssh_host: Option<&str>,
) -> Result<()> {
    terminal
        .draw(|f| {
            let title = if ssh_mode {
                let host = ssh_host
                    .map(resolve_display_host)
                    .unwrap_or_else(|| discover_local_ip().to_string());
                format!("ssh-soundmeter  quit:q/Ctrl+C  menu:m  host:{host}")
            } else {
                "ssh-soundmeter  quit:q/Ctrl+C  menu:m".to_string()
            };
            let block = Block::default()
                .borders(Borders::ALL)
                .title(title);
            let area = f.area();
            let inner = block.inner(area);
            f.render_widget(block, area);

            if inner.width < 3 || inner.height < 3 {
                return;
            }

            let (cols, center_col) = history_columns(frames, inner.width as usize);
            let lines = build_graph_lines(
                &cols,
                inner.height as usize,
                center_col,
                settings.graph_min_db,
                settings.graph_max_db,
            );
            f.render_widget(Paragraph::new(lines), inner);

            let shown_db = match display_mode {
                DisplayMode::Rms => display_rms_db,
                DisplayMode::Peak => display_peak_db,
            };
            let current_text = shown_db
                .map(|db| format!("{db:.1}"))
                .unwrap_or_else(|| "n/a".to_string());
            let over_limit = shown_db.map(|db| db >= settings.limit_db).unwrap_or(false);
            let mut scale = fit_big_scale(inner.width, inner.height, &current_text);
            let (mut big_w, mut big_h) = big_text_size(&current_text, scale);
            if big_w.saturating_add(2) > inner.width || big_h.saturating_add(2) > inner.height {
                scale = 0;
                big_w = current_text.len() as u16;
                big_h = 1;
            }
            let tx = inner
                .x
                .saturating_add(inner.width / 2)
                .saturating_sub(big_w / 2);
            let ty = inner
                .y
                .saturating_add(inner.height / 2)
                .saturating_sub(big_h / 2);
            if scale > 0 {
                render_big_text(
                    f,
                    tx,
                    ty,
                    &current_text,
                    Style::default()
                        .fg(if over_limit { Color::Red } else { Color::White })
                        .add_modifier(Modifier::BOLD),
                    scale,
                    over_limit,
                );
            } else {
                f.render_widget(
                    Paragraph::new(Line::from(Span::styled(
                        current_text.clone(),
                        Style::default()
                            .fg(if over_limit { Color::Red } else { Color::White })
                            .add_modifier(Modifier::BOLD),
                    ))),
                    Rect {
                        x: tx,
                        y: ty,
                        width: big_w.min(inner.width),
                        height: 1,
                    },
                );
            }

            let unit = display_mode.unit_label();
            let ux = inner
                .x
                .saturating_add(inner.width / 2)
                .saturating_sub((unit.len() as u16) / 2);
            let uy = ty.saturating_add(big_h).saturating_add(if scale > 0 { 1 } else { 0 });
            if uy < inner.y.saturating_add(inner.height) {
                f.render_widget(
                    Paragraph::new(Line::from(Span::styled(
                        unit.to_string(),
                        Style::default().fg(Color::Gray),
                    ))),
                    Rect {
                        x: ux,
                        y: uy,
                        width: unit.len() as u16,
                        height: 1,
                    },
                );
            }

            if !last_decode.is_empty() && inner.height > 2 {
                let status_rect = Rect {
                    x: inner.x.saturating_add(1),
                    y: inner.y.saturating_add(inner.height.saturating_sub(1)),
                    width: inner.width.saturating_sub(2),
                    height: 1,
                };
                f.render_widget(
                    Paragraph::new(Line::from(Span::styled(
                        last_decode.to_string(),
                        Style::default().fg(Color::DarkGray),
                    ))),
                    status_rect,
                );
            }

            if show_menu {
                if inner.width < 24 || inner.height < 8 {
                    return;
                }
                let mark = |field: MenuField| if selected_field == field { '*' } else { ' ' };
                let now = Instant::now();
                let reset_flashing = reset_flash_until.is_some_and(|until| until > now);
                let reset_flash_on = reset_flash_until
                    .map(|until| until.saturating_duration_since(now).as_millis() / 120 % 2 == 0)
                    .unwrap_or(false);
                let reset_mark = if reset_flashing && reset_flash_on {
                    '*'
                } else {
                    mark(MenuField::ResetDefaults)
                };
                let reset_text = if reset_flashing && reset_flash_on {
                    "RESET: DEFAULTS"
                } else {
                    "reset: defaults"
                };
                let menu_text = format!(
                    "{} limit: {:.1} dB\n{} min: {:.1} dB\n{} max: {:.1} dB\n{} view: {}\n{} {}\nTab: next  +/-: adjust  m: close",
                    mark(MenuField::Limit),
                    settings.limit_db,
                    mark(MenuField::GraphMin),
                    settings.graph_min_db,
                    mark(MenuField::GraphMax),
                    settings.graph_max_db,
                    mark(MenuField::ViewMode),
                    display_mode.label(),
                    reset_mark,
                    reset_text,
                );
                let menu_w = 42u16;
                let menu_rect = Rect {
                    x: inner.x.saturating_add(1),
                    y: inner.y.saturating_add(1),
                    width: menu_w.min(inner.width.saturating_sub(2)),
                    height: 8.min(inner.height.saturating_sub(2)),
                };
                let menu = Paragraph::new(menu_text).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Menu")
                        .style(Style::default().fg(Color::White).bg(Color::Black)),
                );
                f.render_widget(menu, menu_rect);
            }
        })
        .map_err(|e| anyhow::anyhow!("terminal draw failed: {e:?}"))?;
    Ok(())
}

fn synthetic_db(start: Instant) -> f32 {
    let t = start.elapsed().as_secs_f32();
    let base = 58.0 + (t * 2.7).sin() * 10.0 + (t * 6.9).sin() * 12.0 + (t * 13.1).sin() * 6.0;
    let pulse = if (t * 1.7).sin() > 0.65 { 22.0 } else { 0.0 };
    let random_like = (((t * 23.0).sin() * 43758.5453).fract().abs() - 0.5) * 10.0;
    let dip = if (t * 0.47).sin() < -0.92 { -14.0 } else { 0.0 };
    (base + pulse + random_like + dip).clamp(28.0, 112.0)
}

#[derive(Debug)]
struct RollingRms {
    cap: usize,
    powers: VecDeque<f64>,
    sum_power: f64,
}

impl RollingRms {
    fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            powers: VecDeque::with_capacity(cap.max(1)),
            sum_power: 0.0,
        }
    }

    fn push_db(&mut self, db: f32) -> f32 {
        let power = 10f64.powf((db as f64) / 10.0);
        self.powers.push_back(power);
        self.sum_power += power;
        if self.powers.len() > self.cap
            && let Some(old) = self.powers.pop_front()
        {
            self.sum_power -= old;
        }
        let n = self.powers.len().max(1) as f64;
        let mean_power = (self.sum_power / n).max(1e-12);
        (10.0 * mean_power.log10()) as f32
    }
}

fn history_columns(
    frames: &VecDeque<Frame>,
    width: usize,
) -> (Vec<Option<f32>>, usize) {
    let width = width.max(1);
    let center = width.saturating_sub(1);
    let mut cols: Vec<Option<f32>> = vec![None; width];
    let history: Vec<f32> = frames.iter().filter_map(|f| f.db).collect();
    cols[center] = history.first().copied();

    for i in 1..width {
        if let Some(v) = history.get(i) {
            cols[center - i] = Some(*v);
        } else {
            break;
        }
    }
    (cols, center)
}

fn build_graph_lines(
    cols: &[Option<f32>],
    height: usize,
    center_col: usize,
    graph_min_db: f32,
    graph_max_db: f32,
) -> Vec<Line<'static>> {
    let cols = smooth_columns(cols);
    let heights: Vec<usize> = cols
        .iter()
        .map(|v| {
            v.map(|db| db_to_rows(db, height, graph_min_db, graph_max_db))
                .unwrap_or(0)
        })
        .collect();
    let mut lines: Vec<Line> = Vec::with_capacity(height);
    for y in 0..height {
        let mut spans: Vec<Span> = Vec::with_capacity(cols.len());
        for x in 0..cols.len() {
            let mut ch = ' ';
            let mut style = Style::default();
            let h = heights[x];
            if h > 0 {
                let line_y = height.saturating_sub(h);
                if y >= line_y {
                    ch = GRAPH_FILL_CHAR;
                    style = style.fg(gradient_color_for_row(y, height));
                }
            }

            if x == center_col && ch == ' ' {
                ch = GRAPH_CENTER_CHAR;
                style = style.fg(Color::DarkGray);
            }

            spans.push(Span::styled(ch.to_string(), style));
        }
        lines.push(Line::from(spans));
    }
    lines
}

fn smooth_columns(cols: &[Option<f32>]) -> Vec<Option<f32>> {
    let mut out = Vec::with_capacity(cols.len());
    for i in 0..cols.len() {
        if cols[i].is_none() {
            out.push(None);
            continue;
        }
        let mut acc = 0.0f32;
        let mut wsum = 0.0f32;
        for (off, w) in [
            (-2isize, 0.10f32),
            (-1, 0.22),
            (0, 0.36),
            (1, 0.22),
            (2, 0.10),
        ] {
            let idx = i as isize + off;
            if idx >= 0
                && (idx as usize) < cols.len()
                && let Some(v) = cols[idx as usize]
            {
                acc += v * w;
                wsum += w;
            }
        }
        if wsum > 0.0 {
            out.push(Some(acc / wsum));
        } else {
            out.push(cols[i]);
        }
    }
    out
}

fn db_to_rows(db: f32, height: usize, graph_min_db: f32, graph_max_db: f32) -> usize {
    if height == 0 {
        return 0;
    }
    let denom = (graph_max_db - graph_min_db).max(1.0);
    let normalized = ((db - graph_min_db) / denom).clamp(0.0, 1.0);
    ((normalized * height as f32).round() as usize).clamp(0, height)
}

fn gradient_color_for_row(y: usize, height: usize) -> Color {
    if height <= 1 {
        return Color::Green;
    }
    let t = 1.0 - (y as f32 / (height - 1) as f32);
    // Continuous heat-style gradient with two linear segments:
    // green -> yellow -> red.
    if t < 0.5 {
        let u = t / 0.5;
        let r = lerp_u8(46, 232, u);
        let g = lerp_u8(204, 215, u);
        let b = lerp_u8(113, 72, u);
        Color::Rgb(r, g, b)
    } else {
        let u = (t - 0.5) / 0.5;
        let r = lerp_u8(232, 255, u);
        let g = lerp_u8(215, 76, u);
        let b = lerp_u8(72, 60, u);
        Color::Rgb(r, g, b)
    }
}

fn lerp_u8(a: u8, b: u8, t: f32) -> u8 {
    let t = t.clamp(0.0, 1.0);
    (a as f32 + (b as f32 - a as f32) * t).round() as u8
}

fn adjust_setting(
    settings: &mut UiSettings,
    display_mode: &mut DisplayMode,
    field: MenuField,
    delta: f32,
) -> bool {
    match field {
        MenuField::Limit => {
            settings.limit_db = (settings.limit_db + delta).clamp(30.0, settings.graph_max_db);
            settings.limit_db = settings.limit_db.max(settings.graph_min_db);
            false
        }
        MenuField::GraphMin => {
            settings.graph_min_db =
                (settings.graph_min_db + delta).clamp(10.0, settings.graph_max_db - 1.0);
            settings.limit_db = settings.limit_db.max(settings.graph_min_db);
            false
        }
        MenuField::GraphMax => {
            settings.graph_max_db =
                (settings.graph_max_db + delta).clamp(settings.graph_min_db + 1.0, 140.0);
            settings.limit_db = settings.limit_db.min(settings.graph_max_db);
            false
        }
        MenuField::ViewMode => {
            *display_mode = display_mode.toggle();
            false
        }
        MenuField::ResetDefaults => {
            *settings = UiSettings::default();
            *display_mode = DisplayMode::Peak;
            true
        }
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("USERPROFILE")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| {
            let drive = std::env::var("HOMEDRIVE").ok()?;
            let path = std::env::var("HOMEPATH").ok()?;
            let combined = format!("{drive}{path}");
            if combined.trim().is_empty() {
                None
            } else {
                Some(PathBuf::from(combined))
            }
        })
}

fn settings_path() -> PathBuf {
    home_dir()
        .map(|p| p.join(".ssh-soundmeter-settings"))
        .unwrap_or_else(|| PathBuf::from(".ssh-soundmeter-settings"))
}

fn host_key_path() -> PathBuf {
    home_dir()
        .map(|p| p.join(".ssh-soundmeter-hostkey"))
        .unwrap_or_else(|| PathBuf::from(".ssh-soundmeter-hostkey"))
}

fn load_or_create_ssh_host_key() -> Result<PrivateKey> {
    let path = host_key_path();
    if path.exists() {
        return PrivateKey::read_openssh_file(&path)
            .with_context(|| format!("failed reading SSH host key {}", path.display()));
    }

    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| anyhow::anyhow!("failed generating server host key: {e}"))?;
    key.write_openssh_file(&path, ssh_key::LineEnding::LF)
        .with_context(|| format!("failed writing SSH host key {}", path.display()))?;
    Ok(key)
}

fn load_ui_settings() -> Option<UiSettings> {
    let path = settings_path();
    let content = fs::read_to_string(path).ok()?;
    let mut out = UiSettings::default();
    for line in content.lines() {
        let mut parts = line.splitn(2, '=');
        let key = parts.next()?.trim();
        let val = parts.next()?.trim().parse::<f32>().ok()?;
        match key {
            "limit_db" => out.limit_db = val,
            "graph_min_db" => out.graph_min_db = val,
            "graph_max_db" => out.graph_max_db = val,
            _ => {}
        }
    }
    if out.graph_max_db <= out.graph_min_db {
        return None;
    }
    out.limit_db = out.limit_db.clamp(out.graph_min_db, out.graph_max_db);
    Some(out)
}

fn save_ui_settings(settings: UiSettings) -> Result<PathBuf> {
    let path = settings_path();
    let data = format!(
        "limit_db={:.1}\ngraph_min_db={:.1}\ngraph_max_db={:.1}\n",
        settings.limit_db, settings.graph_min_db, settings.graph_max_db
    );
    fs::write(&path, data).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(path)
}

fn autosave_ui_settings(settings: UiSettings, last_decode: &mut String) {
    *last_decode = match save_ui_settings(settings) {
        Ok(path) => format!("saved settings to {}", path.display()),
        Err(e) => format!("save failed: {e}"),
    };
}

fn resolve_display_host(host: &str) -> String {
    if host == "0.0.0.0" || host == "::" {
        discover_local_ip().to_string()
    } else {
        host.to_string()
    }
}

fn compute_big_scale(inner_w: u16, inner_h: u16, text: &str) -> u16 {
    let base_h = 5u16;
    let mut base_w = 0u16;
    for ch in text.chars() {
        base_w = base_w.saturating_add(big_glyph(ch)[0].chars().count() as u16);
        base_w = base_w.saturating_add(1);
    }
    base_w = base_w.saturating_sub(1);
    if base_w == 0 {
        return 1;
    }
    let w_budget = inner_w.saturating_sub(4);
    let h_budget = inner_h.saturating_sub(4);
    let by_w = (w_budget / base_w).max(1);
    let by_h = (h_budget / (base_h + 1)).max(1);
    by_w.min(by_h).clamp(1, 4)
}

fn fit_big_scale(inner_w: u16, inner_h: u16, text: &str) -> u16 {
    let mut scale = compute_big_scale(inner_w, inner_h, text);
    while scale > 1 {
        let (w, h) = big_text_size(text, scale);
        if w.saturating_add(2) <= inner_w && h.saturating_add(2) <= inner_h {
            break;
        }
        scale -= 1;
    }
    scale
}

fn big_text_size(text: &str, scale: u16) -> (u16, u16) {
    let mut width = 0u16;
    for ch in text.chars() {
        let glyph = big_glyph(ch);
        width = width.saturating_add((glyph[0].chars().count() as u16).saturating_mul(scale));
        width = width.saturating_add(scale);
    }
    (width.saturating_sub(scale), 5u16.saturating_mul(scale))
}

fn render_big_text(
    f: &mut ratatui::Frame<'_>,
    x: u16,
    y: u16,
    text: &str,
    style: Style,
    scale: u16,
    over_limit: bool,
) {
    if text.is_empty() {
        return;
    }
    let mut rows = vec![
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    ];
    for ch in text.chars() {
        let glyph = big_glyph(ch);
        for i in 0..5 {
            for c in glyph[i].chars() {
                for _ in 0..scale {
                    rows[i].push(c);
                }
            }
            for _ in 0..scale {
                rows[i].push(' ');
            }
        }
    }
    let total_h = (rows.len() as u16).saturating_mul(scale).max(1);
    for (i, row) in rows.iter().enumerate() {
        for sy in 0..scale {
            let out_y = y
                .saturating_add((i as u16).saturating_mul(scale))
                .saturating_add(sy);
            let rel_y = (i as u16).saturating_mul(scale).saturating_add(sy) as usize;
            let row_style = if over_limit {
                style.fg(Color::Red)
            } else {
                style.fg(subtle_text_gradient(rel_y, total_h as usize))
            };
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(row.clone(), row_style))),
                Rect {
                    x,
                    y: out_y,
                    width: row.chars().count() as u16,
                    height: 1,
                },
            );
        }
    }
}

fn subtle_text_gradient(y: usize, height: usize) -> Color {
    if height <= 1 {
        return Color::White;
    }
    let t = y as f32 / (height - 1) as f32;
    let r = lerp_u8(255, 160, t);
    let g = lerp_u8(255, 172, t);
    let b = lerp_u8(255, 196, t);
    Color::Rgb(r, g, b)
}

fn big_glyph(ch: char) -> [&'static str; 5] {
    match ch {
        '0' => ["█████", "█   █", "█   █", "█   █", "█████"],
        '1' => ["  ██ ", " ███ ", "  ██ ", "  ██ ", "█████"],
        '2' => ["█████", "    █", "█████", "█    ", "█████"],
        '3' => ["█████", "    █", " ████", "    █", "█████"],
        '4' => ["█   █", "█   █", "█████", "    █", "    █"],
        '5' => ["█████", "█    ", "█████", "    █", "█████"],
        '6' => ["█████", "█    ", "█████", "█   █", "█████"],
        '7' => ["█████", "    █", "   █ ", "  █  ", " █   "],
        '8' => ["█████", "█   █", "█████", "█   █", "█████"],
        '9' => ["█████", "█   █", "█████", "    █", "█████"],
        '.' => ["     ", "     ", "     ", "     ", "  ██ "],
        '-' => ["     ", "     ", "█████", "     ", "     "],
        'n' | 'N' => ["     ", "███  ", "█  █ ", "█  ██", "█   █"],
        'a' | 'A' => ["     ", " ███ ", "█   █", "█████", "█   █"],
        '/' => ["    █", "   █ ", "  █  ", " █   ", "█    "],
        _ => ["     ", "  ?  ", "  ?  ", "  ?  ", "     "],
    }
}
