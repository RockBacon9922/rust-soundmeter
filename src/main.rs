use std::collections::VecDeque;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::Local;
use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use hidapi::{DeviceInfo, HidApi, HidDevice};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

const DEFAULT_VID: u16 = 0x64BD;
const DEFAULT_PID: u16 = 0x74E3;
const HID_READ_TIMEOUT_MS: i32 = 200;
const MAX_FRAME_BYTES: usize = 64;

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
        /// Optional poll frame; if omitted, passively reads only.
        #[arg(long)]
        tx: Option<String>,
        #[arg(long, default_value_t = 500)]
        tx_interval_ms: u64,
    },
}

#[derive(Clone, Debug)]
struct Frame {
    ts: chrono::DateTime<Local>,
    bytes: Vec<u8>,
    decoded: Option<String>,
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
            tx,
            tx_interval_ms,
        }) => cmd_tui(vid, pid, tx, tx_interval_ms),
        None => cmd_tui(
            format!("0x{DEFAULT_VID:04X}"),
            format!("0x{DEFAULT_PID:04X}"),
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

fn cmd_tui(vid: String, pid: String, tx: Option<String>, tx_interval_ms: u64) -> Result<()> {
    let vid = parse_hex_u16(&vid)?;
    let pid = parse_hex_u16(&pid)?;
    let tx_frame = tx.as_deref().map(parse_hex_bytes).transpose()?;
    let api = HidApi::new().context("failed to initialize hidapi")?;
    let dev = open_hid_device(&api, vid, pid)?;

    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)
        .context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;
    terminal.clear()?;

    let result = run_tui_loop(
        &mut terminal,
        &dev,
        vid,
        pid,
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
    dev: &HidDevice,
    vid: u16,
    pid: u16,
    tx_frame: Option<&[u8]>,
    tx_interval_ms: u64,
) -> Result<()> {
    let mut buf = [0u8; MAX_FRAME_BYTES];
    let mut frames: VecDeque<Frame> = VecDeque::with_capacity(200);
    let mut last_tx = Instant::now()
        .checked_sub(Duration::from_millis(tx_interval_ms))
        .unwrap_or_else(Instant::now);
    let mut last_decode = String::from("n/a");

    loop {
        if let Some(tx) = tx_frame
            && last_tx.elapsed() >= Duration::from_millis(tx_interval_ms)
        {
            if let Err(e) = write_frame(dev, tx) {
                frames.push_front(Frame {
                    ts: Local::now(),
                    bytes: tx.to_vec(),
                    decoded: Some(format!("TX error: {e}")),
                });
            } else {
                frames.push_front(Frame {
                    ts: Local::now(),
                    bytes: tx.to_vec(),
                    decoded: Some("TX probe".to_string()),
                });
            }
            while frames.len() > 200 {
                frames.pop_back();
            }
            last_tx = Instant::now();
        }

        match dev.read_timeout(&mut buf, HID_READ_TIMEOUT_MS) {
            Ok(n) if n > 0 => {
                let data = buf[..n].to_vec();
                let decoded = decode_frame(&data);
                if let Some(ref d) = decoded {
                    last_decode = d.clone();
                }
                frames.push_front(Frame {
                    ts: Local::now(),
                    bytes: data,
                    decoded,
                });
                while frames.len() > 200 {
                    frames.pop_back();
                }
            }
            Ok(_) => {}
            Err(e) => {
                frames.push_front(Frame {
                    ts: Local::now(),
                    bytes: Vec::new(),
                    decoded: Some(format!("Read error: {e}")),
                });
                while frames.len() > 200 {
                    frames.pop_back();
                }
            }
        }

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Min(1),
                ])
                .split(f.area());

            let header = Paragraph::new(Line::from(vec![
                Span::styled("USB Sound Meter", Style::default().fg(Color::Cyan)),
                Span::raw(format!("  VID=0x{vid:04X} PID=0x{pid:04X}")),
                Span::raw("  q=quit"),
            ]))
            .block(Block::default().borders(Borders::ALL).title("Session"));

            let decode = Paragraph::new(last_decode.clone()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Last Decoded Measurement"),
            );

            let mut lines: Vec<Line> = Vec::new();
            for frame in frames.iter().take(35) {
                let ts = frame.ts.format("%H:%M:%S%.3f").to_string();
                let mut line = format!("{ts}  {}", fmt_hex(&frame.bytes));
                if let Some(decoded) = &frame.decoded {
                    line.push_str("  |  ");
                    line.push_str(decoded);
                }
                lines.push(Line::from(line));
            }
            if lines.is_empty() {
                lines.push(Line::from("No frames yet."));
            }
            let traffic = Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title("Traffic"));

            f.render_widget(header, chunks[0]);
            f.render_widget(decode, chunks[1]);
            f.render_widget(traffic, chunks[2]);
        })?;

        if event::poll(Duration::from_millis(10)).context("event poll failed")?
            && let Event::Key(k) = event::read().context("event read failed")?
            && k.code == KeyCode::Char('q')
        {
            break;
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

    for window in bytes.windows(2) {
        let raw = u16::from_le_bytes([window[0], window[1]]);
        let db = raw as f32 / 10.0;
        if (20.0..140.0).contains(&db) {
            return Some(format!("candidate_db={db:.1} (from 0x{raw:04X})"));
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
