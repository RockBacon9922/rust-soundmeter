use std::collections::VecDeque;
use std::io::{self, Write};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::Local;
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use hidapi::{DeviceInfo, HidApi, HidDevice};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::prelude::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

const DEFAULT_VID: u16 = 0x64BD;
const DEFAULT_PID: u16 = 0x74E3;
const REPORT_ID: u8 = 0x00;
const FRAME_FILL: u8 = 0x23;
const FRAME_LEN: usize = 65;
const HID_READ_TIMEOUT_MS: i32 = 200;
const TUI_READ_TIMEOUT_MS: i32 = 5;
const MAX_FRAME_BYTES: usize = FRAME_LEN;
const FLAG_BATTERY: u8 = 0x80;
const FLAG_MODE_FAST: u8 = 0x40;
const FLAG_MAX: u8 = 0x20;
const FLAG_WEIGHT_C: u8 = 0x10;
const TUI_FRAME_MS: u64 = 33;
const SETTINGS_ITEM_COUNT: usize = 4;

#[derive(Parser, Debug)]
#[command(name = "ssh-soundmeter")]
#[command(about = "USB sound meter reverse-engineering CLI")]
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
    /// Write device settings and exit.
    Set {
        #[arg(long, default_value = "0x64BD")]
        vid: String,
        #[arg(long, default_value = "0x74E3")]
        pid: String,
        /// Device mode: FAST or SLOW.
        #[arg(long)]
        set_mode: Option<String>,
        /// MAX state: MAX or NORMAL.
        #[arg(long)]
        set_max: Option<String>,
        /// Weighting: A or C.
        #[arg(long)]
        set_weighting: Option<String>,
        /// Range (vendor docs indicate 0..4).
        #[arg(long)]
        set_range: Option<u8>,
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
        /// Send a default ReadPoint poll frame when --tx is not provided.
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        wake: bool,
        /// Interval in ms for optional TX polling frame.
        #[arg(long, default_value_t = 1000)]
        tx_interval_ms: u64,
        /// Apply device mode on startup: FAST or SLOW.
        #[arg(long)]
        set_mode: Option<String>,
        /// Apply MAX state on startup: MAX or NORMAL.
        #[arg(long)]
        set_max: Option<String>,
        /// Apply weighting on startup: A or C.
        #[arg(long)]
        set_weighting: Option<String>,
        /// Apply range on startup (vendor docs indicate 0..4).
        #[arg(long)]
        set_range: Option<u8>,
    },
    /// Show a live terminal UI with current reading and scrolling history.
    Tui {
        #[arg(long, default_value = "0x64BD")]
        vid: String,
        #[arg(long, default_value = "0x74E3")]
        pid: String,
        /// Poll interval in ms for ReadPoint requests.
        #[arg(long, default_value_t = 60)]
        tx_interval_ms: u64,
        /// Use a minimal padded ReadPoint poll frame (falls back automatically if rejected).
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        compact_poll: bool,
        /// Nerd Font rendering mode for graph/text: auto, on, or off.
        #[arg(long, value_enum, default_value_t = NerdFontMode::Off)]
        nerd_font: NerdFontMode,
        /// Apply device mode on startup: FAST or SLOW.
        #[arg(long)]
        set_mode: Option<String>,
        /// Apply MAX state on startup: MAX or NORMAL.
        #[arg(long)]
        set_max: Option<String>,
        /// Apply weighting on startup: A or C.
        #[arg(long)]
        set_weighting: Option<String>,
        /// Apply range on startup (vendor docs indicate 0..4).
        #[arg(long)]
        set_range: Option<u8>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum NerdFontMode {
    Auto,
    On,
    Off,
}

#[derive(Clone, Debug, Default)]
struct ProtocolMember {
    mea_value: f32,
    bat: u8,
    mode: &'static str,
    is_max: bool,
    weighting: &'static str,
    range: u8,
    time: Option<String>,
    date: Option<String>,
}

#[derive(Clone, Debug)]
struct SettingsMenuState {
    open: bool,
    selected: usize,
    settings: ProtocolMember,
}

fn protocol_report_byte(buffer: &[u8], idx: usize) -> Option<u8> {
    let payload = if buffer.len() >= FRAME_LEN && !buffer.is_empty() && buffer[0] == REPORT_ID {
        &buffer[1..]
    } else {
        buffer
    };
    payload.get(idx).copied()
}

fn protocol_command(code: u8) -> Vec<u8> {
    let mut out = vec![FRAME_FILL; FRAME_LEN];
    out[0] = REPORT_ID;
    out[1] = code;
    out
}

fn protocol_read_point() -> Vec<u8> {
    protocol_command(0xB3)
}

fn protocol_read_point_compact() -> Vec<u8> {
    let mut out = vec![0u8; FRAME_LEN];
    out[0] = REPORT_ID;
    out[1] = 0xB3;
    out
}

fn protocol_write_settings(set: &ProtocolMember) -> Vec<u8> {
    let mut out = protocol_command(0x56);
    let mut flags = 0u8;
    if set.mode == "FAST" {
        flags |= FLAG_MODE_FAST;
    }
    if set.is_max {
        flags |= FLAG_MAX;
    }
    if set.weighting == "C" {
        flags |= FLAG_WEIGHT_C;
    }
    flags |= set.range & 0x0F;
    out[2] = flags;
    out
}

fn protocol_is_correct(buffer: &[u8]) -> bool {
    protocol_report_byte(buffer, 0) == Some(0xC4) || protocol_report_byte(buffer, 1) == Some(0xC4)
}

fn parse_startup_settings(
    mode: Option<String>,
    max: Option<String>,
    weighting: Option<String>,
    range: Option<u8>,
) -> Result<Option<ProtocolMember>> {
    if mode.is_none() && max.is_none() && weighting.is_none() && range.is_none() {
        return Ok(None);
    }
    let mode = match mode.as_deref() {
        None => "SLOW",
        Some(v) if v.eq_ignore_ascii_case("FAST") => "FAST",
        Some(v) if v.eq_ignore_ascii_case("SLOW") => "SLOW",
        Some(v) => bail!("invalid --set-mode '{v}', expected FAST or SLOW"),
    };
    let max = match max.as_deref() {
        None => false,
        Some(v) if v.eq_ignore_ascii_case("MAX") => true,
        Some(v) if v.eq_ignore_ascii_case("NORMAL") => false,
        Some(v) => bail!("invalid --set-max '{v}', expected MAX or NORMAL"),
    };
    let weighting = match weighting.as_deref() {
        None => "A",
        Some(v) if v.eq_ignore_ascii_case("A") => "A",
        Some(v) if v.eq_ignore_ascii_case("C") => "C",
        Some(v) => bail!("invalid --set-weighting '{v}', expected A or C"),
    };
    let range = range.unwrap_or(0);
    if range > 4 {
        bail!("invalid --set-range {range}, expected 0..4");
    }
    Ok(Some(ProtocolMember {
        mea_value: 0.0,
        bat: 0,
        mode,
        is_max: max,
        weighting,
        range,
        time: None,
        date: None,
    }))
}

fn default_tui_settings() -> ProtocolMember {
    ProtocolMember {
        mea_value: 0.0,
        bat: 0,
        mode: "SLOW",
        is_max: false,
        weighting: "A",
        range: 0,
        time: None,
        date: None,
    }
}

fn move_menu_selection(selected: usize, delta: isize) -> usize {
    let count = SETTINGS_ITEM_COUNT as isize;
    (((selected as isize + delta).rem_euclid(count)) as usize).min(SETTINGS_ITEM_COUNT - 1)
}

fn adjust_menu_setting(settings: &mut ProtocolMember, selected: usize, delta: isize) -> bool {
    match selected {
        0 => {
            settings.weighting = if settings.weighting == "A" { "C" } else { "A" };
            true
        }
        1 => {
            settings.mode = if settings.mode == "FAST" {
                "SLOW"
            } else {
                "FAST"
            };
            true
        }
        2 => {
            settings.is_max = !settings.is_max;
            true
        }
        3 => {
            let next = (settings.range as isize + delta).clamp(0, 4) as u8;
            if next != settings.range {
                settings.range = next;
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

fn max_label(is_max: bool) -> &'static str {
    if is_max { "MAX" } else { "NORMAL" }
}

fn device_settings_summary(settings: &ProtocolMember) -> String {
    format!(
        "mode={} max={} weight={} range={}",
        settings.mode,
        max_label(settings.is_max),
        settings.weighting,
        settings.range
    )
}

fn apply_startup_settings(dev: &HidDevice, settings: &ProtocolMember) -> Result<bool> {
    let frame = protocol_write_settings(settings);
    write_frame(dev, &frame)?;
    let mut buf = [0u8; MAX_FRAME_BYTES];
    for _ in 0..8 {
        match dev.read_timeout(&mut buf, HID_READ_TIMEOUT_MS) {
            Ok(n) if n > 0 => {
                if protocol_is_correct(&buf[..n]) {
                    return Ok(true);
                }
            }
            Ok(_) => {}
            Err(e) => return Err(e).context("failed while waiting for settings ACK"),
        }
    }
    Ok(false)
}

fn protocol_analysis_read_point(buffer: &[u8]) -> Option<ProtocolMember> {
    fn parse_at(buffer: &[u8], offset: usize) -> Option<ProtocolMember> {
        let high = protocol_report_byte(buffer, offset)? as u16;
        let low = protocol_report_byte(buffer, offset + 1)? as u16;
        let flags = protocol_report_byte(buffer, offset + 2)?;
        let signed = ((high << 8) | low) as i16;
        let mea_value = signed as f32 / 10.0;
        let mode = if flags & FLAG_MODE_FAST == 0 {
            "SLOW"
        } else {
            "FAST"
        };
        let is_max = flags & FLAG_MAX != 0;
        let weighting = if flags & FLAG_WEIGHT_C == 0 { "A" } else { "C" };
        Some(ProtocolMember {
            mea_value,
            bat: (flags & FLAG_BATTERY) >> 7,
            mode,
            is_max,
            weighting,
            range: flags & 0x0F,
            time: None,
            date: None,
        })
    }

    let primary = parse_at(buffer, 0);
    let fallback = parse_at(buffer, 1);
    match (primary, fallback) {
        (Some(a), Some(b)) => {
            let a_ok = (-50.0..=150.0).contains(&a.mea_value);
            let b_ok = (-50.0..=150.0).contains(&b.mea_value);
            if a_ok && !b_ok {
                Some(a)
            } else if b_ok && !a_ok {
                Some(b)
            } else if a.range <= 4 && b.range > 4 {
                Some(a)
            } else if b.range <= 4 && a.range > 4 {
                Some(b)
            } else {
                Some(a)
            }
        }
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn bcd_to_u8(v: u8) -> u8 {
    ((v >> 4) * 10) + (v & 0x0F)
}

fn protocol_analysis_read_history_header(buffer: &[u8]) -> Option<ProtocolMember> {
    if protocol_report_byte(buffer, 0)? != 0xFD {
        return None;
    }
    let flags = protocol_report_byte(buffer, 1)?;
    let hh = bcd_to_u8(protocol_report_byte(buffer, 4)?);
    let mm = bcd_to_u8(protocol_report_byte(buffer, 3)?);
    let ss = bcd_to_u8(protocol_report_byte(buffer, 2)?);
    let yy = 2000u16 + bcd_to_u8(protocol_report_byte(buffer, 7)?) as u16;
    let mon = bcd_to_u8(protocol_report_byte(buffer, 6)?);
    let day = bcd_to_u8(protocol_report_byte(buffer, 5)?);
    let mode = if flags & FLAG_MODE_FAST == 0 {
        "SLOW"
    } else {
        "FAST"
    };
    let is_max = flags & FLAG_MAX != 0;
    let weighting = if flags & FLAG_WEIGHT_C == 0 { "A" } else { "C" };
    Some(ProtocolMember {
        mea_value: 0.0,
        bat: (flags & FLAG_BATTERY) >> 7,
        mode,
        is_max,
        weighting,
        range: flags & 0x0F,
        time: Some(format!("{hh}:{mm}:{ss}")),
        date: Some(format!("{yy}-{mon}-{day}")),
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Scan { vid, pid }) => cmd_scan(vid, pid),
        Some(Command::Set {
            vid,
            pid,
            set_mode,
            set_max,
            set_weighting,
            set_range,
        }) => cmd_set(
            vid,
            pid,
            parse_startup_settings(set_mode, set_max, set_weighting, set_range)?,
        ),
        Some(Command::Sniff {
            vid,
            pid,
            tx,
            wake,
            tx_interval_ms,
            set_mode,
            set_max,
            set_weighting,
            set_range,
        }) => cmd_sniff(
            vid,
            pid,
            tx,
            wake,
            tx_interval_ms,
            parse_startup_settings(set_mode, set_max, set_weighting, set_range)?,
        ),
        Some(Command::Tui {
            vid,
            pid,
            tx_interval_ms,
            compact_poll,
            nerd_font,
            set_mode,
            set_max,
            set_weighting,
            set_range,
        }) => cmd_tui(
            vid,
            pid,
            tx_interval_ms,
            compact_poll,
            nerd_font,
            parse_startup_settings(set_mode, set_max, set_weighting, set_range)?,
        ),
        None => cmd_sniff(
            format!("0x{DEFAULT_VID:04X}"),
            format!("0x{DEFAULT_PID:04X}"),
            None,
            true,
            1000,
            None,
        ),
    }
}

fn cmd_set(vid: String, pid: String, startup_settings: Option<ProtocolMember>) -> Result<()> {
    let settings = startup_settings.ok_or_else(|| {
        anyhow::anyhow!("provide at least one of --set-mode/--set-max/--set-weighting/--set-range")
    })?;
    let (vid, pid) = lock_target_ids(&vid, &pid)?;
    let api = HidApi::new().context("failed to initialize hidapi")?;
    let dev = open_hid_device(&api, vid, pid)?;
    let frame = protocol_write_settings(&settings);
    println!("Connected to VID=0x{vid:04X} PID=0x{pid:04X}");
    println!(
        "writing settings {} | TX {}",
        device_settings_summary(&settings),
        fmt_hex(&frame)
    );
    let ack = apply_startup_settings(&dev, &settings)?;
    println!("write result: {}", if ack { "ack" } else { "no-ack" });
    Ok(())
}

fn cmd_scan(vid: Option<String>, pid: Option<String>) -> Result<()> {
    if vid.is_some() || pid.is_some() {
        eprintln!(
            "Ignoring custom VID/PID filters. This app is locked to VID=0x{DEFAULT_VID:04X} PID=0x{DEFAULT_PID:04X}."
        );
    }

    let api = HidApi::new().context("failed to initialize hidapi")?;
    let mut count = 0usize;

    for dev in api.device_list() {
        if dev.vendor_id() != DEFAULT_VID {
            continue;
        }
        if dev.product_id() != DEFAULT_PID {
            continue;
        }

        count += 1;
        print_device(
            dev,
            dev.vendor_id() == DEFAULT_VID && dev.product_id() == DEFAULT_PID,
        );
    }

    if count == 0 {
        println!(
            "No matching HID devices found for VID=0x{DEFAULT_VID:04X} PID=0x{DEFAULT_PID:04X}."
        );
    }
    Ok(())
}

fn lock_target_ids(vid: &str, pid: &str) -> Result<(u16, u16)> {
    let parsed_vid = parse_hex_u16(vid)?;
    let parsed_pid = parse_hex_u16(pid)?;
    if parsed_vid != DEFAULT_VID || parsed_pid != DEFAULT_PID {
        bail!(
            "this app only supports VID=0x{DEFAULT_VID:04X} PID=0x{DEFAULT_PID:04X} (got VID=0x{parsed_vid:04X} PID=0x{parsed_pid:04X})"
        );
    }
    Ok((DEFAULT_VID, DEFAULT_PID))
}

fn cmd_sniff(
    vid: String,
    pid: String,
    tx: Option<String>,
    wake: bool,
    tx_interval_ms: u64,
    startup_settings: Option<ProtocolMember>,
) -> Result<()> {
    let (vid, pid) = lock_target_ids(&vid, &pid)?;
    let tx_frame = resolve_tx_frame(tx, wake)?;
    let api = HidApi::new().context("failed to initialize hidapi")?;
    let dev = open_hid_device(&api, vid, pid)?;
    println!("Connected to VID=0x{vid:04X} PID=0x{pid:04X}");
    if let Some(settings) = startup_settings.as_ref() {
        let ack = apply_startup_settings(&dev, settings)?;
        println!("startup settings write ack={ack}");
    }

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
    tx_interval_ms: u64,
    compact_poll: bool,
    nerd_font_mode: NerdFontMode,
    startup_settings: Option<ProtocolMember>,
) -> Result<()> {
    let (vid, pid) = lock_target_ids(&vid, &pid)?;
    let api = HidApi::new().context("failed to initialize hidapi")?;
    let dev = open_hid_device(&api, vid, pid)?;

    if let Some(settings) = startup_settings.as_ref() {
        apply_startup_settings(&dev, settings)?;
    }
    let initial_settings = startup_settings.unwrap_or_else(default_tui_settings);

    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal backend")?;
    terminal.clear().context("failed to clear terminal")?;

    let nerd_font = resolve_nerd_font_mode(nerd_font_mode);
    let app_result = run_tui(
        &mut terminal,
        &dev,
        vid,
        pid,
        tx_interval_ms,
        compact_poll,
        nerd_font,
        initial_settings,
    );

    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")?;

    app_result
}

fn run_tui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    dev: &HidDevice,
    vid: u16,
    pid: u16,
    tx_interval_ms: u64,
    compact_poll: bool,
    nerd_font: bool,
    initial_settings: ProtocolMember,
) -> Result<()> {
    let sample_interval = Duration::from_millis(tx_interval_ms.max(20));
    let frame_interval = Duration::from_millis(TUI_FRAME_MS);
    let mut last_tx = Instant::now()
        .checked_sub(sample_interval)
        .unwrap_or_else(Instant::now);
    let mut history = VecDeque::new();
    let mut current = None;
    let mut status = String::from("polling");
    let mut buf = [0u8; MAX_FRAME_BYTES];
    let compact_frame = protocol_read_point_compact();
    let standard_frame = protocol_read_point();
    let mut use_compact = compact_poll;
    let mut menu = SettingsMenuState {
        open: false,
        selected: 0,
        settings: initial_settings,
    };
    let mut initialized_from_device = false;

    loop {
        while event::poll(Duration::from_millis(0)).context("failed to poll terminal event")? {
            match event::read().context("failed to read terminal event")? {
                Event::Key(key)
                    if key.kind == KeyEventKind::Press
                        && matches!(
                            key.code,
                            KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('c')
                        )
                        && (key.code != KeyCode::Char('c')
                            || key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL)) =>
                {
                    if menu.open && key.code == KeyCode::Esc {
                        menu.open = false;
                        continue;
                    }
                    return Ok(());
                }
                Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                    KeyCode::Char('m') => {
                        menu.open = !menu.open;
                        status = if menu.open {
                            String::from("settings menu open")
                        } else {
                            String::from("settings menu closed")
                        };
                    }
                    KeyCode::Up | KeyCode::Char('k') if menu.open => {
                        menu.selected = move_menu_selection(menu.selected, -1);
                    }
                    KeyCode::Down | KeyCode::Char('j') if menu.open => {
                        menu.selected = move_menu_selection(menu.selected, 1);
                    }
                    KeyCode::Left | KeyCode::Char('h') if menu.open => {
                        if adjust_menu_setting(&mut menu.settings, menu.selected, -1) {
                            match apply_startup_settings(dev, &menu.settings) {
                                Ok(true) => {
                                    status =
                                        format!("saved {}", device_settings_summary(&menu.settings))
                                }
                                Ok(false) => status = String::from("save sent (no-ack)"),
                                Err(e) => status = format!("save failed: {e}"),
                            }
                        }
                    }
                    KeyCode::Right | KeyCode::Char('l') if menu.open => {
                        if adjust_menu_setting(&mut menu.settings, menu.selected, 1) {
                            match apply_startup_settings(dev, &menu.settings) {
                                Ok(true) => {
                                    status =
                                        format!("saved {}", device_settings_summary(&menu.settings))
                                }
                                Ok(false) => status = String::from("save sent (no-ack)"),
                                Err(e) => status = format!("save failed: {e}"),
                            }
                        }
                    }
                    _ => {}
                },
                Event::Resize(_, _) => {
                    terminal
                        .clear()
                        .context("failed to clear terminal after resize")?;
                }
                _ => {}
            }
        }

        if last_tx.elapsed() >= sample_interval {
            let poll_frame = if use_compact {
                &compact_frame
            } else {
                &standard_frame
            };
            if let Err(e) = write_frame(dev, poll_frame) {
                if use_compact {
                    use_compact = false;
                    status = format!("compact poll failed, using standard: {e}");
                } else {
                    status = format!("poll write error: {e}");
                }
            } else if use_compact {
                status = String::from("polling (compact)");
            } else {
                status = String::from("polling");
            }
            last_tx = Instant::now();
        }

        match dev.read_timeout(&mut buf, TUI_READ_TIMEOUT_MS) {
            Ok(n) if n > 0 => {
                if let Some(measurement) = protocol_analysis_read_point(&buf[..n])
                    && (-50.0..=150.0).contains(&measurement.mea_value)
                {
                    if !initialized_from_device {
                        menu.settings.mode = measurement.mode;
                        menu.settings.is_max = measurement.is_max;
                        menu.settings.weighting = measurement.weighting;
                        menu.settings.range = measurement.range.min(4);
                        initialized_from_device = true;
                    }
                    current = Some(measurement.mea_value);
                    history.push_back(measurement.mea_value);
                    while history.len() > 20_000 {
                        history.pop_front();
                    }
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }

        terminal
            .draw(|frame| {
                draw_tui(
                    frame,
                    vid,
                    pid,
                    current,
                    &history,
                    sample_interval,
                    &status,
                    nerd_font,
                    &menu,
                )
            })
            .context("failed drawing terminal frame")?;

        thread::sleep(frame_interval);
    }
}

fn resolve_nerd_font_mode(mode: NerdFontMode) -> bool {
    match mode {
        NerdFontMode::On => true,
        NerdFontMode::Off => false,
        NerdFontMode::Auto => detect_nerd_font(),
    }
}

fn detect_nerd_font() -> bool {
    if let Ok(v) = std::env::var("SSH_SOUNDMETER_NERD_FONT") {
        let value = v.trim().to_ascii_lowercase();
        if matches!(value.as_str(), "1" | "true" | "yes" | "on") {
            return true;
        }
        if matches!(value.as_str(), "0" | "false" | "no" | "off") {
            return false;
        }
    }

    let utf8_locale = ["LC_ALL", "LC_CTYPE", "LANG"].iter().any(|k| {
        std::env::var(k)
            .map(|v| v.to_ascii_uppercase().contains("UTF-8"))
            .unwrap_or(false)
    });
    if !utf8_locale {
        return false;
    }

    let term_program = std::env::var("TERM_PROGRAM").unwrap_or_default();
    let term = std::env::var("TERM").unwrap_or_default();
    matches!(
        term_program.as_str(),
        "WezTerm" | "iTerm.app" | "WarpTerminal" | "vscode"
    ) || term.contains("xterm")
        || term.contains("kitty")
        || term.contains("alacritty")
        || term.contains("wezterm")
        || term.contains("tmux")
}

fn draw_tui(
    frame: &mut ratatui::Frame<'_>,
    vid: u16,
    pid: u16,
    current: Option<f32>,
    history: &VecDeque<f32>,
    sample_interval: Duration,
    status: &str,
    nerd_font: bool,
    menu: &SettingsMenuState,
) {
    let history_seconds =
        (sample_interval.as_secs_f32() * frame.area().width as f32).round() as u32;
    let title = format!(
        "Volume History  VID=0x{vid:04X} PID=0x{pid:04X}  window=~{history_seconds}s  m=settings  q/Ctrl+C=quit"
    );
    let block = Block::default().borders(Borders::ALL).title(title);
    let area = frame.area();
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width < 3 || inner.height < 3 {
        return;
    }

    let (cols, latest_db, _) = history_columns(history, inner.width as usize);
    let lines = build_graph_lines(&cols, inner.height as usize, nerd_font);
    frame.render_widget(Paragraph::new(lines), inner);

    let shown_db = current.or(latest_db);
    let current_text = shown_db
        .map(|db| format!("{db:.1}"))
        .unwrap_or_else(|| "n/a".to_string());
    let scale = compute_big_scale(inner.width, inner.height, &current_text, nerd_font);
    let (big_w, big_h) = big_text_size(&current_text, scale, nerd_font);
    let tx = inner
        .x
        .saturating_add(inner.width / 2)
        .saturating_sub(big_w / 2);
    let ty = inner
        .y
        .saturating_add(inner.height / 2)
        .saturating_sub(big_h / 2);
    render_big_text(
        frame,
        tx,
        ty,
        &current_text,
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
        scale,
        nerd_font,
    );

    let unit = "dB";
    let ux = inner
        .x
        .saturating_add(inner.width / 2)
        .saturating_sub((unit.len() as u16) / 2);
    let uy = ty.saturating_add(big_h).saturating_add(1);
    if uy < inner.bottom() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                unit,
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

    if inner.height > 2 {
        let status_rect = Rect {
            x: inner.x.saturating_add(1),
            y: inner.bottom().saturating_sub(1),
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                status.to_string(),
                Style::default().fg(Color::DarkGray),
            ))),
            status_rect,
        );
    }

    if menu.open {
        draw_settings_popup(frame, area, menu);
    }
}

fn draw_settings_popup(frame: &mut ratatui::Frame<'_>, area: Rect, menu: &SettingsMenuState) {
    let popup_width = if area.width >= 20 {
        area.width.min(44)
    } else {
        area.width
    };
    let popup_height = if area.height >= 7 {
        area.height.min(11)
    } else {
        area.height
    };
    let popup = Rect {
        x: area.x + area.width.saturating_sub(popup_width) / 2,
        y: area.y + area.height.saturating_sub(popup_height) / 2,
        width: popup_width,
        height: popup_height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .title(" Meter Settings ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::White).bg(Color::Black));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = [
        format!("Weighting: {}", menu.settings.weighting),
        format!("Mode     : {}", menu.settings.mode),
        format!(
            "Max Hold : {}",
            if menu.settings.is_max {
                "MAX"
            } else {
                "NORMAL"
            }
        ),
        format!("Range    : {}", menu.settings.range),
    ];
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(Span::styled(
        "Use j/k or arrows. h/l or left/right to change.",
        Style::default().fg(Color::Gray),
    )));
    lines.push(Line::from(""));
    for (idx, row) in rows.iter().enumerate() {
        let prefix = if idx == menu.selected { "> " } else { "  " };
        let style = if idx == menu.selected {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(Span::styled(format!("{prefix}{row}"), style)));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Changes auto-save immediately. Press m or Esc to close.",
        Style::default().fg(Color::Gray),
    )));
    frame.render_widget(Paragraph::new(lines), inner);
}

fn history_columns(
    history: &VecDeque<f32>,
    width: usize,
) -> (Vec<Option<f32>>, Option<f32>, usize) {
    let width = width.max(11);
    let center = width.saturating_sub(1);
    let mut cols: Vec<Option<f32>> = vec![None; width];
    let current = history.back().copied();
    cols[center] = current;

    for i in 1..width {
        let idx = history.len().checked_sub(1 + i);
        if let Some(v) = idx.and_then(|j| history.get(j)) {
            cols[center - i] = Some(*v);
        } else {
            break;
        }
    }
    (cols, current, center)
}

fn build_graph_lines(cols: &[Option<f32>], height: usize, nerd_font: bool) -> Vec<Line<'static>> {
    let cols = smooth_columns(cols);
    let heights: Vec<usize> = cols
        .iter()
        .map(|v| v.map(|db| db_to_rows(db, height)).unwrap_or(0))
        .collect();
    let mut lines: Vec<Line<'static>> = Vec::with_capacity(height);
    for y in 0..height {
        let mut spans: Vec<Span<'static>> = Vec::with_capacity(cols.len());
        for x in 0..cols.len() {
            let mut ch = ' ';
            let mut style = Style::default();
            let h = heights[x];
            if h > 0 {
                let line_y = height.saturating_sub(h);
                if y >= line_y {
                    ch = if nerd_font { '󰇝' } else { '=' };
                    style = style.fg(gradient_color_for_row(y, height));
                }
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

fn db_to_rows(db: f32, height: usize) -> usize {
    const CHART_DB_MIN: f32 = 20.0;
    const CHART_DB_MAX: f32 = 120.0;
    if height == 0 {
        return 0;
    }
    let normalized = ((db - CHART_DB_MIN) / (CHART_DB_MAX - CHART_DB_MIN)).clamp(0.0, 1.0);
    ((normalized * height as f32).round() as usize).clamp(0, height)
}

fn gradient_color_for_row(y: usize, height: usize) -> Color {
    if height <= 1 {
        return Color::Green;
    }
    let t = 1.0 - (y as f32 / (height - 1) as f32);
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

fn compute_big_scale(inner_w: u16, inner_h: u16, text: &str, nerd_font: bool) -> u16 {
    let base_h = 5u16;
    let mut base_w = 0u16;
    for ch in text.chars() {
        base_w = base_w.saturating_add(big_glyph(ch, nerd_font)[0].chars().count() as u16);
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

fn big_text_size(text: &str, scale: u16, nerd_font: bool) -> (u16, u16) {
    let mut width = 0u16;
    for ch in text.chars() {
        let glyph = big_glyph(ch, nerd_font);
        width = width.saturating_add((glyph[0].chars().count() as u16).saturating_mul(scale));
        width = width.saturating_add(scale);
    }
    (width.saturating_sub(scale), 5u16.saturating_mul(scale))
}

fn render_big_text(
    frame: &mut ratatui::Frame<'_>,
    x: u16,
    y: u16,
    text: &str,
    style: Style,
    scale: u16,
    nerd_font: bool,
) {
    if text.is_empty() {
        return;
    }
    let area = frame.area();
    let buf: &mut Buffer = frame.buffer_mut();
    let mut cursor_x = x;

    for ch in text.chars() {
        let glyph = big_glyph(ch, nerd_font);
        for (row_idx, row) in glyph.iter().enumerate() {
            for sy in 0..scale {
                let yy = y
                    .saturating_add((row_idx as u16).saturating_mul(scale))
                    .saturating_add(sy);
                if yy >= area.bottom() {
                    continue;
                }
                let mut local_x = cursor_x;
                for c in row.chars() {
                    for _ in 0..scale {
                        if local_x >= area.right() {
                            break;
                        }
                        if c != ' ' {
                            buf[(local_x, yy)].set_char(c).set_style(style);
                        }
                        local_x = local_x.saturating_add(1);
                    }
                }
            }
        }
        cursor_x = cursor_x
            .saturating_add((big_glyph(ch, nerd_font)[0].chars().count() as u16 + 1) * scale);
    }
}

fn big_glyph(ch: char, nerd_font: bool) -> [&'static str; 5] {
    if nerd_font {
        return match ch {
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
        };
    }
    match ch {
        '0' => ["#####", "#   #", "#   #", "#   #", "#####"],
        '1' => ["  ## ", " ### ", "  ## ", "  ## ", "#####"],
        '2' => ["#####", "    #", "#####", "#    ", "#####"],
        '3' => ["#####", "    #", " ####", "    #", "#####"],
        '4' => ["#   #", "#   #", "#####", "    #", "    #"],
        '5' => ["#####", "#    ", "#####", "    #", "#####"],
        '6' => ["#####", "#    ", "#####", "#   #", "#####"],
        '7' => ["#####", "    #", "   # ", "  #  ", " #   "],
        '8' => ["#####", "#   #", "#####", "#   #", "#####"],
        '9' => ["#####", "#   #", "#####", "    #", "#####"],
        '.' => ["     ", "     ", "     ", "     ", "  ## "],
        '-' => ["     ", "     ", "#####", "     ", "     "],
        'n' | 'N' => ["     ", "###  ", "#  # ", "#  ##", "#   #"],
        'a' | 'A' => ["     ", " ### ", "#   #", "#####", "#   #"],
        '/' => ["    #", "   # ", "  #  ", " #   ", "#    "],
        _ => ["     ", "  ?  ", "  ?  ", "  ?  ", "     "],
    }
}

fn open_hid_device(api: &HidApi, vid: u16, pid: u16) -> Result<HidDevice> {
    let matching: Vec<_> = api
        .device_list()
        .filter(|d| d.vendor_id() == vid && d.product_id() == pid)
        .collect();

    if matching.is_empty() {
        let mut available = Vec::new();
        for dev in api.device_list().take(10) {
            available.push(format_device_short(dev));
        }
        let details = if available.is_empty() {
            "No HID devices reported by hidapi.".to_string()
        } else {
            format!(
                "Detected HID devices (first {}):\n{}",
                available.len(),
                available.join("\n")
            )
        };
        bail!(
            "no HID device found for VID=0x{vid:04X} PID=0x{pid:04X}. Run `scan` to inspect all devices.\n{details}"
        );
    }

    let mut open_errors = Vec::new();
    for dev in matching {
        match api.open_path(dev.path()) {
            Ok(device) => return Ok(device),
            Err(e) => {
                open_errors.push(format!("{} | open error: {e}", format_device_short(dev)));
            }
        }
    }

    bail!(
        "found HID interfaces for VID=0x{vid:04X} PID=0x{pid:04X}, but failed to open any.\n{}",
        open_errors.join("\n")
    );
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

    if let Some(header) = protocol_analysis_read_history_header(bytes) {
        return Some(format!(
            "history-header date={} time={} mode={} {} weight={} range={} bat={}",
            header.date.unwrap_or_else(|| "?".to_string()),
            header.time.unwrap_or_else(|| "?".to_string()),
            header.mode,
            max_label(header.is_max),
            header.weighting,
            header.range,
            header.bat
        ));
    }

    if let Some(m) = protocol_analysis_read_point(bytes)
        && (-50.0..=150.0).contains(&m.mea_value)
    {
        return Some(format!(
            "current={:.1} dB mode={} {} weight={} range={} bat={}",
            m.mea_value,
            m.mode,
            max_label(m.is_max),
            m.weighting,
            m.range,
            m.bat
        ));
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

fn parse_hex_u16(s: &str) -> Result<u16> {
    let normalized = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(normalized, 16).with_context(|| format!("invalid hex u16: {s}"))
}

fn resolve_tx_frame(tx: Option<String>, wake: bool) -> Result<Option<Vec<u8>>> {
    if let Some(raw) = tx {
        return Ok(Some(parse_hex_bytes(&raw)?));
    }
    if wake {
        return Ok(Some(protocol_read_point()));
    }
    Ok(None)
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

fn format_device_short(dev: &DeviceInfo) -> String {
    let product = dev.product_string().unwrap_or("?");
    let manufacturer = dev.manufacturer_string().unwrap_or("?");
    format!(
        "VID=0x{:04X} PID=0x{:04X} usage_page=0x{:04X} interface={} manufacturer={} product={}",
        dev.vendor_id(),
        dev.product_id(),
        dev.usage_page(),
        dev.interface_number(),
        manufacturer,
        product
    )
}
