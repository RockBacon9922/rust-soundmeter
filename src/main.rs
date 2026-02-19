use std::io::{self, Write};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::Local;
use clap::{ArgAction, Parser, Subcommand};
use hidapi::{DeviceInfo, HidApi, HidDevice};

const DEFAULT_VID: u16 = 0x64BD;
const DEFAULT_PID: u16 = 0x74E3;
const REPORT_ID: u8 = 0x00;
const FRAME_FILL: u8 = 0x23;
const FRAME_LEN: usize = 65;
const HID_READ_TIMEOUT_MS: i32 = 200;
const MAX_FRAME_BYTES: usize = FRAME_LEN;

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
}

#[derive(Clone, Debug, Default)]
struct ProtocolMember {
    mea_value: f32,
    bat: u8,
    mode: &'static str,
    max: &'static str,
    weighting: &'static str,
    range: u8,
    time: Option<String>,
    date: Option<String>,
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

#[allow(dead_code)]
fn protocol_write_settings(set: &ProtocolMember) -> Vec<u8> {
    let mut out = protocol_command(0x56);
    let mut flags = 0u8;
    if set.mode == "FAST" {
        flags |= 0x40;
    }
    if set.max == "MAX" {
        flags |= 0x20;
    }
    if set.weighting == "C" {
        flags |= 0x10;
    }
    flags |= set.range & 0x0F;
    out[2] = flags;
    out
}

#[allow(dead_code)]
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
        None => "",
        Some(v) if v.eq_ignore_ascii_case("MAX") => "MAX",
        Some(v) if v.eq_ignore_ascii_case("NORMAL") => "",
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
        max,
        weighting,
        range,
        time: None,
        date: None,
    }))
}

fn max_label(max: &str) -> &'static str {
    if max == "MAX" { "MAX" } else { "NORMAL" }
}

fn device_settings_summary(settings: &ProtocolMember) -> String {
    format!(
        "mode={} max={} weight={} range={}",
        settings.mode,
        max_label(settings.max),
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
        let mode = if flags & 0x40 == 0 { "SLOW" } else { "FAST" };
        let max = if flags & 0x20 == 0 { "" } else { "MAX" };
        let weighting = if flags & 0x10 == 0 { "A" } else { "C" };
        Some(ProtocolMember {
            mea_value,
            bat: (flags & 0x80) >> 7,
            mode,
            max,
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
    let mode = if flags & 0x40 == 0 { "SLOW" } else { "FAST" };
    let max = if flags & 0x20 == 0 { "" } else { "MAX" };
    let weighting = if flags & 0x10 == 0 { "A" } else { "C" };
    Some(ProtocolMember {
        mea_value: 0.0,
        bat: (flags & 0x80) >> 7,
        mode,
        max,
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
            header.max,
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
            m.mea_value, m.mode, m.max, m.weighting, m.range, m.bat
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
