# ssh-soundmeter

Rust CLI for reverse-engineering a USB sound level meter protocol.

## What we know from the extracted Windows app

- Transport: USB HID (`UsbLibrary.dll` with `UsbHidPort` usage).
- Protocol API names in vendor assembly:
  - `ReadPoint`, `AnalysisReadPoint`
  - `WriteSettings`
  - `HandshakeHistory`, `ReadHistory`, `AnalysisReadHistoryHeader`
- Likely target IDs seen in resources:
  - `VID 0x64BD`
  - `PID 0x74E3`
- Current implementation is intentionally locked to only this VID/PID pair.

## Build

```bash
cargo build
```

## Usage

Run with default mode (TUI):

```bash
cargo run
```

1. Enumerate HID devices:

```bash
cargo run -- scan
```

2. Sniff traffic (sends vendor `ReadPoint` poll frame by default unless disabled):

```bash
cargo run -- sniff --vid 0x64BD --pid 0x74E3
```

3. Sniff while sending a probe frame every second:

```bash
cargo run -- sniff --vid 0x64BD --pid 0x74E3 --tx "00 01 02 03" --tx-interval-ms 1000
```

4. Write device settings from CLI and exit:

```bash
cargo run -- set --vid 0x64BD --pid 0x74E3 --set-mode FAST --set-max MAX --set-weighting C --set-range 2
```

5. Open the live TUI (centered large reading with scrolling history graph):

```bash
cargo run -- tui --vid 0x64BD --pid 0x74E3 --tx-interval-ms 120
```

Inside TUI: press `m` to open settings; use `j/k` or arrow up/down to select, `h/l` or arrow left/right to change. Changes are auto-saved to the meter.

Optional:
- Compact poll is enabled by default in `tui`. Use `--compact-poll false` to force standard poll frames only.
- `--nerd-font auto|on|off` controls glyph style. Default is `off`; set `on` to force the old Nerd Font look.

Notes:
- `sniff` uses vendor `ReadPoint` polling by default (`--wake true`).
- Writable startup settings map to vendor `WriteSettings`: `--set-mode FAST|SLOW`, `--set-max MAX|NORMAL`, `--set-weighting A|C`, `--set-range 0..4`.
- If device open fails, the app prints a short list of detected HID devices to help confirm your VID/PID.
