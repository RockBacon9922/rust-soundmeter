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

Notes:
- `sniff` uses vendor `ReadPoint` polling by default (`--wake true`).
- Writable startup settings map to vendor `WriteSettings`: `--set-mode FAST|SLOW`, `--set-max MAX|NORMAL`, `--set-weighting A|C`, `--set-range 0..4`.
- If device open fails, the app prints a short list of detected HID devices to help confirm your VID/PID.
