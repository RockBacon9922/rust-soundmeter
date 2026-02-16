# ssh-soundmeter

Rust CLI + `ratatui` starter for reverse-engineering a USB sound level meter protocol.

## What we know from the extracted Windows app

- Transport: USB HID (`UsbLibrary.dll` with `UsbHidPort` usage).
- Protocol API names in vendor assembly:
  - `ReadPoint`, `AnalysisReadPoint`
  - `WriteSettings`
  - `HandshakeHistory`, `ReadHistory`, `AnalysisReadHistoryHeader`
- Likely target IDs seen in resources:
  - `VID 0x64BD`
  - `PID 0x74E3`

## Build

```bash
cargo build
```

## Usage

1. Enumerate HID devices:

```bash
cargo run -- scan
```

2. Sniff traffic (passive):

```bash
cargo run -- sniff --vid 0x64BD --pid 0x74E3
```

3. Sniff while sending a probe frame every second:

```bash
cargo run -- sniff --vid 0x64BD --pid 0x74E3 --tx "00 01 02 03" --tx-interval-ms 1000
```

4. Run the terminal UI:

```bash
cargo run -- tui --vid 0x64BD --pid 0x74E3
```

5. Run the same UI over SSH:

```bash
ssh user@host "cd /path/to/rust-soundmeter && cargo run --release -- tui --vid 0x64BD --pid 0x74E3"
```

`ratatui` renders in any normal PTY, so a built-in SSH server is not required unless you want multi-user/auth logic inside the app itself.

## Next reverse-engineering step

Capture actual RX/TX with `sniff`, then codify exact frame encode/decode logic in `decode_frame` and add explicit settings/history commands.
