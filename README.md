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

Demo UI without hardware:

```bash
cargo run -- tui --demo true
```

5. Run the built-in SSH server with mDNS (`soundmeter.local`):

```bash
cargo run -- serve-ssh --host 0.0.0.0 --port 22 --mdns --mdns-name soundmeter --vid 0x64BD --pid 0x74E3
```

Demo SSH-hosted UI without hardware:

```bash
cargo run -- serve-ssh --demo true
```

Then connect from another machine on the same LAN:

```bash
ssh soundmeter.local
```

Notes:
- `open_access` is enabled by default, so any username/password is accepted.
- If you keep a non-standard port, include `-p` in your SSH command.
- If mDNS does not resolve on your network, use direct IP.

Press `q` in the SSH session to close that client session.

## Next reverse-engineering step

Capture actual RX/TX with `sniff`, then codify exact frame encode/decode logic in `decode_frame` and add explicit settings/history commands.
