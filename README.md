# CodeAlpha_Basic-Network-Sniffer
# Network Sniffer

`network_sniffer.py` is a cross-platform packet sniffer written in Python for Windows and Linux. It captures live network traffic using raw sockets, prints decoded packet details in the terminal, and can optionally save captures to a JSON file.

## Features

- Cross-platform support for Windows and Linux
- Auto-detects the best local interface/IP when none is provided
- Filters traffic by protocol: TCP, UDP, ICMP, or all packets
- Shows packet metadata such as source/destination IP and ports, flags, TTL, and protocol hints
- Optional verbose mode with hex and ASCII payload output
- Optional JSON export of captured packets
- Clean terminal output with ANSI colors, plus a plain-text mode
- Lists available interfaces or local IPs

## Requirements

- Python 3.8 or newer
- Administrator privileges on Windows
- Root privileges on Linux

## Usage

Run the sniffer from the same folder as the script:

```bash
python network_sniffer.py
```

### Windows

Open Command Prompt or PowerShell as Administrator, then run:

```bash
python network_sniffer.py
```

### Linux

Run with sudo:

```bash
sudo python3 network_sniffer.py
```

## Options

- `-i, --interface` - Interface name on Linux, or local IP address on Windows
- `-c, --count` - Stop after N packets
- `-f, --filter` - Filter by `tcp`, `udp`, `icmp`, or `all`
- `-o, --output` - Save captured packets to a JSON file
- `-v, --verbose` - Show hex and ASCII payload dump
- `--no-color` - Disable ANSI colors
- `--list-interfaces` - Print available interfaces or IPs and exit

## Examples

Capture all packets:

```bash
python network_sniffer.py
```

Capture only TCP traffic:

```bash
python network_sniffer.py -f tcp
```

Capture 100 packets and stop:

```bash
python network_sniffer.py -c 100
```

Save traffic to JSON:

```bash
python network_sniffer.py -o capture.json
```

Show payload details:

```bash
python network_sniffer.py -v
```

Combine options:

```bash
python network_sniffer.py -f tcp -c 50 -v -o tcp_packets.json
```

List available interfaces or local IPs:

```bash
python network_sniffer.py --list-interfaces
```

## Output

The script prints each packet with:

- timestamp
- protocol name
- source and destination IP addresses
- source and destination ports when available
- TCP flags or ICMP type names
- packet payload size

When verbose mode is enabled, the payload is shown as a hex dump and decoded ASCII preview.

## Notes

- On Windows, the script uses the local IP address and enables receive-all mode on the raw socket.
- On Linux, the script uses an AF_PACKET raw socket and can bind to a specific interface.
- The capture stops with Ctrl+C or automatically after the packet count limit is reached.
