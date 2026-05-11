#!/usr/bin/env python3
"""
network_sniffer.py — Cross-platform network packet sniffer (Windows + Linux)

HOW TO RUN
----------
Windows (must be Administrator):
    1. Right-click Command Prompt -> "Run as administrator"
    2. python network_sniffer.py
    3. Press Ctrl+C to stop

Linux (must be root):
    sudo python3 network_sniffer.py

OPTIONS
-------
  -i, --interface     Interface name (Linux: eth0) or IP (Windows: auto-detected)
  -c, --count         Stop after N packets  [default: 0 = unlimited]
  -f, --filter        tcp | udp | icmp | all  [default: all]
  -o, --output        Save results to a JSON file
  -v, --verbose       Show hex dump of each packet payload
  --no-color          Plain text output (no ANSI colors)
  --list-interfaces   Show available interfaces/IPs and exit

EXAMPLES
--------
  python network_sniffer.py
  python network_sniffer.py -f tcp -c 100
  python network_sniffer.py -v -o capture.json
  python network_sniffer.py --list-interfaces
  # Basic capture


python network_sniffer.py

# Filter by protocol
python network_sniffer.py -f tcp
python network_sniffer.py -f udp
python network_sniffer.py -f icmp

# Capture exactly N packets then stop
python network_sniffer.py -c 100

# Save results to file
python network_sniffer.py -o capture.json

# Show full packet payload (hex + ASCII)
python network_sniffer.py -v

# Combine options
python network_sniffer.py -f tcp -c 50 -v -o tcp_packets.json
"""

import socket
import struct
import json
import argparse
import sys
import os
import time
import signal
import threading
import textwrap
from datetime import datetime


# ─────────────────────────────────────────────────────────────
# ANSI colors  (auto-enabled on Windows 10+ via os.system(""))
# ─────────────────────────────────────────────────────────────

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"

USE_COLOR = True

def c(text, color):
    return f"{color}{text}{Colors.RESET}" if USE_COLOR else text


# ─────────────────────────────────────────────────────────────
# Protocol tables
# ─────────────────────────────────────────────────────────────

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 41: "IPv6", 89: "OSPF"}

WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}


# ─────────────────────────────────────────────────────────────
# Interface detection  (cross-platform)
# ─────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """
    Most reliable way to find the machine's outbound IP on any OS.
    Creates a UDP socket (no data sent) and reads the local address.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))          # no data sent, just routing
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def list_interfaces() -> list:
    """Return interface names (Linux) or local IPs (Windows)."""
    if sys.platform == "win32":
        ips = []
        # Method 1: gethostbyname_ex
        try:
            _, _, addr_list = socket.gethostbyname_ex(socket.gethostname())
            ips = [ip for ip in addr_list if not ip.startswith("127.")]
        except Exception:
            pass
        # Method 2: UDP connect trick (fallback / always add as option)
        local = get_local_ip()
        if local and local not in ips and not local.startswith("127."):
            ips.append(local)
        return ips if ips else ["127.0.0.1"]
    else:
        try:
            return [n for n in os.listdir("/sys/class/net/") if n != "lo"]
        except Exception:
            return []


def detect_interface() -> str:
    """Auto-pick the best interface for the current OS."""
    if sys.platform == "win32":
        return get_local_ip()          # Windows needs an IP address
    else:
        priority  = ["eth0", "wlan0", "ens3", "ens33", "enp0s3", "enp3s0", "en0"]
        available = list_interfaces()
        for name in priority:
            if name in available:
                return name
        for name in available:
            if not name.startswith(("docker", "veth", "br-", "virbr")):
                return name
        return "any"


# ─────────────────────────────────────────────────────────────
# Raw socket factory
# ─────────────────────────────────────────────────────────────

def open_raw_socket(interface: str):
    """
    Open the right raw socket for this OS.
    Returns (sock, has_ethernet_header).

    Windows  → AF_INET  + IPPROTO_IP  → IP header only (no Ethernet)
    Linux    → AF_PACKET + SOCK_RAW   → full Ethernet frame
    """
    if sys.platform == "win32":
        # ── Windows ──────────────────────────────────────────
        # interface must be a local IPv4 address (not a name)
        local_ip = interface if _is_ip(interface) else get_local_ip()

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

        # FIX: settimeout so recvfrom() wakes up periodically
        #      → allows Ctrl+C and stop_event to work on Windows
        sock.settimeout(1.0)

        sock.bind((local_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Tell Windows to pass ALL inbound IP packets to this socket
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        return sock, False      # no Ethernet header on Windows

    else:
        # ── Linux ─────────────────────────────────────────────
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(0x0003))   # ETH_P_ALL
        sock.settimeout(1.0)   # same fix — allows clean Ctrl+C

        if interface and interface.lower() != "any":
            try:
                sock.bind((interface, 0))
            except OSError as e:
                sock.close()
                print(c(f"\n  [ERROR] Cannot bind to '{interface}': {e}", Colors.RED))
                avail = list_interfaces()
                if avail:
                    print(c(f"  Available: {', '.join(avail)}", Colors.YELLOW))
                sys.exit(1)

        return sock, True       # Ethernet header present on Linux


def _is_ip(s: str) -> bool:
    """Return True if s looks like an IPv4 address."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────
# Packet parsers
# ─────────────────────────────────────────────────────────────

def parse_ethernet(raw: bytes):
    if len(raw) < 14:
        return None, raw
    dst, src, eth_type = struct.unpack("!6s6sH", raw[:14])
    return {"dst_mac": _fmt_mac(dst), "src_mac": _fmt_mac(src),
            "eth_type": eth_type}, raw[14:]


def parse_ipv4(raw: bytes):
    if len(raw) < 20:
        return None, raw
    ver_ihl = raw[0]
    ihl = (ver_ihl & 0xF) * 4
    if ihl < 20 or ihl > len(raw):
        return None, raw
    ttl, proto, chk = struct.unpack("!BBH", raw[8:12])
    return {
        "version":    ver_ihl >> 4,
        "ihl":        ihl,
        "ttl":        ttl,
        "protocol":   proto,
        "proto_name": PROTO_MAP.get(proto, f"PROTO_{proto}"),
        "checksum":   f"0x{chk:04X}",
        "src_ip":     socket.inet_ntoa(raw[12:16]),
        "dst_ip":     socket.inet_ntoa(raw[16:20]),
    }, raw[ihl:]


def parse_tcp(raw: bytes):
    if len(raw) < 20:
        return None, raw
    sp, dp, seq, ack = struct.unpack("!HHII", raw[:12])
    off_flags = struct.unpack("!H", raw[12:14])[0]
    offset = max(20, min((off_flags >> 12) * 4, len(raw)))
    fl = off_flags & 0x1FF
    flags = (["FIN"] if fl & 0x001 else []) + \
            (["SYN"] if fl & 0x002 else []) + \
            (["RST"] if fl & 0x004 else []) + \
            (["PSH"] if fl & 0x008 else []) + \
            (["ACK"] if fl & 0x010 else []) + \
            (["URG"] if fl & 0x020 else [])
    return {"src_port": sp, "dst_port": dp, "seq": seq, "ack_num": ack,
            "flags": flags, "window": struct.unpack("!H", raw[14:16])[0],
            "service_hint": _svc(sp, dp)}, raw[offset:]


def parse_udp(raw: bytes):
    if len(raw) < 8:
        return None, raw
    sp, dp, length, chk = struct.unpack("!HHHH", raw[:8])
    return {"src_port": sp, "dst_port": dp, "length": length,
            "checksum": f"0x{chk:04X}", "service_hint": _svc(sp, dp)}, raw[8:]


def parse_icmp(raw: bytes):
    if len(raw) < 8:
        return None, raw
    t, code, chk = struct.unpack("!BBH", raw[:4])
    names = {0: "Echo Reply", 3: "Dest Unreachable", 5: "Redirect",
             8: "Echo Request", 11: "Time Exceeded"}
    return {"type": t, "type_name": names.get(t, f"Type_{t}"),
            "code": code, "checksum": f"0x{chk:04X}"}, raw[8:]


def _fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)

def _svc(sp: int, dp: int) -> str:
    return WELL_KNOWN_PORTS.get(dp) or WELL_KNOWN_PORTS.get(sp) or ""


# ─────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────

def hex_dump(data: bytes, bpl: int = 16) -> str:
    lines = []
    for i in range(0, len(data), bpl):
        chunk = data[i:i+bpl]
        h = " ".join(f"{b:02X}" for b in chunk)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04X}  {h:<{bpl*3}}  {a}")
    return "\n".join(lines)


def safe_decode(payload, max_chars: int = 200) -> str:
    if not isinstance(payload, (bytes, bytearray)) or not payload:
        return ""
    try:
        text = payload.decode("utf-8", errors="replace")
        text = "".join(ch if ch.isprintable() else "." for ch in text)
        return text[:max_chars] + ("..." if len(text) > max_chars else "")
    except Exception:
        return ""


def display_packet(pkt: dict, verbose: bool = False, counter: int = 0):
    ip    = pkt.get("ip", {})
    proto = ip.get("proto_name", "?")
    ts    = pkt.get("timestamp", "")

    pc = {"TCP": Colors.GREEN, "UDP": Colors.CYAN,
          "ICMP": Colors.YELLOW}.get(proto, Colors.WHITE)

    tr  = pkt.get("transport", {})
    sp  = tr.get("src_port", "")
    dp  = tr.get("dst_port", "")
    svc = tr.get("service_hint", "")
    fls = tr.get("flags", [])

    src_p = f":{sp}" if sp else ""
    dst_p = f":{dp}" if dp else ""
    flag_s = f" [{','.join(fls)}]"       if fls  else ""
    svc_s  = f" ({svc})"                 if svc  else ""
    icmp_s = f" {tr.get('type_name','')}" if proto == "ICMP" else ""
    size   = pkt.get("payload_size", 0)

    print(
        f"{c(f'#{counter:>4}', Colors.GREY)} "
        f"{c(ts, Colors.GREY)} "
        f"{c(f'{proto:<6}', pc)}"
        f"{c(ip.get('src_ip','?'), Colors.WHITE)}{c(src_p, Colors.GREY)} "
        f"-> "
        f"{c(ip.get('dst_ip','?'), Colors.WHITE)}{c(dst_p, Colors.GREY)}"
        f"{c(flag_s, Colors.MAGENTA)}"
        f"{c(svc_s, Colors.YELLOW)}"
        f"{c(icmp_s, Colors.YELLOW)}"
        f"  {c(f'{size}B', Colors.GREY)}"
    )

    if verbose and size > 0:
        raw = pkt.get("payload_raw", b"")
        print(c("  +-- Hex Dump " + "-"*50, Colors.GREY))
        print(c(hex_dump(raw[:256]), Colors.GREY))
        decoded = safe_decode(raw)
        if decoded.strip():
            print(c("  +-- ASCII " + "-"*53, Colors.GREY))
            for line in textwrap.wrap(decoded, 70):
                print(c(f"  |  {line}", Colors.GREY))
        print()


def print_banner(iface: str, proto_filter: str, count: int):
    print()
    print(c("  +======================================================+", Colors.CYAN))
    print(c("  |        PYTHON NETWORK SNIFFER  v2.2                  |", Colors.CYAN))
    print(c("  +======================================================+", Colors.CYAN))
    label = "Local IP   " if sys.platform == "win32" else "Interface  "
    print(f"  {label} : {c(iface, Colors.YELLOW)}")
    print(f"  Filter     : {c(proto_filter.upper(), Colors.YELLOW)}")
    print(f"  Count      : {c(str(count) if count else 'unlimited', Colors.YELLOW)}")
    print(f"  Platform   : {c(sys.platform, Colors.YELLOW)}")
    print(f"  Started    : {c(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), Colors.YELLOW)}")
    print()
    print(c("  Press Ctrl+C to stop.", Colors.GREY))
    print()
    print(c(
        f"  {'#':>4}  {'TIME':8}  {'PROTO':<6}  {'SRC IP:PORT':<22}  "
        f"{'DST IP:PORT':<22}  {'FLAGS/SERVICE':<22}  SIZE",
        Colors.BOLD
    ))
    print(c("  " + "-" * 95, Colors.GREY))


def print_summary(stats: dict, elapsed: float):
    print()
    print(c("  +======================================================+", Colors.CYAN))
    print(c("  |                 CAPTURE SUMMARY                      |", Colors.CYAN))
    print(c("  +======================================================+", Colors.CYAN))
    total = stats.get("total", 0)
    print(f"  Total packets : {c(str(total), Colors.GREEN)}")
    print(f"  Duration      : {c(f'{elapsed:.1f}s', Colors.GREEN)}")
    if elapsed > 0:
        print(f"  Rate          : {c(f'{total/elapsed:.1f} pkt/s', Colors.GREEN)}")
    print()
    for proto, cnt in sorted(stats.get("by_proto", {}).items(), key=lambda x: -x[1]):
        bar = "#" * min(cnt, 40)
        print(f"  {proto:<14} {c(bar, Colors.CYAN)} {cnt}")
    print()


# ─────────────────────────────────────────────────────────────
# Core capture loop  (runs in its own thread on Windows)
# ─────────────────────────────────────────────────────────────

# Global stop flag — set by Ctrl+C handler OR count limit
_stop = threading.Event()


def _capture_loop(raw_sock, has_ethernet: bool, proto_filter: str,
                  count: int, verbose: bool, output_file: str,
                  stats: dict, captured: list):
    counter = 0

    while not _stop.is_set():
        # ── Receive one packet ──────────────────────────────
        try:
            raw_data, _addr = raw_sock.recvfrom(65535)
        except socket.timeout:
            # Woke up after 1 s — just check _stop and loop again
            continue
        except OSError:
            break

        # ── Ethernet header (Linux only) ────────────────────
        ip_raw = raw_data
        if has_ethernet:
            eth, ip_raw = parse_ethernet(raw_data)
            if eth is None or eth["eth_type"] != 0x0800:
                continue        # skip non-IPv4 frames

        # ── IPv4 ────────────────────────────────────────────
        ip, transport_raw = parse_ipv4(ip_raw)
        if ip is None:
            continue

        proto = ip["proto_name"]

        # ── Protocol filter ─────────────────────────────────
        if proto_filter != "all" and proto.lower() != proto_filter.lower():
            continue

        # ── Transport layer ─────────────────────────────────
        transport = {}
        payload   = transport_raw

        if ip["protocol"] == 6:
            r, payload = parse_tcp(transport_raw);  transport = r or {}
        elif ip["protocol"] == 17:
            r, payload = parse_udp(transport_raw);  transport = r or {}
        elif ip["protocol"] == 1:
            r, payload = parse_icmp(transport_raw); transport = r or {}

        pkt = {
            "timestamp":    datetime.now().strftime("%H:%M:%S"),
            "ip":           ip,
            "transport":    transport,
            "payload_size": len(payload),
            "payload_raw":  payload,
        }

        counter += 1
        stats["total"] = counter
        stats["by_proto"][proto] = stats["by_proto"].get(proto, 0) + 1

        display_packet(pkt, verbose=verbose, counter=counter)

        if output_file:
            j = {k: v for k, v in pkt.items() if k != "payload_raw"}
            j["payload_preview"] = safe_decode(payload, 200)
            captured.append(j)

        if count and counter >= count:
            _stop.set()
            break


# ─────────────────────────────────────────────────────────────
# Main sniff entry point
# ─────────────────────────────────────────────────────────────

def sniff(interface: str, count: int, proto_filter: str,
          output_file: str, verbose: bool):

    global _stop
    _stop.clear()

    captured = []
    stats    = {"total": 0, "by_proto": {}}
    start_ts = time.time()

    # ── Open socket ─────────────────────────────────────────
    try:
        raw_sock, has_ethernet = open_raw_socket(interface)
    except PermissionError:
        if sys.platform == "win32":
            print(c("\n  [ERROR] Permission denied.", Colors.RED))
            print(c("  Right-click Command Prompt -> 'Run as administrator'\n",
                    Colors.YELLOW))
        else:
            print(c("\n  [ERROR] Permission denied.", Colors.RED))
            print(c("  Run with:  sudo python3 network_sniffer.py\n", Colors.YELLOW))
        sys.exit(1)
    except OSError as e:
        print(c(f"\n  [ERROR] Socket error: {e}\n", Colors.RED))
        sys.exit(1)

    print_banner(interface, proto_filter, count)

    # ── Ctrl+C handler ──────────────────────────────────────
    # Install BEFORE starting the capture thread so it works on
    # both Windows and Linux regardless of which thread blocks.
    def _sigint_handler(sig, frame):
        print(c("\n\n  [!] Stopping capture...", Colors.YELLOW))
        _stop.set()

    signal.signal(signal.SIGINT, _sigint_handler)

    # ── Run capture in background thread ────────────────────
    # On Windows, running inside a thread means the main thread
    # stays free to receive signals (including Ctrl+C / SIGINT).
    t = threading.Thread(
        target=_capture_loop,
        args=(raw_sock, has_ethernet, proto_filter,
              count, verbose, output_file, stats, captured),
        daemon=True,
    )
    t.start()

    # ── Wait — main thread stays alive for signal handling ──
    try:
        while t.is_alive():
            t.join(timeout=0.2)   # wake every 200 ms to check signals
    except KeyboardInterrupt:
        _stop.set()

    t.join()    # wait for capture thread to finish current packet

    # ── Cleanup ─────────────────────────────────────────────
    if sys.platform == "win32":
        try:
            raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
    raw_sock.close()

    elapsed = time.time() - start_ts
    print_summary(stats, elapsed)

    if output_file and captured:
        with open(output_file, "w") as f:
            json.dump(captured, f, indent=2, default=str)
        print(c(f"  Saved {len(captured)} packets -> {output_file}\n", Colors.GREEN))


# ─────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────

def main():
    global USE_COLOR

    # Enable ANSI escape codes on Windows 10+ cmd / PowerShell
    if sys.platform == "win32":
        os.system("")

    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer — no pip installs, works on Windows & Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Interface (Linux: eth0) or local IP (Windows: auto)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Stop after N packets  [0 = unlimited]")
    parser.add_argument("-f", "--filter", default="all",
                        choices=["all", "tcp", "udp", "icmp"],
                        help="Protocol filter  [default: all]")
    parser.add_argument("-o", "--output", default=None,
                        help="Save packets to JSON file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show hex + ASCII payload dump")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="Print available interfaces/IPs and exit")
    args = parser.parse_args()

    if args.no_color:
        USE_COLOR = False

    if args.list_interfaces:
        ifaces = list_interfaces()
        label  = "Local IP addresses" if sys.platform == "win32" else "Interfaces"
        print(f"{label} (pass to -i):")
        for iface in ifaces:
            print(f"  {iface}")
        if not ifaces:
            print("  (none found)")
        sys.exit(0)

    interface = args.interface or detect_interface()
    sniff(
        interface=interface,
        count=args.count,
        proto_filter=args.filter,
        output_file=args.output,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
