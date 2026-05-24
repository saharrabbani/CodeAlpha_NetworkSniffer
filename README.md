# 🔍 CodeAlpha – Task 1: Basic Network Sniffer

> **CodeAlpha Cybersecurity Internship** | Task 1 of 4

---

## 📌 Overview

A Python-based network packet sniffer built with **Scapy** that captures and
analyzes live network traffic in real time. The tool decodes multiple protocols,
displays human-readable packet summaries, and generates a full log file with
a statistical summary at the end.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔵 **TCP Analysis** | Flags, ports, service name detection |
| 🟡 **UDP Analysis** | Port info and payload length |
| 🔎 **DNS Decoding** | Extracts query names and response IPs |
| 🌐 **HTTP Inspection** | Method, host, and path extraction |
| 🔴 **ICMP Detection** | Echo request/reply and unreachable messages |
| 📡 **ARP Monitoring** | Request and reply with MAC addresses |
| 📦 **Payload Preview** | First 64 bytes shown as readable text |
| 📊 **Live Statistics** | Per-protocol counts and top connections |
| 📁 **Log File** | Full capture saved to `capture_log.txt` |

---

## 🛠️ Prerequisites

- Python 3.8+
- Root / Administrator privileges (required for raw socket access)
- Linux / macOS / Windows (with Npcap)

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/YourUsername/CodeAlpha_NetworkSniffer
cd CodeAlpha_NetworkSniffer

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
# Basic capture (unlimited packets, default interface)
sudo python3 sniffer.py

# Capture exactly 100 packets
sudo python3 sniffer.py --count=100

# Capture on a specific interface
sudo python3 sniffer.py --iface=eth0

# Apply a BPF filter (only TCP traffic)
sudo python3 sniffer.py --filter="tcp"

# Combine options
sudo python3 sniffer.py --iface=wlan0 --count=50 --filter="udp port 53"

# Help
python3 sniffer.py --help
```

---

## 📋 Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║         🔍  CodeAlpha - Basic Network Sniffer  🔍            ║
║              Internship Task 1 | Cybersecurity               ║
╚══════════════════════════════════════════════════════════════╝

[*] Starting capture on interface: default
──────────────────────────────────────────────────────────────
    Press  Ctrl+C  to stop and view summary
──────────────────────────────────────────────────────────────

[14:22:01.045] 🔎 DNS   QUERY  | 192.168.1.5 → 8.8.8.8  [google.com]
[14:22:01.102] 🔎 DNS   REPLY  | 192.168.1.5 ← 8.8.8.8  [142.250.74.14]
[14:22:01.110] 🔵 TCP   S      | 192.168.1.5:54301 → 142.250.74.14:443  [HTTPS]
[14:22:01.200] 🔵 TCP   SA     | 142.250.74.14:443 → 192.168.1.5:54301  [HTTPS]
[14:22:05.321] 📡 ARP REQUEST  | 192.168.1.1 (aa:bb:cc:dd:ee:ff) → 192.168.1.5
[14:22:08.001] 🔴 ICMP  ECHO-REQUEST  | 192.168.1.5 → 8.8.8.8

──────────────────────────────────────────────────────────────
📊  CAPTURE SUMMARY
──────────────────────────────────────────────────────────────
  Total packets  : 6
  TCP            : 2
  UDP            : 2
  ICMP           : 1
  ARP            : 1
  Other          : 0

  🔎 Top DNS queries:
      • google.com

  🔗 Top TCP connections:
      [   2x] 192.168.1.5:54301 → 142.250.74.14:443

  📁 Full log saved → capture_log.txt
──────────────────────────────────────────────────────────────
```

---

## 📂 Project Structure

```
CodeAlpha_NetworkSniffer/
├── sniffer.py          # Main sniffer script
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## 🔒 Ethical Notice

This tool is intended for **educational purposes only** and for use on networks
you own or have explicit permission to monitor. Unauthorized packet capture is
illegal in most jurisdictions.

---

## 📞 Contact

CodeAlpha — [www.codealpha.tech](https://www.codealpha.tech)