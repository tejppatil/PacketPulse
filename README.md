# PacketPulse 🛡️

**Terminal-based modular cybersecurity monitoring platform**

Real-time packet capture, URL threat detection, DNS monitoring, and deep device forensics — all from your terminal.

```
pip install packetpulse
sudo packetpulse start
```

---

## Commands

### `packetpulse sniff` — Deep Packet Capture

Captures every packet with full detail across all layers:

```
sudo packetpulse sniff
sudo packetpulse sniff -i eth0
sudo packetpulse sniff -f "tcp port 80"
```

**What you see for every packet:**
- `L2` — Source & destination MAC address
- `L3` — IP version, TTL, fragmentation
- `L4` — TCP flags (SYN/ACK/FIN/RST/PSH), sequence numbers, window size
- `L7 HTTP` — Full method, URL, all request headers, User-Agent, Referer, POST body
- `L7 HTTP` — Response status code, Content-Type, Server header, Set-Cookie
- `L7 DNS` — Query name, record type (A/AAAA/MX/TXT), response IPs
- `GeoIP` — Country, city, coordinates, ISP for every remote IP
- `rDNS` — Reverse DNS hostname of destination
- `Process` — Which app on your machine sent this packet (e.g. `chrome(4821)`)

---

### `packetpulse urlscan` — URL Threat Scanner

**Single URL (full analysis):**
```
packetpulse urlscan https://suspicious-site.com
packetpulse urlscan http://free-prize-winner.top/claim
```

**Live traffic watch (auto-scans every URL your machine visits):**
```
sudo packetpulse urlscan --live
sudo packetpulse urlscan --live -i wlan0
```

**4 checks run on every URL:**

| Check | What it detects |
|---|---|
| **URL Structure** | Suspicious TLDs, IP-as-host, deep subdomains, high-entropy domains (DGA), encoded characters, punycode homograph attacks, suspicious keywords |
| **SSL/TLS** | Certificate validity, expiry, weak TLS version, CN mismatch |
| **Reputation** | VirusTotal (90 engines), Google Safe Browsing, PhishTank |
| **Page Content** | Obfuscated JS (eval/atob), hidden iframes, forms posting to external domains, phishing login patterns, base64 payload blobs, suspicious external scripts |

Results saved to `pcap_store/urls/`.

**Set API keys for full reputation checks:**
```bash
export PACKETPULSE_VT_KEY="your_virustotal_key"
export PACKETPULSE_GSB_KEY="your_google_safebrowsing_key"
```

---

### `packetpulse dns` — DNS Query Monitor

```
sudo packetpulse dns
sudo packetpulse dns -i eth0
```

Watches every DNS query your machine makes and flags:
- **DGA domains** — high Shannon entropy (malware C2 beacons)
- **High-risk TLDs** — `.tk .ml .xyz .top .win .loan` etc.
- **Suspicious keywords** — malware, botnet, c2, exploit, shell, ransom
- **Beaconing** — same domain queried 30+ times (C2 keepalive)
- **Punycode** — homograph/lookalike domain attacks
- **Very long domains** — DNS tunneling indicator

---

### `packetpulse forensics` — Deep Device Forensics

```
sudo packetpulse forensics
sudo packetpulse forensics --no-nmap        # faster, passive only
sudo packetpulse forensics --usb-watch      # live USB event monitor
sudo packetpulse forensics -s 10.0.0.0/24  # specific subnet
```

**USB devices** (via pyudev — exact kernel data):
- Exact product name, manufacturer (from kernel, not guessed)
- Serial number
- VID / PID (USB vendor/product IDs)
- USB speed class (1.1 / 2.0 / 3.0 / 3.1 / 3.2)
- Power draw in mA
- Device class (Storage / HID / Audio / Network / MFi)
- Loaded driver
- OS/platform identification (iOS / Android / macOS)
- Session history (how many times this serial has been seen)
- **Storage details**: volume label, filesystem, capacity, used/free, mount point, UUID

**LAN devices** (ARP scan + passive fingerprinting + optional nmap):
- MAC address → manufacturer (OUI lookup)
- Device type classification
- Hostname (reverse DNS + mDNS + NetBIOS)
- OS fingerprint from TCP/IP signals (TTL, window size, TCP options)
- nmap active scan: open ports, service versions, OS detection
- Active connections to this device
- Risk assessment (dangerous ports flagged)

---

### `packetpulse start` — Full Pipeline

```
sudo packetpulse start
sudo packetpulse start -i wlan0
```

Runs sniff + urlscan + dns simultaneously in parallel threads.

---

## Installation

```bash
# Install
pip install packetpulse

# Or from source
git clone https://github.com/packetpulse/packetpulse
cd packetpulse
pip install -e .

# GeoIP database (optional but recommended)
# Download GeoLite2-City.mmdb from MaxMind
export PACKETPULSE_GEOIP_DB="/path/to/GeoLite2-City.mmdb"
```

**Requirements:**
- Python 3.11+
- Root/sudo for packet capture and ARP scanning
- Linux recommended (pyudev for USB monitoring is Linux-only)

---

## Project Structure

```
packetpulse/
├── packetpulse/
│   ├── cli.py                   ← CLI entry point (typer)
│   ├── sensor/
│   │   └── sensor.py            ← Deep packet sniffer (Scapy)
│   ├── urlscan/
│   │   └── url_scanner.py       ← URL threat scanner + live watcher
│   ├── dns/
│   │   └── dns_monitor.py       ← DNS query monitor
│   ├── forensics/
│   │   └── forensics.py         ← USB + LAN device forensics
│   ├── core/
│   │   ├── config.py            ← Configuration
│   │   └── logger.py            ← Rich logging
│   └── utils/
│       └── helpers.py           ← GeoIP, entropy, file utils
├── scripts/
│   └── simulate_malicious_urls.sh
├── pcap_store/                  ← All output files
│   ├── *.pcap                   ← Raw packet captures
│   ├── urls/                    ← URL scan results (JSON)
│   ├── dns/                     ← DNS flag results (JSON)
│   └── forensics/               ← Device profiles (JSON)
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## License

MIT License — see LICENSE file.
