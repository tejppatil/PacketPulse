# PacketPulse 🛡️

**Terminal-based interactive cybersecurity monitoring platform**

Repository: https://github.com/tejppatil/PacketPulse

```
pip install packetpulse
sudo packetpulse
```

That's it. An interactive menu guides you through everything.

---

## How it works

Run `sudo packetpulse` and you get a numbered main menu:

```
  1  Packet Sniffer      Deep capture — HTTP headers, DNS, GeoIP, process attribution
  2  URL Scanner         Scan a URL or watch live traffic for malicious sites
  3  DNS Monitor         Watch every DNS query — flag DGA domains, beaconing, bad TLDs
  4  Device Forensics    Profile USB devices and LAN devices in depth
  5  Full Pipeline       Run Sniffer + URL Scanner + DNS Monitor simultaneously
  0  Exit
```

Each module asks you everything it needs before running — interface,
duration, options — then runs, then returns you to the menu.

---

## Each module

### 1 — Packet Sniffer
Prompts: interface · BPF filter · duration · HTTP/DNS/GeoIP on/off · save PCAP?

Shows every packet with full detail:
- L2: source + destination MAC
- L3: IP version, TTL
- L4: TCP flags, sequence numbers, window size
- L7 HTTP: full request headers, User-Agent, Referer, POST body; response status, Server, Set-Cookie
- L7 DNS: query name, type (A/AAAA/MX/TXT), response IPs
- GeoIP: country, city, ISP for every remote IP
- rDNS: reverse hostname of destination
- Process: which app on your machine sent this packet

### 2 — URL Scanner
Prompts: single URL or live mode · interface (live) · duration (live) · page scan on/off

**Single URL** — 4 checks:
- URL structure (TLD, IP-as-host, entropy, encoding, keywords, punycode)
- SSL/TLS certificate (validity, expiry, weak version, CN mismatch)
- Reputation (VirusTotal 90 engines, Google Safe Browsing, PhishTank)
- Page content (obfuscated JS, hidden iframes, phishing forms, base64 blobs)

**Live mode** — passively watches all HTTP + DNS traffic, auto-scans every URL seen.

### 3 — DNS Monitor
Prompts: interface · duration · DGA/keywords/beaconing on/off · save results?

Flags:
- DGA domains (high Shannon entropy = malware C2)
- High-risk TLDs (.tk .ml .xyz .top .win .loan …)
- Suspicious keywords (botnet, c2, shell, exploit, ransom …)
- Beaconing (same domain 30+ queries)
- Punycode homograph attacks
- Very long domains (DNS tunneling)

### 4 — Device Forensics
Prompts: USB / LAN / both / USB live watch · subnet · nmap on/off · save JSON?

**USB** (via pyudev — exact kernel data):
product name, manufacturer, serial number, VID/PID, USB speed, power draw,
device class, driver, OS platform, session history, volume label, filesystem,
capacity, free/used space, mount point, UUID

**LAN** (ARP scan + passive fingerprint + optional nmap):
MAC → manufacturer, hostname (rDNS + mDNS + NetBIOS), OS fingerprint,
nmap open ports + services + versions, risk flagging (dangerous ports)

### 5 — Full Pipeline
Prompts: interface · duration · which modules to enable

Runs selected modules as parallel threads, all output to the same terminal.

---

## Installation

```bash
pip install packetpulse

# Optional — for full URL reputation checks
export PACKETPULSE_VT_KEY="your_virustotal_api_key"
export PACKETPULSE_GSB_KEY="your_google_safe_browsing_key"

# Optional — for offline GeoIP (faster, no rate limit)
export PACKETPULSE_GEOIP_DB="/path/to/GeoLite2-City.mmdb"

sudo packetpulse
```

Requires Python 3.11+, Linux (pyudev for USB), root/sudo for packet capture.

### Security-safe configuration

Keep API keys in environment variables, not in source files.

```bash
# from project root
cp .env.example .env
```

Then set your keys in `.env` (local only, never commit):

```bash
PACKETPULSE_VT_KEY=your_virustotal_api_key
PACKETPULSE_GSB_KEY=your_google_safe_browsing_key
PACKETPULSE_GEOIP_DB=/path/to/GeoLite2-City.mmdb
```

Sensitive files and generated capture outputs are excluded via `.gitignore`.

---

## Publish to PyPI

You can distribute PacketPulse through pip so users install with:

```bash
pip install packetpulse
```

### 1) Build distribution artifacts

```bash
python -m pip install --upgrade build twine
python -m build
```

This generates:
- `dist/*.whl` (wheel)
- `dist/*.tar.gz` (source distribution)

### 2) Validate package metadata

```bash
python -m twine check dist/*
```

### 3) Upload to TestPyPI (recommended first)

```bash
python -m twine upload --repository testpypi dist/*
```

### 4) Upload to PyPI

```bash
python -m twine upload dist/*
```

### 5) Verify install

```bash
pip install packetpulse
packetpulse
```

Note: `pip install` downloads and installs the package for users automatically.
With a pure-Python package, source files are still present in the installed environment.
If you need to hide implementation details, you need a compiled distribution strategy.

### One-command publish (local)

PowerShell:

```powershell
./scripts/publish.ps1 -Repository testpypi
./scripts/publish.ps1 -Repository pypi
```

Cross-platform Python:

```bash
python scripts/release.py --repository testpypi
python scripts/release.py --repository pypi
```

### GitHub Actions trusted publishing

This repository includes a workflow at `.github/workflows/publish.yml`.

It supports:
- Manual dispatch to `testpypi` or `pypi`
- Auto-publish to `pypi` on tag push (`v*`)

Before first run, configure trusted publishing in both indexes:

1. Create project on TestPyPI/PyPI (same package name).
2. In each project, add a Trusted Publisher:
  - Owner: your GitHub org/user
  - Repository: tejppatil/PacketPulse
  - Workflow: `publish.yml`
  - Environment: `testpypi` or `pypi`

After this, no API token is needed in GitHub secrets for publish jobs.

### Optional binary distribution

For executable-only delivery, build a standalone binary (less source visibility than plain pip install):

```powershell
./scripts/build-binary.ps1 -Clean
```

Output:
- `dist/packetpulse` (Linux/macOS)
- `dist/packetpulse.exe` (Windows)

---

## Project structure

```
packetpulse/
├── packetpulse/
│   ├── __init__.py          ← entry point
│   ├── cli.py               ← interactive menu + all module prompts
│   ├── sensor/sensor.py     ← deep packet sniffer (Scapy)
│   ├── urlscan/url_scanner.py  ← URL threat scanner
│   ├── dns/dns_monitor.py   ← DNS query monitor
│   ├── forensics/forensics.py  ← USB + LAN device forensics
│   ├── core/config.py       ← configuration
│   ├── core/logger.py       ← logging
│   └── utils/helpers.py     ← GeoIP, entropy, file helpers
├── pcap_store/              ← all output files
│   ├── *.pcap
│   ├── urls/*.json
│   ├── dns/*.json
│   └── forensics/*.json
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## License

MIT
