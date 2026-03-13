"""
PacketPulse — URL Scanner & Threat Detector
Watches all HTTP/DNS traffic in real time.
When a URL is caught, runs:
  1. URL structure analysis   (patterns, keywords, TLD, length)
  2. Domain reputation check  (VirusTotal, Google Safe Browsing)
  3. Page content scan        (malicious JS, iframes, forms, obfuscation)
  4. SSL/TLS check            (certificate validity, HTTPS enforcement)
"""
from __future__ import annotations

import re
import json
import hashlib
import threading
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs

import requests
import tldextract
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from packetpulse.core.config import get_config
from packetpulse.core.logger import get_logger
from packetpulse.utils.helpers import (
    shannon_entropy, save_json, ensure_dir, now_str, truncate, md5
)

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, Ether
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

console = Console()
log = get_logger("urlscan")

# ── Patterns ───────────────────────────────────────────────────────────────────

# Obfuscated JS patterns
OBFUSCATION_PATTERNS = [
    (r"eval\s*\(", "eval() call — common obfuscation wrapper"),
    (r"eval\s*\(\s*atob\s*\(", "eval(atob()) — base64-decoded execution"),
    (r"eval\s*\(\s*unescape\s*\(", "eval(unescape()) — encoded execution"),
    (r"String\.fromCharCode\s*\(", "String.fromCharCode — char-code obfuscation"),
    (r"\\x[0-9a-fA-F]{2}", "Hex-escaped characters in JS"),
    (r"\\u[0-9a-fA-F]{4}", "Unicode-escaped characters in JS"),
    (r"document\.write\s*\(", "document.write() — common in drive-by scripts"),
    (r"window\[.{1,30}\]\s*\(", "window[variable]() — indirect function call"),
    (r"setTimeout\s*\(\s*['\"][^'\"]{50,}", "setTimeout with long encoded string"),
    (r"fromCharCode.{0,200}fromCharCode", "Multiple fromCharCode — heavy obfuscation"),
]

# Malicious script sources
MALICIOUS_SCRIPT_DOMAINS = [
    "malware", "exploit", "inject", "payload", "shell",
    "c2", "botnet", "rat.", "trojan", "dropper",
]

# Phishing page indicators
PHISHING_PATTERNS = [
    (r'<input[^>]+type=["\']password["\']', "Password input field"),
    (r'action=["\'][^"\']*\.(php|asp|jsp)', "Form POSTing to server-side script"),
    (r'<form[^>]+method=["\']post["\']', "POST form present"),
    (r'login|signin|sign.in|log.in', "Login-related page content"),
    (r'password|passwd|credentials', "Credential-related content"),
    (r'verify.*account|account.*verify', "Account verification prompt"),
    (r'suspended|locked|unusual activity', "Account threat language"),
]

# Suspicious URL parameters
SUSPICIOUS_PARAMS = [
    "redirect", "url", "next", "return", "target", "dest",
    "ref", "token", "key", "cmd", "exec", "shell", "pass",
]


# ── URL Analysis ──────────────────────────────────────────────────────────────

class URLAnalyzer:
    """Runs all checks against a single URL and produces a detailed report."""

    def __init__(self, url: str):
        self.url = url.strip()
        self.parsed = urlparse(self.url)
        self.ext = tldextract.extract(self.url)
        self.cfg = get_config().urlscan
        self.findings: list[dict] = []   # {level, check, detail}
        self.score = 0                   # 0-100 risk score
        self._page_content: Optional[str] = None
        self._page_soup: Optional[BeautifulSoup] = None

    def _add(self, level: str, check: str, detail: str, score: int = 0) -> None:
        """Add a finding. level: OK | WARN | MALICIOUS"""
        self.findings.append({"level": level, "check": check, "detail": detail})
        self.score = min(100, self.score + score)

    # ── Check 1: URL Structure ─────────────────────────────────────────────────

    def check_url_structure(self) -> None:
        url = self.url
        parsed = self.parsed
        ext = self.ext

        # HTTPS check
        if parsed.scheme == "http":
            self._add("WARN", "No HTTPS", "Plain HTTP — traffic is unencrypted", 10)
        elif parsed.scheme == "https":
            self._add("OK", "HTTPS", "Encrypted connection")

        # Suspicious TLD
        tld = "." + ext.suffix if ext.suffix else ""
        if any(url.lower().endswith(bad) or tld.lower() == bad
               for bad in self.cfg.suspicious_tlds):
            self._add("WARN", "Suspicious TLD",
                      f"TLD '{tld}' is commonly used in malicious domains", 15)

        # IP address as host (instead of domain)
        host = parsed.hostname or ""
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, host):
            self._add("MALICIOUS", "IP Address as Host",
                      f"Direct IP '{host}' used — avoids domain reputation checks", 25)

        # URL length
        if len(url) > 200:
            self._add("WARN", "Very Long URL",
                      f"URL is {len(url)} chars — may be obfuscating destination", 10)
        elif len(url) > 100:
            self._add("WARN", "Long URL",
                      f"URL is {len(url)} chars", 5)

        # Subdomain depth
        sub_parts = ext.subdomain.split(".") if ext.subdomain else []
        if len(sub_parts) >= 4:
            self._add("MALICIOUS", "Deep Subdomain",
                      f"{len(sub_parts)} subdomain levels — phishing technique to fake legitimacy", 20)
        elif len(sub_parts) >= 2:
            self._add("WARN", "Multiple Subdomains",
                      f"{len(sub_parts)} subdomain levels", 5)

        # Suspicious keywords in domain
        domain_lower = (ext.domain + "." + ext.suffix).lower()
        found_kw = [kw for kw in self.cfg.suspicious_keywords
                    if kw in domain_lower]
        if len(found_kw) >= 2:
            self._add("MALICIOUS", "Multiple Suspicious Keywords",
                      f"Found in domain: {', '.join(found_kw)}", 25)
        elif found_kw:
            self._add("WARN", "Suspicious Keyword in Domain",
                      f"Found: '{found_kw[0]}'", 10)

        # Suspicious keywords in path/query
        path_lower = (parsed.path + "?" + parsed.query).lower()
        path_kw = [kw for kw in self.cfg.suspicious_keywords if kw in path_lower]
        if path_kw:
            self._add("WARN", "Suspicious Keywords in Path",
                      f"Found: {', '.join(path_kw[:3])}", 8)

        # Suspicious URL parameters
        params = parse_qs(parsed.query)
        sus_p = [p for p in params if p.lower() in SUSPICIOUS_PARAMS]
        if sus_p:
            self._add("WARN", "Suspicious URL Parameters",
                      f"Params: {', '.join(sus_p)}", 8)

        # High entropy domain (DGA indicator)
        domain_name = ext.domain
        if len(domain_name) > 6:
            ent = shannon_entropy(domain_name)
            if ent > 3.8:
                self._add("MALICIOUS", "High-Entropy Domain (DGA)",
                          f"Domain '{domain_name}' entropy={ent:.2f} — looks auto-generated (malware C2)", 30)
            elif ent > 3.2:
                self._add("WARN", "Suspicious Domain Entropy",
                          f"Domain entropy={ent:.2f}", 10)

        # Encoded characters in URL
        if "%2e" in url.lower() or "%2f" in url.lower():
            self._add("MALICIOUS", "URL Encoding Evasion",
                      "Encoded dots/slashes — may be path traversal or filter evasion", 20)

        # Double slash after scheme
        if re.search(r"https?://[^/]+//", url):
            self._add("WARN", "Double Slash in Path",
                      "May be used to confuse URL parsers", 8)

        # Data URI
        if url.startswith("data:"):
            self._add("MALICIOUS", "Data URI",
                      "Inline data URI — common in phishing to bypass URL filters", 35)

        # Homograph / punycode
        if "xn--" in url:
            self._add("MALICIOUS", "Punycode Domain (Homograph Attack)",
                      "IDN domain may be impersonating a legitimate site using look-alike chars", 30)

    # ── Check 2: Domain Reputation ────────────────────────────────────────────

    def check_reputation(self) -> None:
        domain = self.ext.registered_domain or self.parsed.hostname or ""
        if not domain:
            return

        # VirusTotal
        vt_key = self.cfg.virustotal_api_key
        if vt_key:
            try:
                headers = {"x-apikey": vt_key}
                url_id = hashlib.sha256(self.url.encode()).hexdigest()
                # Submit URL
                r = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": self.url},
                    timeout=10,
                )
                if r.status_code == 200:
                    scan_id = r.json().get("data", {}).get("id", "")
                    if scan_id:
                        time.sleep(2)
                        r2 = requests.get(
                            f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
                            headers=headers, timeout=10
                        )
                        if r2.status_code == 200:
                            stats = r2.json().get("data", {}).get("attributes", {}).get("stats", {})
                            malicious = stats.get("malicious", 0)
                            total = sum(stats.values())
                            if malicious > 0:
                                self._add("MALICIOUS", "VirusTotal Detection",
                                          f"{malicious}/{total} engines flagged this URL", 40)
                            else:
                                self._add("OK", "VirusTotal",
                                          f"0/{total} engines flagged")
            except Exception as e:
                self._add("OK", "VirusTotal", f"Check skipped: {e}")
        else:
            self._add("OK", "VirusTotal", "No API key — skipped (set PACKETPULSE_VT_KEY)")

        # Google Safe Browsing
        gsb_key = self.cfg.google_safebrowsing_key
        if gsb_key:
            try:
                payload = {
                    "client": {"clientId": "packetpulse", "clientVersion": "1.0.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                        "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": self.url}],
                    },
                }
                r = requests.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}",
                    json=payload, timeout=8
                )
                if r.status_code == 200:
                    matches = r.json().get("matches", [])
                    if matches:
                        threat_type = matches[0].get("threatType", "UNKNOWN")
                        self._add("MALICIOUS", "Google Safe Browsing",
                                  f"FLAGGED — {threat_type}", 45)
                    else:
                        self._add("OK", "Google Safe Browsing", "Not flagged")
            except Exception as e:
                self._add("OK", "Google Safe Browsing", f"Check skipped: {e}")
        else:
            self._add("OK", "Google Safe Browsing", "No API key — skipped (set PACKETPULSE_GSB_KEY)")

        # PhishTank (no key needed for basic check)
        try:
            r = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": self.url, "format": "json"},
                headers={"User-Agent": "PacketPulse/1.0"},
                timeout=6,
            )
            if r.status_code == 200:
                data = r.json()
                in_db = data.get("results", {}).get("in_database", False)
                valid = data.get("results", {}).get("valid", False)
                if in_db and valid:
                    self._add("MALICIOUS", "PhishTank", "URL is listed as a known phishing page", 45)
                else:
                    self._add("OK", "PhishTank", "Not listed")
        except Exception:
            self._add("OK", "PhishTank", "Check skipped (service unavailable)")

    # ── Check 3: SSL/TLS Certificate ─────────────────────────────────────────

    def check_ssl(self) -> None:
        if self.parsed.scheme != "https":
            self._add("WARN", "SSL/TLS", "Site does not use HTTPS")
            return

        host = self.parsed.hostname or ""
        port = self.parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_ver = ssock.version()

                    # Expiry check
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        from datetime import datetime
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.utcnow()).days
                        if days_left < 0:
                            self._add("MALICIOUS", "SSL Certificate EXPIRED",
                                      f"Expired {abs(days_left)} days ago", 30)
                        elif days_left < 7:
                            self._add("WARN", "SSL Certificate Expiring Soon",
                                      f"Expires in {days_left} days", 10)
                        else:
                            self._add("OK", "SSL Certificate",
                                      f"Valid  •  {tls_ver}  •  {cipher[0]}  •  expires in {days_left}d")

                    # Weak TLS
                    if tls_ver in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        self._add("MALICIOUS", "Weak TLS Version",
                                  f"{tls_ver} is deprecated and insecure", 20)

                    # Subject alt names / CN
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "")
                    if cn and cn != host and not cn.startswith("*."):
                        self._add("WARN", "Certificate CN Mismatch",
                                  f"CN={cn} does not match host={host}", 15)

        except ssl.SSLCertVerificationError as e:
            self._add("MALICIOUS", "SSL Certificate Invalid",
                      f"Certificate verification failed: {e}", 35)
        except ssl.SSLError as e:
            self._add("MALICIOUS", "SSL Error", str(e), 25)
        except (socket.timeout, ConnectionRefusedError, OSError):
            self._add("WARN", "SSL", "Could not connect to check certificate")

    # ── Check 4: Page Content Scan ────────────────────────────────────────────

    def _fetch_page(self) -> bool:
        """Fetch page HTML. Returns True on success."""
        if self._page_content is not None:
            return bool(self._page_content)
        try:
            r = requests.get(
                self.url,
                timeout=self.cfg.request_timeout,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; PacketPulse/1.0)",
                    "Accept": "text/html,application/xhtml+xml",
                },
                verify=False,
                allow_redirects=True,
            )
            self._page_content = r.text
            self._page_soup = BeautifulSoup(r.text, "lxml")
            return True
        except Exception as e:
            self._page_content = ""
            return False

    def check_page_content(self) -> None:
        if not self.cfg.fetch_page:
            self._add("OK", "Page Scan", "Disabled in config")
            return
        if not self._fetch_page():
            self._add("WARN", "Page Scan", "Could not fetch page content")
            return

        content = self._page_content or ""
        soup = self._page_soup

        # Obfuscated JavaScript
        for pattern, description in OBFUSCATION_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                self._add("MALICIOUS", "Obfuscated JavaScript",
                          description, 25)
                break

        # Hidden iframes
        if soup:
            iframes = soup.find_all("iframe")
            hidden_iframes = [
                i for i in iframes
                if (i.get("style", "") and ("display:none" in i.get("style", "").replace(" ", "")
                    or "visibility:hidden" in i.get("style", "").replace(" ", "")))
                or i.get("width") == "0" or i.get("height") == "0"
            ]
            if hidden_iframes:
                self._add("MALICIOUS", "Hidden iframes",
                          f"{len(hidden_iframes)} hidden iframe(s) found — drive-by download technique", 30)
            elif iframes:
                self._add("WARN", "iframes Present",
                          f"{len(iframes)} iframe(s) on page")

        # External scripts from suspicious domains
        if soup:
            scripts = soup.find_all("script", src=True)
            sus_scripts = [
                s["src"] for s in scripts
                if any(kw in s["src"].lower() for kw in MALICIOUS_SCRIPT_DOMAINS)
            ]
            if sus_scripts:
                self._add("MALICIOUS", "Suspicious External Scripts",
                          f"Scripts from: {', '.join(sus_scripts[:3])}", 35)
            elif len(scripts) > 15:
                self._add("WARN", "Many External Scripts",
                          f"{len(scripts)} external scripts loaded", 5)

        # Phishing patterns
        phish_found = []
        for pattern, desc in PHISHING_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                phish_found.append(desc)
        if len(phish_found) >= 3:
            self._add("MALICIOUS", "Phishing Page Indicators",
                      " | ".join(phish_found[:4]), 35)
        elif phish_found:
            self._add("WARN", "Possible Phishing Indicators",
                      " | ".join(phish_found[:2]), 15)

        # Forms submitting to different domains
        if soup:
            forms = soup.find_all("form", action=True)
            base_domain = self.ext.registered_domain
            ext_forms = []
            for f in forms:
                action = f["action"]
                if action.startswith("http"):
                    fext = tldextract.extract(action)
                    if fext.registered_domain and fext.registered_domain != base_domain:
                        ext_forms.append(action)
            if ext_forms:
                self._add("MALICIOUS", "Form Submits to External Domain",
                          f"Data sent to: {ext_forms[0]}", 30)

        # Meta refresh redirect
        if soup:
            meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
            if meta_refresh:
                self._add("WARN", "Meta Refresh Redirect",
                          "Page auto-redirects — common in phishing chains", 10)

        # Favicon spoofing
        if soup and base_domain:
            favicons = soup.find_all("link", rel=lambda r: r and "icon" in r)
            for fav in favicons:
                href = fav.get("href", "")
                if href.startswith("http"):
                    fext = tldextract.extract(href)
                    if fext.registered_domain and fext.registered_domain != base_domain:
                        self._add("WARN", "Favicon from External Domain",
                                  f"Icon loaded from {fext.registered_domain} — possible brand spoofing", 10)

        # Base64 blobs
        b64_count = len(re.findall(r'base64,[A-Za-z0-9+/]{100,}', content))
        if b64_count >= 3:
            self._add("MALICIOUS", "Multiple Base64 Blobs",
                      f"{b64_count} inline base64 blocks — possible payload delivery", 20)
        elif b64_count:
            self._add("WARN", "Base64 Content", f"{b64_count} base64 block(s) in page", 5)

        if not any(f["level"] in ("WARN", "MALICIOUS") for f in self.findings
                   if f["check"] not in ("HTTPS", "SSL/TLS", "SSL Certificate")):
            self._add("OK", "Page Content", "No malicious patterns detected")

    # ── Run all & report ──────────────────────────────────────────────────────

    def run(self) -> dict:
        self.check_url_structure()
        self.check_ssl()
        self.check_reputation()
        self.check_page_content()
        return self.report()

    def verdict(self) -> str:
        levels = [f["level"] for f in self.findings]
        if "MALICIOUS" in levels:
            return "MALICIOUS"
        if "WARN" in levels:
            return "SUSPICIOUS"
        return "CLEAN"

    def report(self) -> dict:
        return {
            "url": self.url,
            "timestamp": now_str(),
            "verdict": self.verdict(),
            "risk_score": self.score,
            "findings": self.findings,
        }


# ── Terminal display ───────────────────────────────────────────────────────────

def _print_report(report: dict) -> None:
    url = report["url"]
    verdict = report["verdict"]
    score = report["risk_score"]
    findings = report["findings"]

    verdict_col = {"MALICIOUS": "bold red", "SUSPICIOUS": "bold yellow", "CLEAN": "bold green"}[verdict]
    verdict_icon = {"MALICIOUS": "✗", "SUSPICIOUS": "⚠", "CLEAN": "✓"}[verdict]

    console.rule(f"[bold]URL SCAN REPORT[/bold]")
    console.print(f"\n  [dim]URL[/dim]     {truncate(url, 100)}")
    console.print(f"  [dim]Time[/dim]    {now_str()}")
    console.print(f"  [dim]Score[/dim]   {score}/100")
    console.print(f"  [dim]Verdict[/dim] [{verdict_col}]{verdict_icon} {verdict}[/{verdict_col}]\n")

    # Findings table
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="dim",
                  padding=(0, 1))
    table.add_column("STATUS", width=10)
    table.add_column("CHECK", width=30)
    table.add_column("DETAIL")

    icon_map = {"OK": "[green]  ✓ OK[/green]",
                "WARN": "[yellow]  ⚠ WARN[/yellow]",
                "MALICIOUS": "[bold red]  ✗ MALICIOUS[/bold red]"}

    for f in findings:
        table.add_row(icon_map[f["level"]], f["check"], f["detail"])

    console.print(table)

    # Summary box
    malicious = [f for f in findings if f["level"] == "MALICIOUS"]
    warnings = [f for f in findings if f["level"] == "WARN"]
    if malicious:
        console.print(f"  [bold red]THREATS FOUND ({len(malicious)}):[/bold red]")
        for m in malicious:
            console.print(f"  [red]  ✗  {m['check']}:[/red] {m['detail']}")
    if warnings:
        console.print(f"  [yellow]WARNINGS ({len(warnings)}):[/yellow]")
        for w in warnings:
            console.print(f"  [yellow]  ⚠  {w['check']}:[/yellow] {w['detail']}")

    console.print("[dim]" + "─" * 100 + "[/dim]\n")


# ── Live traffic watcher ───────────────────────────────────────────────────────

_seen_urls: set[str] = set()
_seen_domains: set[str] = set()


def _extract_url_from_packet(pkt) -> Optional[str]:
    """Extract HTTP URL from a raw packet."""
    if not pkt.haslayer(Raw):
        return None
    try:
        payload = bytes(pkt[Raw]).decode("utf-8", errors="replace")
    except Exception:
        return None

    m = re.match(r"(GET|POST|PUT|DELETE|HEAD)\s+(\S+)\s+HTTP", payload)
    if not m:
        return None

    path = m.group(2)
    # Extract host from headers
    host_m = re.search(r"Host:\s*([^\r\n]+)", payload)
    host = host_m.group(1).strip() if host_m else ""
    if not host:
        return None

    scheme = "https" if pkt.haslayer(TCP) and pkt[TCP].dport == 443 else "http"
    return f"{scheme}://{host}{path}"


def _extract_domain_from_dns(pkt) -> Optional[str]:
    """Extract domain from a DNS query packet."""
    try:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qdcount > 0:
            domain = pkt[DNS].qd.qname.decode("utf-8", errors="replace").rstrip(".")
            return domain
    except Exception:
        pass
    return None


def _live_packet_callback(pkt) -> None:
    """Callback used in live mode — catches URLs from traffic."""
    cfg = get_config().urlscan

    # From HTTP payload
    url = _extract_url_from_packet(pkt)
    if url and url not in _seen_urls:
        _seen_urls.add(url)
        console.print(f"\n[dim]↳ URL detected:[/dim] [cyan]{truncate(url, 80)}[/cyan]")
        _scan_and_print(url)
        return

    # From DNS query — scan the domain
    domain = _extract_domain_from_dns(pkt)
    if domain and domain not in _seen_domains and len(domain) > 3:
        _seen_domains.add(domain)
        url = f"http://{domain}"
        if url not in _seen_urls:
            _seen_urls.add(url)
            console.print(f"\n[dim]↳ DNS query:[/dim] [magenta]{domain}[/magenta]")
            _scan_and_print(url)


def _scan_and_print(url: str) -> None:
    """Run scanner in background thread to avoid blocking sniff loop."""
    def _run():
        try:
            analyzer = URLAnalyzer(url)
            # In live mode: only do structure + reputation (skip full page fetch)
            analyzer.check_url_structure()
            analyzer.check_ssl()
            analyzer.check_reputation()
            report = analyzer.report()
            if report["verdict"] != "CLEAN" or report["risk_score"] > 0:
                _print_report(report)
                cfg = get_config().urlscan
                fname = f"{cfg.results_path}/{md5(url)}_{now_str()[:10]}.json"
                save_json(report, fname)
        except Exception as e:
            log.debug(f"URL scan error: {e}")

    threading.Thread(target=_run, daemon=True).start()


# ── Entry points ───────────────────────────────────────────────────────────────

def scan_url(url: str) -> None:
    """Manually scan a single URL — full analysis including page content."""
    if not url.startswith("http"):
        url = "http://" + url

    console.rule(f"[bold green]PACKETPULSE  ›  URL SCANNER[/bold green]")
    console.print(f"  [dim]Target:[/dim] [cyan]{url}[/cyan]")
    console.print(f"  [dim]Mode:[/dim]   Full analysis (structure + SSL + reputation + page content)")
    console.print("[dim]" + "─" * 100 + "[/dim]\n")

    console.print("  [dim]Running checks...[/dim]")
    console.print(f"  [dim]  [1/4] URL structure analysis...[/dim]")
    analyzer = URLAnalyzer(url)
    analyzer.check_url_structure()

    console.print(f"  [dim]  [2/4] SSL/TLS certificate check...[/dim]")
    analyzer.check_ssl()

    console.print(f"  [dim]  [3/4] Domain reputation check...[/dim]")
    analyzer.check_reputation()

    console.print(f"  [dim]  [4/4] Page content scan...[/dim]\n")
    analyzer.check_page_content()

    report = analyzer.report()
    _print_report(report)

    cfg = get_config().urlscan
    ensure_dir(cfg.results_path)
    fname = f"{cfg.results_path}/{md5(url)}.json"
    save_json(report, fname)
    console.print(f"  [dim]Report saved →[/dim] [cyan]{fname}[/cyan]\n")


def run_live_urlscan(interface: Optional[str] = None) -> None:
    """Watch live traffic and auto-scan every URL/domain seen."""
    if not SCAPY_OK:
        console.print("[red]ERROR: scapy is not installed.[/red]")
        return

    cfg = get_config().urlscan
    ensure_dir(cfg.results_path)

    console.rule("[bold green]PACKETPULSE  ›  LIVE URL WATCHER[/bold green]")
    console.print(
        f"  [dim]Mode:[/dim] Passive traffic watch — catches every URL/domain your machine visits\n"
        f"  [dim]Checks:[/dim] URL structure  •  Domain reputation  •  SSL certificate\n"
        f"  [dim]Results →[/dim] [cyan]{cfg.results_path}/[/cyan]\n"
    )
    console.print("[dim]" + "─" * 100 + "[/dim]")
    console.print("  [dim]Waiting for URLs... (browse normally)[/dim]\n")

    try:
        from scapy.all import conf
        sniff(
            iface=interface or None,
            filter="tcp port 80 or tcp port 443 or udp port 53",
            prn=_live_packet_callback,
            store=False,
        )
    except KeyboardInterrupt:
        console.print(f"\n[green]Stopped.[/green] Scanned {len(_seen_urls)} URLs, {len(_seen_domains)} domains.")
    except PermissionError:
        console.print("[red]ERROR: Requires root/sudo privileges.[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
