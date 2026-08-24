"""
PacketPulse — URL Scanner v2
• Single URL: 4-check deep analysis with dataset-backed verdicts
• Live mode:  intercepts every URL from ALL browsers via /proc/net/tcp
              (works even on HTTPS — reads SNI from socket state)
              Instant desktop popup alert on MALICIOUS detection
              Final session report generated on exit
"""
from __future__ import annotations

import re
import json
import threading
import socket
import ssl
import time
import subprocess
import os
import base64
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs

import requests
import tldextract
from bs4 import BeautifulSoup
from rich.table import Table
from rich import box

from packetpulse.core.config import get_config
from packetpulse.core.logger import get_logger, console as _shared_console
from packetpulse.utils.helpers import (
    shannon_entropy, save_json, ensure_dir, now_str, truncate, timestamp_filename, save_report_pdf, safe_output_path, shell_safe,
    h as esc, utc_now,
)
from packetpulse import __version__
from packetpulse.core import capabilities


def _registered(ext) -> str:
    """Registered domain, using whichever accessor this tldextract provides."""
    value = getattr(ext, "top_domain_under_public_suffix", None)
    if value is None:
        value = getattr(ext, "registered_domain", "")
    return (value or "").lower()
from packetpulse.core.session import Session, StopController
from concurrent.futures import ThreadPoolExecutor
from rich.markup import escape as rescape

# Narrow scapy imports. `from scapy.all import ...` loads every contrib module
# and measured ~123 s on a Windows host with 79 network adapters; importing the
# layers actually used takes ~4 s and leaves conf.ifaces fully populated, so
# capture, BPF filters, decoding and PCAP writing behave identically.
from packetpulse.core import scapy_compat
from packetpulse.core.scapy_compat import prepare_scapy, IMPORT_ERROR as _SCAPY_ERR

# Must run before any scapy layer import: on some kernels scapy 2.6+
# raises KeyError: 'scope' while building its IPv6 route table.
prepare_scapy()

try:
    from scapy.layers.dns import DNS
    from scapy.packet import Raw
    from scapy.sendrecv import sniff
    SCAPY_OK = True
    SCAPY_UNAVAILABLE_REASON = ""
except Exception as _e:
    SCAPY_OK = False
    SCAPY_UNAVAILABLE_REASON = _SCAPY_ERR or "{}: {}".format(type(_e).__name__, _e)

console = _shared_console


class _RateLimiter:
    """Token bucket per external service.

    The config carried vt_rate_limit / gsb_rate_limit fields that nothing read,
    so live mode exhausted a free API key within seconds.
    """

    def __init__(self) -> None:
        self._hits: dict = {}
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        if limit <= 0:
            return True
        now = time.time()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < window_seconds]
            if len(hits) >= limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


_rate_limiter = _RateLimiter()
log = get_logger("urlscan")

# ═══════════════════════════════════════════════════════════════════════════════
# THREAT DATASETS  (embedded — no external files needed)
# These are compact but comprehensive rule sets derived from public threat intel.
# ═══════════════════════════════════════════════════════════════════════════════

# High-confidence malicious TLDs (abuse stats from SURBL / Spamhaus)
MALICIOUS_TLDS = {
    ".tk",".ml",".ga",".cf",".gq",         # Freenom — >80% abuse rate
    ".top",".xyz",".win",".loan",".click",  # High-abuse generic TLDs
    ".download",".stream",".racing",
    ".review",".party",".science",
    ".accountant",".trade",".date",
    ".faith",".webcam",".men",
    ".gdn",".kim",".work",".link",
}
SUSPICIOUS_TLDS = {".ru",".cn",".cc",".su",".pw",".in",".info",".biz"}

# Keyword sets by category (from phishing kit analysis)
PHISH_BRAND_KEYWORDS = {
    "paypal","amazon","microsoft","apple","google","facebook","instagram","netflix",
    "bank","wellsfargo","chase","citibank","barclays","hsbc","lloyds","natwest",
    "outlook","office365","onedrive","dropbox","icloud","signin","secure-login",
    "account-verify","update-billing","confirm-identity",
}
MALWARE_KEYWORDS = {
    "malware","botnet","c2","c&c","payload","shell","exploit","inject",
    "trojan","ransomware","dropper","loader","stealer","miner","cryptominer",
    "rat","beacon","exfil","backdoor",
}
SUSPICIOUS_KEYWORDS = {
    "free","winner","claim","prize","urgent","verify","login","secure",
    "update","confirm","account","suspended","alert","warning","invoice",
    "download","install","crack","keygen","serial","patch","activator",
}

# Suspicious URL params (from OWASP top-10 analysis)
SUSPICIOUS_PARAMS = {
    "redirect","url","next","return","target","dest","ref","token","key",
    "cmd","exec","shell","pass","payload","callback","goto","redir","jump",
}

# JS execution patterns (high confidence malicious)
JS_EXEC_PATTERNS = [
    (r"eval\s*\(\s*atob\s*\(",    "eval(atob()) — base64-decoded execution"),
    (r"eval\s*\(\s*unescape\s*\(","eval(unescape()) — encoded execution"),
    (r"eval\s*\(\s*String",       "eval(String.fromCharCode) — char-code execution"),
    (r"new\s+Function\s*\(",      "new Function() — dynamic code construction"),
    (r"document\.write\s*\(",     "document.write() — common in drive-by injections"),
    (r"window\.location\s*=\s*atob","atob-decoded redirect — obfuscated redirect"),
]

# Phishing structural patterns
PHISHING_STRUCTURAL = [
    (r'<input[^>]+type=["\']password["\']',         "Password input field"),
    (r'action=["\'][^"\']*\.(php|asp|jsp|aspx)',    "Form POSTing to server-side script"),
    (r'<form[^>]+method=["\']post["\']',            "POST form present"),
    (r'verify.*(?:account|identity|email)',         "Account verification prompt"),
    (r'(?:suspended|locked|unusual.activity)',      "Account threat language"),
    (r'(?:enter|provide).{0,30}(?:password|credentials|card.number)', "Credential request"),
]

# Brand impersonation patterns
BRAND_IMPERSONATION = [
    (r'paypal\.(?!com)', "PayPal impersonation"),
    (r'amazon\.(?!com|co\.uk|de|fr|jp|in|ca|com\.au)', "Amazon impersonation"),
    (r'appleid\.(?!apple\.com)', "Apple ID impersonation"),
    (r'microsoft\.(?!com)', "Microsoft impersonation"),
    (r'(?:google|gmail)\.(?!com|co\.|org)', "Google impersonation"),
]

# Safe domain whitelist (skip expensive checks on these)
SAFE_DOMAINS = {
    "google.com","googleapis.com","gstatic.com","youtube.com","youtu.be",
    "facebook.com","instagram.com","twitter.com","x.com","microsoft.com",
    "windows.com","apple.com","icloud.com","amazon.com","amazonaws.com",
    "cloudflare.com","fastly.com","akamai.com","github.com","githubusercontent.com",
    "stackoverflow.com","reddit.com","linkedin.com","wikipedia.org","mozilla.org",
    "python.org","pypi.org","npmjs.com","docker.com","kubernetes.io",
}

# ═══════════════════════════════════════════════════════════════════════════════
# DESKTOP POPUP ALERT
# Works on Linux (notify-send), macOS (osascript), Windows (PowerShell toast)
# ═══════════════════════════════════════════════════════════════════════════════

def _desktop_alert(url: str, verdict: str, score: int, reasons: list) -> None:
    """Fire a desktop notification for a detection.

    Every interpolated value is sanitised first. In live mode the URL comes
    from someone else's traffic, and these values previously reached a
    PowerShell -Command string and an AppleScript literal, where a quote and a
    semicolon in a hostname would execute arbitrary code.
    """
    safe_url = shell_safe(url, 90)
    safe_verdict = shell_safe(verdict, 20)
    safe_reason = shell_safe(reasons[0] if reasons else "multiple indicators", 90)
    title = "PacketPulse - URL detection"
    body = "URL: {}\nScore: {}/100\nVerdict: {}\nBasis: {}".format(
        safe_url, int(score), safe_verdict, safe_reason)

    try:
        if sys.platform.startswith("linux"):
            if not shutil.which("notify-send"):
                return
            subprocess.Popen(
                ["notify-send", "--urgency=critical", "--app-name=PacketPulse",
                 title, body],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        elif sys.platform == "darwin":
            # Pass the script on stdin so no captured text reaches argv.
            script = 'display notification "{}" with title "{}"'.format(
                body.replace("\n", " "), title)
            proc = subprocess.Popen(["osascript", "-"], stdin=subprocess.PIPE,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.stdin.write(script.encode("utf-8", "ignore"))
            proc.stdin.close()
        elif os.name == "nt":
            # Write the message to a temp file and have PowerShell READ it, so
            # no captured text is ever parsed as PowerShell source.
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                             encoding="utf-8") as fh:
                fh.write(title + "\n" + body)
                msg_path = fh.name
            ps = (
                "$ErrorActionPreference='SilentlyContinue';"
                "$t=Get-Content -Raw -LiteralPath $env:PP_MSG;"
                "[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');"
                "$n=New-Object System.Windows.Forms.NotifyIcon;"
                "$n.Icon=[System.Drawing.SystemIcons]::Warning;$n.Visible=$true;"
                "$n.ShowBalloonTip(8000,'PacketPulse',$t,"
                "[System.Windows.Forms.ToolTipIcon]::Warning);Start-Sleep -Seconds 9"
            )
            env = dict(os.environ, PP_MSG=msg_path)
            subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("desktop alert unavailable: %s: %s", type(e).__name__, e)


def _load_url_cache() -> dict[str, dict]:
    cfg = get_config().urlscan
    if not cfg.cache_enabled:
        return {}
    try:
        path = Path(cfg.cache_path)
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        log.debug(f"Could not load URL cache: {e}")
    return {}


def _save_url_cache(cache: dict[str, dict]) -> None:
    cfg = get_config().urlscan
    if not cfg.cache_enabled:
        return
    try:
        path = Path(cfg.cache_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        log.debug(f"Could not save URL cache: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# URL ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class URLAnalyzer:
    def __init__(self, url: str):
        self.url = (url or "").strip()
        self.parse_error = ""
        try:
            self.parsed = urlparse(self.url)
        except ValueError as e:
            # urlparse raises on malformed IPv6 literals such as "https://[::1".
            # A malformed URL is a finding, not a crash.
            self.parse_error = "URL could not be parsed: {}".format(e)
            self.parsed = urlparse("http://invalid.invalid/")
        try:
            self.ext = tldextract.extract(self.url)
        except Exception as e:
            self.parse_error = self.parse_error or "domain extraction failed: {}".format(e)
            self.ext = tldextract.extract("invalid.invalid")
        self.cfg    = get_config().urlscan
        self.findings: list[dict] = []
        self.score  = 0
        self._page_content: Optional[str] = None
        self._page_soup:    Optional[BeautifulSoup] = None
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; PacketPulse/1.0)"})

    def _add(self, level: str, check: str, detail: str, score: int = 0) -> None:
        """Record a finding. `score` is the documented weight it contributes."""
        self.findings.append({"level": level, "check": check,
                              "detail": detail, "weight": score})
        self.score = min(100, self.score + score)

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname or ""
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme.lower()}://{host.lower()}{path}{query}"

    def _host_matches_cert(self, host: str, cert: dict) -> bool:
        altnames = [name for typ, name in cert.get("subjectAltName", []) if typ == "DNS"]
        if host in altnames:
            return True
        if cert.get("subject"):
            subject = dict(x[0] for x in cert.get("subject", []))
            cn = subject.get("commonName", "")
            if cn and (cn == host or cn.startswith("*.") and host.endswith(cn[2:])):
                return True
        for name in altnames:
            if name.startswith("*.") and host.endswith(name[2:]):
                return True
        return False

    # ── Check 1: URL structure + dataset matching ─────────────────────────────

    def check_url_structure(self) -> None:
        if self.parse_error:
            self._add("SUSPICIOUS", "Malformed URL", self.parse_error, 15)
            return
        url = self.url; parsed = self.parsed; ext = self.ext

        # Scheme
        if parsed.scheme == "http":
            self._add("WARN", "No HTTPS", "Plain HTTP — traffic unencrypted", 8)
        elif parsed.scheme == "https":
            self._add("OK", "HTTPS", "Encrypted connection")

        # TLD check against dataset
        tld = ("." + ext.suffix).lower() if ext.suffix else ""
        if tld in MALICIOUS_TLDS:
            self._add("MALICIOUS", "High-Abuse TLD",
                      f"'{tld}' — abuse rate >70% (Freenom/SURBL data)", 25)
        elif tld in SUSPICIOUS_TLDS:
            self._add("WARN", "Suspicious TLD",
                      f"'{tld}' — elevated abuse in threat intel feeds", 10)

        # IP-as-host
        host = parsed.hostname or ""
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            self._add("MALICIOUS", "IP Address as Host",
                      f"Direct IP '{host}' — bypasses domain reputation", 25)

        # URL length
        if len(url) > 200:
            self._add("WARN", "Very Long URL", f"{len(url)} chars — obfuscation indicator", 10)
        elif len(url) > 100:
            self._add("WARN", "Long URL", f"{len(url)} chars", 5)

        # Subdomain depth
        sub_parts = ext.subdomain.split(".") if ext.subdomain else []
        if len(sub_parts) >= 4:
            self._add("MALICIOUS", "Deep Subdomain Stack",
                      f"{len(sub_parts)} levels — phishing legitimacy-faking technique", 20)
        elif len(sub_parts) >= 2:
            self._add("WARN", "Multiple Subdomains", f"{len(sub_parts)} subdomain levels", 5)

        # Brand impersonation in domain
        registered = _registered(ext)
        # Whole-token matching. Substring matching flagged bankofamerica.com as
        # PayPal-style impersonation because 'bank' appeared inside the name.
        tokens = set(t for t in re.split(r"[.\-_0-9]+", ext.domain.lower()) if t)
        for brand in PHISH_BRAND_KEYWORDS:
            if brand not in tokens:
                continue
            if ext.domain.lower() == brand:
                continue  # the brand's own domain is not impersonating itself
            real_domains = {brand + s2 for s2 in (".com", ".org", ".net", ".co.uk")}
            if registered not in real_domains:
                self._add("SUSPICIOUS", "Brand token in domain",
                          "token '{}' appears in a domain that is not {}.com "
                          "(possible impersonation; not confirmed)".format(brand, brand), 25)
                break

        # Malware-related keywords
        full_url_lower = url.lower()
        _url_tokens = set(re.split(r"[^a-z0-9]+", full_url_lower))
        mal_kw = sorted(_url_tokens & MALWARE_KEYWORDS)
        if mal_kw:
            self._add("MALICIOUS", "Malware-Related Keywords",
                      f"Found: {', '.join(mal_kw[:3])}", 25)

        # Suspicious keywords (multiple = higher score)
        sus_kw = sorted(set(re.split(r"[.\-_0-9]+", ext.domain.lower())) & SUSPICIOUS_KEYWORDS)
        if len(sus_kw) >= 2:
            self._add("MALICIOUS", "Multiple Suspicious Keywords",
                      f"In domain: {', '.join(sus_kw)}", 20)
        elif sus_kw:
            self._add("WARN", "Suspicious Keyword", f"'{sus_kw[0]}' in domain", 8)

        # Path keywords
        path_lower = (parsed.path + "?" + parsed.query).lower()
        path_sus = [k for k in SUSPICIOUS_KEYWORDS if k in path_lower]
        if path_sus:
            self._add("WARN", "Suspicious Path Keywords",
                      f"Found: {', '.join(path_sus[:3])}", 6)

        # Suspicious params
        params = parse_qs(parsed.query)
        sus_p = [p for p in params if p.lower() in SUSPICIOUS_PARAMS]
        if sus_p:
            self._add("WARN", "Suspicious URL Parameters",
                      f"Params: {', '.join(sus_p)}", 8)

        # High entropy domain (DGA)
        if len(ext.domain) > 6:
            ent = shannon_entropy(ext.domain)
            if ent > 3.8:
                self._add("MALICIOUS", "DGA Domain (High Entropy)",
                          f"entropy={ent:.2f} — auto-generated malware C2 domain", 35)
            elif ent > 3.2:
                self._add("WARN", "Suspicious Domain Entropy",
                          f"entropy={ent:.2f}", 10)

        # Encoding evasion
        if "%2e" in url.lower() or "%2f" in url.lower():
            self._add("MALICIOUS", "URL Encoding Evasion",
                      "Encoded dots/slashes — path traversal or filter bypass", 20)

        # Punycode / homograph
        if "xn--" in url:
            self._add("MALICIOUS", "Punycode Homograph Attack",
                      "IDN domain — impersonating legitimate site with look-alike chars", 30)

        # Data URI
        if url.startswith("data:"):
            self._add("MALICIOUS", "Data URI",
                      "Inline data URI — common phishing URL filter bypass", 35)

        # Double slash trick
        if re.search(r"https?://[^/]+//", url):
            self._add("WARN", "Double Slash in Path",
                      "May confuse URL parsers", 8)

        # Executable extension in URL
        if re.search(r"\.(exe|bat|ps1|vbs|jar|msi|cmd|sh|py|rb|php)(\?|$)", url.lower()):
            self._add("WARN", "Executable File Extension",
                      "URL points to executable or script file", 15)

    # ── Check 2: SSL/TLS ─────────────────────────────────────────────────────

    def check_ssl(self) -> None:
        if self.parse_error:
            self._add("INFO", "Skipped", "URL is malformed; check not run")
            return
        if self.parsed.scheme != "https":
            self._add("WARN", "SSL/TLS", "No HTTPS")
            return
        host = self.parsed.hostname or ""
        port = self.parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.cfg.request_timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_v = ssock.version()
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            # Certificate notAfter is GMT; compare aware-to-aware
                            # so the 7-day warning boundary is correct in every
                            # timezone.
                            expiry = datetime.strptime(
                                not_after, "%b %d %H:%M:%S %Y %Z"
                            ).replace(tzinfo=timezone.utc)
                            days = (expiry - utc_now()).days
                            if days < 0:
                                self._add("MALICIOUS", "SSL Certificate EXPIRED", f"Expired {abs(days)} days ago", 30)
                            elif days < 7:
                                self._add("WARN", "SSL Certificate Expiring Soon", f"Expires in {days} days", 10)
                            else:
                                self._add("OK", "SSL Certificate", f"Valid  •  {tls_v}  •  {cipher[0]}  •  {days}d left")
                        except Exception:
                            self._add("WARN", "SSL Certificate", "Could not parse certificate expiry")
                    if tls_v in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        self._add("MALICIOUS", "Weak TLS Version", f"{tls_v} deprecated and insecure", 20)
                    if not self._host_matches_cert(host, cert):
                        self._add("WARN", "Certificate Hostname Mismatch", f"Certificate does not match host {host}", 15)
        except ssl.SSLCertVerificationError as e:
            self._add("MALICIOUS", "SSL Certificate Invalid", str(e)[:80], 35)
        except ssl.SSLError as e:
            self._add("MALICIOUS", "SSL Error", str(e)[:60], 25)
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            self._add("WARN", "SSL", f"Could not connect to verify certificate: {str(e)[:60]}")

    # ── Check 3: Reputation ───────────────────────────────────────────────────

    def check_reputation(self, scope: str = "url") -> None:
        """Query external reputation services — only when explicitly enabled.

        `scope` is "url" (single-URL mode, user typed it) or "domain" (live
        mode, where sending full URLs would transmit paths and query strings
        containing tokens for every site the monitored network visits).

        A service that is not configured, or not reachable, is reported as
        such. It is NEVER reported as a clean result: "not checked" and
        "checked and clean" are different facts.
        """
        domain = _registered(self.ext) or self.parsed.hostname or ""
        if not domain:
            self._add("INFO", "Reputation", "no resolvable domain to check")
            return

        if not self.cfg.allow_external:
            self._add("INFO", "External reputation",
                      "NOT CHECKED — external lookups are disabled. "
                      "Enable them to query VirusTotal / Safe Browsing / PhishTank.")
            return

        target = self.url if scope == "url" else "http://{}/".format(domain)
        if scope == "domain":
            self._add("INFO", "External reputation scope",
                      "domain only ({}) — full URL not transmitted".format(domain))

        self._check_virustotal(target)
        self._check_safebrowsing(target)
        self._check_phishtank(target)

    def _check_virustotal(self, target: str) -> None:
        key = self.cfg.virustotal_api_key
        if not key:
            self._add("INFO", "VirusTotal", "NOT CONFIGURED (set PACKETPULSE_VT_KEY)")
            return
        if not _rate_limiter.allow("virustotal", self.cfg.vt_rate_limit, 60):
            self._add("INFO", "VirusTotal", "NOT CHECKED — local rate limit reached "
                                            "({}/min)".format(self.cfg.vt_rate_limit))
            return
        try:
            # URL-report endpoint keyed by the unpadded base64url id. This READS
            # existing analysis; it does not submit the URL to the public corpus,
            # and it returns a real answer immediately instead of a queued job.
            uid = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            r = requests.get(
                "https://www.virustotal.com/api/v3/urls/{}".format(uid),
                headers={"x-apikey": key},
                timeout=self.cfg.request_timeout,
            )
            if r.status_code == 200:
                stats = (r.json().get("data", {}).get("attributes", {})
                         .get("last_analysis_stats", {})) or {}
                mal = int(stats.get("malicious", 0))
                susp = int(stats.get("suspicious", 0))
                total = sum(int(v) for v in stats.values()) or 0
                if total == 0:
                    self._add("INFO", "VirusTotal", "no analysis statistics returned")
                elif mal > 0:
                    self._add("MALICIOUS", "VirusTotal Detection",
                              "{}/{} engines flagged this URL".format(mal, total), 40)
                elif susp > 0:
                    self._add("WARN", "VirusTotal",
                              "{}/{} engines marked suspicious".format(susp, total), 12)
                else:
                    self._add("OK", "VirusTotal", "0/{} engines flagged".format(total))
            elif r.status_code == 404:
                self._add("INFO", "VirusTotal", "URL not present in the VirusTotal corpus "
                                                "(no analysis exists; not a clean verdict)")
            elif r.status_code in (401, 403):
                self._add("INFO", "VirusTotal", "API key rejected (HTTP {})".format(r.status_code))
            elif r.status_code == 429:
                self._add("INFO", "VirusTotal", "rate limited by the service (HTTP 429)")
            else:
                self._add("INFO", "VirusTotal", "UNAVAILABLE (HTTP {})".format(r.status_code))
        except requests.exceptions.RequestException as e:
            self._add("INFO", "VirusTotal", "UNAVAILABLE ({})".format(type(e).__name__))
        except (ValueError, KeyError) as e:
            self._add("INFO", "VirusTotal", "unreadable response ({})".format(type(e).__name__))

    def _check_safebrowsing(self, target: str) -> None:
        key = self.cfg.google_safebrowsing_key
        if not key:
            self._add("INFO", "Google Safe Browsing", "NOT CONFIGURED (set PACKETPULSE_GSB_KEY)")
            return
        if not _rate_limiter.allow("gsb", self.cfg.gsb_rate_limit, 86400):
            self._add("INFO", "Google Safe Browsing", "NOT CHECKED — local daily limit reached")
            return
        try:
            payload = {
                "client": {"clientId": "packetpulse", "clientVersion": __version__},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": target}],
                },
            }
            r = requests.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": key}, json=payload, timeout=self.cfg.request_timeout,
            )
            if r.status_code == 200:
                matches = r.json().get("matches", [])
                if matches:
                    self._add("MALICIOUS", "Google Safe Browsing",
                              "listed as {}".format(matches[0].get("threatType", "a threat")), 45)
                else:
                    self._add("OK", "Google Safe Browsing", "not listed")
            else:
                self._add("INFO", "Google Safe Browsing",
                          "UNAVAILABLE (HTTP {})".format(r.status_code))
        except requests.exceptions.RequestException as e:
            self._add("INFO", "Google Safe Browsing", "UNAVAILABLE ({})".format(type(e).__name__))
        except (ValueError, KeyError) as e:
            self._add("INFO", "Google Safe Browsing", "unreadable response ({})".format(type(e).__name__))

    def _check_phishtank(self, target: str) -> None:
        key = os.environ.get("PACKETPULSE_PHISHTANK_KEY", "")
        if not key:
            # The public endpoint requires a registered application key; querying
            # it anonymously produced a permanent error row in every report.
            self._add("INFO", "PhishTank", "NOT CONFIGURED (set PACKETPULSE_PHISHTANK_KEY)")
            return
        try:
            r = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": target, "format": "json", "app_key": key},
                headers={"User-Agent": "phishtank/packetpulse"},
                timeout=self.cfg.request_timeout,
            )
            if r.status_code == 200:
                res = (r.json().get("results") or {})
                if res.get("in_database") and res.get("valid"):
                    self._add("MALICIOUS", "PhishTank", "listed as a verified phishing page", 45)
                else:
                    self._add("OK", "PhishTank", "not listed")
            else:
                self._add("INFO", "PhishTank", "UNAVAILABLE (HTTP {})".format(r.status_code))
        except requests.exceptions.RequestException as e:
            self._add("INFO", "PhishTank", "UNAVAILABLE ({})".format(type(e).__name__))
        except (ValueError, KeyError):
            self._add("INFO", "PhishTank", "unreadable response")

    # ── Check 4: Page content ─────────────────────────────────────────────────

    MAX_PAGE_BYTES = 2_000_000

    def _fetch_page(self) -> bool:
        """Fetch the page with verification ON and a hard size limit.

        Certificate verification is never disabled: a scanner that reports on
        TLS must not silently ignore it, and a hostile page must not be able to
        stream unbounded data into memory.
        """
        if self._page_content is not None:
            return bool(self._page_content)
        try:
            r = requests.get(
                self.url,
                timeout=self.cfg.request_timeout,
                headers={"User-Agent": "Mozilla/5.0 (compatible; PacketPulse/1.0)"},
                allow_redirects=True,
                stream=True,
            )
            chunks, total = [], 0
            for chunk in r.iter_content(8192):
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total >= self.MAX_PAGE_BYTES:
                    self._add("INFO", "Page truncated",
                              "stopped reading at {} bytes".format(self.MAX_PAGE_BYTES))
                    break
            raw = b"".join(chunks)
            self._page_content = raw.decode(r.encoding or "utf-8", errors="replace")
            self._page_soup = BeautifulSoup(self._page_content, "lxml")
            return True
        except requests.exceptions.SSLError as e:
            self._add("SUSPICIOUS", "TLS verification failed",
                      "certificate could not be verified: {}".format(str(e)[:90]), 30)
            self._page_content = ""
            return False
        except requests.exceptions.RequestException as e:
            self._add("INFO", "Page not fetched",
                      "{}: {}".format(type(e).__name__, str(e)[:70]))
            self._page_content = ""
            return False

    def check_page_content(self) -> None:
        if self.parse_error:
            self._add("INFO", "Skipped", "URL is malformed; check not run")
            return
        if not self.cfg.fetch_page:
            self._add("OK","Page Scan","Disabled"); return
        if not self._fetch_page():
            self._add("WARN","Page Scan","Could not fetch page"); return
        content = self._page_content or ""; soup = self._page_soup

        # JS execution patterns (high-confidence)
        for pattern, desc in JS_EXEC_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                self._add("MALICIOUS","Malicious JavaScript",desc,30); break

        # Hidden iframes
        if soup:
            iframes = soup.find_all("iframe")
            hidden  = [i for i in iframes if
                       ("display:none" in (i.get("style","") or "").replace(" ","") or
                        "visibility:hidden" in (i.get("style","") or "").replace(" ","") or
                        i.get("width")=="0" or i.get("height")=="0")]
            if hidden:
                self._add("MALICIOUS","Hidden iframes",f"{len(hidden)} hidden — drive-by technique",30)
            elif iframes:
                self._add("WARN","iframes Present",f"{len(iframes)} iframe(s)")

        # Phishing structural patterns
        phish = []
        for pattern, desc in PHISHING_STRUCTURAL:
            if re.search(pattern, content, re.IGNORECASE):
                phish.append(desc)
        if len(phish) >= 3:
            self._add("MALICIOUS","Phishing Page Structure"," | ".join(phish[:4]),35)
        elif phish:
            self._add("WARN","Possible Phishing Indicators"," | ".join(phish[:2]),12)

        # Brand impersonation in page content
        for pattern, desc in BRAND_IMPERSONATION:
            if re.search(pattern, content, re.IGNORECASE):
                self._add("MALICIOUS","Brand Impersonation in Content",desc,25); break

        # Forms submitting to external domain
        if soup:
            base = _registered(self.ext)
            for f in soup.find_all("form", action=True):
                action = f["action"]
                if action.startswith("http"):
                    fext = tldextract.extract(action)
                    if _registered(fext) and _registered(fext) != base:
                        self._add("MALICIOUS","Form Submits Externally",
                                  "Data -> {}".format(_registered(fext)),30); break

        # Meta refresh redirect
        if soup and soup.find("meta", attrs={"http-equiv": re.compile("refresh",re.I)}):
            self._add("WARN","Meta Refresh Redirect","Auto-redirect — phishing chain indicator",10)

        # Base64 blobs (payload delivery)
        b64 = len(re.findall(r'base64,[A-Za-z0-9+/]{100,}', content))
        if b64 >= 3:
            self._add("MALICIOUS","Multiple Base64 Blobs",f"{b64} blobs — possible payload delivery",20)
        elif b64:
            self._add("WARN","Base64 Content",f"{b64} base64 block(s)",5)

        # Suspicious external scripts
        if soup:
            scripts   = soup.find_all("script", src=True)
            mal_scripts = [s["src"] for s in scripts if
                          any(kw in s["src"].lower() for kw in
                              ["malware","exploit","inject","payload","shell","c2","botnet"])]
            if mal_scripts:
                self._add("MALICIOUS","Suspicious External Scripts",
                          f"Scripts: {', '.join(mal_scripts[:2])}",35)

        if not any(f["level"] in ("WARN","MALICIOUS") for f in self.findings
                   if f["check"] not in ("HTTPS","SSL/TLS","SSL Certificate","No HTTPS")):
            self._add("OK","Page Content","No malicious patterns detected")

    # ── Report ────────────────────────────────────────────────────────────────

    def is_allowlisted(self) -> bool:
        """True when the registered domain is on the trusted list."""
        reg = _registered(self.ext)
        return bool(reg) and reg in SAFE_DOMAINS

    def run(self, scope: str = "url") -> dict:
        if self.is_allowlisted():
            # The comment on SAFE_DOMAINS promised this and the code never did
            # it: every check still ran, spending API quota on known-good hosts.
            self._add("OK", "Allowlisted domain",
                      "{} is on the trusted-domain list; deeper checks skipped"
                      .format(_registered(self.ext)))
            return self.report()
        self.check_url_structure()
        self.check_ssl()
        self.check_reputation(scope=scope)
        self.check_page_content()
        return self.report()

    # Findings that are conclusive on their own (an external service or the
    # certificate chain actually said so), independent of accumulated score.
    CONCLUSIVE = {"Google Safe Browsing", "VirusTotal Detection", "PhishTank",
                  "SSL Certificate EXPIRED", "SSL Certificate Invalid"}

    def verdict(self) -> str:
        """Derive the verdict from accumulated evidence.

        Previously ANY warning produced SUSPICIOUS, so plain HTTP or two
        subdomains were enough — CLEAN was effectively unreachable and the
        0-100 score had no effect on the result.
        """
        for f in self.findings:
            if f["level"] == "MALICIOUS" and f["check"] in self.CONCLUSIVE:
                return "MALICIOUS"
        if self.score >= 60:
            return "MALICIOUS"
        if self.score >= 25:
            return "SUSPICIOUS"
        return "CLEAN"

    def scoring_basis(self) -> list:
        """The findings that contributed, so a score can be checked."""
        return [
            {"check": f["check"], "level": f["level"], "detail": f["detail"],
             "weight": f.get("weight", 0)}
            for f in self.findings if f.get("weight")
        ]

    def report(self) -> dict:
        return {
            "url": self.url,
            "timestamp": now_str(),
            "verdict": self.verdict(),
            "risk_score": self.score,
            "scoring_basis": self.scoring_basis(),
            "findings": self.findings,
            "external_enrichment_enabled": bool(self.cfg.allow_external),
            "limitations": [
                "Structure, entropy and TLS checks are local and deterministic.",
                "Reputation results are present only when a service was configured, "
                "enabled and reachable; otherwise the finding says NOT CHECKED.",
                "A CLEAN verdict means no indicator fired, not that the URL is safe.",
            ],
        }


# ═══════════════════════════════════════════════════════════════════════════════
# TERMINAL DISPLAY
# ═══════════════════════════════════════════════════════════════════════════════

def _print_report(report: dict) -> None:
    url     = report["url"]; verdict=report["verdict"]
    score   = report["risk_score"]; findings=report["findings"]
    vc = {"MALICIOUS": "bold red", "SUSPICIOUS": "bold yellow", "CLEAN": "bold green"}.get(verdict, "white")
    vi = {"MALICIOUS": "!", "SUSPICIOUS": "?", "CLEAN": "+"}.get(verdict, "-")
    console.rule("[bold]URL SCAN REPORT[/bold]")
    console.print(f"\n  [dim]URL    [/dim] {rescape(truncate(url,100))}")
    console.print(f"  [dim]Time   [/dim] {now_str()}")
    console.print(f"  [dim]Score  [/dim] {score}/100")
    console.print(f"  [dim]Verdict[/dim] [{vc}]{vi} {verdict}[/{vc}]\n")
    t=Table(box=box.SIMPLE_HEAVY,show_header=True,header_style="dim",padding=(0,1))
    t.add_column("STATUS",width=12); t.add_column("CHECK",width=30); t.add_column("DETAIL")
    im = {"OK": "[green]  OK[/green]", "INFO": "[cyan]  INFO[/cyan]",
          "WARN": "[yellow]  NOTABLE[/yellow]", "SUSPICIOUS": "[yellow]  SUSPICIOUS[/yellow]",
          "MALICIOUS": "[bold red]  DETECTED[/bold red]"}
    for f in findings:
        t.add_row(im.get(f["level"], f["level"]), rescape(str(f["check"])),
                  rescape(str(f["detail"])))
    console.print(t)
    mal = [f for f in findings if f["level"] in ("MALICIOUS", "SUSPICIOUS")]
    if mal:
        console.print(f"  [bold]Contributing indicators ({len(mal)}):[/bold]")
        for m in mal:
            console.print("  [yellow]  -[/yellow] {} (+{}): {}".format(
                rescape(str(m["check"])), m.get("weight", 0), rescape(str(m["detail"]))))
    console.print("[dim]"+"─"*100+"[/dim]\n")


def _generate_url_pdf_report(save_path: str, report: dict, session=None) -> str:
    title = "PACKETPULSE URL SCANNER REPORT"
    subtitle = "PacketPulse | Dreamwalker4u"
    summary = [
        "URL: {}".format(report.get("url", "")),
        "Timestamp: {}".format(report.get("timestamp", "")),
        "Verdict: {}".format(report.get("verdict", "")),
        "Risk score: {}/100 (sum of documented indicator weights)".format(report.get("risk_score", 0)),
        "External enrichment: {}".format(
            "enabled" if report.get("external_enrichment_enabled") else "DISABLED - local checks only"),
        "Findings recorded: {}".format(len(report.get("findings", []))),
    ]
    if session is not None:
        sd = session.to_dict()
        summary.insert(0, "Session ID: {}".format(sd["session_id"]))
        summary.append("Status: {}".format(sd["status"]))
    findings = [
        f"[{f['level']}] {f['check']}: {f['detail']}"
        for f in report.get('findings', [])
    ] or ["No findings"]
    basis = ["{} +{}: {}".format(b["check"], b["weight"], b["detail"])
             for b in report.get("scoring_basis", [])] or ["No indicator contributed to the score"]
    sections = [
        ("Summary", summary),
        ("Scoring basis", basis),
        ("All checks", findings),
        ("Limitations", report.get("limitations", []) or ["None recorded"]),
    ]
    return save_report_pdf(title, subtitle, sections, save_path)


# ═══════════════════════════════════════════════════════════════════════════════
# LIVE BROWSER INTERCEPTOR
# Reads /proc/net/tcp6 + /proc/net/tcp to find active browser connections
# and extracts destination IPs → reverse DNS → scan
# Also uses Scapy to capture SNI from TLS ClientHello (gets HTTPS domains)
# ═══════════════════════════════════════════════════════════════════════════════

_seen_urls: set = set()
_seen_domains: set = set()
_session_results: list = []
_session_lock = threading.Lock()

# Bounded scan pool. One thread per observed URL previously meant hundreds of
# concurrent threads on a busy link, each making external requests.
_SCAN_WORKERS = 4
_SCAN_QUEUE_MAX = 200
_scan_pool = None
_scan_stop = None
_scan_dropped = 0
_scan_inflight = 0


def _reset_live_state() -> None:
    global _scan_dropped, _scan_inflight
    with _session_lock:
        _seen_urls.clear()
        _seen_domains.clear()
        _session_results.clear()
        _scan_dropped = 0
        _scan_inflight = 0
    _rate_limiter.reset()


def _claim(collection: set, value: str) -> bool:
    """Atomic check-then-add. Prevents the same URL being scanned twice when
    two sources observe it at the same moment."""
    with _session_lock:
        if value in collection:
            return False
        if len(collection) > 20000:
            collection.clear()      # bounded: long watches must not grow forever
        collection.add(value)
        return True

# Browser process names
BROWSER_PROCESSES = {
    "chrome","chromium","firefox","mozilla","brave","opera","edge","msedge",
    "safari","epiphany","midori","konqueror","vivaldi","waterfox","librewolf",
}

def _get_browser_connections() -> list:
    """Established outbound connections owned by browser processes.

    Uses psutil.Process.net_connections(); the previous code requested a
    "connections" attribute from process_iter(), which raises ValueError on
    psutil >= 6 and was swallowed by a bare except, so this returned nothing
    at all on any current psutil.
    """
    conns = []
    try:
        import psutil
    except ImportError:
        return conns

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if not name or not any(b in name for b in BROWSER_PROCESSES):
                continue
            for c in proc.net_connections(kind="inet"):
                if c.raddr and c.status == "ESTABLISHED":
                    conns.append({
                        "pid": proc.pid,
                        "proc": proc.info.get("name") or "UNKNOWN",
                        "raddr": c.raddr.ip,
                        "rport": c.raddr.port,
                    })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except (AttributeError, OSError) as e:
            log.warning("connection enumeration failed for pid %s: %s", proc.pid, e)
            continue
    return conns


def _extract_sni_from_tls(payload: bytes) -> Optional[str]:
    """Extract SNI hostname from TLS ClientHello packet."""
    try:
        # TLS record: type=0x16 (handshake), version, length
        if len(payload) < 5 or payload[0] != 0x16: return None
        # Handshake type: 0x01 = ClientHello
        if len(payload) < 6 or payload[5] != 0x01: return None
        pos = 43  # skip fixed ClientHello header
        if len(payload) <= pos: return None
        # Session ID
        session_id_len = payload[pos]; pos += 1 + session_id_len
        if len(payload) <= pos+1: return None
        # Cipher suites
        cs_len = int.from_bytes(payload[pos:pos+2],"big"); pos += 2 + cs_len
        if len(payload) <= pos: return None
        # Compression methods
        cm_len = payload[pos]; pos += 1 + cm_len
        if len(payload) <= pos+1: return None
        # Extensions
        ext_total = int.from_bytes(payload[pos:pos+2],"big"); pos += 2
        end = pos + ext_total
        while pos + 4 <= end and pos + 4 <= len(payload):
            ext_type   = int.from_bytes(payload[pos:pos+2],"big"); pos += 2
            ext_len    = int.from_bytes(payload[pos:pos+2],"big"); pos += 2
            if ext_type == 0x0000:  # server_name
                # SNI list length
                entry_type = payload[pos+2]
                if entry_type == 0x00:  # host_name
                    name_len = int.from_bytes(payload[pos+3:pos+5],"big")
                    sni = payload[pos+5:pos+5+name_len].decode("utf-8",errors="replace")
                    return sni
            pos += ext_len
    except Exception: pass
    return None

def _extract_url_from_http(payload: bytes) -> Optional[str]:
    try:
        text = payload.decode("utf-8",errors="replace")
    except Exception:
        return None
    m = re.match(r"(GET|POST|PUT|DELETE|HEAD)\s+(\S+)\s+HTTP", text)
    if not m: return None
    path = m.group(2)
    hm = re.search(r"Host:\s*([^\r\n]+)", text)
    host = hm.group(1).strip() if hm else ""
    if not host: return None
    return f"http://{host}{path}"

def _extract_domain_from_dns(pkt) -> Optional[str]:
    try:
        from packetpulse.sensor.sensor import _dns_first
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            q = _dns_first(getattr(pkt[DNS], "qd", None))
            if q is not None:
                return q.qname.decode("utf-8", errors="replace").rstrip(".")
        return None
    except Exception:
        pass
    return None

def _scan_and_alert(url: str, source: str = "traffic", scope: str = "domain") -> None:
    """Queue a scan on the bounded pool. Never spawns an unbounded thread."""
    global _scan_dropped, _scan_inflight
    if _scan_pool is None:
        return
    with _session_lock:
        if _scan_inflight >= _SCAN_QUEUE_MAX:
            _scan_dropped += 1
            return
        _scan_inflight += 1
    try:
        _scan_pool.submit(_run_scan, url, source, scope)
    except RuntimeError:
        with _session_lock:
            _scan_inflight -= 1


def _run_scan(url: str, source: str, scope: str) -> None:
    global _scan_inflight
    try:
        if _scan_stop is not None and _scan_stop.is_set():
            return
        analyzer = URLAnalyzer(url)
        if analyzer.is_allowlisted():
            return
        analyzer.check_url_structure()
        analyzer.check_ssl()
        analyzer.check_reputation(scope=scope)
        report = analyzer.report()
        report["source"] = source

        verdict = report["verdict"]
        score = report["risk_score"]

        if verdict == "MALICIOUS":
            console.print("\n  [bold red]DETECTION[/bold red]  "
                          "[dim]score {}/100 via {}[/dim]".format(score, rescape(source)))
            console.print("  [red]URL:[/red] {}".format(rescape(truncate(url, 90))))
            contributors = [f for f in report["findings"]
                            if f["level"] in ("MALICIOUS", "SUSPICIOUS")]
            for m in contributors[:3]:
                console.print("    [red]-[/red] {} (+{}): {}".format(
                    rescape(str(m["check"])), m.get("weight", 0),
                    rescape(str(m["detail"]))))
            _desktop_alert(url, verdict, score,
                           [m["detail"] for m in contributors[:2]])
        elif verdict == "SUSPICIOUS":
            console.print("  [yellow]SUSPICIOUS[/yellow] {}  [dim](score {})[/dim]".format(
                rescape(truncate(url, 70)), score))

        cfg = get_config().urlscan
        try:
            ensure_dir(cfg.results_path)
            out = safe_output_path(cfg.results_path, "scan_", url, ".json")
            save_json(report, str(out))
        except (OSError, ValueError) as e:
            log.warning("could not save scan for %r: %s", url, e)

        with _session_lock:
            _session_results.append(report)
    except Exception as e:
        log.warning("scan failed for %r: %s: %s", url, type(e).__name__, e)
    finally:
        with _session_lock:
            _scan_inflight -= 1


def _live_packet_cb(pkt) -> None:
    """Extract observable URLs/domains from one packet. Nothing is invented:
    HTTP URLs come from real request lines, HTTPS yields only the SNI hostname,
    and DNS yields only the queried name."""
    try:
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw])
            url = _extract_url_from_http(raw)
            if url and _claim(_seen_urls, url):
                console.print("  [dim]HTTP  ->[/dim] [cyan]{}[/cyan]".format(
                    rescape(truncate(url, 80))))
                _scan_and_alert(url, "http-request", scope="url")
                return
            sni = _extract_sni_from_tls(raw)
            if sni and len(sni) > 3 and _claim(_seen_domains, sni):
                console.print("  [dim]TLS   ->[/dim] [cyan]{}[/cyan] "
                              "[dim](SNI only; payload encrypted)[/dim]".format(rescape(sni)))
                _scan_and_alert("https://{}".format(sni), "tls-sni", scope="domain")
                return

        domain = _extract_domain_from_dns(pkt)
        if domain and len(domain) > 3 and _claim(_seen_domains, domain):
            console.print("  [dim]DNS   ->[/dim] [magenta]{}[/magenta]".format(rescape(domain)))
            _scan_and_alert("http://{}".format(domain), "dns-query", scope="domain")
    except (AttributeError, IndexError, ValueError, UnicodeDecodeError) as e:
        log.warning("live extraction error: %s: %s", type(e).__name__, e)


def _browser_poll_loop(stop) -> None:
    """Poll browser processes for new destinations until stopped.

    Reverse DNS is the ONLY link from an address back to a name here, so when
    it fails the destination is recorded as its IP rather than guessed.
    """
    seen_conns = set()
    while not stop.is_set():
        try:
            for conn in _get_browser_connections():
                if stop.is_set():
                    return
                key = "{}:{}".format(conn["raddr"], conn["rport"])
                if key in seen_conns:
                    continue
                seen_conns.add(key)
                ip = conn["raddr"]
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror, OSError):
                    hostname = ""
                if not hostname:
                    # No name available: do not invent one.
                    continue
                if _claim(_seen_domains, hostname):
                    scheme = "https" if conn["rport"] == 443 else "http"
                    console.print("  [dim]BROWSER ({}) ->[/dim] [cyan]{}[/cyan]".format(
                        rescape(str(conn["proc"])), rescape(hostname)))
                    _scan_and_alert("{}://{}".format(scheme, hostname),
                                    "browser:{}".format(conn["proc"]), scope="domain")
        except Exception as e:
            log.warning("browser poll error: %s: %s", type(e).__name__, e)
        stop.wait(3.0)


def _generate_session_report(save_path: str, session) -> str:
    """Generate the HTML report for THIS live session. Observed values escaped."""
    sd = session.to_dict()
    ts_str = utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")
    results = list(_session_results)
    total   = len(results)
    mal     = [r for r in results if r["verdict"]=="MALICIOUS"]
    sus     = [r for r in results if r["verdict"]=="SUSPICIOUS"]
    clean   = [r for r in results if r["verdict"]=="CLEAN"]

    def badge(verdict):
        cfg = {"MALICIOUS":("#ff4444","#ff444422"),"SUSPICIOUS":("#f0e040","#f0e04022"),"CLEAN":("#39d353","#39d35322")}
        col,bg = cfg.get(verdict,("#888","#88888822"))
        return f"<span style='font-size:10px;padding:2px 8px;border-radius:3px;border:1px solid {col}44;background:{bg};color:{col};font-weight:700'>{verdict}</span>"

    rows = "".join(
        "<tr><td class='ts'>{}</td><td class='mono'>{}</td><td>{}</td>"
        "<td class='right'>{}/100</td><td class='dim'>{}</td></tr>".format(
            esc(r["timestamp"]), esc(truncate(r["url"], 80)), badge(r["verdict"]),
            esc(r["risk_score"]),
            esc("; ".join("{} (+{})".format(f["check"], f.get("weight", 0))
                          for f in r["findings"]
                          if f["level"] in ("MALICIOUS", "SUSPICIOUS"))[:90]) or "no indicators")
        for r in sorted(results, key=lambda x: x["risk_score"], reverse=True)
    ) or "<tr><td colspan='5' class='dim'>No URLs were observed in this session</td></tr>"

    meta_rows = "".join(
        "<tr><td class='mono'>{}</td><td>{}</td></tr>".format(esc(k), esc(v))
        for k, v in [("Session ID", sd["session_id"]), ("Status", sd["status"]),
                     ("Started", sd["started_at"]), ("Ended", sd["ended_at"]),
                     ("Measured capture", "{}s".format(sd["capture_duration_seconds"])),
                     ("URLs observed", len(_seen_urls)),
                     ("Domains observed", len(_seen_domains))]
    )
    limitation_rows = "".join("<tr><td>{}</td></tr>".format(esc(t))
                              for t in sd["limitations"]) or         "<tr><td class='dim'>None recorded</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>PacketPulse — URL Scanner Session Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#080808;color:#c8c8c8;font-family:'JetBrains Mono','Courier New',monospace;font-size:13px;line-height:1.6}}
.header{{background:#0a0a0f;border-bottom:2px solid #0f0f2a;padding:28px 40px}}
.t1{{font-size:26px;font-weight:700;color:#00ff41;letter-spacing:4px}}
.t2{{font-size:10px;color:#39d353;letter-spacing:2px;margin-top:3px}}
.by{{font-size:10px;color:#1a1a3a;margin-top:6px}}.by span{{color:#6060ff}}
.dw-badge{{display:inline-block;margin-top:8px;padding:4px 10px;border-radius:999px;border:1px solid #00d4ff55;background:#00d4ff1a;color:#8be9fd;font-size:9px;letter-spacing:1px;text-transform:uppercase}}
.stats{{display:flex;gap:12px;padding:16px 40px;border-bottom:1px solid #0f0f0f;flex-wrap:wrap}}
.sc{{background:#0d0d0d;border:1px solid #151515;border-radius:4px;padding:12px 20px;flex:1;min-width:90px}}
.sn{{font-size:26px;font-weight:700;line-height:1}}
.sl{{font-size:9px;color:#444;text-transform:uppercase;letter-spacing:1px;margin-top:3px}}
.body{{padding:28px 40px}}
.sh{{font-size:10px;color:#00d4ff;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px;padding-bottom:7px;border-bottom:1px solid #0f0f0f;display:flex;align-items:center;gap:8px}}
.sh::before{{content:'';width:3px;height:12px;background:#00d4ff;border-radius:1px;display:inline-block}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#0d0d0d;color:#444;font-size:9px;text-transform:uppercase;letter-spacing:1px;padding:7px 12px;text-align:left;border-bottom:1px solid #111}}
td{{padding:6px 12px;border-bottom:1px solid #0d0d0d;vertical-align:middle}}
tr:hover td{{background:#0d0d11}}
.ts{{color:#444;white-space:nowrap;font-size:11px}}
.mono{{font-size:11px}}
.dim{{color:#555;font-size:11px}}
.right{{text-align:right}}
.footer{{background:#050505;border-top:1px solid #0f0f0f;padding:16px 40px;display:flex;justify-content:space-between;margin-top:24px}}
.fb{{font-size:14px;font-weight:700;color:#00ff41;letter-spacing:2px}}
</style></head><body>
<div class="header">
  <div class="t1">PACKETPULSE</div>
  <div class="t2">URL SCANNER SESSION REPORT</div>
  <div class="by">by <span>Dreamwalker4u</span>  •  {ts_str}</div>
    <div class="dw-badge">Generated by Dreamwalker4u</div>
</div>
<div class="stats">
  <div class="sc"><div class="sn" style="color:#e8edf3">{total}</div><div class="sl">URLs Scanned</div></div>
  <div class="sc"><div class="sn" style="color:#ff4444">{len(mal)}</div><div class="sl">Malicious</div></div>
  <div class="sc"><div class="sn" style="color:#f0e040">{len(sus)}</div><div class="sl">Suspicious</div></div>
  <div class="sc"><div class="sn" style="color:#39d353">{len(clean)}</div><div class="sl">Clean</div></div>
  <div class="sc"><div class="sn" style="color:#c09ffd">{esc(len(_seen_domains))}</div><div class="sl">Domains Seen</div></div>
</div>
<div class="body">
  <div class="sh">All Scanned URLs — sorted by risk score</div>
  <table>
    <tr><th>Timestamp</th><th>URL</th><th>Verdict</th><th>Score</th><th>Threats</th></tr>
    {rows}
  </table>
</div>
<div class="body">
  <div class="sh">Session Provenance</div>
  <table><tr><th>Field</th><th>Value</th></tr>{meta_rows}</table>
</div>
<div class="body">
  <div class="sh">Limitations — what this report cannot establish</div>
  <table>{limitation_rows}</table>
</div>
<div class="footer">
  <div style="color:#222;font-size:11px">PacketPulse URL Scanner Session  •  {ts_str}</div>
  <div class="fb">PacketPulse | Dreamwalker4u</div>
</div>
</body></html>"""

    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    with open(save_path,"w",encoding="utf-8") as f: f.write(html)
    return save_path


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════════════════

def scan_url(url: str, session=None):
    """Scan a single URL supplied by the user. Returns the Session."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    cfg = get_config().urlscan
    session = session or Session(module="urlscan", interface="n/a")
    console.rule("[bold green]PACKETPULSE  >  URL SCANNER[/bold green]")
    console.print("  [dim]Target :[/dim] [cyan]{}[/cyan]".format(rescape(url)))
    console.print("  [dim]Session:[/dim] [cyan]{}[/cyan]".format(session.session_id))
    console.print("  [dim]External reputation:[/dim] {}".format(
        "[green]ENABLED[/green]" if cfg.allow_external
        else "[yellow]DISABLED[/yellow] [dim](local checks only)[/dim]"))
    console.print()

    session.begin_capture()
    a = URLAnalyzer(url)

    if a.is_allowlisted():
        console.print("  [dim]Domain is allowlisted; deeper checks skipped.[/dim]\n")
        report = a.run()
    else:
        console.print("  [dim][1/4] URL structure...[/dim]")
        a.check_url_structure()
        console.print("  [dim][2/4] TLS certificate...[/dim]")
        a.check_ssl()
        console.print("  [dim][3/4] Reputation...[/dim]")
        a.check_reputation(scope="url")
        console.print("  [dim][4/4] Page content...[/dim]\n")
        a.check_page_content()
        report = a.report()

    session.end_capture()
    _print_report(report)

    session.count("urls_scanned", 1)
    session.count("indicators", len(report.get("scoring_basis", [])))
    for lim in report.get("limitations", []):
        session.note_limitation(lim)
    if not cfg.allow_external:
        session.record_unavailable(
            "External reputation",
            "disabled by configuration; VirusTotal/Safe Browsing/PhishTank were not queried")
    session.finish(completed=True)

    if report["verdict"] == "MALICIOUS":
        _desktop_alert(url, report["verdict"], report["risk_score"],
                       [f["detail"] for f in report["findings"]
                        if f["level"] == "MALICIOUS"][:2])

    try:
        ensure_dir(cfg.results_path)
        out = safe_output_path(cfg.results_path, "scan_", url, ".json")
        save_json({"session": session.to_dict(), "report": report}, str(out))
        console.print("  [dim]JSON ->[/dim] [cyan]{}[/cyan]".format(out))
        pdf_out = str(out).replace(".json", ".pdf")
        try:
            _generate_url_pdf_report(pdf_out, report, session)
            console.print("  [dim]PDF  ->[/dim] [cyan]{}[/cyan]\n".format(pdf_out))
        except (OSError, ValueError, RuntimeError) as e:
            session.record_error("url_pdf", e)
            console.print("  [yellow]PDF report FAILED: {}[/yellow]\n".format(e))
    except (OSError, ValueError) as e:
        session.record_error("url_save", e)
        console.print("  [red]Could not save report: {}[/red]".format(e))

    return session


def run_live_urlscan(interface=None, duration: int = 0, stop=None, session=None):
    """Watch live traffic and scan observed URLs/domains.

    Honours `duration` and `stop`, drains its worker pool, and returns only
    after every scan thread has finished.
    """
    global _scan_pool, _scan_stop

    _user_iface = bool(interface)
    stop = stop or StopController()
    _scan_stop = stop
    duration = int(duration or 0)
    interface = interface or capabilities.default_route_interface()
    cfg = get_config().urlscan
    session = session or Session(
        module="urlscan-live",
        requested_duration=duration,
        interface=str(interface or "default"),
        bpf_filter="tcp port 80 or tcp port 443 or udp port 53",
    )

    if not SCAPY_OK:
        reason = SCAPY_UNAVAILABLE_REASON or "scapy is not installed"
        session.record_unavailable("Live URL capture", reason)
        session.finish(completed=False, abort_reason=reason)
        console.print("[red]Live URL capture UNAVAILABLE:[/red] " + reason)
        return session

    cap = capabilities.probe_capture()
    if not cap.available:
        session.record_unavailable("Live URL capture", cap.reason)
        session.finish(completed=False, abort_reason=cap.reason)
        console.print("[red]Live URL capture UNAVAILABLE:[/red] " + cap.reason)
        return session

    # Load the capture backend before resolving/using a named interface.
    _load_secs = capabilities.ensure_capture_backend(interface)
    if _load_secs > 5:
        console.print("  [dim]Capture engine loaded in %.1fs (full adapter "
                      "enumeration was required).[/dim]" % _load_secs)

    ok, detail = capabilities.resolve_interface(interface)
    if not ok:
        if _user_iface:
            # The user named this interface explicitly; do not silently
            # capture somewhere else.
            session.record_unavailable("Capture interface", detail)
            session.finish(completed=False, abort_reason=detail)
            console.print("[red]CANNOT START:[/red] " + detail)
            return session
        # Auto-detected interface is not resolvable by the capture backend
        # (observed on Linux, where the routing interface may not appear in
        # scapy's list). Fall back to the platform default and say so, rather
        # than refusing to run.
        console.print("  [yellow]Auto-detected interface unusable:[/yellow] " + detail)
        console.print("  [dim]Falling back to the platform default interface.[/dim]")
        session.note_limitation(
            "Auto-detected interface %r could not be opened (%s); the platform "
            "default was used instead, so the captured traffic may differ from "
            "the routed path." % (interface, detail))
        interface = None
        session.interface = "platform default"


    _reset_live_state()
    ensure_dir(cfg.results_path)

    _compat = scapy_compat.COMPAT_NOTE
    if _compat:
        session.note_limitation(_compat)
    session.note_limitation(capabilities.interface_note(interface))
    session.note_limitation(
        "HTTPS traffic yields the SNI hostname only. Paths, headers and content "
        "are encrypted and are NOT decrypted.")
    session.note_limitation(
        "Only the registered domain is sent to external services in live mode, "
        "and only when external enrichment is enabled.")
    if not cfg.allow_external:
        session.record_unavailable(
            "External reputation",
            "disabled by configuration; live scans used local checks only")

    _scan_pool = ThreadPoolExecutor(max_workers=_SCAN_WORKERS, thread_name_prefix="pp-scan")

    console.rule("[bold green]PACKETPULSE  >  LIVE URL WATCHER[/bold green]")
    console.print("  [dim]Session:[/dim] [cyan]{}[/cyan]  [dim]Interface:[/dim] [green]{}[/green]  "
                  "[dim]Duration:[/dim] [yellow]{}[/yellow]".format(
                      session.session_id, interface or "default",
                      "{}s".format(duration) if duration else "until stopped"))
    console.print("  [dim]Sources: HTTP request lines, TLS SNI, DNS queries, browser sockets[/dim]")
    console.print("  [dim]External reputation: {}[/dim]".format(
        "ENABLED (registered domain only)" if cfg.allow_external else "DISABLED"))
    console.print("[dim]" + "-" * 100 + "[/dim]")

    poll = threading.Thread(target=_browser_poll_loop, args=(stop,),
                            name="pp-browser-poll", daemon=False)
    poll.start()

    aborted = ""
    session.begin_capture()
    try:
        sniff(
            iface=interface or None,
            filter="tcp port 80 or tcp port 443 or udp port 53",
            prn=_live_packet_cb,
            store=False,
            timeout=duration if duration > 0 else None,
            stop_filter=lambda _p: stop.is_set(),
        )
    except KeyboardInterrupt:
        console.print("\n  [yellow]Interrupted - finishing cleanly...[/yellow]")
    except ValueError as e:
        aborted = "interface error: {}".format(e)
        session.record_error("sniff_iface", e)
    except PermissionError as e:
        aborted = "insufficient privilege for live capture: {}".format(e)
        session.record_error("sniff", e)
    except OSError as e:
        aborted = "capture failed: {}".format(e)
        session.record_error("sniff", e)
    finally:
        session.end_capture()
        stop.stop()
        poll.join(timeout=6)
        if poll.is_alive():
            session.record_error("poll_join", "browser poll thread did not stop within 6s")
        pool, _scan_pool = _scan_pool, None
        if pool is not None:
            console.print("  [dim]Waiting for in-flight scans...[/dim]")
            pool.shutdown(wait=True, cancel_futures=True)

    session.count("urls_observed", len(_seen_urls))
    session.count("domains_observed", len(_seen_domains))
    session.count("scans_completed", len(_session_results))
    if _scan_dropped:
        session.count("scans_dropped_queue_full", _scan_dropped)
        session.note_limitation(
            "{} observations were dropped because the scan queue was full; they "
            "were seen but not analysed.".format(_scan_dropped))
    session.finish(completed=not aborted, abort_reason=aborted)

    if aborted:
        console.print("\n[red]LIVE CAPTURE FAILED:[/red] " + aborted)
        return session

    console.print("\n[green]Stopped.[/green]  {}".format(session.summary_line()))
    if not _session_results:
        console.print("  [yellow]No URLs or domains were observed in this window.[/yellow]")

    _write_urlscan_reports(session, cfg)
    return session


def _write_urlscan_reports(session, cfg) -> None:
    """Write live-session artifacts for THIS session only."""
    stamp = timestamp_filename()
    base = Path(cfg.results_path)
    ensure_dir(cfg.results_path)
    sd = session.to_dict()

    try:
        html_path = str(base / "urlscan_session_{}.html".format(stamp))
        _generate_session_report(html_path, session)
        console.print("  [dim]HTML ->[/dim] [cyan]{}[/cyan]".format(html_path))
    except (OSError, ValueError, KeyError) as e:
        session.record_error("urlscan_html", e)
        console.print("  [red]HTML report FAILED:[/red] {}".format(e))

    try:
        json_path = str(base / "urlscan_session_{}.json".format(stamp))
        save_json({
            "session": sd,
            "capabilities_unavailable": capabilities.unavailable_features(),
            "domains_observed": sorted(_seen_domains),
            "urls_observed": sorted(_seen_urls),
            "scans": _session_results,
        }, json_path)
        console.print("  [dim]JSON ->[/dim] [cyan]{}[/cyan]".format(json_path))
    except (OSError, TypeError) as e:
        session.record_error("urlscan_json", e)

    try:
        pdf_path = str(base / "urlscan_session_{}.pdf".format(stamp))
        save_report_pdf(
            "PACKETPULSE URL SCANNER SESSION",
            "Session {}".format(sd["session_id"]),
            [
                ("Session", [
                    "Session ID: {}".format(sd["session_id"]),
                    "Status: {}".format(sd["status"]),
                    "Started: {}".format(sd["started_at"]),
                    "Ended: {}".format(sd["ended_at"]),
                    "Measured capture: {}s".format(sd["capture_duration_seconds"]),
                    "URLs observed: {}".format(len(_seen_urls)),
                    "Domains observed: {}".format(len(_seen_domains)),
                    "Scans completed: {}".format(len(_session_results)),
                ]),
                ("Limitations", sd["limitations"] or ["None recorded"]),
                ("Unavailable", ["{}: {}".format(u["feature"], u["reason"])
                                 for u in sd["unavailable_features"]] or ["Nothing unavailable"]),
                ("Results", [
                    "{}/100 {} [{}]".format(r["risk_score"], truncate(r["url"], 70), r["verdict"])
                    for r in sorted(_session_results,
                                    key=lambda x: x["risk_score"], reverse=True)[:25]
                ] or ["No URLs scanned"]),
            ],
            pdf_path,
        )
        console.print("  [dim]PDF  ->[/dim] [cyan]{}[/cyan]".format(pdf_path))
    except (OSError, ValueError, RuntimeError) as e:
        session.record_error("urlscan_pdf", e)
