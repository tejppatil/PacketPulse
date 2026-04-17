"""
PacketPulse — URL Scanner v2
• Single URL: 4-check deep analysis with dataset-backed verdicts
• Live mode:  intercepts every URL from ALL browsers via /proc/net/tcp
              (works even on HTTPS — reads SNI from socket state)
              Instant desktop popup alert on MALICIOUS detection
              Final session report generated on exit
"""
from __future__ import annotations

import re, json, hashlib, threading, socket, ssl, time, subprocess, os
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

import requests, tldextract
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich import box

from packetpulse.core.config import get_config
from packetpulse.core.logger import get_logger
from packetpulse.utils.helpers import (
    shannon_entropy, save_json, ensure_dir, now_str, truncate, md5,
    timestamp_filename, save_report_pdf
)

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, Ether
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

console = Console()
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

def _desktop_alert(url: str, verdict: str, score: int, reasons: list[str]) -> None:
    """Fire a desktop notification for malicious URL detections."""
    title = "⚠ PacketPulse — MALICIOUS URL DETECTED"
    short_url = url[:70] + "..." if len(url) > 70 else url
    body = (
        f"URL: {short_url}\n"
        f"Risk Score: {score}/100\n"
        f"Verdict: {verdict}\n"
        f"Reason: {reasons[0] if reasons else 'Multiple threat indicators'}"
    )
    try:
        platform = os.uname().sysname if hasattr(os, "uname") else "Unknown"
        if platform == "Linux":
            subprocess.Popen(
                ["notify-send", "--urgency=critical", "--icon=dialog-warning",
                 "--app-name=PacketPulse", title, body],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        elif platform == "Darwin":
            script = f'display notification "{body}" with title "{title}" sound name "Basso"'
            subprocess.Popen(["osascript", "-e", script],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif os.name == "nt":
            ps_script = (
                f"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null;"
                f"$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
                f"$xml.GetElementsByTagName('text')[0].AppendChild($xml.CreateTextNode('{title}')) | Out-Null;"
                f"$xml.GetElementsByTagName('text')[1].AppendChild($xml.CreateTextNode('{body[:100]}')) | Out-Null;"
                f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('PacketPulse').Show([Windows.UI.Notifications.ToastNotification]::new($xml))"
            )
            subprocess.Popen(["powershell", "-Command", ps_script],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log.debug(f"Desktop alert failed: {e}")


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
        self.url    = url.strip()
        self.parsed = urlparse(self.url)
        self.ext    = tldextract.extract(self.url)
        self.cfg    = get_config().urlscan
        self.findings: list[dict] = []
        self.score  = 0
        self._page_content: Optional[str] = None
        self._page_soup:    Optional[BeautifulSoup] = None
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; PacketPulse/1.0)"})

    def _add(self, level: str, check: str, detail: str, score: int = 0) -> None:
        self.findings.append({"level": level, "check": check, "detail": detail})
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
        domain_lower = (ext.domain + "." + ext.suffix).lower()
        registered = ext.registered_domain or ""
        for brand in PHISH_BRAND_KEYWORDS:
            if brand in domain_lower and registered != f"{brand}.com":
                real_domains = {f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.co.uk"}
                if registered not in real_domains:
                    self._add("MALICIOUS", "Brand Impersonation",
                              f"'{brand}' in domain — phishing brand spoofing", 30)
                    break

        # Malware-related keywords
        full_url_lower = url.lower()
        mal_kw = [k for k in MALWARE_KEYWORDS if k in full_url_lower]
        if mal_kw:
            self._add("MALICIOUS", "Malware-Related Keywords",
                      f"Found: {', '.join(mal_kw[:3])}", 25)

        # Suspicious keywords (multiple = higher score)
        sus_kw = [k for k in SUSPICIOUS_KEYWORDS if k in domain_lower]
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
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days = (expiry - datetime.utcnow()).days
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

    def check_reputation(self) -> None:
        domain = self.ext.registered_domain or self.parsed.hostname or ""
        if not domain:
            return

        if domain in SAFE_DOMAINS:
            self._add("OK", "Domain Reputation", f"{domain} is a trusted domain")

        vt_key = self.cfg.virustotal_api_key
        if vt_key:
            try:
                headers = {"x-apikey": vt_key}
                r = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": self.url},
                    timeout=self.cfg.request_timeout,
                )
                if r.status_code == 200:
                    scan_id = r.json().get("data", {}).get("id", "")
                    if scan_id:
                        time.sleep(1)
                        r2 = requests.get(
                            f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
                            headers=headers,
                            timeout=self.cfg.request_timeout,
                        )
                        if r2.status_code == 200:
                            stats = r2.json().get("data", {}).get("attributes", {}).get("stats", {})
                            mal = stats.get("malicious", 0)
                            total = sum(stats.values())
                            if total > 0:
                                if mal > 0:
                                    self._add("MALICIOUS", "VirusTotal Detection",
                                              f"{mal}/{total} engines flagged", 40)
                                else:
                                    self._add("OK", "VirusTotal", f"0/{total} engines flagged")
                            else:
                                self._add("WARN", "VirusTotal", "No detection stats returned")
                elif r.status_code == 429:
                    self._add("WARN", "VirusTotal", "Rate limit — try again later")
                else:
                    self._add("WARN", "VirusTotal", f"Status {r.status_code}")
            except Exception as e:
                self._add("WARN", "VirusTotal", f"Skipped: {str(e)[:50]}")
        else:
            self._add("OK", "VirusTotal", "No API key (set PACKETPULSE_VT_KEY)")

        gsb_key = self.cfg.google_safebrowsing_key
        if gsb_key:
            try:
                payload = {
                    "client": {"clientId": "packetpulse", "clientVersion": "1.0.2"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": self.url}],
                    },
                }
                r = requests.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}",
                    json=payload,
                    timeout=self.cfg.request_timeout,
                )
                if r.status_code == 200:
                    matches = r.json().get("matches", [])
                    if matches:
                        self._add("MALICIOUS", "Google Safe Browsing",
                                  f"FLAGGED — {matches[0].get('threatType', 'UNKNOWN')}", 45)
                    else:
                        self._add("OK", "Google Safe Browsing", "Not flagged")
                else:
                    self._add("WARN", "Google Safe Browsing", f"Status {r.status_code}")
            except Exception as e:
                self._add("WARN", "Google Safe Browsing", f"Check failed: {str(e)[:40]}")
        else:
            self._add("OK", "Google Safe Browsing", "No API key (set PACKETPULSE_GSB_KEY)")

        try:
            r = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": self.url, "format": "json"},
                timeout=self.cfg.request_timeout,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("results", {}).get("in_database") and data.get("results", {}).get("valid"):
                    self._add("MALICIOUS", "PhishTank", "Listed as known phishing page", 45)
                else:
                    self._add("OK", "PhishTank", "Not listed")
            else:
                self._add("WARN", "PhishTank", f"Status {r.status_code}")
        except Exception:
            self._add("WARN", "PhishTank", "Service unavailable")

    # ── Check 4: Page content ─────────────────────────────────────────────────

    def _fetch_page(self) -> bool:
        if self._page_content is not None: return bool(self._page_content)
        try:
            r = requests.get(self.url, timeout=self.cfg.request_timeout,
                             headers={"User-Agent":"Mozilla/5.0 (compatible; PacketPulse/1.0)"},
                             verify=False, allow_redirects=True)
            self._page_content = r.text
            self._page_soup    = BeautifulSoup(r.text,"lxml")
            return True
        except:
            self._page_content = ""; return False

    def check_page_content(self) -> None:
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
            base = self.ext.registered_domain
            for f in soup.find_all("form", action=True):
                action = f["action"]
                if action.startswith("http"):
                    fext = tldextract.extract(action)
                    if fext.registered_domain and fext.registered_domain != base:
                        self._add("MALICIOUS","Form Submits Externally",
                                  f"Data → {fext.registered_domain}",30); break

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

    def run(self) -> dict:
        self.check_url_structure()
        self.check_ssl()
        self.check_reputation()
        self.check_page_content()
        return self.report()

    def verdict(self) -> str:
        levels = [f["level"] for f in self.findings]
        if "MALICIOUS" in levels: return "MALICIOUS"
        if "WARN"      in levels: return "SUSPICIOUS"
        return "CLEAN"

    def report(self) -> dict:
        return {"url":self.url,"timestamp":now_str(),"verdict":self.verdict(),
                "risk_score":self.score,"findings":self.findings}


# ═══════════════════════════════════════════════════════════════════════════════
# TERMINAL DISPLAY
# ═══════════════════════════════════════════════════════════════════════════════

def _print_report(report: dict) -> None:
    url     = report["url"]; verdict=report["verdict"]
    score   = report["risk_score"]; findings=report["findings"]
    vc      = {"MALICIOUS":"bold red","SUSPICIOUS":"bold yellow","CLEAN":"bold green"}[verdict]
    vi      = {"MALICIOUS":"✗","SUSPICIOUS":"⚠","CLEAN":"✓"}[verdict]
    console.rule("[bold]URL SCAN REPORT[/bold]")
    console.print(f"\n  [dim]URL    [/dim] {truncate(url,100)}")
    console.print(f"  [dim]Time   [/dim] {now_str()}")
    console.print(f"  [dim]Score  [/dim] {score}/100")
    console.print(f"  [dim]Verdict[/dim] [{vc}]{vi} {verdict}[/{vc}]\n")
    t=Table(box=box.SIMPLE_HEAVY,show_header=True,header_style="dim",padding=(0,1))
    t.add_column("STATUS",width=12); t.add_column("CHECK",width=30); t.add_column("DETAIL")
    im={"OK":"[green]  ✓ OK[/green]","WARN":"[yellow]  ⚠ WARN[/yellow]","MALICIOUS":"[bold red]  ✗ MALICIOUS[/bold red]"}
    for f in findings: t.add_row(im[f["level"]],f["check"],f["detail"])
    console.print(t)
    mal=[f for f in findings if f["level"]=="MALICIOUS"]
    if mal:
        console.print(f"  [bold red]THREATS ({len(mal)}):[/bold red]")
        for m in mal: console.print(f"  [red]  ✗  {m['check']}:[/red] {m['detail']}")
    console.print("[dim]"+"─"*100+"[/dim]\n")


def _generate_url_pdf_report(save_path: str, report: dict) -> str:
    title = "PACKETPULSE URL SCANNER REPORT"
    subtitle = "PacketPulse | Dreamwalker4u"
    summary = [
        f"URL: {report.get('url','')}",
        f"Timestamp: {report.get('timestamp','')}",
        f"Verdict: {report.get('verdict','')}",
        f"Risk score: {report.get('risk_score',0)}/100",
        f"Findings: {len(report.get('findings',[]))} items",
    ]
    findings = [
        f"[{f['level']}] {f['check']}: {f['detail']}"
        for f in report.get('findings', [])
    ] or ["No findings"]
    sections = [
        ("Summary", summary),
        ("Findings", findings),
    ]
    return save_report_pdf(title, subtitle, sections, save_path)


# ═══════════════════════════════════════════════════════════════════════════════
# LIVE BROWSER INTERCEPTOR
# Reads /proc/net/tcp6 + /proc/net/tcp to find active browser connections
# and extracts destination IPs → reverse DNS → scan
# Also uses Scapy to capture SNI from TLS ClientHello (gets HTTPS domains)
# ═══════════════════════════════════════════════════════════════════════════════

_seen_urls:    set[str] = set()
_seen_domains: set[str] = set()
_session_results: list[dict] = []
_session_lock = threading.Lock()

# Browser process names
BROWSER_PROCESSES = {
    "chrome","chromium","firefox","mozilla","brave","opera","edge","msedge",
    "safari","epiphany","midori","konqueror","vivaldi","waterfox","librewolf",
}

def _get_browser_connections() -> list[dict]:
    """Read /proc/net/tcp to find active browser outbound connections."""
    conns = []
    try:
        import psutil
        for proc in psutil.process_iter(["pid","name","connections"]):
            try:
                name = proc.info["name"].lower() if proc.info["name"] else ""
                if not any(b in name for b in BROWSER_PROCESSES): continue
                for c in proc.connections(kind="inet"):
                    if c.raddr and c.status == "ESTABLISHED":
                        conns.append({
                            "pid":   proc.pid,
                            "proc":  proc.info["name"],
                            "raddr": c.raddr.ip,
                            "rport": c.raddr.port,
                        })
            except Exception: continue
    except Exception: pass
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
                list_len = int.from_bytes(payload[pos:pos+2],"big")
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
    except: return None
    m = re.match(r"(GET|POST|PUT|DELETE|HEAD)\s+(\S+)\s+HTTP", text)
    if not m: return None
    path = m.group(2)
    hm = re.search(r"Host:\s*([^\r\n]+)", text)
    host = hm.group(1).strip() if hm else ""
    if not host: return None
    return f"http://{host}{path}"

def _extract_domain_from_dns(pkt) -> Optional[str]:
    try:
        if pkt.haslayer(DNS) and pkt[DNS].qr==0 and pkt[DNS].qdcount>0:
            return pkt[DNS].qd.qname.decode("utf-8",errors="replace").rstrip(".")
    except: pass
    return None

def _scan_and_alert(url: str, source: str = "traffic") -> None:
    """Run scan in background thread. Desktop alert if malicious."""
    def _run():
        try:
            analyzer = URLAnalyzer(url)
            analyzer.check_url_structure()
            analyzer.check_ssl()
            analyzer.check_reputation()
            report = analyzer.report()
            verdict = report["verdict"]
            score   = report["risk_score"]

            if verdict == "MALICIOUS":
                # Immediate terminal alert
                console.print(f"\n[bold red]  ╔═══════════════════════════════════════════╗[/bold red]")
                console.print(f"[bold red]  ║  ⚠  MALICIOUS URL DETECTED               ║[/bold red]")
                console.print(f"[bold red]  ║  Score: {score}/100  •  Source: {source[:20]:<20}  ║[/bold red]")
                console.print(f"[bold red]  ╚═══════════════════════════════════════════╝[/bold red]")
                console.print(f"  [red]URL:[/red] {truncate(url,90)}")
                mal = [f for f in report["findings"] if f["level"]=="MALICIOUS"]
                for m in mal[:3]:
                    console.print(f"  [red]  ✗  {m['check']}:[/red] {m['detail']}")
                console.print()
                # Desktop popup
                reasons = [m["detail"] for m in mal[:2]]
                _desktop_alert(url, verdict, score, reasons)

            elif verdict == "SUSPICIOUS" and score >= 20:
                console.print(f"\n  [yellow]⚠  SUSPICIOUS:[/yellow] {truncate(url,70)}  [dim](score:{score})[/dim]")
                for w in [f for f in report["findings"] if f["level"]=="WARN"][:2]:
                    console.print(f"  [yellow]  ⚠  {w['check']}:[/yellow] {w['detail']}")

            cfg = get_config().urlscan
            fname = f"{cfg.results_path}/{md5(url)}.json"
            save_json(report, fname)
            with _session_lock:
                _session_results.append(report)

        except Exception as e:
            log.debug(f"Scan error for {url}: {e}")

    threading.Thread(target=_run, daemon=True).start()

def _live_packet_cb(pkt) -> None:
    # HTTP from raw payload
    if pkt.haslayer(Raw):
        raw = bytes(pkt[Raw])
        url = _extract_url_from_http(raw)
        if url and url not in _seen_urls:
            _seen_urls.add(url)
            console.print(f"  [dim]↳ HTTP:[/dim] [cyan]{truncate(url,80)}[/cyan]")
            _scan_and_alert(url, "HTTP")
            return
        # TLS SNI (gets HTTPS domains)
        sni = _extract_sni_from_tls(raw)
        if sni and sni not in _seen_domains and len(sni) > 3:
            _seen_domains.add(sni)
            sni_url = f"https://{sni}"
            if sni_url not in _seen_urls:
                _seen_urls.add(sni_url)
                console.print(f"  [dim]↳ TLS SNI:[/dim] [cyan]{sni}[/cyan]")
                _scan_and_alert(sni_url, "TLS SNI")
    # DNS queries
    domain = _extract_domain_from_dns(pkt)
    if domain and domain not in _seen_domains and len(domain) > 3:
        _seen_domains.add(domain)
        url = f"http://{domain}"
        if url not in _seen_urls:
            _seen_urls.add(url)
            console.print(f"  [dim]↳ DNS:[/dim] [magenta]{domain}[/magenta]")
            _scan_and_alert(url, "DNS")

def _browser_poll_loop() -> None:
    """Poll psutil every 3s for new browser connections (catches HTTPS without decryption)."""
    seen_connections: set[str] = set()
    while True:
        try:
            for conn in _get_browser_connections():
                key = f"{conn['raddr']}:{conn['rport']}"
                if key in seen_connections: continue
                seen_connections.add(key)
                ip = conn["raddr"]
                # Reverse DNS to get domain
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    if hostname and hostname not in _seen_domains:
                        _seen_domains.add(hostname)
                        scheme = "https" if conn["rport"] == 443 else "http"
                        url = f"{scheme}://{hostname}"
                        if url not in _seen_urls:
                            _seen_urls.add(url)
                            console.print(f"  [dim]↳ Browser ({conn['proc']}):[/dim] [cyan]{hostname}[/cyan]")
                            _scan_and_alert(url, f"browser:{conn['proc']}")
                except: pass
        except: pass
        time.sleep(3)


def _generate_session_report(save_path: str) -> str:
    """Generate final HTML report for the live scan session."""
    ts_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
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
        f"<tr>"
        f"<td class='ts'>{r['timestamp']}</td>"
        f"<td class='mono'>{truncate(r['url'],80)}</td>"
        f"<td>{badge(r['verdict'])}</td>"
        f"<td class='right'>{r['risk_score']}/100</td>"
        f"<td class='dim'>{', '.join(f['check'] for f in r['findings'] if f['level']=='MALICIOUS')[:60]}</td>"
        f"</tr>"
        for r in sorted(results, key=lambda x: x['risk_score'], reverse=True)
    ) or "<tr><td colspan='5' class='dim'>No URLs scanned</td></tr>"

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
  <div class="sc"><div class="sn" style="color:#c09ffd">{len(_seen_domains)}</div><div class="sl">Domains Seen</div></div>
</div>
<div class="body">
  <div class="sh">All Scanned URLs — sorted by risk score</div>
  <table>
    <tr><th>Timestamp</th><th>URL</th><th>Verdict</th><th>Score</th><th>Threats</th></tr>
    {rows}
  </table>
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

def scan_url(url: str) -> None:
    if not url.startswith("http"): url = "http://" + url
    console.rule("[bold green]PACKETPULSE  ›  URL SCANNER[/bold green]")
    console.print(f"  [dim]Target:[/dim] [cyan]{url}[/cyan]")
    console.print(f"  [dim]Checks:[/dim] URL structure + dataset · SSL/TLS · Reputation · Page content\n")
    console.print("  [dim]  [1/4] URL structure + threat datasets...[/dim]")
    a = URLAnalyzer(url); a.check_url_structure()
    console.print("  [dim]  [2/4] SSL/TLS certificate...[/dim]"); a.check_ssl()
    console.print("  [dim]  [3/4] Reputation (VirusTotal / PhishTank / GSB)...[/dim]"); a.check_reputation()
    console.print("  [dim]  [4/4] Page content scan...[/dim]\n"); a.check_page_content()
    report = a.report(); _print_report(report)
    # Desktop alert for malicious
    if report["verdict"] == "MALICIOUS":
        reasons = [f["detail"] for f in report["findings"] if f["level"]=="MALICIOUS"][:2]
        _desktop_alert(url, report["verdict"], report["risk_score"], reasons)
    cfg = get_config().urlscan; ensure_dir(cfg.results_path)
    fname = f"{cfg.results_path}/{md5(url)}.json"
    save_json(report, fname)
    console.print(f"  [dim]Report saved →[/dim] [cyan]{fname}[/cyan]")
    pdf_path = f"{cfg.results_path}/{md5(url)}.pdf"
    try:
        _generate_url_pdf_report(pdf_path, report)
        console.print(f"  [dim]PDF saved    →[/dim] [cyan]{pdf_path}[/cyan]\n")
    except Exception as e:
        console.print(f"  [yellow]PDF report skipped: {e}[/yellow]\n")


def run_live_urlscan(interface: Optional[str] = None) -> None:
    if not SCAPY_OK: console.print("[red]ERROR: scapy not installed.[/red]"); return
    cfg = get_config().urlscan; ensure_dir(cfg.results_path)
    _seen_urls.clear(); _seen_domains.clear(); _session_results.clear()

    console.rule("[bold green]PACKETPULSE  ›  LIVE URL WATCHER[/bold green]")
    console.print(
        "  [dim]Intercepts URLs from:[/dim]\n"
        "    [dim]•[/dim] All browser processes (Chrome/Firefox/Brave/Edge/Safari/...)\n"
        "    [dim]•[/dim] HTTP packet payloads (port 80)\n"
        "    [dim]•[/dim] TLS SNI extraction (port 443 — gets HTTPS domains without decryption)\n"
        "    [dim]•[/dim] DNS queries (every domain lookup)\n"
        "  [dim]Alerts:[/dim] Instant terminal + desktop popup on MALICIOUS detection\n"
        "  [dim]Report:[/dim] Full HTML session report generated on exit\n"
    )
    console.print("[dim]"+"─"*100+"[/dim]")
    console.print("  [dim]Watching all traffic... browse normally.[/dim]\n")

    # Start browser connection poller (catches HTTPS by process inspection)
    poll_t = threading.Thread(target=_browser_poll_loop, daemon=True)
    poll_t.start()

    try:
        sniff(
            iface=interface or None,
            filter="tcp port 80 or tcp port 443 or udp port 53",
            prn=_live_packet_cb,
            store=False,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        console.print("[red]ERROR: Requires root/sudo.[/red]"); return
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]"); return

    console.print(f"\n[green]Session ended.[/green]  URLs scanned: {len(_session_results)}  Domains seen: {len(_seen_domains)}")

    # Generate session report
    console.print("\n[dim]Generating session report...[/dim]")
    rpath = f"{cfg.results_path}/urlscan_session_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
    try:
        out = _generate_session_report(rpath)
        console.print(f"\n[bold green]╔═══════════════════════════════════════════════════╗[/bold green]")
        console.print(f"[bold green]║  SESSION REPORT  —  PacketPulse | Dreamwalker4u  ║[/bold green]")
        console.print(f"[bold green]╚═══════════════════════════════════════════════════╝[/bold green]")
        console.print(f"  [dim]HTML →[/dim] [bold cyan]{out}[/bold cyan]")
        pdf_path = rpath.replace(".html", ".pdf")
        try:
            save_report_pdf(
                "PACKETPULSE URL SCANNER SESSION REPORT",
                "PacketPulse | Dreamwalker4u",
                [
                    ("Summary", [
                        f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                        f"URLs scanned: {len(_session_results)}",
                        f"Domains seen: {len(_seen_domains)}",
                        f"Malicious: {len([r for r in _session_results if r['verdict'] == 'MALICIOUS'])}",
                        f"Suspicious: {len([r for r in _session_results if r['verdict'] == 'SUSPICIOUS'])}",
                    ]),
                    ("Top URLs", [
                        f"{r['risk_score']}/100 {truncate(r['url'], 80)} [{r['verdict']}]: {', '.join(f['check'] for f in r['findings'] if f['level'] == 'MALICIOUS')[:80]}"
                        for r in sorted(_session_results, key=lambda x: x['risk_score'], reverse=True)[:25]
                    ]),
                ],
                pdf_path,
            )
            console.print(f"  [dim]PDF  →[/dim] [bold cyan]{pdf_path}[/bold cyan]\n")
        except Exception as e:
            console.print(f"  [yellow]PDF report skipped: {e}[/yellow]\n")
    except Exception as e:
        console.print(f"[red]Report failed: {e}[/red]")
