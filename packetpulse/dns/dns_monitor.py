"""
PacketPulse — DNS Query Monitor
Watches every DNS query the machine makes and flags suspicious ones.
"""
from __future__ import annotations

import re
import threading
from collections import defaultdict
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich import box

from packetpulse.core.config import get_config
from packetpulse.core.logger import get_logger
from packetpulse.utils.helpers import shannon_entropy, save_json, ensure_dir, now_str

try:
    from scapy.all import sniff, DNS, DNSQR, IP, UDP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

console = Console()
log = get_logger("dns")

_query_count: dict[str, int] = defaultdict(int)
_seen_domains: set[str] = set()
_flagged: list[dict] = []
_lock = threading.Lock()

# High-risk TLDs for DGA / malware
HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz",
    ".win", ".loan", ".click", ".download", ".stream",
    ".racing", ".review", ".party", ".science", ".accountant",
}

SUSPICIOUS_KEYWORDS = [
    "malware", "botnet", "c2", "payload", "shell", "exploit",
    "inject", "trojan", "ransom", "crypto", "miner", "stealer",
]

# Well-known safe domains (skip scanning these)
SAFE_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com",
    "youtube.com", "youtu.be", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "microsoft.com", "windows.com",
    "apple.com", "icloud.com", "amazon.com", "amazonaws.com",
    "cloudflare.com", "fastly.com", "akamai.com",
    "github.com", "githubusercontent.com",
    "stackoverflow.com", "reddit.com",
}


def _assess_domain(domain: str) -> tuple[str, list[str]]:
    """
    Assess a domain for threat indicators.
    Returns (level, reasons)   level: OK | WARN | MALICIOUS
    """
    reasons = []
    level = "OK"

    # Skip safe domains
    for safe in SAFE_DOMAINS:
        if domain == safe or domain.endswith("." + safe):
            return "OK", []

    # High-risk TLD
    for tld in HIGH_RISK_TLDS:
        if domain.endswith(tld):
            reasons.append(f"High-risk TLD: {tld}")
            level = "WARN"
            break

    # Suspicious keywords
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in domain.lower():
            reasons.append(f"Suspicious keyword: '{kw}'")
            level = "MALICIOUS"
            break

    # High entropy (DGA detection)
    parts = domain.split(".")
    if len(parts) >= 2:
        hostname = parts[-2]  # e.g. "abc123xyz" from "abc123xyz.com"
        if len(hostname) > 8:
            ent = shannon_entropy(hostname)
            if ent > 3.8:
                reasons.append(f"DGA-like domain (entropy={ent:.2f})")
                level = "MALICIOUS"
            elif ent > 3.2:
                reasons.append(f"Unusual domain entropy ({ent:.2f})")
                if level == "OK":
                    level = "WARN"

    # Very long domain
    if len(domain) > 60:
        reasons.append(f"Unusually long domain ({len(domain)} chars)")
        if level == "OK":
            level = "WARN"

    # Lots of hyphens (common in typosquatting)
    if domain.count("-") >= 4:
        reasons.append(f"{domain.count('-')} hyphens (typosquatting indicator)")
        if level == "OK":
            level = "WARN"

    # Many numeric characters
    num_count = sum(c.isdigit() for c in domain.replace(".", ""))
    ratio = num_count / max(len(domain.replace(".", "")), 1)
    if ratio > 0.5 and len(domain) > 10:
        reasons.append(f"High numeric ratio ({ratio:.0%}) — possible DGA")
        if level == "OK":
            level = "WARN"

    # Punycode (homograph attack)
    if "xn--" in domain:
        reasons.append("Punycode domain — possible homograph attack")
        level = "MALICIOUS"

    # Beaconing detection (same domain queried many times)
    with _lock:
        count = _query_count[domain]
    if count > 30:
        reasons.append(f"Queried {count} times — possible C2 beaconing")
        level = "MALICIOUS"
    elif count > 15:
        reasons.append(f"Queried {count} times — watch for beaconing")
        if level == "OK":
            level = "WARN"

    return level, reasons


def _dns_callback(pkt) -> None:
    """Scapy callback for DNS packets."""
    try:
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        if dns.qr != 0:  # Only queries (qr=0)
            return
        if dns.qdcount == 0:
            return

        domain = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
        if not domain or len(domain) < 4:
            return

        # Count queries
        with _lock:
            _query_count[domain] += 1
            is_new = domain not in _seen_domains
            _seen_domains.add(domain)

        src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
        qtype_map = {1: "A", 2: "NS", 5: "CNAME", 15: "MX",
                     16: "TXT", 28: "AAAA", 255: "ANY"}
        qtype = qtype_map.get(dns.qd.qtype, str(dns.qd.qtype))
        ts = datetime.utcnow().strftime("%H:%M:%S")

        level, reasons = _assess_domain(domain)

        level_str = {
            "OK": "[dim]  OK      [/dim]",
            "WARN": "[yellow]  ⚠ WARN  [/yellow]",
            "MALICIOUS": "[bold red]  ✗ THREAT[/bold red]",
        }[level]

        new_flag = " [dim](new)[/dim]" if is_new else ""
        domain_col = {"OK": "white", "WARN": "yellow", "MALICIOUS": "red"}[level]

        console.print(
            f"  [dim]{ts}[/dim]"
            f"{level_str}"
            f"  [{domain_col}]{domain}[/{domain_col}]{new_flag}"
            f"  [dim]{qtype}[/dim]"
            f"  [dim]{src_ip}[/dim]"
        )

        if reasons:
            for r in reasons:
                console.print(f"            [dim]╰─[/dim] {r}")

        if level != "OK":
            entry = {
                "timestamp": now_str(),
                "domain": domain,
                "level": level,
                "reasons": reasons,
                "src_ip": src_ip,
                "qtype": qtype,
            }
            with _lock:
                _flagged.append(entry)
            cfg = get_config().dns
            ensure_dir(cfg.results_path)
            save_json(entry, f"{cfg.results_path}/dns_flag_{domain[:40]}.json")

    except Exception as e:
        log.debug(f"DNS callback error: {e}")


def run_dns_monitor(interface: Optional[str] = None) -> None:
    """Start DNS query monitor."""
    if not SCAPY_OK:
        console.print("[red]ERROR: scapy is not installed.[/red]")
        return

    cfg = get_config().dns
    ensure_dir(cfg.results_path)

    console.rule("[bold green]PACKETPULSE  ›  DNS MONITOR[/bold green]")
    console.print(
        "  [dim]Watching every DNS query made by this machine.[/dim]\n"
        "  [dim]Flags:[/dim] DGA domains  •  High-risk TLDs  •  Suspicious keywords  •  C2 beaconing\n"
        f"  [dim]Results →[/dim] [cyan]{cfg.results_path}/[/cyan]\n"
    )
    console.print("[dim]" + "─" * 100 + "[/dim]")
    console.print(
        "  [dim]TIME      STATUS      DOMAIN                                    TYPE   SRC[/dim]"
    )
    console.print("[dim]" + "─" * 100 + "[/dim]")

    try:
        sniff(
            iface=interface or None,
            filter="udp port 53",
            prn=_dns_callback,
            store=False,
        )
    except KeyboardInterrupt:
        console.print(
            f"\n[green]Stopped.[/green]  "
            f"Unique domains: [cyan]{len(_seen_domains)}[/cyan]  "
            f"Flagged: [red]{len(_flagged)}[/red]"
        )
        if _flagged:
            console.print(f"\n[bold red]FLAGGED DOMAINS:[/bold red]")
            for f in _flagged[-10:]:
                console.print(f"  [red]✗[/red] {f['domain']}  [dim]{', '.join(f['reasons'][:2])}[/dim]")
    except PermissionError:
        console.print("[red]ERROR: Requires root/sudo privileges.[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
