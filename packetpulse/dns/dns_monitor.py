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
from packetpulse.utils.helpers import shannon_entropy, save_json, ensure_dir, now_str, timestamp_filename, save_report_pdf

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


def _assess_domain(domain: str, cfg) -> tuple[str, list[str]]:
    """
    Assess a domain for threat indicators.
    Returns (level, reasons)   level: OK | WARN | MALICIOUS
    """
    reasons = []
    level = "OK"
    domain_lower = domain.lower()

    # Skip safe domains
    for safe in SAFE_DOMAINS:
        if domain_lower == safe or domain_lower.endswith("." + safe):
            return "OK", []

    # High-risk TLD
    for tld in HIGH_RISK_TLDS:
        if domain_lower.endswith(tld):
            reasons.append(f"High-risk TLD: {tld}")
            level = "WARN"
            break

    # Suspicious keywords
    if cfg.flag_keywords:
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in domain_lower:
                reasons.append(f"Suspicious keyword: '{kw}'")
                level = "MALICIOUS"
                break

    # High entropy (DGA detection)
    if cfg.flag_dga:
        parts = domain_lower.split(".")
        if len(parts) >= 2:
            hostname = parts[-2]
            if len(hostname) > 8:
                ent = shannon_entropy(hostname)
                if ent > cfg.dga_entropy_threshold:
                    reasons.append(f"DGA-like domain (entropy={ent:.2f})")
                    level = "MALICIOUS"
                elif ent > max(3.2, cfg.dga_entropy_threshold - 0.6):
                    reasons.append(f"Unusual domain entropy ({ent:.2f})")
                    if level == "OK":
                        level = "WARN"

    # Very long domain
    if len(domain) > cfg.max_domain_length:
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
    if "xn--" in domain_lower:
        reasons.append("Punycode domain — possible homograph attack")
        level = "MALICIOUS"

    # Beaconing detection (same domain queried many times)
    if cfg.flag_beacon:
        with _lock:
            count = _query_count[domain]
        if count >= cfg.beacon_malicious_threshold:
            reasons.append(f"Queried {count} times — possible C2 beaconing")
            level = "MALICIOUS"
        elif count >= cfg.beacon_warning_threshold:
            reasons.append(f"Queried {count} times — watch for beaconing")
            if level == "OK":
                level = "WARN"

    return level, reasons


def _save_flagged_summary(cfg) -> None:
    if not _flagged:
        return
    try:
        summary = {
            "timestamp": now_str(),
            "flagged_count": len(_flagged),
            "domains": _flagged,
        }
        save_json(summary, f"{cfg.results_path}/dns_summary_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
    except Exception as e:
        log.debug(f"Could not save DNS summary: {e}")


def _generate_dns_html_report(cfg, duration: Optional[int]) -> str:
    now = datetime.utcnow()
    ts_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    top_domains = sorted(_query_count.items(), key=lambda it: it[1], reverse=True)[:40]
    flagged = [_ for _ in _flagged]
    total_domains = len(_query_count)
    total_queries = sum(_query_count.values())
    duration_label = f"{duration}s" if duration else "Until stopped"

    top_rows = "".join(
        f"<tr><td class='mono'>{domain}</td><td class='right'>{count}</td></tr>"
        for domain, count in top_domains
    ) or "<tr><td colspan='2' class='dim'>No domains queried</td></tr>"

    flagged_rows = "".join(
        f"<tr><td class='mono'>{entry['domain']}</td>"
        f"<td>{entry['level']}</td>"
        f"<td>{', '.join(entry['reasons'])}</td>"
        f"<td class='right'>{entry['qtype']}</td></tr>"
        for entry in flagged
    ) or "<tr><td colspan='4' class='dim'>No flagged domains</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>PacketPulse DNS Monitor Report — {ts_str}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0b0b0d;color:#dedede;font-family:'Segoe UI',sans-serif;font-size:14px;line-height:1.6}}
.container{{max-width:1100px;margin:0 auto;padding:30px 24px}}
.header{{padding:20px 0;border-bottom:1px solid #1c1c24;display:flex;align-items:flex-start;gap:20px}}
.brand{{font-size:32px;font-weight:800;color:#50fa7b;letter-spacing:2px}}
.subtitle{{font-size:14px;color:#8be9fd;margin-top:6px}}
.dw-badge{{display:inline-block;margin-top:10px;padding:5px 11px;border-radius:999px;border:1px solid #50fa7b55;background:#50fa7b1a;color:#9effbf;font-size:10px;letter-spacing:1px;text-transform:uppercase}}
.meta{{display:grid;grid-template-columns:repeat(3,minmax(180px,1fr));gap:16px;margin-top:24px}}
.card{{background:#11131a;border:1px solid #1f2330;border-radius:12px;padding:18px}}
.card .label{{font-size:11px;color:#6f7b9c;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}}
.card .value{{font-size:18px;font-weight:700;color:#ffffff}}
.section{{margin-top:32px}}
.section h2{{font-size:18px;color:#f1fa8c;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:12px 14px;border-bottom:1px solid #1c1c24;text-align:left;vertical-align:top}}
th{{font-size:11px;color:#6272a4;text-transform:uppercase;letter-spacing:1px}}
td{{font-size:13px;color:#e6e6ff}}
.mono{{font-family:'Courier New',monospace;font-size:13px}}
.right{{text-align:right}}
.dim{{color:#7f8fa4}}
.footer{{display:flex;justify-content:space-between;align-items:center;margin-top:42px;padding-top:18px;border-top:1px solid #1c1c24;font-size:12px;color:#6272a4}}
</style>
</head>
<body>
<div class='container'>
  <div class='header'>
    <div>
      <div class='brand'>PACKETPULSE</div>
      <div class='subtitle'>DNS Monitor Session Report • Engineered by Dreamwalker4u</div>
            <div class='dw-badge'>Generated by Dreamwalker4u</div>
    </div>
    <div class='dim' style='margin-left:auto;text-align:right'>Generated: {ts_str}</div>
  </div>

  <div class='meta'>
    <div class='card'><div class='label'>Session Duration</div><div class='value'>{duration_label}</div></div>
    <div class='card'><div class='label'>Total DNS Queries</div><div class='value'>{total_queries:,}</div></div>
    <div class='card'><div class='label'>Unique Domains</div><div class='value'>{total_domains:,}</div></div>
    <div class='card'><div class='label'>Flagged Domains</div><div class='value'>{len(flagged):,}</div></div>
    <div class='card'><div class='label'>DGA Detection</div><div class='value'>{'Enabled' if cfg.flag_dga else 'Disabled'}</div></div>
    <div class='card'><div class='label'>Keyword Flags</div><div class='value'>{'Enabled' if cfg.flag_keywords else 'Disabled'}</div></div>
  </div>

  <div class='section'>
    <h2>Top Queried Domains</h2>
    <table>
      <thead><tr><th>Domain</th><th class='right'>Queries</th></tr></thead>
      <tbody>{top_rows}</tbody>
    </table>
  </div>

  <div class='section'>
    <h2>Flagged Domain Findings</h2>
    <table>
      <thead><tr><th>Domain</th><th>Severity</th><th>Reasons</th><th class='right'>Type</th></tr></thead>
      <tbody>{flagged_rows}</tbody>
    </table>
  </div>

  <div class='footer'>
    <div>PacketPulse • Dreamwalker4u</div>
    <div>Report generated by PacketPulse DNS Monitor</div>
  </div>
</div>
</body>
</html>"""
    return html


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

        cfg = get_config().dns
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

        level, reasons = _assess_domain(domain, cfg)

        level_str = {
            "OK": "[dim]  OK      [/dim]",
            "WARN": "[yellow]  ⚠ WARN  [/yellow]",
            "MALICIOUS": "[bold red]  ✗ THREAT[/bold red]",
        }[level]

        new_flag = " [dim](new)[/dim]" if is_new and cfg.flag_new_domains else ""
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
            if cfg.save_results:
                ensure_dir(cfg.results_path)
                save_json(entry, f"{cfg.results_path}/dns_flag_{domain[:40]}.json")

    except Exception as e:
        log.debug(f"DNS callback error: {e}")


def run_dns_monitor(interface: Optional[str] = None, duration: Optional[int] = None) -> None:
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

    timeout = duration if duration and duration > 0 else None
    try:
        sniff(
            iface=interface or None,
            filter="udp port 53",
            prn=_dns_callback,
            store=False,
            timeout=timeout,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        console.print("[red]ERROR: Requires root/sudo privileges.[/red]")
        return
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return
    finally:
        console.print(
            f"\n[green]Stopped.[/green]  "
            f"Unique domains: [cyan]{len(_seen_domains)}[/cyan]  "
            f"Flagged: [red]{len(_flagged)}[/red]"
        )
        if _flagged and cfg.save_results:
            console.print(f"\n[bold red]FLAGGED DOMAINS:[/bold red]")
            for f in _flagged[-10:]:
                console.print(f"  [red]✗[/red] {f['domain']}  [dim]{', '.join(f['reasons'][:2])}[/dim]")
            _save_flagged_summary(cfg)

        if cfg.save_results:
            try:
                report_id = timestamp_filename()
                report_html = _generate_dns_html_report(cfg, duration)
                report_path = f"{cfg.results_path}/dns_report_{report_id}.html"
                ensure_dir(cfg.results_path)
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(report_html)
                console.print(f"\n[bold green]Report saved →[/bold green] [cyan]{report_path}[/cyan]")

                report_json = {
                    "generated": now_str(),
                    "duration_seconds": duration or 0,
                    "total_queries": sum(_query_count.values()),
                    "unique_domains": len(_query_count),
                    "flagged_count": len(_flagged),
                    "flagged_domains": _flagged,
                    "settings": {
                        "flag_dga": cfg.flag_dga,
                        "flag_keywords": cfg.flag_keywords,
                        "flag_beacon": cfg.flag_beacon,
                    },
                }
                json_path = f"{cfg.results_path}/dns_report_{report_id}.json"
                save_json(report_json, json_path)
                console.print(f"[bold green]JSON saved   →[/bold green] [cyan]{json_path}[/cyan]")

                pdf_path = f"{cfg.results_path}/dns_report_{report_id}.pdf"
                try:
                    save_report_pdf(
                        "PACKETPULSE DNS MONITOR REPORT",
                        "PacketPulse | Dreamwalker4u",
                        [
                            ("Summary", [
                                f"Duration: {duration or 'Until stopped'}",
                                f"Total DNS queries: {sum(_query_count.values()):,}",
                                f"Unique domains: {len(_query_count):,}",
                                f"Flagged domains: {len(_flagged):,}",
                            ]),
                            ("Top Queried Domains", [
                                f"{domain}: {count}" for domain, count in sorted(_query_count.items(), key=lambda x: x[1], reverse=True)[:25]
                            ]),
                            ("Flagged Domains", [
                                f"{entry['domain']} [{entry['level']}]: {', '.join(entry['reasons'])}" for entry in _flagged[:25]
                            ] or ["No flagged domains"]),
                        ],
                        pdf_path,
                    )
                    console.print(f"[bold green]PDF saved   →[/bold green] [cyan]{pdf_path}[/cyan]")
                except Exception as e:
                    console.print(f"[yellow]PDF report skipped: {e}[/yellow]")
            except Exception as e:
                log.debug(f"Could not write DNS report: {e}")
