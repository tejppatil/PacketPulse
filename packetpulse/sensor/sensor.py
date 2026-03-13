"""
PacketPulse — Deep Packet Sniffer
Captures packets with full L2/L3/L4/L7 detail including:
  - HTTP request/response headers
  - DNS queries and responses
  - Geolocation of destination IPs
  - TCP/IP stack details
  - Process attribution (which app sent this)
"""
from __future__ import annotations

import os
import re
import socket
import threading
from collections import defaultdict
from datetime import datetime
from typing import Optional

import psutil
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich import box

from packetpulse.core.config import get_config
from packetpulse.core.logger import get_logger
from packetpulse.utils.helpers import (
    geoip_lookup, is_private_ip, reverse_dns,
    human_bytes, truncate, save_json, ensure_dir, now_str, timestamp_filename
)

try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        Raw, Ether, ARP, wrpcap
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

console = Console()
log = get_logger("sensor")

# ── Globals ────────────────────────────────────────────────────────────────────
_stats = {
    "total": 0, "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "other": 0,
    "bytes": 0, "http": 0, "dns": 0, "start": datetime.utcnow(),
}
_geo_cache: dict[str, dict] = {}
_dns_cache: dict[str, str] = {}
_captured_packets = []
_lock = threading.Lock()


# ── GeoIP (cached) ─────────────────────────────────────────────────────────────

def _geo(ip: str) -> dict:
    if ip not in _geo_cache:
        _geo_cache[ip] = geoip_lookup(ip, get_config().sensor.geoip_db)
    return _geo_cache[ip]


def _geo_str(ip: str) -> str:
    if is_private_ip(ip):
        return "[dim]LAN[/dim]"
    g = _geo(ip)
    cc = g.get("country_code", "??")
    city = g.get("city", "")
    return f"[cyan]{cc}[/cyan] {city}" if city and city != "Unknown" else f"[cyan]{cc}[/cyan]"


# ── Process attribution ────────────────────────────────────────────────────────

def _find_process(src_port: int, dst_port: int) -> str:
    """Try to find which process owns a connection by port."""
    try:
        for conn in psutil.net_connections(kind="inet"):
            lport = conn.laddr.port if conn.laddr else None
            rport = conn.raddr.port if conn.raddr else None
            if lport in (src_port, dst_port) or rport in (src_port, dst_port):
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        return f"{p.name()}({conn.pid})"
                    except Exception:
                        return f"pid:{conn.pid}"
    except Exception:
        pass
    return ""


# ── HTTP parser ────────────────────────────────────────────────────────────────

def _parse_http(payload: bytes) -> Optional[dict]:
    """Extract HTTP request/response details from raw payload."""
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return None

    result: dict = {}

    # HTTP Request
    req_match = re.match(
        r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+(HTTP/[\d.]+)\r?\n(.+?)(?:\r?\n\r?\n|$)",
        text, re.DOTALL
    )
    if req_match:
        result["type"] = "REQUEST"
        result["method"] = req_match.group(1)
        result["path"] = req_match.group(2)
        result["version"] = req_match.group(3)
        headers = {}
        for line in req_match.group(4).splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
        result["headers"] = headers
        result["host"] = headers.get("Host", "")
        result["user_agent"] = headers.get("User-Agent", "")
        result["content_type"] = headers.get("Content-Type", "")
        result["referer"] = headers.get("Referer", "")
        # Body (for POST)
        body_start = text.find("\r\n\r\n")
        if body_start > 0:
            result["body"] = truncate(text[body_start + 4:], 200)
        return result

    # HTTP Response
    resp_match = re.match(
        r"(HTTP/[\d.]+)\s+(\d+)\s+(.+?)\r?\n(.+?)(?:\r?\n\r?\n|$)",
        text, re.DOTALL
    )
    if resp_match:
        result["type"] = "RESPONSE"
        result["version"] = resp_match.group(1)
        result["status_code"] = resp_match.group(2)
        result["status_text"] = resp_match.group(3).strip()
        headers = {}
        for line in resp_match.group(4).splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
        result["headers"] = headers
        result["content_type"] = headers.get("Content-Type", "")
        result["content_length"] = headers.get("Content-Length", "")
        result["server"] = headers.get("Server", "")
        result["set_cookie"] = headers.get("Set-Cookie", "")
        return result

    return None


# ── DNS parser ─────────────────────────────────────────────────────────────────

def _parse_dns(pkt) -> Optional[dict]:
    """Extract DNS query/response details."""
    if not pkt.haslayer(DNS):
        return None
    dns = pkt[DNS]
    result: dict = {"type": "QUERY" if dns.qr == 0 else "RESPONSE"}

    if dns.qr == 0 and dns.qdcount > 0:  # Query
        try:
            q = dns.qd
            qname = q.qname.decode("utf-8", errors="replace").rstrip(".")
            qtype_map = {1: "A", 2: "NS", 5: "CNAME", 15: "MX",
                         16: "TXT", 28: "AAAA", 255: "ANY"}
            result["query"] = qname
            result["qtype"] = qtype_map.get(q.qtype, str(q.qtype))
        except Exception:
            pass

    elif dns.qr == 1:  # Response
        answers = []
        try:
            q = dns.qd
            result["query"] = q.qname.decode("utf-8", errors="replace").rstrip(".")
        except Exception:
            pass
        try:
            rr = dns.an
            while rr:
                if hasattr(rr, "rdata"):
                    answers.append(str(rr.rdata))
                rr = rr.payload if hasattr(rr, "payload") and rr.payload else None
                if rr and not hasattr(rr, "rdata"):
                    break
        except Exception:
            pass
        result["answers"] = answers[:5]
        result["rcode"] = dns.rcode  # 0=OK, 3=NXDOMAIN

    return result


# ── TCP flags ─────────────────────────────────────────────────────────────────

def _tcp_flags(flags) -> str:
    names = []
    flag_map = [
        ("F", "FIN"), ("S", "SYN"), ("R", "RST"),
        ("P", "PSH"), ("A", "ACK"), ("U", "URG"),
    ]
    for char, name in flag_map:
        if char in str(flags):
            names.append(name)
    return " ".join(names) if names else str(flags)


# ── Rich display ───────────────────────────────────────────────────────────────

def _render_packet_detail(info: dict) -> None:
    """Print a detailed packet block to terminal."""
    ptype = info.get("proto", "?")
    src = info.get("src_ip", "?")
    dst = info.get("dst_ip", "?")
    sport = info.get("src_port", "")
    dport = info.get("dst_port", "")
    ts = info.get("timestamp", "")
    geo = info.get("geo", {})
    proc = info.get("process", "")
    size = info.get("size", 0)
    mac_src = info.get("mac_src", "")
    mac_dst = info.get("mac_dst", "")
    ttl = info.get("ttl", "")
    tcp_flags = info.get("tcp_flags", "")
    window = info.get("window", "")
    seq = info.get("seq", "")
    ack_num = info.get("ack", "")

    # Colour by type
    colour_map = {
        "TCP": "cyan", "UDP": "yellow", "ICMP": "green",
        "DNS": "magenta", "ARP": "blue", "HTTP": "bright_green",
    }
    col = colour_map.get(ptype, "white")

    lines = []
    lines.append(f"[dim]{ts}[/dim]  [{col}]{ptype}[/{col}]  "
                 f"[bold white]{src}[/bold white]"
                 f"{':[yellow]' + str(sport) + '[/yellow]' if sport else ''}"
                 f"  [dim]→[/dim]  "
                 f"[bold white]{dst}[/bold white]"
                 f"{':[green]' + str(dport) + '[/green]' if dport else ''}"
                 f"  [dim]{size}B[/dim]"
                 + (f"  [dim italic]{proc}[/dim italic]" if proc else ""))

    # Layer 2
    if mac_src or mac_dst:
        lines.append(f"  [dim]L2  MAC[/dim]  {mac_src} [dim]→[/dim] {mac_dst}")

    # Layer 3
    l3_parts = []
    if ttl:
        l3_parts.append(f"TTL={ttl}")
    if l3_parts:
        lines.append(f"  [dim]L3  IP[/dim]   " + "  ".join(l3_parts))

    # Layer 4 — TCP details
    if tcp_flags:
        l4 = f"  [dim]L4  TCP[/dim]  flags=[yellow]{tcp_flags}[/yellow]"
        if window:
            l4 += f"  win={window}"
        if seq:
            l4 += f"  seq={seq}"
        if ack_num:
            l4 += f"  ack={ack_num}"
        lines.append(l4)

    # GeoIP
    country = geo.get("country", "")
    city = geo.get("city", "")
    org = geo.get("org", "")
    if country and country not in ("Unknown", "LAN"):
        lines.append(f"  [dim]GEO      [/dim]  "
                     f"[cyan]{country}[/cyan]"
                     + (f", {city}" if city and city != "Unknown" else "")
                     + (f"  [dim]{org}[/dim]" if org else ""))

    # Reverse DNS
    rdns = info.get("rdns", "")
    if rdns:
        lines.append(f"  [dim]rDNS     [/dim]  [dim]{rdns}[/dim]")

    # HTTP detail
    http = info.get("http")
    if http:
        if http.get("type") == "REQUEST":
            lines.append(f"  [dim]HTTP     [/dim]  "
                         f"[bright_green]{http['method']}[/bright_green] "
                         f"[white]{http.get('host','')}{http.get('path','')}[/white]")
            if http.get("user_agent"):
                lines.append(f"  [dim]  User-Agent[/dim]  {truncate(http['user_agent'], 60)}")
            if http.get("content_type"):
                lines.append(f"  [dim]  Content-Type[/dim]  {http['content_type']}")
            if http.get("referer"):
                lines.append(f"  [dim]  Referer[/dim]  {http['referer']}")
            if http.get("body"):
                lines.append(f"  [dim]  Body[/dim]  [yellow]{truncate(http['body'], 120)}[/yellow]")
        elif http.get("type") == "RESPONSE":
            sc = http.get("status_code", "")
            sc_col = "green" if sc.startswith("2") else "yellow" if sc.startswith("3") else "red"
            lines.append(f"  [dim]HTTP     [/dim]  "
                         f"[{sc_col}]{sc} {http.get('status_text','')}[/{sc_col}]"
                         + (f"  {http.get('content_type','')}" if http.get("content_type") else "")
                         + (f"  [{http.get('content_length','')} bytes]" if http.get("content_length") else ""))
            if http.get("server"):
                lines.append(f"  [dim]  Server[/dim]  {http['server']}")
            if http.get("set_cookie"):
                lines.append(f"  [dim]  Set-Cookie[/dim]  {truncate(http['set_cookie'], 80)}")

    # DNS detail
    dns_info = info.get("dns")
    if dns_info:
        if dns_info.get("type") == "QUERY":
            lines.append(f"  [dim]DNS      [/dim]  "
                         f"[magenta]? {dns_info.get('query','')}[/magenta]  "
                         f"[dim]{dns_info.get('qtype','')}[/dim]")
        elif dns_info.get("type") == "RESPONSE":
            answers = dns_info.get("answers", [])
            rcode = dns_info.get("rcode", 0)
            if rcode == 3:
                lines.append(f"  [dim]DNS      [/dim]  "
                             f"[red]NXDOMAIN[/red] {dns_info.get('query','')}")
            else:
                lines.append(f"  [dim]DNS      [/dim]  "
                             f"[magenta]{dns_info.get('query','')}[/magenta]"
                             + (f"  [dim]→[/dim]  [green]{', '.join(answers)}[/green]"
                                if answers else ""))

    console.print("\n".join(lines))
    console.print("[dim]" + "─" * 100 + "[/dim]")


# ── Packet callback ────────────────────────────────────────────────────────────

def _packet_callback(pkt) -> None:
    global _stats, _captured_packets
    cfg = get_config().sensor

    with _lock:
        _stats["total"] += 1
        _stats["bytes"] += len(pkt)
        _captured_packets.append(pkt)
        if len(_captured_packets) > 5000:
            _captured_packets = _captured_packets[-5000:]

    info: dict = {
        "timestamp": datetime.utcnow().strftime("%H:%M:%S.%f")[:-3],
        "size": len(pkt),
        "proto": "OTHER",
    }

    # Layer 2 — Ethernet
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        info["mac_src"] = eth.src
        info["mac_dst"] = eth.dst

    # ARP
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        info["proto"] = "ARP"
        info["src_ip"] = arp.psrc
        info["dst_ip"] = arp.pdst
        with _lock:
            _stats["arp"] += 1
        _render_packet_detail(info)
        return

    # IP layer
    src_ip = dst_ip = ttl = ""
    if pkt.haslayer(IP):
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        ttl = ip.ttl
        info["src_ip"] = src_ip
        info["dst_ip"] = dst_ip
        info["ttl"] = ttl
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        src_ip = ip6.src
        dst_ip = ip6.dst
        info["src_ip"] = src_ip
        info["dst_ip"] = dst_ip
    else:
        return

    # Geolocation of destination
    if cfg.show_geoip and not is_private_ip(dst_ip):
        info["geo"] = _geo(dst_ip)
        # reverse DNS (cached)
        if dst_ip not in _dns_cache:
            _dns_cache[dst_ip] = reverse_dns(dst_ip)
        rdns = _dns_cache.get(dst_ip, "")
        if rdns:
            info["rdns"] = rdns

    # ICMP
    if pkt.haslayer(ICMP):
        info["proto"] = "ICMP"
        with _lock:
            _stats["icmp"] += 1
        _render_packet_detail(info)
        return

    # DNS (UDP 53)
    if pkt.haslayer(DNS) and cfg.show_dns:
        info["proto"] = "DNS"
        info["src_port"] = pkt[UDP].sport if pkt.haslayer(UDP) else ""
        info["dst_port"] = pkt[UDP].dport if pkt.haslayer(UDP) else ""
        info["dns"] = _parse_dns(pkt)
        with _lock:
            _stats["dns"] += 1
        _render_packet_detail(info)
        return

    # UDP
    if pkt.haslayer(UDP):
        info["proto"] = "UDP"
        info["src_port"] = pkt[UDP].sport
        info["dst_port"] = pkt[UDP].dport
        with _lock:
            _stats["udp"] += 1
        _render_packet_detail(info)
        return

    # TCP
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        info["proto"] = "TCP"
        info["src_port"] = tcp.sport
        info["dst_port"] = tcp.dport
        info["tcp_flags"] = _tcp_flags(tcp.flags)
        info["window"] = tcp.window
        info["seq"] = tcp.seq
        info["ack"] = tcp.ack

        # Process attribution
        info["process"] = _find_process(tcp.sport, tcp.dport)

        # HTTP payload
        if pkt.haslayer(Raw) and cfg.show_http:
            raw = bytes(pkt[Raw])
            http = _parse_http(raw)
            if http:
                info["proto"] = "HTTP"
                info["http"] = http
                with _lock:
                    _stats["http"] += 1

        with _lock:
            _stats["tcp"] += 1
        _render_packet_detail(info)
        return

    _render_packet_detail(info)


# ── Stats bar ─────────────────────────────────────────────────────────────────

def _print_stats() -> None:
    elapsed = (datetime.utcnow() - _stats["start"]).total_seconds()
    pps = _stats["total"] / max(elapsed, 1)
    console.print(
        f"\n[dim]── STATS ──[/dim]  "
        f"total=[green]{_stats['total']}[/green]  "
        f"TCP=[cyan]{_stats['tcp']}[/cyan]  "
        f"UDP=[yellow]{_stats['udp']}[/yellow]  "
        f"DNS=[magenta]{_stats['dns']}[/magenta]  "
        f"HTTP=[bright_green]{_stats['http']}[/bright_green]  "
        f"ICMP=[green]{_stats['icmp']}[/green]  "
        f"pkt/s=[bold]{pps:.0f}[/bold]  "
        f"bytes=[dim]{human_bytes(_stats['bytes'])}[/dim]"
    )


# ── Entry point ────────────────────────────────────────────────────────────────

def run_sniffer(
    interface: Optional[str] = None,
    bpf_filter: str = "",
    count: int = 0,
    save_pcap: bool = True,
) -> None:
    """Start the deep packet sniffer."""
    if not SCAPY_OK:
        console.print("[red]ERROR: scapy is not installed. Run: pip install scapy[/red]")
        return

    cfg = get_config().sensor
    iface = interface or cfg.interface

    # Header
    console.rule("[bold green]PACKETPULSE  ›  DEEP PACKET SNIFFER[/bold green]")
    console.print(
        f"  [dim]Interface:[/dim] [green]{iface or 'auto'}[/green]  "
        f"[dim]Filter:[/dim] [yellow]{bpf_filter or 'none'}[/yellow]  "
        f"[dim]GeoIP:[/dim] [green]{'ON' if cfg.show_geoip else 'OFF'}[/green]  "
        f"[dim]HTTP:[/dim] [green]{'ON' if cfg.show_http else 'OFF'}[/green]  "
        f"[dim]DNS:[/dim] [green]{'ON' if cfg.show_dns else 'OFF'}[/green]"
    )
    console.print(f"  [dim]Saving PCAP:[/dim] [green]{'ON → pcap_store/' if save_pcap else 'OFF'}[/green]")
    console.print("[dim]" + "─" * 100 + "[/dim]\n")
    console.print(
        f"  [dim]TIME        PROTO  SRC → DST                           SIZE   PROCESS[/dim]"
    )
    console.print("[dim]" + "─" * 100 + "[/dim]")

    ensure_dir(cfg.pcap_store_path)

    try:
        sniff(
            iface=iface or None,
            filter=bpf_filter or None,
            prn=_packet_callback,
            count=count or 0,
            store=False,
        )
    except KeyboardInterrupt:
        _print_stats()
        if save_pcap and _captured_packets:
            fname = f"{cfg.pcap_store_path}/session_{timestamp_filename()}.pcap"
            try:
                wrpcap(fname, _captured_packets)
                console.print(f"\n[green]PCAP saved →[/green] [cyan]{fname}[/cyan]")
            except Exception as e:
                console.print(f"[yellow]Could not save PCAP: {e}[/yellow]")
    except PermissionError:
        console.print("[red]ERROR: Packet capture requires root/sudo privileges.[/red]")
    except Exception as e:
        console.print(f"[red]Sniffer error: {e}[/red]")
