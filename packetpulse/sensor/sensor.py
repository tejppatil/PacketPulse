"""
PacketPulse — Deep Packet Sniffer + Forensic Report Generator
Captures full L2/L3/L4/L7 data and generates a branded HTML report.
Report: PacketPulse | Dreamwalker4u
"""
from __future__ import annotations

import json
import re
import threading
import time
import queue
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, Counter, deque
from datetime import datetime
from pathlib import Path
from textwrap import wrap
from typing import Optional

import psutil
from rich.markup import escape as rescape

from packetpulse import __version__
from packetpulse.core.config import get_config
from packetpulse.core.logger import get_logger, console as _shared_console
from packetpulse.core import capabilities
from packetpulse.core.session import Session, StopController, utc_now
from packetpulse.utils.helpers import (
    geoip_lookup, is_private_ip, reverse_dns,
    human_bytes, truncate, save_json, ensure_dir, timestamp_filename,
    h as esc, UNKNOWN,
)

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
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS
    from scapy.packet import Raw
    from scapy.sendrecv import sniff
    from scapy.utils import PcapReader, PcapWriter
    SCAPY_OK = True
    SCAPY_UNAVAILABLE_REASON = ""
except Exception as _e:
    SCAPY_OK = False
    SCAPY_UNAVAILABLE_REASON = _SCAPY_ERR or "{}: {}".format(type(_e).__name__, _e)

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    PDF_OK = True
except ImportError:
    PDF_OK = False

console = _shared_console
log = get_logger("sensor")

# ── Session globals ───────────────────────────────────────────────────────────
_stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "other": 0,
          "bytes": 0, "http": 0, "dns": 0, "start": utc_now()}
_geo_cache:   dict[str, dict] = {}
_dns_cache:   dict[str, str]  = {}
_packet_log: deque = deque(maxlen=50000)
_pcap_writer = None          # scapy PcapWriter; complete, streamed to disk
_ndjson_fh = None            # complete per-packet record stream
_connections:  dict[str, dict] = {}
_domains_seen: set[str] = set()
_ips_seen:     dict[str, dict] = {}
_http_requests: list[dict] = []
_investigation_hits: list[dict] = []
_lock = threading.Lock()
_packet_queue: Optional[queue.Queue] = None
_worker_thread: Optional[threading.Thread] = None
_conn_cache: list = []
_conn_cache_timestamp: float = 0.0
_attribution_blocked: dict = {"reason": ""}
_draining = False
_stop_sniffing = False
_sniff_start_time: Optional[float] = None
_sniff_duration: int = 0


# ── Endpoint enrichment ──────────────────────────────────────────────────────
#
# GeoIP and reverse DNS are NETWORK operations. Performing them inline in the
# packet path made a short capture take minutes: every new public address
# triggered an HTTP lookup plus a PTR query, serially, while packets queued
# behind it.
#
# They now run on a small bounded pool. The packet record captures whatever is
# already known; the report is written after the pool drains, so results that
# arrive late are still included. Anything unresolved is reported as such
# rather than guessed.

_ENRICH_WORKERS = 4
_ENRICH_MAX_ADDRESSES = 500        # hard ceiling per session
_enrich_pool: Optional[ThreadPoolExecutor] = None
_enrich_requested: set[str] = set()
_enrich_lock = threading.Lock()


def _enrich_start() -> None:
    global _enrich_pool
    _enrich_requested.clear()
    _enrich_pool = ThreadPoolExecutor(
        max_workers=_ENRICH_WORKERS, thread_name_prefix="pp-enrich"
    )
    # Enrichment is best-effort metadata. Its threads must not keep the process
    # alive or delay a return to the menu, so they are marked daemon after
    # creation; unfinished lookups are reported as unresolved rather than waited on.
    for t in threading.enumerate():
        if t.name.startswith("pp-enrich"):
            t.daemon = True


def _enrich_pending_count() -> int:
    with _enrich_lock:
        return max(len(_enrich_requested) - len(_geo_cache), 0)


def _enrich_shutdown(timeout: float = 8.0) -> int:
    """Drain outstanding enrichment work. Returns the count left UNRESOLVED."""
    global _enrich_pool
    pool, _enrich_pool = _enrich_pool, None
    if pool is None:
        return 0
    # Bounded: cancel work that has not started rather than let shutdown hang.
    deadline = time.monotonic() + timeout
    pool.shutdown(wait=False, cancel_futures=True)
    while time.monotonic() < deadline:
        if not any(t.is_alive() for t in threading.enumerate()
                   if t.name.startswith("pp-enrich")):
            break
        time.sleep(0.1)
    return _enrich_pending_count()


def _enrich_endpoint(ip: str) -> None:
    """Resolve one address off the packet path."""
    threading.current_thread().daemon = True
    try:
        cfg = get_config().sensor
        _geo_cache[ip] = geoip_lookup(ip, cfg.geoip_db, allow_online=cfg.geoip_online)
    except (OSError, ValueError) as e:
        log.warning("geoip lookup failed for %s: %s", ip, e)
        _geo_cache[ip] = {"country": "UNAVAILABLE", "city": "UNAVAILABLE",
                          "org": "", "source": "none", "available": False}
    try:
        _dns_cache[ip] = reverse_dns(ip)
    except OSError:
        _dns_cache[ip] = ""


def _request_enrichment(ip: str) -> None:
    """Queue an address for background enrichment, once, up to the ceiling."""
    if not ip or _enrich_pool is None:
        return
    with _enrich_lock:
        if ip in _enrich_requested or len(_enrich_requested) >= _ENRICH_MAX_ADDRESSES:
            return
        _enrich_requested.add(ip)
    try:
        _enrich_pool.submit(_enrich_endpoint, ip)
    except RuntimeError:
        # Pool already shutting down; not an error worth failing the capture for.
        pass


def _geo(ip: str) -> dict:
    """Return what is currently known about an address. Never blocks."""
    if ip in _geo_cache:
        return _geo_cache[ip]
    _request_enrichment(ip)
    return {"country": "PENDING", "city": "PENDING", "lat": 0.0, "lon": 0.0,
            "org": "", "source": "pending", "available": False}


def _refresh_connection_cache() -> None:
    global _conn_cache, _conn_cache_timestamp
    now = time.monotonic()
    if now - _conn_cache_timestamp > 2.0:
        try:
            _conn_cache = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as e:
            # Without privilege the OS hides other users' sockets. Attribution
            # then legitimately cannot be established for most packets.
            _conn_cache = []
            _attribution_blocked["reason"] = f"{type(e).__name__}: insufficient privilege to enumerate sockets"
        except OSError as e:
            _conn_cache = []
            _attribution_blocked["reason"] = f"{type(e).__name__}: {e}"
        _conn_cache_timestamp = now


def _find_process(sp: int, dp: int, src_ip: str = "", dst_ip: str = "") -> dict:
    """Attribute a packet to a local process by exact socket four-tuple.

    Returns {"process": str, "attribution": "EXACT"|"INFERRED"|"UNKNOWN",
             "reason": str}.

    Only an exact match on (local ip, local port, remote ip, remote port) is
    reported as confirmed. A previous implementation fell back to the first
    connection sharing EITHER port, which meant any HTTPS packet could be
    attributed to an unrelated process that merely also talked to port 443.
    A wrong process name is worse than UNKNOWN, so the fallback is now
    reported as INFERRED with its basis, or not at all.
    """
    unknown = {"process": "", "attribution": "UNKNOWN", "reason": "no matching socket"}
    if not (src_ip and dst_ip):
        return {"process": "", "attribution": "UNKNOWN",
                "reason": "packet lacks addresses for socket matching"}

    _refresh_connection_cache()
    exact = None
    same_local_port = []

    for c in _conn_cache:
        if not c.laddr:
            continue
        try:
            l_ip, l_port = c.laddr.ip, c.laddr.port
        except AttributeError:
            continue
        r_ip, r_port = "", 0
        if c.raddr:
            try:
                r_ip, r_port = c.raddr.ip, c.raddr.port
            except AttributeError:
                r_ip, r_port = "", 0

        # Outbound: local socket is the packet source.
        if l_ip == src_ip and l_port == sp and r_ip == dst_ip and r_port == dp:
            exact = c
            break
        # Inbound: local socket is the packet destination.
        if l_ip == dst_ip and l_port == dp and r_ip == src_ip and r_port == sp:
            exact = c
            break
        # Candidate for clearly-labelled inference: our own listening/ephemeral
        # port on the matching address, remote side not yet established.
        if (l_ip == src_ip and l_port == sp) or (l_ip == dst_ip and l_port == dp):
            same_local_port.append(c)

    if exact is not None:
        name = _proc_name(exact.pid)
        if name:
            return {"process": name, "attribution": "EXACT",
                    "reason": "exact socket four-tuple match"}
        return {"process": f"pid:{exact.pid}" if exact.pid else "",
                "attribution": "EXACT" if exact.pid else "UNKNOWN",
                "reason": "socket matched but process name unavailable"}

    # Exactly one candidate on our own local endpoint is a defensible
    # inference. More than one is ambiguous, so we say UNKNOWN.
    if len(same_local_port) == 1:
        c = same_local_port[0]
        name = _proc_name(c.pid)
        if name:
            return {"process": name, "attribution": "INFERRED",
                    "reason": "unique local endpoint match; remote peer not confirmed"}

    return unknown


def _proc_name(pid) -> str:
    if not pid:
        return ""
    try:
        proc = psutil.Process(pid)
        return f"{proc.name()}({pid})"
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return ""


def _parse_http(payload: bytes) -> Optional[dict]:
    try: text = payload.decode("utf-8", errors="replace")
    except Exception:
        return None
    req = re.match(r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+(HTTP/[\d.]+)\r?\n(.+?)(?:\r?\n\r?\n|$)", text, re.DOTALL)
    if req:
        headers = {}
        for line in req.group(4).splitlines():
            if ":" in line:
                k,_,v = line.partition(":"); headers[k.strip()]=v.strip()
        r = {"type":"REQUEST","method":req.group(1),"path":req.group(2),"version":req.group(3),
             "headers":headers,"host":headers.get("Host",""),"user_agent":headers.get("User-Agent",""),
             "content_type":headers.get("Content-Type",""),"referer":headers.get("Referer","")}
        bs = text.find("\r\n\r\n")
        if bs > 0: r["body"] = truncate(text[bs+4:], 200)
        return r
    resp = re.match(r"(HTTP/[\d.]+)\s+(\d+)\s+(.+?)\r?\n(.+?)(?:\r?\n\r?\n|$)", text, re.DOTALL)
    if resp:
        headers = {}
        for line in resp.group(4).splitlines():
            if ":" in line:
                k,_,v = line.partition(":"); headers[k.strip()]=v.strip()
        return {"type":"RESPONSE","version":resp.group(1),"status_code":resp.group(2),
                "status_text":resp.group(3).strip(),"headers":headers,
                "content_type":headers.get("Content-Type",""),"content_length":headers.get("Content-Length",""),
                "server":headers.get("Server",""),"set_cookie":headers.get("Set-Cookie","")}
    return None

def _dns_first(record):
    """First entry of a DNS section, across scapy versions.

    scapy >= 2.6 exposes qd/an/ns/ar as PacketListField, where attribute access
    is deprecated and raises IndexError when the section is empty. Older scapy
    returns the record directly.
    """
    if record is None:
        return None
    if isinstance(record, (list, tuple)):
        return record[0] if record else None
    try:
        return record[0]
    except (IndexError, TypeError, KeyError):
        return record


def _dns_section(record):
    """All entries of a DNS section as a list."""
    if record is None:
        return []
    if isinstance(record, (list, tuple)):
        return list(record)
    try:
        return [record[i] for i in range(len(record))]
    except (TypeError, IndexError, KeyError):
        return [record]


def _parse_dns_pkt(pkt) -> Optional[dict]:
    if not pkt.haslayer(DNS):
        return None
    dns = pkt[DNS]

    def _count(value) -> int:
        """Record counts may be absent on malformed packets; treat as zero."""
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    qd_n, an_n = _count(dns.qdcount), _count(dns.ancount)
    r: dict = {
        "type": "QUERY" if dns.qr == 0 else "RESPONSE",
        "rcode": _count(dns.rcode),
        "qdcount": qd_n,
        "ancount": an_n,
        "nscount": _count(dns.nscount),
        "arcount": _count(dns.arcount),
    }
    qmap = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 255: "ANY"}

    q = _dns_first(getattr(dns, "qd", None))
    if q is not None:
        try:
            r["query"] = q.qname.decode("utf-8", errors="replace").rstrip(".")
            r["qtype"] = qmap.get(q.qtype, str(q.qtype))
            r["qclass"] = q.qclass
        except Exception:
            pass

    if dns.qr == 1:
        answers = []
        for rr in _dns_section(getattr(dns, "an", None)):
            if hasattr(rr, "rdata"):
                try:
                    name = getattr(rr, "rrname", b"").decode("utf-8", errors="replace").rstrip(".")
                except Exception:
                    name = ""
                try:
                    rtype = int(getattr(rr, "type", -1))
                except Exception:
                    rtype = -1
                answer_text = str(rr.rdata)
                answers.append({
                    "name": name,
                    "type": qmap.get(rtype, str(rtype)),
                    "ttl": getattr(rr, "ttl", None),
                    "data": answer_text,
                })
        r["answers"] = answers
    return r

def _tcp_flags(f) -> str:
    return " ".join(n for c,n in [("F","FIN"),("S","SYN"),("R","RST"),("P","PSH"),("A","ACK"),("U","URG")] if c in str(f)) or str(f)


# ── Evidence-based classification ────────────────────────────────────────────
#
# Every observation below is derived from fields actually present in the packet.
# There are no fixed confidence percentages: a score is the sum of the weights
# of the indicators that genuinely fired, and each indicator carries the basis
# on which it fired so a reader can check the reasoning.
#
# Weights (documented, deterministic):
#   40  known-dangerous service exposed to a public peer
#   30  cleartext credential-bearing request
#   25  administrative interface access
#   20  remote-access protocol
#   15  cleartext protocol carrying data
#   10  protocol anomaly / unusual structure
#    5  routine egress to a public address
#
# Score -> signal:  >=50 STRONG,  >=25 MODERATE,  >0 WEAK,  0 NONE
# "Signal" describes how much evidence was observed. It is NOT a probability
# and is never presented as one.

_SIGNAL_STRONG = "STRONG"
_SIGNAL_MODERATE = "MODERATE"
_SIGNAL_WEAK = "WEAK"
_SIGNAL_NONE = "NONE"

_SERVICE_PORTS = {
    20: ("FTP data", 15, "cleartext"),
    21: ("FTP control", 15, "cleartext"),
    22: ("SSH", 20, "remote-access"),
    23: ("Telnet", 30, "cleartext-remote-access"),
    25: ("SMTP", 15, "mail"),
    53: ("DNS", 0, "infrastructure"),
    80: ("HTTP", 15, "cleartext"),
    110: ("POP3", 15, "cleartext"),
    143: ("IMAP", 15, "cleartext"),
    443: ("HTTPS/TLS", 0, "encrypted"),
    445: ("SMB", 25, "file-sharing"),
    1433: ("MSSQL", 20, "database"),
    3306: ("MySQL", 20, "database"),
    3389: ("RDP", 20, "remote-access"),
    5432: ("PostgreSQL", 20, "database"),
    5900: ("VNC", 20, "remote-access"),
    8080: ("HTTP-alt", 15, "cleartext"),
}


def _signal_for(score: int) -> str:
    if score >= 50:
        return _SIGNAL_STRONG
    if score >= 25:
        return _SIGNAL_MODERATE
    if score > 0:
        return _SIGNAL_WEAK
    return _SIGNAL_NONE


def _infer_activity(info: dict) -> dict:
    """Classify a packet from observed fields only.

    Returns a dict containing the observation, the evidence list that produced
    it, a deterministic score, and a signal level. Language is deliberately
    hedged: this function reports what was *observed*, and labels anything
    beyond that as a heuristic indication.
    """
    proto = info.get("proto", "")
    try:
        sp = int(info.get("src_port") or 0)
        dp = int(info.get("dst_port") or 0)
    except (TypeError, ValueError):
        sp = dp = 0
    ports = {p for p in (sp, dp) if p}

    remote = info.get("dst_ip", "")
    remote_is_public = bool(remote) and not is_private_ip(remote)

    evidence: list[dict] = []
    score = 0

    def add(indicator: str, weight: int, basis: str) -> None:
        nonlocal score
        evidence.append({"indicator": indicator, "weight": weight, "basis": basis})
        score = min(100, score + weight)

    observation = f"{proto or 'Unknown protocol'} packet observed"
    encrypted_note = ""

    # ── Service identification from port numbers ─────────────────────────────
    service = ""
    for port in sorted(ports):
        if port in _SERVICE_PORTS:
            name, weight, kind = _SERVICE_PORTS[port]
            service = name
            observation = f"{name} traffic observed"
            if weight:
                scope = "public peer" if remote_is_public else "local peer"
                add(f"{name} service port", weight if remote_is_public else max(weight - 10, 5),
                    f"port {port} ({kind}) with {scope}")
            if kind == "encrypted":
                encrypted_note = (
                    "Payload is TLS-encrypted; contents were not decrypted. "
                    "Only endpoint metadata is available."
                )
            break

    # ── DNS: structural observations only ────────────────────────────────────
    if proto == "DNS":
        d = info.get("dns") or {}
        qname = (d.get("query") or "").lower()
        observation = "DNS query observed" if d.get("type") == "QUERY" else "DNS response observed"
        if qname:
            labels = qname.split(".")
            if len(qname) > 60:
                add("Long DNS name", 10, f"query name is {len(qname)} characters")
            if len(labels) >= 6:
                add("Deeply nested DNS name", 10, f"{len(labels)} labels in query name")
            longest = max((len(l) for l in labels), default=0)
            if longest >= 40:
                add("Long single DNS label", 10, f"longest label is {longest} characters")
        if d.get("rcode") == 3:
            add("NXDOMAIN response", 10, "server reported the name does not exist")
            observation = "DNS lookup failed (NXDOMAIN)"

    # ── HTTP: only ever from genuinely plaintext traffic ─────────────────────
    elif proto == "HTTP":
        hh = info.get("http") or {}
        method = (hh.get("method") or "").upper()
        path = (hh.get("path") or "").lower()
        host = (hh.get("host") or "").lower()
        if method:
            observation = f"Cleartext HTTP {method} request observed"
        else:
            observation = "Cleartext HTTP response observed"
        add("Cleartext HTTP", 15, "request/response readable on the wire")

        auth_terms = ("login", "signin", "auth", "token", "oauth", "password", "session")
        admin_terms = ("admin", "wp-admin", "dashboard", "manager", "phpmyadmin")
        matched_auth = [t for t in auth_terms if t in path]
        matched_admin = [t for t in admin_terms if t in path]

        if method == "POST" and matched_auth:
            add("Credential-bearing POST over cleartext", 30,
                f"POST to path containing {matched_auth[0]!r}")
            observation = "Potential credential submission over cleartext HTTP"
        elif matched_auth:
            add("Authentication-related path", 10,
                f"path contains {matched_auth[0]!r}")
        if matched_admin:
            add("Administrative interface path", 25,
                f"path contains {matched_admin[0]!r}")
            observation = "Administrative interface access observed"
        if host and remote_is_public:
            add("External web request", 5, f"Host header {host!r} on a public peer")

    elif proto == "ICMP":
        observation = "ICMP message observed"

    elif proto == "ARP":
        observation = "ARP exchange observed on local segment"

    # ── Generic egress ───────────────────────────────────────────────────────
    if remote_is_public and proto in ("TCP", "UDP", "HTTP", "DNS") and not evidence:
        add("Egress to public address", 5, f"destination {remote} is globally routable")

    signal = _signal_for(score)
    result = {
        "observation": observation,
        "signal": signal,
        "score": score,
        "evidence": evidence,
        "service": service or None,
    }
    if encrypted_note:
        result["encryption_note"] = encrypted_note
    if not evidence:
        result["evidence_note"] = "No scored indicators; routine traffic."
    return result


def _attribution_fields(attr: dict) -> dict:
    """Flatten process attribution into packet fields, preserving the label."""
    return {
        "process": attr.get("process", ""),
        "process_attribution": attr.get("attribution", "UNKNOWN"),
        "process_basis": attr.get("reason", ""),
    }


def _record_finding(info: dict, src_ip: str, dst_ip: str) -> None:
    """Record a scored observation. Only indicators that actually fired qualify."""
    intel = info.get("intel") or {}
    if intel.get("signal") in ("STRONG", "MODERATE"):
        _investigation_hits.append({
            "time": info.get("timestamp", ""),
            "src": src_ip or "UNKNOWN",
            "dst": dst_ip or "UNKNOWN",
            "proto": info.get("proto", ""),
            "observation": intel.get("observation", ""),
            "signal": intel.get("signal", ""),
            "score": intel.get("score", 0),
            "evidence": intel.get("evidence", []),
        })


def _should_stop(pkt) -> bool:
    if _stop_sniffing: return True
    if _sniff_duration>0 and _sniff_start_time and time.time()-_sniff_start_time>=_sniff_duration: return True
    return False

def _render_process(info: dict) -> str:
    """Show attribution honestly: confirmed, inferred, or unknown."""
    attr = info.get("process_attribution", "UNKNOWN")
    name = info.get("process", "")
    if attr == "EXACT" and name:
        return f"  [dim italic]{rescape(name)}[/dim italic]"
    if attr == "INFERRED" and name:
        return f"  [dim italic]{rescape(name)}[/dim italic] [yellow](INFERRED)[/yellow]"
    return "  [dim italic]proc:UNKNOWN[/dim italic]"


def _log_packet(info: dict) -> None:
    """Record a packet: complete to NDJSON on disk, bounded in memory."""
    _packet_log.append(dict(info))
    if _ndjson_fh is not None:
        try:
            _ndjson_fh.write(json.dumps(info, default=str) + "\n")
        except (OSError, TypeError, ValueError) as e:
            log.warning("NDJSON write failed: %s: %s", type(e).__name__, e)


def _render(info: dict) -> None:
    if _draining:
        return
    p   = info.get("proto","?"); src=info.get("src_ip","?"); dst=info.get("dst_ip","?")
    sp  = info.get("src_port",""); dp=info.get("dst_port",""); ts=info.get("timestamp","")
    geo = info.get("geo",{}); size=info.get("size",0)
    cm  = {"TCP":"cyan","UDP":"yellow","ICMP":"green","DNS":"magenta","ARP":"blue","HTTP":"bright_green"}
    c   = cm.get(p,"white")
    lines=[
        f"[dim]{ts}[/dim]  [{c}]{p}[/{c}]  [bold white]{src}[/bold white]"
        f"{':[yellow]'+str(sp)+'[/yellow]' if sp else ''}  [dim]→[/dim]  "
        f"[bold white]{dst}[/bold white]{':[green]'+str(dp)+'[/green]' if dp else ''}  [dim]{size}B[/dim]"
        + _render_process(info)
    ]
    if info.get("mac_src"): lines.append(f"  [dim]L2  MAC[/dim]  {info['mac_src']} [dim]→[/dim] {info['mac_dst']}")
    if info.get("ttl"):     lines.append(f"  [dim]L3  IP[/dim]   TTL={info['ttl']}")
    if info.get("tcp_flags"):
        l4=f"  [dim]L4  TCP[/dim]  flags=[yellow]{info['tcp_flags']}[/yellow]"
        if info.get("window"): l4+=f"  win={info['window']}"
        if info.get("seq"):    l4+=f"  seq={info['seq']}"
        lines.append(l4)
    country=geo.get("country","")
    if country and country not in("Unknown","LAN"):
        city=geo.get("city",""); org=geo.get("org","")
        lines.append(f"  [dim]GEO      [/dim]  [cyan]{country}[/cyan]"+(f", {city}" if city and city!="Unknown" else "")+(f"  [dim]{org}[/dim]" if org else ""))
    if info.get("rdns"): lines.append(f"  [dim]rDNS     [/dim]  [dim]{rescape(str(info['rdns']))}[/dim]")
    h=info.get("http")
    if h:
        if h.get("type")=="REQUEST":
            lines.append(f"  [dim]HTTP     [/dim]  [bright_green]{rescape(str(h['method']))}[/bright_green] [white]{rescape(str(h.get('host','')) + str(h.get('path','')))}[/white]")
            if h.get("user_agent"): lines.append(f"  [dim]  User-Agent[/dim]  {rescape(truncate(str(h['user_agent']),60))}")
            if h.get("referer"):    lines.append(f"  [dim]  Referer  [/dim]  {rescape(str(h['referer']))}")
            if h.get("body"):       lines.append(f"  [dim]  Body     [/dim]  [yellow]{truncate(h['body'],120)}[/yellow]")
        elif h.get("type")=="RESPONSE":
            sc=h.get("status_code",""); sc_col="green" if sc.startswith("2") else "yellow" if sc.startswith("3") else "red"
            lines.append(f"  [dim]HTTP     [/dim]  [{sc_col}]{sc} {h.get('status_text','')}[/{sc_col}]"+(f"  {h.get('content_type','')}" if h.get("content_type") else ""))
            if h.get("server"): lines.append(f"  [dim]  Server[/dim]  {h['server']}")
    di=info.get("dns")
    if di:
        if di.get("type")=="QUERY":
            lines.append(f"  [dim]DNS      [/dim]  [magenta]? {rescape(str(di.get('query','')))}[/magenta]  [dim]{rescape(str(di.get('qtype','')))}[/dim]")
        elif di.get("type")=="RESPONSE":
            ans=di.get("answers",[])
            if di.get("rcode")==3:
                lines.append(f"  [dim]DNS      [/dim]  [red]NXDOMAIN[/red] {di.get('query','')}")
            else:
                answer_text = ""
                if ans:
                    if isinstance(ans[0], dict):
                        answer_text = ", ".join(str(a.get("data", "")) for a in ans[:3])
                    else:
                        answer_text = ", ".join(str(a) for a in ans[:3])
                lines.append(
                    f"  [dim]DNS      [/dim]  [magenta]{di.get('query','')}[/magenta]"
                    + (f"  [dim]→[/dim]  [green]{answer_text}[/green]" if answer_text else "")
                )
    intel = info.get("intel")
    if intel:
        sig = intel.get("signal", "NONE")
        sc = {"STRONG": "red", "MODERATE": "yellow", "WEAK": "cyan"}.get(sig, "dim")
        lines.append(
            f"  [dim]OBSERVED [/dim]  [bold]{rescape(str(intel.get('observation','')))}[/bold]"
            f"  [{sc}]signal={sig}[/{sc}]"
            f"  [dim]score={intel.get('score',0)}/100[/dim]"
        )
        for ev in intel.get("evidence", [])[:3]:
            lines.append(
                f"  [dim]  +{ev.get('weight',0):<3}[/dim]  [dim]{rescape(str(ev.get('indicator','')))}"
                f" — {rescape(str(ev.get('basis','')))}[/dim]"
            )
        if intel.get("encryption_note"):
            lines.append(f"  [dim]  NOTE   [/dim]  [dim]{rescape(intel['encryption_note'])}[/dim]")
    console.print("\n".join(lines))
    console.print("[dim]"+"─"*100+"[/dim]")

def _process_packet(pkt) -> None:
    global _stats
    cfg = get_config().sensor
    with _lock:
        _stats["total"] += 1
        _stats["bytes"] += len(pkt)

    info: dict = {
        "timestamp": utc_now().strftime("%H:%M:%S.%f")[:-3],
        "ts_epoch": time.time(),
        "size": len(pkt),
        "proto": "OTHER",
    }
    if pkt.haslayer(Ether):
        info["mac_src"] = pkt[Ether].src
        info["mac_dst"] = pkt[Ether].dst

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        info.update({"proto": "ARP", "src_ip": arp.psrc, "dst_ip": arp.pdst})
        with _lock:
            _stats["arp"] += 1
        _log_packet(info)
        _render(info)
        return

    if pkt.haslayer(IP):
        ip = pkt[IP]
        info["src_ip"] = ip.src
        info["dst_ip"] = ip.dst
        info["ttl"] = ip.ttl
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        info["src_ip"] = ip6.src
        info["dst_ip"] = ip6.dst
    else:
        return

    src_ip = info.get("src_ip", "")
    dst_ip = info.get("dst_ip", "")

    if cfg.show_geoip:
        src_geo, src_rdns = _endpoint_intel(src_ip)
        dst_geo, dst_rdns = _endpoint_intel(dst_ip)
        info["src_geo"] = src_geo
        info["dst_geo"] = dst_geo
        if src_rdns:
            info["src_rdns"] = src_rdns
        if dst_rdns:
            info["dst_rdns"] = dst_rdns
        info["geo"] = dst_geo
        if dst_rdns:
            info["rdns"] = dst_rdns
        with _lock:
            if src_ip:
                _ips_seen[src_ip] = src_geo
            if dst_ip:
                _ips_seen[dst_ip] = dst_geo

    if pkt.haslayer(ICMP):
        info["proto"] = "ICMP"
        with _lock:
            _stats["icmp"] += 1
        info["intel"] = _infer_activity(info)
        _record_finding(info, src_ip, dst_ip)
        _log_packet(info)
        _render(info)
        return

    if pkt.haslayer(DNS) and cfg.show_dns:
        info["proto"] = "DNS"
        info["src_port"] = pkt[UDP].sport if pkt.haslayer(UDP) else ""
        info["dst_port"] = pkt[UDP].dport if pkt.haslayer(UDP) else ""
        dp = _parse_dns_pkt(pkt)
        info["dns"] = dp
        if dp and dp.get("query"):
            with _lock:
                _domains_seen.add(dp["query"])
        with _lock:
            _stats["dns"] += 1
        info["intel"] = _infer_activity(info)
        _record_finding(info, src_ip, dst_ip)
        _log_packet(info)
        _render(info)
        return

    if pkt.haslayer(UDP):
        info.update({"proto": "UDP", "src_port": pkt[UDP].sport, "dst_port": pkt[UDP].dport})
        with _lock:
            _stats["udp"] += 1
        info["intel"] = _infer_activity(info)
        _record_finding(info, src_ip, dst_ip)
        _log_packet(info)
        _render(info)
        return

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        info.update({
            "proto": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "tcp_flags": _tcp_flags(tcp.flags),
            "window": tcp.window,
            "seq": tcp.seq,
            "ack": tcp.ack,
            **_attribution_fields(_find_process(tcp.sport, tcp.dport, src_ip, dst_ip)),
        })
        with _lock:
            _connections[f"{src_ip}:{tcp.sport}"] = {
                "src": src_ip,
                "dst": dst_ip,
                "sport": tcp.sport,
                "dport": tcp.dport,
                "flags": str(tcp.flags),
            }
        if pkt.haslayer(Raw) and cfg.show_http:
            h = _parse_http(bytes(pkt[Raw]))
            if h:
                info["proto"] = "HTTP"
                info["http"] = h
                with _lock:
                    _stats["http"] += 1
                    _http_requests.append({
                        "time": info["timestamp"],
                        "src": src_ip,
                        "dst": dst_ip,
                        "method": h.get("method", ""),
                        "host": h.get("host", ""),
                        "path": h.get("path", ""),
                        "ua": h.get("user_agent", ""),
                        "referer": h.get("referer", ""),
                        "body": h.get("body", ""),
                    })
        info["intel"] = _infer_activity(info)
        _record_finding(info, src_ip, dst_ip)
        with _lock:
            _stats["tcp"] += 1
        _log_packet(info)
        _render(info)
        return

    info["intel"] = _infer_activity(info)
    _log_packet(info)
    _render(info)


def _packet_callback(pkt) -> None:
    """Sniff callback. Writes the frame to the PCAP immediately so the on-disk
    capture is complete, then hands the packet to the render worker.

    Rendering is allowed to fall behind and drop; the PCAP never does.
    """
    global _packet_queue
    if _pcap_writer is not None:
        try:
            _pcap_writer.write(pkt)
        except (OSError, ValueError) as e:
            log.warning("PCAP write failed: %s: %s", type(e).__name__, e)
    if _packet_queue is None:
        return
    try:
        _packet_queue.put_nowait(pkt)
    except queue.Full:
        # Render queue saturated. The packet is already on disk; count the
        # render drop so the session can report it honestly.
        _stats["render_dropped"] = _stats.get("render_dropped", 0) + 1


def _worker_loop() -> None:
    """Drain the render queue until stopped AND empty, then exit.

    Runs as a normal (non-daemon) thread so the caller can join it and be
    certain no processing continues after the module reports it stopped.
    """
    global _draining
    while True:
        try:
            pkt = _packet_queue.get(timeout=0.3)
        except queue.Empty:
            if _stop_sniffing:
                return
            continue
        if _stop_sniffing and not _draining:
            # Capture has stopped; finish recording the backlog without paying
            # for terminal rendering, so shutdown stays bounded.
            _draining = True
            qsize = _packet_queue.qsize()
            if qsize > 50:
                console.print(f"  [dim]Draining {qsize:,} queued packets...[/dim]")
        try:
            _process_packet(pkt)
        except (AttributeError, IndexError, ValueError, KeyError, UnicodeDecodeError) as e:
            _stats["parse_errors"] = _stats.get("parse_errors", 0) + 1
            log.warning("packet parse error: %s: %s", type(e).__name__, e)
        finally:
            _packet_queue.task_done()


# ── Report Generator ──────────────────────────────────────────────────────────

def _geo_field(ip: str, key: str) -> str:
    """Return a GeoIP field, or an explicit marker. Never invents a location."""
    g = _ips_seen.get(ip, {}) or {}
    if g.get("source") == "local":
        return {"country": "LAN", "city": "Local", "org": "Private Network"}.get(key, "LAN")
    if not g.get("available"):
        return "UNAVAILABLE"
    return str(g.get(key) or "UNKNOWN")


def _geo_country(p: dict) -> str:
    ip = p.get("dst_ip") or ""
    return _geo_field(ip, "country") if ip else ""


def _generate_report(save_path: str, session) -> str:
    """Render the HTML report from THIS session only.

    Every value interpolated below is escaped: captured data (Host headers,
    User-Agents, DNS names) is attacker-controlled and this document is
    opened in a browser.
    """
    sess = session.to_dict()
    now = utc_now(); ts_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    elapsed = session.actual_duration
    pps = _stats["total"] / max(elapsed, 1e-6)
    iface = sess["interface"]; bpf = sess["bpf_filter"]
    dur_label = "{:.1f}s measured".format(elapsed)
    protos:dict[str,int]=defaultdict(int)
    for p in _packet_log: protos[p.get("proto","OTHER")]+=1
    dst_counts:dict[str,int]=defaultdict(int)
    for p in _packet_log:
        if p.get("dst_ip"): dst_counts[p["dst_ip"]]+=1
    top_dsts=sorted(dst_counts.items(),key=lambda x:x[1],reverse=True)[:15]
    ip_counts:dict[str,int]=defaultdict(int)
    for p in _packet_log:
        if p.get("src_ip"): ip_counts[p["src_ip"]] += 1
        if p.get("dst_ip"): ip_counts[p["dst_ip"]] += 1
    top_ips=sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:30]
    domain_list=sorted(_domains_seen)[:40]
    conn_list=list(_connections.values())[:60]
    http_list=_http_requests[:60]
    country_counts:dict[str,int]=defaultdict(int)
    for ip, g in _ips_seen.items():
        if not (g.get("available") or g.get("source") == "local"):
            continue
        c = g.get("country")
        if c and c not in ("Unknown", "UNAVAILABLE"):
            country_counts[c] += 1
    top_countries=sorted(country_counts.items(),key=lambda x:x[1],reverse=True)[:10]
    high_hits = [x for x in _investigation_hits if x.get("signal") == "STRONG"][:80]
    med_hits = [x for x in _investigation_hits if x.get("signal") == "MODERATE"][:80]
    max_cnt=top_dsts[0][1] if top_dsts else 1
    max_co =top_countries[0][1] if top_countries else 1

    proto_colors={"HTTP":"#39d353","TCP":"#00d4ff","DNS":"#c09ffd","UDP":"#f0e040","ICMP":"#50fa7b","ARP":"#79c0ff","OTHER":"#888"}

    def badge(p): c=proto_colors.get(p,"#888"); return f"<span style='font-size:10px;padding:2px 7px;border-radius:3px;border:1px solid {c}44;background:{c}18;color:{c};font-weight:700'>{p}</span>"
    def method_badge(m):
        c="#39d353" if m=="GET" else "#ff4444" if m=="POST" else "#f0e040"
        return f"<span style='font-size:10px;padding:2px 7px;border-radius:3px;border:1px solid {c}44;background:{c}18;color:{c};font-weight:700'>{m}</span>"

    def _detail_cell(p):
        if p.get("http"):
            hh = p.get("http") or {}
            return esc("{} {}{}".format(hh.get("method", ""), hh.get("host", ""), hh.get("path", "")))
        if p.get("dns"):
            return esc((p.get("dns") or {}).get("query", ""))
        return ""

    def _proc_cell(p):
        attr = p.get("process_attribution", "UNKNOWN")
        name = p.get("process", "")
        if attr == "EXACT" and name:
            return esc(name)
        if attr == "INFERRED" and name:
            return esc(name) + " <span style='color:#f0e040;font-size:9px'>INFERRED</span>"
        return "<span class='dim'>UNKNOWN</span>"

    pkt_rows = "".join(
        "<tr><td class='ts'>{}</td><td>{}</td>"
        "<td class='mono'>{}:{}</td><td class='mono'>{}:{}</td>"
        "<td class='right'>{}B</td><td class='dim'>{}</td>"
        "<td class='detail'>{}</td><td class='detail'>{}</td>"
        "<td class='dim'>{}</td></tr>".format(
            esc(p.get("timestamp", "")),
            badge(p.get("proto", "?")),
            esc(p.get("src_ip", "?")), esc(p.get("src_port", "")),
            esc(p.get("dst_ip", "?")), esc(p.get("dst_port", "")),
            esc(p.get("size", 0)),
            esc(_geo_country(p)),
            _detail_cell(p),
            esc((p.get("intel") or {}).get("observation", "")),
            _proc_cell(p),
        )
        for p in list(_packet_log)[-300:]
    ) or "<tr><td colspan='9' class='dim'>No packets captured</td></tr>"

    def _sig_badge(sig):
        col = {"STRONG": "#ff6b6b", "MODERATE": "#f0e040"}.get(sig, "#888")
        return ("<span style='font-size:10px;padding:2px 7px;border-radius:3px;"
                "border:1px solid {c}44;background:{c}18;color:{c};font-weight:700'>{s}</span>"
                ).format(c=col, s=esc(sig))

    def _evidence_cell(x):
        ev = x.get("evidence") or []
        if not ev:
            return "<span class='dim'>no scored indicators</span>"
        return "<br>".join(
            "+{} {} <span class='dim'>({})</span>".format(
                esc(e.get("weight", 0)), esc(e.get("indicator", "")), esc(e.get("basis", "")))
            for e in ev[:4]
        )

    intel_rows = "".join(
        "<tr><td class='ts'>{}</td><td class='mono'>{}</td><td class='mono'>{}</td>"
        "<td>{}</td><td class='detail'>{}</td><td class='dim'>{}</td>"
        "<td class='right'>{}/100</td></tr>".format(
            esc(x.get("time", "")), esc(x.get("src", "")), esc(x.get("dst", "")),
            _sig_badge(x.get("signal", "")),
            esc(x.get("observation", "")),
            _evidence_cell(x),
            esc(x.get("score", 0)),
        )
        for x in (high_hits + med_hits)
    ) or "<tr><td colspan='7' class='dim'>No scored indicators observed in this capture</td></tr>"

    http_rows = "".join(
        "<tr><td class='ts'>{}</td><td>{}</td><td class='mono'>{}</td>"
        "<td class='detail'>{}</td><td class='dim'>{}</td></tr>".format(
            esc(x["time"]), method_badge(x["method"]), esc(x["src"]),
            esc(str(x["host"]) + str(x["path"])[:80]), esc(str(x["ua"])[:50]),
        )
        for x in http_list
    ) or "<tr><td colspan='5' class='dim'>No cleartext HTTP observed (HTTPS is not decrypted)</td></tr>"

    dns_rows = "".join(
        "<tr><td class='mono'>{}</td></tr>".format(esc(d)) for d in domain_list
    ) or "<tr><td class='dim'>No DNS queries observed</td></tr>"
    conn_rows = "".join(
        "<tr><td class='mono'>{}:{}</td><td class='mono'>{}:{}</td><td class='dim'>{}</td></tr>".format(
            esc(c.get("src", "")), esc(c.get("sport", "")),
            esc(c.get("dst", "")), esc(c.get("dport", "")), esc(c.get("flags", "")))
        for c in conn_list
    ) or "<tr><td colspan='3' class='dim'>No connections observed</td></tr>"

    ip_rows = "".join(
        "<tr><td class='mono'>{}</td><td class='right'>{}</td><td class='dim'>{}</td>"
        "<td class='dim'>{}</td><td><div style='width:{}px;height:6px;"
        "background:#00d4ff44;border-radius:2px'></div></td></tr>".format(
            esc(ip), esc(cnt), esc(_geo_field(ip, "country")),
            esc(str(_geo_field(ip, "org"))[:35]), int(cnt / max_cnt * 100))
        for ip, cnt in top_dsts
    ) or "<tr><td colspan='5' class='dim'>No destination data</td></tr>"

    def _coord(ip, key):
        g = _ips_seen.get(ip, {}) or {}
        if not (g.get("available") or g.get("source") == "local"):
            return "UNAVAILABLE"
        v = g.get(key)
        return "{:.5f}".format(float(v)) if isinstance(v, (int, float)) else "UNKNOWN"

    ip_intel_rows = "".join(
        "<tr><td class='mono'>{}</td><td class='dim'>{}</td><td class='dim'>{}</td>"
        "<td class='dim'>{}</td><td class='mono'>{}</td><td class='mono'>{}</td>"
        "<td class='dim'>{}</td></tr>".format(
            esc(ip),
            esc(_dns_cache.get(ip) or "NOT RESOLVED"),
            esc(_geo_field(ip, "country")),
            esc(_geo_field(ip, "city")),
            esc(_coord(ip, "lat")), esc(_coord(ip, "lon")),
            esc(str(_geo_field(ip, "org"))[:30]),
        )
        for ip, _ in top_ips
    ) or "<tr><td colspan='7' class='dim'>No IP intelligence collected</td></tr>"

    country_rows = "".join(
        "<tr><td>{}</td><td class='right'>{}</td><td><div style='width:{}px;height:6px;"
        "background:#c09ffd44;border-radius:2px'></div></td></tr>".format(
            esc(co), esc(cnt), int(cnt / max_co * 120))
        for co, cnt in top_countries
    ) or "<tr><td colspan='3' class='dim'>No geo data available</td></tr>"

    def _proto_bar(p, v):
        col = proto_colors.get(p, "#888")
        tot = max(_stats["total"], 1)
        pct = int(v / tot * 100)
        return (
            f"<div style='display:flex;align-items:center;gap:10px;margin-bottom:7px'>"
            f"<div style='width:55px;font-size:11px;font-weight:700;color:{col}'>{p}</div>"
            f"<div style='flex:1;height:10px;background:#111;border-radius:2px;overflow:hidden'>"
            f"<div style='width:{pct}%;height:100%;background:{col}44;border-radius:2px'></div></div>"
            f"<div style='width:55px;text-align:right;font-size:11px;color:#555'>{v:,}</div>"
            f"</div>"
        )
    proto_bars = "".join(
        _proto_bar(p, v)
        for p, v in sorted(protos.items(), key=lambda x: x[1], reverse=True) if v > 0
    )

    limitation_rows = "".join(
        "<tr><td colspan='2'>{}</td></tr>".format(esc(t)) for t in sess["limitations"]
    ) or "<tr><td colspan='2' class='dim'>None recorded</td></tr>"
    unavailable_rows = "".join(
        "<tr><td class='mono'>{}</td><td class='dim'>{}</td></tr>".format(
            esc(u["feature"]), esc(u["reason"])) for u in sess["unavailable_features"]
    ) or "<tr><td colspan='2' class='dim'>Nothing was unavailable</td></tr>"
    error_rows = "".join(
        "<tr><td class='mono'>{}</td><td class='dim'>{}</td></tr>".format(
            esc(e["where"]), esc(e["error"])) for e in sess["errors"]
    ) or "<tr><td colspan='2' class='dim'>No errors recorded</td></tr>"

    html=f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PacketPulse Report — {ts_str}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#080808;color:#c8c8c8;font-family:'JetBrains Mono','Courier New',monospace;font-size:13px;line-height:1.6}}
.header{{background:#0a0f0a;border-bottom:2px solid #0f2a0f;padding:32px 40px 24px}}
.logo-row{{display:flex;align-items:flex-start;gap:20px;margin-bottom:20px}}
.ascii{{color:#00ff41;font-size:9px;line-height:1.05;font-weight:700;white-space:pre}}
.title-block .t1{{font-size:30px;font-weight:700;color:#00ff41;letter-spacing:4px}}
.title-block .t2{{font-size:11px;color:#39d353;letter-spacing:2px;margin-top:3px}}
.title-block .t3{{font-size:10px;color:#1a4a1a;margin-top:6px}}
.title-block .t3 span{{color:#39d353}}
.dw-badge{{display:inline-block;margin-top:8px;padding:4px 10px;border-radius:999px;border:1px solid #00d4ff55;background:#00d4ff1a;color:#8be9fd;font-size:9px;letter-spacing:1px;text-transform:uppercase}}
.meta-row{{display:flex;gap:12px;flex-wrap:wrap}}
.meta-card{{background:#0d150d;border:1px solid #1a2e1a;border-radius:4px;padding:10px 16px}}
.meta-card .l{{font-size:10px;color:#444;text-transform:uppercase;letter-spacing:1px;margin-bottom:3px}}
.meta-card .v{{font-size:13px;color:#e8edf3;font-weight:700}}
.stats{{display:flex;gap:10px;padding:18px 40px;border-bottom:1px solid #0f0f0f;flex-wrap:wrap}}
.sc{{background:#0d0d0d;border:1px solid #151515;border-radius:4px;padding:12px 18px;flex:1;min-width:90px}}
.sn{{font-size:26px;font-weight:700;line-height:1}}
.sl{{font-size:9px;color:#444;text-transform:uppercase;letter-spacing:1px;margin-top:3px}}
.body{{padding:28px 40px}}
.section{{margin-bottom:36px}}
.sh{{font-size:10px;color:#00d4ff;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px;padding-bottom:7px;border-bottom:1px solid #0f0f0f;display:flex;align-items:center;gap:8px}}
.sh::before{{content:'';width:3px;height:12px;background:#00d4ff;border-radius:1px;display:inline-block}}
.sh .sub{{color:#333;font-size:9px;text-transform:none;letter-spacing:0}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#0d0d0d;color:#444;font-size:9px;text-transform:uppercase;letter-spacing:1px;padding:7px 12px;text-align:left;border-bottom:1px solid #111}}
td{{padding:6px 12px;border-bottom:1px solid #0d0d0d;vertical-align:middle}}
tr:hover td{{background:#0d110d}}
.ts{{color:#444;white-space:nowrap;font-size:11px}}
.mono{{font-family:inherit;font-size:11px}}
.dim{{color:#555;font-size:11px}}
.right{{text-align:right}}
.detail{{color:#999;font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.two{{display:grid;grid-template-columns:1fr 1fr;gap:24px}}
@media(max-width:900px){{.two{{grid-template-columns:1fr}}}}
.footer{{background:#050505;border-top:1px solid #0f0f0f;padding:18px 40px;display:flex;justify-content:space-between;align-items:center;margin-top:24px}}
.fl{{color:#222;font-size:11px;line-height:1.8}}
.fr{{text-align:right}}
.fb{{font-size:15px;font-weight:700;color:#00ff41;letter-spacing:2px}}
.fs{{font-size:10px;color:#1a3a1a;margin-top:2px}}
.wm{{text-align:center;padding:14px;color:#111;font-size:9px;letter-spacing:4px;text-transform:uppercase}}
</style>
</head>
<body>

<div class="header">
  <div class="logo-row">
    <pre class="ascii">██████╗ ██████╗ 
██╔══██╗██╔══██╗
██████╔╝██████╔╝
██╔═══╝ ██╔═══╝ 
██║     ██║     
╚═╝     ╚═╝     </pre>
    <div class="title-block">
      <div class="t1">PACKETPULSE</div>
      <div class="t2">NETWORK FORENSIC CAPTURE REPORT</div>
      <div class="t3">Engineered by <span>Dreamwalker4u</span></div>
            <div class="dw-badge">Generated by Dreamwalker4u</div>
    </div>
    <div style="margin-left:auto;text-align:right">
      <div style="font-size:10px;color:#333">Report Generated</div>
      <div style="font-size:14px;color:#e8edf3;font-weight:700;margin-top:4px">{ts_str}</div>
    </div>
  </div>
  <div class="meta-row">
    <div class="meta-card"><div class="l">Session ID</div><div class="v">{esc(sess["session_id"])}</div></div>
    <div class="meta-card"><div class="l">Status</div><div class="v">{esc(sess["status"])}</div></div>
    <div class="meta-card"><div class="l">Interface</div><div class="v">{esc(iface or "auto")}</div></div>
    <div class="meta-card"><div class="l">BPF Filter</div><div class="v">{esc(bpf or "none — all traffic")}</div></div>
    <div class="meta-card"><div class="l">Requested</div><div class="v">{esc(sess["requested_duration_seconds"] or "until stopped")}</div></div>
    <div class="meta-card"><div class="l">Measured</div><div class="v">{sess["actual_duration_seconds"]:.1f}s</div></div>
    <div class="meta-card"><div class="l">Started</div><div class="v">{esc(sess["started_at"])}</div></div>
    <div class="meta-card"><div class="l">Ended</div><div class="v">{esc(sess["ended_at"] or "NOT RECORDED")}</div></div>
    <div class="meta-card"><div class="l">Avg Pkt/sec</div><div class="v">{pps:.1f}</div></div>
    <div class="meta-card"><div class="l">Unique IPs</div><div class="v">{len(_ips_seen):,}</div></div>
    <div class="meta-card"><div class="l">Unique Domains</div><div class="v">{len(_domains_seen):,}</div></div>
  </div>
</div>

<div class="stats">
  <div class="sc"><div class="sn" style="color:#00ff41">{_stats['total']:,}</div><div class="sl">Total Packets</div></div>
  <div class="sc"><div class="sn" style="color:#00d4ff">{_stats['tcp']:,}</div><div class="sl">TCP</div></div>
  <div class="sc"><div class="sn" style="color:#f0e040">{_stats['udp']:,}</div><div class="sl">UDP</div></div>
  <div class="sc"><div class="sn" style="color:#c09ffd">{_stats['dns']:,}</div><div class="sl">DNS</div></div>
  <div class="sc"><div class="sn" style="color:#39d353">{_stats['http']:,}</div><div class="sl">HTTP</div></div>
  <div class="sc"><div class="sn" style="color:#50fa7b">{_stats['icmp']:,}</div><div class="sl">ICMP</div></div>
  <div class="sc"><div class="sn" style="color:#79c0ff">{_stats['arp']:,}</div><div class="sl">ARP</div></div>
  <div class="sc"><div class="sn" style="color:#e8edf3">{human_bytes(_stats['bytes'])}</div><div class="sl">Data Captured</div></div>
</div>

<div class="body">

  <div class="two">
    <div class="section">
      <div class="sh">Protocol Breakdown</div>
      {proto_bars}
    </div>
    <div class="section">
      <div class="sh">Traffic by Country</div>
      <table><tr><th>Country</th><th>Conn</th><th>Volume</th></tr>{country_rows}</table>
    </div>
  </div>

  <div class="section">
    <div class="sh">Top Destination IPs <span class="sub">— {len(top_dsts)} shown</span></div>
    <table><tr><th>IP Address</th><th>Packets</th><th>Country</th><th>Organization</th><th>Volume</th></tr>{ip_rows}</table>
  </div>

    <div class="section">
        <div class="sh">IP Intelligence <span class="sub">— rDNS + GeoIP coordinates (approximate)</span></div>
        <table><tr><th>IP</th><th>Reverse DNS</th><th>Country</th><th>City</th><th>Lat</th><th>Lon</th><th>Org/ISP</th></tr>{ip_intel_rows}</table>
    </div>

    <div class="section">
        <div class="sh">Scored Observations <span class="sub">— indicators that actually fired, with their basis</span></div>
        <table><tr><th>Time</th><th>Source</th><th>Destination</th><th>Signal</th><th>Observation</th><th>Evidence (weight &amp; basis)</th><th>Score</th></tr>{intel_rows}</table>
    </div>

    <div class="section">
        <div class="sh">Packet Log <span class="sub">— last {min(300,len(_packet_log))} of {len(_packet_log):,} captured</span></div>
        <table><tr><th>Time</th><th>Proto</th><th>Source</th><th>Destination</th><th>Size</th><th>Country</th><th>Detail</th><th>Observation</th><th>Process</th></tr>{pkt_rows}</table>
  </div>

  <div class="section">
    <div class="sh">HTTP Requests <span class="sub">— {len(http_list)} shown</span></div>
    <table><tr><th>Time</th><th>Method</th><th>Source IP</th><th>URL</th><th>User-Agent</th></tr>{http_rows}</table>
  </div>

  <div class="two">
    <div class="section">
      <div class="sh">DNS Queries <span class="sub">— {len(_domains_seen):,} unique domains</span></div>
      <table><tr><th>Domain</th></tr>{dns_rows}</table>
    </div>
    <div class="section">
      <div class="sh">TCP Connections <span class="sub">— {len(conn_list)} tracked</span></div>
      <table><tr><th>Source</th><th>Destination</th><th>TCP Flags</th></tr>{conn_rows}</table>
    </div>
  </div>

</div>

<div class="body">
  <div class="sh">Provenance &amp; Limitations <span class="sub">— what this report can and cannot establish</span></div>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Packets captured</td><td class="mono">{_stats['total']:,}</td></tr>
    <tr><td>Packets rendered/analysed</td><td class="mono">{len(_packet_log):,}</td></tr>
    <tr><td>Render drops (present in PCAP)</td><td class="mono">{_stats.get('render_dropped', 0):,}</td></tr>
    <tr><td>Parse errors</td><td class="mono">{_stats.get('parse_errors', 0):,}</td></tr>
    <tr><td>Cleartext HTTP messages parsed</td><td class="mono">{_stats.get('http', 0):,}</td></tr>
    <tr><td>Session status</td><td class="mono">{esc(sess['status'])}</td></tr>
    <tr><td>Duration honoured</td><td class="mono">{esc('n/a (open-ended)' if sess['duration_honored'] is None else ('YES' if sess['duration_honored'] else 'NO'))}</td></tr>
  </table>
  <div style="margin-top:18px"></div>
  <div class="sh">Limitations</div>
  <table>
    {limitation_rows}
  </table>
  <div style="margin-top:18px"></div>
  <div class="sh">Unavailable This Run</div>
  <table>
    {unavailable_rows}
  </table>
  <div style="margin-top:18px"></div>
  <div class="sh">Errors Recorded</div>
  <table>
    {error_rows}
  </table>
</div>
<div class="footer">
  <div class="fl">
    PacketPulse Network Forensic Capture Report<br>
    Generated: {ts_str}<br>
    Packets captured: {_stats['total']:,}  •  Data: {human_bytes(_stats['bytes'])}  •  Duration: {dur_label}
  </div>
  <div class="fr">
    <div class="fb">PacketPulse | Dreamwalker4u</div>
    <div class="fs">Network Forensics Platform  •  v{__version__}</div>
  </div>
</div>
<div class="wm">PacketPulse | Dreamwalker4u  •  Network Forensic Capture Report  •  {ts_str}</div>
</body>
</html>"""

    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    with open(save_path,"w",encoding="utf-8") as f: f.write(html)
    return save_path


def _packet_intel_line(p: dict) -> str:
    intel = p.get("intel") or {}
    if not intel:
        return "observation=none signal=NONE score=0"
    return "observation={} signal={} score={}".format(
        intel.get("observation", "none"),
        intel.get("signal", "NONE"),
        intel.get("score", 0),
    )


def _packet_detail_line(p: dict) -> str:
    if p.get("http"):
        h = p.get("http") or {}
        return f"HTTP {h.get('method','')} {h.get('host','')}{h.get('path','')}"
    if p.get("dns"):
        d = p.get("dns") or {}
        return f"DNS {d.get('type','')} {d.get('query','')}"
    return ""


def _endpoint_intel(ip: str):
    """GeoIP + reverse DNS for an endpoint, without blocking the packet path."""
    if not ip:
        return ({"country": UNKNOWN, "city": UNKNOWN, "lat": 0.0, "lon": 0.0,
                 "org": "", "source": "none", "available": False}, "")
    if is_private_ip(ip):
        return ({"country": "LAN", "city": "Local", "lat": 0.0, "lon": 0.0,
                 "org": "Private Network", "source": "local", "available": True}, "")
    geo = _geo(ip)
    return geo, _dns_cache.get(ip, "")


def _fmt_ip(ip: str) -> str:
    if not ip:
        return "unknown"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x"
    return ip


def _analyze_capture_summary(session) -> dict:
    """Summarise what was actually observed.

    This function reports counts and describes patterns. It does not assign an
    overall "risk" — the previous version defaulted to MEDIUM regardless of
    evidence and averaged hardcoded confidence values into a percentage. Where
    a pattern merely resembles a known protocol, the language says so.
    """
    packets = list(_packet_log)
    total = len(packets)
    observed: list[str] = []
    not_determinable: list[str] = [
        "Payload contents of TLS/HTTPS traffic (encrypted; not decrypted)",
        "Domains inside encrypted tunnels or DNS-over-HTTPS",
        "File names or content transferred over encrypted channels",
        "Process ownership of sockets belonging to other users without elevation",
    ]

    if total == 0:
        if session.get("packets_captured"):
            headline = ["Packets were captured but no records were retained for analysis."]
        else:
            headline = ["No packets were captured during this session."]
        return {
            "headline": headline,
            "observed": [],
            "not_determinable": not_determinable,
            "summary": "NO DATA — nothing was observed to analyse.",
            "signal_counts": {},
        }

    proto_counts = Counter((p.get("proto") or "OTHER") for p in packets)
    port_counts = Counter()
    unique_ips = set()
    for p in packets:
        for key in ("src_ip", "dst_ip"):
            if p.get(key):
                unique_ips.add(p[key])
        for po in (p.get("src_port"), p.get("dst_port")):
            if po:
                try:
                    port_counts[int(po)] += 1
                except (TypeError, ValueError):
                    continue

    elapsed = session.actual_duration if hasattr(session, "actual_duration") else 0.0
    pps = _stats["total"] / max(elapsed, 1e-6)

    signal_counts = Counter(x.get("signal", "NONE") for x in _investigation_hits)

    headline = [
        "{:,} packets captured in {:.1f}s ({:.1f} packets/sec)".format(_stats["total"], elapsed, pps),
        "{} transferred | {} unique addresses | {} distinct ports".format(
            human_bytes(_stats["bytes"]), len(unique_ips), len(port_counts)),
    ]

    # Protocol composition — a fact.
    observed.append("Protocol mix: " + ", ".join(
        "{} {}".format(k, v) for k, v in proto_counts.most_common(6)))

    if _stats.get("http", 0) == 0:
        observed.append(
            "No cleartext HTTP observed. Any web traffic present was encrypted, "
            "so request contents are not available.")
    else:
        observed.append("{} cleartext HTTP messages observed and parsed.".format(_stats["http"]))

    if _stats.get("dns", 0):
        observed.append("{} DNS messages observed; {} unique names.".format(
            _stats["dns"], len(_domains_seen)))
    else:
        observed.append("No DNS traffic observed in this capture window.")

    # Dominant port — described, not diagnosed.
    if port_counts:
        dport, dcount = port_counts.most_common(1)[0]
        share = dcount / max(sum(port_counts.values()), 1) * 100
        note = ""
        if dport == 51820 and proto_counts.get("UDP", 0) == total:
            note = (" This is the port WireGuard commonly uses; the traffic is "
                    "consistent with a WireGuard tunnel but was not verified as one.")
        elif dport in _SERVICE_PORTS:
            note = " Commonly associated with {}.".format(_SERVICE_PORTS[dport][0])
        observed.append("Most frequent port: {} ({:.0f}% of port observations).{}".format(
            dport, share, note))

    # Render drops and parse errors are reported, not hidden.
    if _stats.get("render_dropped"):
        observed.append(
            "{} packets were not rendered because the display queue was saturated; "
            "they are present in the PCAP.".format(_stats["render_dropped"]))
    if _stats.get("parse_errors"):
        observed.append("{} packets could not be parsed.".format(_stats["parse_errors"]))

    if _investigation_hits:
        observed.append("Scored indicators: {} STRONG, {} MODERATE.".format(
            signal_counts.get("STRONG", 0), signal_counts.get("MODERATE", 0)))
    else:
        observed.append("No scored indicators fired on the captured traffic.")

    if signal_counts.get("STRONG"):
        summary = "{} observation(s) with STRONG evidence — review the findings table.".format(
            signal_counts["STRONG"])
    elif signal_counts.get("MODERATE"):
        summary = "{} observation(s) with MODERATE evidence; no strong indicators.".format(
            signal_counts["MODERATE"])
    else:
        summary = "No threat indicators observed in the captured data."

    return {
        "headline": headline,
        "observed": observed,
        "not_determinable": not_determinable,
        "summary": summary,
        "signal_counts": dict(signal_counts),
    }


def _generate_pdf_report(save_path: str, session) -> str:
    if not PDF_OK:
        raise RuntimeError("reportlab is not installed. Install dependency 'reportlab'.")

    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(save_path, pagesize=letter)
    width, height = letter
    margin = 36
    content_w = width - (2 * margin)
    y = height - margin
    page_no = 1

    palette = {
        "bg": (0.06, 0.09, 0.15),
        "panel": (0.10, 0.14, 0.23),
        "line": (0.21, 0.28, 0.44),
        "text": (0.94, 0.97, 1.00),
        "muted": (0.66, 0.74, 0.86),
        "cyan": (0.20, 0.84, 0.98),
        "green": (0.30, 0.86, 0.56),
        "orange": (0.98, 0.66, 0.27),
        "yellow": (0.98, 0.89, 0.35),
        "red": (0.97, 0.41, 0.41),
    }

    def _apply_fill(color: tuple[float, float, float]):
        c.setFillColorRGB(*color)

    def _apply_stroke(color: tuple[float, float, float]):
        c.setStrokeColorRGB(*color)

    def _draw_page_footer(label: str = ""):
        _apply_stroke(palette["line"])
        c.setLineWidth(0.7)
        c.line(margin, 22, width - margin, 22)
        _apply_fill(palette["muted"])
        c.setFont("Helvetica", 8)
        c.drawString(margin, 10, f"PacketPulse Network Forensic Report | {label}" if label else "PacketPulse Network Forensic Report")
        c.drawRightString(width - margin, 10, f"Page {page_no}")

    def _new_page(label: str = ""):
        nonlocal y, page_no
        _draw_page_footer(label)
        c.showPage()
        page_no += 1
        y = height - margin

    def _section_title(title: str, subtitle: str = ""):
        nonlocal y
        _apply_fill(palette["cyan"])
        c.setFont("Helvetica-Bold", 14)
        c.drawString(margin, y, title)
        y -= 16
        if subtitle:
            _apply_fill(palette["muted"])
            c.setFont("Helvetica", 9)
            c.drawString(margin, y, subtitle)
            y -= 14
        _apply_stroke(palette["line"])
        c.setLineWidth(0.7)
        c.line(margin, y, width - margin, y)
        y -= 12

    def _ensure_space(min_h: float, label: str = ""):
        nonlocal y
        if y - min_h < 36:
            _new_page(label)

    def _draw_wrapped_text(
        text: str,
        x: float,
        top: float,
        max_w_chars: int,
        font: str = "Helvetica",
        size: int = 10,
        color: tuple[float, float, float] | None = None,
        line_gap: int = 12,
        bullet: bool = False,
    ) -> float:
        _apply_fill(color or palette["text"])
        c.setFont(font, size)
        yy = top
        lines = wrap(text, width=max_w_chars) or [""]
        for idx, line in enumerate(lines):
            prefix = "- " if bullet and idx == 0 else "  " if bullet else ""
            c.drawString(x, yy, f"{prefix}{line}")
            yy -= line_gap
        return yy

    def _draw_card(x: float, top: float, w: float, h: float, title: str, value: str, accent: tuple[float, float, float]):
        _apply_fill(palette["panel"])
        _apply_stroke(palette["line"])
        c.setLineWidth(1)
        c.roundRect(x, top - h, w, h, 6, stroke=1, fill=1)
        _apply_fill(palette["muted"])
        c.setFont("Helvetica", 9)
        c.drawString(x + 10, top - 18, title)
        _apply_fill(accent)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(x + 10, top - 40, value)

    sess = session.to_dict()
    iface = sess["interface"]
    bpf = sess["bpf_filter"]
    dur_label = "{:.1f}s measured".format(session.actual_duration)
    ts = utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")
    summary = _analyze_capture_summary(session)
    packets = list(_packet_log)

    ip_counts: Counter = Counter()
    for p in packets:
        if p.get("src_ip"):
            ip_counts[p["src_ip"]] += 1
        if p.get("dst_ip"):
            ip_counts[p["dst_ip"]] += 1

    unique_ips = len(ip_counts)
    proto_counts = {
        "TCP": _stats.get("tcp", 0),
        "UDP": _stats.get("udp", 0),
        "DNS": _stats.get("dns", 0),
        "HTTP": _stats.get("http", 0),
    }
    proto_colors = {
        "TCP": palette["cyan"],
        "UDP": palette["yellow"],
        "DNS": (0.73, 0.60, 0.97),
        "HTTP": palette["green"],
    }

    private_ips = [ip for ip in ip_counts if is_private_ip(ip)]
    public_ips = [ip for ip in ip_counts if not is_private_ip(ip)]
    local_ip = max(private_ips, key=lambda i: ip_counts[i]) if private_ips else ""
    primary_peer = max(public_ips, key=lambda i: ip_counts[i]) if public_ips else ""

    inbound = 0
    outbound = 0
    if local_ip and primary_peer:
        for p in packets:
            if p.get("src_ip") == primary_peer and p.get("dst_ip") == local_ip:
                inbound += 1
            elif p.get("src_ip") == local_ip and p.get("dst_ip") == primary_peer:
                outbound += 1

    size_bins = {
        "0-199B": 0,
        "200-599B": 0,
        "600-1199B": 0,
        "1200-1600B": 0,
        "1600+B": 0,
    }
    for p in packets:
        size = int(p.get("size", 0) or 0)
        if size < 200:
            size_bins["0-199B"] += 1
        elif size < 600:
            size_bins["200-599B"] += 1
        elif size < 1200:
            size_bins["600-1199B"] += 1
        elif size <= 1600:
            size_bins["1200-1600B"] += 1
        else:
            size_bins["1600+B"] += 1

    risk_counter = Counter((x.get("signal") or "NONE").upper() for x in _investigation_hits)
    high_ips = {x.get("src") for x in _investigation_hits if x.get("signal") == "STRONG"} | {
        x.get("dst") for x in _investigation_hits if x.get("signal") == "STRONG"
    }
    medium_ips = {x.get("src") for x in _investigation_hits if x.get("signal") == "MODERATE"} | {
        x.get("dst") for x in _investigation_hits if x.get("signal") == "MODERATE"
    }
    high_ips.discard(None)
    medium_ips.discard(None)

    timeline = Counter()
    for p in packets:
        t = p.get("timestamp", "")
        try:
            sec = datetime.strptime(t, "%H:%M:%S.%f").strftime("%H:%M:%S")
        except Exception:
            continue
        timeline[sec] += 1
    timeline_items = sorted(timeline.items(), key=lambda x: x[0])
    timeline_top = timeline_items[-40:] if len(timeline_items) > 40 else timeline_items
    timeline_max = max((v for _, v in timeline_top), default=1) or 1

    avg_rate = (sum(v for _, v in timeline_items) / len(timeline_items)) if timeline_items else 0
    peak_time, peak_count = max(timeline_items, key=lambda x: x[1]) if timeline_items else ("n/a", 0)

    # Evidence level, not a risk verdict: describes how much was observed.
    if risk_counter.get("STRONG", 0) > 0:
        overall_risk = "STRONG"
    elif risk_counter.get("MODERATE", 0) > 0:
        overall_risk = "MODERATE"
    elif _stats["total"] == 0:
        overall_risk = "NO DATA"
    else:
        overall_risk = "NONE"

    # 1) Cover Page
    _apply_fill(palette["bg"])
    c.rect(0, 0, width, height, stroke=0, fill=1)
    _apply_fill(palette["cyan"])
    c.setFont("Helvetica-Bold", 30)
    c.drawCentredString(width / 2, height * 0.62, "PacketPulse Network Forensic Report")
    _apply_fill(palette["muted"])
    c.setFont("Helvetica", 15)
    c.drawCentredString(width / 2, height * 0.57, "Session / Capture Summary")
    c.setFont("Helvetica", 11)
    c.drawCentredString(width / 2, height * 0.50, f"Generated: {ts}")
    c.drawCentredString(width / 2, height * 0.47,
                        "Interface: {} | Filter: {} | {}".format(iface or "auto", bpf or "none", dur_label))
    c.setFont("Helvetica", 9)
    c.drawCentredString(width / 2, height * 0.44,
                        "Session {} | HTTPS payloads were NOT decrypted".format(sess["session_id"]))
    _apply_fill((0.08, 0.15, 0.26))
    _apply_stroke(palette["green"])
    c.setLineWidth(1)
    c.roundRect((width / 2) - 130, (height * 0.43) - 10, 260, 22, 11, stroke=1, fill=1)
    _apply_fill(palette["green"])
    c.setFont("Helvetica-Bold", 11)
    c.drawCentredString(width / 2, height * 0.43, "Generated by Dreamwalker4u")
    _apply_fill(palette["green"])
    c.setFont("Helvetica-Bold", 12)
    c.drawCentredString(width / 2, height * 0.39, "PacketPulse")
    _new_page("Cover")

    # 2) Executive Dashboard
    _apply_fill(palette["bg"])
    c.rect(0, 0, width, height, stroke=0, fill=1)
    _section_title("Executive Dashboard", "Visual capture summary")

    cards = [
        ("Total Packets", f"{_stats['total']:,}", palette["cyan"]),
        ("Data Transferred", human_bytes(_stats["bytes"]), palette["green"]),
        ("Unique IPs", f"{unique_ips:,}", palette["yellow"]),
        ("Evidence Level", overall_risk, palette["orange"] if overall_risk == "MODERATE" else palette["red"] if overall_risk == "STRONG" else palette["green"]),
        ("Duration", dur_label, palette["muted"]),
    ]
    card_w = (content_w - 18) / 2
    card_h = 62
    cx = margin
    cy = y
    for idx, (title, value, accent) in enumerate(cards):
        _draw_card(cx, cy, card_w, card_h, title, value, accent)
        if idx % 2 == 0:
            cx += card_w + 18
        else:
            cx = margin
            cy -= card_h + 14
    if len(cards) % 2 == 1:
        cy -= card_h + 14
    y = cy - 4

    _draw_wrapped_text(
        f"Primary peer: {primary_peer or 'n/a'} | Inbound packets: {inbound:,} | Outbound packets: {outbound:,}",
        margin,
        y,
        110,
        font="Helvetica",
        size=10,
        color=palette["muted"],
    )
    _new_page("Executive Dashboard")

    # 3) Traffic Visualization
    _apply_fill(palette["bg"])
    c.rect(0, 0, width, height, stroke=0, fill=1)
    _section_title("Traffic Visualization", "Inbound/outbound, protocol mix, and packet-size histogram")

    pie_x = margin + 95
    pie_y = y - 95
    pie_r = 70
    total_dir = max(inbound + outbound, 1)  # guard: no traffic in one direction
    in_deg = 360 * inbound / total_dir
    out_deg = 360 - in_deg

    _apply_stroke(palette["line"])
    # reportlab raises ZeroDivisionError on a zero-extent wedge, which happens
    # whenever traffic ran in only one direction. Draw only real slices, and
    # say so plainly when there is no directional data at all.
    if inbound + outbound == 0:
        _apply_fill(palette["panel"])
        c.circle(pie_x, pie_y, pie_r, stroke=1, fill=1)
        _apply_fill(palette["muted"])
        c.setFont("Helvetica", 9)
        c.drawCentredString(pie_x, pie_y, "NO DIRECTIONAL DATA")
    else:
        if in_deg > 0:
            _apply_fill(palette["cyan"])
            c.wedge(pie_x - pie_r, pie_y - pie_r, pie_x + pie_r, pie_y + pie_r,
                    90, -in_deg, stroke=1, fill=1)
        if out_deg > 0:
            _apply_fill(palette["orange"])
            c.wedge(pie_x - pie_r, pie_y - pie_r, pie_x + pie_r, pie_y + pie_r,
                    90 - in_deg, -out_deg, stroke=1, fill=1)
    _apply_fill(palette["text"])
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(pie_x, pie_y + pie_r + 12, "Inbound vs Outbound")
    c.setFont("Helvetica", 9)
    c.drawCentredString(pie_x, pie_y - pie_r - 14, f"Inbound {inbound:,} ({(inbound/max(total_dir,1))*100:.1f}%)")
    c.drawCentredString(pie_x, pie_y - pie_r - 28, f"Outbound {outbound:,} ({(outbound/max(total_dir,1))*100:.1f}%)")

    bx = margin + 240
    by = y - 10
    _apply_fill(palette["text"])
    c.setFont("Helvetica-Bold", 10)
    c.drawString(bx, by, "Protocol Distribution")
    by -= 16
    max_proto = max(proto_counts.values()) if proto_counts else 0
    max_proto = max_proto or 1
    for proto, val in proto_counts.items():
        _apply_fill(palette["muted"])
        c.setFont("Helvetica", 9)
        c.drawString(bx, by, f"{proto}")
        _apply_fill(palette["panel"])
        c.rect(bx + 52, by - 2, 190, 9, stroke=0, fill=1)
        _apply_fill(proto_colors.get(proto, palette["cyan"]))
        c.rect(bx + 52, by - 2, int((val / max_proto) * 190), 9, stroke=0, fill=1)
        _apply_fill(palette["text"])
        c.drawRightString(bx + 255, by, f"{val:,}")
        by -= 18

    y = pie_y - pie_r - 55
    _apply_fill(palette["text"])
    c.setFont("Helvetica-Bold", 10)
    c.drawString(margin, y, "Packet Size Histogram")
    y -= 14
    max_bin = max(size_bins.values()) if size_bins else 0
    max_bin = max_bin or 1
    x_cursor = margin
    bar_area_h = 92
    bar_w = (content_w - 20) / max(len(size_bins), 1)
    for label, val in size_bins.items():
        bh = int((val / max_bin) * bar_area_h) if max_bin else 0
        _apply_fill(palette["panel"])
        c.rect(x_cursor, y - bar_area_h, bar_w - 12, bar_area_h, stroke=0, fill=1)
        _apply_fill(palette["green"])
        c.rect(x_cursor, y - bh, bar_w - 12, bh, stroke=0, fill=1)
        _apply_fill(palette["muted"])
        c.setFont("Helvetica", 8)
        c.drawCentredString(x_cursor + (bar_w - 12) / 2, y - bar_area_h - 12, label)
        c.drawCentredString(x_cursor + (bar_w - 12) / 2, y - bar_area_h - 23, f"{val:,}")
        x_cursor += bar_w
    _new_page("Traffic Visualization")

    # 4) IP Intelligence
    _apply_fill(palette["bg"])
    c.rect(0, 0, width, height, stroke=0, fill=1)
    _section_title("IP Intelligence", "Observed endpoints and evidence level")

    _draw_wrapped_text(
        f"Primary peer: {primary_peer or 'n/a'} | Suspicious endpoints: {len(high_ips | medium_ips)}",
        margin,
        y,
        115,
        font="Helvetica",
        size=10,
        color=palette["muted"],
    )
    y -= 18

    headers = ["IP", "Country", "Org", "Packets", "Risk"]
    col_w = [140, 72, 180, 60, 70]
    x_positions = [margin]
    for w_col in col_w[:-1]:
        x_positions.append(x_positions[-1] + w_col)

    _apply_fill(palette["panel"])
    c.rect(margin, y - 14, sum(col_w), 16, stroke=0, fill=1)
    _apply_fill(palette["muted"])
    c.setFont("Helvetica-Bold", 8)
    for i, h in enumerate(headers):
        c.drawString(x_positions[i] + 4, y - 9, h)
    y -= 20

    for ip, cnt in ip_counts.most_common(14):
        _ensure_space(16, "IP Intelligence")
        geo = _ips_seen.get(ip, {})
        country = geo.get("country", "LAN")
        org = (geo.get("org", "Private Network") or "Private Network")[:34]
        risk = "NONE"
        if ip in high_ips:
            risk = "STRONG"
        elif ip in medium_ips:
            risk = "MODERATE"
        risk_color = palette["orange"] if risk == "MODERATE" else palette["red"] if risk == "STRONG" else palette["green"]

        _apply_stroke(palette["line"])
        c.setLineWidth(0.5)
        c.line(margin, y - 2, margin + sum(col_w), y - 2)
        _apply_fill(palette["text"])
        c.setFont("Helvetica", 8)
        c.drawString(x_positions[0] + 4, y - 12, ip)
        c.drawString(x_positions[1] + 4, y - 12, country)
        c.drawString(x_positions[2] + 4, y - 12, org)
        c.drawRightString(x_positions[3] + col_w[3] - 6, y - 12, f"{cnt:,}")
        _apply_fill(risk_color)
        c.drawString(x_positions[4] + 4, y - 12, risk)
        y -= 16
    y -= 6
    _new_page("IP Intelligence")

    # 5) Key Findings + 6) Risk Analysis
    _apply_fill(palette["bg"])
    c.rect(0, 0, width, height, stroke=0, fill=1)
    _section_title("Observations", "Facts derived from the captured data")

    findings = list(summary.get("observed", []))
    if inbound + outbound > 0:
        findings.insert(0, f"Download-heavy traffic: {(inbound / max(inbound + outbound, 1)) * 100:.1f}% inbound.")
    if peak_count and avg_rate and peak_count > avg_rate * 1.8:
        findings.append(f"Burst spike detected near {peak_time} with {peak_count} packets in one second.")
    udp_pct = (_stats.get("udp", 0) / max(_stats.get("total", 1), 1)) * 100
    if udp_pct > 40:
        findings.append(f"High UDP activity observed ({udp_pct:.1f}%), consistent with streaming/tunneling behavior.")

    for item in findings[:8]:
        _ensure_space(20, "Key Findings")
        y = _draw_wrapped_text(item, margin, y, 105, font="Helvetica", size=10, color=palette["text"], bullet=True)
        y -= 2

    y -= 8
    _section_title("Evidence Summary", "How many scored indicators fired, and at what strength")
    total_events = max(len(_investigation_hits), 1)
    low_events = max(total_events - risk_counter.get("MODERATE", 0) - risk_counter.get("STRONG", 0), 0)
    risk_rows = [
        ("WEAK/NONE", low_events, palette["green"]),
        ("MODERATE", risk_counter.get("MODERATE", 0), palette["orange"]),
        ("STRONG", risk_counter.get("STRONG", 0), palette["red"]),
    ]
    for level, count, col in risk_rows:
        _apply_fill(palette["panel"])
        c.roundRect(margin, y - 18, content_w, 16, 4, stroke=0, fill=1)
        _apply_fill(col)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(margin + 8, y - 12, level)
        _apply_fill(palette["text"])
        c.setFont("Helvetica", 9)
        c.drawRightString(width - margin - 8, y - 12, f"{count} events")
        y -= 22

    explanation = (
        "Evidence level reflects the strongest scored indicator observed in this capture window. "
        "Scores are the sum of documented indicator weights; each indicator records the basis on "
        "which it fired. This is a measure of what was observed, not a probability of compromise."
    )
    y = _draw_wrapped_text(explanation, margin, y - 2, 112, font="Helvetica", size=9, color=palette["muted"], line_gap=11)
    _new_page("Findings and Risk")

    # 7) Timeline
    _apply_fill(palette["bg"])
    c.rect(0, 0, width, height, stroke=0, fill=1)
    _section_title("Timeline", "Activity spikes and notable events")

    chart_top = y
    chart_h = 130
    bar_count = max(len(timeline_top), 1)
    bar_w = max((content_w - 8) / bar_count, 2)
    x = margin
    _apply_fill(palette["panel"])
    c.rect(margin, chart_top - chart_h, content_w, chart_h, stroke=0, fill=1)
    for idx, (sec, val) in enumerate(timeline_top):
        bh = int((val / timeline_max) * (chart_h - 16)) if timeline_max else 0
        _apply_fill(palette["cyan"] if idx % 2 == 0 else palette["green"])
        c.rect(x, chart_top - bh - 6, bar_w - 1, bh, stroke=0, fill=1)
        x += bar_w
    _apply_fill(palette["muted"])
    c.setFont("Helvetica", 8)
    c.drawString(margin, chart_top - chart_h - 12, f"Timeline points: {len(timeline_top)} | Peak: {peak_time} ({peak_count} pkts/s)")

    y = chart_top - chart_h - 24
    _apply_fill(palette["text"])
    c.setFont("Helvetica-Bold", 10)
    c.drawString(margin, y, "Time | Event | Type | Risk")
    y -= 12
    _apply_stroke(palette["line"])
    c.line(margin, y, width - margin, y)
    y -= 8

    timeline_events = _investigation_hits[:14]
    if not timeline_events:
        timeline_events = [
            {
                "time": p.get("timestamp", ""),
                "activity": (p.get("intel") or {}).get("observation", "Packet observed"),
                "proto": p.get("proto", "OTHER"),
                "signal": (p.get("intel") or {}).get("signal", "NONE"),
            }
            for p in packets[-14:]
        ]

    for e in timeline_events:
        _ensure_space(16, "Timeline")
        tval = e.get("time", "n/a")
        event = (e.get("activity", "Event") or "Event")[:44]
        typ = (e.get("proto") or e.get("type") or "NET")[:7]
        risk = (e.get("signal") or "NONE").upper()
        risk_color = palette["orange"] if risk == "MODERATE" else palette["red"] if risk == "STRONG" else palette["green"]
        _apply_fill(palette["text"])
        c.setFont("Helvetica", 8)
        c.drawString(margin, y, f"{tval}")
        c.drawString(margin + 72, y, event)
        c.drawString(margin + 330, y, typ)
        _apply_fill(risk_color)
        c.drawString(margin + 380, y, risk)
        y -= 13

    # 9) Final Verdict (before appendix)
    y -= 8
    _ensure_space(110, "Timeline")
    _apply_fill(palette["panel"])
    _apply_stroke(palette["cyan"])
    c.setLineWidth(1.2)
    c.roundRect(margin, y - 90, content_w, 88, 8, stroke=1, fill=1)
    _apply_fill(palette["cyan"])
    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin + 12, y - 18, "Session Summary")
    _apply_fill(palette["text"])
    c.setFont("Helvetica", 10)
    c.drawString(margin + 12, y - 36, "Evidence Level: {}".format(overall_risk))
    c.drawString(margin + 12, y - 52, (summary.get("summary", "") or "No summary")[:90])
    c.drawString(margin + 12, y - 68, "Status: {} | Measured duration: {:.1f}s".format(
        sess["status"], session.actual_duration))
    _new_page("Timeline and Verdict")

    # 8) Detailed Logs Appendix (last section)
    _apply_fill(palette["bg"])
    c.rect(0, 0, width, height, stroke=0, fill=1)
    y = height - margin
    _section_title("Detailed Logs (Appendix)", "Monospace packet records, paginated")
    _apply_fill(palette["muted"])
    c.setFont("Helvetica", 8)
    c.drawString(margin, y, f"Showing last {min(len(packets), 350):,} packets out of {len(packets):,} captured")
    y -= 16

    log_rows = packets[-350:]
    c.setFont("Courier", 7)
    for idx, p in enumerate(log_rows, 1):
        if y < 50:
            _new_page("Appendix Logs")
            _apply_fill(palette["bg"])
            c.rect(0, 0, width, height, stroke=0, fill=1)
            y = height - margin
            _section_title("Detailed Logs (Appendix)", "Continued")
            c.setFont("Courier", 7)

        t = p.get("timestamp", "")
        proto = p.get("proto", "?")
        src = f"{p.get('src_ip', '?')}:{p.get('src_port', '')}"
        dst = f"{p.get('dst_ip', '?')}:{p.get('dst_port', '')}"
        sz = int(p.get("size", 0) or 0)
        risk = ((p.get("intel") or {}).get("signal", "NONE") or "NONE").upper()
        line = f"{idx:04d} {t} {proto:4} {src:27} -> {dst:27} {sz:5}B {risk:6}"
        _apply_fill(palette["text"])
        c.drawString(margin, y, line[:130])
        y -= 9

    _draw_page_footer("Appendix Logs")
    c.save()
    return save_path


def _print_stats() -> None:
    elapsed = (utc_now() - _stats["start"]).total_seconds()
    pps = _stats["total"] / max(elapsed, 1e-6)
    console.print(
        f"\n[dim]── STATS ──[/dim]  total=[green]{_stats['total']:,}[/green]  "
        f"TCP=[cyan]{_stats['tcp']:,}[/cyan]  UDP=[yellow]{_stats['udp']:,}[/yellow]  "
        f"DNS=[magenta]{_stats['dns']:,}[/magenta]  HTTP=[bright_green]{_stats['http']:,}[/bright_green]  "
        f"pkt/s=[bold]{pps:.0f}[/bold]  bytes=[dim]{human_bytes(_stats['bytes'])}[/dim]"
    )

def _fmt_dur(s:int)->str:
    if s==0: return "unlimited"
    if s>=3600: return f"{s//3600}h {(s%3600)//60}m"
    if s>=60: return f"{s//60}m {s%60}s"
    return f"{s}s"

# In-memory record limit for report tables. This is SEPARATE from the PCAP,
# which is streamed to disk and is never truncated by this value.
RENDER_LOG_LIMIT = 50000


def _reset_session_state() -> None:
    """Clear every module global so run N+1 cannot inherit run N's data."""
    global _stats, _packet_log, _investigation_hits
    _stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "other": 0,
              "bytes": 0, "http": 0, "dns": 0, "start": utc_now()}
    _packet_log = deque(maxlen=RENDER_LOG_LIMIT)
    _investigation_hits = []
    _connections.clear()
    _domains_seen.clear()
    _ips_seen.clear()
    _http_requests.clear()
    _geo_cache.clear()
    _dns_cache.clear()
    _attribution_blocked["reason"] = ""
    with _enrich_lock:
        _enrich_requested.clear()


def run_sniffer(
    interface=None,
    bpf_filter: str = "",
    count: int = 0,
    duration: int = 0,
    save_pcap: bool = True,
    stop=None,
    session=None,
):
    """Capture live packets and produce verified artifacts.

    Returns the Session describing what actually happened. This function
    starts its worker, honours the stop signal and duration, joins every
    thread it created, closes every file it opened, and only then returns.
    """
    global _sniff_start_time, _sniff_duration, _stop_sniffing, _draining
    global _packet_queue, _worker_thread, _pcap_writer, _ndjson_fh

    _user_iface = bool(interface)
    stop = stop or StopController()
    cfg = get_config().sensor
    # Fall back to the OS route interface, not scapy's default: on a host
    # with a VPN tunnel those differ and the default sees no internet traffic.
    iface = interface or cfg.interface or capabilities.default_route_interface()
    session = session or Session(
        module="sniffer",
        requested_duration=duration,
        interface=str(iface or "default"),
        bpf_filter=bpf_filter,
    )

    if not SCAPY_OK:
        reason = SCAPY_UNAVAILABLE_REASON or "scapy is not installed"
        session.record_unavailable("Packet capture", reason)
        session.finish(completed=False, abort_reason=reason)
        console.print("[red]Packet capture UNAVAILABLE:[/red] " + reason)
        return session

    cap = capabilities.probe_capture()
    if not cap.available:
        session.record_unavailable("Packet capture", cap.reason)
        session.finish(completed=False, abort_reason=cap.reason)
        console.print("[red]Packet capture UNAVAILABLE:[/red] " + cap.reason)
        console.print("  [dim]" + capabilities.privilege_hint() + "[/dim]")
        return session

    # Load the capture backend before resolving/using a named interface.
    _load_secs = capabilities.ensure_capture_backend(iface)
    if _load_secs > 5:
        console.print("  [dim]Capture engine loaded in %.1fs (full adapter "
                      "enumeration was required).[/dim]" % _load_secs)

    ok, detail = capabilities.resolve_interface(iface)
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
            "the routed path." % (iface, detail))
        iface = None
        session.interface = "platform default"


    _reset_session_state()
    _stop_sniffing = False
    _draining = False
    _sniff_duration = duration
    _sniff_start_time = time.time() if duration > 0 else None

    _compat = scapy_compat.COMPAT_NOTE
    if _compat:
        session.note_limitation(_compat)
    session.note_limitation(capabilities.interface_note(iface))
    session.note_limitation(
        "TLS/HTTPS payloads are encrypted and were not decrypted; only endpoint "
        "metadata (addresses, ports, sizes, timing) is available for that traffic."
    )
    session.note_limitation(
        "In-memory packet records are capped at {:,} for report tables; the PCAP "
        "and NDJSON written to disk are complete.".format(RENDER_LOG_LIMIT)
    )
    if not cfg.geoip_db:
        if cfg.geoip_online:
            session.note_limitation(
                "GeoIP resolved via ip-api.com: observed addresses were sent to a "
                "third party, and results are approximate (city-level at best).")
        else:
            session.record_unavailable(
                "GeoIP enrichment",
                "no local database (PACKETPULSE_GEOIP_DB) and online lookup disabled")
    if not capabilities.is_admin():
        session.note_limitation(
            "Process attribution is limited without elevated privileges: the OS "
            "hides socket ownership for processes owned by other users."
        )

    ensure_dir(cfg.pcap_store_path)
    stamp = timestamp_filename()
    base = Path(cfg.pcap_store_path)
    pcap_path = str(base / ("session_" + stamp + ".pcap"))
    ndjson_path = str(base / ("report_" + stamp + ".ndjson"))

    _pcap_writer = None
    if save_pcap:
        try:
            _pcap_writer = PcapWriter(pcap_path, append=False, sync=False)
        except (OSError, PermissionError) as e:
            session.record_error("pcap_open", e)
            session.record_unavailable("PCAP output", "cannot open {}: {}".format(pcap_path, e))
            console.print("[yellow]PCAP output UNAVAILABLE: {}[/yellow]".format(e))
    try:
        _ndjson_fh = open(ndjson_path, "w", encoding="utf-8")
    except OSError as e:
        _ndjson_fh = None
        session.record_error("ndjson_open", e)

    _enrich_start()

    # Worker is NOT a daemon: we join it before returning.
    _packet_queue = queue.Queue(maxsize=100000)
    _worker_thread = threading.Thread(target=_worker_loop, name="pp-sensor-worker", daemon=False)
    _worker_thread.start()

    dur_label = _fmt_dur(duration)
    console.rule("[bold green]PACKETPULSE - DEEP PACKET SNIFFER[/bold green]")
    console.print(
        "  [dim]Interface:[/dim] [green]{}[/green]  [dim]Filter:[/dim] [yellow]{}[/yellow]  "
        "[dim]Duration:[/dim] [yellow]{}[/yellow]  [dim]Session:[/dim] [cyan]{}[/cyan]".format(
            iface or "default", bpf_filter or "none", dur_label, session.session_id)
    )
    console.print("  [dim]HTTPS payloads are encrypted and are NOT decrypted.[/dim]")
    console.print("[dim]" + "-" * 100 + "[/dim]")

    aborted = ""
    session.begin_capture()
    try:
        sniff(
            iface=iface,
            filter=bpf_filter or None,
            prn=_packet_callback,
            stop_filter=lambda pkt: stop.is_set() or _should_stop(pkt),
            timeout=duration if duration > 0 else None,
            count=count or 0,
            store=False,
        )
    except KeyboardInterrupt:
        console.print("\n  [yellow]Interrupted - finishing cleanly...[/yellow]")
    except PermissionError as e:
        aborted = "insufficient privilege for live capture: {}".format(e)
        session.record_error("sniff", e)
    except ValueError as e:
        aborted = "interface error: {}".format(e)
        session.record_error("sniff_iface", e)
    except OSError as e:
        aborted = "capture failed: {}".format(e)
        session.record_error("sniff", e)
    finally:
        session.end_capture()
        stop.stop()
        _stop_sniffing = True
        if _worker_thread and _worker_thread.is_alive():
            _worker_thread.join(timeout=15)
            if _worker_thread.is_alive():
                session.record_error("worker_join", "worker thread did not terminate within 15s")
        # Drain enrichment so late GeoIP/rDNS results still reach the report.
        pending = _enrich_pending_count()
        if pending:
            console.print(f"  [dim]Resolving endpoint metadata ({pending} addresses)...[/dim]")
        unresolved = _enrich_shutdown()
        _backfill_geo()
        if unresolved:
            session.note_limitation(
                f"{unresolved} address(es) were not resolved before the deadline and "
                "are reported as NOT RESOLVED rather than guessed.")
        if _pcap_writer is not None:
            try:
                _pcap_writer.close()
            except OSError as e:
                session.record_error("pcap_close", e)
        if _ndjson_fh is not None:
            try:
                _ndjson_fh.close()
            except OSError as e:
                session.record_error("ndjson_close", e)
            finally:
                _ndjson_fh = None

    session.count("packets_captured", _stats["total"])
    session.count("bytes_captured", _stats["bytes"])
    for k in ("tcp", "udp", "icmp", "arp", "dns", "http"):
        if _stats.get(k):
            session.count(k, _stats[k])
    session.count("unique_domains", len(_domains_seen))
    session.count("findings", len(_investigation_hits))
    session.finish(completed=not aborted, abort_reason=aborted)

    if aborted:
        console.print("\n[red]CAPTURE FAILED:[/red] " + aborted)
        console.print("  [dim]" + capabilities.privilege_hint() + "[/dim]")
        return session

    _print_stats()

    artifacts = {}
    if save_pcap and _pcap_writer is not None:
        verified, detail = _verify_pcap(pcap_path, _stats["total"])
        if verified:
            artifacts["pcap"] = pcap_path
            console.print("\n[green]PCAP verified ->[/green] [cyan]{}[/cyan]  [dim]{}[/dim]".format(pcap_path, detail))
        else:
            session.record_error("pcap_verify", detail)
            console.print("\n[yellow]PCAP NOT VERIFIED:[/yellow] " + detail)
    if Path(ndjson_path).exists():
        artifacts["ndjson"] = ndjson_path

    _write_reports(session, cfg, stamp, artifacts)
    return session


def _backfill_geo() -> None:
    """Attach enrichment that arrived after a packet was rendered.

    _ips_seen is what the report reads, so refresh it from the resolved caches
    once the pool has drained. Addresses that never resolved keep their
    unavailable marker.
    """
    for ip in list(_ips_seen.keys()):
        if ip in _geo_cache:
            _ips_seen[ip] = _geo_cache[ip]


def _verify_pcap(path: str, expected: int):
    """Re-read the written PCAP and count frames. Never assume the write worked."""
    try:
        if not Path(path).exists():
            return False, "file was not created"
        size = Path(path).stat().st_size
        n = 0
        with PcapReader(path) as rd:
            for _ in rd:
                n += 1
        if expected and n != expected:
            return False, "{} frames on disk vs {} counted in session".format(n, expected)
        return True, "{:,} frames, {}".format(n, human_bytes(size))
    except Exception as e:
        return False, "{}: {}".format(type(e).__name__, e)


def _write_reports(session, cfg, stamp, artifacts) -> None:
    """Generate HTML/PDF/JSON from this session only."""
    base = Path(cfg.pcap_store_path)
    console.print("\n[dim]Generating report from captured data...[/dim]")

    rpath = str(base / ("report_" + stamp + ".html"))
    try:
        _generate_report(rpath, session)
        artifacts["html"] = rpath
        console.print("  [dim]HTML   ->[/dim] [cyan]{}[/cyan]".format(rpath))
    except Exception as e:
        session.record_error("html_report", e)
        console.print("  [red]HTML report FAILED:[/red] {}".format(e))

    if PDF_OK:
        pp = str(base / ("report_" + stamp + ".pdf"))
        try:
            _generate_pdf_report(pp, session)
            artifacts["pdf"] = pp
            console.print("  [dim]PDF    ->[/dim] [cyan]{}[/cyan]".format(pp))
        except Exception as e:
            session.record_error("pdf_report", e)
            console.print("  [yellow]PDF report FAILED:[/yellow] {}".format(e))
    else:
        session.record_unavailable("PDF reports", "reportlab is not installed")

    jp = str(base / ("report_" + stamp + ".json"))
    try:
        save_json(
            {
                "session": session.to_dict(),
                "capabilities_unavailable": capabilities.unavailable_features(),
                "artifacts": dict(artifacts),
                "dns_queries_observed": sorted(_domains_seen),
                "http_requests_observed": _http_requests[:200],
                "connections_observed": list(_connections.values())[:200],
                "findings": _investigation_hits[:300],
                "ip_intelligence": _ip_intel_records(),
            },
            jp,
        )
        artifacts["json"] = jp
        console.print("  [dim]JSON   ->[/dim] [cyan]{}[/cyan]".format(jp))
    except Exception as e:
        session.record_error("json_report", e)
        console.print("  [red]JSON report FAILED:[/red] {}".format(e))

    console.print("\n  [bold]{}[/bold]".format(session.summary_line()))
    if session.unavailable:
        console.print("  [yellow]Unavailable this run:[/yellow]")
        for u in session.unavailable:
            console.print("    [dim]- {}: {}[/dim]".format(u["feature"], u["reason"]))


def _ip_intel_records():
    """GeoIP records for observed addresses. Unresolved entries say so."""
    out = []
    for ip in sorted(_ips_seen.keys()):
        g = _ips_seen.get(ip) or {}
        available = bool(g.get("available", False)) or g.get("source") == "local"
        out.append({
            "ip": ip,
            "rdns": _dns_cache.get(ip) or "NOT RESOLVED",
            "geoip_available": available,
            "country": g.get("country") if available else "UNAVAILABLE",
            "city": g.get("city") if available else "UNAVAILABLE",
            "org": g.get("org") or "UNKNOWN",
            "source": g.get("source", "none"),
        })
    return out
