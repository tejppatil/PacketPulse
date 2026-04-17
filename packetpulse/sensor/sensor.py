"""
PacketPulse — Deep Packet Sniffer + Forensic Report Generator
Captures full L2/L3/L4/L7 data and generates a branded HTML report.
Report: PacketPulse | Dreamwalker4u
"""
from __future__ import annotations

import os, re, socket, threading, time, json, queue
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from textwrap import wrap
from typing import Optional

import psutil
from rich.console import Console
from rich import box

from packetpulse.core.config import get_config
from packetpulse.core.logger import get_logger
from packetpulse.utils.helpers import (
    geoip_lookup, is_private_ip, reverse_dns,
    human_bytes, truncate, save_json, save_ndjson, ensure_dir, now_str, timestamp_filename
)

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, Raw, Ether, ARP, wrpcap
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    PDF_OK = True
except ImportError:
    PDF_OK = False

console = Console()
log = get_logger("sensor")

# ── Session globals ───────────────────────────────────────────────────────────
_stats = {"total":0,"tcp":0,"udp":0,"icmp":0,"arp":0,"other":0,
          "bytes":0,"http":0,"dns":0,"start":datetime.utcnow()}
_geo_cache:   dict[str, dict] = {}
_dns_cache:   dict[str, str]  = {}
_captured_packets = []
_packet_log:   list[dict] = []
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
_stop_sniffing = False
_sniff_start_time: Optional[float] = None
_sniff_duration: int = 0


def _geo(ip: str) -> dict:
    if ip not in _geo_cache:
        _geo_cache[ip] = geoip_lookup(ip, get_config().sensor.geoip_db)
    return _geo_cache[ip]


def _refresh_connection_cache() -> None:
    global _conn_cache, _conn_cache_timestamp
    now = time.monotonic()
    if now - _conn_cache_timestamp > 2.0:
        try:
            _conn_cache = psutil.net_connections(kind="inet")
        except Exception:
            _conn_cache = []
        _conn_cache_timestamp = now


def _find_process(sp: int, dp: int, src_ip: str = "", dst_ip: str = "") -> str:
    _refresh_connection_cache()
    ports = {sp, dp}
    best_conn = None
    for c in _conn_cache:
        if not c.laddr:
            continue
        try:
            l_ip, l_port = c.laddr
        except Exception:
            continue
        r_ip, r_port = ("", "")
        if c.raddr:
            try:
                r_ip, r_port = c.raddr
            except Exception:
                pass
        if l_port not in ports and r_port not in ports:
            continue

        exact_local = (src_ip and dst_ip and l_ip == src_ip and r_ip == dst_ip and l_port == sp and r_port == dp)
        exact_remote = (src_ip and dst_ip and l_ip == dst_ip and r_ip == src_ip and l_port == dp and r_port == sp)
        if exact_local or exact_remote:
            best_conn = c
            break
        if best_conn is None:
            best_conn = c

    if best_conn and best_conn.pid:
        try:
            proc = psutil.Process(best_conn.pid)
            proc_name = proc.name()
            return f"{proc_name}({best_conn.pid})"
        except Exception:
            return f"pid:{best_conn.pid}"
    return ""

def _parse_http(payload: bytes) -> Optional[dict]:
    try: text = payload.decode("utf-8", errors="replace")
    except: return None
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

def _parse_dns_pkt(pkt) -> Optional[dict]:
    if not pkt.haslayer(DNS):
        return None
    dns = pkt[DNS]
    r: dict = {
        "type": "QUERY" if dns.qr == 0 else "RESPONSE",
        "rcode": dns.rcode,
        "qdcount": dns.qdcount,
        "ancount": dns.ancount,
        "nscount": dns.nscount,
        "arcount": dns.arcount,
    }
    qmap = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 255: "ANY"}

    if dns.qdcount > 0:
        try:
            q = dns.qd
            r["query"] = q.qname.decode("utf-8", errors="replace").rstrip(".")
            r["qtype"] = qmap.get(q.qtype, str(q.qtype))
            r["qclass"] = q.qclass
        except Exception:
            pass

    if dns.qr == 1 and dns.ancount > 0:
        answers = []
        rr = dns.an
        seen = 0
        while rr and seen < dns.ancount:
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
                seen += 1
            rr = rr.payload if hasattr(rr, "payload") and rr.payload else None
        r["answers"] = answers
    return r

def _tcp_flags(f) -> str:
    return " ".join(n for c,n in [("F","FIN"),("S","SYN"),("R","RST"),("P","PSH"),("A","ACK"),("U","URG")] if c in str(f)) or str(f)


def _infer_activity(info: dict) -> Optional[dict]:
    """Infer likely user/system action represented by a packet."""
    proto = info.get("proto", "")
    sp = int(info.get("src_port") or 0)
    dp = int(info.get("dst_port") or 0)
    ports = {sp, dp}
    remote = info.get("dst_ip", "")
    private_dst = is_private_ip(remote) if remote else True

    risk = "LOW"
    confidence = 55
    action = "Generic network traffic"
    reason = "No strong signature"
    tags: list[str] = []

    if proto == "DNS":
        d = info.get("dns") or {}
        q = (d.get("query") or "").lower()
        action = "Domain name resolution"
        reason = "DNS query/response observed"
        confidence = 82
        tags = ["dns", "resolution"]
        if len(q) > 45 or q.count(".") >= 5:
            risk = "MEDIUM"
            action = "Possible DNS tunneling / beaconing"
            reason = "Very long or deeply nested domain"
            confidence = 72
            tags.append("possible-c2")
        elif d.get("rcode") == 3:
            risk = "MEDIUM"
            action = "Failed domain lookup (NXDOMAIN)"
            reason = "Could indicate typo, DGA, or blocked domain"
            confidence = 70
            tags.append("nxdomain")

    elif proto == "HTTP":
        h = info.get("http") or {}
        method = (h.get("method") or "").upper()
        host = (h.get("host") or "").lower()
        path = (h.get("path") or "").lower()
        action = "Web browsing/API request"
        reason = "HTTP method and host/path visible"
        confidence = 88
        tags = ["http", "web"]

        auth_terms = ("login", "signin", "auth", "token", "oauth", "password", "session")
        admin_terms = ("admin", "wp-admin", "dashboard", "panel")
        file_terms = ("upload", "download", "export", "backup", "dump", "archive", "zip")

        if method == "POST" and any(t in path for t in auth_terms):
            action = "Credential submission / authentication"
            reason = "POST to auth-like endpoint"
            confidence = 93
            risk = "MEDIUM"
            tags += ["auth", "credentials"]
        elif any(t in path for t in admin_terms):
            action = "Admin portal access"
            reason = "Admin-like URL path"
            confidence = 86
            risk = "MEDIUM"
            tags += ["admin"]
        elif any(t in path for t in file_terms):
            action = "File transfer operation"
            reason = "Upload/download/export-like endpoint"
            confidence = 82
            risk = "MEDIUM"
            tags += ["file-transfer"]
        if any(x in host for x in ("paste", "anon", "temp", "share", "drop")):
            risk = "MEDIUM" if risk == "LOW" else "HIGH"
            tags.append("external-share")

    elif proto == "TCP":
        tags = ["tcp"]
        if 443 in ports:
            action = "Encrypted web session (HTTPS/TLS)"
            reason = "Traffic to/from port 443"
            confidence = 80
            tags += ["https", "encrypted"]
        elif 22 in ports:
            action = "Remote shell session (SSH)"
            reason = "Traffic to/from port 22"
            confidence = 92
            risk = "MEDIUM"
            tags += ["ssh", "remote-access"]
        elif 3389 in ports:
            action = "Remote desktop session (RDP)"
            reason = "Traffic to/from port 3389"
            confidence = 94
            risk = "HIGH"
            tags += ["rdp", "remote-access"]
        elif 445 in ports:
            action = "SMB file share activity"
            reason = "Traffic to/from port 445"
            confidence = 90
            risk = "HIGH" if not private_dst else "MEDIUM"
            tags += ["smb", "lateral-movement"]
        elif 21 in ports or 20 in ports:
            action = "FTP file transfer"
            reason = "Traffic to/from FTP ports"
            confidence = 90
            risk = "HIGH"
            tags += ["ftp", "cleartext"]
        elif 25 in ports or 587 in ports or 465 in ports:
            action = "Email transport activity (SMTP)"
            reason = "Traffic to/from SMTP ports"
            confidence = 86
            risk = "MEDIUM"
            tags += ["smtp", "mail"]
        elif 1433 in ports or 3306 in ports or 5432 in ports:
            action = "Database connectivity"
            reason = "Traffic to common DB service port"
            confidence = 84
            risk = "MEDIUM" if private_dst else "HIGH"
            tags += ["database"]
        else:
            action = "General TCP session"
            reason = "TCP stream without recognized service port"
            confidence = 60

    elif proto == "UDP":
        tags = ["udp"]
        if 53 in ports:
            action = "DNS transport"
            reason = "UDP/53 observed"
            confidence = 84
            tags += ["dns"]
        elif 123 in ports:
            action = "Time synchronization (NTP)"
            reason = "UDP/123 observed"
            confidence = 90
            tags += ["ntp"]
        elif 67 in ports or 68 in ports:
            action = "DHCP lease negotiation"
            reason = "UDP/67-68 observed"
            confidence = 90
            tags += ["dhcp"]
        else:
            action = "General UDP datagram exchange"
            reason = "UDP without known service port"
            confidence = 58

    elif proto == "ICMP":
        action = "Network reachability / diagnostics"
        reason = "ICMP packet observed (ping/traceroute behavior)"
        confidence = 85
        tags = ["icmp", "diagnostics"]

    if not private_dst and risk == "LOW" and proto in ("TCP", "UDP", "HTTP"):
        risk = "MEDIUM"
        tags.append("internet-egress")

    return {
        "activity": action,
        "risk": risk,
        "confidence": confidence,
        "reason": reason,
        "tags": tags,
    }

def _should_stop(pkt) -> bool:
    if _stop_sniffing: return True
    if _sniff_duration>0 and _sniff_start_time and time.time()-_sniff_start_time>=_sniff_duration: return True
    return False

def _render(info: dict) -> None:
    p   = info.get("proto","?"); src=info.get("src_ip","?"); dst=info.get("dst_ip","?")
    sp  = info.get("src_port",""); dp=info.get("dst_port",""); ts=info.get("timestamp","")
    geo = info.get("geo",{}); proc=info.get("process",""); size=info.get("size",0)
    cm  = {"TCP":"cyan","UDP":"yellow","ICMP":"green","DNS":"magenta","ARP":"blue","HTTP":"bright_green"}
    c   = cm.get(p,"white")
    lines=[
        f"[dim]{ts}[/dim]  [{c}]{p}[/{c}]  [bold white]{src}[/bold white]"
        f"{':[yellow]'+str(sp)+'[/yellow]' if sp else ''}  [dim]→[/dim]  "
        f"[bold white]{dst}[/bold white]{':[green]'+str(dp)+'[/green]' if dp else ''}  [dim]{size}B[/dim]"
        + (f"  [dim italic]{proc}[/dim italic]" if proc else "")
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
    if info.get("rdns"): lines.append(f"  [dim]rDNS     [/dim]  [dim]{info['rdns']}[/dim]")
    h=info.get("http")
    if h:
        if h.get("type")=="REQUEST":
            lines.append(f"  [dim]HTTP     [/dim]  [bright_green]{h['method']}[/bright_green] [white]{h.get('host','')}{h.get('path','')}[/white]")
            if h.get("user_agent"): lines.append(f"  [dim]  User-Agent[/dim]  {truncate(h['user_agent'],60)}")
            if h.get("referer"):    lines.append(f"  [dim]  Referer  [/dim]  {h['referer']}")
            if h.get("body"):       lines.append(f"  [dim]  Body     [/dim]  [yellow]{truncate(h['body'],120)}[/yellow]")
        elif h.get("type")=="RESPONSE":
            sc=h.get("status_code",""); sc_col="green" if sc.startswith("2") else "yellow" if sc.startswith("3") else "red"
            lines.append(f"  [dim]HTTP     [/dim]  [{sc_col}]{sc} {h.get('status_text','')}[/{sc_col}]"+(f"  {h.get('content_type','')}" if h.get("content_type") else ""))
            if h.get("server"): lines.append(f"  [dim]  Server[/dim]  {h['server']}")
    di=info.get("dns")
    if di:
        if di.get("type")=="QUERY":
            lines.append(f"  [dim]DNS      [/dim]  [magenta]? {di.get('query','')}[/magenta]  [dim]{di.get('qtype','')}[/dim]")
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
        rc = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(intel.get("risk", "LOW"), "white")
        lines.append(
            f"  [dim]INTEL    [/dim]  [bold]{intel.get('activity','')}[/bold]"
            f"  [{rc}]risk={intel.get('risk','LOW')}[/{rc}]"
            f"  [dim]conf={intel.get('confidence',0)}%[/dim]"
        )
        if intel.get("reason"):
            lines.append(f"  [dim]  Why    [/dim]  [dim]{intel.get('reason')}[/dim]")
    console.print("\n".join(lines))
    console.print("[dim]"+"─"*100+"[/dim]")

def _process_packet(pkt) -> None:
    global _stats
    cfg = get_config().sensor
    with _lock:
        _stats["total"] += 1
        _stats["bytes"] += len(pkt)
        _captured_packets.append(pkt)
        if len(_captured_packets) > 8000:
            _captured_packets[:] = _captured_packets[-8000:]

    info: dict = {
        "timestamp": datetime.utcnow().strftime("%H:%M:%S.%f")[:-3],
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
        _packet_log.append(dict(info))
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
        if info["intel"] and info["intel"].get("risk") in ("MEDIUM", "HIGH"):
            _investigation_hits.append({
                "time": info.get("timestamp", ""),
                "src": src_ip,
                "dst": dst_ip,
                **info["intel"],
            })
        _packet_log.append(dict(info))
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
        if info["intel"] and info["intel"].get("risk") in ("MEDIUM", "HIGH"):
            _investigation_hits.append({
                "time": info.get("timestamp", ""),
                "src": src_ip,
                "dst": dst_ip,
                **info["intel"],
            })
        _packet_log.append(dict(info))
        _render(info)
        return

    if pkt.haslayer(UDP):
        info.update({"proto": "UDP", "src_port": pkt[UDP].sport, "dst_port": pkt[UDP].dport})
        with _lock:
            _stats["udp"] += 1
        info["intel"] = _infer_activity(info)
        if info["intel"] and info["intel"].get("risk") in ("MEDIUM", "HIGH"):
            _investigation_hits.append({
                "time": info.get("timestamp", ""),
                "src": src_ip,
                "dst": dst_ip,
                **info["intel"],
            })
        _packet_log.append(dict(info))
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
            "process": _find_process(tcp.sport, tcp.dport, src_ip, dst_ip),
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
        if info["intel"] and info["intel"].get("risk") in ("MEDIUM", "HIGH"):
            _investigation_hits.append({
                "time": info.get("timestamp", ""),
                "src": src_ip,
                "dst": dst_ip,
                **info["intel"],
            })
        with _lock:
            _stats["tcp"] += 1
        _packet_log.append(dict(info))
        _render(info)
        return

    info["intel"] = _infer_activity(info)
    _packet_log.append(dict(info))
    _render(info)


def _packet_callback(pkt) -> None:
    global _packet_queue
    if _packet_queue is None:
        return
    try:
        _packet_queue.put_nowait(pkt)
    except queue.Full:
        pass


def _worker_loop() -> None:
    while not _stop_sniffing or (_packet_queue and not _packet_queue.empty()):
        try:
            pkt = _packet_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            _process_packet(pkt)
        except Exception as e:
            log.debug(f"Packet processing error: {e}")
        finally:
            _packet_queue.task_done()


# ── Report Generator ──────────────────────────────────────────────────────────

def _generate_report(save_path:str, iface:str, bpf:str, dur_label:str) -> str:
    now=datetime.utcnow(); ts_str=now.strftime("%Y-%m-%d %H:%M:%S UTC")
    elapsed=(now-_stats["start"]).total_seconds(); pps=_stats["total"]/max(elapsed,1)
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
    for ip,g in _ips_seen.items():
        c=g.get("country","Unknown")
        if c and c!="Unknown": country_counts[c]+=1
    top_countries=sorted(country_counts.items(),key=lambda x:x[1],reverse=True)[:10]
    high_hits = [h for h in _investigation_hits if h.get("risk") == "HIGH"][:80]
    med_hits = [h for h in _investigation_hits if h.get("risk") == "MEDIUM"][:80]
    max_cnt=top_dsts[0][1] if top_dsts else 1
    max_co =top_countries[0][1] if top_countries else 1

    proto_colors={"HTTP":"#39d353","TCP":"#00d4ff","DNS":"#c09ffd","UDP":"#f0e040","ICMP":"#50fa7b","ARP":"#79c0ff","OTHER":"#888"}

    def badge(p): c=proto_colors.get(p,"#888"); return f"<span style='font-size:10px;padding:2px 7px;border-radius:3px;border:1px solid {c}44;background:{c}18;color:{c};font-weight:700'>{p}</span>"
    def method_badge(m):
        c="#39d353" if m=="GET" else "#ff4444" if m=="POST" else "#f0e040"
        return f"<span style='font-size:10px;padding:2px 7px;border-radius:3px;border:1px solid {c}44;background:{c}18;color:{c};font-weight:700'>{m}</span>"

    pkt_rows="".join(
        f"<tr><td class='ts'>{p.get('timestamp','')}</td><td>{badge(p.get('proto','?'))}</td>"
        f"<td class='mono'>{p.get('src_ip','?')}:{p.get('src_port','')}</td>"
        f"<td class='mono'>{p.get('dst_ip','?')}:{p.get('dst_port','')}</td>"
        f"<td class='right'>{p.get('size',0)}B</td>"
        f"<td class='dim'>{(p.get('geo') or {}).get('country','')}</td>"
        f"<td class='detail'>{p.get('http',{}).get('method','')+' '+p.get('http',{}).get('host','')+p.get('http',{}).get('path','') if p.get('http') else (p.get('dns') or {}).get('query','')}</td>"
        f"<td class='detail'>{(p.get('intel') or {}).get('activity','')}</td></tr>"
        for p in _packet_log[-300:]
    ) or "<tr><td colspan='8' class='dim'>No packets captured</td></tr>"

    intel_rows="".join(
        f"<tr><td class='ts'>{h.get('time','')}</td>"
        f"<td class='mono'>{h.get('src','')}</td><td class='mono'>{h.get('dst','')}</td>"
        f"<td><span style='font-size:10px;padding:2px 7px;border-radius:3px;border:1px solid {'#ff6b6b44' if h.get('risk')=='HIGH' else '#f0e04044'};background:{'#ff6b6b18' if h.get('risk')=='HIGH' else '#f0e04018'};color:{'#ff6b6b' if h.get('risk')=='HIGH' else '#f0e040'};font-weight:700'>{h.get('risk','')}</span></td>"
        f"<td class='detail'>{h.get('activity','')}</td>"
        f"<td class='dim'>{h.get('reason','')}</td>"
        f"<td class='right'>{h.get('confidence',0)}%</td></tr>"
        for h in (high_hits + med_hits)
    ) or "<tr><td colspan='7' class='dim'>No medium/high-risk inferences detected</td></tr>"

    http_rows="".join(
        f"<tr><td class='ts'>{h['time']}</td><td>{method_badge(h['method'])}</td>"
        f"<td class='mono'>{h['src']}</td>"
        f"<td class='detail'>{h['host']}{h['path'][:80]}</td>"
        f"<td class='dim'>{h['ua'][:50]}</td></tr>"
        for h in http_list
    ) or "<tr><td colspan='5' class='dim'>No HTTP requests captured</td></tr>"

    dns_rows="".join(f"<tr><td class='mono'>{d}</td></tr>" for d in domain_list) or "<tr><td class='dim'>No DNS queries</td></tr>"
    conn_rows="".join(
        f"<tr><td class='mono'>{c.get('src','')}:{c.get('sport','')}</td>"
        f"<td class='mono'>{c.get('dst','')}:{c.get('dport','')}</td>"
        f"<td class='dim'>{c.get('flags','')}</td></tr>"
        for c in conn_list
    ) or "<tr><td colspan='3' class='dim'>No connections tracked</td></tr>"

    ip_rows="".join(
        f"<tr><td class='mono'>{ip}</td><td class='right'>{cnt}</td>"
        f"<td class='dim'>{_ips_seen.get(ip,{}).get('country','LAN')}</td>"
        f"<td class='dim'>{_ips_seen.get(ip,{}).get('org','')[:35]}</td>"
        f"<td><div style='width:{int(cnt/max_cnt*100)}px;height:6px;background:#00d4ff44;border-radius:2px'></div></td></tr>"
        for ip,cnt in top_dsts
    ) or "<tr><td colspan='5' class='dim'>No destination data</td></tr>"

    ip_intel_rows="".join(
        f"<tr><td class='mono'>{ip}</td>"
        f"<td class='dim'>{_dns_cache.get(ip,'')}</td>"
        f"<td class='dim'>{_ips_seen.get(ip,{}).get('country','')}</td>"
        f"<td class='dim'>{_ips_seen.get(ip,{}).get('city','')}</td>"
        f"<td class='mono'>{float(_ips_seen.get(ip,{}).get('lat',0.0)):.5f}</td>"
        f"<td class='mono'>{float(_ips_seen.get(ip,{}).get('lon',0.0)):.5f}</td>"
        f"<td class='dim'>{_ips_seen.get(ip,{}).get('org','')[:30]}</td></tr>"
        for ip,_ in top_ips
    ) or "<tr><td colspan='7' class='dim'>No IP intelligence collected</td></tr>"

    country_rows="".join(
        f"<tr><td>{co}</td><td class='right'>{cnt}</td>"
        f"<td><div style='width:{int(cnt/max_co*120)}px;height:6px;background:#c09ffd44;border-radius:2px'></div></td></tr>"
        for co,cnt in top_countries
    ) or "<tr><td colspan='3' class='dim'>No geo data</td></tr>"

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
    <div class="meta-card"><div class="l">Interface</div><div class="v">{iface or "auto"}</div></div>
    <div class="meta-card"><div class="l">BPF Filter</div><div class="v">{bpf or "none — all traffic"}</div></div>
    <div class="meta-card"><div class="l">Duration</div><div class="v">{dur_label}</div></div>
    <div class="meta-card"><div class="l">Session Start</div><div class="v">{_stats['start'].strftime('%H:%M:%S UTC')}</div></div>
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
        <div class="sh">Investigation Highlights <span class="sub">— medium/high confidence events</span></div>
        <table><tr><th>Time</th><th>Source</th><th>Destination</th><th>Risk</th><th>Possible Activity</th><th>Why</th><th>Confidence</th></tr>{intel_rows}</table>
    </div>

    <div class="section">
        <div class="sh">Packet Log <span class="sub">— last {min(300,len(_packet_log))} of {len(_packet_log):,} captured</span></div>
        <table><tr><th>Time</th><th>Proto</th><th>Source</th><th>Destination</th><th>Size</th><th>Country</th><th>Detail</th><th>Possible Activity</th></tr>{pkt_rows}</table>
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

<div class="footer">
  <div class="fl">
    PacketPulse Network Forensic Capture Report<br>
    Generated: {ts_str}<br>
    Packets captured: {_stats['total']:,}  •  Data: {human_bytes(_stats['bytes'])}  •  Duration: {dur_label}
  </div>
  <div class="fr">
    <div class="fb">PacketPulse | Dreamwalker4u</div>
    <div class="fs">Network Forensics Platform  •  v1.0.2</div>
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
        return "activity=unknown risk=LOW conf=0%"
    return (
        f"activity={intel.get('activity','unknown')} "
        f"risk={intel.get('risk','LOW')} "
        f"conf={intel.get('confidence',0)}%"
    )


def _packet_detail_line(p: dict) -> str:
    if p.get("http"):
        h = p.get("http") or {}
        return f"HTTP {h.get('method','')} {h.get('host','')}{h.get('path','')}"
    if p.get("dns"):
        d = p.get("dns") or {}
        return f"DNS {d.get('type','')} {d.get('query','')}"
    return ""


def _endpoint_intel(ip: str) -> tuple[dict, str]:
    """Return GeoIP + reverse DNS for endpoint IP (LAN returns local placeholder)."""
    if not ip:
        return ({"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0, "org": ""}, "")
    if is_private_ip(ip):
        return ({"country": "LAN", "city": "Local", "lat": 0.0, "lon": 0.0, "org": "Private Network"}, "")

    geo = _geo(ip)
    if ip not in _dns_cache:
        _dns_cache[ip] = reverse_dns(ip)
    return geo, _dns_cache.get(ip, "")


def _fmt_ip(ip: str) -> str:
    if not ip:
        return "unknown"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x"
    return ip


def _analyze_capture_summary(iface: str, dur_label: str) -> dict:
    packets = _packet_log
    total = len(packets)
    if total == 0:
        return {
            "headline": ["No packets captured; investigation summary unavailable."],
            "key_intel": [],
            "can_extract": [],
            "cannot_extract": [],
            "verdict": "No traffic captured",
        }

    proto_counts = Counter((p.get("proto") or "OTHER") for p in packets)
    udp_only = proto_counts.get("UDP", 0) == total
    unique_ips = set()
    port_counts = Counter()
    confs = []

    for p in packets:
        si = p.get("src_ip")
        di = p.get("dst_ip")
        if si:
            unique_ips.add(si)
        if di:
            unique_ips.add(di)
        for po in (p.get("src_port"), p.get("dst_port")):
            if po:
                try:
                    port_counts[int(po)] += 1
                except Exception:
                    pass
        intel = p.get("intel") or {}
        if intel.get("confidence") is not None:
            try:
                confs.append(int(intel.get("confidence")))
            except Exception:
                pass

    avg_conf = round(sum(confs) / len(confs), 1) if confs else 0.0

    # Infer local/private and remote/public peers.
    src_counts = Counter(p.get("src_ip") for p in packets if p.get("src_ip"))
    dst_counts = Counter(p.get("dst_ip") for p in packets if p.get("dst_ip"))
    ip_counts = src_counts + dst_counts

    private_ips = [ip for ip in ip_counts if is_private_ip(ip)]
    public_ips = [ip for ip in ip_counts if not is_private_ip(ip)]

    local_ip = max(private_ips, key=lambda i: ip_counts[i]) if private_ips else (max(ip_counts, key=ip_counts.get) if ip_counts else "")
    remote_ip = max(public_ips, key=lambda i: ip_counts[i]) if public_ips else ""

    inbound = 0
    outbound = 0
    if local_ip and remote_ip:
        for p in packets:
            if p.get("src_ip") == remote_ip and p.get("dst_ip") == local_ip:
                inbound += 1
            elif p.get("src_ip") == local_ip and p.get("dst_ip") == remote_ip:
                outbound += 1

    # Size classes.
    sz_data = sum(1 for p in packets if 1200 <= int(p.get("size", 0)) <= 1600)
    sz_ack = sum(1 for p in packets if 100 <= int(p.get("size", 0)) <= 200)
    sz_other = total - sz_data - sz_ack

    # 500ms packet-rate timeline and burst detection.
    bucket = defaultdict(int)
    t_vals = []
    for p in packets:
        ts = p.get("timestamp", "")
        if not ts:
            continue
        try:
            dt = datetime.strptime(ts, "%H:%M:%S.%f")
            sec = dt.hour * 3600 + dt.minute * 60 + dt.second + dt.microsecond / 1_000_000.0
            bi = int(sec * 2)
            bucket[bi] += 1
            t_vals.append(sec)
        except Exception:
            continue

    burst_start = "n/a"
    burst_end = "n/a"
    if bucket:
        keys = sorted(bucket)
        run_start = None
        prev = None
        best_len = 0
        best_range = None
        # >= 8 packets per 500ms ~= >= 16 packets/sec burst.
        hot = {k for k, v in bucket.items() if v >= 8}
        for k in keys:
            if k in hot:
                if run_start is None:
                    run_start = k
                elif prev is not None and k != prev + 1:
                    ln = prev - run_start + 1
                    if ln > best_len:
                        best_len = ln
                        best_range = (run_start, prev)
                    run_start = k
                prev = k
            else:
                if run_start is not None and prev is not None:
                    ln = prev - run_start + 1
                    if ln > best_len:
                        best_len = ln
                        best_range = (run_start, prev)
                run_start = None
                prev = None
        if run_start is not None and prev is not None:
            ln = prev - run_start + 1
            if ln > best_len:
                best_range = (run_start, prev)
        if best_range:
            b0, b1 = best_range
            burst_start = time.strftime("%H:%M:%S", time.gmtime(b0 / 2))
            burst_end = time.strftime("%H:%M:%S", time.gmtime((b1 + 1) / 2))

    dominant_port = port_counts.most_common(1)[0][0] if port_counts else None
    wireguard_like = bool(
        udp_only and dominant_port == 51820 and remote_ip and not is_private_ip(remote_ip)
    )

    elapsed = (datetime.utcnow() - _stats["start"]).total_seconds()
    pps = _stats["total"] / max(elapsed, 1)

    risk = "MEDIUM"
    if wireguard_like:
        risk = "LOW"
    elif _investigation_hits and any(h.get("risk") == "HIGH" for h in _investigation_hits):
        risk = "HIGH"

    headline = [
        f"{_stats['total']:,} total packets | {'100% UDP only' if udp_only else 'mixed protocols'} | {dur_label} capture | {pps:.1f} packets/sec",
        f"{human_bytes(_stats['bytes'])} transferred | {len(unique_ips)} unique IPs | {len(port_counts)} ports used | {avg_conf}% avg confidence",
    ]

    key_intel = []
    if wireguard_like:
        key_intel.append(
            f"WireGuard VPN tunnel likely confirmed on port 51820 between {local_ip or 'local host'} and {remote_ip}."
        )
    if inbound or outbound:
        direction = "download-heavy" if inbound > outbound else "upload-heavy" if outbound > inbound else "balanced"
        key_intel.append(
            f"Traffic direction appears {direction}: inbound ~{inbound} packets vs outbound ~{outbound} packets."
        )
    key_intel.append(
        f"Packet sizes: 1200-1600B ~{sz_data} packets, 100-200B ~{sz_ack} packets, other sizes ~{sz_other} packets."
    )
    if burst_start != "n/a":
        key_intel.append(
            f"Burst activity window detected around {burst_start} to {burst_end} (500ms buckets)."
        )
    if _stats.get("tcp", 0) == 0 and _stats.get("dns", 0) == 0 and _stats.get("http", 0) == 0:
        key_intel.append(
            "No plaintext TCP/HTTP/DNS observed in this capture window; traffic appears encrypted/opaque."
        )

    can_extract = [
        f"Primary peer IP: {remote_ip or 'unknown'}",
        f"Session duration estimate: {dur_label}",
        f"Transferred volume: {human_bytes(_stats['bytes'])}",
        f"Likely activity: {'VPN tunnel / bulk transfer' if wireguard_like else 'network session analysis from metadata'}",
        f"Direction split: inbound ~{inbound}, outbound ~{outbound}",
        f"Burst window: {burst_start} -> {burst_end}" if burst_start != "n/a" else "Burst window: no sustained burst detected",
    ]
    cannot_extract = [
        "Exact payload contents when traffic is encrypted",
        "Visited websites/domains hidden inside encrypted tunnels",
        "Downloaded file names/content when payload is encrypted",
        "True final destinations behind VPN/relay endpoints",
    ]

    verdict = (
        f"Protocol profile: {'WireGuard-like UDP tunnel' if wireguard_like else 'Mixed/unknown traffic profile'} | "
        f"Risk: {risk} | Peer: {remote_ip or 'unknown'}:{dominant_port or 'n/a'}"
    )

    return {
        "headline": headline,
        "key_intel": key_intel,
        "can_extract": can_extract,
        "cannot_extract": cannot_extract,
        "verdict": verdict,
    }


def _generate_pdf_report(save_path: str, iface: str, bpf: str, dur_label: str) -> str:
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

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    summary = _analyze_capture_summary(iface, dur_label)
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

    risk_counter = Counter((h.get("risk") or "LOW").upper() for h in _investigation_hits)
    high_ips = {h.get("src") for h in _investigation_hits if (h.get("risk") or "").upper() == "HIGH"} | {
        h.get("dst") for h in _investigation_hits if (h.get("risk") or "").upper() == "HIGH"
    }
    medium_ips = {h.get("src") for h in _investigation_hits if (h.get("risk") or "").upper() == "MEDIUM"} | {
        h.get("dst") for h in _investigation_hits if (h.get("risk") or "").upper() == "MEDIUM"
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
    timeline_max = max((v for _, v in timeline_top), default=1)

    avg_rate = (sum(v for _, v in timeline_items) / len(timeline_items)) if timeline_items else 0
    peak_time, peak_count = max(timeline_items, key=lambda x: x[1]) if timeline_items else ("n/a", 0)

    overall_risk = "LOW"
    if risk_counter.get("HIGH", 0) > 0:
        overall_risk = "HIGH"
    elif risk_counter.get("MEDIUM", 0) > 0:
        overall_risk = "MEDIUM"

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
    c.drawCentredString(width / 2, height * 0.47, f"Interface: {iface or 'auto'} | Filter: {bpf or 'none'} | Duration: {dur_label}")
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
        ("Risk Level", overall_risk, palette["orange"] if overall_risk == "MEDIUM" else palette["red"] if overall_risk == "HIGH" else palette["green"]),
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
    total_dir = max(inbound + outbound, 1)
    in_deg = 360 * inbound / total_dir
    out_deg = 360 - in_deg

    _apply_stroke(palette["line"])
    _apply_fill(palette["cyan"])
    c.wedge(pie_x - pie_r, pie_y - pie_r, pie_x + pie_r, pie_y + pie_r, 90, -in_deg, stroke=1, fill=1)
    _apply_fill(palette["orange"])
    c.wedge(pie_x - pie_r, pie_y - pie_r, pie_x + pie_r, pie_y + pie_r, 90 - in_deg, -out_deg, stroke=1, fill=1)
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
    max_proto = max(proto_counts.values()) if proto_counts else 1
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
    max_bin = max(size_bins.values()) if size_bins else 1
    x_cursor = margin
    bar_area_h = 92
    bar_w = (content_w - 20) / len(size_bins)
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
    _section_title("IP Intelligence", "Color-coded endpoint table with risk hints")

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
        risk = "LOW"
        if ip in high_ips:
            risk = "HIGH"
        elif ip in medium_ips:
            risk = "MEDIUM"
        risk_color = palette["green"] if risk == "LOW" else palette["orange"] if risk == "MEDIUM" else palette["red"]

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
    _section_title("Key Findings", "Human-friendly investigation insights")

    findings = list(summary.get("key_intel", []))
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
    _section_title("Risk Analysis", "Why this session is categorized as low/medium/high")
    total_events = max(len(_investigation_hits), 1)
    low_events = max(total_events - risk_counter.get("MEDIUM", 0) - risk_counter.get("HIGH", 0), 0)
    risk_rows = [
        ("LOW", low_events, palette["green"]),
        ("MEDIUM", risk_counter.get("MEDIUM", 0), palette["orange"]),
        ("HIGH", risk_counter.get("HIGH", 0), palette["red"]),
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
        "Why medium? Medium risk usually indicates encrypted or atypical sessions without direct malicious payload evidence. "
        "It implies continued monitoring is recommended, especially for repeated medium-risk peers and bursty UDP traffic."
        if overall_risk == "MEDIUM"
        else "Risk level is based on observed intelligence events and confidence scores within this capture window."
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
                "activity": (p.get("intel") or {}).get("activity", "Packet observed"),
                "proto": p.get("proto", "OTHER"),
                "risk": (p.get("intel") or {}).get("risk", "LOW"),
            }
            for p in packets[-14:]
        ]

    for e in timeline_events:
        _ensure_space(16, "Timeline")
        tval = e.get("time", "n/a")
        event = (e.get("activity", "Event") or "Event")[:44]
        typ = (e.get("proto") or e.get("type") or "NET")[:7]
        risk = (e.get("risk") or "LOW").upper()
        risk_color = palette["green"] if risk == "LOW" else palette["orange"] if risk == "MEDIUM" else palette["red"]
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
    c.drawString(margin + 12, y - 18, "Final Verdict")
    _apply_fill(palette["text"])
    c.setFont("Helvetica", 10)
    c.drawString(margin + 12, y - 36, f"Risk Level: {overall_risk}")
    likely_activity = (summary.get("verdict", "") or "Network activity observed")[:90]
    c.drawString(margin + 12, y - 52, f"Likely Activity: {likely_activity}")
    avg_conf = 0.0
    if _investigation_hits:
        avg_conf = round(sum(int(h.get("confidence", 0) or 0) for h in _investigation_hits) / len(_investigation_hits), 1)
    c.drawString(margin + 12, y - 68, f"Confidence: {avg_conf:.1f}%")
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
        risk = ((p.get("intel") or {}).get("risk", "LOW") or "LOW").upper()
        line = f"{idx:04d} {t} {proto:4} {src:27} -> {dst:27} {sz:5}B {risk:6}"
        _apply_fill(palette["text"])
        c.drawString(margin, y, line[:130])
        y -= 9

    _draw_page_footer("Appendix Logs")
    c.save()
    return save_path


def _print_stats() -> None:
    elapsed=(datetime.utcnow()-_stats["start"]).total_seconds(); pps=_stats["total"]/max(elapsed,1)
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

def run_sniffer(interface:Optional[str]=None,bpf_filter:str="",count:int=0,duration:int=0,save_pcap:bool=True)->None:
    global _sniff_start_time,_sniff_duration,_stop_sniffing,_stats
    global _packet_log,_connections,_domains_seen,_ips_seen,_http_requests,_captured_packets,_investigation_hits
    global _packet_queue,_worker_thread
    if not SCAPY_OK: console.print("[red]ERROR: scapy not installed.[/red]"); return
    _stop_sniffing=False; _sniff_duration=duration; _sniff_start_time=time.time() if duration>0 else None
    _stats={"total":0,"tcp":0,"udp":0,"icmp":0,"arp":0,"other":0,"bytes":0,"http":0,"dns":0,"start":datetime.utcnow()}
    _packet_log.clear(); _connections.clear(); _domains_seen.clear()
    _ips_seen.clear(); _http_requests.clear(); _captured_packets.clear(); _investigation_hits.clear()
    _packet_queue = queue.Queue()
    _worker_thread = threading.Thread(target=_worker_loop, daemon=True)
    _worker_thread.start()
    cfg=get_config().sensor; iface=interface or cfg.interface; dur_label=_fmt_dur(duration)
    console.rule("[bold green]PACKETPULSE — DEEP PACKET SNIFFER[/bold green]")
    console.print(f"  [dim]Interface:[/dim] [green]{iface or 'auto'}[/green]  [dim]Filter:[/dim] [yellow]{bpf_filter or 'none'}[/yellow]  [dim]Duration:[/dim] [yellow]{dur_label}[/yellow]")
    console.print("  [dim]A full forensic report (HTML + PDF + JSON) will be generated when capture ends.[/dim]")
    console.print("[dim]"+"─"*100+"[/dim]\n")
    ensure_dir(cfg.pcap_store_path)
    try:
        sniff(iface=iface or None,filter=bpf_filter or None,prn=_packet_callback,
              stop_filter=_should_stop,count=count or 0,store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        console.print("[red]ERROR: Requires root/sudo.[/red]")
        _stop_sniffing = True
        if _packet_queue:
            _packet_queue.join()
        return
    except Exception as e:
        console.print(f"[red]Sniffer error: {e}[/red]")
        _stop_sniffing = True
        if _packet_queue:
            _packet_queue.join()
        return
    finally:
        _stop_sniffing = True
        if _packet_queue:
            _packet_queue.join()
        if _worker_thread:
            _worker_thread.join(timeout=2)
    _print_stats()
    if save_pcap and _captured_packets:
        fname=f"{cfg.pcap_store_path}/session_{timestamp_filename()}.pcap"
        try: wrpcap(fname,_captured_packets); console.print(f"\n[green]PCAP saved →[/green] [cyan]{fname}[/cyan]")
        except Exception as e: console.print(f"[yellow]PCAP save failed: {e}[/yellow]")
    console.print("\n[dim]Generating forensic report...[/dim]")
    rpath=f"{cfg.pcap_store_path}/report_{timestamp_filename()}.html"
    try:
        out=_generate_report(rpath,iface or "auto",bpf_filter,dur_label)
        console.print(f"\n[bold green]╔════════════════════════════════════════════════╗[/bold green]")
        console.print(f"[bold green]║  REPORT READY  —  PacketPulse | Dreamwalker4u  ║[/bold green]")
        console.print(f"[bold green]╚════════════════════════════════════════════════╝[/bold green]")
        console.print(f"  [dim]HTML →[/dim] [bold cyan]{out}[/bold cyan]")
        console.print(f"  [dim]Open in any browser to view the full forensic report.[/dim]\n")
    except Exception as e: console.print(f"[red]Report failed: {e}[/red]")
    try:
        pp=rpath.replace(".html", ".pdf")
        pdf_out=_generate_pdf_report(pp,iface or "auto",bpf_filter,dur_label)
        console.print(f"  [dim]PDF  →[/dim] [bold cyan]{pdf_out}[/bold cyan]\n")
    except Exception as e:
        console.print(f"[yellow]PDF report failed: {e}[/yellow]")
    try:
        jp=rpath.replace(".html",".json")
        save_json({"session":{"interface":iface,"filter":bpf_filter,"duration":dur_label,"generated":now_str()},
                   "stats":{k:v for k,v in _stats.items() if k!="start"},
                   "dns_queries":list(_domains_seen),"http_requests":_http_requests[:100],
                   "connections":list(_connections.values())[:100],
                   "investigation_hits":_investigation_hits[:200],
                   "ip_intelligence":[
                       {
                           "ip": ip,
                           "rdns": _dns_cache.get(ip, ""),
                           "country": _ips_seen.get(ip, {}).get("country", ""),
                           "city": _ips_seen.get(ip, {}).get("city", ""),
                           "lat": _ips_seen.get(ip, {}).get("lat", 0.0),
                           "lon": _ips_seen.get(ip, {}).get("lon", 0.0),
                           "org": _ips_seen.get(ip, {}).get("org", ""),
                       }
                       for ip in sorted(_ips_seen.keys())
                   ]},jp)
        console.print(f"  [dim]JSON →[/dim] [cyan]{jp}[/cyan]\n")
        ndjp = rpath.replace(".html",".ndjson")
        save_ndjson(_packet_log, ndjp)
        console.print(f"  [dim]NDJSON →[/dim] [cyan]{ndjp}[/cyan]\n")
    except Exception as e:
        console.print(f"[yellow]JSON/NDJSON save failed: {e}[/yellow]")
