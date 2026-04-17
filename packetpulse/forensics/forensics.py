"""
PacketPulse — Deep Device Forensics
Extracts every possible data point from USB + LAN devices.
Report output: JSON (enject-compatible) + terminal display.
Branding: PacketPulse | Dreamwalker4u
"""
from __future__ import annotations

import re, json, socket, subprocess, threading, platform, hashlib, time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil
from rich.console import Console
from rich.table import Table
from rich import box

from packetpulse.core.config import get_config
from packetpulse.core.logger import get_logger
from packetpulse.utils.helpers import (
    geoip_lookup, is_private_ip, save_json, ensure_dir, now_str, human_bytes, timestamp_filename, save_report_pdf
)

console = Console()
log = get_logger("forensics")

# ── Device history (cross-session) ────────────────────────────────────────────
_device_history: dict[str, int] = {}
_HIST_FILE = "pcap_store/forensics/.device_history.json"

def _load_history():
    try:
        with open(_HIST_FILE) as f:
            _device_history.update(json.load(f))
    except: pass

def _save_history():
    try:
        Path(_HIST_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(_HIST_FILE,"w") as f: json.dump(_device_history, f)
    except: pass


# ═══════════════════════════════════════════════════════════════════════════════
# MAC OUI LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

def _mac_lookup(mac: str) -> str:
    try:
        from manuf import manuf
        p = manuf.MacParser()
        result = p.get_manuf(mac)
        if result: return result
    except: pass
    prefix = mac.upper().replace("-",":")[0:8]
    KNOWN = {
        "00:0C:29":"VMware","00:50:56":"VMware","08:00:27":"VirtualBox","52:54:00":"QEMU/KVM",
        "3C:06:30":"Apple","A4:C3:F0":"Apple","A8:66:7F":"Apple","AC:87:A3":"Apple",
        "B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi","E4:5F:01":"Raspberry Pi",
        "00:1A:11":"Google","94:65:2D":"Google","3C:21:9C":"Google Nest",
        "FC:F1:36":"Samsung","CC:79:CF":"Samsung","70:F0:87":"Samsung",
        "00:26:B9":"Dell","D4:BE:D9":"Dell","18:66:DA":"Dell",
        "00:21:CC":"Cisco","00:24:13":"Cisco","00:1B:2B":"Cisco",
        "D4:5D:64":"TP-Link","50:C7:BF":"TP-Link","00:0F:F7":"TP-Link",
        "80:CE:62":"Huawei","90:4E:2B":"Huawei","00:E0:4C":"Realtek",
        "B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi",
        "00:16:3E":"Xen","00:1B:44":"SanDisk","F0:18:98":"Xiaomi",
        "FC:F5:28":"Huawei","B0:A7:B9":"Intel","8C:8D:28":"Intel",
        "3C:D9:2B":"Hewlett Packard","38:63:BB":"HP",
        "00:60:2F":"Cisco-Linksys","00:18:F8":"Netgear","C0:3F:0E":"Netgear",
    }
    return KNOWN.get(prefix, "Unknown")


# ═══════════════════════════════════════════════════════════════════════════════
# OS FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════════

OS_SIGNATURES = [
    (120,128,8192, 65535,"Windows 10/11",90),(112,120,8192,65535,"Windows 7/8",80),
    (60, 64, 5840, 29200,"Linux 4.x/5.x", 88),(60, 64,65535,65535,"Linux / Android",82),
    (58, 64,65535,65535,"macOS / iOS",85),(50,64,4096,16384,"Embedded / IoT",70),
    (60, 64, 1024, 4096,"FreeBSD",75),(30,64,512,4096,"Network Device",72),
]

def _fingerprint_os(ttl:int, window:int, vendor:str) -> tuple[str,int]:
    v = vendor.lower()
    if "apple"     in v: return "macOS / iOS",85
    if "microsoft" in v: return "Windows",85
    if "raspberry" in v: return "Linux (Raspberry Pi OS)",95
    if "samsung"   in v or "xiaomi" in v: return "Android",80
    if "vmware"    in v: return "Linux (VMware guest)",88
    if "virtualbox"in v: return "Linux/Windows (VirtualBox)",80
    if "cisco"     in v or "netgear" in v or "tp-link" in v: return "Network Equipment OS",75
    for tmin,tmax,wmin,wmax,name,conf in OS_SIGNATURES:
        if tmin<=ttl<=tmax and wmin<=window<=wmax: return name,conf
    if ttl>=120: return "Windows",60
    if ttl>=60:  return "Linux / Unix",60
    if ttl>=30:  return "Network Device",55
    return "Unknown",0


# ═══════════════════════════════════════════════════════════════════════════════
# LOCAL MACHINE PROFILE
# ═══════════════════════════════════════════════════════════════════════════════

def _profile_local_machine() -> dict:
    """Extract every possible data point about the machine running PacketPulse."""
    data: dict = {"type": "local_machine", "timestamp": now_str()}
    try:
        data["hostname"]  = socket.gethostname()
        data["fqdn"]      = socket.getfqdn()
        data["os"]        = platform.system()
        data["os_release"]= platform.release()
        data["os_version"]= platform.version()
        data["machine"]   = platform.machine()
        data["processor"] = platform.processor()
        data["python"]    = platform.python_version()
        data["boot_time"] = datetime.fromtimestamp(psutil.boot_time()).isoformat()
        uptime = time.time() - psutil.boot_time()
        data["uptime_hours"] = round(uptime/3600, 2)
    except Exception as e: data["error_basic"] = str(e)

    # CPU
    try:
        data["cpu_physical_cores"] = psutil.cpu_count(logical=False)
        data["cpu_logical_cores"]  = psutil.cpu_count(logical=True)
        data["cpu_freq_mhz"]       = psutil.cpu_freq().current if psutil.cpu_freq() else None
        data["cpu_usage_pct"]      = psutil.cpu_percent(interval=0.5)
    except: pass

    # Memory
    try:
        mem = psutil.virtual_memory()
        data["memory_total_gb"]  = round(mem.total/1e9, 2)
        data["memory_used_gb"]   = round(mem.used/1e9, 2)
        data["memory_free_gb"]   = round(mem.available/1e9, 2)
        data["memory_pct"]       = mem.percent
        swap = psutil.swap_memory()
        data["swap_total_gb"] = round(swap.total/1e9, 2)
        data["swap_used_gb"]  = round(swap.used/1e9, 2)
    except: pass

    # Disk
    try:
        disks = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    "device": part.device,"mountpoint": part.mountpoint,
                    "fstype": part.fstype,"total_gb": round(usage.total/1e9,2),
                    "used_gb": round(usage.used/1e9,2),"free_gb": round(usage.free/1e9,2),
                    "pct": usage.percent,
                })
            except: pass
        data["disks"] = disks
    except: pass

    # Network interfaces
    try:
        ifaces = []
        for name, addrs in psutil.net_if_addrs().items():
            iface = {"name": name, "addresses": []}
            stats = psutil.net_if_stats().get(name)
            if stats:
                iface["is_up"]    = stats.isup
                iface["speed_mb"] = stats.speed
                iface["mtu"]      = stats.mtu
            for addr in addrs:
                iface["addresses"].append({
                    "family": str(addr.family), "address": addr.address,
                    "netmask": addr.netmask or "", "broadcast": addr.broadcast or "",
                })
            ifaces.append(iface)
        data["network_interfaces"] = ifaces
    except: pass

    # Network counters
    try:
        nc = psutil.net_io_counters()
        data["net_bytes_sent"]   = nc.bytes_sent
        data["net_bytes_recv"]   = nc.bytes_recv
        data["net_packets_sent"] = nc.packets_sent
        data["net_packets_recv"] = nc.packets_recv
        data["net_errors_in"]    = nc.errin
        data["net_errors_out"]   = nc.errout
    except: pass

    # Open sockets
    try:
        conns = []
        for c in psutil.net_connections(kind="inet"):
            try:
                proc_name = psutil.Process(c.pid).name() if c.pid else ""
            except: proc_name = ""
            conns.append({
                "family": str(c.family),"type": str(c.type),
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status": c.status,"pid": c.pid,"process": proc_name,
            })
        data["open_connections"] = conns[:100]
    except: pass

    # Listening ports
    try:
        listening = [c for c in psutil.net_connections(kind="inet")
                     if c.status == "LISTEN" and c.laddr]
        data["listening_ports"] = [
            {"port": c.laddr.port,"addr": c.laddr.ip,
             "pid": c.pid,"process": psutil.Process(c.pid).name() if c.pid else ""}
            for c in listening
        ]
    except: pass

    # Processes with network activity
    try:
        net_procs = []
        for proc in psutil.process_iter(["pid","name","status","cpu_percent","memory_info"]):
            try:
                conns = proc.connections(kind="inet")
                if conns:
                    net_procs.append({
                        "pid":     proc.info["pid"],
                        "name":    proc.info["name"],
                        "status":  proc.info["status"],
                        "connections": len(conns),
                        "cpu_pct": proc.info["cpu_percent"],
                        "mem_mb":  round(proc.info["memory_info"].rss/1e6,2) if proc.info["memory_info"] else 0,
                    })
            except: pass
        data["network_processes"] = sorted(net_procs, key=lambda x:x["connections"], reverse=True)[:30]
    except: pass

    # ARP table
    try:
        arp_out = subprocess.run(["arp","-n"],capture_output=True,text=True,timeout=5)
        data["arp_table_raw"] = arp_out.stdout[:2000]
    except: pass

    # Routing table
    try:
        route_out = subprocess.run(["ip","route"],capture_output=True,text=True,timeout=5)
        data["routing_table_raw"] = route_out.stdout[:2000]
    except:
        try:
            r = subprocess.run(["netstat","-rn"],capture_output=True,text=True,timeout=5)
            data["routing_table_raw"] = r.stdout[:2000]
        except: pass

    # DNS cache (systemd-resolved)
    try:
        dns_out = subprocess.run(["resolvectl","statistics"],capture_output=True,text=True,timeout=5)
        data["dns_resolver_stats"] = dns_out.stdout[:1000]
    except: pass

    # USB history (from kernel logs)
    try:
        dmesg = subprocess.run(["dmesg","--notime"],capture_output=True,text=True,timeout=5)
        usb_lines = [l for l in dmesg.stdout.splitlines() if "usb" in l.lower() and
                     any(k in l.lower() for k in ["new","disconnect","product","manufacturer","serial"])]
        data["usb_kernel_history"] = usb_lines[-30:]
    except: pass

    return data


# ═══════════════════════════════════════════════════════════════════════════════
# USB DEVICE PROFILING
# ═══════════════════════════════════════════════════════════════════════════════

def _get_usb_blkid(device: str) -> dict:
    """Get filesystem info for a USB storage device via blkid."""
    info: dict = {}
    try:
        r = subprocess.run(["blkid","-o","export",device],
                           capture_output=True,text=True,timeout=5)
        for line in r.stdout.splitlines():
            if "=" in line:
                k,_,v = line.partition("=")
                info[k.lower()] = v
    except: pass
    return info

def _get_usb_lsusb_detail(vid: str, pid: str) -> dict:
    """Get extended USB info via lsusb -v."""
    detail: dict = {}
    try:
        r = subprocess.run(["lsusb","-d",f"{vid}:{pid}","-v"],
                           capture_output=True,text=True,timeout=8)
        for line in r.stdout.splitlines():
            line = line.strip()
            for key in ["iManufacturer","iProduct","iSerialNumber","bcdUSB",
                        "bDeviceClass","bDeviceSubClass","bDeviceProtocol",
                        "bMaxPower","wTotalLength"]:
                if line.startswith(key):
                    parts = line.split(None,2)
                    if len(parts) >= 2:
                        detail[key] = parts[-1].strip()
    except: pass
    return detail

def _platform_from_device(vid:str, pid:str, product:str, manufacturer:str) -> str:
    p = (product+" "+manufacturer).lower()
    if vid=="05ac" or "apple" in manufacturer.lower():
        if "iphone" in p: return "iOS"
        if "ipad" in p: return "iPadOS"
        if "macbook" in p or "imac" in p: return "macOS"
        return "Apple"
    if vid in ("18d1","04e8","12d1","19d2","2717") or "android" in p or "adb" in p:
        return "Android"
    if "windows" in p: return "Windows"
    if "raspberry" in p: return "Linux (Raspberry Pi)"
    if "linux" in p: return "Linux"
    return ""

def _classify_usb(device_class:str, product:str, manufacturer:str) -> str:
    p = (product+" "+manufacturer).lower()
    dc = device_class.lower()
    if "storage" in dc or "disk" in p or "flash" in p or "drive" in p: return "Mass Storage"
    if "hid" in dc or "keyboard" in p: return "HID Keyboard"
    if "hid" in dc or "mouse" in p: return "HID Mouse"
    if "audio" in dc or "headset" in p or "microphone" in p: return "Audio Device"
    if "network" in dc or "ethernet" in p or "wifi" in p: return "Network Adapter"
    if "iphone" in p or "ipad" in p: return "Apple Mobile Device (MFi)"
    if "android" in p or "adb" in p: return "Android Device"
    if "printer" in p: return "Printer"
    if "webcam" in p or "camera" in p or "video" in dc: return "Camera / Webcam"
    if "hub" in dc or "hub" in p: return "USB Hub"
    if "smartcard" in dc or "card reader" in p: return "Smart Card Reader"
    return "USB Device"

def _get_storage_detail(product:str) -> Optional[dict]:
    time.sleep(1.5)
    best = None
    for part in psutil.disk_partitions(all=True):
        if not part.mountpoint or part.fstype in ("","tmpfs","devtmpfs","sysfs","proc","cgroup","squashfs"):
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
            blkid = _get_usb_blkid(part.device)
            d = {
                "device":      part.device,
                "label":       blkid.get("label", Path(part.mountpoint).name),
                "uuid":        blkid.get("uuid",""),
                "fstype":      part.fstype or blkid.get("type",""),
                "total_bytes": usage.total,
                "used_bytes":  usage.used,
                "free_bytes":  usage.free,
                "pct_used":    usage.percent,
                "mountpoint":  part.mountpoint,
                "total_hr":    human_bytes(usage.total),
                "used_hr":     human_bytes(usage.used),
                "free_hr":     human_bytes(usage.free),
            }
            if best is None or usage.total > best.get("total_bytes",0):
                best = d
        except: pass
    return best

def _scan_usb_devices() -> list[dict]:
    devices = []
    _load_history()
    try:
        import pyudev
        context = pyudev.Context()
        for dev in context.list_devices(subsystem="usb", DEVTYPE="usb_device"):
            try:
                vid      = (dev.get("ID_VENDOR_ID") or "").lower()
                pid      = (dev.get("ID_MODEL_ID") or "").lower()
                product  = (dev.get("ID_MODEL") or dev.get("ID_MODEL_FROM_DATABASE") or "").replace("_"," ").strip()
                manuf    = (dev.get("ID_VENDOR") or dev.get("ID_VENDOR_FROM_DATABASE") or "").replace("_"," ").strip()
                serial   = dev.get("ID_SERIAL_SHORT") or dev.get("ID_SERIAL") or ""
                bus      = dev.get("BUSNUM") or ""
                devnum   = dev.get("DEVNUM") or ""
                devpath  = dev.get("DEVPATH") or ""
                devnode  = dev.get("DEVNAME") or ""

                if not product and not manuf: continue

                # Speed
                speed_raw = ""
                try: speed_raw = dev.attributes.asstring("speed") if dev.attributes.available_attributes else ""
                except: pass
                speed_map = {"1.5":"USB 1.1 (Low Speed — 1.5 Mbps)","12":"USB 1.1 (Full Speed — 12 Mbps)",
                             "480":"USB 2.0 (High Speed — 480 Mbps)","5000":"USB 3.0 (SuperSpeed — 5 Gbps)",
                             "10000":"USB 3.1 Gen2 (10 Gbps)","20000":"USB 3.2 Gen2x2 (20 Gbps)"}
                speed_str = speed_map.get(speed_raw.strip(), f"USB ({speed_raw} Mbps)" if speed_raw else "Unknown")

                # Power
                power_raw = ""
                try: power_raw = dev.attributes.asstring("bMaxPower") if dev.attributes.available_attributes else ""
                except: pass

                # Device class
                dev_class = (dev.get("ID_USB_CLASS_FROM_DATABASE") or
                             dev.get("DRIVER") or
                             dev.attributes.asstring("bDeviceClass") if hasattr(dev,"attributes") else "Unknown")
                try: dev_class = dev_class or "Unknown"
                except: dev_class = "Unknown"

                driver   = dev.get("DRIVER") or ""
                seen     = _device_history.get(serial, 0)
                _device_history[serial] = seen + 1
                _save_history()

                lsusb_detail = _get_usb_lsusb_detail(vid, pid)
                os_platform  = _platform_from_device(vid, pid, product, manuf)
                device_type  = _classify_usb(dev_class, product, manuf)
                risk         = "NEW_DEVICE" if seen == 0 else "KNOWN"

                # Hash for fingerprint
                fingerprint = hashlib.sha256(f"{vid}{pid}{serial}".encode()).hexdigest()[:16]

                d = {
                    "type":          "usb_device",
                    "timestamp":     now_str(),
                    "product":       product or "Unknown Device",
                    "manufacturer":  manuf,
                    "serial_number": serial,
                    "vid":           vid,
                    "pid":           pid,
                    "vid_pid_str":   f"VID_{vid.upper()}&PID_{pid.upper()}",
                    "bus":           bus,
                    "port":          devnum,
                    "devpath":       devpath,
                    "devnode":       devnode,
                    "speed":         speed_str,
                    "max_power_ma":  power_raw,
                    "device_class":  dev_class,
                    "device_type":   device_type,
                    "driver":        driver,
                    "os_platform":   os_platform,
                    "lsusb_detail":  lsusb_detail,
                    "fingerprint":   fingerprint,
                    "times_seen":    seen,
                    "first_seen":    "THIS SESSION" if seen == 0 else f"SESSION #{seen+1}",
                    "risk":          risk,
                    "connected_at":  now_str(),
                }

                # Storage details
                if any(k in device_type.lower() for k in ["storage","mass"]):
                    storage = _get_storage_detail(product)
                    if storage: d["storage"] = storage

                devices.append(d)
            except Exception as e:
                log.debug(f"USB parse error: {e}")
    except ImportError:
        console.print("  [yellow]pyudev not available — USB requires Linux + pyudev[/yellow]")
    except Exception as e:
        console.print(f"  [yellow]USB scan error: {e}[/yellow]")

    # Fallback: lsusb parsing
    if not devices:
        try:
            r = subprocess.run(["lsusb"],capture_output=True,text=True,timeout=5)
            for line in r.stdout.splitlines():
                m = re.match(r"Bus (\d+) Device (\d+): ID ([0-9a-f]{4}):([0-9a-f]{4}) (.+)", line)
                if m:
                    devices.append({
                        "type":"usb_device","timestamp":now_str(),
                        "bus":m.group(1),"port":m.group(2),
                        "vid":m.group(3),"pid":m.group(4),
                        "product":m.group(5).strip(),"manufacturer":"",
                        "serial_number":"","speed":"Unknown","max_power_ma":"Unknown",
                        "device_class":"Unknown","device_type":"USB Device",
                        "driver":"","os_platform":"","times_seen":0,"risk":"UNKNOWN",
                    })
        except: pass

    return devices


# ═══════════════════════════════════════════════════════════════════════════════
# LAN DEVICE PROFILING
# ═══════════════════════════════════════════════════════════════════════════════

def _arp_scan(subnet: Optional[str] = None) -> list[dict]:
    try:
        from scapy.all import ARP, Ether, srp
        if not subnet:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        parts = addr.address.split(".")
                        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                        break
                if subnet: break
        if not subnet: return []
        console.print(f"  [dim]ARP scanning[/dim] [cyan]{subnet}[/cyan] [dim]...[/dim]")
        answered,_ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet),timeout=3,verbose=False)
        return [{"ip":rcv[ARP].psrc,"mac":rcv[Ether].src} for _,rcv in answered]
    except Exception as e:
        log.debug(f"ARP scan error: {e}"); return []

def _get_hostname(ip: str) -> dict:
    """Try all hostname resolution methods."""
    result = {"rdns":"","netbios":"","mdns":""}
    try: result["rdns"] = socket.gethostbyaddr(ip)[0]
    except: pass
    try:
        r = subprocess.run(["nmblookup","-A",ip],capture_output=True,text=True,timeout=3)
        for line in r.stdout.splitlines():
            if "<00>" in line and "GROUP" not in line:
                name = line.strip().split()[0]
                if name and name != ip: result["netbios"] = name + " (NetBIOS)"
    except: pass
    try:
        r = subprocess.run(["avahi-resolve","-a",ip],capture_output=True,text=True,timeout=3)
        if r.stdout.strip(): result["mdns"] = r.stdout.strip().split()[-1] + " (mDNS)"
    except: pass
    return result

def _nmap_scan(ip: str) -> dict:
    result = {"open_ports":[],"os_guess":"","os_confidence":0,"services":{},"scan_type":""}
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments="-sS -sV -O --top-ports 200 -T4 --open --version-intensity 5")
        if ip in nm.all_hosts():
            host = nm[ip]
            for proto in host.all_protocols():
                for port in sorted(host[proto].keys()):
                    pd = host[proto][port]
                    if pd["state"] == "open":
                        result["open_ports"].append(port)
                        result["services"][str(port)] = {
                            "protocol":  proto,
                            "service":   pd.get("name",""),
                            "version":   pd.get("version",""),
                            "product":   pd.get("product",""),
                            "extrainfo": pd.get("extrainfo",""),
                            "cpe":       pd.get("cpe",""),
                            "state":     "open",
                        }
            if "osmatch" in host and host["osmatch"]:
                best = host["osmatch"][0]
                result["os_guess"]      = best.get("name","")
                result["os_confidence"] = int(best.get("accuracy",0))
            result["scan_type"] = "nmap -sS -sV -O"
    except Exception as e:
        log.debug(f"nmap error for {ip}: {e}")
        result["error"] = str(e)
    return result

def _get_traffic_stats(ip: str) -> dict:
    stats = {"active_connections":[],"bytes_sent":0,"bytes_recv":0}
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.raddr and c.raddr.ip == ip:
                proc = ""
                try: proc = psutil.Process(c.pid).name() if c.pid else ""
                except: pass
                stats["active_connections"].append({
                    "local_port":  c.laddr.port if c.laddr else "",
                    "remote_port": c.raddr.port,
                    "status":      c.status,
                    "pid":         c.pid,
                    "process":     proc,
                })
    except: pass
    return stats

def _classify_device(vendor: str, hostname_data: dict, open_ports: list) -> str:
    v = vendor.lower()
    h = " ".join(hostname_data.values()).lower()
    if "apple"     in v: return "Apple Device"
    if "raspberry" in v: return "Raspberry Pi / IoT Linux"
    if "vmware"    in v or "virtualbox" in v: return "Virtual Machine"
    if "cisco"     in v or "juniper" in v: return "Network Equipment"
    if "tp-link"   in v or "netgear" in v or "asus" in v: return "Router / Access Point"
    if "samsung"   in v or "xiaomi" in v: return "Android / Smart Device"
    if "intel"     in v or "dell" in v or "hp " in v or "lenovo" in v: return "Laptop / Desktop"
    if "espressif" in v or "arduino" in v or "microchip" in v: return "IoT / Embedded"
    if "printer"   in h or 9100 in open_ports: return "Network Printer"
    if "nas"       in h or 139 in open_ports or 445 in open_ports: return "NAS / File Server"
    if "camera"    in h or "cam" in h: return "IP Camera"
    if "switch"    in h or "router" in h: return "Network Switch / Router"
    return "Unknown Device"

def _assess_lan_risk(open_ports: list, vendor: str) -> tuple[str, list[str]]:
    risk = "LOW"; findings = []
    DANGEROUS_PORTS = {4444:"Metasploit default",1337:"Hacker port",31337:"Elite port",
                       12345:"NetBus trojan",6667:"IRC C2",6666:"IRC",23:"Telnet (unencrypted)",
                       2323:"Telnet alternate",5555:"ADB Android debug"}
    EXPOSED_PORTS   = {22:"SSH exposed",3389:"RDP exposed",445:"SMB exposed",
                       139:"NetBIOS exposed",5432:"PostgreSQL exposed",3306:"MySQL exposed",
                       27017:"MongoDB exposed",6379:"Redis exposed",9200:"Elasticsearch exposed"}
    for port in open_ports:
        if port in DANGEROUS_PORTS:
            findings.append(f"Port {port} open — {DANGEROUS_PORTS[port]}")
            risk = "CRITICAL"
        elif port in EXPOSED_PORTS and risk != "CRITICAL":
            findings.append(f"Port {port} open — {EXPOSED_PORTS[port]}")
            risk = "HIGH" if risk not in ("CRITICAL",) else risk
    if len(open_ports) > 15 and risk == "LOW":
        findings.append(f"{len(open_ports)} open ports — unusually exposed")
        risk = "MEDIUM"
    return risk, findings

def _profile_lan_device(ip: str, mac: str, cfg, subnet: str = "") -> dict:
    vendor        = _mac_lookup(mac)
    hostname_data = _get_hostname(ip)
    hostname      = hostname_data["rdns"] or hostname_data["netbios"] or hostname_data["mdns"] or ""

    nmap_data: dict = {}
    if cfg.nmap_enabled:
        console.print(f"  [dim]  nmap →[/dim] [cyan]{ip}[/cyan] [dim]...[/dim]")
        nmap_data = _nmap_scan(ip)

    open_ports = nmap_data.get("open_ports",[])
    os_guess, os_conf = _fingerprint_os(64, 65535, vendor)
    if nmap_data.get("os_guess"):
        os_guess = nmap_data["os_guess"]; os_conf = nmap_data["os_confidence"]

    geo     = geoip_lookup(ip, cfg.geoip_db) if not is_private_ip(ip) else {"country":"LAN","city":"Local"}
    traffic = _get_traffic_stats(ip)
    d_type  = _classify_device(vendor, hostname_data, open_ports)
    risk, risk_findings = _assess_lan_risk(open_ports, vendor)

    # MAC fingerprint hash
    mac_fp = hashlib.sha256(mac.encode()).hexdigest()[:12]

    # Try to get device manufacturer URL from OUI
    oui_url = f"https://api.macvendors.com/{mac}" if mac else ""

    return {
        "type":           "lan_device",
        "timestamp":      now_str(),
        "ip":             ip,
        "mac":            mac,
        "mac_fingerprint":mac_fp,
        "vendor":         vendor,
        "hostname":       hostname,
        "hostname_rdns":  hostname_data["rdns"],
        "hostname_netbios":hostname_data["netbios"],
        "hostname_mdns":  hostname_data["mdns"],
        "device_type":    d_type,
        "os_guess":       os_guess,
        "os_confidence":  os_conf,
        "os_source":      "nmap" if nmap_data.get("os_guess") else "tcp_fingerprint",
        "nmap":           nmap_data,
        "open_ports":     open_ports,
        "services":       nmap_data.get("services",{}),
        "geo":            geo,
        "traffic":        traffic,
        "risk":           risk,
        "risk_findings":  risk_findings,
        "subnet":         subnet,
        "first_seen":     now_str(),
        "oui_lookup_url": oui_url,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TERMINAL DISPLAY
# ═══════════════════════════════════════════════════════════════════════════════

def _row(k:str,v:str,vc:str="white")->None:
    console.print(f"  [dim]{k:<24}[/dim] [{vc}]{v}[/{vc}]")

def _print_usb(dev: dict) -> None:
    risk = dev.get("risk","OK")
    rc   = {"NEW_DEVICE":"bold red","KNOWN":"green","UNKNOWN":"yellow"}.get(risk,"white")
    console.print()
    console.rule(f"[bold]USB — {dev.get('product','?')}[/bold]  [{rc}]{risk}[/{rc}]")
    _row("Product",         dev.get("product",""),"bold white")
    _row("Manufacturer",    dev.get("manufacturer",""))
    _row("Serial Number",   dev.get("serial_number",""),"cyan")
    _row("VID / PID",       f"{dev.get('vid','')} / {dev.get('pid','')} — {dev.get('vid_pid_str','')}","dim")
    _row("Device Type",     dev.get("device_type",""),"white")
    _row("USB Speed",       dev.get("speed",""),"yellow")
    _row("Power Draw",      dev.get("max_power_ma",""),"yellow")
    _row("Device Class",    dev.get("device_class",""))
    _row("Driver",          dev.get("driver",""),"dim")
    _row("OS Platform",     dev.get("os_platform","") or "(unknown)","green")
    _row("Bus / Port",      f"Bus {dev.get('bus','?')}, Device {dev.get('port','?')}")
    _row("Device Node",     dev.get("devnode",""),"dim")
    _row("Fingerprint",     dev.get("fingerprint",""),"dim")
    seen = dev.get("times_seen",0)
    _row("Session History", f"FIRST TIME — NEW DEVICE" if seen==0 else f"Seen {seen+1} times","red" if seen==0 else "dim")
    s = dev.get("storage")
    if s:
        console.print(f"\n  [dim]Storage Details:[/dim]")
        _row("  Label",       s.get("label",""),"cyan")
        _row("  Filesystem",  s.get("fstype",""))
        _row("  UUID",        s.get("uuid",""),"dim")
        _row("  Capacity",    s.get("total_hr",""))
        _row("  Used / Free", f"{s.get('used_hr','')} / {s.get('free_hr','')}  ({s.get('pct_used',0):.0f}%)")
        _row("  Mount Point", s.get("mountpoint",""),"cyan")
    console.print()

def _print_lan(dev: dict) -> None:
    risk = dev.get("risk","LOW")
    rc   = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","LOW":"green"}.get(risk,"white")
    console.print()
    console.rule(f"[bold]LAN — {dev.get('ip','?')}[/bold]  [{rc}]risk: {risk}[/{rc}]")
    _row("IP Address",    dev.get("ip",""),"cyan")
    _row("MAC Address",   dev.get("mac",""))
    _row("Hostname",      dev.get("hostname","") or "(not resolved)","green" if dev.get("hostname") else "dim")
    if dev.get("hostname_netbios"): _row("  NetBIOS",  dev["hostname_netbios"],"dim")
    if dev.get("hostname_mdns"):    _row("  mDNS",     dev["hostname_mdns"],"dim")
    _row("Manufacturer",  dev.get("vendor",""))
    _row("Device Type",   dev.get("device_type",""),"cyan")
    _row("OS",            f"{dev.get('os_guess','')}  [dim](conf: {dev.get('os_confidence',0)}%)[/dim]","white")
    if dev.get("open_ports"):
        console.print(f"\n  [dim]Open Ports ({len(dev['open_ports'])}):[/dim]")
        for port in dev["open_ports"][:20]:
            svc = dev.get("services",{}).get(str(port),{})
            s   = svc.get("service",""); v=svc.get("version",""); pr=svc.get("product","")
            risk_p = " [red]← DANGEROUS[/red]" if port in (4444,1337,31337,23,2323) else " [yellow]← EXPOSED[/yellow]" if port in (22,3389,445,139,3306,5432) else ""
            console.print(f"  [dim]  {port:<6}[/dim]  [green]OPEN[/green]  [cyan]{s:<12}[/cyan]  [dim]{pr} {v}[/dim]{risk_p}")
    if dev.get("risk_findings"):
        console.print(f"\n  [bold red]Risk Findings:[/bold red]")
        for f in dev["risk_findings"]: console.print(f"  [red]  ✗  {f}[/red]")
    if dev.get("traffic",{}).get("active_connections"):
        console.print(f"\n  [dim]Active Connections:[/dim]")
        for c in dev["traffic"]["active_connections"][:8]:
            console.print(f"  [dim]  :{c.get('local_port','')} → :{c.get('remote_port','')}[/dim]  [yellow]{c.get('status','')}[/yellow]  [dim]{c.get('process','')}({c.get('pid','')})[/dim]")
    console.print()


# ═══════════════════════════════════════════════════════════════════════════════
# ENJECT-STYLE JSON REPORT
# Enject format = nested JSON with full device data, typed records, timestamps
# ═══════════════════════════════════════════════════════════════════════════════

def _generate_enject_report(data: dict, save_path: str) -> str:
    """Generate enject-compatible JSON forensics report."""
    report = {
        "__meta": {
            "tool":      "PacketPulse",
            "author":    "Dreamwalker4u",
            "version":   "1.0.2",
            "format":    "enject-forensics-v1",
            "generated": now_str(),
            "platform":  platform.system(),
            "hostname":  socket.gethostname(),
        },
        "session": {
            "start_time":  data.get("timestamp", now_str()),
            "scan_type":   data.get("scan_type","full"),
            "usb_count":   len(data.get("usb_devices",[])),
            "lan_count":   len(data.get("lan_devices",[])),
        },
        "local_machine":  data.get("local_machine",{}),
        "usb_devices":    data.get("usb_devices",[]),
        "lan_devices":    data.get("lan_devices",[]),
        "risk_summary": {
            "critical_lan": [d["ip"] for d in data.get("lan_devices",[]) if d.get("risk")=="CRITICAL"],
            "new_usb":      [d["product"] for d in data.get("usb_devices",[]) if d.get("risk")=="NEW_DEVICE"],
            "high_risk_lan":[d["ip"] for d in data.get("lan_devices",[]) if d.get("risk") in ("CRITICAL","HIGH")],
        },
    }
    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    with open(save_path,"w",encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    return save_path


def _generate_forensics_report(data: dict, save_path: str) -> str:
    ts_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    usb_devices = data.get("usb_devices", [])
    lan_devices = data.get("lan_devices", [])
    local = data.get("local_machine", {})

    def device_row(dev: dict) -> str:
        return (
            f"<tr><td class='mono'>{dev.get('ip','')}</td>"
            f"<td>{dev.get('hostname','')}</td>"
            f"<td>{dev.get('vendor','')}</td>"
            f"<td>{dev.get('risk','')}</td>"
            f"<td class='dim'>{', '.join(dev.get('risk_findings',[])[:3])}</td></tr>"
        )

    usb_rows = "".join(
        f"<tr><td class='mono'>{dev.get('product','')}</td>"
        f"<td>{dev.get('manufacturer','')}</td>"
        f"<td>{dev.get('device_type','')}</td>"
        f"<td>{dev.get('risk','')}</td>"
        f"<td class='dim'>{dev.get('serial_number','')}</td></tr>"
        for dev in usb_devices[:30]
    ) or "<tr><td colspan='5' class='dim'>No USB devices profiled</td></tr>"

    lan_rows = "".join(device_row(dev) for dev in lan_devices[:30]) or "<tr><td colspan='5' class='dim'>No LAN devices profiled</td></tr>"
    critical_count = len([d for d in lan_devices if d.get('risk') == 'CRITICAL'])
    high_count = len([d for d in lan_devices if d.get('risk') == 'HIGH'])
    new_usb_count = len([d for d in usb_devices if d.get('risk') == 'NEW_DEVICE'])

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>PacketPulse Forensics Report — {ts_str}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#09090f;color:#d8d8e8;font-family:'Segoe UI',sans-serif;font-size:14px;line-height:1.6}}
.container{{max-width:1140px;margin:0 auto;padding:32px 24px}}
.header{{padding-bottom:24px;border-bottom:1px solid #11131c;display:flex;align-items:flex-start;gap:20px}}
.brand{{font-size:32px;font-weight:800;color:#50fa7b;letter-spacing:2px}}
.subtitle{{font-size:12px;color:#8be9fd;margin-top:6px}}
.dw-badge{{display:inline-block;margin-top:10px;padding:5px 12px;border-radius:999px;border:1px solid #8be9fd55;background:#8be9fd1a;color:#b8f5ff;font-size:10px;letter-spacing:1px;text-transform:uppercase}}
.meta{{display:grid;grid-template-columns:repeat(3,minmax(180px,1fr));gap:16px;margin-top:24px}}
.card{{background:#11131d;border:1px solid #1f2431;border-radius:12px;padding:16px}}
.card .label{{font-size:11px;color:#7a88a6;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}}
.card .value{{font-size:18px;font-weight:700;color:#f8f8ff}}
.section{{margin-top:36px}}
.section h2{{font-size:18px;color:#f1fa8c;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{padding:12px 14px;border-bottom:1px solid #141820;text-align:left;vertical-align:top}}
th{{font-size:11px;color:#6b7c9c;text-transform:uppercase;letter-spacing:1px}}
td{{color:#e4e8ff}}
.mono{{font-family:'Courier New',monospace;font-size:13px}}
.dim{{color:#7c88a6}}
.right{{text-align:right}}
.footer{{display:flex;justify-content:space-between;align-items:center;margin-top:32px;padding-top:18px;border-top:1px solid #11131c;font-size:12px;color:#7e89a6}}
</style>
</head>
<body>
<div class='container'>
  <div class='header'>
    <div>
      <div class='brand'>PACKETPULSE</div>
      <div class='subtitle'>DEVICE FORENSICS REPORT</div>
      <div class='subtitle'>Engineered by Dreamwalker4u</div>
            <div class='dw-badge'>Generated by Dreamwalker4u</div>
    </div>
    <div style='margin-left:auto;text-align:right;color:#7c88a6'>Generated: {ts_str}</div>
  </div>

  <div class='meta'>
    <div class='card'><div class='label'>Host</div><div class='value'>{local.get('hostname','unknown')}</div></div>
    <div class='card'><div class='label'>OS</div><div class='value'>{local.get('os','unknown')} {local.get('os_release','')}</div></div>
    <div class='card'><div class='label'>Total USB</div><div class='value'>{len(usb_devices):,}</div></div>
    <div class='card'><div class='label'>Total LAN</div><div class='value'>{len(lan_devices):,}</div></div>
    <div class='card'><div class='label'>Critical LAN</div><div class='value'>{critical_count}</div></div>
    <div class='card'><div class='label'>New USB</div><div class='value'>{new_usb_count}</div></div>
  </div>

  <div class='section'>
    <h2>Local Machine Summary</h2>
    <table>
      <tr><th>Hostname</th><td>{local.get('hostname','')}</td></tr>
      <tr><th>OS</th><td>{local.get('os','')} {local.get('os_release','')}</td></tr>
      <tr><th>CPU</th><td>{local.get('cpu_logical_cores','')} cores @ {local.get('cpu_freq_mhz',0):.0f} MHz</td></tr>
      <tr><th>RAM</th><td>{local.get('memory_total_gb','')} GB ({local.get('memory_pct','')}% used)</td></tr>
      <tr><th>Network</th><td>{len(local.get('open_connections',[]))} open / {len(local.get('listening_ports',[]))} listening</td></tr>
    </table>
  </div>

  <div class='section'>
    <h2>USB Devices</h2>
    <table>
      <tr><th>Product</th><th>Vendor</th><th>Type</th><th>Risk</th><th>Serial</th></tr>
      {usb_rows}
    </table>
  </div>

  <div class='section'>
    <h2>LAN Devices</h2>
    <table>
      <tr><th>IP</th><th>Hostname</th><th>Vendor</th><th>Risk</th><th>Top Findings</th></tr>
      {lan_rows}
    </table>
  </div>

  <div class='footer'>
    <div>PacketPulse • Dreamwalker4u</div>
    <div>Forensics session summary</div>
  </div>
</div>
</body>
</html>"""

    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    with open(save_path, "w", encoding="utf-8") as f:
        f.write(html)
    return save_path


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════════════════

def run_forensics(subnet:Optional[str]=None, no_nmap:bool=False) -> None:
    cfg = get_config().forensics
    if no_nmap: cfg.nmap_enabled = False
    ensure_dir(cfg.results_path)
    _load_history()

    console.rule("[bold green]PACKETPULSE — DEVICE FORENSICS[/bold green]")
    console.print(
        f"  [dim]USB:[/dim] [green]{'ON' if cfg.usb_enabled else 'OFF'}[/green]   "
        f"[dim]LAN:[/dim] [green]{'ON' if cfg.lan_enabled else 'OFF'}[/green]   "
        f"[dim]nmap:[/dim] [green]{'ACTIVE SCAN' if cfg.nmap_enabled else 'PASSIVE ONLY'}[/green]"
    )
    console.print("  [dim]Output format: enject-forensics JSON + terminal display[/dim]")
    console.print("[dim]"+"─"*100+"[/dim]\n")

    session_data: dict = {
        "timestamp":  now_str(),
        "scan_type":  "full",
        "usb_devices":[],
        "lan_devices":[],
        "local_machine":{},
    }

    # ── Local machine profile ─────────────────────────────────────────────────
    console.print("  [bold cyan][ LOCAL MACHINE ][/bold cyan]")
    console.print("  [dim]Profiling local system...[/dim]")
    local = _profile_local_machine()
    session_data["local_machine"] = local
    console.print(
        f"  [dim]Hostname    :[/dim] [green]{local.get('hostname','')}[/green]  "
        f"[dim]OS:[/dim] [green]{local.get('os','')} {local.get('os_release','')}[/green]  "
        f"[dim]CPU:[/dim] [green]{local.get('cpu_logical_cores','')} cores @ {local.get('cpu_freq_mhz',0):.0f} MHz[/green]"
    )
    console.print(
        f"  [dim]RAM         :[/dim] [green]{local.get('memory_total_gb','')} GB[/green]  "
        f"[dim]Used:[/dim] [yellow]{local.get('memory_pct','')}%[/yellow]"
    )
    console.print(
        f"  [dim]Open conns  :[/dim] [green]{len(local.get('open_connections',[]))}[/green]  "
        f"[dim]Listening ports:[/dim] [green]{len(local.get('listening_ports',[]))}[/green]  "
        f"[dim]Net processes:[/dim] [green]{len(local.get('network_processes',[]))}[/green]"
    )
    lm_path = f"{cfg.results_path}/local_machine_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    save_json(local, lm_path)
    console.print(f"  [dim]Local profile →[/dim] [cyan]{lm_path}[/cyan]\n")

    # ── USB ───────────────────────────────────────────────────────────────────
    if cfg.usb_enabled:
        console.print("  [bold cyan][ USB DEVICES ][/bold cyan]")
        usb_devices = _scan_usb_devices()
        if usb_devices:
            session_data["usb_devices"] = usb_devices
            for dev in usb_devices:
                _print_usb(dev)
                p = f"{cfg.results_path}/usb_{(dev.get('serial_number') or dev.get('product','unknown')).replace('/','_')[:40]}.json"
                save_json(dev, p)
                console.print(f"  [dim]Saved →[/dim] [cyan]{p}[/cyan]")
        else:
            console.print("  [dim]No USB devices found (or pyudev unavailable).[/dim]\n")

    # ── LAN ───────────────────────────────────────────────────────────────────
    if cfg.lan_enabled:
        console.print("\n  [bold cyan][ LAN DEVICES ][/bold cyan]")
        arp_results = _arp_scan(subnet)
        if not arp_results:
            console.print("  [yellow]No ARP responses. Are you on a LAN? (requires sudo)[/yellow]\n")
        else:
            console.print(f"  [green]{len(arp_results)} device(s) discovered[/green]\n")
            t = Table(box=box.SIMPLE_HEAVY,show_header=True,header_style="dim",padding=(0,1))
            t.add_column("IP",style="cyan"); t.add_column("MAC"); t.add_column("VENDOR"); t.add_column("HOSTNAME"); t.add_column("RISK")
            for e in arp_results:
                t.add_row(e["ip"],e["mac"],_mac_lookup(e["mac"]),"resolving...","—")
            console.print(t); console.print()

            for e in arp_results:
                dev = _profile_lan_device(e["ip"],e["mac"],cfg,subnet or "")
                session_data["lan_devices"].append(dev)
                _print_lan(dev)
                p = f"{cfg.results_path}/lan_{e['ip'].replace('.','_')}.json"
                save_json(dev,p); console.print(f"  [dim]Saved →[/dim] [cyan]{p}[/cyan]")

    # ── Enject JSON report ────────────────────────────────────────────────────
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    enject_path = f"{cfg.results_path}/forensics_enject_{ts}.json"
    _generate_enject_report(session_data, enject_path)

    html_path = f"{cfg.results_path}/forensics_report_{ts}.html"
    try:
        _generate_forensics_report(session_data, html_path)
    except Exception as e:
        log.debug(f"Could not generate HTML forensics report: {e}")
        html_path = ""

    pdf_path = f"{cfg.results_path}/forensics_report_{ts}.pdf"
    try:
        save_report_pdf(
            "PACKETPULSE FORENSICS REPORT",
            "PacketPulse | Dreamwalker4u",
            [
                ("Summary", [
                    f"Host: {session_data['local_machine'].get('hostname','unknown')}",
                    f"OS: {session_data['local_machine'].get('os','unknown')} {session_data['local_machine'].get('os_release','')}",
                    f"USB devices: {len(session_data['usb_devices']):,}",
                    f"LAN devices: {len(session_data['lan_devices']):,}",
                    f"Critical LAN devices: {len([d for d in session_data['lan_devices'] if d.get('risk') == 'CRITICAL']):,}",
                    f"New USB devices: {len([d for d in session_data['usb_devices'] if d.get('risk') == 'NEW_DEVICE']):,}",
                ]),
                ("USB Devices", [
                    f"{dev.get('product','')} ({dev.get('manufacturer','')}) — {dev.get('risk','')}"
                    for dev in session_data['usb_devices'][:20]
                ] or ["No USB devices"]),
                ("LAN Devices", [
                    f"{dev.get('ip','')} / {dev.get('hostname','')} — {dev.get('risk','')}"
                    for dev in session_data['lan_devices'][:20]
                ] or ["No LAN devices"]),
            ],
            pdf_path,
        )
    except Exception as e:
        log.debug(f"Could not generate PDF forensics report: {e}")
        pdf_path = ""

    console.print(f"\n[bold green]╔═══════════════════════════════════════════════════════╗[/bold green]")
    console.print(f"[bold green]║  FORENSICS REPORT  —  PacketPulse | Dreamwalker4u    ║[/bold green]")
    console.print(f"[bold green]╚═══════════════════════════════════════════════════════╝[/bold green]")
    console.print(f"  [dim]Enject JSON  →[/dim] [bold cyan]{enject_path}[/bold cyan]")
    if html_path:
        console.print(f"  [dim]HTML Report  →[/dim] [bold cyan]{html_path}[/bold cyan]")
    if pdf_path:
        console.print(f"  [dim]PDF Report   →[/dim] [bold cyan]{pdf_path}[/bold cyan]")
    crit = [d["ip"] for d in session_data["lan_devices"] if d.get("risk")=="CRITICAL"]
    new_usb = [d["product"] for d in session_data["usb_devices"] if d.get("risk")=="NEW_DEVICE"]
    if crit:    console.print(f"  [bold red]CRITICAL LAN DEVICES:[/bold red] {', '.join(crit)}")
    if new_usb: console.print(f"  [bold red]NEW USB DEVICES:[/bold red] {', '.join(new_usb)}")
    console.print()


def run_usb_watch() -> None:
    console.rule("[bold green]PACKETPULSE — USB LIVE MONITOR[/bold green]")
    console.print("  [dim]Watching USB connect/disconnect events...[/dim]\n")
    console.print("[dim]"+"─"*100+"[/dim]")
    try:
        import pyudev
        ctx     = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(ctx)
        monitor.filter_by(subsystem="usb", device_type="usb_device")
        _load_history()
        for dev in iter(monitor.poll, None):
            action   = dev.action
            product  = (dev.get("ID_MODEL") or "").replace("_"," ")
            manuf    = (dev.get("ID_VENDOR") or "").replace("_"," ")
            serial   = dev.get("ID_SERIAL_SHORT") or ""
            vid      = dev.get("ID_VENDOR_ID","")
            pid      = dev.get("ID_MODEL_ID","")
            ts       = datetime.utcnow().strftime("%H:%M:%S")
            if action == "add":
                seen = _device_history.get(serial,0)
                new_flag = "[bold red]  ← NEW DEVICE (first time seen)[/bold red]" if seen==0 else f"  [dim](seen {seen} times before)[/dim]"
                _device_history[serial] = seen+1; _save_history()
                console.print(f"  [dim]{ts}[/dim]  [green]CONNECTED  [/green]  [bold white]{manuf} {product}[/bold white]  [dim]VID:{vid} PID:{pid}[/dim]"+(f"  [dim]S/N:{serial}[/dim]" if serial else "")+new_flag)
            elif action == "remove":
                console.print(f"  [dim]{ts}[/dim]  [yellow]DISCONNECTED[/yellow]  [dim]{manuf} {product}[/dim]")
    except ImportError:
        console.print("[red]pyudev not installed: pip install pyudev[/red]")
    except KeyboardInterrupt:
        console.print("\n[green]USB monitor stopped.[/green]")
    except Exception as e:
        console.print(f"[red]USB monitor error: {e}[/red]")
