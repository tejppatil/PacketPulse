"""
PacketPulse — Deep Device Forensics
Extracts every possible data point from USB + LAN devices.
Report output: JSON (enject-compatible) + terminal display.
Branding: PacketPulse | Dreamwalker4u
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import types
import platform
import socket
import subprocess
import time
from pathlib import Path
from datetime import datetime
from typing import Optional

import psutil

from packetpulse import __version__
from packetpulse.core.config import get_config
from packetpulse.core.logger import get_logger, console as _shared_console
from packetpulse.core import capabilities
from packetpulse.core.session import Session, StopController, utc_now
from packetpulse.utils.helpers import (
    geoip_lookup, is_private_ip, save_json, ensure_dir, now_str, human_bytes,
    timestamp_filename, save_report_pdf, safe_output_path, h as esc,
)

console = _shared_console

UNKNOWN_VALUE = "UNKNOWN"
log = get_logger("forensics")

# ── Device history (cross-session) ────────────────────────────────────────────
_device_history: dict[str, int] = {}
_HIST_FILE = "pcap_store/forensics/.device_history.json"

def _load_history():
    try:
        with open(_HIST_FILE) as f:
            _device_history.update(json.load(f))
    except Exception:
        pass

def _save_history():
    try:
        Path(_HIST_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(_HIST_FILE,"w") as f: json.dump(_device_history, f)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# MAC OUI LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

def _mac_lookup(mac: str) -> str:
    try:
        from manuf import manuf
        p = manuf.MacParser()
        result = p.get_manuf(mac)
        if result: return result
    except Exception:
        pass
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

def _fingerprint_os(ttl: int, window: int, vendor: str) -> dict:
    """Coarse OS guess from TTL and TCP window size.

    This is a weak heuristic: TTL is decremented by every hop and window sizes
    overlap heavily between systems. The result is labelled as a heuristic with
    its evidence, and returns UNKNOWN when there is nothing to go on — it is
    never presented as an identification.
    """
    if not ttl:
        return {"likely_os": UNKNOWN_VALUE, "basis": "no TTL observed",
                "method": "none", "confidence": "none"}

    initial = 64 if ttl <= 64 else 128 if ttl <= 128 else 255
    family = {64: "Linux/Unix/macOS", 128: "Windows", 255: "network device"}[initial]
    hops = initial - ttl

    return {
        "likely_os": family,
        "basis": "observed TTL {} implies initial TTL {} ({} hops away)".format(ttl, initial, hops),
        "method": "TTL/window heuristic",
        "confidence": "heuristic - not an identification",
        "window_size": window or UNKNOWN_VALUE,
        "vendor_hint": vendor or UNKNOWN_VALUE,
    }


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
    except Exception:
        pass

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
    except Exception:
        pass

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
            except Exception:
                pass
        data["disks"] = disks
    except Exception:
        pass

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
    except Exception:
        pass

    # Network counters
    try:
        nc = psutil.net_io_counters()
        data["net_bytes_sent"]   = nc.bytes_sent
        data["net_bytes_recv"]   = nc.bytes_recv
        data["net_packets_sent"] = nc.packets_sent
        data["net_packets_recv"] = nc.packets_recv
        data["net_errors_in"]    = nc.errin
        data["net_errors_out"]   = nc.errout
    except Exception:
        pass

    # Open sockets
    try:
        conns = []
        for c in psutil.net_connections(kind="inet"):
            try:
                proc_name = psutil.Process(c.pid).name() if c.pid else ""
            except Exception:
                proc_name = ""
            conns.append({
                "family": str(c.family),"type": str(c.type),
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status": c.status,"pid": c.pid,"process": proc_name,
            })
        data["open_connections"] = conns[:100]
    except Exception:
        pass

    # Listening ports
    try:
        listening = [c for c in psutil.net_connections(kind="inet")
                     if c.status == "LISTEN" and c.laddr]
        data["listening_ports"] = [
            {"port": c.laddr.port,"addr": c.laddr.ip,
             "pid": c.pid,"process": psutil.Process(c.pid).name() if c.pid else ""}
            for c in listening
        ]
    except Exception:
        pass

    # Processes with network activity
    try:
        net_procs = []
        for proc in psutil.process_iter(["pid","name","status","cpu_percent","memory_info"]):
            try:
                conns = proc.net_connections(kind="inet")
                if conns:
                    net_procs.append({
                        "pid":     proc.info["pid"],
                        "name":    proc.info["name"],
                        "status":  proc.info["status"],
                        "connections": len(conns),
                        "cpu_pct": proc.info["cpu_percent"],
                        "mem_mb":  round(proc.info["memory_info"].rss/1e6,2) if proc.info["memory_info"] else 0,
                    })
            except Exception:
                pass
        data["network_processes"] = sorted(net_procs, key=lambda x:x["connections"], reverse=True)[:30]
    except Exception:
        pass

    # ARP table
    try:
        # BSD/Linux use -n; Windows arp.exe only understands -a.
        arp_args = ["arp", "-a"] if sys.platform == "win32" else ["arp", "-n"]
        arp_out_text, arp_status = _run_tool(arp_args)
        data["arp_table_status"] = arp_status
        arp_out = types.SimpleNamespace(stdout=arp_out_text)
        data["arp_table_raw"] = arp_out.stdout[:2000]
    except Exception:
        pass

    # Routing table
    try:
        route_cmd = ["route", "print"] if sys.platform == "win32" else ["ip", "route"]
        route_text, route_status = _run_tool(route_cmd)
        data["routing_table_status"] = route_status
        route_out = types.SimpleNamespace(stdout=route_text)
        data["routing_table_raw"] = route_out.stdout[:2000]
    except Exception:
        try:
            netstat_text, netstat_status = _run_tool(["netstat", "-rn"])
            data["routing_table_status"] = netstat_status
            r = types.SimpleNamespace(stdout=netstat_text)
            data["routing_table_raw"] = r.stdout[:2000]
        except Exception:
            pass

    # DNS cache (systemd-resolved)
    try:
        dns_text, dns_status = _run_tool(["resolvectl", "statistics"])
        data["resolver_stats_status"] = dns_status
        dns_out = types.SimpleNamespace(stdout=dns_text)
        data["dns_resolver_stats"] = dns_out.stdout[:1000]
    except Exception:
        pass

    # USB history (from kernel logs)
    try:
        dmesg_text, dmesg_status = _run_tool(["dmesg", "--notime"])
        data["kernel_log_status"] = dmesg_status
        dmesg = types.SimpleNamespace(stdout=dmesg_text)
        usb_lines = [l for l in dmesg.stdout.splitlines() if "usb" in l.lower() and
                     any(k in l.lower() for k in ["new","disconnect","product","manufacturer","serial"])]
        data["usb_kernel_history"] = usb_lines[-30:]
    except Exception:
        pass

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
    except Exception:
        pass
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
    except Exception:
        pass
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
        except Exception:
            pass
    return best

def _usb_storage_detail(ctx, usb_dev) -> dict:
    """Filesystem detail for the block devices belonging to a USB device.

    Returns a dict describing what was OBSERVED, or an explicit status when the
    device has no block children (keyboards, hubs, dongles) or when the tools
    needed to inspect them are absent.
    """
    result = {"status": "NOT APPLICABLE",
              "reason": "device exposes no block devices",
              "partitions": []}
    try:
        children = list(ctx.list_devices(subsystem="block").match_parent(usb_dev))
    except Exception as e:
        return {"status": "UNAVAILABLE",
                "reason": "could not enumerate block devices: {}".format(type(e).__name__),
                "partitions": []}

    if not children:
        return result

    have_blkid = capabilities.probe_all()["blkid"].available
    partitions = []
    for blk in children:
        node = blk.device_node
        if not node:
            continue
        part = {
            "device": node,
            "type": blk.get("DEVTYPE") or UNKNOWN_VALUE,
            "size_bytes": UNKNOWN_VALUE,
            "filesystem": UNKNOWN_VALUE,
            "label": UNKNOWN_VALUE,
            "uuid": UNKNOWN_VALUE,
            "mountpoint": UNKNOWN_VALUE,
        }
        try:
            sectors = blk.attributes.asstring("size")
            part["size_bytes"] = int(sectors) * 512     # sysfs reports 512B sectors
        except Exception:
            pass

        # udev already carries filesystem properties for most media.
        for key, prop in (("filesystem", "ID_FS_TYPE"), ("label", "ID_FS_LABEL"),
                          ("uuid", "ID_FS_UUID")):
            value = blk.get(prop)
            if value:
                part[key] = value

        if have_blkid and part["filesystem"] == UNKNOWN_VALUE:
            info = _get_usb_blkid(node)
            for key, src in (("filesystem", "TYPE"), ("label", "LABEL"), ("uuid", "UUID")):
                if info.get(src):
                    part[key] = info[src]

        part["mountpoint"] = _mountpoint_for(node)
        partitions.append(part)

    return {"status": "OBSERVED" if partitions else "NOT APPLICABLE",
            "reason": "" if partitions else "no usable block devices",
            "partitions": partitions}


def _mountpoint_for(device_node: str) -> str:
    """Where a block device is mounted, from the kernel's own mount table."""
    try:
        with open("/proc/self/mounts", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == device_node:
                    return parts[1].replace(chr(92) + "040", " ")
    except OSError:
        return UNKNOWN_VALUE
    return "not mounted"


def _scan_usb_devices(session=None) -> tuple:
    """Enumerate USB devices via pyudev.

    Returns (devices, unavailable_reason). When the dependency or platform is
    missing the reason is returned so the caller can report UNAVAILABLE — an
    empty list must never be presented as a successful scan that found nothing.
    """
    cap = capabilities.probe_all()["usb"]
    if not cap.available:
        return [], cap.reason

    try:
        import pyudev
    except ImportError as e:
        return [], "pyudev import failed: {}".format(e)

    devices = []
    try:
        ctx = pyudev.Context()
        for dev in ctx.list_devices(subsystem="usb", DEVTYPE="usb_device"):
            try:
                vid = dev.get("ID_VENDOR_ID", "") or ""
                pid = dev.get("ID_MODEL_ID", "") or ""
                product = (dev.get("ID_MODEL") or "").replace("_", " ")
                manuf = (dev.get("ID_VENDOR") or "").replace("_", " ")
                serial = dev.get("ID_SERIAL_SHORT") or ""
                entry = {
                    "source": "pyudev (OBSERVED)",
                    "product": product or UNKNOWN_VALUE,
                    "manufacturer": manuf or UNKNOWN_VALUE,
                    "serial_number": serial or UNKNOWN_VALUE,
                    "vendor_id": vid or UNKNOWN_VALUE,
                    "product_id": pid or UNKNOWN_VALUE,
                    "device_node": dev.device_node or UNKNOWN_VALUE,
                    "driver": dev.driver or UNKNOWN_VALUE,
                    "sys_path": dev.sys_path or UNKNOWN_VALUE,
                    "speed": dev.attributes.asstring("speed") if dev.attributes.get("speed") else UNKNOWN_VALUE,
                    "max_power": dev.attributes.asstring("bMaxPower") if dev.attributes.get("bMaxPower") else UNKNOWN_VALUE,
                }
                seen = _device_history.get(serial, 0) if serial else 0
                entry["previously_seen_count"] = seen
                entry["first_time_seen"] = (seen == 0)
                if serial:
                    _device_history[serial] = seen + 1
                # Storage detail comes from the BLOCK devices belonging to this
                # USB device, not from its own device node: a usb_device node is
                # /dev/bus/usb/BBB/DDD (the control endpoint), which carries no
                # filesystem, so blkid on it always returned nothing.
                entry["storage"] = _usb_storage_detail(ctx, dev)
                devices.append(entry)
            except (OSError, KeyError, AttributeError) as e:
                log.warning("could not read USB device: %s: %s", type(e).__name__, e)
                if session is not None:
                    session.record_error("usb_device_read", e)
        _save_history()
    except Exception as e:
        return [], "pyudev enumeration failed: {}: {}".format(type(e).__name__, e)

    return devices, ""


def _arp_scan(subnet: Optional[str] = None) -> list[dict]:
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
        if not subnet:
            # Use the address the OS actually routes from, not the first
            # non-loopback address found: that picked APIPA/link-local
            # (169.254.x) addresses and scanned a subnet with no hosts on it.
            route_ip = ""
            try:
                sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sk.connect(("8.8.8.8", 53))
                    route_ip = sk.getsockname()[0]
                finally:
                    sk.close()
            except OSError:
                route_ip = ""
            if route_ip and not route_ip.startswith(("127.", "169.254.")):
                parts = route_ip.split(".")
                subnet = "{}.{}.{}.0/24".format(parts[0], parts[1], parts[2])
            else:
                for _iface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if (addr.family == socket.AF_INET
                                and not addr.address.startswith(("127.", "169.254."))):
                            parts = addr.address.split(".")
                            subnet = "{}.{}.{}.0/24".format(parts[0], parts[1], parts[2])
                            break
                    if subnet:
                        break
        if not subnet:
            log.warning("no usable IPv4 subnet found for ARP scan")
            return []
        console.print(f"  [dim]ARP scanning[/dim] [cyan]{subnet}[/cyan] [dim]...[/dim]")
        answered,_ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet),timeout=3,verbose=False)
        return [{"ip":rcv[ARP].psrc,"mac":rcv[Ether].src} for _,rcv in answered]
    except Exception as e:
        log.debug(f"ARP scan error: {e}"); return []

def _run_tool(args, timeout=5):
    """Run an external tool and report what happened.

    Returns (stdout, status) where status is "OBSERVED" or an explicit reason.
    Several of these tools are absent by default on current distributions —
    `arp` moved to the optional net-tools package, `dmesg` is root-restricted
    under kernel.dmesg_restrict, `resolvectl` needs systemd-resolved — and
    swallowing that silently produced empty sections that looked like findings
    of "nothing".
    """
    tool = args[0]
    if not shutil.which(tool):
        return "", "UNAVAILABLE: {} is not installed".format(tool)
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "", "UNAVAILABLE: {} timed out after {}s".format(tool, timeout)
    except (OSError, ValueError) as e:
        return "", "UNAVAILABLE: {} failed ({})".format(tool, type(e).__name__)
    if r.returncode != 0:
        detail = (r.stderr or "").strip().splitlines()
        why = detail[0][:90] if detail else "exit code {}".format(r.returncode)
        return r.stdout or "", "UNAVAILABLE: {} -> {}".format(tool, why)
    return r.stdout or "", "OBSERVED"


def _get_hostname(ip: str) -> dict:
    """Resolve a host name by every available method, reporting each outcome.

    A blank name previously meant either "no name exists" or "the tool that
    would have found it is not installed". Those are different facts, so each
    method now carries its own status.
    """
    result = {"rdns": "", "netbios": "", "mdns": "", "methods": {}}

    try:
        result["rdns"] = socket.gethostbyaddr(ip)[0]
        result["methods"]["reverse_dns"] = "OBSERVED"
    except (socket.herror, socket.gaierror, OSError):
        result["methods"]["reverse_dns"] = "NOT RESOLVED"

    out, status = _run_tool(["nmblookup", "-A", ip], timeout=3)
    result["methods"]["netbios"] = status
    if status == "OBSERVED":
        for line in out.splitlines():
            if "<00>" in line and "GROUP" not in line:
                name = line.strip().split()[0]
                if name and name != ip:
                    result["netbios"] = name
                    break
        if not result["netbios"]:
            result["methods"]["netbios"] = "NOT RESOLVED"

    out, status = _run_tool(["avahi-resolve", "-a", ip], timeout=3)
    result["methods"]["mdns"] = status
    if status == "OBSERVED":
        if out.strip():
            result["mdns"] = out.strip().split()[-1]
        else:
            result["methods"]["mdns"] = "NOT RESOLVED"

    return result


def _nmap_scan(ip: str, timeout: int = 180) -> dict:
    """Active port scan of one host.

    Verifies that both the binding and the nmap binary exist before running,
    bounds the scan, and reports failure explicitly. It never returns invented
    ports or services.
    """
    result = {
        "status": "NOT RUN",
        "open_ports": [],
        "services": {},
        "os_guess": None,
        "os_evidence": None,
        "scan_type": None,
    }
    cap = capabilities.probe_all()["nmap"]
    if not cap.available:
        result["status"] = "UNAVAILABLE"
        result["reason"] = cap.reason
        return result

    try:
        import nmap

        nm = nmap.PortScanner()
        args = "-sT -sV --top-ports 100 -T4 --open --host-timeout {}s".format(timeout)
        if capabilities.is_admin():
            # SYN scan and OS detection both require raw sockets.
            args = "-sS -sV -O --top-ports 200 -T4 --open --host-timeout {}s".format(timeout)
        nm.scan(hosts=ip, arguments=args)
        result["scan_type"] = "nmap {}".format(args)

        if ip not in nm.all_hosts():
            result["status"] = "COMPLETED"
            result["note"] = "host did not respond to the scan"
            return result

        host = nm[ip]
        for proto in host.all_protocols():
            for port in sorted(host[proto].keys()):
                pd = host[proto][port]
                if pd.get("state") != "open":
                    continue
                result["open_ports"].append(port)
                result["services"][str(port)] = {
                    "protocol": proto,
                    "service": pd.get("name") or UNKNOWN_VALUE,
                    "product": pd.get("product") or UNKNOWN_VALUE,
                    "version": pd.get("version") or UNKNOWN_VALUE,
                    "state": "open",
                }
        osmatch = host.get("osmatch") if hasattr(host, "get") else None
        if osmatch:
            best = osmatch[0]
            result["os_guess"] = best.get("name") or UNKNOWN_VALUE
            result["os_evidence"] = "nmap OS fingerprint, accuracy {}%".format(
                best.get("accuracy", "?"))
        result["status"] = "COMPLETED"
    except Exception as e:
        result["status"] = "FAILED"
        result["reason"] = "{}: {}".format(type(e).__name__, str(e)[:160])
        log.warning("nmap scan of %s failed: %s", ip, e)
    return result


def _get_traffic_stats(ip: str) -> dict:
    stats = {"active_connections":[],"bytes_sent":0,"bytes_recv":0}
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.raddr and c.raddr.ip == ip:
                proc = ""
                try: proc = psutil.Process(c.pid).name() if c.pid else ""
                except Exception:
                    pass
                stats["active_connections"].append({
                    "local_port":  c.laddr.port if c.laddr else "",
                    "remote_port": c.raddr.port,
                    "status":      c.status,
                    "pid":         c.pid,
                    "process":     proc,
                })
    except Exception:
        pass
    return stats

def _classify_device(vendor: str, hostname_data: dict, open_ports: list) -> str:
    v = vendor.lower()
    h = " ".join(str(v) for k, v in hostname_data.items()
                 if k != "methods").lower()
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
    hostname      = (hostname_data["rdns"] or hostname_data["netbios"]
                     or hostname_data["mdns"] or "")

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
        "hostname_methods": hostname_data.get("methods", {}),
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

def _usb_storage_line(dev: dict) -> str:
    st = dev.get("storage") or {}
    parts = st.get("partitions") or []
    if st.get("status") == "OBSERVED" and parts:
        first = parts[0]
        return "{} {} on {} ({})".format(
            first.get("device", UNKNOWN_VALUE), first.get("filesystem", UNKNOWN_VALUE),
            first.get("mountpoint", UNKNOWN_VALUE), first.get("type", UNKNOWN_VALUE))
    return "{}{}".format(st.get("status", UNKNOWN_VALUE),
                         " - " + st["reason"] if st.get("reason") else "")


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
    _row("Session History", "FIRST TIME — NEW DEVICE" if seen==0 else f"Seen {seen+1} times","red" if seen==0 else "dim")
    s = dev.get("storage")
    if s:
        console.print("\n  [dim]Storage Details:[/dim]")
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
        console.print("\n  [bold red]Risk Findings:[/bold red]")
        for f in dev["risk_findings"]: console.print(f"  [red]  ✗  {f}[/red]")
    if dev.get("traffic",{}).get("active_connections"):
        console.print("\n  [dim]Active Connections:[/dim]")
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
            "version":   __version__,
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
    ts_str = utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")
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

def run_forensics(subnet=None, no_nmap: bool = False, stop=None, session=None):
    """Profile this host, its USB devices and the local network.

    Every section is reported as OBSERVED, INFERRED or UNAVAILABLE. A section
    that could not run says why; it never appears as an empty success.
    """
    stop = stop or StopController()
    cfg = get_config().forensics
    if no_nmap:
        cfg.nmap_enabled = False
    session = session or Session(module="forensics", interface=str(subnet or "auto"))

    caps = capabilities.probe_all()
    ensure_dir(cfg.results_path)
    _load_history()

    console.rule("[bold green]PACKETPULSE - DEVICE FORENSICS[/bold green]")
    console.print("  [dim]Session:[/dim] [cyan]{}[/cyan]  [dim]Host:[/dim] [green]{}[/green]".format(
        session.session_id, platform.system()))
    console.print("\n  [bold]Capabilities on this host[/bold]")
    for line in capabilities.describe():
        console.print("  " + line)
    console.print()

    session.note_limitation(
        "OS fingerprinting from TTL/window size is a heuristic, not an identification.")
    session.note_limitation(
        "Only devices and hosts the OS actually reports are listed; nothing is inferred "
        "into existence.")

    data = {
        "session": None,
        "host": {},
        "usb": {"status": "NOT RUN", "devices": []},
        "lan": {"status": "NOT RUN", "devices": []},
    }

    # ── LOCAL HOST (always observable) ──────────────────────────────────────
    console.print("  [bold cyan][ LOCAL HOST ][/bold cyan]  [dim]source: OS APIs (OBSERVED)[/dim]")
    try:
        local = _profile_local_machine()
        data["host"] = local
        console.print("  Hostname      : [green]{}[/green]".format(esc(local.get("hostname", UNKNOWN_VALUE))))
        console.print("  OS            : [green]{} {}[/green]".format(
            esc(local.get("os", UNKNOWN_VALUE)), esc(local.get("os_release", ""))))
        console.print("  Open sockets  : [green]{}[/green]   Listening: [green]{}[/green]".format(
            len(local.get("open_connections", [])), len(local.get("listening_ports", []))))
        session.count("host_open_connections", len(local.get("open_connections", [])))
        session.count("host_listening_ports", len(local.get("listening_ports", [])))
    except Exception as e:
        session.record_error("local_profile", e)
        console.print("  [red]Local host profiling FAILED:[/red] {}".format(e))

    # ── USB ─────────────────────────────────────────────────────────────────
    if cfg.usb_enabled:
        console.print("\n  [bold cyan][ USB DEVICES ][/bold cyan]")
        devices, reason = _scan_usb_devices(session)
        if reason:
            data["usb"] = {"status": "UNAVAILABLE", "reason": reason, "devices": []}
            session.record_unavailable("USB forensics", reason)
            console.print("  [yellow]USB Forensics: UNAVAILABLE[/yellow]")
            console.print("  [dim]Reason: {}[/dim]".format(esc(reason)))
        else:
            data["usb"] = {"status": "OBSERVED", "devices": devices}
            session.count("usb_devices", len(devices))
            if devices:
                for dev in devices:
                    _print_usb(dev)
                    try:
                        pth = str(safe_output_path(
                            cfg.results_path, "usb_",
                            dev.get("serial_number") or dev.get("product") or "unknown", ".json"))
                        save_json(dev, pth)
                    except (OSError, ValueError) as e:
                        session.record_error("usb_save", e)
            else:
                console.print("  [dim]No USB devices are currently connected "
                              "(enumeration succeeded and returned none).[/dim]")

    # ── LAN ─────────────────────────────────────────────────────────────────
    if cfg.lan_enabled:
        console.print("\n  [bold cyan][ LAN DEVICES ][/bold cyan]")
        if not caps["capture"].available:
            reason = caps["capture"].reason
            data["lan"] = {"status": "UNAVAILABLE", "reason": reason, "devices": []}
            session.record_unavailable("LAN discovery", reason)
            console.print("  [yellow]LAN discovery: UNAVAILABLE[/yellow]  [dim]{}[/dim]".format(esc(reason)))
        else:
            console.print("  [dim]source: ARP sweep (OBSERVED)[/dim]")
            arp = _arp_scan(subnet)
            if not arp:
                data["lan"] = {"status": "COMPLETED", "devices": [],
                               "note": "no ARP replies received"}
                console.print("  [yellow]No ARP replies received.[/yellow]")
                console.print("  [dim]Nothing was observed - this is not proof the network is empty. "
                              "ARP replies may be filtered, or the subnet may be wrong.[/dim]")
            else:
                console.print("  [green]{} host(s) replied to ARP[/green]\n".format(len(arp)))
                if cfg.nmap_enabled and not caps["nmap"].available:
                    session.record_unavailable("Active port scan (nmap)", caps["nmap"].reason)
                    console.print("  [yellow]Nmap scan: UNAVAILABLE[/yellow]  [dim]{}[/dim]".format(
                        esc(caps["nmap"].reason)))
                devices = []
                for entry in arp:
                    if stop.is_set():
                        session.note_limitation("LAN profiling stopped early on request.")
                        break
                    try:
                        dev = _profile_lan_device(entry["ip"], entry["mac"], cfg, subnet or "")
                        devices.append(dev)
                        _print_lan(dev)
                        pth = str(Path(cfg.results_path) /
                                  "lan_{}.json".format(entry["ip"].replace(".", "_")))
                        save_json(dev, pth)
                    except Exception as e:
                        session.record_error("lan_profile:{}".format(entry.get("ip")), e)
                        console.print("  [red]Could not profile {}:[/red] {}".format(
                            esc(entry.get("ip", "?")), e))
                data["lan"] = {"status": "OBSERVED", "devices": devices}
                session.count("lan_devices", len(devices))

    session.finish(completed=True)
    data["session"] = session.to_dict()
    data["capabilities"] = [c.as_dict() for c in caps.values()]

    _write_forensics_reports(session, cfg, data)
    return session


def _write_forensics_reports(session, cfg, data) -> None:
    """Write forensics artifacts for THIS session."""
    stamp = timestamp_filename()
    base = Path(cfg.results_path)
    ensure_dir(cfg.results_path)
    sd = session.to_dict()

    json_path = str(base / "forensics_{}.json".format(stamp))
    try:
        save_json(data, json_path)
        console.print("\n  [dim]JSON ->[/dim] [cyan]{}[/cyan]".format(json_path))
    except (OSError, TypeError) as e:
        session.record_error("forensics_json", e)

    html_path = str(base / "forensics_{}.html".format(stamp))
    try:
        _generate_forensics_report(data, html_path)
        console.print("  [dim]HTML ->[/dim] [cyan]{}[/cyan]".format(html_path))
    except Exception as e:
        session.record_error("forensics_html", e)
        console.print("  [yellow]HTML report FAILED:[/yellow] {}".format(e))

    pdf_path = str(base / "forensics_{}.pdf".format(stamp))
    try:
        usb = data.get("usb", {})
        lan = data.get("lan", {})
        host = data.get("host", {})
        save_report_pdf(
            "PACKETPULSE FORENSICS REPORT",
            "Session {}".format(sd["session_id"]),
            [
                ("Session", [
                    "Session ID: {}".format(sd["session_id"]),
                    "Status: {}".format(sd["status"]),
                    "Started: {}".format(sd["started_at"]),
                    "Ended: {}".format(sd["ended_at"]),
                    "Host: {} ({} {})".format(host.get("hostname", UNKNOWN_VALUE),
                                              host.get("os", UNKNOWN_VALUE),
                                              host.get("os_release", "")),
                ]),
                ("USB", [
                    "Status: {}".format(usb.get("status")),
                    "Reason: {}".format(usb.get("reason", "n/a")),
                    "Devices observed: {}".format(len(usb.get("devices", []))),
                ]),
                ("LAN", [
                    "Status: {}".format(lan.get("status")),
                    "Reason: {}".format(lan.get("reason", "n/a")),
                    "Hosts observed: {}".format(len(lan.get("devices", []))),
                ] + [
                    "{} / {} - {}".format(d.get("ip", "?"), d.get("mac", "?"),
                                          (d.get("os_fingerprint") or {}).get("likely_os", UNKNOWN_VALUE))
                    for d in lan.get("devices", [])[:20]
                ]),
                ("Unavailable", ["{}: {}".format(u["feature"], u["reason"])
                                 for u in sd["unavailable_features"]] or ["Nothing unavailable"]),
                ("Limitations", sd["limitations"] or ["None recorded"]),
            ],
            pdf_path,
        )
        console.print("  [dim]PDF  ->[/dim] [cyan]{}[/cyan]".format(pdf_path))
    except (OSError, ValueError, RuntimeError) as e:
        session.record_error("forensics_pdf", e)
        console.print("  [yellow]PDF report FAILED:[/yellow] {}".format(e))

    console.print("\n  [bold]{}[/bold]".format(session.summary_line()))
    if sd["unavailable_features"]:
        console.print("  [yellow]Unavailable this run:[/yellow]")
        for u in sd["unavailable_features"]:
            console.print("    [dim]- {}: {}[/dim]".format(esc(u["feature"]), esc(u["reason"])))


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
            ts       = utc_now().strftime("%H:%M:%S")
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
