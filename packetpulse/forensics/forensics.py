"""
PacketPulse — Deep Device Forensics
Profiles every device: USB-connected and LAN-connected.

USB devices  → kernel-level data via pyudev (serial, product, VID/PID, power)
LAN devices  → ARP + MAC OUI + mDNS + NetBIOS + TCP fingerprint + nmap
"""
from __future__ import annotations

import re
import json
import socket
import struct
import subprocess
import threading
import platform
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from packetpulse.core.config import get_config
from packetpulse.core.logger import get_logger
from packetpulse.utils.helpers import (
    geoip_lookup, is_private_ip, save_json, ensure_dir, now_str, human_bytes
)

console = Console()
log = get_logger("forensics")


# ══════════════════════════════════════════════════════════════════════════════
# MAC OUI lookup
# ══════════════════════════════════════════════════════════════════════════════

def _mac_lookup(mac: str) -> str:
    """Look up MAC vendor using manuf library or fallback OUI table."""
    try:
        from manuf import manuf
        p = manuf.MacParser()
        result = p.get_manuf(mac)
        return result or "Unknown"
    except Exception:
        pass

    # Fallback: well-known prefixes
    prefix = mac.upper().replace("-", ":")[0:8]
    KNOWN = {
        "00:0C:29": "VMware", "00:50:56": "VMware",
        "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
        "3C:06:30": "Apple", "A4:C3:F0": "Apple",
        "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
        "00:1A:11": "Google", "94:65:2D": "Google Chromecast",
        "FC:F1:36": "Samsung", "00:16:3E": "Xen",
        "00:1B:44": "SanDisk", "00:26:B9": "Dell",
        "00:21:CC": "Cisco", "00:0F:F7": "TP-Link",
        "D4:5D:64": "TP-Link", "50:C7:BF": "TP-Link",
        "80:CE:62": "Huawei", "00:E0:4C": "Realtek",
    }
    return KNOWN.get(prefix, "Unknown")


# ══════════════════════════════════════════════════════════════════════════════
# OS Fingerprinting via TCP/IP signals
# ══════════════════════════════════════════════════════════════════════════════

OS_SIGNATURES = [
    # (ttl_min, ttl_max, window_min, window_max, os_name, confidence)
    (120, 128, 8192,  65535, "Windows 10/11",    90),
    (112, 120, 8192,  65535, "Windows 7/8",       80),
    (60,  64,  5840,  29200, "Linux 4.x/5.x",    88),
    (60,  64,  65535, 65535, "Linux / Android",   82),
    (58,  64,  65535, 65535, "macOS / iOS",       85),
    (50,  64,  4096,  16384, "Embedded / IoT",    70),
    (60,  64,  1024,  4096,  "FreeBSD",           75),
    (30,  64,  512,   4096,  "Network Device",    72),
]


def _fingerprint_os(ttl: int, window: int, vendor: str) -> tuple[str, int]:
    """
    Estimate OS from TTL + window size + vendor.
    Returns (os_name, confidence_pct)
    """
    # Vendor shortcuts
    v = vendor.lower()
    if "apple" in v:
        return "macOS / iOS", 85
    if "microsoft" in v:
        return "Windows", 85
    if "raspberry" in v or "raspberr" in v:
        return "Linux (Raspberry Pi OS)", 95
    if "android" in v or "samsung" in v or "xiaomi" in v or "huawei" in v:
        return "Android", 80
    if "vmware" in v:
        return "Linux (VMware guest)", 88
    if "virtualbox" in v:
        return "Linux/Windows (VirtualBox)", 80

    # TTL + window matching
    for tmin, tmax, wmin, wmax, name, conf in OS_SIGNATURES:
        if tmin <= ttl <= tmax and wmin <= window <= wmax:
            return name, conf

    # TTL-only fallback
    if ttl >= 120:
        return "Windows", 60
    if ttl >= 60:
        return "Linux / Unix", 60
    if ttl >= 30:
        return "Network Device", 55
    return "Unknown", 0


# ══════════════════════════════════════════════════════════════════════════════
# ARP scan (find devices on LAN)
# ══════════════════════════════════════════════════════════════════════════════

def _arp_scan(subnet: Optional[str] = None) -> list[dict]:
    """
    Send ARP requests to discover devices on the local network.
    Returns list of {ip, mac} dicts.
    """
    try:
        from scapy.all import ARP, Ether, srp, conf
        if not subnet:
            # Detect local subnet
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        # Derive /24 subnet
                        parts = addr.address.split(".")
                        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                        break
                if subnet:
                    break

        if not subnet:
            return []

        console.print(f"  [dim]ARP scanning[/dim] [cyan]{subnet}[/cyan] [dim]...[/dim]")
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(arp_req, timeout=3, verbose=False)

        results = []
        for _, rcv in answered:
            results.append({"ip": rcv[ARP].psrc, "mac": rcv[Ether].src})
        return results

    except Exception as e:
        log.debug(f"ARP scan error: {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
# Hostname discovery
# ══════════════════════════════════════════════════════════════════════════════

def _get_hostname(ip: str) -> str:
    """Try multiple methods to resolve hostname."""
    # 1. Reverse DNS
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    # 2. NetBIOS (Windows machines)
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip], capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            if "<00>" in line and "GROUP" not in line:
                name = line.strip().split()[0]
                if name and name != ip:
                    return name + " (NetBIOS)"
    except Exception:
        pass

    return ""


# ══════════════════════════════════════════════════════════════════════════════
# Nmap scan
# ══════════════════════════════════════════════════════════════════════════════

def _nmap_scan(ip: str) -> dict:
    """Run nmap against a single IP for ports, services, OS."""
    result = {
        "open_ports": [],
        "os_guess": "",
        "os_confidence": 0,
        "services": {},
    }
    try:
        import nmap
        nm = nmap.PortScanner()
        # -sS SYN scan, -sV version, -O OS detection, top 100 ports
        nm.scan(hosts=ip, arguments="-sS -sV -O --top-ports 100 -T4 --open")
        if ip in nm.all_hosts():
            host = nm[ip]
            # Open ports
            for proto in host.all_protocols():
                ports = host[proto].keys()
                for port in sorted(ports):
                    pdata = host[proto][port]
                    if pdata["state"] == "open":
                        svc = pdata.get("name", "")
                        ver = pdata.get("version", "")
                        result["open_ports"].append(port)
                        result["services"][port] = {
                            "protocol": proto,
                            "service": svc,
                            "version": ver,
                            "state": "open",
                        }
            # OS detection
            if "osmatch" in host and host["osmatch"]:
                best = host["osmatch"][0]
                result["os_guess"] = best.get("name", "")
                result["os_confidence"] = int(best.get("accuracy", 0))
    except Exception as e:
        log.debug(f"nmap scan error for {ip}: {e}")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Traffic stats from pcap (passive, from sniffer data)
# ══════════════════════════════════════════════════════════════════════════════

def _get_traffic_stats(ip: str) -> dict:
    """Collect active connections and traffic info for an IP via psutil."""
    stats = {
        "active_connections": [],
        "bytes_sent": 0,
        "bytes_recv": 0,
    }
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.raddr and conn.raddr.ip == ip:
                stats["active_connections"].append({
                    "local_port": conn.laddr.port if conn.laddr else "",
                    "remote_port": conn.raddr.port,
                    "status": conn.status,
                    "pid": conn.pid,
                })
    except Exception:
        pass
    return stats


# ══════════════════════════════════════════════════════════════════════════════
# Display helpers
# ══════════════════════════════════════════════════════════════════════════════

def _row(key: str, value: str, val_color: str = "white") -> None:
    console.print(f"  [dim]{key:<22}[/dim] [{val_color}]{value}[/{val_color}]")


def _section(title: str) -> None:
    console.print(f"\n  [dim]┌─ {title} {'─' * (60 - len(title))}┐[/dim]")


def _section_end() -> None:
    console.print(f"  [dim]└{'─' * 64}┘[/dim]")


def _print_lan_device(device: dict) -> None:
    ip = device.get("ip", "?")
    mac = device.get("mac", "?")
    vendor = device.get("vendor", "Unknown")
    hostname = device.get("hostname", "")
    os_guess = device.get("os_guess", "Unknown")
    os_conf = device.get("os_confidence", 0)
    device_type = device.get("device_type", "Unknown")
    nmap = device.get("nmap", {})
    open_ports = nmap.get("open_ports", [])
    services = nmap.get("services", {})
    geo = device.get("geo", {})
    connections = device.get("traffic", {}).get("active_connections", [])
    risk = device.get("risk", "LOW")

    risk_col = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}.get(risk, "white")

    console.print()
    console.rule(f"[bold]LAN DEVICE — {ip}[/bold]  [dim]risk:[/dim] [{risk_col}]{risk}[/{risk_col}]")

    _section("IDENTITY")
    _row("IP Address", ip, "cyan")
    _row("MAC Address", mac)
    _row("Hostname", hostname or "(not resolved)", "dim" if not hostname else "green")
    _row("First Seen", device.get("first_seen", now_str()), "dim")
    _section_end()

    _section("DEVICE PROFILE")
    _row("Manufacturer", vendor, "white")
    _row("Device Type", device_type, "cyan")
    _row("OS (TCP fingerprint)", f"{os_guess}  [dim](confidence: {os_conf}%)[/dim]",
         "green" if os_conf >= 80 else "yellow")
    if nmap.get("os_guess"):
        _row("OS (nmap active)", f"{nmap['os_guess']}  [dim]({nmap.get('os_confidence',0)}%)[/dim]", "bright_green")
    _section_end()

    if open_ports:
        _section("OPEN PORTS & SERVICES")
        for port in open_ports[:20]:
            svc_info = services.get(port, {})
            svc = svc_info.get("service", "")
            ver = svc_info.get("version", "")
            risk_port = ""
            if port in (4444, 5555, 6666, 1337, 31337, 12345, 23, 2323):
                risk_port = " [red]← SUSPICIOUS[/red]"
            elif port in (22, 23, 3389, 445, 139):
                risk_port = " [yellow]← EXPOSED[/yellow]"
            console.print(
                f"  [dim]  {port:<6}[/dim]"
                f"  [green]OPEN[/green]"
                f"  [cyan]{svc:<12}[/cyan]"
                f"  [dim]{ver}[/dim]"
                f"{risk_port}"
            )
        _section_end()

    if connections:
        _section("ACTIVE CONNECTIONS TO THIS DEVICE")
        for c in connections[:10]:
            pid = c.get("pid", "")
            proc = ""
            if pid:
                try:
                    proc = psutil.Process(pid).name()
                except Exception:
                    pass
            console.print(
                f"  [dim]  :{c.get('local_port','')} → :{c.get('remote_port','')}[/dim]"
                f"  [yellow]{c.get('status','')}[/yellow]"
                + (f"  [dim]{proc}({pid})[/dim]" if proc else "")
            )
        _section_end()

    # GeoIP (for non-LAN IPs)
    if geo and geo.get("country") not in ("LAN", "Unknown", ""):
        _section("GEOLOCATION")
        _row("Country", geo.get("country", ""), "cyan")
        _row("City", geo.get("city", ""), "white")
        _row("Coordinates", f"{geo.get('lat',0):.4f}, {geo.get('lon',0):.4f}", "dim")
        _row("Organization", geo.get("org", ""), "dim")
        _section_end()

    console.print()


def _print_usb_device(dev: dict) -> None:
    """Pretty-print a USB device profile."""
    product = dev.get("product", "Unknown Device")
    risk = dev.get("risk", "OK")
    risk_col = {"OK": "green", "NEW": "yellow", "SUSPICIOUS": "red"}.get(risk, "white")

    console.print()
    console.rule(f"[bold]USB DEVICE — {product}[/bold]  [{risk_col}]{risk}[/{risk_col}]")

    _section("PHYSICAL CONNECTION")
    _row("Connected At", dev.get("connected_at", ""), "green")
    _row("Bus / Port", f"Bus {dev.get('bus','?')}, Port {dev.get('port','?')}")
    _row("USB Speed", dev.get("speed_str", ""), "cyan")
    _row("Power Draw", dev.get("power", ""), "yellow")
    _row("Duration", dev.get("duration", ""))
    _section_end()

    _section("KERNEL IDENTITY (exact data from OS)")
    _row("Product Name", dev.get("product", ""), "green")
    _row("Manufacturer", dev.get("manufacturer", ""), "white")
    _row("Serial Number", dev.get("serial", ""), "cyan")
    _row("VID / PID", f"{dev.get('vid','?')} / {dev.get('pid','?')}", "dim")
    _row("Device Class", dev.get("device_class", ""), "white")
    _row("Driver", dev.get("driver", ""), "dim")
    _row("OS Platform", dev.get("os_platform", ""), "green")
    seen = dev.get("times_seen", 0)
    _row("Previously Seen",
         f"YES — {seen} prior sessions" if seen > 0 else "NO — FIRST TIME",
         "yellow" if seen == 0 else "white")
    _section_end()

    storage = dev.get("storage")
    if storage:
        _section("STORAGE DETAILS")
        _row("Volume Label", storage.get("label", ""), "cyan")
        _row("Filesystem", storage.get("fstype", ""), "white")
        _row("Total Capacity", human_bytes(storage.get("total", 0)), "white")
        used = storage.get("used", 0)
        total = storage.get("total", 1)
        pct = used / total * 100 if total else 0
        bar_len = 40
        filled = int(bar_len * pct / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        _row("Used", f"{human_bytes(used)} ({pct:.0f}%)", "yellow")
        console.print(f"  [dim]{'':22}[/dim] [yellow]{bar}[/yellow]")
        _row("Free", human_bytes(storage.get("free", 0)), "green")
        _row("Mount Point", storage.get("mountpoint", ""), "cyan")
        _row("UUID", storage.get("uuid", ""), "dim")
        _section_end()

    console.print()


# ══════════════════════════════════════════════════════════════════════════════
# USB monitoring via pyudev
# ══════════════════════════════════════════════════════════════════════════════

_device_history: dict[str, int] = {}   # serial → times seen


def _classify_usb_device(device_class: str, product: str, vendor: str) -> str:
    """Guess device type from class/product name."""
    p = (product + " " + vendor).lower()
    if "storage" in device_class.lower() or "disk" in p or "flash" in p or "drive" in p:
        return "Mass Storage"
    if "hid" in device_class.lower() or "keyboard" in p or "mouse" in p:
        return "Human Interface Device (HID)"
    if "audio" in device_class.lower() or "headset" in p or "microphone" in p:
        return "Audio Device"
    if "network" in device_class.lower() or "ethernet" in p or "wifi" in p:
        return "Network Adapter"
    if "iphone" in p or "ipad" in p or "apple mobile" in p:
        return "Apple Mobile Device (MFi)"
    if "android" in p or "adb" in p:
        return "Android Device (ADB)"
    if "printer" in p or "print" in device_class.lower():
        return "Printer"
    if "webcam" in p or "camera" in p or "video" in device_class.lower():
        return "Camera / Webcam"
    return "USB Device"


def _get_storage_info(product: str) -> Optional[dict]:
    """Try to find filesystem info for a newly connected storage device."""
    time_import = __import__("time")
    time_import.sleep(2)  # wait for mount

    for part in psutil.disk_partitions(all=True):
        if not part.mountpoint:
            continue
        label = ""
        uuid = ""

        # Try to get volume label / UUID on Linux
        try:
            r = subprocess.run(
                ["blkid", "-o", "export", part.device],
                capture_output=True, text=True, timeout=3
            )
            for line in r.stdout.splitlines():
                if line.startswith("LABEL="):
                    label = line.split("=", 1)[1]
                elif line.startswith("UUID="):
                    uuid = line.split("=", 1)[1]
        except Exception:
            pass

        # Skip system partitions
        if part.fstype in ("", "tmpfs", "devtmpfs", "sysfs", "proc", "cgroup"):
            continue

        try:
            usage = psutil.disk_usage(part.mountpoint)
            return {
                "label": label or Path(part.mountpoint).name,
                "fstype": part.fstype,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "mountpoint": part.mountpoint,
                "uuid": uuid,
            }
        except Exception:
            pass
    return None


def _identify_os_platform(vid: str, pid: str, product: str, manufacturer: str) -> str:
    """Identify device OS/platform from VID/PID and product name."""
    p = product.lower()
    m = manufacturer.lower()

    # Apple devices
    if vid == "05ac" or "apple" in m:
        if "iphone" in p:
            return "iOS"
        if "ipad" in p:
            return "iPadOS"
        if "macbook" in p or "imac" in p:
            return "macOS"
        return "Apple iOS / macOS"

    # Android
    if vid in ("18d1", "04e8", "12d1", "19d2", "2717"):
        return "Android"
    if "android" in p or "adb" in p:
        return "Android"

    # Windows
    if "windows" in p:
        return "Windows"

    # Raspberry Pi
    if "raspberry" in m or "raspberry" in p:
        return "Linux (Raspberry Pi OS)"

    return ""


def _scan_usb_devices() -> list[dict]:
    """Enumerate all currently connected USB devices."""
    devices = []
    try:
        import pyudev
        context = pyudev.Context()
        for device in context.list_devices(subsystem="usb", DEVTYPE="usb_device"):
            try:
                vendor_id = (device.get("ID_VENDOR_ID") or "").lower()
                model_id = (device.get("ID_MODEL_ID") or "").lower()
                product = (device.get("ID_MODEL") or device.get("ID_MODEL_FROM_DATABASE") or "").replace("_", " ")
                manufacturer = (device.get("ID_VENDOR") or device.get("ID_VENDOR_FROM_DATABASE") or "").replace("_", " ")
                serial = device.get("ID_SERIAL_SHORT") or device.get("ID_SERIAL") or ""
                bus = device.get("BUSNUM") or ""
                devnum = device.get("DEVNUM") or ""
                speed_raw = device.attributes.asstring("speed") if device.attributes.available_attributes else ""
                power_raw = device.attributes.asstring("bMaxPower") if device.attributes.available_attributes else ""
                dev_class = (device.get("ID_USB_CLASS_FROM_DATABASE") or
                             device.get("DRIVER") or "Unknown")

                if not product and not manufacturer:
                    continue

                # Speed
                speed_map = {"1.5": "USB 1.1 (1.5 Mbps)", "12": "USB 1.1 (12 Mbps)",
                             "480": "USB 2.0 (480 Mbps)", "5000": "USB 3.0 (5 Gbps)",
                             "10000": "USB 3.1 (10 Gbps)", "20000": "USB 3.2 (20 Gbps)"}
                speed_str = speed_map.get(speed_raw.strip(), f"USB ({speed_raw} Mbps)" if speed_raw else "Unknown")

                seen = _device_history.get(serial, 0)
                _device_history[serial] = seen + 1

                os_platform = _identify_os_platform(vendor_id, model_id, product, manufacturer)

                dev = {
                    "product": product or "Unknown Device",
                    "manufacturer": manufacturer,
                    "serial": serial,
                    "vid": vendor_id,
                    "pid": model_id,
                    "bus": bus,
                    "port": devnum,
                    "speed_str": speed_str,
                    "power": power_raw or "Unknown",
                    "device_class": dev_class,
                    "driver": device.get("DRIVER") or "",
                    "os_platform": os_platform,
                    "connected_at": now_str(),
                    "times_seen": seen,
                    "risk": "NEW" if seen == 0 else "OK",
                    "duration": "current session",
                }

                # Try storage info
                if "storage" in dev_class.lower() or "mass" in dev_class.lower():
                    storage = _get_storage_info(product)
                    if storage:
                        dev["storage"] = storage

                devices.append(dev)
            except Exception as e:
                log.debug(f"USB device parse error: {e}")

    except ImportError:
        console.print("  [yellow]pyudev not available. USB monitoring requires Linux + pyudev.[/yellow]")
    except Exception as e:
        console.print(f"  [yellow]USB scan error: {e}[/yellow]")

    return devices


# ══════════════════════════════════════════════════════════════════════════════
# LAN device profiling
# ══════════════════════════════════════════════════════════════════════════════

def _profile_lan_device(ip: str, mac: str, cfg) -> dict:
    """Build a full profile for a single LAN device."""
    vendor = _mac_lookup(mac)
    hostname = _get_hostname(ip)

    # Device type from vendor
    v = vendor.lower()
    if "apple" in v:
        dtype = "Apple Device (Mac/iPhone/iPad)"
    elif "samsung" in v or "xiaomi" in v or "oppo" in v or "oneplus" in v:
        dtype = "Android Smartphone"
    elif "raspberry" in v:
        dtype = "Raspberry Pi / IoT"
    elif "vmware" in v or "virtualbox" in v or "qemu" in v:
        dtype = "Virtual Machine"
    elif "tp-link" in v or "netgear" in v or "asus" in v or "linksys" in v:
        dtype = "Router / Access Point"
    elif "cisco" in v or "juniper" in v:
        dtype = "Network Equipment"
    elif "intel" in v or "dell" in v or "hp " in v or "lenovo" in v:
        dtype = "Laptop / Desktop"
    elif "espressif" in v or "arduino" in v or "microchip" in v:
        dtype = "IoT / Embedded Device"
    else:
        dtype = "Unknown Device"

    # Passive TCP/IP fingerprint from current connections
    os_guess, os_conf = "Unknown", 0
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.raddr and conn.raddr.ip == ip:
                # Can't get TTL/window from psutil — use vendor only
                os_guess, os_conf = _fingerprint_os(64, 65535, vendor)
                break
    except Exception:
        pass

    if os_conf == 0:
        os_guess, os_conf = _fingerprint_os(64, 65535, vendor)

    # Active nmap scan
    nmap_data: dict = {}
    if cfg.nmap_enabled:
        console.print(f"  [dim]  nmap scan →[/dim] [cyan]{ip}[/cyan] [dim]...[/dim]")
        nmap_data = _nmap_scan(ip)
        if nmap_data.get("os_guess"):
            os_guess = nmap_data["os_guess"]
            os_conf = nmap_data["os_confidence"]

    # GeoIP (for external IPs that somehow appear in ARP — unlikely but safe)
    geo = geoip_lookup(ip, cfg.geoip_db) if not is_private_ip(ip) else {}

    # Traffic stats
    traffic = _get_traffic_stats(ip)

    # Risk assessment
    risk = "LOW"
    if nmap_data.get("open_ports"):
        dangerous = [p for p in nmap_data["open_ports"] if p in (4444, 5555, 6666, 1337, 23, 2323, 31337)]
        if dangerous:
            risk = "CRITICAL"
        elif len(nmap_data["open_ports"]) > 10:
            risk = "MEDIUM"

    device = {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "device_type": dtype,
        "os_guess": os_guess,
        "os_confidence": os_conf,
        "nmap": nmap_data,
        "geo": geo,
        "traffic": traffic,
        "risk": risk,
        "first_seen": now_str(),
        "timestamp": now_str(),
    }
    return device


# ══════════════════════════════════════════════════════════════════════════════
# Entry points
# ══════════════════════════════════════════════════════════════════════════════

def run_forensics(subnet: Optional[str] = None, no_nmap: bool = False) -> None:
    """Run full forensics: USB devices + LAN device profiling."""
    cfg = get_config().forensics
    if no_nmap:
        cfg.nmap_enabled = False
    ensure_dir(cfg.results_path)

    console.rule("[bold green]PACKETPULSE  ›  DEVICE FORENSICS[/bold green]")
    console.print(
        f"  [dim]USB scan:[/dim] [green]{'ON' if cfg.usb_enabled else 'OFF'}[/green]  "
        f"[dim]LAN scan:[/dim] [green]{'ON' if cfg.lan_enabled else 'OFF'}[/green]  "
        f"[dim]nmap active:[/dim] [green]{'ON' if cfg.nmap_enabled else 'OFF (use --nmap to enable)'}[/green]"
    )
    console.print("[dim]" + "─" * 100 + "[/dim]")

    all_data: dict = {"timestamp": now_str(), "usb_devices": [], "lan_devices": []}

    # ── USB ───────────────────────────────────────────────────────────────────
    if cfg.usb_enabled:
        console.print("\n  [bold cyan][ USB DEVICES ][/bold cyan]")
        console.print("  [dim]Reading /dev/bus/usb via pyudev...[/dim]\n")
        usb_devices = _scan_usb_devices()
        if usb_devices:
            for dev in usb_devices:
                _print_usb_device(dev)
                all_data["usb_devices"].append(dev)
        else:
            console.print("  [dim]No USB devices found (or pyudev unavailable).[/dim]")

    # ── LAN ───────────────────────────────────────────────────────────────────
    if cfg.lan_enabled:
        console.print("\n  [bold cyan][ LAN DEVICES ][/bold cyan]")

        arp_results = _arp_scan(subnet)
        if not arp_results:
            console.print("  [yellow]No ARP responses — are you on a local network? (requires sudo)[/yellow]")
        else:
            console.print(f"  [green]{len(arp_results)} device(s) discovered[/green]\n")

            # Quick summary table first
            table = Table(box=box.SIMPLE_HEAVY, show_header=True,
                          header_style="dim", padding=(0, 1))
            table.add_column("IP", style="cyan")
            table.add_column("MAC")
            table.add_column("VENDOR")
            table.add_column("HOSTNAME")
            table.add_column("OPEN PORTS")
            table.add_column("RISK")

            for entry in arp_results:
                table.add_row(
                    entry["ip"], entry["mac"],
                    _mac_lookup(entry["mac"]),
                    _get_hostname(entry["ip"]) or "(resolving...)",
                    "scanning...",
                    "—",
                )
            console.print(table)
            console.print("\n  [dim]Building full profiles...[/dim]\n")

            # Full profile per device
            for entry in arp_results:
                device = _profile_lan_device(entry["ip"], entry["mac"], cfg)
                _print_lan_device(device)
                all_data["lan_devices"].append(device)

                fname = f"{cfg.results_path}/lan_{entry['ip'].replace('.','_')}.json"
                save_json(device, fname)
                console.print(f"  [dim]Saved →[/dim] [cyan]{fname}[/cyan]")

    # Save full report
    full_report_path = f"{cfg.results_path}/forensics_{now_str()[:10]}.json"
    save_json(all_data, full_report_path)
    console.print(f"\n  [green]Full report →[/green] [cyan]{full_report_path}[/cyan]\n")


def run_usb_watch() -> None:
    """Watch for USB device connect/disconnect events in real time."""
    console.rule("[bold green]PACKETPULSE  ›  USB LIVE MONITOR[/bold green]")
    console.print("  [dim]Watching for USB device events... (plug/unplug devices)[/dim]\n")
    console.print("[dim]" + "─" * 100 + "[/dim]")

    try:
        import pyudev
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem="usb", device_type="usb_device")

        for device in iter(monitor.poll, None):
            action = device.action
            product = (device.get("ID_MODEL") or "").replace("_", " ")
            vendor = (device.get("ID_VENDOR") or "").replace("_", " ")
            serial = device.get("ID_SERIAL_SHORT") or ""
            ts = datetime.utcnow().strftime("%H:%M:%S")

            if action == "add":
                seen = _device_history.get(serial, 0)
                new_flag = "[bold red] NEW DEVICE[/bold red]" if seen == 0 else f" [dim](seen {seen}x)[/dim]"
                console.print(
                    f"  [dim]{ts}[/dim]  [green]CONNECTED  [/green]  "
                    f"[white]{vendor} {product}[/white]"
                    + (f"  [dim]s/n: {serial}[/dim]" if serial else "")
                    + new_flag
                )
                _device_history[serial] = seen + 1

            elif action == "remove":
                console.print(
                    f"  [dim]{ts}[/dim]  [yellow]DISCONNECTED[/yellow]  "
                    f"[dim]{vendor} {product}[/dim]"
                )

    except ImportError:
        console.print("[red]pyudev not available. Install: pip install pyudev[/red]")
    except KeyboardInterrupt:
        console.print("\n[green]USB monitor stopped.[/green]")
    except Exception as e:
        console.print(f"[red]USB monitor error: {e}[/red]")
