"""
PacketPulse — Runtime capability probing.

Determines what this machine can actually do, once, at startup. Modules consult
this instead of discovering missing tools via exceptions swallowed by bare
excepts. A capability that is absent is reported as UNAVAILABLE with a reason —
never as an empty successful section.
"""
from __future__ import annotations

import importlib
import os
import platform
import shutil
import sys
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

SUPPORTED = "SUPPORTED"
PARTIAL = "PARTIALLY SUPPORTED"
UNSUPPORTED = "UNSUPPORTED"

# Npcap capture-device prefix on Windows.
NPF_PREFIX = chr(92) + "Device" + chr(92) + "NPF_"


@dataclass(frozen=True)
class Capability:
    name: str
    available: bool
    detail: str = ""
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "available": self.available,
            "detail": self.detail,
            "reason": self.reason,
        }


def _probe_module(mod: str, label: str, why: str) -> Capability:
    try:
        m = importlib.import_module(mod)
    except Exception as e:  # ImportError, and platform-specific failures
        return Capability(label, False, reason=f"{why} ({type(e).__name__})")
    ver = getattr(m, "__version__", "")
    return Capability(label, True, detail=f"{mod} {ver}".strip())


def _probe_binary(binary: str, label: str, why: str) -> Capability:
    path = shutil.which(binary)
    if not path:
        return Capability(label, False, reason=why)
    return Capability(label, True, detail=path)


def is_admin() -> bool:
    """True when the process has the privileges packet capture requires."""
    if os.name == "posix":
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def privilege_hint() -> str:
    """Platform-correct advice. Never tells a Windows user to run sudo."""
    if os.name == "posix":
        return ("Re-run with: sudo packetpulse  (or grant CAP_NET_RAW to the "
                "interpreter to capture without root)")
    return "Re-run from an Administrator terminal (packet capture also requires Npcap)"


@lru_cache(maxsize=1)
def probe_capture() -> Capability:
    """Can this host open a live capture handle?

    Deliberately avoids importing scapy: on a Windows host with many virtual
    adapters `import scapy.all` measured ~123 seconds, which froze the menu
    before the user had chosen anything. The capture backend is detected
    natively instead, and scapy is imported only when a capture actually runs.
    """
    if sys.platform == "win32":
        return _probe_capture_windows()
    return _probe_capture_posix()


# Runtime sonames, newest first. ctypes.util.find_library("pcap") looks for the
# LINKER name libpcap.so, which ships in libpcap-dev — so on a stock Kali or
# Debian install (runtime libpcap0.8 only, no -dev) it returns nothing even
# though capture works perfectly. We look for the runtime libraries directly.
_PCAP_SONAMES = ("libpcap.so.1", "libpcap.so.0.8", "libpcap.so", "libpcap.dylib")


def _find_pcap() -> Optional[str]:
    import ctypes

    for soname in _PCAP_SONAMES:
        try:
            ctypes.CDLL(soname)
            return soname
        except OSError:
            continue
    try:
        import ctypes.util

        found = ctypes.util.find_library("pcap")
        if found:
            ctypes.CDLL(found)
            return found
    except (OSError, ImportError):
        pass
    return None


def _can_open_raw_socket() -> bool:
    """Test the actual permission to capture, rather than assuming root.

    Linux grants packet capture through CAP_NET_RAW, which can be attached to
    the interpreter or granted via a group — so a non-root user may well be
    able to capture. Asking `is_admin()` alone reports UNAVAILABLE for those
    setups. Opening a raw socket is the definitive test; it sends nothing and
    is closed immediately.
    """
    import socket

    families = []
    if hasattr(socket, "AF_PACKET"):            # Linux
        families.append((socket.AF_PACKET, socket.SOCK_RAW, 0))
    else:                                        # macOS/BSD have no AF_PACKET
        families.append((socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP))

    for family, kind, proto in families:
        try:
            sk = socket.socket(family, kind, proto)
            sk.close()
            return True
        except (PermissionError, OSError):
            continue
    return False


def _probe_capture_posix() -> Capability:
    """Detect libpcap and real capture permission on Linux/macOS."""
    lib = _find_pcap()
    if not lib:
        hint = ("install libpcap (Debian/Kali: apt install libpcap0.8; "
                "Fedora: dnf install libpcap)")
        return Capability("Packet capture", False,
                          reason="libpcap not found — {}".format(hint))

    if _can_open_raw_socket():
        how = "root" if is_admin() else "granted capability (CAP_NET_RAW)"
        return Capability("Packet capture", True,
                          detail="{} via {}".format(lib, how))

    return Capability(
        "Packet capture", False,
        reason="{} present but raw sockets are not permitted for this user — "
               "run with sudo, or grant CAP_NET_RAW "
               "(setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3)))"
        .format(lib))


def _probe_capture_windows() -> Capability:
    """Detect Npcap/WinPcap without importing scapy."""
    import ctypes

    for dll in ("wpcap.dll", "Packet.dll"):
        try:
            ctypes.WinDLL(dll)
        except OSError:
            return Capability(
                "Packet capture", False,
                reason="{} not found — install Npcap "
                       "(https://npcap.com) to capture on Windows".format(dll))

    # A capture device must also be visible.
    try:
        import socket as _socket

        sk = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        try:
            sk.connect(("8.8.8.8", 53))
            route_ip = sk.getsockname()[0]
        finally:
            sk.close()
        _friendly, guid = _windows_adapter_for_ip(route_ip)
        if guid:
            return Capability("Packet capture", True,
                              detail="Npcap; route adapter {}".format(_friendly or guid))
    except OSError:
        pass
    return Capability("Packet capture", True, detail="Npcap present")


@lru_cache(maxsize=1)
def probe_all() -> dict[str, Capability]:
    """Full capability map. Cached — probing is cheap but not free."""
    linux = sys.platform.startswith("linux")

    caps = {
        "capture": probe_capture(),
        "pcap_write": _probe_module("scapy.utils", "PCAP writing", "scapy is required"),
        "pdf": _probe_module("reportlab", "PDF reports", "reportlab is not installed"),
        "geoip_db": _probe_module("geoip2", "Offline GeoIP", "geoip2 is not installed"),
        "mac_vendor": _probe_module("manuf", "MAC vendor lookup", "manuf is not installed"),
        "html_parse": _probe_module("bs4", "HTML content analysis", "beautifulsoup4 is not installed"),
        "tld": _probe_module("tldextract", "Domain parsing", "tldextract is not installed"),
        "process_attribution": _probe_module("psutil", "Process attribution", "psutil is not installed"),
    }

    # USB forensics is genuinely Linux-only: pyudev wraps libudev.
    if linux:
        caps["usb"] = _probe_module("pyudev", "USB forensics", "pyudev is not installed")
    else:
        caps["usb"] = Capability(
            "USB forensics",
            False,
            reason=f"requires Linux (libudev); this host is {platform.system()}",
        )

    # nmap needs BOTH the python binding and the binary.
    nmap_mod = _probe_module("nmap", "nmap binding", "python-nmap is not installed")
    nmap_bin = _probe_binary("nmap", "nmap binary", "nmap is not installed or not on PATH")
    if nmap_mod.available and nmap_bin.available:
        caps["nmap"] = Capability("Active port scan (nmap)", True, detail=nmap_bin.detail)
    else:
        caps["nmap"] = Capability(
            "Active port scan (nmap)",
            False,
            reason=nmap_bin.reason or nmap_mod.reason,
        )

    # Linux hostname-resolution helpers used by LAN profiling.
    for key, binary, label in (
        ("nmblookup", "nmblookup", "NetBIOS name lookup"),
        ("avahi", "avahi-resolve", "mDNS name lookup"),
        ("lsusb", "lsusb", "USB descriptor detail"),
        ("blkid", "blkid", "USB filesystem detail"),
    ):
        caps[key] = _probe_binary(binary, label, f"{binary} not found on PATH")

    return caps


def platform_support() -> dict[str, str]:
    """Per-module honest support level for THIS host."""
    caps = probe_all()
    capture_ok = caps["capture"].available

    sniffer = SUPPORTED if capture_ok else UNSUPPORTED
    dns = SUPPORTED if capture_ok else UNSUPPORTED
    urlscan = SUPPORTED if capture_ok else PARTIAL  # single-URL mode needs no capture

    if caps["usb"].available and caps["nmap"].available:
        forensics = SUPPORTED
    elif caps["usb"].available or caps["nmap"].available or capture_ok:
        forensics = PARTIAL
    else:
        forensics = UNSUPPORTED

    return {
        "Packet Sniffer": sniffer,
        "DNS Monitor": dns,
        "URL Scanner": urlscan,
        "Device Forensics": forensics,
        "Full Pipeline": sniffer,
    }


def unavailable_features() -> list[dict]:
    """Everything that is missing, with the reason, for inclusion in reports."""
    return [c.as_dict() for c in probe_all().values() if not c.available]


def describe(width: int = 0) -> list[str]:
    """Human-readable capability lines for the terminal."""
    caps = probe_all()
    lines = []
    for cap in caps.values():
        mark = "ok" if cap.available else "--"
        note = cap.detail if cap.available else cap.reason
        lines.append(f"  [{mark}] {cap.name}: {note}")
    return lines


def require(feature: str) -> Optional[str]:
    """Return None if available, else the reason it is not.

    Callers use this to emit an explicit UNAVAILABLE record.
    """
    cap = probe_all().get(feature)
    if cap is None:
        return f"unknown capability {feature!r}"
    return None if cap.available else cap.reason


# ── Interface selection ──────────────────────────────────────────────────────


def _windows_adapter_for_ip(route_ip: str):
    """Map a local IPv4 address to its adapter GUID using the Windows API.

    Measured on a host with 79 virtual adapters:
        scapy.arch.windows import ....... ~123 s
        GetAdaptersAddresses ............ ~0.01 s

    Both return the same adapter, so interface detection uses the native call
    and never pays scapy's import cost just to answer "which adapter is this".
    Returns (friendly_name, guid) or (None, None).
    """
    import ctypes
    import ctypes.wintypes as wt

    AF_UNSPEC = 0
    SKIP = 0x2 | 0x4 | 0x8   # anycast | multicast | dns-server
    ERROR_BUFFER_OVERFLOW = 111

    class SOCKADDR(ctypes.Structure):
        _fields_ = [("sa_family", wt.USHORT), ("sa_data", ctypes.c_ubyte * 26)]

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [("lpSockaddr", ctypes.POINTER(SOCKADDR)),
                    ("iSockaddrLength", ctypes.c_int)]

    class UNICAST(ctypes.Structure):
        pass

    UNICAST._fields_ = [
        ("Length", wt.ULONG), ("Flags", wt.DWORD),
        ("Next", ctypes.POINTER(UNICAST)), ("Address", SOCKET_ADDRESS),
        ("PrefixOrigin", ctypes.c_int), ("SuffixOrigin", ctypes.c_int),
        ("DadState", ctypes.c_int), ("ValidLifetime", wt.ULONG),
        ("PreferredLifetime", wt.ULONG), ("LeaseLifetime", wt.ULONG),
        ("OnLinkPrefixLength", ctypes.c_ubyte),
    ]

    class ADAPTER(ctypes.Structure):
        pass

    ADAPTER._fields_ = [
        ("Length", wt.ULONG), ("IfIndex", wt.DWORD),
        ("Next", ctypes.POINTER(ADAPTER)), ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(UNICAST)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", ctypes.c_wchar_p), ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
    ]

    try:
        size = wt.ULONG(15000)
        buf = ctypes.create_string_buffer(size.value)
        rc = ctypes.windll.iphlpapi.GetAdaptersAddresses(
            AF_UNSPEC, SKIP, None, buf, ctypes.byref(size))
        if rc == ERROR_BUFFER_OVERFLOW:
            buf = ctypes.create_string_buffer(size.value)
            rc = ctypes.windll.iphlpapi.GetAdaptersAddresses(
                AF_UNSPEC, SKIP, None, buf, ctypes.byref(size))
        if rc != 0:
            return None, None

        import socket as _socket

        node = ctypes.cast(buf, ctypes.POINTER(ADAPTER))
        while node:
            adapter = node.contents
            ua = adapter.FirstUnicastAddress
            while ua:
                sa = ua.contents.Address.lpSockaddr.contents
                if sa.sa_family == _socket.AF_INET:
                    octets = bytes(sa.sa_data)[2:6]
                    if ".".join(str(b) for b in octets) == route_ip:
                        guid = adapter.AdapterName.decode(errors="replace")
                        return adapter.FriendlyName, guid
                ua = ua.contents.Next
            node = adapter.Next if adapter.Next else None
    except (OSError, AttributeError, ValueError):
        return None, None
    return None, None


_backend_ready = False
_backend_full = False


def _iface_resolves(name) -> bool:
    """Can scapy turn this interface name into a capture handle?"""
    if not name:
        return True
    try:
        from scapy.interfaces import resolve_iface

        return bool(getattr(resolve_iface(name), "network_name", None))
    except Exception:
        return False


def ensure_capture_backend(iface=None) -> float:
    """Prepare scapy for a capture on `iface`, as cheaply as it can be done.

    scapy.sniff() resolves its `iface` argument against conf.ifaces. Importing
    the layer modules alone populates that registry quickly (~2 s) and is
    enough on most hosts, but it can miss adapters that only the platform arch
    provider enumerates — on this Windows host the VPN tunnel adapter was
    missing, and capture failed with "Interface not found".

    So: take the fast path, verify the chosen interface actually resolves, and
    escalate to the full `scapy.all` import only when it does not. That import
    measured ~123 s here, so it is a fallback, never the default.

    Returns seconds spent, so the caller can tell the user why it waited.
    """
    global _backend_ready, _backend_full
    import time as _time

    t0 = _time.monotonic()

    if not _backend_ready:
        try:
            from scapy.config import conf  # noqa: F401
            from scapy.layers.l2 import Ether  # noqa: F401
            from scapy.sendrecv import sniff  # noqa: F401

            _backend_ready = True
        except Exception:
            return _time.monotonic() - t0

    if _iface_resolves(iface):
        return _time.monotonic() - t0

    if not _backend_full:
        # The fast registry does not know this interface. Load everything.
        try:
            import scapy.all  # noqa: F401

            _backend_full = True
        except Exception:
            pass

    return _time.monotonic() - t0


def backend_is_full() -> bool:
    """True when the slow, complete scapy load was required."""
    return _backend_full


@lru_cache(maxsize=1)
def default_route_interface() -> Optional[str]:
    """The interface the OS actually uses to reach the internet.

    scapy's conf.iface is not necessarily the routing interface: on a host with
    a VPN tunnel active, outbound traffic leaves via the tunnel adapter while
    conf.iface still points at the physical NIC, so a capture there sees only
    local broadcast traffic. Verified on this host: DNS was invisible on the
    default interface and present on the tunnel adapter.

    Returns None when the mapping cannot be established; callers should then
    fall back to the platform default rather than guessing.
    """
    import socket

    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sk.connect(("8.8.8.8", 53))   # no packets sent; just route lookup
            route_ip = sk.getsockname()[0]
        finally:
            sk.close()
    except OSError:
        return None

    if not route_ip or route_ip.startswith("0."):
        return None

    if sys.platform == "win32":
        # Address the Npcap device directly. The friendly adapter name is
        # rejected by scapy's resolver unless its interface cache happens to be
        # warm, which made capture succeed or fail depending on what else had
        # touched scapy first. The NPF device path built from the adapter GUID
        # always works, and the native lookup avoids a ~123 s scapy import.
        _friendly, guid = _windows_adapter_for_ip(route_ip)
        if guid:
            return NPF_PREFIX + guid

        try:
            from scapy.arch.windows import get_windows_if_list

            for i in get_windows_if_list():
                if route_ip in (i.get("ips") or []):
                    fallback_guid = i.get("guid")
                    if fallback_guid:
                        return NPF_PREFIX + fallback_guid
                    return i.get("name")
        except Exception:
            return None
        return None

    try:
        import psutil

        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if getattr(a, "address", None) == route_ip:
                    return name
    except Exception:
        return None
    return None


def interface_note(chosen: Optional[str]) -> str:
    """Explain the consequence of the interface choice, for the session record."""
    routed = default_route_interface()
    if not chosen:
        if routed:
            return ("No interface specified; the platform default was used. Outbound "
                    "internet traffic on this host routes via {!r}, so a capture on "
                    "the default interface may see only local traffic.".format(routed))
        return "No interface specified; the platform default was used."
    if routed and chosen != routed:
        return ("Capturing on {!r}; outbound internet traffic on this host routes via "
                "{!r}, so traffic to the internet may not appear in this capture."
                .format(chosen, routed))
    return "Capturing on {!r}, which is the current outbound route interface.".format(chosen)


def resolve_interface(name):
    """Validate an interface name against scapy. Returns (ok, detail).

    A name scapy cannot resolve must produce a clean UNAVAILABLE, not a
    ValueError traceback out of sniff().
    """
    if not name:
        return True, "platform default"

    # A raw device path is passed straight to the capture library; scapy's
    # name resolver does not need to (and cannot reliably) validate it.
    if str(name).startswith((NPF_PREFIX[:8], "/dev/")):
        return True, "capture device {}".format(name)

    try:
        from scapy.interfaces import resolve_iface

        iface = resolve_iface(name)
        if getattr(iface, "network_name", None):
            return True, getattr(iface, "description", None) or str(iface)
        return False, "interface {!r} is not usable for capture".format(name)
    except Exception as e:
        return False, "interface {!r} not found ({})".format(name, type(e).__name__)
