"""Tests for the Linux-only code paths.

These run on any platform. Where a Linux facility is required (pyudev), a
stand-in is injected so the enumeration logic itself is exercised — the point
is to prove the code is correct before it reaches a Linux host, since USB
forensics cannot run on Windows or macOS at all.

The stand-ins live here, in tests. The application never fabricates devices.
"""
from __future__ import annotations

import sys
import types

import pytest

from packetpulse.core import capabilities as C
from packetpulse.core.capabilities import Capability
from packetpulse.forensics import forensics as F


# ── External tool invocation ─────────────────────────────────────────────────

def test_missing_tool_reports_unavailable_with_the_tool_name():
    out, status = F._run_tool(["definitely-not-a-real-tool-xyz"])
    assert out == ""
    assert status.startswith("UNAVAILABLE")
    assert "definitely-not-a-real-tool-xyz" in status


def test_tool_status_is_never_silently_empty():
    """Every outcome must be classifiable; a blank name must be explainable."""
    _out, status = F._run_tool(["nmblookup", "-A", "127.0.0.1"], timeout=3)
    assert status == "OBSERVED" or status.startswith("UNAVAILABLE")


def test_failing_tool_reports_its_error(tmp_path):
    exe = sys.executable
    out, status = F._run_tool([exe, "-c", "import sys; sys.exit(3)"], timeout=15)
    assert status.startswith("UNAVAILABLE")
    assert "exit code 3" in status or "->" in status


def test_successful_tool_is_observed():
    exe = sys.executable
    out, status = F._run_tool([exe, "-c", "print('hello')"], timeout=15)
    assert status == "OBSERVED"
    assert "hello" in out


def test_hostname_resolution_reports_each_method_separately():
    result = F._get_hostname("127.0.0.1")
    assert set(result) >= {"rdns", "netbios", "mdns", "methods"}
    for method, status in result["methods"].items():
        assert status in ("OBSERVED", "NOT RESOLVED") or status.startswith("UNAVAILABLE"), \
            f"{method} -> {status}"


# ── USB enumeration (pyudev stand-in) ────────────────────────────────────────

class _FakeAttrs:
    def __init__(self, data):
        self._data = data

    def get(self, key, default=None):
        return self._data.get(key, default)

    def asstring(self, key):
        return self._data[key]


class _FakeDevice:
    def __init__(self, props, attrs=None, node=None, driver="", syspath=""):
        self._props = props
        self._attrs = _FakeAttrs(attrs or {})
        self.device_node = node
        self.driver = driver
        self.sys_path = syspath

    def get(self, key, default=None):
        return self._props.get(key, default)

    @property
    def attributes(self):
        return self._attrs


@pytest.fixture
def fake_udev(monkeypatch):
    """Inject a pyudev stand-in and mark USB forensics available."""
    stick = _FakeDevice(
        {"ID_VENDOR_ID": "0781", "ID_MODEL_ID": "5567", "ID_MODEL": "Cruzer_Blade",
         "ID_VENDOR": "SanDisk", "ID_SERIAL_SHORT": "4C530001234"},
        {"speed": "480", "bMaxPower": "200mA"},
        node="/dev/bus/usb/001/004", driver="usb-storage", syspath="/sys/devices/usb1/1-4",
    )
    keyboard = _FakeDevice(
        {"ID_VENDOR_ID": "046d", "ID_MODEL_ID": "c31c", "ID_MODEL": "USB_Keyboard",
         "ID_VENDOR": "Logitech", "ID_SERIAL_SHORT": ""},
        {"speed": "1.5"}, node=None, driver="usbhid", syspath="/sys/devices/usb2/2-1",
    )
    partition = _FakeDevice(
        {"DEVTYPE": "partition", "ID_FS_TYPE": "vfat", "ID_FS_LABEL": "USBDATA",
         "ID_FS_UUID": "1234-ABCD"},
        {"size": "61341696"}, node="/dev/sdb1",
    )

    class _Listing(list):
        def match_parent(self, parent):
            return _Listing([partition] if parent is stick else [])

    class _Context:
        def list_devices(self, **kwargs):
            if kwargs.get("subsystem") == "block":
                return _Listing()
            return _Listing([stick, keyboard])

    module = types.ModuleType("pyudev")
    module.Context = _Context
    monkeypatch.setitem(sys.modules, "pyudev", module)

    caps = dict(C.probe_all())
    caps["usb"] = Capability("USB forensics", True, detail="stand-in")
    monkeypatch.setattr(F.capabilities, "probe_all", lambda: caps)
    monkeypatch.setattr(F, "_save_history", lambda: None)
    return stick, keyboard, partition


def test_usb_devices_are_enumerated_from_udev(fake_udev):
    devices, reason = F._scan_usb_devices()
    assert reason == ""
    assert len(devices) == 2
    stick = devices[0]
    assert stick["product"] == "Cruzer Blade"
    assert stick["manufacturer"] == "SanDisk"
    assert stick["vendor_id"] == "0781"
    assert stick["product_id"] == "5567"
    assert stick["serial_number"] == "4C530001234"
    assert stick["speed"] == "480"
    assert stick["source"].startswith("pyudev")


def test_usb_storage_reads_block_children_not_the_control_node(fake_udev):
    """A usb_device node is /dev/bus/usb/... and carries no filesystem."""
    devices, _ = F._scan_usb_devices()
    storage = devices[0]["storage"]
    assert storage["status"] == "OBSERVED"
    part = storage["partitions"][0]
    assert part["device"] == "/dev/sdb1"
    assert part["filesystem"] == "vfat"
    assert part["label"] == "USBDATA"
    assert part["uuid"] == "1234-ABCD"
    assert part["size_bytes"] == 61341696 * 512


def test_non_storage_device_says_not_applicable(fake_udev):
    devices, _ = F._scan_usb_devices()
    storage = devices[1]["storage"]
    assert storage["status"] == "NOT APPLICABLE"
    assert storage["reason"]
    assert storage["partitions"] == []


def test_missing_field_becomes_unknown_not_blank(fake_udev):
    devices, _ = F._scan_usb_devices()
    keyboard = devices[1]
    assert keyboard["serial_number"] == F.UNKNOWN_VALUE
    assert keyboard["device_node"] == F.UNKNOWN_VALUE


def test_usb_unavailable_returns_a_reason(monkeypatch):
    caps = dict(C.probe_all())
    caps["usb"] = Capability("USB forensics", False, reason="pyudev is not installed")
    monkeypatch.setattr(F.capabilities, "probe_all", lambda: caps)
    devices, reason = F._scan_usb_devices()
    assert devices == []
    assert "pyudev" in reason


def test_udev_failure_is_reported_not_swallowed(monkeypatch):
    class _Broken:
        def __init__(self):
            raise RuntimeError("udev socket unavailable")

    module = types.ModuleType("pyudev")
    module.Context = _Broken
    monkeypatch.setitem(sys.modules, "pyudev", module)
    caps = dict(C.probe_all())
    caps["usb"] = Capability("USB forensics", True, detail="stand-in")
    monkeypatch.setattr(F.capabilities, "probe_all", lambda: caps)

    devices, reason = F._scan_usb_devices()
    assert devices == []
    assert "udev socket unavailable" in reason


# ── POSIX capture probe ──────────────────────────────────────────────────────

def test_pcap_lookup_returns_a_name_or_none():
    result = C._find_pcap()
    assert result is None or isinstance(result, str)


def test_raw_socket_check_returns_a_boolean():
    assert isinstance(C._can_open_raw_socket(), bool)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX capture probe")
def test_posix_probe_explains_a_missing_backend(monkeypatch):
    monkeypatch.setattr(C, "_find_pcap", lambda: None)
    cap = C._probe_capture_posix()
    assert cap.available is False
    assert "libpcap" in cap.reason


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX capture probe")
def test_posix_probe_explains_missing_permission(monkeypatch):
    monkeypatch.setattr(C, "_find_pcap", lambda: "libpcap.so.1")
    monkeypatch.setattr(C, "_can_open_raw_socket", lambda: False)
    cap = C._probe_capture_posix()
    assert cap.available is False
    # Must offer the capability route, not just "run as root".
    assert "CAP_NET_RAW" in cap.reason


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX capture probe")
def test_posix_probe_succeeds_without_root_when_capability_granted(monkeypatch):
    monkeypatch.setattr(C, "_find_pcap", lambda: "libpcap.so.1")
    monkeypatch.setattr(C, "_can_open_raw_socket", lambda: True)
    monkeypatch.setattr(C, "is_admin", lambda: False)
    cap = C._probe_capture_posix()
    assert cap.available is True
    assert "CAP_NET_RAW" in cap.detail


def test_privilege_hint_mentions_capabilities_on_posix():
    if sys.platform == "win32":
        pytest.skip("POSIX hint")
    assert "CAP_NET_RAW" in C.privilege_hint()
