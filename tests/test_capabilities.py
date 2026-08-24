"""Capability probing and interface selection tests.

These cover the code that decides what this host can do, and which interface a
capture should use. Getting the interface wrong silently produces a capture
containing only local broadcast traffic, so it is worth pinning down.
"""
from __future__ import annotations

import sys

import pytest

from packetpulse.core import capabilities as C


# ── Capability model ─────────────────────────────────────────────────────────

def test_every_capability_reports_availability_with_a_reason():
    caps = C.probe_all()
    assert caps, "no capabilities probed"
    for key, cap in caps.items():
        assert cap.name, key
        if cap.available:
            assert cap.detail, f"{key} available but gave no detail"
        else:
            # An unavailable capability must always say why, so callers can
            # print UNAVAILABLE with a cause instead of an empty section.
            assert cap.reason, f"{key} unavailable with no reason"


def test_unavailable_features_are_serialisable_for_reports():
    for entry in C.unavailable_features():
        assert set(entry) == {"name", "available", "detail", "reason"}
        assert entry["available"] is False
        assert entry["reason"]


def test_platform_support_covers_every_module():
    support = C.platform_support()
    assert set(support) == {
        "Packet Sniffer", "DNS Monitor", "URL Scanner",
        "Device Forensics", "Full Pipeline",
    }
    assert all(v in (C.SUPPORTED, C.PARTIAL, C.UNSUPPORTED) for v in support.values())


def test_usb_is_unavailable_off_linux_with_the_real_reason():
    cap = C.probe_all()["usb"]
    if sys.platform.startswith("linux"):
        pytest.skip("USB forensics is genuinely available on Linux")
    assert cap.available is False
    assert "Linux" in cap.reason


def test_nmap_requires_both_binding_and_binary():
    cap = C.probe_all()["nmap"]
    if cap.available:
        assert cap.detail, "available nmap must name the binary path"
    else:
        assert "nmap" in cap.reason.lower()


def test_privilege_hint_is_platform_correct():
    hint = C.privilege_hint()
    if sys.platform == "win32":
        assert "sudo" not in hint.lower(), "Windows users must not be told to run sudo"
        assert "administrator" in hint.lower()
    else:
        assert "sudo" in hint.lower()


def test_describe_returns_one_line_per_capability():
    lines = C.describe()
    assert len(lines) == len(C.probe_all())
    assert all(line.strip().startswith(("[ok]", "[--]")) for line in lines)


# ── Interface selection ──────────────────────────────────────────────────────

def test_route_interface_is_stable_within_a_process():
    assert C.default_route_interface() == C.default_route_interface()


def test_route_interface_resolves_when_one_is_found():
    iface = C.default_route_interface()
    if iface is None:
        pytest.skip("no route interface on this host")
    ok, detail = C.resolve_interface(iface)
    assert ok is True, detail
    assert detail


def test_unknown_interface_is_rejected_with_a_reason():
    ok, detail = C.resolve_interface("DefinitelyNotAnAdapter_zzz")
    assert ok is False
    assert "not found" in detail or "not usable" in detail


def test_empty_interface_means_platform_default():
    ok, detail = C.resolve_interface(None)
    assert ok is True
    assert "default" in detail


def test_device_paths_are_accepted_without_resolution():
    """A raw capture-device path goes straight to the capture library.

    Requiring scapy to resolve it made capture succeed or fail depending on
    whether scapy's interface cache happened to be warm.
    """
    ok, _ = C.resolve_interface(C.NPF_PREFIX + "{00000000-0000-0000-0000-000000000000}")
    assert ok is True


def test_interface_note_warns_on_a_mismatch():
    routed = C.default_route_interface()
    if not routed:
        pytest.skip("no route interface on this host")
    note = C.interface_note("SomeOtherAdapter")
    assert "may not appear" in note or "routes via" in note
    assert C.interface_note(routed).startswith("Capturing on")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows adapter lookup")
def test_windows_adapter_lookup_matches_the_route_address():
    import socket

    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sk.connect(("8.8.8.8", 53))
        route_ip = sk.getsockname()[0]
    finally:
        sk.close()

    friendly, guid = C._windows_adapter_for_ip(route_ip)
    if guid is None:
        pytest.skip("route address not attached to an enumerable adapter")
    assert guid.startswith("{") and guid.endswith("}")
    assert C.default_route_interface() == C.NPF_PREFIX + guid


@pytest.mark.skipif(sys.platform != "win32", reason="Windows adapter lookup")
def test_windows_adapter_lookup_returns_nothing_for_a_foreign_address():
    friendly, guid = C._windows_adapter_for_ip("203.0.113.7")
    assert friendly is None and guid is None


# ── Capture backend ──────────────────────────────────────────────────────────

def test_capture_backend_load_is_idempotent():
    C.ensure_capture_backend()
    # Second call must be effectively free — not a repeat of an import that
    # has been measured at over two minutes on some hosts.
    assert C.ensure_capture_backend() < 0.5


def test_capture_probe_does_not_require_elevation_to_answer():
    """Probing must return a verdict either way, never raise."""
    cap = C.probe_capture()
    assert isinstance(cap.available, bool)
    assert cap.detail or cap.reason
