"""Lifecycle, state-reset and security-regression tests.

The security tests here are regressions for defects that were exploitable by
anyone on the same network as a tool running with elevated privileges. They
must keep passing.
"""
from __future__ import annotations

import threading
import time

import pytest

from packetpulse.core.session import Session, StopController, utc_now
from packetpulse.utils.helpers import h, safe_output_path, safe_slug, shell_safe


# ── Session ──────────────────────────────────────────────────────────────────

def test_duration_measured_not_echoed():
    s = Session(module="test", requested_duration=30)
    s.begin_capture()
    time.sleep(0.15)
    s.end_capture()
    s.finish()
    assert s.capture_duration >= 0.1
    assert s.capture_duration < 5            # measured, not the requested 30
    assert s.to_dict()["requested_duration_seconds"] == 30


def test_duration_honored_judged_on_capture_window():
    s = Session(module="test", requested_duration=1)
    s.begin_capture()
    time.sleep(1.0)
    s.end_capture()
    time.sleep(0.2)                          # post-processing
    s.finish()
    assert s.duration_honored() is True


def test_open_ended_run_has_no_duration_claim():
    s = Session(module="test", requested_duration=0)
    s.begin_capture()
    s.end_capture()
    s.finish()
    assert s.duration_honored() is None


def test_status_reflects_what_happened():
    ok = Session(module="t")
    ok.finish(completed=True)
    assert ok.status() == "PASS"

    partial = Session(module="t")
    partial.record_unavailable("USB", "not on this platform")
    partial.finish(completed=True)
    assert partial.status() == "PARTIAL"

    failed = Session(module="t")
    failed.finish(completed=False, abort_reason="no permission")
    assert failed.status() == "FAIL"
    assert "INCOMPLETE" in failed.summary_line()


def test_counters_start_at_zero_and_only_increment():
    s = Session(module="t")
    assert s.get("packets") == 0
    s.count("packets", 3)
    s.count("packets")
    assert s.get("packets") == 4


def test_errors_are_recorded_not_swallowed():
    s = Session(module="t")
    s.record_error("sniff", OSError("device busy"))
    assert s.errors[0]["where"] == "sniff"
    assert "OSError" in s.errors[0]["error"]


def test_unavailable_is_deduplicated():
    s = Session(module="t")
    s.record_unavailable("USB", "reason A")
    s.record_unavailable("USB", "reason B")
    assert len(s.unavailable) == 1


def test_timestamps_are_timezone_aware():
    assert utc_now().tzinfo is not None


# ── Stop control ─────────────────────────────────────────────────────────────

def test_stop_controller_signals_waiters():
    stop = StopController()
    assert stop.is_set() is False

    def worker():
        stop.wait(5)

    t = threading.Thread(target=worker)
    t.start()
    stop.stop()
    t.join(timeout=2)
    assert not t.is_alive()
    assert stop.is_set() is True
    assert stop.scapy_stop_filter(None) is True


def test_stop_wait_returns_promptly():
    stop = StopController()
    start = time.time()
    stop.wait(0.2)
    assert time.time() - start < 1.5


# ── SECURITY REGRESSION: path traversal ──────────────────────────────────────

@pytest.mark.parametrize("hostile", [
    "../../../../etc/passwd",
    "..\\..\\..\\Windows\\System32\\evil",
    "../" * 20 + "tmp/pwned",
    "/absolute/path",
    "name\x00truncated",
    "a" * 500,
])
def test_untrusted_names_cannot_escape_the_output_directory(tmp_path, hostile):
    base = tmp_path / "results"
    base.mkdir()
    out = safe_output_path(str(base), "flag_", hostile, ".json")
    assert out.is_relative_to(base.resolve()), f"escaped with {hostile!r}"
    assert ".." not in out.name
    assert "/" not in out.name and "\\" not in out.name


def test_distinct_hostile_names_do_not_collide(tmp_path):
    base = tmp_path / "r"
    base.mkdir()
    a = safe_output_path(str(base), "f_", "../../evil", ".json")
    b = safe_output_path(str(base), "f_", "../../../evil", ".json")
    assert a != b, "different inputs must not overwrite each other"


def test_safe_slug_strips_separators():
    assert "/" not in safe_slug("a/b/c")
    assert "\\" not in safe_slug("a\\b")
    assert safe_slug("") == "unnamed"
    assert safe_slug("...") == "unnamed"


# ── SECURITY REGRESSION: command injection ───────────────────────────────────

@pytest.mark.parametrize("payload", [
    "http://evil.com/';calc.exe;#",
    'http://evil.com/";Start-Process calc;"',
    "http://evil.com/$(whoami)",
    "http://evil.com/`id`",
    "http://evil.com/\nnewline",
])
def test_notification_text_cannot_break_out_of_a_command(payload):
    cleaned = shell_safe(payload)
    for ch in ("'", '"', ";", "`", "$", "\n", "\r", "|", "&", "(", ")"):
        assert ch not in cleaned, f"{ch!r} survived in {cleaned!r}"


# ── SECURITY REGRESSION: HTML injection in reports ───────────────────────────

@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "<iframe src='javascript:alert(1)'>",
    "' onmouseover='alert(1)",
])
def test_captured_values_are_escaped_for_reports(payload):
    out = h(payload)
    assert "<" not in out and ">" not in out
    assert '"' not in out
    assert "&" in out          # something was actually escaped


def test_escape_handles_none_and_numbers():
    assert h(None) == ""
    assert h(42) == "42"


# ── Honest value rendering ───────────────────────────────────────────────────

def test_present_marks_missing_values_explicitly():
    from packetpulse.utils.helpers import present, UNKNOWN
    assert present(None) == UNKNOWN
    assert present("") == UNKNOWN
    assert present("   ") == UNKNOWN
    assert present("real") == "real"


def test_geoip_reports_unavailable_rather_than_guessing():
    """With no local database and online lookup disabled, the answer is
    UNAVAILABLE with a reason — never a placeholder location."""
    from packetpulse.utils.helpers import geoip_lookup
    result = geoip_lookup("8.8.8.8", db_path="", allow_online=False)
    assert result["available"] is False
    assert result["country"] == "UNAVAILABLE"
    assert result["reason"]


def test_geoip_private_address_is_local_not_looked_up():
    from packetpulse.utils.helpers import geoip_lookup
    result = geoip_lookup("192.168.1.1")
    assert result["source"] == "local"
    assert result["available"] is True
