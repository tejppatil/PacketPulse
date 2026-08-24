"""Tests for the analysis heuristics.

These prove the scoring is deterministic and explainable, that legitimate
domains are not flagged, and that nothing reports a confidence it did not
compute.
"""
from __future__ import annotations

import time

import pytest

from packetpulse.core.config import get_config
from packetpulse.sensor import sensor
from packetpulse.urlscan.url_scanner import URLAnalyzer
from packetpulse.utils.helpers import is_private_ip, shannon_entropy


# ── Packet classification ────────────────────────────────────────────────────

def test_every_score_is_explained_by_evidence():
    """A score must equal the sum of the weights that produced it."""
    info = {
        "proto": "HTTP", "src_ip": "10.0.0.5", "dst_ip": "93.184.216.34",
        "src_port": 50000, "dst_port": 80,
        "http": {"method": "POST", "path": "/user/login", "host": "example.com"},
    }
    result = sensor._infer_activity(info)
    assert result["evidence"], "a scored result must carry its evidence"
    assert result["score"] == min(100, sum(e["weight"] for e in result["evidence"]))
    for item in result["evidence"]:
        assert item["basis"], "every indicator must state its basis"


def test_no_fabricated_confidence_field():
    """The old implementation emitted hardcoded confidence percentages."""
    result = sensor._infer_activity({"proto": "TCP", "dst_ip": "1.1.1.1",
                                     "src_port": 1, "dst_port": 443})
    assert "confidence" not in result
    assert result["signal"] in ("NONE", "WEAK", "MODERATE", "STRONG")


def test_https_is_marked_as_not_decrypted():
    result = sensor._infer_activity({"proto": "TCP", "dst_ip": "93.184.216.34",
                                     "src_port": 50000, "dst_port": 443})
    assert "encryption_note" in result
    assert "not decrypted" in result["encryption_note"].lower()


def test_quiet_traffic_produces_no_signal():
    result = sensor._infer_activity({"proto": "UDP", "dst_ip": "192.168.1.5",
                                     "src_port": 1234, "dst_port": 5678})
    assert result["score"] == 0
    assert result["signal"] == "NONE"


@pytest.mark.parametrize("port,expect", [(3389, "RDP"), (22, "SSH"), (445, "SMB")])
def test_service_ports_identified(port, expect):
    result = sensor._infer_activity({"proto": "TCP", "dst_ip": "203.0.113.9",
                                     "src_port": 40000, "dst_port": port})
    assert expect in result["observation"]


# ── Process attribution ──────────────────────────────────────────────────────

def test_attribution_is_unknown_without_a_matching_socket():
    """A wrong process name is worse than UNKNOWN."""
    result = sensor._find_process(9, 9, "203.0.113.1", "203.0.113.2")
    assert result["attribution"] == "UNKNOWN"
    assert result["process"] == ""


def test_attribution_requires_addresses():
    result = sensor._find_process(443, 50000)
    assert result["attribution"] == "UNKNOWN"


# ── Address classification ───────────────────────────────────────────────────

@pytest.mark.parametrize("addr", [
    "10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1",
    "169.254.1.1", "100.64.0.1",                 # CGNAT: missed by is_private
    "fd00::1", "fc00::1", "fe80::1", "::1", "224.0.0.1",
])
def test_non_routable_addresses_detected(addr):
    assert is_private_ip(addr) is True


@pytest.mark.parametrize("addr", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2001:4860:4860::8888"])
def test_public_addresses_detected(addr):
    assert is_private_ip(addr) is False


def test_malformed_address_is_not_private():
    assert is_private_ip("not-an-ip") is False
    assert is_private_ip("") is False


# ── DNS heuristics ───────────────────────────────────────────────────────────

def _dns():
    from packetpulse.dns import dns_monitor
    return dns_monitor


@pytest.mark.parametrize("domain", [
    "google.com", "wikipedia.org", "github.com", "cloudflare.com",
])
def test_known_good_domains_not_flagged(domain):
    d = _dns()
    d._state.reset()
    level, reasons, _ = d._assess_domain(domain, get_config().dns)
    assert level == "OK", f"{domain} flagged: {reasons}"


def test_legitimate_domain_with_keyword_token_not_flagged():
    """Substring matching flagged bankofamerica.com and api.crypto.com."""
    d = _dns()
    d._state.reset()
    for domain in ("bankofamerica.com", "crypto.com", "api.crypto.com"):
        level, reasons, _ = d._assess_domain(domain, get_config().dns)
        assert level != "SUSPICIOUS", f"{domain} wrongly escalated: {reasons}"


def test_dga_indicators_are_reported_individually():
    d = _dns()
    d._state.reset()
    level, reasons, detail = d._assess_domain("xkqjvzwmrbtplnghdsf.com", get_config().dns)
    assert "dga_indicators" in detail
    for ind in detail["dga_indicators"]:
        assert ind["indicator"] and ind["value"] and ind["threshold"]


def test_bigram_score_separates_words_from_random():
    d = _dns()
    assert d._bigram_score("wikipedia") > d._bigram_score("xkqjvzwmrbt")


def test_frequency_analysis_reports_regular_intervals():
    """Periodicity must be measured, not assumed from volume."""
    d = _dns()
    d._state.reset()
    cfg = get_config().dns
    base = time.time()
    # Perfectly regular 1s spacing.
    d._state.query_times["beacon.example"] = [base + i for i in range(20)]
    result = d._frequency_analysis("beacon.example", cfg)
    assert result["periodicity"] == "REGULAR INTERVALS OBSERVED"
    assert result["interval_stats"]["coefficient_of_variation"] < 0.15


def test_frequency_analysis_reports_irregular_traffic_as_irregular():
    """High volume alone must NOT be called beaconing."""
    d = _dns()
    d._state.reset()
    cfg = get_config().dns
    base = time.time()
    bursty = [0, 0.05, 0.08, 0.1, 3.0, 3.1, 9.5, 9.6, 9.7, 20.0,
              20.1, 20.2, 31.0, 44.0, 44.1, 60.0, 60.2, 81.0, 81.1, 99.0]
    d._state.query_times["cdn.example"] = [base + t for t in bursty]
    result = d._frequency_analysis("cdn.example", cfg)
    assert result["periodicity"] in ("IRREGULAR", "SOMEWHAT REGULAR")
    assert result["periodicity"] != "REGULAR INTERVALS OBSERVED"


def test_frequency_analysis_below_threshold_returns_nothing():
    d = _dns()
    d._state.reset()
    d._state.query_times["quiet.example"] = [time.time()]
    assert d._frequency_analysis("quiet.example", get_config().dns) is None


def test_dns_state_reset_clears_everything():
    d = _dns()
    d._state.query_count["x.example"] = 99
    d._state.seen_domains.add("x.example")
    d._state.flagged.append({"domain": "x.example"})
    d._state.total_queries = 99
    d._state.reset()
    assert not d._state.query_count
    assert not d._state.seen_domains
    assert not d._state.flagged
    assert d._state.total_queries == 0


# ── URL analysis ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "https://bankofamerica.com/login",
    "https://crypto.com",
    "https://www.wikipedia.org",
    "https://github.com/python/cpython",
    "https://secure.paypal.com",
])
def test_legitimate_urls_are_clean(url):
    a = URLAnalyzer(url)
    a.check_url_structure()
    assert a.verdict() == "CLEAN", f"{url} -> {a.score}: {[f['check'] for f in a.findings]}"


@pytest.mark.parametrize("url", [
    "http://free-prize-winner-claim-now.tk/verify?token=abc",
    "http://192.168.1.1/admin/login.php",
])
def test_structurally_suspicious_urls_accumulate_score(url):
    a = URLAnalyzer(url)
    a.check_url_structure()
    assert a.score >= 25
    assert a.verdict() in ("SUSPICIOUS", "MALICIOUS")


def test_url_score_matches_its_basis():
    a = URLAnalyzer("http://free-prize-winner.tk/claim?redirect=x")
    a.check_url_structure()
    assert a.score == min(100, sum(b["weight"] for b in a.scoring_basis()))


@pytest.mark.parametrize("bad", ["https://[::1", "http://", "notaurl", "http://.", ""])
def test_malformed_urls_do_not_crash(bad):
    a = URLAnalyzer(bad)
    a.check_url_structure()
    a.check_ssl()
    assert a.verdict() in ("CLEAN", "SUSPICIOUS", "MALICIOUS")


def test_reputation_reports_not_checked_when_disabled():
    cfg = get_config().urlscan
    original = cfg.allow_external
    cfg.allow_external = False
    try:
        a = URLAnalyzer("http://example.com")
        a.check_reputation()
        detail = " ".join(f["detail"] for f in a.findings)
        assert "NOT CHECKED" in detail
        # Crucially, it must not claim a clean result.
        assert not any(f["level"] == "OK" and "not listed" in f["detail"] for f in a.findings)
    finally:
        cfg.allow_external = original


def test_allowlisted_domain_short_circuits():
    a = URLAnalyzer("https://github.com/some/path")
    assert a.is_allowlisted() is True
    report = a.run()
    assert report["verdict"] == "CLEAN"
    # Only the allowlist finding: no network checks were performed.
    assert len(report["findings"]) == 1


def test_entropy_is_length_independent_enough():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") > 1.0
