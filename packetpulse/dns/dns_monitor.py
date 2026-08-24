"""
PacketPulse — DNS Query Monitor
Watches every DNS query the machine makes and flags suspicious ones.
"""
from __future__ import annotations

import re
import statistics
import threading
from collections import defaultdict
from pathlib import Path
import time
from typing import Optional


from packetpulse.core.config import get_config
from packetpulse.core.logger import get_logger, console as _shared_console
from packetpulse.utils.helpers import (
    shannon_entropy, save_json, ensure_dir, now_str, timestamp_filename,
    save_report_pdf, safe_output_path, h as esc, utc_now,
)
from packetpulse.core import capabilities
from packetpulse.core.session import Session, StopController
from rich.markup import escape as rescape

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
    from scapy.layers.dns import DNS
    from scapy.layers.inet import IP
    from scapy.sendrecv import sniff
    SCAPY_OK = True
    SCAPY_UNAVAILABLE_REASON = ""
except Exception as _e:
    SCAPY_OK = False
    SCAPY_UNAVAILABLE_REASON = _SCAPY_ERR or "{}: {}".format(type(_e).__name__, _e)

console = _shared_console
log = get_logger("dns")

_lock = threading.Lock()


class _DNSState:
    """All per-run state. Recreated for every monitoring session so a second
    run can never inherit the first run's counters, domains or findings."""

    def __init__(self) -> None:
        self.query_count: dict[str, int] = defaultdict(int)
        self.query_times: dict[str, list[float]] = defaultdict(list)
        self.qtypes: dict[str, set] = defaultdict(set)
        self.seen_domains: set[str] = set()
        self.flagged: list[dict] = []
        self.first_seen: dict[str, float] = {}
        self.parse_errors: int = 0
        self.total_queries: int = 0

    def reset(self) -> None:
        self.__init__()


_state = _DNSState()

# Backwards-compatible read-only views used by the report builders.
_query_count = _state.query_count
_seen_domains = _state.seen_domains
_flagged = _state.flagged

# High-risk TLDs for DGA / malware
HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz",
    ".win", ".loan", ".click", ".download", ".stream",
    ".racing", ".review", ".party", ".science", ".accountant",
}

SUSPICIOUS_KEYWORDS = [
    "malware", "botnet", "c2", "payload", "shell", "exploit",
    "inject", "trojan", "ransom", "crypto", "miner", "stealer",
]

# Well-known safe domains (skip scanning these)
SAFE_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com",
    "youtube.com", "youtu.be", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "microsoft.com", "windows.com",
    "apple.com", "icloud.com", "amazon.com", "amazonaws.com",
    "cloudflare.com", "fastly.com", "akamai.com",
    "github.com", "githubusercontent.com",
    "stackoverflow.com", "reddit.com",
}


# ── Domain assessment ────────────────────────────────────────────────────────
#
# Every indicator below is computed from the observed name. The function
# returns the indicators that fired so a reader can check the reasoning, and
# deliberately avoids asserting "malware" or "C2" — those require evidence
# this tool does not have.

_VOWELS = set("aeiou")
# Common English/tech bigrams. A generated name scores low on these.
_COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es",
    "or", "te", "of", "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng",
    "se", "ha", "as", "ou", "io", "le", "ve", "co", "me", "de", "hi", "ri",
    "ro", "ic", "ne", "ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si",
    "om", "ur", "ca", "el", "ta", "la", "ns", "di", "fo", "ho", "pe", "ec",
    "pr", "no", "ct", "us", "ac", "ot", "il", "tr", "ly", "nc", "et", "ut",
    "ss", "so", "rs", "un", "lo", "wa", "ge", "ie", "wh", "ee", "wi", "em",
    "ad", "ol", "rt", "po", "we", "na", "ul", "ni", "ts", "mo", "ow", "pa",
    "im", "mi", "ai", "sh", "ir", "su", "id", "os", "iv", "ia", "am", "fi",
    "ci", "vi", "pl", "ig", "tu", "ev", "ld", "ry", "mp", "fe", "bl", "ab",
}


def _bigram_score(label: str) -> float:
    """Fraction of adjacent letter pairs that are common in real words.

    Length-independent, unlike raw Shannon entropy, which rises with length
    and therefore flags long legitimate CDN hostnames.
    """
    letters = [c for c in label.lower() if c.isalpha()]
    if len(letters) < 3:
        return 1.0
    pairs = ["".join(letters[i:i + 2]) for i in range(len(letters) - 1)]
    hits = sum(1 for pr in pairs if pr in _COMMON_BIGRAMS)
    return hits / len(pairs)


def _dga_indicators(label: str, cfg) -> list[dict]:
    """Structural indicators that a label may be machine-generated.

    Documented heuristic; no single indicator is conclusive.
    """
    out = []
    if len(label) < 8:
        return out

    entropy = shannon_entropy(label)
    if entropy > cfg.dga_entropy_threshold:
        out.append({"indicator": "High character entropy",
                    "value": "{:.2f}".format(entropy),
                    "threshold": str(cfg.dga_entropy_threshold)})

    bigram = _bigram_score(label)
    if bigram < 0.25:
        out.append({"indicator": "Few common letter pairs",
                    "value": "{:.0%} of bigrams are common".format(bigram),
                    "threshold": "<25%"})

    letters = [c for c in label if c.isalpha()]
    if letters:
        vowel_ratio = sum(1 for c in letters if c in _VOWELS) / len(letters)
        if vowel_ratio < 0.20:
            out.append({"indicator": "Low vowel ratio",
                        "value": "{:.0%}".format(vowel_ratio),
                        "threshold": "<20%"})

    digits = sum(1 for c in label if c.isdigit())
    if digits and digits / len(label) > 0.40:
        out.append({"indicator": "High digit ratio",
                    "value": "{:.0%}".format(digits / len(label)),
                    "threshold": ">40%"})
    return out


def _frequency_analysis(domain: str, cfg) -> Optional[dict]:
    """Describe query frequency, and test for periodicity honestly.

    Query VOLUME alone is not beaconing: CDNs and telemetry are high volume and
    irregular. Periodicity is only reported when the intervals between queries
    are actually regular, measured by coefficient of variation.
    """
    times = _state.query_times.get(domain) or []
    count = len(times)
    if count < cfg.beacon_warning_threshold:
        return None

    window = max(times[-1] - times[0], 1e-6)
    result = {
        "queries": count,
        "window_seconds": round(window, 1),
        "rate_per_minute": round(count / (window / 60.0), 2) if window > 0 else 0.0,
        "periodicity": "NOT ESTABLISHED",
        "interval_stats": None,
    }

    if count >= 4:
        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        intervals = [i for i in intervals if i > 0]
        if len(intervals) >= 3:
            mean = statistics.fmean(intervals)
            stdev = statistics.pstdev(intervals)
            cv = (stdev / mean) if mean > 0 else float("inf")
            result["interval_stats"] = {
                "mean_seconds": round(mean, 2),
                "stdev_seconds": round(stdev, 2),
                "coefficient_of_variation": round(cv, 3),
                "samples": len(intervals),
            }
            # A regular beacon has low variance relative to its mean.
            if cv < 0.15 and len(intervals) >= 5:
                result["periodicity"] = "REGULAR INTERVALS OBSERVED"
            elif cv < 0.35:
                result["periodicity"] = "SOMEWHAT REGULAR"
            else:
                result["periodicity"] = "IRREGULAR"
    return result


def _assess_domain(domain: str, cfg) -> tuple[str, list[str], dict]:
    """Assess an observed domain.

    Returns (level, reasons, detail) where level is OK | NOTABLE | SUSPICIOUS.
    Language is deliberately non-committal: this function reports structural
    observations, not verdicts about malware.
    """
    reasons: list[str] = []
    detail: dict = {}
    level = "OK"
    domain_lower = domain.lower().rstrip(".")

    for safe in SAFE_DOMAINS:
        if domain_lower == safe or domain_lower.endswith("." + safe):
            return "OK", [], {"allowlisted": safe}

    # Reverse-DNS zones are structurally long and deeply nested by definition
    # (an IPv6 PTR is 32 nibble labels). Judging them by shape produces noise,
    # not findings.
    if domain_lower.endswith((".arpa", ".in-addr.arpa", ".ip6.arpa")):
        return "OK", [], {"zone": "reverse-DNS (structural checks not applicable)"}

    # Multicast/local service discovery names are not internet domains.
    if domain_lower.endswith((".local", ".localdomain", ".home.arpa")):
        return "OK", [], {"zone": "link-local service discovery"}

    labels = domain_lower.split(".")
    sld = labels[-2] if len(labels) >= 2 else domain_lower

    def escalate(new: str) -> None:
        nonlocal level
        order = {"OK": 0, "NOTABLE": 1, "SUSPICIOUS": 2}
        if order[new] > order[level]:
            level = new

    for tld in HIGH_RISK_TLDS:
        if domain_lower.endswith(tld):
            reasons.append("TLD {} has elevated abuse rates in public feeds".format(tld))
            detail["tld"] = tld
            escalate("NOTABLE")
            break

    if cfg.flag_keywords:
        # Whole-token matching: substring matching flagged bankofamerica.com
        # and api.crypto.com as threats.
        tokens = set(re.split(r"[.\-_0-9]+", domain_lower))
        hits = sorted(tokens & set(SUSPICIOUS_KEYWORDS))
        if hits and sld not in SUSPICIOUS_KEYWORDS:
            reasons.append("Domain contains the token(s): {}".format(", ".join(hits)))
            detail["keyword_tokens"] = hits
            escalate("NOTABLE")

    if cfg.flag_dga:
        ind = _dga_indicators(sld, cfg)
        if len(ind) >= 3:
            reasons.append("Name is structurally consistent with algorithmic generation "
                           "({} indicators)".format(len(ind)))
            escalate("SUSPICIOUS")
        elif len(ind) == 2:
            reasons.append("Name has unusual structure ({} indicators)".format(len(ind)))
            escalate("NOTABLE")
        if ind:
            detail["dga_indicators"] = ind

    if len(domain_lower) > cfg.max_domain_length:
        reasons.append("Name is unusually long ({} characters)".format(len(domain_lower)))
        detail["length"] = len(domain_lower)
        escalate("NOTABLE")

    longest = max((len(x) for x in labels), default=0)
    if longest >= 45:
        reasons.append("Single label of {} characters (can indicate DNS tunnelling; "
                       "not confirmed)".format(longest))
        detail["longest_label"] = longest
        escalate("NOTABLE")

    if domain_lower.count("-") >= 4:
        reasons.append("{} hyphens in the name".format(domain_lower.count("-")))
        escalate("NOTABLE")

    if "xn--" in domain_lower:
        reasons.append("Punycode/IDN name — visually similar to other names is possible, "
                       "but homograph abuse is NOT confirmed by this check")
        detail["punycode"] = True
        escalate("NOTABLE")

    if cfg.flag_beacon:
        freq = _frequency_analysis(domain_lower, cfg)
        if freq:
            detail["frequency"] = freq
            msg = "High query frequency: {} queries over {}s ({}/min); periodicity: {}".format(
                freq["queries"], freq["window_seconds"], freq["rate_per_minute"],
                freq["periodicity"])
            reasons.append(msg)
            if freq["periodicity"] == "REGULAR INTERVALS OBSERVED":
                escalate("SUSPICIOUS")
            else:
                escalate("NOTABLE")

    return level, reasons, detail


def _save_flagged_summary(cfg) -> None:
    if not _flagged:
        return
    try:
        summary = {
            "timestamp": now_str(),
            "flagged_count": len(_flagged),
            "domains": _flagged,
        }
        save_json(summary, "{}/dns_summary_{}.json".format(
            cfg.results_path, utc_now().strftime("%Y%m%d_%H%M%S")))
    except Exception as e:
        log.debug(f"Could not save DNS summary: {e}")


def _generate_dns_html_report(cfg, session) -> str:
    """Render the DNS report for THIS session. All observed values are escaped."""
    sd = session.to_dict()
    now = utc_now()
    ts_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    top_domains = sorted(_state.query_count.items(), key=lambda it: it[1], reverse=True)[:40]
    flagged = list(_state.flagged)
    total_domains = len(_state.seen_domains)
    total_queries = _state.total_queries
    duration_label = "{}s measured".format(sd["capture_duration_seconds"])

    top_rows = "".join(
        "<tr><td class='mono'>{}</td><td class='right'>{}</td></tr>".format(esc(d), esc(c))
        for d, c in top_domains
    ) or "<tr><td colspan='2' class='dim'>No DNS queries were observed</td></tr>"

    flagged_rows = "".join(
        "<tr><td class='mono'>{}</td><td>{}</td><td>{}</td><td class='right'>{}</td></tr>".format(
            esc(e["domain"]), esc(e["level"]),
            esc("; ".join(e["reasons"])), esc(e["qtype"]))
        for e in flagged
    ) or "<tr><td colspan='4' class='dim'>No domains matched any indicator</td></tr>"

    session_rows = "".join(
        "<tr><td class='mono'>{}</td><td>{}</td></tr>".format(esc(k), esc(v))
        for k, v in [
            ("Session ID", sd["session_id"]), ("Status", sd["status"]),
            ("Started", sd["started_at"]), ("Ended", sd["ended_at"]),
            ("Requested duration", sd["requested_duration_seconds"] or "until stopped"),
            ("Measured capture", "{}s".format(sd["capture_duration_seconds"])),
            ("Duration honoured", "n/a" if sd["duration_honored"] is None
             else ("YES" if sd["duration_honored"] else "NO")),
            ("Queries observed", total_queries),
            ("Parse errors", _state.parse_errors),
        ]
    )
    limitation_rows = "".join(
        "<tr><td>{}</td></tr>".format(esc(t)) for t in sd["limitations"]
    ) or "<tr><td class='dim'>None recorded</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>PacketPulse DNS Monitor Report — {ts_str}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0b0b0d;color:#dedede;font-family:'Segoe UI',sans-serif;font-size:14px;line-height:1.6}}
.container{{max-width:1100px;margin:0 auto;padding:30px 24px}}
.header{{padding:20px 0;border-bottom:1px solid #1c1c24;display:flex;align-items:flex-start;gap:20px}}
.brand{{font-size:32px;font-weight:800;color:#50fa7b;letter-spacing:2px}}
.subtitle{{font-size:14px;color:#8be9fd;margin-top:6px}}
.dw-badge{{display:inline-block;margin-top:10px;padding:5px 11px;border-radius:999px;border:1px solid #50fa7b55;background:#50fa7b1a;color:#9effbf;font-size:10px;letter-spacing:1px;text-transform:uppercase}}
.meta{{display:grid;grid-template-columns:repeat(3,minmax(180px,1fr));gap:16px;margin-top:24px}}
.card{{background:#11131a;border:1px solid #1f2330;border-radius:12px;padding:18px}}
.card .label{{font-size:11px;color:#6f7b9c;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}}
.card .value{{font-size:18px;font-weight:700;color:#ffffff}}
.section{{margin-top:32px}}
.section h2{{font-size:18px;color:#f1fa8c;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:12px 14px;border-bottom:1px solid #1c1c24;text-align:left;vertical-align:top}}
th{{font-size:11px;color:#6272a4;text-transform:uppercase;letter-spacing:1px}}
td{{font-size:13px;color:#e6e6ff}}
.mono{{font-family:'Courier New',monospace;font-size:13px}}
.right{{text-align:right}}
.dim{{color:#7f8fa4}}
.footer{{display:flex;justify-content:space-between;align-items:center;margin-top:42px;padding-top:18px;border-top:1px solid #1c1c24;font-size:12px;color:#6272a4}}
</style>
</head>
<body>
<div class='container'>
  <div class='header'>
    <div>
      <div class='brand'>PACKETPULSE</div>
      <div class='subtitle'>DNS Monitor Session Report • Engineered by Dreamwalker4u</div>
            <div class='dw-badge'>Generated by Dreamwalker4u</div>
    </div>
    <div class='dim' style='margin-left:auto;text-align:right'>Generated: {ts_str}</div>
  </div>

  <div class='meta'>
    <div class='card'><div class='label'>Session Duration</div><div class='value'>{esc(duration_label)}</div></div>
    <div class='card'><div class='label'>Total DNS Queries</div><div class='value'>{total_queries:,}</div></div>
    <div class='card'><div class='label'>Unique Domains</div><div class='value'>{total_domains:,}</div></div>
    <div class='card'><div class='label'>Flagged Domains</div><div class='value'>{len(flagged):,}</div></div>
    <div class='card'><div class='label'>DGA Detection</div><div class='value'>{'Enabled' if cfg.flag_dga else 'Disabled'}</div></div>
    <div class='card'><div class='label'>Keyword Flags</div><div class='value'>{'Enabled' if cfg.flag_keywords else 'Disabled'}</div></div>
  </div>

  <div class='section'>
    <h2>Top Queried Domains</h2>
    <table>
      <thead><tr><th>Domain</th><th class='right'>Queries</th></tr></thead>
      <tbody>{top_rows}</tbody>
    </table>
  </div>

  <div class='section'>
    <h2>Flagged Domain Findings</h2>
    <table>
      <thead><tr><th>Domain</th><th>Severity</th><th>Reasons</th><th class='right'>Type</th></tr></thead>
      <tbody>{flagged_rows}</tbody>
    </table>
  </div>

  <div class='section'>
    <h2>Session Provenance</h2>
    <table><tr><th>Field</th><th>Value</th></tr>{session_rows}</table>
  </div>
  <div class='section'>
    <h2>Limitations</h2>
    <table><tr><th>What this report cannot establish</th></tr>{limitation_rows}</table>
  </div>
  <div class='footer'>
    <div>PacketPulse • Dreamwalker4u</div>
    <div>Report generated by PacketPulse DNS Monitor</div>
  </div>
</div>
</body>
</html>"""
    return html


_QTYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT", 43: "DS", 46: "RRSIG",
    48: "DNSKEY", 65: "HTTPS", 255: "ANY",
}


from packetpulse.sensor.sensor import _dns_first


def _dns_callback(pkt) -> None:
    """Process one observed DNS packet. Queries only."""
    try:
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        if dns.qr != 0:
            return
        question = _dns_first(getattr(dns, "qd", None))
        if question is None:
            return

        raw = question.qname
        domain = raw.decode("utf-8", errors="replace").rstrip(".") if isinstance(raw, bytes) else str(raw).rstrip(".")
        if not domain:
            return

        cfg = get_config().dns
        now_ts = time.time()

        with _lock:
            _state.total_queries += 1
            _state.query_count[domain] += 1
            _state.query_times[domain].append(now_ts)
            is_new = domain not in _state.seen_domains
            _state.seen_domains.add(domain)
            if is_new:
                _state.first_seen[domain] = now_ts
            qtype = _QTYPE_MAP.get(question.qtype, "TYPE{}".format(question.qtype))
            _state.qtypes[domain].add(qtype)

        src_ip = pkt[IP].src if pkt.haslayer(IP) else "UNKNOWN"
        ts = utc_now().strftime("%H:%M:%S")

        level, reasons, detail = _assess_domain(domain, cfg)

        level_str = {
            "OK": "[dim]  OK        [/dim]",
            "NOTABLE": "[yellow]  NOTABLE   [/yellow]",
            "SUSPICIOUS": "[bold red]  SUSPICIOUS[/bold red]",
        }[level]
        domain_col = {"OK": "white", "NOTABLE": "yellow", "SUSPICIOUS": "red"}[level]
        new_flag = " [dim](first seen this session)[/dim]" if is_new and cfg.flag_new_domains else ""

        console.print(
            "  [dim]{}[/dim]{}  [{}]{}[/{}]{}  [dim]{}[/dim]  [dim]{}[/dim]".format(
                ts, level_str, domain_col, rescape(domain), domain_col,
                new_flag, rescape(qtype), rescape(src_ip))
        )
        for r in reasons:
            console.print("            [dim]|- {}[/dim]".format(rescape(r)))

        if level != "OK":
            entry = {
                "timestamp": now_str(),
                "domain": domain,
                "level": level,
                "reasons": reasons,
                "indicators": detail,
                "src_ip": src_ip,
                "qtype": qtype,
                "query_count_at_flag": _state.query_count[domain],
            }
            with _lock:
                _state.flagged.append(entry)
            if cfg.save_results:
                try:
                    ensure_dir(cfg.results_path)
                    # Never build a path directly from a name observed on the
                    # wire: it can contain traversal segments.
                    out = safe_output_path(cfg.results_path, "dns_flag_", domain, ".json")
                    save_json(entry, str(out))
                except (OSError, ValueError) as e:
                    log.warning("could not save flag for %r: %s", domain, e)

    except (AttributeError, IndexError, UnicodeDecodeError, ValueError) as e:
        _state.parse_errors += 1
        log.warning("DNS parse error: %s: %s", type(e).__name__, e)


def run_dns_monitor(interface: Optional[str] = None,
                   duration: Optional[int] = None,
                   stop=None,
                   session=None):
    """Monitor live DNS queries. Returns the Session describing the run."""
    _user_iface = bool(interface)
    stop = stop or StopController()
    duration = int(duration or 0)
    interface = interface or capabilities.default_route_interface()
    cfg = get_config().dns
    session = session or Session(
        module="dns",
        requested_duration=duration,
        interface=str(interface or "default"),
        bpf_filter="udp port 53",
    )

    if not SCAPY_OK:
        reason = SCAPY_UNAVAILABLE_REASON or "scapy is not installed"
        session.record_unavailable("DNS monitoring", reason)
        session.finish(completed=False, abort_reason=reason)
        console.print("[red]DNS monitoring UNAVAILABLE:[/red] " + reason)
        return session

    cap = capabilities.probe_capture()
    if not cap.available:
        session.record_unavailable("DNS monitoring", cap.reason)
        session.finish(completed=False, abort_reason=cap.reason)
        console.print("[red]DNS monitoring UNAVAILABLE:[/red] " + cap.reason)
        console.print("  [dim]" + capabilities.privilege_hint() + "[/dim]")
        return session

    # Load the capture backend before resolving/using a named interface.
    _load_secs = capabilities.ensure_capture_backend(interface)
    if _load_secs > 5:
        console.print("  [dim]Capture engine loaded in %.1fs (full adapter "
                      "enumeration was required).[/dim]" % _load_secs)

    ok, detail = capabilities.resolve_interface(interface)
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
            "the routed path." % (interface, detail))
        interface = None
        session.interface = "platform default"


    # Clean state for every run: the previous implementation let run 2 inherit
    # run 1's query counts, which made beacon thresholds fire on history.
    with _lock:
        _state.reset()

    _compat = scapy_compat.COMPAT_NOTE
    if _compat:
        session.note_limitation(_compat)
    session.note_limitation(capabilities.interface_note(interface))
    session.note_limitation(
        "Only plaintext DNS on UDP/53 is observed. DNS-over-HTTPS and "
        "DNS-over-TLS are encrypted and are NOT visible to this monitor.")
    session.note_limitation(
        "Query frequency is measured directly. Periodicity is reported only when "
        "inter-query intervals are actually regular; volume alone is not beaconing.")

    ensure_dir(cfg.results_path)
    console.rule("[bold green]PACKETPULSE  >  DNS MONITOR[/bold green]")
    console.print(
        "  [dim]Session:[/dim] [cyan]{}[/cyan]  [dim]Interface:[/dim] [green]{}[/green]  "
        "[dim]Duration:[/dim] [yellow]{}[/yellow]".format(
            session.session_id, interface or "default",
            "{}s".format(duration) if duration else "until stopped")
    )
    console.print("  [dim]Encrypted DNS (DoH/DoT) is not visible to this monitor.[/dim]")
    console.print("[dim]" + "-" * 100 + "[/dim]")
    console.print("  [dim]TIME      STATUS      DOMAIN                          TYPE    SOURCE[/dim]")
    console.print("[dim]" + "-" * 100 + "[/dim]")

    aborted = ""
    session.begin_capture()
    try:
        sniff(
            iface=interface or None,
            filter="udp port 53",
            prn=_dns_callback,
            store=False,
            timeout=duration if duration > 0 else None,
            stop_filter=lambda _p: stop.is_set(),
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

    session.count("dns_queries_observed", _state.total_queries)
    session.count("unique_domains", len(_state.seen_domains))
    session.count("flagged_domains", len(_state.flagged))
    if _state.parse_errors:
        session.count("parse_errors", _state.parse_errors)
    session.finish(completed=not aborted, abort_reason=aborted)

    if aborted:
        console.print("\n[red]DNS CAPTURE FAILED:[/red] " + aborted)
        console.print("  [dim]" + capabilities.privilege_hint() + "[/dim]")
        return session

    console.print("\n[green]Stopped.[/green]  {}".format(session.summary_line()))

    if _state.total_queries == 0:
        console.print("  [yellow]No DNS queries were observed in this window.[/yellow]")
        console.print("  [dim]This means nothing was seen - not that nothing happened. "
                      "Encrypted DNS would not appear here.[/dim]")

    if _state.flagged:
        console.print("\n[bold]Domains with indicators ({}):[/bold]".format(len(_state.flagged)))
        for f in _state.flagged[-10:]:
            console.print("  [yellow]-[/yellow] {}  [dim]{}[/dim]".format(
                rescape(f["domain"]), rescape("; ".join(f["reasons"][:2]))))

    if cfg.save_results:
        _write_dns_reports(session, cfg)
    return session


def _write_dns_reports(session, cfg) -> None:
    """Write DNS artifacts for THIS session only."""
    report_id = timestamp_filename()
    base = Path(cfg.results_path)
    ensure_dir(cfg.results_path)
    artifacts = {}

    try:
        html_path = str(base / "dns_report_{}.html".format(report_id))
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(_generate_dns_html_report(cfg, session))
        artifacts["html"] = html_path
        console.print("\n[green]HTML ->[/green] [cyan]{}[/cyan]".format(html_path))
    except (OSError, ValueError, KeyError) as e:
        session.record_error("dns_html_report", e)
        console.print("[red]HTML report FAILED:[/red] {}".format(e))

    try:
        json_path = str(base / "dns_report_{}.json".format(report_id))
        save_json({
            "session": session.to_dict(),
            "capabilities_unavailable": capabilities.unavailable_features(),
            "total_queries_observed": _state.total_queries,
            "unique_domains": len(_state.seen_domains),
            "top_domains": [
                {"domain": d, "queries": c, "qtypes": sorted(_state.qtypes.get(d, []))}
                for d, c in sorted(_state.query_count.items(), key=lambda x: x[1], reverse=True)[:50]
            ],
            "flagged_domains": _state.flagged,
            "settings": {
                "flag_dga": cfg.flag_dga,
                "flag_keywords": cfg.flag_keywords,
                "frequency_analysis": cfg.flag_beacon,
                "dga_entropy_threshold": cfg.dga_entropy_threshold,
            },
        }, json_path)
        artifacts["json"] = json_path
        console.print("[green]JSON ->[/green] [cyan]{}[/cyan]".format(json_path))
    except (OSError, TypeError) as e:
        session.record_error("dns_json_report", e)

    try:
        pdf_path = str(base / "dns_report_{}.pdf".format(report_id))
        sd = session.to_dict()
        save_report_pdf(
            "PACKETPULSE DNS MONITOR REPORT",
            "Session {}".format(sd["session_id"]),
            [
                ("Session", [
                    "Session ID: {}".format(sd["session_id"]),
                    "Status: {}".format(sd["status"]),
                    "Started: {}".format(sd["started_at"]),
                    "Ended: {}".format(sd["ended_at"]),
                    "Requested duration: {}".format(sd["requested_duration_seconds"] or "until stopped"),
                    "Measured capture: {}s".format(sd["capture_duration_seconds"]),
                    "Queries observed: {}".format(_state.total_queries),
                    "Unique domains: {}".format(len(_state.seen_domains)),
                    "Flagged: {}".format(len(_state.flagged)),
                ]),
                ("Limitations", sd["limitations"] or ["None recorded"]),
                ("Top Queried Domains", [
                    "{}: {} queries".format(d, c)
                    for d, c in sorted(_state.query_count.items(), key=lambda x: x[1], reverse=True)[:25]
                ] or ["No domains observed"]),
                ("Domains With Indicators", [
                    "{} [{}]: {}".format(e["domain"], e["level"], "; ".join(e["reasons"]))
                    for e in _state.flagged[:25]
                ] or ["No indicators fired"]),
            ],
            pdf_path,
        )
        artifacts["pdf"] = pdf_path
        console.print("[green]PDF  ->[/green] [cyan]{}[/cyan]".format(pdf_path))
    except (OSError, ValueError, RuntimeError) as e:
        session.record_error("dns_pdf_report", e)
        console.print("[yellow]PDF report FAILED:[/yellow] {}".format(e))
