"""
PacketPulse — Utility Helpers
"""
from __future__ import annotations
import math
import re
import socket
import json
import hashlib
from datetime import datetime
from pathlib import Path
from textwrap import wrap
from typing import Optional

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

GEOIP_CACHE_FILE = Path.home() / ".packetpulse" / "geoip_cache.json"
_geoip_cache: dict[str, dict] = {}


def _load_geoip_cache() -> None:
    global _geoip_cache
    try:
        if GEOIP_CACHE_FILE.exists():
            with GEOIP_CACHE_FILE.open("r", encoding="utf-8") as f:
                _geoip_cache = json.load(f)
    except Exception:
        _geoip_cache = {}


def _save_geoip_cache() -> None:
    try:
        GEOIP_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with GEOIP_CACHE_FILE.open("w", encoding="utf-8") as f:
            json.dump(_geoip_cache, f, indent=2)
    except Exception:
        pass


# Load persistent GeoIP cache at import.
_load_geoip_cache()


# ── GeoIP ─────────────────────────────────────────────────────────────────────

def geoip_lookup(ip: str, db_path: str = "") -> dict:
    """
    Return GeoIP data for an IP address.
    Uses geoip2 with a local MaxMind DB if available, else falls back
    to the free ip-api.com endpoint (no key required, rate-limited).
    Results are cached persistently across sessions.
    """
    if not ip or is_private_ip(ip):
        return {"country": "LAN", "city": "Local", "lat": 0.0, "lon": 0.0, "org": "Private Network", "source": "local"}

    if ip in _geoip_cache:
        return _geoip_cache[ip]

    result = {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0, "org": "", "source": "none"}

    if db_path and Path(db_path).exists():
        try:
            import geoip2.database
            with geoip2.database.Reader(db_path) as reader:
                r = reader.city(ip)
                result = {
                    "country": r.country.name or "Unknown",
                    "country_code": r.country.iso_code or "??",
                    "city": r.city.name or "Unknown",
                    "lat": float(r.location.latitude or 0),
                    "lon": float(r.location.longitude or 0),
                    "org": "",
                    "source": "maxmind",
                }
        except Exception:
            pass

    if result["source"] == "none":
        try:
            import requests
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,org,isp",
                timeout=3,
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    result = {
                        "country": d.get("country", "Unknown"),
                        "country_code": d.get("countryCode", "??"),
                        "city": d.get("city", "Unknown"),
                        "lat": d.get("lat", 0.0),
                        "lon": d.get("lon", 0.0),
                        "org": d.get("org", d.get("isp", "")),
                        "source": "ip-api",
                    }
        except Exception:
            pass

    _geoip_cache[ip] = result
    _save_geoip_cache()
    return result


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private/reserved range."""
    private = [
        r"^10\.", r"^172\.(1[6-9]|2[0-9]|3[01])\.",
        r"^192\.168\.", r"^127\.", r"^::1$", r"^fc", r"^fe80",
    ]
    return any(re.match(p, ip) for p in private)


def reverse_dns(ip: str) -> str:
    """Reverse DNS lookup with timeout."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ── String / Math ──────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (used for DGA detection)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def human_bytes(n: int) -> str:
    """Convert bytes to human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def truncate(s: str, length: int = 80) -> str:
    return s if len(s) <= length else s[:length - 3] + "..."


# ── File helpers ───────────────────────────────────────────────────────────────

def ensure_dir(path: str) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def save_json(data: dict, path: str) -> None:
    ensure_dir(str(Path(path).parent))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def save_ndjson(entries: list[dict], path: str) -> None:
    ensure_dir(str(Path(path).parent))
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, default=str) + "\n")


def save_report_pdf(title: str, subtitle: str, sections: list[tuple[str, list[str]]], path: str) -> str:
    if not REPORTLAB_OK:
        raise RuntimeError("reportlab is not installed. Install dependency 'reportlab'.")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(path, pagesize=letter)
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

    def _fill(color: tuple[float, float, float]):
        c.setFillColorRGB(*color)

    def _stroke(color: tuple[float, float, float]):
        c.setStrokeColorRGB(*color)

    def _footer(label: str = ""):
        _stroke(palette["line"])
        c.setLineWidth(0.7)
        c.line(margin, 22, width - margin, 22)
        _fill(palette["muted"])
        c.setFont("Helvetica", 8)
        c.drawString(margin, 10, f"{title} | {label}" if label else title)
        c.drawRightString(width - margin, 10, f"Page {page_no}")

    def _new_page(label: str = ""):
        nonlocal y, page_no
        _footer(label)
        c.showPage()
        page_no += 1
        y = height - margin

    def _title(text: str, sub: str = ""):
        nonlocal y
        _fill(palette["cyan"])
        c.setFont("Helvetica-Bold", 14)
        c.drawString(margin, y, text)
        y -= 16
        if sub:
            _fill(palette["muted"])
            c.setFont("Helvetica", 9)
            c.drawString(margin, y, sub)
            y -= 13
        _stroke(palette["line"])
        c.setLineWidth(0.7)
        c.line(margin, y, width - margin, y)
        y -= 12

    def _ensure_space(h: float, label: str = ""):
        nonlocal y
        if y - h < 42:
            _new_page(label)
            _fill(palette["bg"])
            c.rect(0, 0, width, height, stroke=0, fill=1)

    def _draw_wrapped(text: str, x: float, top: float, w_chars: int, size: int = 9, bullet: bool = False) -> float:
        yy = top
        c.setFont("Helvetica", size)
        _fill(palette["text"])
        lines = wrap(text, width=w_chars) or [""]
        for i, ln in enumerate(lines):
            prefix = "- " if bullet and i == 0 else "  " if bullet else ""
            c.drawString(x, yy, f"{prefix}{ln}")
            yy -= 12
        return yy

    def _card(x: float, top: float, w: float, h: float, k: str, v: str, accent: tuple[float, float, float]):
        _fill(palette["panel"])
        _stroke(palette["line"])
        c.setLineWidth(1)
        c.roundRect(x, top - h, w, h, 6, stroke=1, fill=1)
        _fill(palette["muted"])
        c.setFont("Helvetica", 8)
        c.drawString(x + 10, top - 16, k)
        _fill(accent)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(x + 10, top - 35, v[:30])

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Extract key/value lines from sections for dashboard cards.
    kv_pairs: list[tuple[str, str]] = []
    for heading, lines in sections:
        for line in lines:
            if ":" in line:
                left, right = line.split(":", 1)
                k = left.strip()
                v = right.strip()
                if k and v:
                    kv_pairs.append((k, v))
            if len(kv_pairs) >= 12:
                break
        if len(kv_pairs) >= 12:
            break

    verdict_candidates = [
        line for _, lines in sections for line in lines
        if "verdict" in line.lower() or "risk" in line.lower()
    ]
    final_verdict = verdict_candidates[0] if verdict_candidates else "No explicit risk/verdict line provided in this report."

    main_sections: list[tuple[str, list[str]]] = []
    appendix_sections: list[tuple[str, list[str]]] = []
    for heading, lines in sections:
        is_appendix = len(lines) > 40 or "log" in heading.lower()
        if is_appendix:
            appendix_sections.append((heading, lines))
        else:
            main_sections.append((heading, lines))

    # Cover page
    _fill(palette["bg"])
    c.rect(0, 0, width, height, stroke=0, fill=1)
    _fill(palette["cyan"])
    c.setFont("Helvetica-Bold", 28)
    c.drawCentredString(width / 2, height * 0.62, title)
    _fill(palette["muted"])
    c.setFont("Helvetica", 14)
    c.drawCentredString(width / 2, height * 0.57, subtitle)
    c.setFont("Helvetica", 10)
    c.drawCentredString(width / 2, height * 0.50, f"Generated: {ts}")
    _fill((0.08, 0.15, 0.26))
    _stroke(palette["green"])
    c.setLineWidth(1)
    c.roundRect((width / 2) - 130, (height * 0.46) - 10, 260, 22, 11, stroke=1, fill=1)
    _fill(palette["green"])
    c.setFont("Helvetica-Bold", 11)
    c.drawCentredString(width / 2, height * 0.46, "Generated by Dreamwalker4u")
    _fill(palette["muted"])
    c.setFont("Helvetica", 10)
    c.drawCentredString(width / 2, height * 0.43, "PacketPulse | Premium PDF Report")
    _new_page("Cover")

    # Dashboard page
    _fill(palette["bg"])
    c.rect(0, 0, width, height, stroke=0, fill=1)
    _title("Executive Dashboard", "High-level session metrics")
    cards = kv_pairs[:5] if kv_pairs else [("Report Time", ts), ("Sections", str(len(sections))), ("Summary", "Available")]
    accents = [palette["cyan"], palette["green"], palette["yellow"], palette["orange"], palette["muted"]]
    cw = (content_w - 16) / 2
    ch = 58
    cx = margin
    cy = y
    for idx, (k, v) in enumerate(cards):
        _card(cx, cy, cw, ch, k, v, accents[idx % len(accents)])
        if idx % 2 == 0:
            cx += cw + 16
        else:
            cx = margin
            cy -= ch + 12
    y = cy - 12
    _draw_wrapped(final_verdict, margin, y, 105, size=9)
    _new_page("Executive Dashboard")

    # Main sections
    _fill(palette["bg"])
    c.rect(0, 0, width, height, stroke=0, fill=1)
    for heading, lines in main_sections:
        _ensure_space(80, "Sections")
        _title(heading)
        if not lines:
            _fill(palette["muted"])
            c.setFont("Helvetica", 9)
            c.drawString(margin, y, "No entries")
            y -= 16
            continue
        for line in lines:
            _ensure_space(20, "Sections")
            y = _draw_wrapped(line, margin, y, 106, size=9, bullet=True)
            y -= 1
        y -= 8

    # Final verdict highlight
    _ensure_space(92, "Sections")
    _fill(palette["panel"])
    _stroke(palette["cyan"])
    c.setLineWidth(1.2)
    c.roundRect(margin, y - 78, content_w, 76, 8, stroke=1, fill=1)
    _fill(palette["cyan"])
    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin + 10, y - 18, "Final Verdict")
    y2 = _draw_wrapped(final_verdict, margin + 10, y - 34, 98, size=10)
    y = y2 - 12

    # Appendix pages
    if appendix_sections:
        _new_page("Main Sections")
        _fill(palette["bg"])
        c.rect(0, 0, width, height, stroke=0, fill=1)
        _title("Detailed Logs (Appendix)", "Large sections moved here for readability")
        c.setFont("Courier", 7)
        for heading, lines in appendix_sections:
            _ensure_space(36, "Appendix")
            _fill(palette["orange"])
            c.setFont("Helvetica-Bold", 10)
            c.drawString(margin, y, heading)
            y -= 14
            c.setFont("Courier", 7)
            for line in lines:
                wrapped = wrap(line, width=118) or [""]
                for ln in wrapped:
                    _ensure_space(10, "Appendix")
                    _fill(palette["text"])
                    c.drawString(margin, y, ln)
                    y -= 9
            y -= 8

    _footer("Report End")
    c.save()
    return path


def now_str() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def timestamp_filename() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()[:8]
