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
from typing import Optional


# ── GeoIP ─────────────────────────────────────────────────────────────────────

def geoip_lookup(ip: str, db_path: str = "") -> dict:
    """
    Return GeoIP data for an IP address.
    Uses geoip2 with a local MaxMind DB if available, else falls back
    to the free ip-api.com endpoint (no key required, rate-limited).
    """
    # Skip private / loopback ranges
    if is_private_ip(ip):
        return {"country": "LAN", "city": "Local", "lat": 0.0, "lon": 0.0, "org": "Private Network"}

    # Try local MaxMind DB first
    if db_path and Path(db_path).exists():
        try:
            import geoip2.database
            with geoip2.database.Reader(db_path) as reader:
                r = reader.city(ip)
                return {
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

    # Fallback: free ip-api.com
    try:
        import requests
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,org,isp",
                         timeout=3)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                return {
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

    return {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0, "org": ""}


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
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def now_str() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def timestamp_filename() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()[:8]
