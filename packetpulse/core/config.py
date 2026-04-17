"""
PacketPulse — Core Configuration
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class SensorConfig:
    interface: Optional[str] = None
    bpf_filter: str = ""
    store_pcap: bool = True
    pcap_store_path: str = "pcap_store"
    show_geoip: bool = True
    show_http: bool = True
    show_dns: bool = True
    geoip_db: str = ""          # path to GeoLite2-City.mmdb


@dataclass
class URLScanConfig:
    enabled: bool = True
    fetch_page: bool = True
    virustotal_api_key: str = ""
    google_safebrowsing_key: str = ""
    results_path: str = "pcap_store/urls"
    request_timeout: int = 10
    # Rate limiting (VirusTotal free = 4 requests/min)
    vt_rate_limit: int = 4          # max requests per minute
    vt_request_count: int = 0       # current request count
    vt_last_reset: float = 0.0      # timestamp of last reset
    gsb_rate_limit: int = 100       # Google Safe Browsing free = 100/day
    suspicious_tlds: list = field(default_factory=lambda: [
        ".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".top", ".xyz", ".win", ".loan", ".click", ".download",
        ".stream", ".racing", ".review", ".party", ".science",
    ])
    suspicious_keywords: list = field(default_factory=lambda: [
        "free", "winner", "claim", "prize", "urgent", "verify",
        "login", "secure", "update", "confirm", "account",
        "suspended", "alert", "warning", "invoice", "paypal",
        "amazon", "microsoft", "apple", "google", "facebook",
    ])
    cache_enabled: bool = True
    cache_path: str = "pcap_store/urls/cache.json"


@dataclass
class DNSConfig:
    enabled: bool = True
    results_path: str = "pcap_store/dns"
    flag_new_domains: bool = True
    flag_dga: bool = True          # Domain Generation Algorithm detection
    flag_keywords: bool = True
    flag_beacon: bool = True
    save_results: bool = True
    max_domain_length: int = 60
    beacon_warning_threshold: int = 15
    beacon_malicious_threshold: int = 30
    dga_entropy_threshold: float = 3.5


@dataclass
class ForensicsConfig:
    usb_enabled: bool = True
    lan_enabled: bool = True
    nmap_enabled: bool = True      # active port scan (needs sudo)
    results_path: str = "pcap_store/forensics"
    geoip_db: str = ""


@dataclass
class PacketPulseConfig:
    sensor: SensorConfig = field(default_factory=SensorConfig)
    urlscan: URLScanConfig = field(default_factory=URLScanConfig)
    dns: DNSConfig = field(default_factory=DNSConfig)
    forensics: ForensicsConfig = field(default_factory=ForensicsConfig)
    log_level: str = "INFO"
    log_file: str = "packetpulse.log"


# Global config singleton
_config: Optional[PacketPulseConfig] = None


def get_config() -> PacketPulseConfig:
    global _config
    if _config is None:
        _config = PacketPulseConfig()
        # Load optional API keys from environment only.
        vt = os.environ.get("PACKETPULSE_VT_KEY", "")
        gsb = os.environ.get("PACKETPULSE_GSB_KEY", "")
        geoip = os.environ.get("PACKETPULSE_GEOIP_DB", "")
        if vt:
            _config.urlscan.virustotal_api_key = vt
        if gsb:
            _config.urlscan.google_safebrowsing_key = gsb
        if geoip:
            _config.sensor.geoip_db = geoip
            _config.forensics.geoip_db = geoip
    return _config
