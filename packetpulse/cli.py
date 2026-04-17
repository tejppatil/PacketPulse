"""
PacketPulse — Interactive CLI
─────────────────────────────
Entry point: `packetpulse` or `sudo packetpulse`

Shows an interactive numbered menu. Each module walks the user
through its own prompts (interface, duration, URL, mode, etc.)
before running. After each module finishes, the user is returned
to the main menu.
"""
from __future__ import annotations

import os
import sys
import time
import signal
import threading
import subprocess
from datetime import datetime
from typing import Optional

# Allow `python cli.py` to work when executed from the package directory.
if __package__ is None or __package__ == "":
    _here = os.path.dirname(os.path.abspath(__file__))
    _repo_root = os.path.dirname(_here)
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)

# Force UTF-8 encoding for Windows compatibility
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

console = Console()
_INTRO_ANIM_PLAYED = False

# ── Colours / helpers ─────────────────────────────────────────────────────────

def _c(text: str, style: str) -> str:
    """Wrap text in rich markup."""
    return f"[{style}]{text}[/{style}]"

def _hr(char: str = "-", width: int = 72) -> str:
    return f"[dim]{char * width}[/dim]"

def _ask(prompt: str, default: str = "") -> str:
    """Print a styled prompt and read input."""
    hint = f" [dim](default: {default})[/dim]" if default else ""
    console.print(f"  [cyan]>[/cyan] {prompt}{hint}", end="")
    try:
        val = input("  ").strip()
    except (EOFError, KeyboardInterrupt):
        console.print()
        return default
    return val if val else default

def _ask_choice(prompt: str, choices: list[str], default: str = "") -> str:
    """Show numbered list and return chosen value."""
    console.print(f"\n  [dim]{prompt}[/dim]")
    for i, c in enumerate(choices, 1):
        marker = "[cyan]►[/cyan]" if c == default else " "
        console.print(f"    {marker} [bold]{i}[/bold]  {c}")
    console.print()
    while True:
        raw = _ask("Enter number", str(choices.index(default) + 1) if default in choices else "1")
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(choices):
                return choices[idx]
        except ValueError:
            pass
        console.print("  [yellow]  Invalid choice, try again.[/yellow]")

def _ask_yn(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    val = _ask(f"{prompt} [{hint}]")
    if not val:
        return default
    return val.lower().startswith("y")

def _check_root() -> bool:
    return os.name == "posix" and os.geteuid() == 0

def _root_warn() -> None:
    if not _check_root():
        console.print(
            "\n  [yellow]⚠  This module requires root/sudo.[/yellow]"
            "\n  [dim]  Rerun with: sudo packetpulse[/dim]\n"
        )

def _net_interfaces() -> list[str]:
    """Return available network interfaces."""
    try:
        import psutil
        ifaces = list(psutil.net_if_stats().keys())
        # filter loopback and virtual
        return [i for i in ifaces if not i.startswith("lo")] or ifaces
    except Exception:
        return ["eth0", "wlan0", "en0"]

def _ensure_dirs() -> None:
    for d in ["pcap_store", "pcap_store/urls", "pcap_store/dns", "pcap_store/forensics"]:
        os.makedirs(d, exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════════════════════

BANNER_ART = r"""
[bold bright_green]██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗██████╗ ██╗   ██╗██╗     ███████╗███████╗[/bold bright_green]
[bold bright_green]██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██║   ██║██║     ██╔════╝██╔════╝[/bold bright_green]
[bold bright_cyan]██████╔╝███████║██║     █████╔╝ █████╗     ██║   ██████╔╝██║   ██║██║     ███████╗█████╗  [/bold bright_cyan]
[bold bright_cyan]██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  [/bold bright_cyan]
[bold bright_green]██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   ██║     ╚██████╔╝███████╗███████║███████╗[/bold bright_green]
[bold bright_green]╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝[/bold bright_green]
"""


def _flow_line(width: int, phase: int, reverse: bool = False) -> str:
    chars = ["-"] * width
    offsets = (0, 11, 23, 37, 49, 58)
    for off in offsets:
        pos = (phase * 3 + off) % width
        if reverse:
            pos = (width - 1 - pos) % width
        chars[pos] = ">"
        if pos + 1 < width:
            chars[pos + 1] = "="
        if pos + 2 < width:
            chars[pos + 2] = "="
        if pos - 1 >= 0:
            chars[pos - 1] = "~"
    return "".join(chars)


def _render_banner_frame(phase: int) -> Panel:
    flow_a = _flow_line(62, phase, reverse=False)
    flow_b = _flow_line(62, phase + 7, reverse=True)
    return Panel(
        Text.from_markup(
            f"{BANNER_ART}\n"
            f"[bright_cyan]{flow_a}[/bright_cyan]\n"
            f"[bright_green]{flow_b}[/bright_green]\n"
            "[bold bright_green]:: TERMINAL CYBERSECURITY MONITORING PLATFORM ::[/bold bright_green]\n"
            "[bold bright_cyan]:: HACKER VIBE // BLUE TEAM POWER ::[/bold bright_cyan]\n"
            "[bright_cyan]made by Dreamwalker4u[/bright_cyan]\n"
            "[dim]Version 1.0.1  |  MIT License  |  Threat-Hunting Console[/dim]"
        ),
        box=box.DOUBLE,
        title="[bold bright_green] PACKETPULSE // NEON GRID [/bold bright_green]",
        title_align="left",
        border_style="bright_green",
        padding=(1, 2),
    )


def _play_intro_animation() -> None:
    for phase in range(16):
        os.system("clear" if os.name == "posix" else "cls")
        console.print(_render_banner_frame(phase))
        time.sleep(0.045)


def _print_banner() -> None:
    global _INTRO_ANIM_PLAYED
    os.system("clear" if os.name == "posix" else "cls")
    if not _INTRO_ANIM_PLAYED:
        _play_intro_animation()
        _INTRO_ANIM_PLAYED = True
        os.system("clear" if os.name == "posix" else "cls")

    console.print(_render_banner_frame(16))
    root_status = "[green]root [OK][/green]" if _check_root() else "[yellow]no root [WARN][/yellow]"
    ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    console.print(f"  [bold cyan]{ts}[/bold cyan]  [dim]|[/dim]  {root_status}")
    console.print()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN MENU
# ══════════════════════════════════════════════════════════════════════════════

MENU_ITEMS = [
    ("1", "Packet Sniffer",   "Deep capture - HTTP headers, DNS, GeoIP, process attribution"),
    ("2", "URL Scanner",      "Scan a URL or watch live traffic for malicious sites"),
    ("3", "DNS Monitor",      "Watch every DNS query - flag DGA domains, beaconing, bad TLDs"),
    ("4", "Device Forensics", "Profile USB devices and LAN devices in depth"),
    ("5", "Full Pipeline",    "Run Sniffer + URL Scanner + DNS Monitor simultaneously"),
    ("0", "Exit",             ""),
]


def _print_menu() -> None:
    console.print(_hr())
    console.print()
    t = Table(box=None, show_header=False, padding=(0, 2))
    t.add_column(width=4)
    t.add_column(width=22)
    t.add_column()
    for num, name, desc in MENU_ITEMS:
        if num == "0":
            t.add_row(f"[dim]{num}[/dim]", f"[dim]{name}[/dim]", "")
        else:
            t.add_row(
                f"[bold cyan]{num}[/bold cyan]",
                f"[bold white]{name}[/bold white]",
                f"[dim]{desc}[/dim]"
            )
    console.print(t)
    console.print()
    console.print(_hr())


def _main_menu_prompt() -> str:
    console.print(
        "\n  [bold green]PacketPulse[/bold green] [dim]>[/dim]"
        "  What do you want to do?  ",
        end=""
    )
    try:
        choice = input("").strip()
    except (EOFError, KeyboardInterrupt):
        console.print()
        return "0"
    return choice


# ══════════════════════════════════════════════════════════════════════════════
# MODULE  1 — PACKET SNIFFER
# ══════════════════════════════════════════════════════════════════════════════

def _module_sniffer() -> None:
    _root_warn()
    console.print()
    console.rule("[bold cyan]  PACKET SNIFFER  [/bold cyan]")
    console.print(
        "\n  Captures every packet with full detail across all layers:\n"
        "  [dim]MAC addresses · TCP flags · HTTP headers · DNS · GeoIP · process attribution[/dim]\n"
    )

    # ── interface ─────────────────────────────────────────────────────────────
    ifaces = _net_interfaces()
    if not ifaces:
        console.print("  [red]ERROR: No network interfaces found![/red]")
        _press_enter()
        return
    
    console.print("\n  [dim]Available network interfaces:[/dim]")
    iface = _ask_choice("Select interface", ifaces, ifaces[0] if ifaces else "")

    # ── BPF filter ────────────────────────────────────────────────────────────
    console.print(
        "\n  [dim]BPF filter examples:[/dim]\n"
        "    [dim]tcp port 80[/dim]          (HTTP only)\n"
        "    [dim]udp port 53[/dim]          (DNS only)\n"
        "    [dim]host 192.168.1.1[/dim]     (one device)\n"
        "    [dim]not port 443[/dim]         (exclude HTTPS)\n"
        "    [dim](leave blank to capture everything)[/dim]\n"
    )
    bpf = _ask("BPF filter", "")

    # ── duration ──────────────────────────────────────────────────────────────
    console.print(
        "\n  [dim]Duration examples:[/dim]  30s  •  5m  •  1h  •  0 = run until Ctrl+C"
    )
    dur_raw = _ask("How long to capture", "0")
    duration_secs = _parse_duration(dur_raw)

    # ── options ───────────────────────────────────────────────────────────────
    console.print()
    show_http = _ask_yn("Show full HTTP request/response headers?", True)
    show_dns  = _ask_yn("Show DNS query details?",                  True)
    show_geo  = _ask_yn("Show GeoIP for remote IPs?",               True)
    save_pcap = _ask_yn("Save raw packets to PCAP file?",           True)

    # ── confirm ───────────────────────────────────────────────────────────────
    console.print()
    console.print(_hr())
    console.print(f"  [dim]Interface :[/dim] [green]{iface}[/green]")
    console.print(f"  [dim]Filter    :[/dim] [yellow]{bpf or 'none (capture all)'}[/yellow]")
    dur_label = _fmt_duration(duration_secs)
    console.print(f"  [dim]Duration  :[/dim] [yellow]{dur_label}[/yellow]")
    console.print(f"  [dim]HTTP      :[/dim] {'[green]ON[/green]' if show_http else '[dim]OFF[/dim]'}")
    console.print(f"  [dim]DNS       :[/dim] {'[green]ON[/green]' if show_dns  else '[dim]OFF[/dim]'}")
    console.print(f"  [dim]GeoIP     :[/dim] {'[green]ON[/green]' if show_geo  else '[dim]OFF[/dim]'}")
    console.print(f"  [dim]Save PCAP :[/dim] {'[green]YES[/green]' if save_pcap else '[dim]NO[/dim]'}")
    console.print(_hr())

    if not _ask_yn("\n  Start capture?", True):
        return

    # ── run ───────────────────────────────────────────────────────────────────
    from packetpulse.core.config import get_config
    cfg = get_config()
    cfg.sensor.interface    = iface
    cfg.sensor.bpf_filter   = bpf
    cfg.sensor.show_http    = show_http
    cfg.sensor.show_dns     = show_dns
    cfg.sensor.show_geoip   = show_geo
    cfg.sensor.store_pcap   = save_pcap

    _ensure_dirs()
    console.print(
        f"\n  [bold green]Starting capture[/bold green]  [dim]on[/dim] [cyan]{iface}[/cyan]"
        + (f"  [dim]for[/dim] [yellow]{dur_label}[/yellow]" if duration_secs else "  [dim](Ctrl+C to stop)[/dim]")
    )
    console.print()

    from packetpulse.sensor.sensor import run_sniffer

    run_sniffer(
        interface=iface,
        bpf_filter=bpf,
        count=0,
        duration=duration_secs,
        save_pcap=save_pcap
    )

    _press_enter()


# ══════════════════════════════════════════════════════════════════════════════
# MODULE  2 — URL SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def _module_urlscan() -> None:
    console.print()
    console.rule("[bold cyan]  URL SCANNER  [/bold cyan]")
    console.print(
        "\n  Checks every URL for threats across 4 layers:\n"
        "  [dim]URL structure · SSL/TLS certificate · Reputation (VirusTotal/PhishTank) · Page content[/dim]\n"
    )

    mode = _ask_choice(
        "Choose mode:",
        ["Single URL  — paste a URL to scan it now",
         "Live watch  — auto-scan every URL your machine visits"],
        "Single URL  — paste a URL to scan it now"
    )

    if mode.startswith("Single"):
        # ── single URL mode ───────────────────────────────────────────────────
        console.print(
            "\n  [dim]Paste the full URL including http:// or https://[/dim]\n"
            "  [dim]Examples:[/dim]\n"
            "    [dim]https://free-prize-winner.top/claim?token=abc[/dim]\n"
            "    [dim]http://192.168.0.1/admin[/dim]\n"
        )
        url = _ask("URL to scan")
        if not url:
            console.print("  [yellow]No URL entered.[/yellow]")
            return

        if not url.startswith("http"):
            url = "http://" + url

        console.print()
        fetch_page = _ask_yn("Scan page content? (fetches the page, slower but thorough)", True)
        check_rep  = _ask_yn("Check reputation (VirusTotal, PhishTank, Safe Browsing)?", True)

        console.print()
        console.print(_hr())
        console.print(f"  [dim]URL         :[/dim] [cyan]{url}[/cyan]")
        console.print(f"  [dim]Page scan   :[/dim] {'[green]YES[/green]' if fetch_page else '[dim]NO[/dim]'}")
        console.print(f"  [dim]Reputation  :[/dim] {'[green]YES[/green]' if check_rep  else '[dim]NO[/dim]'}")
        console.print(_hr())

        if not _ask_yn("\n  Start scan?", True):
            return

        from packetpulse.core.config import get_config
        cfg = get_config()
        cfg.urlscan.fetch_page = fetch_page

        _ensure_dirs()
        console.print()
        from packetpulse.urlscan.url_scanner import scan_url
        scan_url(url)

    else:
        # ── live mode ─────────────────────────────────────────────────────────
        _root_warn()
        ifaces = _net_interfaces()
        if not ifaces:
            console.print("  [red]ERROR: No network interfaces found![/red]")
            _press_enter()
            return
        console.print(
            "\n  [dim]Live mode watches ALL traffic and automatically scans[/dim]\n"
            "  [dim]every URL or domain your machine visits.[/dim]\n"
        )
        iface = _ask_choice("Select network interface", ifaces, ifaces[0] if ifaces else "")

        dur_raw = _ask("How long to watch (e.g. 5m, 30m, 1h, 0 = until Ctrl+C)", "0")
        duration_secs = _parse_duration(dur_raw)
        dur_label = _fmt_duration(duration_secs)

        console.print()
        console.print(_hr())
        console.print(f"  [dim]Mode      :[/dim] [green]Live traffic watch[/green]")
        console.print(f"  [dim]Interface :[/dim] [green]{iface}[/green]")
        console.print(f"  [dim]Duration  :[/dim] [yellow]{dur_label}[/yellow]")
        console.print(_hr())

        if not _ask_yn("\n  Start live watch?", True):
            return

        _ensure_dirs()
        console.print(
            f"\n  [bold green]Live URL watcher started[/bold green]  [dim]on[/dim] [cyan]{iface}[/cyan]"
            + (f"  [dim]for[/dim] [yellow]{dur_label}[/yellow]" if duration_secs else "  [dim](Ctrl+C to stop)[/dim]")
        )
        console.print("  [dim]Browse normally — any suspicious URL will be flagged below.[/dim]\n")

        from packetpulse.urlscan.url_scanner import run_live_urlscan
        if duration_secs:
            t = threading.Thread(target=run_live_urlscan,
                                 kwargs={"interface": iface}, daemon=True)
            t.start()
            try:
                time.sleep(duration_secs)
            except KeyboardInterrupt:
                pass
            console.print(f"\n  [green]Live watch complete.[/green]  Duration: {dur_label}")
        else:
            run_live_urlscan(interface=iface)

    _press_enter()


# ══════════════════════════════════════════════════════════════════════════════
# MODULE  3 — DNS MONITOR
# ══════════════════════════════════════════════════════════════════════════════

def _module_dns() -> None:
    _root_warn()
    console.print()
    console.rule("[bold cyan]  DNS MONITOR  [/bold cyan]")
    console.print(
        "\n  Watches every DNS query your machine makes.\n"
        "  [dim]Flags: DGA / malware C2 domains  •  High-risk TLDs  •  Suspicious keywords  •  C2 beaconing[/dim]\n"
    )

    ifaces = _net_interfaces()
    if not ifaces:
        console.print("  [red]ERROR: No network interfaces found![/red]")
        _press_enter()
        return
    iface = _ask_choice("Select network interface", ifaces, ifaces[0] if ifaces else "")

    dur_raw = _ask("How long to monitor (e.g. 2m, 30m, 1h, 0 = until Ctrl+C)", "0")
    duration_secs = _parse_duration(dur_raw)
    dur_label = _fmt_duration(duration_secs)

    console.print()
    flag_dga      = _ask_yn("Flag DGA / high-entropy domains (malware C2 beacons)?", True)
    flag_keywords = _ask_yn("Flag suspicious keywords in domain names?",              True)
    flag_beacon   = _ask_yn("Flag beaconing (same domain queried 30+ times)?",        True)
    highlight_new = _ask_yn("Highlight newly seen domains?",                         True)
    save_results  = _ask_yn("Save flagged domains to pcap_store/dns/?",               True)

    console.print()
    console.print(_hr())
    console.print(f"  [dim]Interface :[/dim] [green]{iface}[/green]")
    console.print(f"  [dim]Duration  :[/dim] [yellow]{dur_label}[/yellow]")
    console.print(f"  [dim]DGA detect:[/dim] {'[green]ON[/green]' if flag_dga else '[dim]OFF[/dim]'}")
    console.print(f"  [dim]Keywords  :[/dim] {'[green]ON[/green]' if flag_keywords else '[dim]OFF[/dim]'}")
    console.print(f"  [dim]Beaconing :[/dim] {'[green]ON[/green]' if flag_beacon else '[dim]OFF[/dim]'}")
    console.print(f"  [dim]New doms  :[/dim] {'[green]ON[/green]' if highlight_new else '[dim]OFF[/dim]'}")
    console.print(f"  [dim]Save JSON :[/dim] {'[green]YES[/green]' if save_results else '[dim]NO[/dim]'}")
    console.print(_hr())

    if not _ask_yn("\n  Start DNS monitor?", True):
        return

    from packetpulse.core.config import get_config
    cfg = get_config()
    cfg.dns.flag_dga = flag_dga
    cfg.dns.flag_keywords = flag_keywords
    cfg.dns.flag_beacon = flag_beacon
    cfg.dns.flag_new_domains = highlight_new
    cfg.dns.save_results = save_results

    _ensure_dirs()
    console.print(
        f"\n  [bold green]DNS monitor started[/bold green]  [dim]on[/dim] [cyan]{iface}[/cyan]"
        + (f"  [dim]for[/dim] [yellow]{dur_label}[/yellow]" if duration_secs else "  [dim](Ctrl+C to stop)[/dim]")
    )
    console.print()

    from packetpulse.dns.dns_monitor import run_dns_monitor
    if duration_secs:
        t = threading.Thread(
            target=run_dns_monitor,
            kwargs={"interface": iface, "duration": duration_secs},
            daemon=True,
        )
        t.start()
        try:
            time.sleep(duration_secs)
        except KeyboardInterrupt:
            pass
        console.print(f"\n  [green]DNS monitor complete.[/green]  Duration: {dur_label}")
    else:
        run_dns_monitor(interface=iface)

    _press_enter()


# ══════════════════════════════════════════════════════════════════════════════
# MODULE  4 — DEVICE FORENSICS
# ══════════════════════════════════════════════════════════════════════════════

def _module_forensics() -> None:
    _root_warn()
    console.print()
    console.rule("[bold cyan]  DEVICE FORENSICS  [/bold cyan]")
    console.print(
        "\n  Profile every connected device in depth.\n"
        "  [dim]USB: product name · serial · VID/PID · power · driver · filesystem[/dim]\n"
        "  [dim]LAN: MAC vendor · OS fingerprint · hostname · open ports · services[/dim]\n"
    )

    scan_mode = _ask_choice(
        "What do you want to scan?",
        ["USB devices only         — profile USB devices plugged into this machine",
         "LAN devices only         — discover and profile all devices on the network",
         "Both USB + LAN           — full scan of everything",
         "USB live watch           — monitor USB plug/unplug events in real time"],
        "Both USB + LAN           — full scan of everything"
    )

    usb_enabled = "USB" in scan_mode or "Both" in scan_mode
    lan_enabled = "LAN" in scan_mode or "Both" in scan_mode
    usb_watch   = "live watch" in scan_mode

    subnet = ""
    nmap_enabled = False

    if lan_enabled:
        console.print(
            "\n  [dim]Subnet examples:[/dim]  192.168.1.0/24  •  10.0.0.0/24  •  (leave blank = auto-detect)[/dim]"
        )
        subnet = _ask("Subnet to scan", "")
        nmap_enabled = _ask_yn(
            "\n  Run active nmap scan? (finds open ports & services — takes longer, needs sudo)", True
        )

    if not usb_watch:
        save_json = _ask_yn("\nSave device profiles to pcap_store/forensics/?", True)

    console.print()
    console.print(_hr())
    if usb_watch:
        console.print("  [dim]Mode      :[/dim] [green]USB live event monitor[/green]")
    else:
        console.print(f"  [dim]USB scan  :[/dim] {'[green]YES[/green]' if usb_enabled else '[dim]NO[/dim]'}")
        console.print(f"  [dim]LAN scan  :[/dim] {'[green]YES[/green]' if lan_enabled else '[dim]NO[/dim]'}")
        if lan_enabled:
            console.print(f"  [dim]Subnet    :[/dim] [cyan]{subnet or 'auto-detect'}[/cyan]")
            console.print(f"  [dim]nmap      :[/dim] {'[green]active scan[/green]' if nmap_enabled else '[dim]passive only[/dim]'}")
    console.print(_hr())

    if not _ask_yn("\n  Start forensics?", True):
        return

    from packetpulse.core.config import get_config
    cfg = get_config()
    cfg.forensics.usb_enabled  = usb_enabled
    cfg.forensics.lan_enabled  = lan_enabled
    cfg.forensics.nmap_enabled = nmap_enabled

    _ensure_dirs()
    console.print()

    from packetpulse.forensics.forensics import run_forensics, run_usb_watch
    if usb_watch:
        run_usb_watch()
    else:
        run_forensics(subnet=subnet or None, no_nmap=not nmap_enabled)

    _press_enter()


# ══════════════════════════════════════════════════════════════════════════════
# MODULE  5 — FULL PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def _module_pipeline() -> None:
    _root_warn()
    console.print()
    console.rule("[bold cyan]  FULL PIPELINE  [/bold cyan]")
    console.print(
        "\n  Runs Packet Sniffer + URL Scanner + DNS Monitor simultaneously.\n"
        "  [dim]All three modules run in parallel threads, output streams to this terminal.[/dim]\n"
    )

    ifaces = _net_interfaces()
    console.print("  [dim]Available interfaces:[/dim]  " +
                  "  ".join(f"[cyan]{i}[/cyan]" for i in ifaces))
    iface = _ask("Network interface (used by all modules)", ifaces[0] if ifaces else "eth0")

    dur_raw = _ask("\nHow long to run (e.g. 10m, 1h, 0 = until Ctrl+C)", "0")
    duration_secs = _parse_duration(dur_raw)
    dur_label = _fmt_duration(duration_secs)

    console.print()
    en_sniff = _ask_yn("Enable Packet Sniffer?",  True)
    en_url   = _ask_yn("Enable URL Scanner?",     True)
    en_dns   = _ask_yn("Enable DNS Monitor?",     True)

    console.print()
    console.print(_hr())
    console.print(f"  [dim]Interface     :[/dim] [green]{iface}[/green]")
    console.print(f"  [dim]Duration      :[/dim] [yellow]{dur_label}[/yellow]")
    console.print(f"  [dim]Pkt Sniffer   :[/dim] {'[green]ON[/green]' if en_sniff else '[dim]OFF[/dim]'}")
    console.print(f"  [dim]URL Scanner   :[/dim] {'[green]ON[/green]' if en_url   else '[dim]OFF[/dim]'}")
    console.print(f"  [dim]DNS Monitor   :[/dim] {'[green]ON[/green]' if en_dns   else '[dim]OFF[/dim]'}")
    console.print(_hr())

    if not _ask_yn("\n  Launch full pipeline?", True):
        return

    _ensure_dirs()
    threads = []
    errors  = []

    def _run(target, kwargs):
        try:
            target(**kwargs)
        except Exception as e:
            errors.append(str(e))

    if en_sniff:
        from packetpulse.sensor.sensor import run_sniffer
        threads.append(threading.Thread(
            target=_run, args=(run_sniffer, {"interface": iface}), daemon=True
        ))
    if en_url:
        from packetpulse.urlscan.url_scanner import run_live_urlscan
        threads.append(threading.Thread(
            target=_run, args=(run_live_urlscan, {"interface": iface}), daemon=True
        ))
    if en_dns:
        from packetpulse.dns.dns_monitor import run_dns_monitor
        threads.append(threading.Thread(
            target=_run, args=(run_dns_monitor, {"interface": iface, "duration": duration_secs}), daemon=True
        ))

    if not threads:
        console.print("  [yellow]No modules selected.[/yellow]")
        return

    for t in threads:
        t.start()

    active = ([" [green]Sniffer[/green]"    if en_sniff else ""] +
              [" [green]URLScan[/green]"    if en_url   else ""] +
              [" [green]DNS Monitor[/green]"if en_dns   else ""])
    console.print(
        f"\n  [bold green]Pipeline running:[/bold green]"
        + "  ".join(active)
        + (f"\n  [dim]Duration:[/dim] [yellow]{dur_label}[/yellow]" if duration_secs else "\n  [dim]Press Ctrl+C to stop all modules.[/dim]")
    )
    console.print()

    try:
        if duration_secs:
            time.sleep(duration_secs)
        else:
            for t in threads:
                t.join()
    except KeyboardInterrupt:
        pass

    console.print(f"\n  [green]Pipeline stopped.[/green]  Duration: {dur_label}")
    if errors:
        for e in errors:
            console.print(f"  [yellow]Error: {e}[/yellow]")

    _press_enter()


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _parse_duration(raw: str) -> int:
    """Parse '30s', '5m', '1h' → seconds. '0' or '' → 0 (unlimited)."""
    raw = raw.strip().lower()
    if not raw or raw == "0":
        return 0
    try:
        if raw.endswith("h"):
            return int(raw[:-1]) * 3600
        if raw.endswith("m"):
            return int(raw[:-1]) * 60
        if raw.endswith("s"):
            return int(raw[:-1])
        return int(raw)
    except ValueError:
        return 0


def _fmt_duration(secs: int) -> str:
    if secs == 0:
        return "unlimited (Ctrl+C to stop)"
    if secs >= 3600:
        return f"{secs // 3600}h {(secs % 3600) // 60}m"
    if secs >= 60:
        return f"{secs // 60}m {secs % 60}s"
    return f"{secs}s"


def _press_enter() -> None:
    console.print()
    console.print("  [dim]Press Enter to return to the main menu...[/dim]", end="")
    try:
        input("")
    except (EOFError, KeyboardInterrupt):
        pass


# ══════════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    while True:
        _print_banner()
        _print_menu()
        choice = _main_menu_prompt()

        if choice == "1":
            _module_sniffer()
        elif choice == "2":
            _module_urlscan()
        elif choice == "3":
            _module_dns()
        elif choice == "4":
            _module_forensics()
        elif choice == "5":
            _module_pipeline()
        elif choice == "0":
            console.print("\n  [dim]Goodbye.[/dim]\n")
            sys.exit(0)
        else:
            console.print(
                f"\n  [yellow]'{choice}' is not a valid option.[/yellow]"
                "  [dim]Enter a number from the menu.[/dim]"
            )
            time.sleep(1)


if __name__ == "__main__":
    main()
