"""
PacketPulse — CLI Entry Point
Usage:
  packetpulse sniff       Deep packet capture (HTTP headers, DNS, GeoIP)
  packetpulse urlscan     Scan a specific URL  OR  watch live traffic
  packetpulse dns         Live DNS query monitor with threat flagging
  packetpulse forensics   Deep device profiling (USB + LAN)
  packetpulse start       Run sniff + urlscan + dns together
"""
from __future__ import annotations

import sys
import threading
from typing import Optional

import typer
from rich.console import Console
from rich import box

app = typer.Typer(
    name="packetpulse",
    help="Terminal-based cybersecurity monitoring platform",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()


def _banner() -> None:
    console.print("""
[bold green]██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗██████╗ ██╗   ██╗██╗     ███████╗███████╗[/bold green]
[bold green]██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██║   ██║██║     ██╔════╝██╔════╝[/bold green]
[bold green]██████╔╝███████║██║     █████╔╝ █████╗     ██║   ██████╔╝██║   ██║██║     ███████╗█████╗  [/bold green]
[bold green]██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  [/bold green]
[bold green]██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   ██║     ╚██████╔╝███████╗███████║███████╗[/bold green]
[bold green]╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝[/bold green]

[dim]           Terminal-based Cybersecurity Monitoring Platform  •  v1.0.0[/dim]
[dim]           ─────────────────────────────────────────────────────────[/dim]
""")


# ── sniff ─────────────────────────────────────────────────────────────────────

@app.command()
def sniff(
    interface: str = typer.Option(..., "-i", "--interface",
        help="Network interface to capture on (e.g. eth0, wlan0)."),
    filter: str = typer.Option("", "-f", "--filter",
        help="BPF filter expression (e.g. 'tcp port 80')"),
    count: int = typer.Option(0, "-c", "--count",
        help="Number of packets to capture (0 = unlimited)"),
    no_pcap: bool = typer.Option(False, "--no-pcap",
        help="Don't save PCAP file to disk"),
    no_geo: bool = typer.Option(False, "--no-geo",
        help="Disable GeoIP lookup for destination IPs"),
    no_http: bool = typer.Option(False, "--no-http",
        help="Disable HTTP request/response parsing"),
    no_dns: bool = typer.Option(False, "--no-dns",
        help="Disable DNS query parsing"),
):
    """
    [bold green]Deep packet capture[/bold green] with full L2/L3/L4/L7 analysis.

    Shows: source/dest IP, MAC, ports, TCP flags, seq/ack numbers,
    full HTTP headers, DNS queries, GeoIP of remote IPs, process attribution.
    """
    _check_root()
    from packetpulse.core.config import get_config
    cfg = get_config()
    if no_geo:
        cfg.sensor.show_geoip = False
    if no_http:
        cfg.sensor.show_http = False
    if no_dns:
        cfg.sensor.show_dns = False

    from packetpulse.sensor.sensor import run_sniffer
    run_sniffer(
        interface=interface,
        bpf_filter=filter,
        count=count,
        save_pcap=not no_pcap,
    )


# ── urlscan ───────────────────────────────────────────────────────────────────

@app.command()
def urlscan(
    url: Optional[str] = typer.Argument(None,
        help="URL to scan. If not given, watches live traffic instead."),
    live: bool = typer.Option(False, "--live", "-l",
        help="Watch live traffic and auto-scan every URL/domain seen."),
    interface: Optional[str] = typer.Option(None, "-i", "--interface",
        help="Interface for live mode"),
):
    """
    [bold green]URL threat scanner[/bold green] — scan a URL or watch live traffic.

    Single URL mode:  packetpulse urlscan https://example.com
      Runs 4 checks: URL structure · SSL/TLS · Reputation · Page content scan

    Live mode:  packetpulse urlscan --live
      Watches every HTTP request and DNS query your machine makes.
      Auto-scans every new URL/domain and alerts on threats.
    """
    if url:
        from packetpulse.urlscan.url_scanner import scan_url
        scan_url(url)
    else:
        if not interface:
            console.print("[red]Error: Interface is required for live mode. Use -i expected_interface[/red]")
            raise typer.Exit(code=1)

        _check_root()
        from packetpulse.urlscan.url_scanner import run_live_urlscan
        run_live_urlscan(interface=interface)


# ── dns ───────────────────────────────────────────────────────────────────────

@app.command()
def dns(
    interface: str = typer.Option(..., "-i", "--interface",
        help="Network interface to watch"),
):
    """
    [bold green]Live DNS query monitor[/bold green] — watch every domain lookup.

    Flags: DGA domains (malware C2) · High-risk TLDs · Suspicious keywords
           Beaconing patterns · Punycode homograph attacks · NXDOMAIN floods
    """
    _check_root()
    from packetpulse.dns.dns_monitor import run_dns_monitor
    run_dns_monitor(interface=interface)


# ── forensics ─────────────────────────────────────────────────────────────────

@app.command()
def forensics(
    subnet: Optional[str] = typer.Option(None, "--subnet", "-s",
        help="Subnet to scan e.g. 192.168.1.0/24"),
    no_nmap: bool = typer.Option(False, "--no-nmap",
        help="Skip active nmap scan (faster, less detail)"),
    usb_watch: bool = typer.Option(False, "--usb-watch",
        help="Watch USB connect/disconnect events in real time instead of scanning"),
):
    """
    [bold green]Deep device forensics[/bold green] — full profile of every connected device.

    USB devices: exact product name, serial number, manufacturer, VID/PID,
                 USB speed, power draw, device class, driver, filesystem data.

    LAN devices: MAC → manufacturer, TCP/IP OS fingerprint, hostname (mDNS/NetBIOS),
                 nmap port scan, open services, geolocation, active connections.
    """
    _check_root()
    if usb_watch:
        from packetpulse.forensics.forensics import run_usb_watch
        run_usb_watch()
    else:
        if not subnet:
            console.print("[red]Error: --subnet is required for forensics scan.[/red]")
            raise typer.Exit(code=1)
        from packetpulse.forensics.forensics import run_forensics
        run_forensics(subnet=subnet, no_nmap=no_nmap)


# ── start (full pipeline) ─────────────────────────────────────────────────────

@app.command()
def start(
    interface: str = typer.Option(..., "-i", "--interface",
        help="Network interface"),
):
    """
    [bold green]Run the full pipeline[/bold green] — sniff + urlscan + dns simultaneously.

    Launches all three modules in parallel threads and shows output
    from all of them in the same terminal.
    """
    _check_root()
    _banner()

    console.print("  [dim]Starting all modules...[/dim]\n")

    from packetpulse.core.config import get_config
    cfg = get_config()

    errors = []

    def _start_sniffer():
        try:
            from packetpulse.sensor.sensor import run_sniffer
            run_sniffer(interface=interface)
        except Exception as e:
            errors.append(f"Sniffer: {e}")

    def _start_urlscan():
        try:
            from packetpulse.urlscan.url_scanner import run_live_urlscan
            run_live_urlscan(interface=interface)
        except Exception as e:
            errors.append(f"URLScan: {e}")

    def _start_dns():
        try:
            from packetpulse.dns.dns_monitor import run_dns_monitor
            run_dns_monitor(interface=interface)
        except Exception as e:
            errors.append(f"DNS: {e}")
            
    # Launch threads
    tasks = [
        ("Sniffer", _start_sniffer),
        ("URLScan", _start_urlscan),
        ("DNS Monitor", _start_dns),
    ]

    threads = [
        threading.Thread(target=_start_sniffer, daemon=True, name="sniffer"),
        threading.Thread(target=_start_urlscan, daemon=True, name="urlscan"),
        threading.Thread(target=_start_dns, daemon=True, name="dns"),
    ]

    console.print("  [green][✓][/green] Packet sniffer       [dim](HTTP headers · DNS · GeoIP)[/dim]")
    console.print("  [green][✓][/green] Live URL scanner     [dim](structure · reputation · page content)[/dim]")
    console.print("  [green][✓][/green] DNS monitor          [dim](DGA · beaconing · suspicious domains)[/dim]")
    console.print(f"\n  [dim]Interface:[/dim] [green]{interface or 'auto-detect'}[/green]")
    console.print(f"  [dim]Output  →[/dim] [cyan]pcap_store/[/cyan]")
    console.print("\n[dim]  Press Ctrl+C to stop all modules.[/dim]")
    console.print("[dim]" + "─" * 100 + "[/dim]\n")

    for t in threads:
        t.start()

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        console.print("\n[green]All modules stopped.[/green]")
        for e in errors:
            console.print(f"[yellow]{e}[/yellow]")


# ── helpers ───────────────────────────────────────────────────────────────────

def _check_root() -> None:
    """Warn if not running as root (most features require it)."""
    import os
    if os.name == "posix" and os.geteuid() != 0:
        console.print(
            "[yellow]⚠  Warning: PacketPulse works best with root/sudo privileges.[/yellow]\n"
            "[dim]   Packet capture, ARP scan, and nmap require elevated permissions.[/dim]\n"
        )


if __name__ == "__main__":
    app()
