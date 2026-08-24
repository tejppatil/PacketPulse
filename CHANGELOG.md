# Changelog

All notable changes to PacketPulse are recorded here.

This project follows [Semantic Versioning](https://semver.org/).

---

## [2.0.0] — 2026-08-24

A correctness and honesty rebuild. Every pipeline now reports only what it
actually observed, and says `UNKNOWN`, `NOT OBSERVED` or `UNAVAILABLE` with a
reason when it cannot determine something.

Verified on Windows 11 (Python 3.12, Npcap) and Ubuntu 26.04
(Python 3.14, psutil 7.2.2, scapy 2.7.0, pyudev 0.24.4).

### Breaking

- **Report JSON schema changed.** Reports now carry a `session` block
  (id, start, end, requested vs measured duration, counters, errors,
  unavailable features, limitations). Anything parsing 1.x reports will need
  updating.
- **Confidence percentages removed.** `intel.confidence` no longer exists.
  Packet observations now carry `signal` (`STRONG`/`MODERATE`/`WEAK`/`NONE`),
  a `score`, and an `evidence` list where the score is the sum of the listed
  indicator weights.
- **`risk` replaced by `signal`** throughout findings and reports.
- **Module entry points changed signature.** `run_sniffer`, `run_dns_monitor`,
  `run_live_urlscan`, `scan_url` and `run_forensics` now accept `stop=` /
  `session=` and return a `Session` object.
- **External reputation and online GeoIP are off by default.** Previously live
  mode sent every observed URL to VirusTotal, Google Safe Browsing and
  PhishTank without asking.
- **`psutil>=6.0.0` is now required.**

### Security

- Fixed path traversal: DNS names and USB serial numbers reached filenames
  directly, so a crafted name could write outside the results directory as
  root. Untrusted names are now slugged, hashed and containment-checked.
- Fixed command injection: captured URLs were interpolated into a PowerShell
  `-Command` string and an AppleScript literal. Notification text is now
  sanitised and never reaches a shell.
- Fixed HTML injection: captured values (Host headers, User-Agents, DNS names)
  went unescaped into generated reports. All report values are now escaped.
- Certificate verification is no longer disabled when fetching pages, and
  responses are capped at 2 MB.
- Rich markup in captured data is escaped before display.
- Replaced 30 bare `except:` clauses, which were swallowing `KeyboardInterrupt`
  and defeating Ctrl+C.

### Added

- `core/session.py` — session lifecycle, stop control, and the honest record
  of each run (status, measured duration, counters, errors, limitations).
- `core/capabilities.py` — runtime capability probing. Reports what this host
  can do and why anything is unavailable, using native OS calls.
- `core/scapy_compat.py` — detects the scapy 2.6+ `KeyError: 'scope'` failure
  on kernels that omit the rtnetlink scope field, and works around it via
  scapy's own `conf.route6_autoload` switch rather than failing to start.
- Capabilities view (menu option 6) showing per-module support for this host.
- Route-aware interface selection. The platform default is often not the
  interface carrying internet traffic on a host with a VPN adapter.
- Test suite: 127 tests covering parsers, heuristics, lifecycle, capabilities,
  Linux-only paths, and security regressions.
- CI now runs lint and tests on Python 3.11 and 3.12, and verifies the built
  wheel installs and runs in a clean environment, before publishing.

### Fixed

- PCAP output was silently truncated at 8,000 packets. It is now streamed to
  disk, complete, and its frame count is verified against the session counter
  after capture.
- Durations were not honoured: `stop_filter` only ran when a packet arrived, so
  a timed capture never ended on a quiet interface.
- Live URL watch and the full pipeline had no stop mechanism; threads kept
  capturing after the UI reported completion.
- DNS monitor state was never reset between runs, so a second run inherited the
  first run's query counts and beacon thresholds.
- Process attribution matched on *either* port, so any HTTPS packet could be
  attributed to an unrelated process. Now requires an exact socket four-tuple;
  anything less reports `UNKNOWN` or is labelled `INFERRED` with its basis.
- Browser socket enumeration raised `ValueError` on psutil ≥ 6 and was silently
  swallowed, so that URL source never worked.
- `Process.connections()` (removed in psutil 7) replaced with
  `net_connections()`.
- Substring keyword matching flagged legitimate domains — `bankofamerica.com`
  as brand impersonation, `api.crypto.com` as malware. Now matches whole tokens.
- URL verdict ignored the risk score entirely, making `CLEAN` unreachable.
- VirusTotal was polled one second after submission and usually returned
  nothing; it now reads the URL report endpoint and no longer submits URLs.
- Rate limiting and the result cache were configured but never implemented.
- USB filesystem detail probed the USB control endpoint
  (`/dev/bus/usb/...`), which carries no filesystem; it now reads the device's
  block children.
- `is_private_ip` missed `fd00::/8`, link-local, multicast and CGNAT ranges.
- GeoIP failures were cached permanently as facts.
- `reverse_dns` had no timeout despite documenting one.
- PDF reports rendered near-white text on unpainted pages after an overflow,
  and crashed on a zero-extent pie wedge when traffic ran one direction only.
- Capture engine start reduced from ~123 s to ~2 s by importing only the scapy
  layers actually used, with a verified fallback to the full import when the
  fast path cannot resolve the chosen interface.
- An auto-detected interface that the capture backend cannot open now falls
  back to the platform default instead of aborting; an interface named
  explicitly by the user still aborts rather than capturing elsewhere.
- Windows console encoding no longer raises `UnicodeEncodeError` on the report
  banners.
- 21 deprecated `datetime.utcnow()` calls replaced with timezone-aware
  equivalents; certificate expiry is now compared aware-to-aware.

### Changed

- "Beaconing" is only reported when inter-query intervals are measurably
  regular (coefficient of variation). High query volume alone is reported as
  "High Query Frequency" with its interval statistics.
- DGA detection combines entropy, bigram frequency, vowel ratio and digit
  ratio, and requires three or more indicators before calling a name suspicious.
- OS fingerprinting is labelled a heuristic with its evidence, never an
  identification.
- Every external tool reports its own status, so a blank field is explained
  rather than merely blank.
- README rewritten with per-platform startup instructions and verified
  limitation tables.
- Version is now single-sourced from `packetpulse.__version__`.

---

## [1.0.2] — 2026-04-17

- Release packaging and build metadata.

## [1.0.1]

- Initial public release.
