"""
PacketPulse — scapy import compatibility.

scapy builds its IPv6 routing table at import time. On kernels whose rtnetlink
does not report a ``scope`` key for an address, scapy 2.6 and later raise
``KeyError: 'scope'`` while doing so — and because it happens during the layer
import, the whole application fails to start rather than reporting a problem.

Observed on WSL2 (kernel 4.4.0-26100-Microsoft, Ubuntu 26.04):

    scapy 2.5.0  layers import OK
    scapy 2.6.1  KeyError: 'scope'
    scapy 2.7.0  KeyError: 'scope'

``conf.route6_autoload`` is scapy's own supported switch for skipping that
table, so this module probes for the failure and disables the autoload only
when it is actually needed. Nothing is monkeypatched, the workaround is
recorded, and PacketPulse reports the resulting limitation instead of quietly
behaving differently.

Import this module and call :func:`prepare_scapy` BEFORE importing any scapy
layer module.
"""
from __future__ import annotations

from typing import Optional

# Populated by prepare_scapy(); read by modules for their session limitations.
COMPAT_NOTE: Optional[str] = None
IMPORT_ERROR: Optional[str] = None

_prepared = False


def prepare_scapy() -> Optional[str]:
    """Make scapy's layer modules importable on this host.

    Returns a note describing any workaround applied, or None when scapy
    imports cleanly. Never raises: a scapy that cannot be made to work is
    reported through :data:`IMPORT_ERROR` so callers can surface UNAVAILABLE.
    """
    global _prepared, COMPAT_NOTE, IMPORT_ERROR
    if _prepared:
        return COMPAT_NOTE
    _prepared = True

    try:
        from scapy.config import conf
    except Exception as e:  # scapy missing or fundamentally broken
        IMPORT_ERROR = f"scapy is unavailable ({type(e).__name__}: {e})"
        return None

    try:
        import scapy.layers.inet  # noqa: F401
        return None                      # imports cleanly; nothing to do
    except KeyError as e:
        if "scope" not in str(e):
            IMPORT_ERROR = f"scapy layer import failed (KeyError: {e})"
            return None
    except Exception as e:
        IMPORT_ERROR = f"scapy layer import failed ({type(e).__name__}: {e})"
        return None

    # Retry with the IPv6 route table switched off.
    try:
        conf.route6_autoload = False
        import scapy.layers.inet  # noqa: F401

        COMPAT_NOTE = (
            "scapy could not read this kernel's IPv6 route table "
            "(KeyError: 'scope', a known scapy 2.6+ issue on kernels that omit "
            "the rtnetlink scope field). IPv6 route autoload was disabled to "
            "allow capture to proceed; IPv6 packets are still decoded, but "
            "scapy cannot choose an IPv6 source address for sending."
        )
        return COMPAT_NOTE
    except Exception as e:
        IMPORT_ERROR = (
            f"scapy cannot initialise on this kernel ({type(e).__name__}: {e}). "
            "Known workaround: pip install 'scapy==2.5.0'."
        )
        return None


def status() -> dict:
    """Machine-readable compatibility state for reports."""
    return {
        "workaround_applied": COMPAT_NOTE is not None,
        "note": COMPAT_NOTE,
        "import_error": IMPORT_ERROR,
    }
