"""
PacketPulse — Logger
"""
from __future__ import annotations
import logging
import sys
from rich.logging import RichHandler
from rich.console import Console


def _init_stream_encoding() -> None:
    """Ensure the terminal can render the box-drawing characters the UI uses.

    On Windows the default console codepage is cp1252, which raises
    UnicodeEncodeError on the report banners. Reconfiguring here (rather than
    only in cli.py) means any entry point into the package is safe.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            # Not a reconfigurable stream (redirected/captured); Rich will fall
            # back to ASCII-safe output via the console below.
            pass


_init_stream_encoding()

# Shared console. legacy_windows=False avoids the cp1252 win32 render path.
console = Console(soft_wrap=False)


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = RichHandler(
        console=console,
        show_path=False,
        show_time=True,
        rich_tracebacks=True,
        markup=True,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger
