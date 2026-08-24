"""
PacketPulse — Session lifecycle and stop control.

Every long-running module owns exactly one Session for the duration of a run.
The Session carries the honest record of what happened: when it really started
and stopped, what was counted, what failed, and what was not available.

Nothing in this module invents data. Counters start at zero and are only ever
incremented by observed events.
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def utc_now() -> datetime:
    """Timezone-aware UTC now. Replaces the deprecated datetime.utcnow()."""
    return datetime.now(timezone.utc)


def iso(dt: Optional[datetime]) -> str:
    return dt.isoformat(timespec="milliseconds") if dt else ""


class StopController:
    """Cooperative stop signal shared by a module and its worker threads.

    Modules must poll `is_set()` or pass `scapy_stop_filter` to sniff().
    A module must never rely on daemon threads to terminate its work.
    """

    def __init__(self) -> None:
        self._event = threading.Event()

    def stop(self) -> None:
        self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: Optional[float] = None) -> bool:
        """Block until stop is requested or timeout elapses. Returns True if stopped."""
        return self._event.wait(timeout)

    def scapy_stop_filter(self, _pkt: Any = None) -> bool:
        """Usable directly as scapy's stop_filter callback."""
        return self._event.is_set()


@dataclass
class Session:
    """The factual record of one module run."""

    module: str
    requested_duration: int = 0          # seconds; 0 == until stopped
    interface: str = ""
    bpf_filter: str = ""

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: datetime = field(default_factory=utc_now)
    ended_at: Optional[datetime] = None

    # The capture window proper. Post-processing (draining queues, resolving
    # metadata, writing reports) happens after capture_ended_at, so honouring
    # a requested duration is judged against THIS window, not total runtime.
    capture_started_at: Optional[datetime] = None
    capture_ended_at: Optional[datetime] = None

    counters: dict[str, int] = field(default_factory=dict)
    errors: list[dict] = field(default_factory=list)
    unavailable: list[dict] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    # completed == the capture ran to its intended end (timer or user stop)
    # rather than aborting on an error.
    completed: bool = False
    abort_reason: str = ""

    # ── lifecycle ────────────────────────────────────────────────────────────

    def begin_capture(self) -> None:
        self.capture_started_at = utc_now()

    def end_capture(self) -> None:
        if self.capture_ended_at is None:
            self.capture_ended_at = utc_now()

    @property
    def capture_duration(self) -> float:
        """Measured seconds of actual capture, from timestamps."""
        if not self.capture_started_at:
            return 0.0
        end = self.capture_ended_at or utc_now()
        return max((end - self.capture_started_at).total_seconds(), 0.0)

    def finish(self, completed: bool = True, abort_reason: str = "") -> None:
        if self.ended_at is None:
            self.ended_at = utc_now()
        self.completed = completed
        if abort_reason:
            self.abort_reason = abort_reason

    @property
    def actual_duration(self) -> float:
        """Measured wall-clock seconds, derived from timestamps — never echoed
        back from the requested duration."""
        end = self.ended_at or utc_now()
        return max((end - self.started_at).total_seconds(), 0.0)

    # ── recording ────────────────────────────────────────────────────────────

    def count(self, key: str, n: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + n

    def get(self, key: str) -> int:
        return self.counters.get(key, 0)

    def record_error(self, where: str, exc: BaseException | str) -> None:
        """Record a real failure. Errors are surfaced in reports, never swallowed."""
        if isinstance(exc, BaseException):
            detail = f"{type(exc).__name__}: {exc}"
        else:
            detail = str(exc)
        self.errors.append({"where": where, "error": detail[:400], "at": iso(utc_now())})

    def record_unavailable(self, feature: str, reason: str) -> None:
        """Record a feature that could not run. This is how the tool says
        UNAVAILABLE instead of producing an empty successful-looking section."""
        if not any(u["feature"] == feature for u in self.unavailable):
            self.unavailable.append({"feature": feature, "reason": reason})

    def note_limitation(self, text: str) -> None:
        if text not in self.limitations:
            self.limitations.append(text)

    # ── status ───────────────────────────────────────────────────────────────

    def status(self) -> str:
        """PASS / PARTIAL / FAIL, derived from what actually happened."""
        if not self.completed:
            return "FAIL"
        if self.errors or self.unavailable:
            return "PARTIAL"
        return "PASS"

    def duration_honored(self, tolerance: float = 3.0) -> Optional[bool]:
        """True if the measured CAPTURE window matches what was asked for.

        Judged against capture_duration, not total runtime: report generation
        legitimately takes time after capture has stopped.
        None when the run was open-ended (nothing to honor).
        """
        if not self.requested_duration:
            return None
        measured = self.capture_duration or self.actual_duration
        return abs(measured - self.requested_duration) <= tolerance

    def to_dict(self) -> dict:
        honored = self.duration_honored()
        return {
            "session_id": self.session_id,
            "module": self.module,
            "status": self.status(),
            "started_at": iso(self.started_at),
            "ended_at": iso(self.ended_at),
            "requested_duration_seconds": self.requested_duration or None,
            "actual_duration_seconds": round(self.actual_duration, 3),
            "capture_started_at": iso(self.capture_started_at),
            "capture_ended_at": iso(self.capture_ended_at),
            "capture_duration_seconds": round(self.capture_duration, 3),
            "duration_honored": honored,
            "interface": self.interface or "NOT SPECIFIED",
            "bpf_filter": self.bpf_filter or "none",
            "completed": self.completed,
            "abort_reason": self.abort_reason or None,
            "counters": dict(self.counters),
            "errors": list(self.errors),
            "unavailable_features": list(self.unavailable),
            "limitations": list(self.limitations),
        }

    def summary_line(self) -> str:
        """One-line honest outcome for the terminal."""
        if not self.completed:
            return f"INCOMPLETE — {self.abort_reason or 'capture did not finish'}"
        parts = [f"{k}={v}" for k, v in sorted(self.counters.items()) if v]
        return (
            f"{self.status()} | capture {self.capture_duration:.1f}s"
            f" | total {self.actual_duration:.1f}s"
            + (f" | {' '.join(parts)}" if parts else " | nothing observed")
        )
