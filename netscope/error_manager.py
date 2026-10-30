"""Error manager — captures, displays, and offers interactive recovery for errors."""

from __future__ import annotations

import asyncio
import time
import traceback
from dataclasses import dataclass, field


@dataclass
class ErrorRecord:
    """A single recorded error with full context."""
    timestamp: float = field(default_factory=time.time)
    agent: str = ""
    step: str = ""
    error_type: str = ""
    message: str = ""
    traceback_str: str = ""
    last_success: str = ""
    resolved: bool = False

    @property
    def time_str(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))

    def summary(self) -> str:
        lines = [
            "╔══════════════════════════════════════════════════╗",
            f"║  ERROR in [{self.agent}] at {self.time_str}",
            "╠══════════════════════════════════════════════════╣",
            f"║  Step: {self.step}",
            f"║  Type: {self.error_type}",
            f"║  Message: {self.message}",
        ]
        if self.last_success:
            lines.append(f"║  Last success: {self.last_success}")
        if self.traceback_str:
            lines.append("╠══════════════════════════════════════════════════╣")
            for tb_line in self.traceback_str.splitlines()[-6:]:
                lines.append(f"║  {tb_line}")
        lines.append("╠══════════════════════════════════════════════════╣")
        lines.append("║  [R] Retry  [D] Diagnostics  [Q] Quit")
        lines.append("╚══════════════════════════════════════════════════╝")
        return "\n".join(lines)


class ErrorManager:
    """Centralised error manager for all NETSCOPE agents.

    When an error is recorded it is pushed onto *error_queue* so the TUI
    can display it and stop processing until the user decides what to do.
    """

    def __init__(self) -> None:
        self.errors: list[ErrorRecord] = []
        self.error_queue: asyncio.Queue[ErrorRecord] = asyncio.Queue()

    async def record(
        self,
        agent: str,
        step: str,
        exc: BaseException | None = None,
        message: str = "",
        last_success: str = "",
        error_type: str | None = None,
    ) -> ErrorRecord:
        """Create an ErrorRecord and push it to the display queue."""
        resolved_type = error_type or (type(exc).__name__ if exc else "RuntimeError")
        rec = ErrorRecord(
            agent=agent,
            step=step,
            error_type=resolved_type,
            message=message or (str(exc) if exc else "Unknown error"),
            traceback_str=traceback.format_exc() if exc else "",
            last_success=last_success,
        )
        self.errors.append(rec)
        await self.error_queue.put(rec)
        return rec

    def record_sync(
        self,
        agent: str,
        step: str,
        exc: BaseException | None = None,
        message: str = "",
        last_success: str = "",
        error_type: str | None = None,
    ) -> ErrorRecord:
        """Synchronous version — adds to list but cannot push to async queue."""
        resolved_type = error_type or (type(exc).__name__ if exc else "RuntimeError")
        rec = ErrorRecord(
            agent=agent,
            step=step,
            error_type=resolved_type,
            message=message or (str(exc) if exc else "Unknown error"),
            traceback_str=traceback.format_exc() if exc else "",
            last_success=last_success,
        )
        self.errors.append(rec)
        return rec

    @property
    def has_errors(self) -> bool:
        return any(not e.resolved for e in self.errors)

    @property
    def unresolved(self) -> list[ErrorRecord]:
        return [e for e in self.errors if not e.resolved]

    def diagnostics(self) -> str:
        """Generate a diagnostics report string."""
        lines = [
            "═══ NETSCOPE DIAGNOSTICS ═══",
            f"Total errors recorded: {len(self.errors)}",
            f"Unresolved: {len(self.unresolved)}",
            "",
        ]
        for i, e in enumerate(self.errors, 1):
            status = "✖ OPEN" if not e.resolved else "✔ resolved"
            lines.append(f"  {i}. [{e.agent}] {e.step} — {e.message} ({status})")
        lines.append("")
        lines.append("── System info ──")
        import platform
        lines.append(f"  Python: {platform.python_version()}")
        lines.append(f"  OS: {platform.platform()}")
        try:
            import shutil
            tshark = shutil.which("tshark")
            lines.append(f"  TShark: {tshark or 'NOT FOUND'}")
        except Exception:
            lines.append("  TShark: check failed")
        try:
            import serial
            lines.append(f"  pyserial: {serial.VERSION}")
        except Exception:
            lines.append("  pyserial: NOT INSTALLED")
        return "\n".join(lines)
