"""Data models for NETSCOPE events."""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


class Source(str, enum.Enum):
    """Event source identifier."""
    PC = "PC"
    ESP32 = "ESP32"
    TSHARK = "TSHARK"
    SYSTEM = "SYSTEM"


class AlertLevel(str, enum.Enum):
    """Severity / visual priority of an event."""
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class NetEvent:
    """A single human-readable network event."""

    source: Source
    who: str
    where: str
    what: str
    alert_level: AlertLevel = AlertLevel.INFO
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    raw_data: dict[str, Any] = field(default_factory=dict)



    @property
    def time_str(self) -> str:
        """HH:MM:SS formatted timestamp."""
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))

    @property
    def source_label(self) -> str:
        """Colored Rich markup label for the source."""
        color_map = {
            Source.PC: "bright_cyan",
            Source.ESP32: "bright_magenta",
            Source.TSHARK: "bright_green",
            Source.SYSTEM: "bright_yellow",
        }
        color = color_map.get(self.source, "white")
        return f"[{color}][{self.source.value}][/{color}]"

    @property
    def alert_icon(self) -> str:
        icons = {
            AlertLevel.INFO: "[*]",
            AlertLevel.NOTICE: "[+]",
            AlertLevel.WARNING: "[!]",
            AlertLevel.ERROR: "[X]",
            AlertLevel.CRITICAL: "[!]",
        }
        return icons.get(self.alert_level, " ")

    def one_line(self) -> str:
        """Rich-markup single-line representation for the TUI."""
        alert_colors = {
            AlertLevel.INFO: "white",
            AlertLevel.NOTICE: "bright_blue",
            AlertLevel.WARNING: "yellow",
            AlertLevel.ERROR: "red",
            AlertLevel.CRITICAL: "bold red",
        }
        c = alert_colors.get(self.alert_level, "white")
        return (
            f"[dim]{self.time_str}[/dim] "
            f"{self.source_label} "
            f"[{c}]{self.alert_icon} {self.who} -> {self.where} -- {self.what}[/{c}]"
        )

    def export_line(self) -> str:
        """Plain-text export line (no markup, ASCII/safe encoding)."""
        return f"{self.time_str} [{self.source.value}] {self.who} -> {self.where} -- {self.what}"

    def to_dict(self) -> dict[str, Any]:
        """Serializable dictionary for JSON export."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "time_str": self.time_str,
            "source": self.source.value,
            "who": self.who,
            "where": self.where,
            "what": self.what,
            "alert_level": self.alert_level.value,
            "raw_data": self.raw_data,
        }


@dataclass
class AgentStatus:
    """Tracks the health of an agent."""
    name: str
    connected: bool = False
    last_event_time: float | None = None
    error_message: str | None = None
    events_count: int = 0
