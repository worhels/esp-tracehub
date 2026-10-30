"""Export module — save captured events to TXT or JSON."""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from pathlib import Path

from .models import NetEvent


def _default_filename(ext: str) -> str:
    ts = time.strftime("%Y%m%d_%H%M%S")
    return f"netscope_capture_{ts}.{ext}"


def export_txt(
    events: Sequence[NetEvent],
    directory: str | Path = ".",
    filename: str | None = None,
) -> Path:
    """Export events as a plain-text file (who → where — what).

    Returns the path to the written file.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    filepath = directory / (filename or _default_filename("txt"))

    lines = [
        "NETSCOPE Capture Export",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total events: {len(events)}",
        "=" * 72,
        "",
    ]
    for ev in events:
        lines.append(ev.export_line())

    lines.append("")
    lines.append("=" * 72)
    lines.append("End of capture")

    filepath.write_text("\n".join(lines), encoding="utf-8")
    return filepath


def export_json(
    events: Sequence[NetEvent],
    directory: str | Path = ".",
    filename: str | None = None,
) -> Path:
    """Export events as a JSON array.

    Returns the path to the written file.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    filepath = directory / (filename or _default_filename("json"))

    payload = {
        "generator": "NETSCOPE",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_events": len(events),
        "events": [ev.to_dict() for ev in events],
    }

    filepath.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return filepath
