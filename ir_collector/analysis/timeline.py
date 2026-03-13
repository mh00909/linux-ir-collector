from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from ir_collector.utils.fs import write_text


@dataclass(order=True)
class Event:
    timestamp: datetime
    source: str = field(compare=False)
    category: str = field(compare=False)
    message: str = field(compare=False)


# Przykładowy format logu: Mar  7 03:14:22
_SYSLOG_RE = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(.+)$'
)


def _parse_syslog_line(line: str, year: int) -> Optional[Event]:
    m = _SYSLOG_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    msg = m.group(2)
    category = "auth" if "Failed password" in msg or "Accepted" in msg else "system"
    return Event(timestamp=ts, source="auth.log", category=category, message=msg)


def build_timeline(out_dir: Path, results: dict) -> list[Event]:
    events: list[Event] = []
    year = datetime.now().year

    # Zdarzenia z logów auth
    auth_file = out_dir / "logs" / "auth_tail.txt"
    if auth_file.exists():
        for line in auth_file.read_text(encoding="utf-8", errors="replace").splitlines():
            ev = _parse_syslog_line(line, year)
            if ev:
                events.append(ev)

    events.sort()
    return events


def write_timeline(out_dir: Path, events: list[Event]) -> None:
    if not events:
        write_text(out_dir / "timeline.txt", "No timestamped events found.\n")
        return

    lines = [f"{'TIMESTAMP':<25} {'SOURCE':<15} {'CATEGORY':<10} MESSAGE"]
    lines.append("-" * 100)
    for ev in events:
        ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"{ts:<25} {ev.source:<15} {ev.category:<10} {ev.message}")

    write_text(out_dir / "timeline.txt", "\n".join(lines) + "\n")