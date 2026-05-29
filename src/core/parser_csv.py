"""
Parse Windows Security Event Log CSV exports produced by Event Viewer
(Action → Save All Events As → CSV) or by LogHawk itself.
"""

from __future__ import annotations

import csv
import re
from datetime import datetime
from pathlib import Path
from typing import Callable

from .event_db import enrich
from .parser_evtx import ParsedEvent

_DT_FORMATS = [
    "%m/%d/%Y %I:%M:%S %p",
    "%Y-%m-%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
]

_EMIT_BATCH = 2_000


def _parse_dt(raw: str) -> datetime | None:
    raw = raw.strip()
    for fmt in _DT_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            pass
    return None


def _coerce_int(v: str, default: int = 0) -> int:
    try:
        return int(v.strip())
    except (ValueError, AttributeError):
        return default


def parse_csv(
    filepath: str | Path,
    progress_cb: Callable[[int], None] | None = None,
    batch_cb: Callable[[list[ParsedEvent]], None] | None = None,
) -> list[ParsedEvent]:
    """
    Parse a CSV event export.  Streams in batches of _EMIT_BATCH when
    batch_cb is provided; otherwise returns the full list.
    """
    path = Path(filepath)
    collected: list[ParsedEvent] = []
    pending:   list[ParsedEvent] = []

    with open(path, encoding="utf-8-sig", newline="", errors="replace") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    total = len(rows)
    for i, row in enumerate(rows):
        if progress_cb and i % 500 == 0:
            progress_cb(int(i / max(total, 1) * 100))

        row_lower = {k.strip().lower(): v.strip() for k, v in row.items()}

        eid_raw  = row_lower.get("event id") or row_lower.get("eventid") or row_lower.get("id") or "0"
        event_id = _coerce_int(re.sub(r"\D", "", eid_raw))

        dt_raw = (
            row_lower.get("date and time")
            or row_lower.get("date/time")
            or row_lower.get("timestamp")
            or row_lower.get("time created")
            or ""
        )
        timestamp = _parse_dt(dt_raw)

        computer = row_lower.get("computer") or row_lower.get("computer name") or row_lower.get("source") or "-"
        user     = row_lower.get("user") or row_lower.get("username") or row_lower.get("account name") or "-"
        record_id    = _coerce_int(row_lower.get("record id") or row_lower.get("recordid") or "0")
        source_ip    = row_lower.get("source network address") or row_lower.get("ip address") or "-"
        logon_type   = row_lower.get("logon type") or ""
        auth_package = row_lower.get("authentication package") or row_lower.get("auth package") or ""

        # CSV rows already have limited columns — keep them all (they're already small)
        raw_fields = {k: v for k, v in row_lower.items() if v}

        info = enrich(event_id)
        ev = ParsedEvent(
            record_id=record_id,
            event_id=event_id,
            timestamp=timestamp,
            computer=computer,
            user=user,
            domain=row_lower.get("domain", "-"),
            source_ip=source_ip,
            logon_type=logon_type,
            auth_package=auth_package,
            raw_fields=raw_fields,
            name=info["name"],
            cat=info["cat"],
            sev=info["sev"],
            desc=info["desc"],
            mitre=info["mitre"],
        )

        if batch_cb:
            pending.append(ev)
            if len(pending) >= _EMIT_BATCH:
                batch_cb(pending)
                pending = []
        else:
            collected.append(ev)

    if batch_cb and pending:
        batch_cb(pending)
    if progress_cb:
        progress_cb(100)

    return collected
