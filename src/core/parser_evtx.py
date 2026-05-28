"""
Parse Windows .evtx files using pywin32 (Windows only).
Falls back gracefully on non-Windows environments.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .event_db import enrich

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_Q  = f"{{{_NS}}}"

WINDOWS = sys.platform == "win32"


@dataclass
class ParsedEvent:
    record_id:    int
    event_id:     int
    timestamp:    datetime | None
    computer:     str
    user:         str
    domain:       str
    source_ip:    str
    logon_type:   str
    auth_package: str
    raw_fields:   dict[str, str] = field(default_factory=dict)
    # enriched from event_db
    name:  str = ""
    cat:   str = "other"
    sev:   str = "info"
    desc:  str = ""
    mitre: list[str] = field(default_factory=list)


def _parse_xml(xml_str: str) -> ParsedEvent | None:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    sys_el = root.find(f"{_Q}System")
    if sys_el is None:
        return None

    def sys_text(tag: str) -> str:
        el = sys_el.find(f"{_Q}{tag}")
        return el.text.strip() if el is not None and el.text else ""

    event_id  = int(sys_text("EventID") or 0)
    record_id = int(sys_text("EventRecordID") or 0)
    computer  = sys_text("Computer")

    # Parse timestamp
    time_el = sys_el.find(f"{_Q}TimeCreated")
    timestamp: datetime | None = None
    if time_el is not None:
        raw_ts = time_el.get("SystemTime", "")
        try:
            raw_ts = raw_ts.rstrip("Z").split(".")[0]
            timestamp = datetime.strptime(raw_ts, "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            pass

    # Collect EventData key-value pairs
    raw_fields: dict[str, str] = {}
    for section_tag in ("EventData", "UserData"):
        section = root.find(f"{_Q}{section_tag}")
        if section is not None:
            for data in section.iter(f"{_Q}Data"):
                name  = data.get("Name") or data.tag
                value = data.text or ""
                raw_fields[name] = value.strip()
            # Also grab any un-named text
            if section.text and section.text.strip():
                raw_fields["_text"] = section.text.strip()

    def rf(key: str) -> str:
        return raw_fields.get(key, "").strip()

    # Resolve user — prefer target, fall back to subject
    user   = rf("TargetUserName") or rf("SubjectUserName") or rf("UserName") or "-"
    domain = rf("TargetDomainName") or rf("SubjectDomainName") or "-"

    # Mask machine accounts and system accounts from the user display
    if user.endswith("$") or user in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
        display_user = user
    else:
        display_user = user

    source_ip    = rf("IpAddress") or rf("WorkstationName") or "-"
    logon_type   = rf("LogonType")
    auth_package = rf("AuthenticationPackageName") or rf("PackageName")

    info = enrich(event_id)
    return ParsedEvent(
        record_id=record_id,
        event_id=event_id,
        timestamp=timestamp,
        computer=computer,
        user=display_user,
        domain=domain,
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


def parse_evtx(
    filepath: str | Path,
    progress_cb: Callable[[int], None] | None = None,
) -> list[ParsedEvent]:
    """
    Parse a .evtx file and return a list of ParsedEvent objects.
    Requires Windows + pywin32.  On other platforms raises RuntimeError.
    """
    if not WINDOWS:
        raise RuntimeError(
            "EVTX parsing requires Windows and pywin32.\n"
            "On this platform you can load exported CSV files instead."
        )

    try:
        import win32evtlog  # type: ignore
        import win32con     # type: ignore  # noqa: F401
        import pywintypes   # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            f"pywin32 is not installed: {exc}\n"
            "Install it with:  pip install pywin32"
        ) from exc

    path = str(Path(filepath).resolve())
    events: list[ParsedEvent] = []

    try:
        query = win32evtlog.EvtQuery(
            path,
            win32evtlog.EvtQueryFilePath | win32evtlog.EvtQueryForwardDirection,
        )
    except pywintypes.error as exc:
        raise RuntimeError(f"Cannot open log file: {exc}") from exc

    batch = 200
    total_hint = _get_record_count(path)

    while True:
        try:
            raw_events = win32evtlog.EvtNext(query, batch)
        except pywintypes.error:
            break
        if not raw_events:
            break

        for raw in raw_events:
            try:
                xml_str = win32evtlog.EvtRender(raw, win32evtlog.EvtRenderEventXml)
            except pywintypes.error:
                continue
            ev = _parse_xml(xml_str)
            if ev is not None:
                events.append(ev)

        if progress_cb and total_hint:
            progress_cb(min(99, int(len(events) / total_hint * 100)))

    if progress_cb:
        progress_cb(100)
    return events


def _get_record_count(path: str) -> int:
    """Best-effort total record count for progress reporting."""
    try:
        import win32evtlog  # type: ignore
        import pywintypes   # type: ignore
        log = win32evtlog.EvtOpenLog(None, path, win32evtlog.EvtOpenFilePath)
        props = win32evtlog.EvtGetLogInfo(log, win32evtlog.EvtLogNumberOfLogRecords)
        return int(props)
    except Exception:
        return 0
