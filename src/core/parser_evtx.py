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

_KEEP_FIELDS: frozenset[str] = frozenset({
    "SubjectUserName", "SubjectDomainName", "SubjectUserSid",
    "TargetUserName",  "TargetDomainName",  "TargetUserSid",
    "TargetServerName", "SamAccountName", "UserPrincipalName",
    "IpAddress", "IpPort", "WorkstationName",
    "LogonType", "AuthenticationPackageName", "PackageName", "LogonProcessName",
    "TicketEncryptionType", "TicketOptions", "ServiceName",
    "PreAuthType", "Status", "SubStatus",
    "Properties", "ObjectServer", "ObjectType", "ObjectName", "AccessMask",
    "GroupName", "GroupSid", "MemberName", "MemberSid",
    "NewUacValue", "OldUacValue",
    "TaskName", "TaskContent",
    "ServiceFileName", "ServiceType", "StartType", "ServiceAccount",
    "PrivilegeList",
    "SettingValueName", "NewTime", "OldTime",
    "NewProcessName", "CommandLine", "ParentProcessName",
    "NotificationPackageName",
    "SidHistory",
})


@dataclass(slots=True)
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
    raw_fields:   dict
    # enriched from event_db
    name:  str
    cat:   str
    sev:   str
    desc:  str
    mitre: list


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

    raw_fields: dict[str, str] = {}
    for section_tag in ("EventData", "UserData"):
        section = root.find(f"{_Q}{section_tag}")
        if section is not None:
            for data in section.iter(f"{_Q}Data"):
                name = data.get("Name") or ""
                if name in _KEEP_FIELDS:
                    raw_fields[name] = (data.text or "").strip()

    def rf(key: str) -> str:
        return raw_fields.get(key, "")

    info = enrich(event_id)
    return ParsedEvent(
        record_id=record_id,
        event_id=event_id,
        timestamp=timestamp,
        computer=computer,
        user=rf("TargetUserName") or rf("SubjectUserName") or "-",
        domain=rf("TargetDomainName") or rf("SubjectDomainName") or "-",
        source_ip=rf("IpAddress") or rf("WorkstationName") or "-",
        logon_type=rf("LogonType"),
        auth_package=rf("AuthenticationPackageName") or rf("PackageName"),
        raw_fields=raw_fields,
        name=info["name"],
        cat=info["cat"],
        sev=info["sev"],
        desc=info["desc"],
        mitre=info["mitre"],
    )


_EMIT_BATCH = 2_000


def parse_evtx(
    filepath: str | Path,
    progress_cb: Callable[[int], None] | None = None,
    batch_cb: Callable[[list[ParsedEvent]], None] | None = None,
) -> list[ParsedEvent]:
    if not WINDOWS:
        raise RuntimeError(
            "EVTX parsing requires Windows and pywin32.\n"
            "On this platform you can load exported CSV files instead."
        )

    try:
        import win32evtlog  # type: ignore
        import pywintypes   # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            f"pywin32 is not installed: {exc}\n"
            "Install it with:  pip install pywin32"
        ) from exc

    path = str(Path(filepath).resolve())
    total_hint = _get_record_count(path)

    try:
        query = win32evtlog.EvtQuery(
            path,
            win32evtlog.EvtQueryFilePath | win32evtlog.EvtQueryForwardDirection,
        )
    except pywintypes.error as exc:
        raise RuntimeError(f"Cannot open log file: {exc}") from exc

    collected: list[ParsedEvent] = []
    pending:   list[ParsedEvent] = []
    total_parsed = 0

    while True:
        try:
            raw_events = win32evtlog.EvtNext(query, 500)
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
            if ev is None:
                continue
            total_parsed += 1
            if batch_cb:
                pending.append(ev)
                if len(pending) >= _EMIT_BATCH:
                    batch_cb(pending)
                    pending = []
            else:
                collected.append(ev)

        if progress_cb and total_hint:
            progress_cb(min(99, int(total_parsed / total_hint * 100)))

    if batch_cb and pending:
        batch_cb(pending)
    if progress_cb:
        progress_cb(100)

    return collected


def fetch_event_xml(filepath: str | Path, record_id: int) -> str | None:
    """Re-read a single event by record_id for on-demand full-field display."""
    if not WINDOWS:
        return None
    try:
        import win32evtlog  # type: ignore
        import pywintypes   # type: ignore
        query = win32evtlog.EvtQuery(
            str(Path(filepath).resolve()),
            win32evtlog.EvtQueryFilePath | win32evtlog.EvtQueryForwardDirection,
            f"*[System[EventRecordID={record_id}]]",
        )
        events = win32evtlog.EvtNext(query, 1)
        if events:
            return win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
    except Exception:
        pass
    return None


def _get_record_count(path: str) -> int:
    try:
        import win32evtlog  # type: ignore
        import pywintypes   # type: ignore
        log   = win32evtlog.EvtOpenLog(None, path, win32evtlog.EvtOpenFilePath)
        props = win32evtlog.EvtGetLogInfo(log, win32evtlog.EvtLogNumberOfLogRecords)
        return int(props)
    except Exception:
        return 0
