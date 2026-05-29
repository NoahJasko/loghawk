"""
Parse Windows .evtx files using pywin32 (Windows only).
Falls back gracefully on non-Windows environments.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .event_db import enrich

WINDOWS = sys.platform == "win32"

# ── Pre-compiled patterns — evaluated once at import, reused for every event ──
# Each search covers ~1 000 bytes and returns in < 5 µs.
# Previously we called ET.fromstring() (~80 µs/event) + multiple .find() calls.
# For 3 M events that was ~4 minutes of pure parsing; regex cuts it to ~40 s.

_P_EVENT_ID  = re.compile(r'<EventID(?:\s[^>]*)?>(\d+)<')
_P_RECORD_ID = re.compile(r'<EventRecordID>(\d+)<')
_P_SYS_TIME  = re.compile(r'SystemTime="([^"]*)"')
_P_COMPUTER  = re.compile(r'<Computer>([^<]*)<')
# Matches every <Data Name="KEY">VALUE</Data> in one pass over the string.
# [^<]* is intentional: values containing '<' are XML-escaped as &lt; so the
# literal '<' never appears in the value text.
_P_DATA      = re.compile(r'<Data Name="([^"]+)">([^<]*)<')

# Fields kept in raw_fields for detection rules and column display.
_KEEP_FIELDS: frozenset[str] = frozenset({
    # Identity
    "SubjectUserName", "SubjectDomainName", "SubjectUserSid",
    "TargetUserName",  "TargetDomainName",  "TargetUserSid",
    "TargetServerName", "SamAccountName", "UserPrincipalName",
    # Network / logon
    "IpAddress", "IpPort", "WorkstationName",
    "LogonType", "AuthenticationPackageName", "PackageName", "LogonProcessName",
    # Kerberos
    "TicketEncryptionType", "TicketOptions", "ServiceName",
    "PreAuthType", "Status", "SubStatus",
    # Object / DS
    "Properties", "ObjectServer", "ObjectType", "ObjectName", "AccessMask",
    # Account management
    "GroupName", "GroupSid", "MemberName", "MemberSid",
    "NewUacValue", "OldUacValue",
    # Scheduled tasks
    "TaskName", "TaskContent",
    # Services
    "ServiceFileName", "ServiceType", "StartType", "ServiceAccount",
    # Privileges
    "PrivilegeList",
    # Firewall / time
    "SettingValueName", "NewTime", "OldTime",
    # Process
    "NewProcessName", "CommandLine", "ParentProcessName",
    # LSA packages
    "NotificationPackageName",
    # SID history
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
    raw_fields:   dict   # ~30 key fields used by detection rules
    # enriched from event_db
    name:  str
    cat:   str
    sev:   str
    desc:  str
    mitre: list


def _parse_xml(xml_str: str) -> ParsedEvent | None:
    """
    Parse a Windows event XML string using pre-compiled regex patterns.
    ~6× faster than xml.etree.ElementTree for bulk loading.
    """
    m = _P_EVENT_ID.search(xml_str)
    if not m:
        return None
    event_id = int(m.group(1))

    m = _P_RECORD_ID.search(xml_str)
    record_id = int(m.group(1)) if m else 0

    m = _P_COMPUTER.search(xml_str)
    computer = m.group(1) if m else ""

    timestamp: datetime | None = None
    m = _P_SYS_TIME.search(xml_str)
    if m:
        try:
            raw_ts = m.group(1).rstrip("Z").split(".")[0]
            timestamp = datetime.strptime(raw_ts, "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            pass

    # Single-pass extraction of all EventData/UserData fields we care about
    raw_fields: dict[str, str] = {
        name: value
        for name, value in _P_DATA.findall(xml_str)
        if name in _KEEP_FIELDS
    }

    def rf(key: str) -> str:
        return raw_fields.get(key, "")

    user         = rf("TargetUserName") or rf("SubjectUserName") or "-"
    domain       = rf("TargetDomainName") or rf("SubjectDomainName") or "-"
    source_ip    = rf("IpAddress") or rf("WorkstationName") or "-"
    logon_type   = rf("LogonType")
    auth_package = rf("AuthenticationPackageName") or rf("PackageName")

    info = enrich(event_id)
    return ParsedEvent(
        record_id=record_id,
        event_id=event_id,
        timestamp=timestamp,
        computer=computer,
        user=user,
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


_EVTNEXT_BATCH = 2_000   # handles fetched per EvtNext call  (was 500)
_EMIT_BATCH    = 2_000   # events emitted per UI-thread signal


def parse_evtx(
    filepath: str | Path,
    progress_cb: Callable[[int], None] | None = None,
    batch_cb: Callable[[list[ParsedEvent]], None] | None = None,
) -> list[ParsedEvent]:
    """
    Parse a .evtx file.  Streams in batches of _EMIT_BATCH when batch_cb is
    provided; otherwise returns the full list.  Requires Windows + pywin32.
    """
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
            raw_events = win32evtlog.EvtNext(query, _EVTNEXT_BATCH)
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
    """
    Re-read a single event by record_id for on-demand full-field display.
    Called only when the user clicks a row — never during bulk loading.
    """
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
