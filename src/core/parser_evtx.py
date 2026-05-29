"""
Parse Windows .evtx files using pywin32 (Windows only).
Falls back gracefully on non-Windows environments.
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as _ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .event_db import enrich

WINDOWS = sys.platform == "win32"

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_Q  = f"{{{_NS}}}"

# ── Pre-compiled patterns ─────────────────────────────────────────────────────
# Windows Event XML uses single OR double quotes for attributes depending on
# Windows version / EvtRender implementation.  All patterns handle both.

# <EventID>4624</EventID>  OR  <EventID Qualifiers="16384">4624</EventID>
_P_EVENT_ID  = re.compile(r'<EventID[^>]*>(\d+)<')
_P_RECORD_ID = re.compile(r'<EventRecordID[^>]*>(\d+)<')
# SystemTime='2024-...'  OR  SystemTime="2024-..."
_P_SYS_TIME  = re.compile(r"SystemTime=['\"]([^'\"]*)['\"]")
_P_COMPUTER  = re.compile(r'<Computer[^>]*>([^<]+)<')
# <Data Name='Key'>Value</Data>  OR  <Data Name="Key">Value</Data>
_P_DATA      = re.compile(r"<Data Name=['\"]([^'\"]+)['\"]>([^<]*)<")

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


def _parse_xml(xml_str) -> ParsedEvent | None:
    """
    Parse a Windows event XML string.
    Fast path: pre-compiled regex (~15 µs/event).
    Fallback:  xml.etree.ElementTree when the regex can't find EventID
               (handles unusual EvtRender output / encoding edge cases).
    """
    # pywin32 usually returns str, but guard against bytes just in case
    if isinstance(xml_str, (bytes, bytearray)):
        try:
            xml_str = xml_str.decode("utf-16-le").lstrip("﻿")
        except UnicodeDecodeError:
            xml_str = xml_str.decode("utf-8", errors="replace")

    # ── Fast regex path ───────────────────────────────────────────────────
    m = _P_EVENT_ID.search(xml_str)
    if not m:
        return _parse_xml_et(xml_str)          # rare — fall back to ET
    event_id = int(m.group(1))

    m = _P_RECORD_ID.search(xml_str)
    record_id = int(m.group(1)) if m else 0

    m = _P_COMPUTER.search(xml_str)
    computer = m.group(1).strip() if m else ""

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

    raw_fields: dict[str, str] = {
        name: value
        for name, value in _P_DATA.findall(xml_str)
        if name in _KEEP_FIELDS
    }

    return _make_event(event_id, record_id, computer, timestamp, raw_fields)


def _parse_xml_et(xml_str: str) -> ParsedEvent | None:
    """Fallback parser using ElementTree — correct but ~6× slower."""
    try:
        root = _ET.fromstring(xml_str)
    except _ET.ParseError:
        return None
    sys_el = root.find(f"{_Q}System")
    if sys_el is None:
        return None

    def st(tag: str) -> str:
        el = sys_el.find(f"{_Q}{tag}")
        return el.text.strip() if el is not None and el.text else ""

    event_id  = int(st("EventID") or 0)
    record_id = int(st("EventRecordID") or 0)
    computer  = st("Computer")

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
    for tag in ("EventData", "UserData"):
        section = root.find(f"{_Q}{tag}")
        if section is not None:
            for data in section.iter(f"{_Q}Data"):
                name = data.get("Name") or ""
                if name in _KEEP_FIELDS:
                    raw_fields[name] = (data.text or "").strip()

    return _make_event(event_id, record_id, computer, timestamp, raw_fields)


def _make_event(
    event_id: int,
    record_id: int,
    computer: str,
    timestamp: datetime | None,
    raw_fields: dict,
) -> ParsedEvent:
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
