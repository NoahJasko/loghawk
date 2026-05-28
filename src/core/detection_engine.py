"""
Threat detection engine — applies rule-based analysis to a list of ParsedEvents
and returns Detection objects, each with MITRE ATT&CK mappings and severity.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .parser_evtx import ParsedEvent


# ── Data model ───────────────────────────────────────────────────────────────

@dataclass
class Detection:
    rule_id:   str
    name:      str
    summary:   str
    severity:  str          # critical / high / medium / low
    mitre:     list[str]
    events:    list[ParsedEvent]
    timestamp: datetime | None
    source:    str
    target:    str


# ── Helpers ──────────────────────────────────────────────────────────────────

def _by_id(events: list[ParsedEvent], *ids: int) -> list[ParsedEvent]:
    id_set = set(ids)
    return [e for e in events if e.event_id in id_set]


def _windows(
    evs: list[ParsedEvent],
    seconds: int,
    key_fn,
    threshold: int,
) -> list[tuple]:
    """
    Sliding-window grouping.  For each unique key produced by key_fn,
    find all time-windows of `seconds` width that contain >= `threshold` events.
    Returns list of (key, window_events) tuples (deduplicated by first event).
    """
    groups: dict = defaultdict(list)
    for e in evs:
        if e.timestamp:
            groups[key_fn(e)].append(e)

    results = []
    delta = timedelta(seconds=seconds)
    seen_starts: set = set()

    for key, grp in groups.items():
        grp_sorted = sorted(grp, key=lambda x: x.timestamp)
        i = 0
        while i < len(grp_sorted):
            j = i + 1
            while j < len(grp_sorted) and grp_sorted[j].timestamp - grp_sorted[i].timestamp <= delta:
                j += 1
            window = grp_sorted[i:j]
            if len(window) >= threshold:
                anchor = (key, grp_sorted[i].timestamp)
                if anchor not in seen_starts:
                    seen_starts.add(anchor)
                    results.append((key, window))
            i += 1
    return results


# ── Detection rules ───────────────────────────────────────────────────────────

def _rule_log_cleared(events: list[ParsedEvent]) -> list[Detection]:
    detections = []
    for e in _by_id(events, 1102):
        detections.append(Detection(
            rule_id="AF-001",
            name="Security Event Log Cleared",
            summary=(
                f"The Security Event Log was cleared by '{e.user}' on '{e.computer}'. "
                "Log clearing is a primary anti-forensics technique used after intrusions."
            ),
            severity="critical",
            mitre=["T1070.001"],
            events=[e],
            timestamp=e.timestamp,
            source=e.source_ip,
            target=e.computer,
        ))
    return detections


def _rule_audit_log_dropped(events: list[ParsedEvent]) -> list[Detection]:
    detections = []
    for e in _by_id(events, 1101):
        detections.append(Detection(
            rule_id="AF-002",
            name="Audit Events Dropped (Evidence Loss)",
            summary=(
                f"Audit events were dropped on '{e.computer}'. An attacker may have "
                "flooded the audit queue to cause evidence loss during an attack."
            ),
            severity="high",
            mitre=["T1562.002"],
            events=[e],
            timestamp=e.timestamp,
            source=e.source_ip,
            target=e.computer,
        ))
    return detections


def _rule_time_tampered(events: list[ParsedEvent]) -> list[Detection]:
    detections = []
    for e in _by_id(events, 4616):
        new_time = e.raw_fields.get("NewTime", "unknown")
        detections.append(Detection(
            rule_id="AF-003",
            name="System Clock Manipulation",
            summary=(
                f"System time was changed on '{e.computer}' by '{e.user}' "
                f"to {new_time}. Clock manipulation is used to confuse log "
                "timelines and bypass time-based Kerberos controls."
            ),
            severity="high",
            mitre=["T1070.006"],
            events=[e],
            timestamp=e.timestamp,
            source=e.source_ip,
            target=e.computer,
        ))
    return detections


def _rule_brute_force(events: list[ParsedEvent]) -> list[Detection]:
    failed = _by_id(events, 4625)
    # Group by (source_ip, target_computer); 5+ failures in 5 min
    windows = _windows(
        failed,
        seconds=300,
        key_fn=lambda e: (e.source_ip.lower(), e.computer.lower()),
        threshold=5,
    )
    detections = []
    for (src_ip, computer), window in windows:
        count = len(window)
        sev = "critical" if count >= 20 else "high"
        users = {e.user for e in window if e.user not in ("-", "")}
        detections.append(Detection(
            rule_id="BF-001",
            name="Brute Force Login Detected",
            summary=(
                f"{count} failed logon attempts from '{src_ip}' targeting "
                f"'{computer}' within 5 minutes. Accounts targeted: "
                f"{', '.join(sorted(users)) or 'multiple'}."
            ),
            severity=sev,
            mitre=["T1110.001"],
            events=window,
            timestamp=window[0].timestamp,
            source=src_ip,
            target=computer,
        ))
    return detections


def _rule_password_spray(events: list[ParsedEvent]) -> list[Detection]:
    failed = _by_id(events, 4625)
    # Group by source_ip; 3+ unique usernames in 10 min with low per-user count
    windows = _windows(
        failed,
        seconds=600,
        key_fn=lambda e: e.source_ip.lower(),
        threshold=3,
    )
    detections = []
    for src_ip, window in windows:
        user_counts: dict[str, int] = defaultdict(int)
        for e in window:
            user_counts[e.user.lower()] += 1
        unique_users = len(user_counts)
        max_per_user = max(user_counts.values()) if user_counts else 0

        # Spray = many users, low per-user frequency (not a focused brute force)
        if unique_users >= 5 and max_per_user <= 5:
            detections.append(Detection(
                rule_id="BF-002",
                name="Password Spraying Detected",
                summary=(
                    f"'{src_ip}' attempted {len(window)} logons against "
                    f"{unique_users} unique accounts within 10 minutes with "
                    "low per-account frequency — consistent with password spraying."
                ),
                severity="high",
                mitre=["T1110.003"],
                events=window,
                timestamp=window[0].timestamp,
                source=src_ip,
                target="multiple accounts",
            ))
    return detections


def _rule_account_lockout_storm(events: list[ParsedEvent]) -> list[Detection]:
    lockouts = _by_id(events, 4740)
    windows = _windows(
        lockouts,
        seconds=300,
        key_fn=lambda e: e.source_ip.lower() or e.computer.lower(),
        threshold=3,
    )
    detections = []
    for src, window in windows:
        accounts = {e.user for e in window}
        detections.append(Detection(
            rule_id="BF-003",
            name="Account Lockout Storm",
            summary=(
                f"{len(window)} account lockouts occurred within 5 minutes "
                f"(source: '{src}'). Affects: {', '.join(sorted(accounts))}. "
                "This is a strong indicator of an ongoing credential attack."
            ),
            severity="high",
            mitre=["T1110.003"],
            events=window,
            timestamp=window[0].timestamp,
            source=src,
            target="multiple accounts",
        ))
    return detections


def _rule_kerberoasting(events: list[ParsedEvent]) -> list[Detection]:
    # 4769 with TicketEncryptionType == 0x17 (RC4-HMAC) — Kerberoasting
    tgs_rc4 = [
        e for e in _by_id(events, 4769)
        if e.raw_fields.get("TicketEncryptionType", "").lower() in ("0x17", "23")
        and e.raw_fields.get("ServiceName", "").lower() not in ("krbtgt", "krbtgt/")
    ]
    windows = _windows(
        tgs_rc4,
        seconds=3600,
        key_fn=lambda e: e.source_ip.lower() or e.user.lower(),
        threshold=3,
    )
    detections = []
    for src, window in windows:
        spns = {e.raw_fields.get("ServiceName", "") for e in window}
        detections.append(Detection(
            rule_id="KR-001",
            name="Kerberoasting Detected",
            summary=(
                f"{len(window)} Kerberos service ticket requests with RC4 encryption "
                f"(0x17) from '{src}' within 1 hour. Targeted SPNs: "
                f"{', '.join(sorted(spns)[:5])}. RC4 tickets are offline-crackable."
            ),
            severity="high",
            mitre=["T1558.003"],
            events=window,
            timestamp=window[0].timestamp,
            source=src,
            target=", ".join(sorted(spns)[:3]),
        ))
    return detections


def _rule_asrep_roasting(events: list[ParsedEvent]) -> list[Detection]:
    # 4768 with PreAuthType == 0 — account has pre-auth disabled → AS-REP Roastable
    asrep = [
        e for e in _by_id(events, 4768)
        if e.raw_fields.get("PreAuthType", "1") in ("0", "0x0")
        and e.raw_fields.get("Status", "0x0") == "0x0"
    ]
    detections = []
    for e in asrep:
        account = e.raw_fields.get("TargetUserName", e.user)
        detections.append(Detection(
            rule_id="KR-002",
            name="AS-REP Roasting Target Identified",
            summary=(
                f"Kerberos pre-authentication is disabled for account '{account}'. "
                "The TGT response hash can be captured and cracked offline without "
                "a password (AS-REP Roasting / T1558.004)."
            ),
            severity="high",
            mitre=["T1558.004"],
            events=[e],
            timestamp=e.timestamp,
            source=e.source_ip,
            target=account,
        ))
    return detections


_DCSYNC_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c",  # DS-Replication-Get-Changes-In-Filtered-Set
}


def _rule_dcsync(events: list[ParsedEvent]) -> list[Detection]:
    candidates = [
        e for e in _by_id(events, 4662)
        if e.raw_fields.get("ObjectServer", "").upper() == "DS"
        and any(g in e.raw_fields.get("Properties", "").lower() for g in _DCSYNC_GUIDS)
    ]
    # Group by user+source — multiple accesses in quick succession
    by_actor: dict[str, list[ParsedEvent]] = defaultdict(list)
    for e in candidates:
        actor = e.user.lower() + "|" + e.source_ip.lower()
        by_actor[actor].append(e)

    detections = []
    for actor, evs in by_actor.items():
        # A legitimate DC replication will also generate these — filter out machine accounts
        user = evs[0].user
        # Machine accounts (ending $) doing replication = normal; user accounts = suspicious
        if user.endswith("$"):
            continue
        detections.append(Detection(
            rule_id="DC-001",
            name="DCSync Attack Detected",
            summary=(
                f"Account '{user}' performed AD replication operations (DS-Replication-Get-Changes) "
                f"from '{evs[0].source_ip}'. This is the DCSync technique used to dump "
                "NTLM password hashes from Active Directory without touching NTDS.dit on disk."
            ),
            severity="critical",
            mitre=["T1003.006"],
            events=evs,
            timestamp=evs[0].timestamp,
            source=evs[0].source_ip,
            target=evs[0].computer,
        ))
    return detections


_SUSPICIOUS_TASK_PATTERNS = [
    "powershell", "cmd /c", "cmd.exe", "wscript", "cscript", "mshta",
    "rundll32", "regsvr32", "certutil", "bitsadmin", "msiexec",
    "base64", "encodedcommand", "-enc ", "bypass", "hidden",
    "invoke-", "iex(", "downloadstring", "webclient",
]


def _rule_persistence_task(events: list[ParsedEvent]) -> list[Detection]:
    detections = []
    for e in _by_id(events, 4698):
        task_content = (
            e.raw_fields.get("TaskContent", "")
            + e.raw_fields.get("TaskName", "")
        ).lower()
        suspicious = any(p in task_content for p in _SUSPICIOUS_TASK_PATTERNS)
        sev = "critical" if suspicious else "high"
        task_name = e.raw_fields.get("TaskName", "unknown")
        detections.append(Detection(
            rule_id="PE-001",
            name="Suspicious Scheduled Task Created" if suspicious else "Scheduled Task Created",
            summary=(
                f"Scheduled task '{task_name}' was created by '{e.user}' on '{e.computer}'. "
                + (
                    "The task content contains suspicious execution patterns (LOLBin / encoding)."
                    if suspicious
                    else "Review task action and trigger for persistence indicators."
                )
            ),
            severity=sev,
            mitre=["T1053.005"],
            events=[e],
            timestamp=e.timestamp,
            source=e.source_ip,
            target=e.computer,
        ))
    return detections


def _rule_persistence_service(events: list[ParsedEvent]) -> list[Detection]:
    detections = []
    for e in _by_id(events, 4697):
        svc_name = e.raw_fields.get("ServiceName", "unknown")
        svc_file = e.raw_fields.get("ServiceFileName", "")
        suspicious = any(
            p in svc_file.lower()
            for p in ["temp", "appdata", "public", "programdata", "%temp%"]
        )
        detections.append(Detection(
            rule_id="PE-002",
            name="New Service Installed" + (" from Suspicious Path" if suspicious else ""),
            summary=(
                f"Service '{svc_name}' was installed by '{e.user}' on '{e.computer}'. "
                f"Binary: {svc_file or 'unknown'}. "
                + (
                    "Service binary is located in a writable/temp directory — high confidence malicious."
                    if suspicious else
                    "Verify the service binary and creating account."
                )
            ),
            severity="critical" if suspicious else "high",
            mitre=["T1543.003"],
            events=[e],
            timestamp=e.timestamp,
            source=e.source_ip,
            target=e.computer,
        ))
    return detections


def _rule_admin_account_created(events: list[ParsedEvent]) -> list[Detection]:
    created = {e.raw_fields.get("TargetUserName", "").lower(): e for e in _by_id(events, 4720)}
    admin_adds = _by_id(events, 4728, 4732, 4756)

    detections = []
    for add_ev in admin_adds:
        group = add_ev.raw_fields.get("GroupName", "").lower()
        if not any(
            kw in group
            for kw in ("admin", "domain admins", "enterprise admins", "schema admins", "operators")
        ):
            continue
        added_user = add_ev.raw_fields.get("MemberName", "").lower().split(",")[0].lstrip("cn=")
        create_ev = created.get(added_user.split("\\")[-1])

        if create_ev and add_ev.timestamp and create_ev.timestamp:
            delta = abs((add_ev.timestamp - create_ev.timestamp).total_seconds())
            if delta <= 3600:
                detections.append(Detection(
                    rule_id="PE-003",
                    name="New Admin Account Created",
                    summary=(
                        f"Account '{added_user}' was created by '{create_ev.user}' and immediately "
                        f"added to '{add_ev.raw_fields.get('GroupName', 'admin group')}' within "
                        f"{int(delta)}s. This is a common backdoor persistence technique."
                    ),
                    severity="critical",
                    mitre=["T1136.001", "T1098.007"],
                    events=[create_ev, add_ev],
                    timestamp=create_ev.timestamp,
                    source=create_ev.source_ip,
                    target=added_user,
                ))
    return detections


def _rule_pass_the_hash(events: list[ParsedEvent]) -> list[Detection]:
    # 4624 Type=3, NTLM auth, non-machine account, multiple targets
    pth_candidates = [
        e for e in _by_id(events, 4624)
        if e.logon_type == "3"
        and "ntlm" in e.auth_package.lower()
        and not e.user.endswith("$")
        and e.user not in ("-", "ANONYMOUS LOGON", "")
    ]
    windows = _windows(
        pth_candidates,
        seconds=600,
        key_fn=lambda e: (e.user.lower(), e.source_ip.lower()),
        threshold=3,
    )
    detections = []
    for (user, src_ip), window in windows:
        targets = {e.computer for e in window}
        if len(targets) >= 2:
            detections.append(Detection(
                rule_id="LM-001",
                name="Pass-the-Hash / Lateral Movement Detected",
                summary=(
                    f"Account '{user}' authenticated via NTLM (Type 3) to "
                    f"{len(targets)} different systems from '{src_ip}' within 10 minutes: "
                    f"{', '.join(sorted(targets))}. "
                    "Rapid NTLM lateral movement without interactive logon is a PtH indicator."
                ),
                severity="high",
                mitre=["T1550.002", "T1021.002"],
                events=window,
                timestamp=window[0].timestamp,
                source=src_ip,
                target=", ".join(sorted(targets)),
            ))
    return detections


def _rule_explicit_credential_logon(events: list[ParsedEvent]) -> list[Detection]:
    # 4648 — explicit credential use, flag when user ≠ subject
    detections = []
    for e in _by_id(events, 4648):
        subject = e.raw_fields.get("SubjectUserName", "").lower()
        target  = e.raw_fields.get("TargetUserName", "").lower()
        if subject and target and subject != target and not subject.endswith("$"):
            detections.append(Detection(
                rule_id="LM-002",
                name="Explicit Credential Use (runas / lateral movement)",
                summary=(
                    f"'{subject}' used explicit credentials for '{target}' on "
                    f"'{e.raw_fields.get('TargetServerName', e.computer)}'. "
                    "Explicit credential logons are common in Pass-the-Hash, runas, and lateral movement."
                ),
                severity="medium",
                mitre=["T1550.002"],
                events=[e],
                timestamp=e.timestamp,
                source=e.source_ip,
                target=target,
            ))
    return detections


def _rule_privilege_escalation(events: list[ParsedEvent]) -> list[Detection]:
    sensitive_privs = {
        "SeDebugPrivilege",
        "SeTcbPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeImpersonatePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeLoadDriverPrivilege",
        "SeRestorePrivilege",
        "SeCreateTokenPrivilege",
    }
    detections = []
    for e in _by_id(events, 4672):
        privs_raw = e.raw_fields.get("PrivilegeList", "")
        granted = {p.strip() for p in privs_raw.split() if p.strip()}
        critical_hit = granted & sensitive_privs
        if critical_hit and not e.user.endswith("$") and e.user not in ("SYSTEM", "-"):
            detections.append(Detection(
                rule_id="PV-001",
                name="Sensitive Privileges Assigned at Logon",
                summary=(
                    f"'{e.user}' was assigned sensitive privileges on '{e.computer}': "
                    f"{', '.join(sorted(critical_hit))}. These privileges enable "
                    "token impersonation, driver loading, and other escalation techniques."
                ),
                severity="medium",
                mitre=["T1134"],
                events=[e],
                timestamp=e.timestamp,
                source=e.source_ip,
                target=e.computer,
            ))
    return detections


def _rule_lsa_package_loaded(events: list[ParsedEvent]) -> list[Detection]:
    detections = []
    for e in _by_id(events, 4610, 4614, 4622):
        pkg = e.raw_fields.get("AuthenticationPackageName") or e.raw_fields.get("NotificationPackageName") or "unknown"
        known_safe = {"kerberos", "msv1_0", "wdigest", "tspkg", "negotiate", "ntlm", "cloudap", ""}
        if pkg.lower() not in known_safe:
            detections.append(Detection(
                rule_id="PE-004",
                name="Unusual LSA Package Loaded",
                summary=(
                    f"An unusual package '{pkg}' was loaded into LSASS on '{e.computer}'. "
                    "Malicious LSA packages are used for credential interception and persistence."
                ),
                severity="high",
                mitre=["T1547.005", "T1547.002"],
                events=[e],
                timestamp=e.timestamp,
                source=e.source_ip,
                target=e.computer,
            ))
    return detections


def _rule_sid_history_injection(events: list[ParsedEvent]) -> list[Detection]:
    detections = []
    for e in _by_id(events, 4765, 4766):
        account = e.raw_fields.get("TargetUserName", e.user)
        detections.append(Detection(
            rule_id="DC-002",
            name="SID History Injection" + (" Attempted" if e.event_id == 4766 else ""),
            summary=(
                f"SID History was {'added to' if e.event_id == 4765 else 'attempted on'} "
                f"account '{account}'. Adding privileged SIDs to a low-privilege account "
                "grants implicit elevated access across the domain."
            ),
            severity="critical",
            mitre=["T1134.005"],
            events=[e],
            timestamp=e.timestamp,
            source=e.source_ip,
            target=account,
        ))
    return detections


def _rule_audit_policy_changed(events: list[ParsedEvent]) -> list[Detection]:
    detections = []
    for e in _by_id(events, 4719):
        detections.append(Detection(
            rule_id="AF-004",
            name="System Audit Policy Changed",
            summary=(
                f"System audit policy was changed by '{e.user}' on '{e.computer}'. "
                "Attackers reduce audit coverage to operate undetected."
            ),
            severity="high",
            mitre=["T1562.002"],
            events=[e],
            timestamp=e.timestamp,
            source=e.source_ip,
            target=e.computer,
        ))
    return detections


def _rule_firewall_disabled(events: list[ParsedEvent]) -> list[Detection]:
    detections = []
    for e in _by_id(events, 4950):
        setting = e.raw_fields.get("SettingValueName", "").lower()
        if "disabled" in setting or "off" in setting or not setting:
            detections.append(Detection(
                rule_id="AF-005",
                name="Windows Firewall Disabled or Weakened",
                summary=(
                    f"Firewall setting changed by '{e.user}' on '{e.computer}'. "
                    "Disabling the firewall is a common attacker preparation step."
                ),
                severity="high",
                mitre=["T1562.004"],
                events=[e],
                timestamp=e.timestamp,
                source=e.source_ip,
                target=e.computer,
            ))
    return detections


_ALL_RULES = [
    _rule_log_cleared,
    _rule_audit_log_dropped,
    _rule_time_tampered,
    _rule_brute_force,
    _rule_password_spray,
    _rule_account_lockout_storm,
    _rule_kerberoasting,
    _rule_asrep_roasting,
    _rule_dcsync,
    _rule_persistence_task,
    _rule_persistence_service,
    _rule_admin_account_created,
    _rule_pass_the_hash,
    _rule_explicit_credential_logon,
    _rule_privilege_escalation,
    _rule_lsa_package_loaded,
    _rule_sid_history_injection,
    _rule_audit_policy_changed,
    _rule_firewall_disabled,
]

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def analyze(events: list[ParsedEvent]) -> list[Detection]:
    """Run all detection rules and return sorted Detection list."""
    sorted_events = sorted(
        (e for e in events if e.timestamp),
        key=lambda e: e.timestamp,
    )
    detections: list[Detection] = []
    for rule in _ALL_RULES:
        try:
            detections.extend(rule(sorted_events))
        except Exception:
            pass
    return sorted(
        detections,
        key=lambda d: (_SEV_ORDER.get(d.severity, 9), d.timestamp or datetime.min),
    )
