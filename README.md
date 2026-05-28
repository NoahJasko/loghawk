# LogHawk

**Windows Security Event Log Analyzer & Threat Detector**

LogHawk is a standalone Windows desktop application for analyzing `.evtx` Security Event Logs and detecting common attack patterns. Download the `.exe`, double-click, done — no Python or installation required.

---

## Features

| Feature | Detail |
|---|---|
| **Event Database** | 300+ Security Event IDs with forensic descriptions |
| **Threat Detection** | 19 automated rules covering the most common attack patterns |
| **MITRE ATT&CK** | Every event and detection is mapped to ATT&CK technique IDs |
| **Severity Scoring** | Critical / High / Medium / Low / Info per event |
| **Visual Triage** | Color-coded table — analysts see what matters first |
| **Search & Filter** | Full-text search, category filter, per-severity toggles |
| **Export** | Filtered view exported to CSV |
| **Formats** | Native `.evtx` (pywin32) and CSV imports |

---

## Detection Rules

| ID | Name | Technique |
|---|---|---|
| AF-001 | Security Event Log Cleared | T1070.001 |
| AF-002 | Audit Events Dropped | T1562.002 |
| AF-003 | System Clock Manipulation | T1070.006 |
| AF-004 | Audit Policy Changed | T1562.002 |
| AF-005 | Windows Firewall Disabled | T1562.004 |
| BF-001 | Brute Force Login | T1110.001 |
| BF-002 | Password Spraying | T1110.003 |
| BF-003 | Account Lockout Storm | T1110.003 |
| KR-001 | Kerberoasting | T1558.003 |
| KR-002 | AS-REP Roasting | T1558.004 |
| DC-001 | DCSync Attack | T1003.006 |
| DC-002 | SID History Injection | T1134.005 |
| PE-001 | Scheduled Task Persistence | T1053.005 |
| PE-002 | New Service Installed | T1543.003 |
| PE-003 | New Admin Account Created | T1136 + T1098 |
| PE-004 | Unusual LSA Package Loaded | T1547.005 |
| LM-001 | Pass-the-Hash / Lateral Movement | T1550.002 |
| LM-002 | Explicit Credential Use | T1550.002 |
| PV-001 | Sensitive Privileges at Logon | T1134 |

---

## Download & Run

1. Go to [Releases](../../releases/latest)
2. Download `LogHawk.exe`
3. Double-click — no install, no Python needed
4. **File → Open EVTX File** (Windows only) or **File → Open CSV File**

> **CSV import** works on any platform and accepts exports from Windows Event Viewer (Action → Save All Events As → CSV).

---

## Usage

```
File → Open EVTX File     Load a .evtx Security log (Windows + pywin32)
File → Open CSV File      Load an Event Viewer CSV export
File → Export CSV         Save filtered events to CSV

Toolbar search box        Full-text search across all fields
Category dropdown         Filter by event category (Logon, Process, Kerberos…)
Severity checkboxes       Show/hide Critical / High / Medium / Low / Info rows

Click any table row       See full event details + raw fields in the bottom panel
Click a Detection card    Scroll & highlight contributing events in the table
```

---

## Building from Source

```bash
# 1 — Clone
git clone https://github.com/NoahJasko/loghawk
cd loghawk

# 2 — Install deps (Windows recommended for full EVTX support)
pip install -r requirements.txt

# 3 — Run from source
python -m src.main

# 4 — Build single EXE (Windows only)
pyinstaller build.spec --clean --noconfirm
# Output: dist/LogHawk.exe
```

---

## Automated Build (GitHub Actions)

Push a version tag to trigger a build and create a GitHub Release automatically:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The workflow (`.github/workflows/build.yml`) runs on `windows-latest`, installs all dependencies, builds with PyInstaller, and attaches `LogHawk.exe` to the release.

---

## Project Structure

```
loghawk/
├── src/
│   ├── main.py                  Entry point
│   ├── ui/
│   │   └── main_window.py       PySide6 GUI — all UI code
│   ├── core/
│   │   ├── event_db.py          JSON event database loader + lookup
│   │   ├── parser_evtx.py       .evtx parser (pywin32 / EvtQuery API)
│   │   ├── parser_csv.py        CSV parser (Event Viewer exports)
│   │   └── detection_engine.py  19 threat detection rules
│   ├── data/
│   │   └── security_events.json 300+ event ID definitions
│   └── resources/
│       └── style.qss            Dark Qt stylesheet
├── .github/
│   └── workflows/
│       └── build.yml            Windows EXE CI/CD
├── build.spec                   PyInstaller spec (onefile, noconsole)
└── requirements.txt
```

---

## Tech Stack

- **Python 3.11**
- **PySide6** (Qt6 GUI)
- **pywin32** (native Windows `.evtx` parsing via EvtQuery API)
- **PyInstaller** (single `.exe`, no console)
- **GitHub Actions** (automated build + release on tag push)

---

## License

MIT
