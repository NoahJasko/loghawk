"""LogHawk — main application window."""

from __future__ import annotations

import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import (
    QAbstractTableModel,
    QDateTime,
    QModelIndex,
    QPoint,
    QSortFilterProxyModel,
    Qt,
    QThread,
    QTimer,
    Signal,
)
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QDockWidget,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QTabWidget,
    QTableView,
    QTextBrowser,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from ..core import detection_engine
from ..core.event_db import all_categories
from ..core.parser_evtx import ParsedEvent

# ── Severity palette ──────────────────────────────────────────────────────────

_SEV_BG: dict[str, QColor] = {
    "critical": QColor(0x2D, 0x1B, 0x22),
    "high":     QColor(0x2D, 0x20, 0x14),
    "medium":   QColor(0x2D, 0x2A, 0x14),
    "low":      QColor(0x14, 0x20, 0x2D),
    "info":     QColor(0x1E, 0x1E, 0x2E),
}
_SEV_FG: dict[str, QColor] = {
    "critical": QColor(0xF3, 0x8B, 0xA8),
    "high":     QColor(0xFA, 0xB3, 0x87),
    "medium":   QColor(0xF9, 0xE2, 0xAF),
    "low":      QColor(0x89, 0xB4, 0xFA),
    "info":     QColor(0x6C, 0x70, 0x86),
}
_SEV_LABEL: dict[str, str] = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}


# ── Table model ───────────────────────────────────────────────────────────────

_COLS = ["Time", "Event ID", "Name", "Category", "Severity", "User", "Computer", "Source IP"]
_COL_W = [155, 72, 260, 85, 72, 140, 150, 130]


class EventTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._events: list[ParsedEvent] = []

    # ── QAbstractTableModel interface ─────────────────────────────────────
    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._events)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(_COLS)

    def headerData(self, section: int, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return _COLS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        ev = self._events[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            return self._display(ev, col)

        if role == Qt.BackgroundRole:
            return _SEV_BG.get(ev.sev, _SEV_BG["info"])

        if role == Qt.ForegroundRole:
            if col == 4:  # severity badge column
                return _SEV_FG.get(ev.sev, _SEV_FG["info"])
            return QColor(0xCD, 0xD6, 0xF4)

        if role == Qt.FontRole:
            if col == 4:
                f = QFont()
                f.setBold(True)
                f.setPointSize(7)
                return f
            if col == 1:  # event ID
                f = QFont("Cascadia Code, Consolas, monospace")
                f.setPointSize(9)
                return f

        if role == Qt.UserRole:
            return ev

        if role == Qt.ToolTipRole:
            mitre = ", ".join(ev.mitre) if ev.mitre else "—"
            return f"<b>{ev.name}</b><br>{ev.desc}<br><br><b>MITRE:</b> {mitre}"

        return None

    def _display(self, ev: ParsedEvent, col: int) -> str:
        if col == 0:
            if ev.timestamp:
                ts = ev.timestamp
                if ts.tzinfo is not None:
                    ts = ts.astimezone().replace(tzinfo=None)
                return ts.strftime("%Y-%m-%d  %H:%M:%S")
            return "—"
        if col == 1: return str(ev.event_id)
        if col == 2: return ev.name
        if col == 3: return ev.cat.title()
        if col == 4: return _SEV_LABEL.get(ev.sev, ev.sev.upper())
        if col == 5: return ev.user or "—"
        if col == 6: return ev.computer or "—"
        if col == 7: return ev.source_ip or "—"
        return ""

    # ── Mutation helpers ──────────────────────────────────────────────────
    def load(self, events: list[ParsedEvent]) -> None:
        self.beginResetModel()
        self._events = events
        self.endResetModel()

    def append_batch(self, events: list[ParsedEvent]) -> None:
        if not events:
            return
        first = len(self._events)
        last  = first + len(events) - 1
        self.beginInsertRows(QModelIndex(), first, last)
        self._events.extend(events)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._events = []
        self.endResetModel()

    def all_events(self) -> list[ParsedEvent]:
        return list(self._events)


# ── Filter proxy ──────────────────────────────────────────────────────────────

class EventFilter(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._search   = ""
        self._category = "All"
        self._sevs: set[str] = {"critical", "high", "medium", "low", "info"}
        # float Unix timestamps — None means no bound (fastest comparison possible)
        self._ts_from: float | None = None
        self._ts_to:   float | None = None
        self.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.setSortRole(Qt.UserRole)

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model: EventTableModel = self.sourceModel()
        if source_row >= len(model._events):
            return False
        ev = model._events[source_row]

        if ev.sev not in self._sevs:
            return False
        if self._category != "All" and ev.cat != self._category:
            return False

        # Timestamp range — float comparison, no allocations
        if (self._ts_from is not None or self._ts_to is not None) and ev.timestamp:
            ts = ev.timestamp.timestamp()
            if self._ts_from is not None and ts < self._ts_from:
                return False
            if self._ts_to is not None and ts > self._ts_to:
                return False

        if self._search:
            needle = self._search.lower()
            hay = " ".join([
                str(ev.event_id), ev.name, ev.user, ev.computer,
                ev.source_ip, ev.cat, ev.desc,
            ]).lower()
            if needle not in hay:
                return False
        return True

    def set_search(self, text: str) -> None:
        self._search = text.strip()
        self.invalidateFilter()

    def set_category(self, cat: str) -> None:
        self._category = cat
        self.invalidateFilter()

    def set_sev(self, sev: str, enabled: bool) -> None:
        if enabled:
            self._sevs.add(sev)
        else:
            self._sevs.discard(sev)
        self.invalidateFilter()

    def set_time_range(self, ts_from: float | None, ts_to: float | None) -> None:
        self._ts_from = ts_from
        self._ts_to   = ts_to
        self.invalidateFilter()


# ── Background loader thread ──────────────────────────────────────────────────

class LoadWorker(QThread):
    batch_ready = Signal(list)   # list[ParsedEvent] — emitted in chunks
    finished    = Signal(int)    # total events loaded
    failed      = Signal(str)    # error message
    progress    = Signal(int)    # 0–100

    def __init__(self, filepath: str, file_type: str):
        super().__init__()
        self.filepath  = filepath
        self.file_type = file_type  # 'evtx' | 'csv'
        self._count    = 0

    def run(self) -> None:
        def on_batch(batch: list) -> None:
            self._count += len(batch)
            self.batch_ready.emit(batch)

        try:
            if self.file_type == "evtx":
                from ..core.parser_evtx import parse_evtx
                parse_evtx(self.filepath, progress_cb=self.progress.emit, batch_cb=on_batch)
            else:
                from ..core.parser_csv import parse_csv
                parse_csv(self.filepath, progress_cb=self.progress.emit, batch_cb=on_batch)
            self.finished.emit(self._count)
        except Exception as exc:
            self.failed.emit(str(exc))


# ── Background detection thread ───────────────────────────────────────────────

class DetectionWorker(QThread):
    finished = Signal(list)   # list[Detection]

    def __init__(self, events: list):
        super().__init__()
        self._events = events

    def run(self) -> None:
        results = detection_engine.analyze(self._events)
        self.finished.emit(results)


class StatsWorker(QThread):
    finished = Signal(str)   # rendered HTML

    def __init__(self, events: list):
        super().__init__()
        self._events = events

    def run(self) -> None:
        html = _build_stats_html(self._events)
        self.finished.emit(html)


# ── Detection card widget ─────────────────────────────────────────────────────

class DetectionCard(QFrame):
    clicked = Signal(object)  # emits Detection

    def __init__(self, detection: detection_engine.Detection, parent=None):
        super().__init__(parent)
        self.detection = detection
        self.setProperty("sev", detection.severity)
        self.setStyleSheet(self.styleSheet())  # apply QSS property
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip("Click to highlight contributing events")
        self._build(detection)

    def _build(self, d: detection_engine.Detection) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(4)

        # Header row: rule_id + severity badge + name
        header = QHBoxLayout()
        rule_lbl = QLabel(d.rule_id)
        rule_lbl.setStyleSheet(
            "color: #6c7086; font-size: 8pt; font-weight: bold; background: transparent;"
        )
        sev_lbl = QLabel(_SEV_LABEL.get(d.severity, d.severity.upper()))
        sev_col  = _SEV_FG.get(d.severity, QColor(0xCD, 0xD6, 0xF4))
        sev_lbl.setStyleSheet(
            f"color: {sev_col.name()}; font-size: 7pt; font-weight: bold; "
            f"background: transparent; border: 1px solid {sev_col.name()}; "
            "border-radius: 3px; padding: 0 4px;"
        )
        name_lbl = QLabel(d.name)
        name_lbl.setStyleSheet(
            "color: #cdd6f4; font-weight: bold; font-size: 9pt; background: transparent;"
        )
        name_lbl.setWordWrap(True)
        header.addWidget(rule_lbl)
        header.addSpacing(6)
        header.addWidget(sev_lbl)
        header.addStretch()

        # Timestamp
        ts_str = (
            d.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S")
            if d.timestamp else "—"
        )
        ts_lbl = QLabel(ts_str)
        ts_lbl.setStyleSheet("color: #6c7086; font-size: 8pt; background: transparent;")
        header.addWidget(ts_lbl)

        lay.addLayout(header)
        lay.addWidget(name_lbl)

        # Summary
        summary_lbl = QLabel(d.summary)
        summary_lbl.setWordWrap(True)
        summary_lbl.setStyleSheet(
            "color: #a6adc8; font-size: 8pt; background: transparent;"
        )
        lay.addWidget(summary_lbl)

        # Source / target
        if d.source or d.target:
            src_tgt = QLabel(
                f"<b>Src:</b> {d.source or '—'}  &nbsp;  <b>Target:</b> {d.target or '—'}"
            )
            src_tgt.setStyleSheet("color: #6c7086; font-size: 8pt; background: transparent;")
            lay.addWidget(src_tgt)

        # MITRE tags
        if d.mitre:
            mitre_row = QHBoxLayout()
            mitre_row.setSpacing(4)
            for tag in d.mitre:
                t = QLabel(tag)
                t.setStyleSheet(
                    "color: #7c3aed; font-size: 7pt; background: #1a1b2e; "
                    "border: 1px solid #7c3aed; border-radius: 3px; padding: 0 5px;"
                )
                mitre_row.addWidget(t)
            mitre_row.addStretch()
            lay.addLayout(mitre_row)

        # Events count badge
        if len(d.events) > 1:
            cnt = QLabel(f"{len(d.events)} contributing events")
            cnt.setStyleSheet("color: #45475a; font-size: 8pt; background: transparent;")
            lay.addWidget(cnt)

    def mousePressEvent(self, event) -> None:
        self.clicked.emit(self.detection)
        super().mousePressEvent(event)


# ── On-demand full field parser ───────────────────────────────────────────────

def _all_fields_from_event(ev: ParsedEvent) -> dict[str, str]:
    """
    Return every key-value field for an event.
    For EVTX events: re-parses the stored raw XML to get ALL fields.
    For CSV events:  returns the fields already stored in raw_fields.
    Called only when the user clicks a row — never during bulk loading.
    """
    if ev.raw_xml:
        import xml.etree.ElementTree as ET
        _NS = "http://schemas.microsoft.com/win/2004/08/events/event"
        _Q  = f"{{{_NS}}}"
        fields: dict[str, str] = {}
        try:
            root = ET.fromstring(ev.raw_xml)
            # System fields
            sys_el = root.find(f"{_Q}System")
            if sys_el is not None:
                for child in sys_el:
                    tag = child.tag.replace(_Q, "")
                    if child.text and child.text.strip():
                        fields[tag] = child.text.strip()
                    # Include attributes (e.g. TimeCreated SystemTime=...)
                    for attr, val in child.attrib.items():
                        if val:
                            fields[f"{tag}.{attr}"] = val
            # EventData / UserData — every Data element
            for section_tag in ("EventData", "UserData"):
                section = root.find(f"{_Q}{section_tag}")
                if section is not None:
                    for data in section.iter(f"{_Q}Data"):
                        name  = data.get("Name") or data.tag.replace(_Q, "")
                        value = (data.text or "").strip()
                        fields[name] = value
                    if section.text and section.text.strip():
                        fields["_text"] = section.text.strip()
        except Exception:
            fields = dict(ev.raw_fields)
        return fields
    # CSV path — raw_fields already contains all available columns
    return dict(ev.raw_fields)


# ── Statistics HTML builder ───────────────────────────────────────────────────

def _build_stats_html(events: list[ParsedEvent]) -> str:
    import html as _h
    from collections import Counter

    if not events:
        return (
            "<body style='background:#1e1e2e;color:#6c7086;font-family:Segoe UI;"
            "padding:40px;text-align:center'>Load a file to see statistics.</body>"
        )

    total = len(events)
    timestamps = [e.timestamp for e in events if e.timestamp]
    if timestamps:
        date_range = (
            f"{min(timestamps).strftime('%Y-%m-%d %H:%M')}"
            f" → {max(timestamps).strftime('%Y-%m-%d %H:%M')}"
        )
    else:
        date_range = "—"

    sev_counts   = Counter(e.sev for e in events)
    id_counts    = Counter((e.event_id, e.name) for e in events)
    top_ids      = id_counts.most_common(10)

    _SKIP_USERS = {"-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", ""}
    user_counts  = Counter(
        e.user for e in events
        if e.user not in _SKIP_USERS and not e.user.endswith("$")
    )
    top_users = user_counts.most_common(5)

    _SKIP_IPS = {"-", "::1", "127.0.0.1", ""}
    ip_counts = Counter(e.source_ip for e in events if e.source_ip not in _SKIP_IPS)
    top_ips   = ip_counts.most_common(5)

    hour_counts: Counter = Counter()
    for e in events:
        if e.timestamp:
            hour_counts[e.timestamp.strftime("%Y-%m-%d %H:00")] += 1
    sorted_hours = sorted(hour_counts.items())[-24:]

    _SEV_COLORS = {
        "critical": "#f38ba8", "high": "#fab387",
        "medium": "#f9e2af",   "low":  "#89b4fa", "info": "#6c7086",
    }

    def bar_row(label: str, count: int, max_count: int, color: str = "#7c3aed") -> str:
        pct  = int(count / max(max_count, 1) * 100)
        lbl  = _h.escape(str(label))
        return (
            f"<tr>"
            f"<td style='color:#a6adc8;font-size:8pt;padding:2px 8px 2px 0;"
            f"white-space:nowrap;max-width:260px;overflow:hidden;text-overflow:ellipsis'>{lbl}</td>"
            f"<td style='width:100%'><div style='background:#313244;border-radius:3px;height:14px'>"
            f"<div style='background:{color};border-radius:3px;height:14px;"
            f"width:{pct}%;min-width:2px'></div></div></td>"
            f"<td style='color:#6c7086;font-size:8pt;padding:2px 0 2px 8px;"
            f"white-space:nowrap;text-align:right'>{count:,}</td>"
            f"</tr>"
        )

    def section(title: str) -> str:
        return (
            f"<h3 style='color:#a6adc8;font-size:8pt;text-transform:uppercase;"
            f"letter-spacing:1px;margin:20px 0 8px 0;border-bottom:1px solid #313244;"
            f"padding-bottom:4px'>{title}</h3>"
        )

    sev_pills = " ".join(
        f"<span style='color:{_SEV_COLORS[s]};border:1px solid {_SEV_COLORS[s]};"
        f"border-radius:4px;padding:2px 8px;margin-right:4px;font-size:8pt;"
        f"font-weight:bold'>{sev_counts[s]:,} {s.upper()}</span>"
        for s in ("critical", "high", "medium", "low", "info")
        if sev_counts.get(s)
    )

    def table(rows_html: str) -> str:
        return f"<table width='100%' cellspacing='0' cellpadding='0'>{rows_html}</table>"

    max_id   = top_ids[0][1]   if top_ids   else 1
    max_usr  = top_users[0][1] if top_users else 1
    max_ip   = top_ips[0][1]   if top_ips   else 1
    max_hr   = max((c for _, c in sorted_hours), default=1)

    id_rows  = "".join(bar_row(f"{eid}  {ename}", cnt, max_id)             for (eid, ename), cnt in top_ids)
    usr_rows = "".join(bar_row(u, c, max_usr, "#89b4fa")                   for u, c in top_users)   or bar_row("—", 0, 1, "#89b4fa")
    ip_rows  = "".join(bar_row(ip, c, max_ip, "#a6e3a1")                   for ip, c in top_ips)    or bar_row("—", 0, 1, "#a6e3a1")
    hr_rows  = "".join(bar_row(h[-5:], c, max_hr, "#cba6f7")               for h, c in sorted_hours)

    return (
        "<!DOCTYPE html><html><body style='background:#1e1e2e;color:#cdd6f4;"
        "font-family:\"Segoe UI\",sans-serif;margin:12px;font-size:9pt'>"
        f"<div style='color:#6c7086;font-size:8pt;margin-bottom:8px'>"
        f"{total:,} events &nbsp;·&nbsp; {_h.escape(date_range)}</div>"
        f"<div style='margin-bottom:12px'>{sev_pills}</div>"
        f"{section('Top 10 Event IDs')}{table(id_rows)}"
        f"{section('Top 5 Users')}{table(usr_rows)}"
        f"{section('Top 5 Source IPs')}{table(ip_rows)}"
        f"{section('Events per Hour (last 24)')}{table(hr_rows)}"
        "</body></html>"
    )


# ── Main Window ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LogHawk — Security Event Log Analyzer")
        self.resize(1400, 860)
        self._events: list[ParsedEvent] = []
        self._detections: list[detection_engine.Detection] = []
        self._worker: LoadWorker | None = None
        self._det_worker: DetectionWorker | None = None
        self._stats_worker: StatsWorker | None = None
        self._highlighted_ids: set[int] = set()
        self._loading_fname: str = ""
        self._loaded_ts_min: float | None = None   # full range of loaded file
        self._loaded_ts_max: float | None = None

        # Debounce: search fires 300 ms after user stops typing
        self._search_timer = QTimer()
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(300)
        self._search_timer.timeout.connect(self._apply_search)

        # Debounce: date pickers fire 400 ms after user stops changing
        self._dt_timer = QTimer()
        self._dt_timer.setSingleShot(True)
        self._dt_timer.setInterval(400)
        self._dt_timer.timeout.connect(self._apply_dt_filter)

        self._load_style()
        self._build_ui()
        self._build_menu()
        self._update_status()

    # ── Stylesheet ─────────────────────────────────────────────────────────
    def _load_style(self) -> None:
        if getattr(sys, "frozen", False):
            qss_path = Path(sys._MEIPASS) / "resources" / "style.qss"  # type: ignore[attr-defined]
        else:
            qss_path = Path(__file__).parent.parent / "resources" / "style.qss"
        if qss_path.exists():
            QApplication.instance().setStyleSheet(qss_path.read_text(encoding="utf-8"))

        # Logo — loaded gracefully; if not present the default system icon is used
        from PySide6.QtGui import QIcon
        if getattr(sys, "frozen", False):
            logo_path = Path(sys._MEIPASS) / "resources" / "logo.png"  # type: ignore[attr-defined]
        else:
            logo_path = Path(__file__).parent.parent / "resources" / "logo.png"
        if logo_path.exists():
            icon = QIcon(str(logo_path))
            QApplication.instance().setWindowIcon(icon)
            self.setWindowIcon(icon)

    # ── UI construction ────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        # ── Toolbar ──────────────────────────────────────────────────────
        tb = QToolBar("Main", self)
        tb.setMovable(False)
        self.addToolBar(tb)

        btn_open_evtx = tb.addAction("Open EVTX")
        btn_open_evtx.triggered.connect(self._open_evtx)
        btn_open_csv  = tb.addAction("Open CSV")
        btn_open_csv.triggered.connect(self._open_csv)
        tb.addSeparator()
        btn_export = tb.addAction("Export CSV")
        btn_export.triggered.connect(self._export_csv)
        tb.addSeparator()

        # Search
        search_lbl = QLabel("Search:")
        search_lbl.setStyleSheet("color:#a6adc8; background:transparent; padding: 0 4px;")
        tb.addWidget(search_lbl)
        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText("Event ID, name, user, IP…")
        self._search_box.setFixedWidth(220)
        self._search_box.textChanged.connect(lambda _: self._search_timer.start())
        tb.addWidget(self._search_box)

        # Clear search button
        btn_clear = tb.addAction("✕")
        btn_clear.setToolTip("Clear search")
        btn_clear.triggered.connect(self._search_box.clear)
        tb.addSeparator()

        # Category filter
        cat_lbl = QLabel("Category:")
        cat_lbl.setStyleSheet("color:#a6adc8; background:transparent; padding: 0 4px;")
        tb.addWidget(cat_lbl)
        self._cat_combo = QComboBox()
        cats = ["All"] + [c.title() for c in all_categories()]
        self._cat_combo.addItems(cats)
        self._cat_combo.currentTextChanged.connect(self._on_category)
        tb.addWidget(self._cat_combo)
        tb.addSeparator()

        # Severity checkboxes
        sev_lbl = QLabel("Severity:")
        sev_lbl.setStyleSheet("color:#a6adc8; background:transparent; padding: 0 4px;")
        tb.addWidget(sev_lbl)
        self._sev_checks: dict[str, QCheckBox] = {}
        for sev in ("critical", "high", "medium", "low", "info"):
            cb = QCheckBox(_SEV_LABEL[sev])
            cb.setChecked(True)
            cb.setStyleSheet(
                f"color: {_SEV_FG[sev].name()}; font-weight: bold; font-size: 8pt;"
            )
            cb.stateChanged.connect(lambda state, s=sev: self._on_sev_toggle(s, state))
            self._sev_checks[sev] = cb
            tb.addWidget(cb)

        # ── Progress bar (hidden until loading) ──────────────────────────
        tb.addSeparator()
        self._load_label = QLabel()
        self._load_label.setStyleSheet(
            "color: #a6adc8; font-size: 8pt; background: transparent; padding: 0 4px;"
        )
        self._load_label.setVisible(False)
        tb.addWidget(self._load_label)

        self._progress = QProgressBar()
        self._progress.setFixedWidth(200)
        self._progress.setFixedHeight(18)
        self._progress.setRange(0, 100)
        self._progress.setFormat("%p%")
        self._progress.setTextVisible(True)
        self._progress.setVisible(False)
        tb.addWidget(self._progress)

        # ── Time-range toolbar ───────────────────────────────────────────
        tb2 = QToolBar("Zeitraum", self)
        tb2.setMovable(False)
        self.addToolBar(tb2)

        for lbl_text in ("Von:",):
            lbl = QLabel(lbl_text)
            lbl.setStyleSheet("color:#a6adc8; background:transparent; padding: 0 4px;")
            tb2.addWidget(lbl)

        self._dt_from_picker = QDateTimeEdit()
        self._dt_from_picker.setDisplayFormat("dd.MM.yyyy  HH:mm")
        self._dt_from_picker.setCalendarPopup(True)
        self._dt_from_picker.setFixedWidth(160)
        self._dt_from_picker.setToolTip("Frühester Zeitpunkt (Von)")
        self._dt_from_picker.dateTimeChanged.connect(lambda _: self._dt_timer.start())
        tb2.addWidget(self._dt_from_picker)

        arrow_lbl = QLabel("→")
        arrow_lbl.setStyleSheet("color:#45475a; background:transparent; padding: 0 6px; font-size:11pt;")
        tb2.addWidget(arrow_lbl)

        bis_lbl = QLabel("Bis:")
        bis_lbl.setStyleSheet("color:#a6adc8; background:transparent; padding: 0 4px;")
        tb2.addWidget(bis_lbl)

        self._dt_to_picker = QDateTimeEdit()
        self._dt_to_picker.setDisplayFormat("dd.MM.yyyy  HH:mm")
        self._dt_to_picker.setCalendarPopup(True)
        self._dt_to_picker.setFixedWidth(160)
        self._dt_to_picker.setToolTip("Spätester Zeitpunkt (Bis)")
        self._dt_to_picker.dateTimeChanged.connect(lambda _: self._dt_timer.start())
        tb2.addWidget(self._dt_to_picker)

        tb2.addSeparator()
        btn_clear_dt = tb2.addAction("Filter zurücksetzen ✕")
        btn_clear_dt.setToolTip("Zeitraum-Filter löschen")
        btn_clear_dt.triggered.connect(self._clear_dt_filter)

        # Disable until a file is loaded
        self._tb2 = tb2
        tb2.setEnabled(False)

        # ── Empty state ───────────────────────────────────────────────────
        empty_widget = QWidget()
        ev_lay = QVBoxLayout(empty_widget)
        ev_lay.setAlignment(Qt.AlignCenter)
        ev_lay.setSpacing(12)
        title_lbl = QLabel("LogHawk")
        title_lbl.setAlignment(Qt.AlignCenter)
        title_lbl.setStyleSheet(
            "font-size: 28pt; font-weight: bold; color: #7c3aed; background: transparent;"
        )
        hint_lbl = QLabel(
            "Open a Windows Security Event Log to get started.\n\n"
            "  File → Open EVTX File   (.evtx — Windows only)\n"
            "  File → Open CSV File      (exported from Event Viewer)"
        )
        hint_lbl.setAlignment(Qt.AlignCenter)
        hint_lbl.setStyleSheet(
            "font-size: 10pt; color: #6c7086; background: transparent; line-height: 1.8;"
        )
        ev_lay.addWidget(title_lbl)
        ev_lay.addWidget(hint_lbl)

        # ── Central splitter ──────────────────────────────────────────────
        splitter = QSplitter(Qt.Vertical)

        # Stack: 0 = empty state, 1 = events splitter
        self._stack = QStackedWidget()
        self._stack.addWidget(empty_widget)
        self._stack.addWidget(splitter)
        self.setCentralWidget(self._stack)

        # Events table
        self._model = EventTableModel()
        self._proxy = EventFilter()
        self._proxy.setSourceModel(self._model)

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(QTableView.SelectRows)
        self._table.setSelectionMode(QTableView.SingleSelection)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setWordWrap(False)
        self._table.verticalHeader().setDefaultSectionSize(22)
        for i, w in enumerate(_COL_W):
            self._table.setColumnWidth(i, w)
        self._table.selectionModel().currentRowChanged.connect(self._on_row_selected)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_table_context_menu)
        splitter.addWidget(self._table)

        # Details panel (tab widget)
        self._detail_tabs = QTabWidget()
        self._detail_tabs.setFixedHeight(230)
        self._detail_summary = QTextBrowser()
        self._detail_summary.setOpenExternalLinks(False)
        self._detail_raw = QTextBrowser()
        self._detail_raw.setFont(QFont("Cascadia Code, Consolas", 9))
        self._detail_stats = QTextBrowser()
        self._detail_stats.setOpenExternalLinks(False)
        self._detail_tabs.addTab(self._detail_summary, "Event Details")
        self._detail_tabs.addTab(self._detail_raw,     "Raw Fields")
        self._detail_tabs.addTab(self._detail_stats,   "Statistics")
        splitter.addWidget(self._detail_tabs)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)

        # ── Detections dock ───────────────────────────────────────────────
        dock = QDockWidget("Detections", self)
        dock.setAllowedAreas(Qt.RightDockWidgetArea | Qt.LeftDockWidgetArea)
        dock.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable)
        dock.setMinimumWidth(340)

        dock_container = QWidget()
        dock_lay = QVBoxLayout(dock_container)
        dock_lay.setContentsMargins(0, 0, 0, 0)
        dock_lay.setSpacing(0)

        self._det_header_lbl = QLabel("No detections")
        self._det_header_lbl.setStyleSheet(
            "padding: 6px 10px; color: #6c7086; font-size: 8pt; background: #181825; "
            "border-bottom: 1px solid #313244;"
        )
        dock_lay.addWidget(self._det_header_lbl)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._det_panel = QWidget()
        self._det_layout = QVBoxLayout(self._det_panel)
        self._det_layout.setContentsMargins(6, 6, 6, 6)
        self._det_layout.setSpacing(6)
        self._det_layout.addStretch()
        scroll.setWidget(self._det_panel)
        dock_lay.addWidget(scroll)

        dock.setWidget(dock_container)
        self.addDockWidget(Qt.RightDockWidgetArea, dock)

        # ── Status bar ────────────────────────────────────────────────────
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status_label = QLabel()
        self._status.addWidget(self._status_label)

    # ── Menu ───────────────────────────────────────────────────────────────
    def _build_menu(self) -> None:
        mb = self.menuBar()

        fm = mb.addMenu("File")
        fm.addAction("Open EVTX File…",         self._open_evtx,                QKeySequence("Ctrl+O"))
        fm.addAction("Open CSV File…",          self._open_csv,                 QKeySequence("Ctrl+Shift+O"))
        fm.addSeparator()
        fm.addAction("Export Events CSV…",      self._export_csv,               QKeySequence("Ctrl+E"))
        fm.addAction("Export Detection Report…",self._export_detection_report,  QKeySequence("Ctrl+Shift+E"))
        fm.addSeparator()
        fm.addAction("Exit",                    self.close,                     QKeySequence("Alt+F4"))

        vm = mb.addMenu("View")
        vm.addAction("Clear Events",     self._clear_events)
        vm.addAction("Run Detections",   self._run_detections)

        hm = mb.addMenu("Help")
        hm.addAction("About LogHawk",    self._about)

    # ── File loading ────────────────────────────────────────────────────────
    def _open_evtx(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Windows Event Log", "", "Event Log Files (*.evtx);;All Files (*)"
        )
        if path:
            self._load_file(path, "evtx")

    def _open_csv(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open CSV Event Export", "", "CSV Files (*.csv);;All Files (*)"
        )
        if path:
            self._load_file(path, "csv")

    def _load_file(self, path: str, file_type: str) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.requestInterruption()
            self._worker.wait(2000)

        self._model.clear()
        self._events = []
        self._clear_detections()
        self._loading_fname = Path(path).name
        self._progress.setValue(0)
        self._progress.setVisible(True)
        self._load_label.setText(f"Loading  {self._loading_fname}")
        self._load_label.setVisible(True)
        self._status_label.setText(f"Loading {self._loading_fname}…")

        self._worker = LoadWorker(path, file_type)
        self._worker.batch_ready.connect(self._on_batch_ready)
        self._worker.finished.connect(self._on_load_finished)
        self._worker.failed.connect(self._on_load_error)
        self._worker.progress.connect(self._progress.setValue)
        self._worker.progress.connect(self._on_progress_update)
        self._worker.start()

    def _on_progress_update(self, _value: int) -> None:
        count = len(self._events)
        if count:
            self._load_label.setText(f"Loading  {self._loading_fname}  —  {count:,} events")

    def _on_batch_ready(self, events: list[ParsedEvent]) -> None:
        self._events.extend(events)
        self._model.append_batch(events)
        self._load_label.setText(
            f"Loading  {self._loading_fname}  —  {len(self._events):,} events"
        )

    def _on_load_finished(self, total: int) -> None:
        self._progress.setValue(100)
        self._load_label.setText(f"Done  —  {total:,} events  |  Running detections…")
        self.setWindowTitle(f"LogHawk — {total:,} events loaded")
        self._stack.setCurrentIndex(1)   # show events view
        self._set_dt_range_from_events()  # populate pickers, enable toolbar
        self._tb2.setEnabled(True)
        self._update_status()

        # Both detection and stats run in background — UI stays live
        snapshot = list(self._events)

        self._det_worker = DetectionWorker(snapshot)
        self._det_worker.finished.connect(self._on_detections_ready)
        self._det_worker.start()

        self._stats_worker = StatsWorker(snapshot)
        self._stats_worker.finished.connect(self._detail_stats.setHtml)
        self._stats_worker.start()

        QTimer.singleShot(1800, lambda: (
            self._progress.setVisible(False),
            self._load_label.setVisible(False),
        ))

    def _on_detections_ready(self, detections: list) -> None:
        self._detections = detections
        self._populate_detections_dock()
        self._update_status()

    def _on_load_error(self, msg: str) -> None:
        self._progress.setVisible(False)
        self._load_label.setVisible(False)
        QMessageBox.critical(self, "Load Error", msg)
        self._update_status()

    # ── Detections ──────────────────────────────────────────────────────────
    def _run_detections(self) -> None:
        """Manual re-run triggered from the View menu — runs in background."""
        self._clear_detections()
        if not self._events:
            return
        self._det_header_lbl.setText("Running detections…")
        self._det_worker = DetectionWorker(list(self._events))
        self._det_worker.finished.connect(self._on_detections_ready)
        self._det_worker.start()

    def _populate_detections_dock(self) -> None:
        """Rebuild detection cards from self._detections (call after analysis)."""
        self._clear_detections()
        if not self._detections:
            return

        sev_counts: dict[str, int] = {}
        for d in self._detections:
            sev_counts[d.severity] = sev_counts.get(d.severity, 0) + 1

        parts = []
        for sev in ("critical", "high", "medium", "low"):
            cnt = sev_counts.get(sev, 0)
            if cnt:
                col = _SEV_FG[sev].name()
                parts.append(f'<span style="color:{col};font-weight:bold">{cnt} {sev.upper()}</span>')
        header_html = " &nbsp;·&nbsp; ".join(parts) if parts else "No detections"
        self._det_header_lbl.setText(header_html)
        self._det_header_lbl.setTextFormat(Qt.RichText)

        count = self._det_layout.count()
        if count > 0:
            stretch_item = self._det_layout.takeAt(count - 1)
            del stretch_item

        for d in self._detections:
            card = DetectionCard(d)
            card.clicked.connect(self._on_detection_clicked)
            self._det_layout.addWidget(card)

        self._det_layout.addStretch()

    def _clear_detections(self) -> None:
        while self._det_layout.count() > 0:
            item = self._det_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._det_layout.addStretch()
        self._det_header_lbl.setText("No detections")
        self._detections = []

    def _on_detection_clicked(self, detection: detection_engine.Detection) -> None:
        ids = {id(e) for e in detection.events}
        if not ids:
            return
        # Scroll table to first matching event
        for row in range(self._model.rowCount()):
            ev = self._model._events[row]
            if id(ev) in ids:
                proxy_idx = self._proxy.mapFromSource(self._model.index(row, 0))
                if proxy_idx.isValid():
                    self._table.scrollTo(proxy_idx)
                    self._table.selectRow(proxy_idx.row())
                break

    # ── Table selection → details ────────────────────────────────────────────
    def _on_row_selected(self, current: QModelIndex, _prev: QModelIndex) -> None:
        src_idx = self._proxy.mapToSource(current)
        if not src_idx.isValid():
            return
        ev: ParsedEvent = self._model._events[src_idx.row()]
        self._show_details(ev)

    def _show_details(self, ev: ParsedEvent) -> None:
        sev_col = _SEV_FG.get(ev.sev, QColor(0xCD, 0xD6, 0xF4)).name()
        ts_str  = (
            ev.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
            if ev.timestamp else "—"
        )
        mitre_html = " ".join(
            f'<span style="color:#7c3aed;border:1px solid #7c3aed;border-radius:3px;padding:1px 5px">{m}</span>'
            for m in ev.mitre
        ) or "—"

        html = f"""
        <table cellspacing="0" cellpadding="3" width="100%">
        <tr><td width="120" style="color:#6c7086">Event ID</td>
            <td><b style="font-size:11pt">{ev.event_id}</b>
                &nbsp;&nbsp;<span style="color:{sev_col};border:1px solid {sev_col};
                border-radius:3px;padding:1px 5px;font-size:8pt">{_SEV_LABEL.get(ev.sev, ev.sev.upper())}</span>
            </td></tr>
        <tr><td style="color:#6c7086">Name</td><td>{ev.name}</td></tr>
        <tr><td style="color:#6c7086">Timestamp</td><td>{ts_str}</td></tr>
        <tr><td style="color:#6c7086">Computer</td><td>{ev.computer or '—'}</td></tr>
        <tr><td style="color:#6c7086">User</td><td>{ev.domain or '—'}\\{ev.user or '—'}</td></tr>
        <tr><td style="color:#6c7086">Source IP</td><td>{ev.source_ip or '—'}</td></tr>
        <tr><td style="color:#6c7086">Logon Type</td><td>{ev.logon_type or '—'}</td></tr>
        <tr><td style="color:#6c7086">Auth Package</td><td>{ev.auth_package or '—'}</td></tr>
        <tr><td style="color:#6c7086">Category</td><td>{ev.cat.title()}</td></tr>
        <tr><td style="color:#6c7086">MITRE</td><td>{mitre_html}</td></tr>
        <tr><td colspan="2" style="padding-top:6px"><hr style="border-color:#313244"></td></tr>
        <tr><td style="color:#6c7086;vertical-align:top">Description</td>
            <td style="color:#a6adc8">{ev.desc}</td></tr>
        </table>
        """
        self._detail_summary.setHtml(html)

        # Raw Fields tab — parse full XML on demand so the user sees every field
        all_fields = _all_fields_from_event(ev)
        if all_fields:
            rows = "\n".join(f"  {k:<40} {v}" for k, v in sorted(all_fields.items()))
            self._detail_raw.setPlainText(
                f"EventID:  {ev.event_id}\nRecord:   {ev.record_id}\n"
                f"Computer: {ev.computer}\nChannel:  Security\n\n{rows}"
            )
        else:
            self._detail_raw.setPlainText("(no field data)")

    # ── Filters ─────────────────────────────────────────────────────────────
    def _apply_search(self) -> None:
        self._proxy.set_search(self._search_box.text())
        self._update_status()

    def _on_search(self, text: str) -> None:   # kept for direct calls (e.g. context menu)
        self._search_timer.stop()
        self._proxy.set_search(text)
        self._update_status()

    def _on_category(self, cat: str) -> None:
        self._proxy.set_category(cat.lower() if cat != "All" else "All")
        self._update_status()

    def _on_sev_toggle(self, sev: str, state: int) -> None:
        self._proxy.set_sev(sev, bool(state))
        self._update_status()

    # ── Export ──────────────────────────────────────────────────────────────
    def _export_csv(self) -> None:
        if not self._events:
            QMessageBox.information(self, "Export", "No events loaded.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Events as CSV", "loghawk_export.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        fields = ["timestamp", "event_id", "name", "cat", "sev", "user", "domain",
                  "computer", "source_ip", "logon_type", "auth_package", "mitre", "desc"]
        visible_events: list[ParsedEvent] = []
        for row in range(self._proxy.rowCount()):
            src = self._proxy.mapToSource(self._proxy.index(row, 0))
            visible_events.append(self._model._events[src.row()])

        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for ev in visible_events:
                ts = (
                    ev.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S")
                    if ev.timestamp else ""
                )
                writer.writerow({
                    "timestamp":    ts,
                    "event_id":     ev.event_id,
                    "name":         ev.name,
                    "cat":          ev.cat,
                    "sev":          ev.sev,
                    "user":         ev.user,
                    "domain":       ev.domain,
                    "computer":     ev.computer,
                    "source_ip":    ev.source_ip,
                    "logon_type":   ev.logon_type,
                    "auth_package": ev.auth_package,
                    "mitre":        "; ".join(ev.mitre),
                    "desc":         ev.desc,
                })
        QMessageBox.information(
            self, "Export Complete",
            f"Exported {len(visible_events):,} events to:\n{path}"
        )

    # ── Date / time filter ───────────────────────────────────────────────────
    def _set_dt_range_from_events(self) -> None:
        """Auto-populate pickers with the actual event range. No filter applied."""
        timestamps = [e.timestamp.timestamp() for e in self._events if e.timestamp]
        if not timestamps:
            return
        self._loaded_ts_min = min(timestamps)
        self._loaded_ts_max = max(timestamps)

        for picker, ts in (
            (self._dt_from_picker, self._loaded_ts_min),
            (self._dt_to_picker,   self._loaded_ts_max),
        ):
            picker.blockSignals(True)
            dt = datetime.fromtimestamp(ts)
            picker.setDateTime(
                QDateTime(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)
            )
            picker.blockSignals(False)

        # Set filter bounds to full range = all events pass = no visible change
        self._proxy._ts_from = self._loaded_ts_min
        self._proxy._ts_to   = self._loaded_ts_max

    def _apply_dt_filter(self) -> None:
        """Read picker values and apply to the proxy filter."""
        def _to_ts(picker: QDateTimeEdit) -> float:
            qdt = picker.dateTime()
            dt  = datetime(
                qdt.date().year(), qdt.date().month(), qdt.date().day(),
                qdt.time().hour(), qdt.time().minute(), qdt.time().second(),
            )
            return dt.timestamp()

        self._proxy.set_time_range(_to_ts(self._dt_from_picker), _to_ts(self._dt_to_picker))
        self._update_status()

    def _clear_dt_filter(self) -> None:
        """Reset pickers to full loaded range and remove the filter."""
        if self._loaded_ts_min is None:
            return
        self._set_dt_range_from_events()
        # Full range = show all events, but still call invalidateFilter so
        # any previous tighter range is released.
        self._proxy.set_time_range(self._loaded_ts_min, self._loaded_ts_max)
        self._update_status()

    # ── Right-click context menu ─────────────────────────────────────────────
    def _on_table_context_menu(self, pos: QPoint) -> None:
        idx = self._table.indexAt(pos)
        if not idx.isValid():
            return
        src_idx = self._proxy.mapToSource(idx)
        ev: ParsedEvent = self._model._events[src_idx.row()]

        menu = QMenu(self)

        if ev.user and ev.user not in ("-", ""):
            menu.addAction(
                f"Filter by User:  {ev.user}",
                lambda u=ev.user: self._search_box.setText(u),
            )
        if ev.source_ip and ev.source_ip not in ("-", ""):
            menu.addAction(
                f"Filter by IP:  {ev.source_ip}",
                lambda ip=ev.source_ip: self._search_box.setText(ip),
            )
        menu.addAction(
            f"Filter by Event ID:  {ev.event_id}",
            lambda eid=str(ev.event_id): self._search_box.setText(eid),
        )
        menu.addSeparator()
        menu.addAction("Copy Row", lambda e=ev: self._copy_event_row(e))
        menu.addSeparator()
        menu.addAction("Clear Filter", self._search_box.clear)

        menu.exec(self._table.viewport().mapToGlobal(pos))

    def _copy_event_row(self, ev: ParsedEvent) -> None:
        ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "—"
        QApplication.clipboard().setText(
            f"{ts}\t{ev.event_id}\t{ev.name}\t{ev.sev.upper()}\t"
            f"{ev.user}\t{ev.computer}\t{ev.source_ip}"
        )

    # ── Statistics ────────────────────────────────────────────────────────────
    def _update_stats(self) -> None:
        if not self._events:
            return
        self._stats_worker = StatsWorker(list(self._events))
        self._stats_worker.finished.connect(self._detail_stats.setHtml)
        self._stats_worker.start()

    # ── Export detection report ───────────────────────────────────────────────
    def _export_detection_report(self) -> None:
        if not self._detections:
            QMessageBox.information(self, "Export", "No detections to export.\nLoad a file first.")
            return
        path, sel = QFileDialog.getSaveFileName(
            self, "Export Detection Report",
            "loghawk_detections.html",
            "HTML Report (*.html);;CSV (*.csv)",
        )
        if not path:
            return
        if path.lower().endswith(".csv"):
            self._export_detections_csv(path)
        else:
            self._export_detections_html(path)

    def _export_detections_csv(self, path: str) -> None:
        fields = ["rule_id", "name", "severity", "timestamp", "source",
                  "target", "mitre", "summary", "event_count"]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for d in self._detections:
                ts = d.timestamp.strftime("%Y-%m-%d %H:%M:%S") if d.timestamp else ""
                w.writerow({
                    "rule_id":     d.rule_id,
                    "name":        d.name,
                    "severity":    d.severity,
                    "timestamp":   ts,
                    "source":      d.source,
                    "target":      d.target,
                    "mitre":       "; ".join(d.mitre),
                    "summary":     d.summary,
                    "event_count": len(d.events),
                })
        QMessageBox.information(self, "Export Complete", f"Detection report saved to:\n{path}")

    def _export_detections_html(self, path: str) -> None:
        import html as _h
        _C = {"critical":"#f38ba8","high":"#fab387","medium":"#f9e2af","low":"#89b4fa","info":"#6c7086"}
        rows = ""
        for d in self._detections:
            ts   = d.timestamp.strftime("%Y-%m-%d %H:%M:%S") if d.timestamp else "—"
            col  = _C.get(d.severity, "#cdd6f4")
            mit  = " ".join(
                f"<span style='color:#7c3aed;border:1px solid #7c3aed;border-radius:3px;"
                f"padding:1px 5px;font-size:11px'>{m}</span>"
                for m in d.mitre
            )
            rows += (
                f"<tr>"
                f"<td style='color:{col};font-weight:bold;white-space:nowrap'>{d.severity.upper()}</td>"
                f"<td style='color:#6c7086;white-space:nowrap'>{d.rule_id}</td>"
                f"<td style='font-weight:bold'>{_h.escape(d.name)}</td>"
                f"<td style='color:#a6adc8'>{_h.escape(d.summary)}</td>"
                f"<td style='color:#6c7086;white-space:nowrap'>{ts}</td>"
                f"<td>{mit}</td>"
                f"<td style='color:#6c7086;white-space:nowrap'>{_h.escape(d.source)}</td>"
                f"</tr>"
            )
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        content = (
            "<!DOCTYPE html><html><head><style>"
            "body{background:#1a1b2e;color:#cdd6f4;font-family:'Segoe UI',sans-serif;padding:24px}"
            "h1{color:#7c3aed;margin-bottom:4px}"
            "p{color:#6c7086;font-size:13px;margin-top:0}"
            "table{width:100%;border-collapse:collapse;margin-top:16px}"
            "th{background:#181825;color:#a6adc8;text-align:left;padding:8px 12px;"
            "font-size:11px;text-transform:uppercase;letter-spacing:0.5px}"
            "td{padding:8px 12px;border-bottom:1px solid #313244;vertical-align:top;font-size:13px}"
            "tr:hover{background:#2a2a3d}"
            "</style></head><body>"
            f"<h1>LogHawk — Detection Report</h1>"
            f"<p>Generated: {now} &nbsp;·&nbsp; {len(self._detections)} detections</p>"
            "<table><tr><th>Severity</th><th>Rule</th><th>Detection</th>"
            "<th>Summary</th><th>Time</th><th>MITRE</th><th>Source</th></tr>"
            f"{rows}</table></body></html>"
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        QMessageBox.information(self, "Export Complete", f"Detection report saved to:\n{path}")

    # ── Misc ─────────────────────────────────────────────────────────────────
    def _clear_events(self) -> None:
        self._model.clear()
        self._events = []
        self._clear_detections()
        self._detail_summary.clear()
        self._detail_raw.clear()
        self._detail_stats.setHtml("")
        self._stack.setCurrentIndex(0)   # back to empty state
        self._tb2.setEnabled(False)
        self._proxy.set_time_range(None, None)
        self.setWindowTitle("LogHawk — Security Event Log Analyzer")
        self._update_status()

    def _update_status(self) -> None:
        total    = self._model.rowCount()
        visible  = self._proxy.rowCount()
        det_cnt  = len(self._detections)
        crit_cnt = sum(1 for d in self._detections if d.severity == "critical")
        high_cnt = sum(1 for d in self._detections if d.severity == "high")
        parts = [f"{visible:,} of {total:,} events"]
        if det_cnt:
            parts.append(f"{det_cnt} detections")
        if crit_cnt:
            parts.append(f"<span style='color:#f38ba8'>{crit_cnt} CRITICAL</span>")
        if high_cnt:
            parts.append(f"<span style='color:#fab387'>{high_cnt} HIGH</span>")
        self._status_label.setText("  |  ".join(parts))

    def _about(self) -> None:
        QMessageBox.about(
            self,
            "About LogHawk",
            "<h2>LogHawk</h2>"
            "<p>Windows Security Event Log Analyzer &amp; Threat Detector</p>"
            "<p><b>Capabilities:</b><br>"
            "• 300+ Security Event ID descriptions<br>"
            "• 19 automated threat detection rules<br>"
            "• MITRE ATT&amp;CK mapping per event and detection<br>"
            "• Brute-force, Kerberoasting, DCSync, PtH, persistence detection<br>"
            "• EVTX and CSV ingestion | CSV export</p>"
            "<p style='color:#6c7086'>Built with Python 3.11 + PySide6</p>",
        )
