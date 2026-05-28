"""LogHawk — main application window."""

from __future__ import annotations

import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
    QThread,
    Signal,
)
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDockWidget,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QScrollArea,
    QSizePolicy,
    QSplitter,
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


# ── Background loader thread ──────────────────────────────────────────────────

class LoadWorker(QThread):
    batch_ready = Signal(list)     # list[ParsedEvent]
    finished    = Signal(int)      # total loaded
    failed      = Signal(str)      # error message
    progress    = Signal(int)      # 0–100

    def __init__(self, filepath: str, file_type: str):
        super().__init__()
        self.filepath  = filepath
        self.file_type = file_type  # 'evtx' | 'csv'

    def run(self) -> None:
        try:
            if self.file_type == "evtx":
                from ..core.parser_evtx import parse_evtx
                events = parse_evtx(self.filepath, progress_cb=self.progress.emit)
            else:
                from ..core.parser_csv import parse_csv
                events = parse_csv(self.filepath, progress_cb=self.progress.emit)
            self.batch_ready.emit(events)
            self.finished.emit(len(events))
        except Exception as exc:
            self.failed.emit(str(exc))


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


# ── Main Window ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LogHawk — Security Event Log Analyzer")
        self.resize(1400, 860)
        self._events: list[ParsedEvent] = []
        self._detections: list[detection_engine.Detection] = []
        self._worker: LoadWorker | None = None
        self._highlighted_ids: set[int] = set()

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
        self._search_box.textChanged.connect(self._on_search)
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
        self._progress = QProgressBar()
        self._progress.setFixedWidth(160)
        self._progress.setFixedHeight(4)
        self._progress.setRange(0, 100)
        self._progress.setVisible(False)
        tb.addSeparator()
        tb.addWidget(self._progress)

        # ── Central splitter ──────────────────────────────────────────────
        splitter = QSplitter(Qt.Vertical, self)
        self.setCentralWidget(splitter)

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
        splitter.addWidget(self._table)

        # Details panel (tab widget)
        self._detail_tabs = QTabWidget()
        self._detail_tabs.setFixedHeight(210)
        self._detail_summary = QTextBrowser()
        self._detail_summary.setOpenExternalLinks(False)
        self._detail_raw = QTextBrowser()
        self._detail_raw.setFont(QFont("Cascadia Code, Consolas", 9))
        self._detail_tabs.addTab(self._detail_summary, "Event Details")
        self._detail_tabs.addTab(self._detail_raw,     "Raw Fields")
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
        fm.addAction("Open EVTX File…",  self._open_evtx,  QKeySequence("Ctrl+O"))
        fm.addAction("Open CSV File…",   self._open_csv,   QKeySequence("Ctrl+Shift+O"))
        fm.addSeparator()
        fm.addAction("Export CSV…",      self._export_csv, QKeySequence("Ctrl+E"))
        fm.addSeparator()
        fm.addAction("Exit",             self.close,       QKeySequence("Alt+F4"))

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
        self._progress.setValue(0)
        self._progress.setVisible(True)
        fname = Path(path).name
        self._status_label.setText(f"Loading {fname}…")

        self._worker = LoadWorker(path, file_type)
        self._worker.batch_ready.connect(self._on_batch_ready)
        self._worker.finished.connect(self._on_load_finished)
        self._worker.failed.connect(self._on_load_error)
        self._worker.progress.connect(self._progress.setValue)
        self._worker.start()

    def _on_batch_ready(self, events: list[ParsedEvent]) -> None:
        self._events.extend(events)
        self._model.append_batch(events)

    def _on_load_finished(self, total: int) -> None:
        self._progress.setVisible(False)
        self.setWindowTitle(f"LogHawk — {total:,} events loaded")
        self._run_detections()
        self._update_status()

    def _on_load_error(self, msg: str) -> None:
        self._progress.setVisible(False)
        QMessageBox.critical(self, "Load Error", msg)
        self._update_status()

    # ── Detections ──────────────────────────────────────────────────────────
    def _run_detections(self) -> None:
        self._clear_detections()
        if not self._events:
            return
        self._detections = detection_engine.analyze(self._events)
        sev_counts: dict[str, int] = {}
        for d in self._detections:
            sev_counts[d.severity] = sev_counts.get(d.severity, 0) + 1

        # Build header summary
        parts = []
        for sev in ("critical", "high", "medium", "low"):
            cnt = sev_counts.get(sev, 0)
            if cnt:
                col = _SEV_FG[sev].name()
                parts.append(f'<span style="color:{col};font-weight:bold">{cnt} {sev.upper()}</span>')
        header_html = " &nbsp;·&nbsp; ".join(parts) if parts else "No detections"
        self._det_header_lbl.setText(header_html)
        self._det_header_lbl.setTextFormat(Qt.RichText)

        # Build cards (remove old stretch first)
        count = self._det_layout.count()
        if count > 0:
            stretch_item = self._det_layout.takeAt(count - 1)
            del stretch_item

        for d in self._detections:
            card = DetectionCard(d)
            card.clicked.connect(self._on_detection_clicked)
            self._det_layout.addWidget(card)

        self._det_layout.addStretch()
        self._update_status()

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

        # Raw fields tab
        if ev.raw_fields:
            rows = "\n".join(
                f"  {k:<35} {v}" for k, v in sorted(ev.raw_fields.items())
            )
            self._detail_raw.setPlainText(f"EventID: {ev.event_id}\nRecord:  {ev.record_id}\n\n{rows}")
        else:
            self._detail_raw.setPlainText("(no raw fields)")

    # ── Filters ─────────────────────────────────────────────────────────────
    def _on_search(self, text: str) -> None:
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

    # ── Misc ─────────────────────────────────────────────────────────────────
    def _clear_events(self) -> None:
        self._model.clear()
        self._events = []
        self._clear_detections()
        self._detail_summary.clear()
        self._detail_raw.clear()
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
