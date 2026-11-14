"""Main Window for OSINT Recon Studio.

Provides a unified high-speed Windows interface organized into 5 Consolidated Category Hubs:
  Hub 1: 🏛️ Executive Overview & Low-RAM Local AI Intelligence Analyst
  Hub 2: 🌐 Domain & Infrastructure (DNS, CT Subdomains, Dangling CNAMEs, RDAP)
  Hub 3: ☁️ Network, Cloud & Threat Exposure (Shodan InternetDB, IP Intel, URLScan/OTX)
  Hub 4: 🛡️ Web & Email Defensive Posture (Security Headers, Email Spoofing, Tech Stack, Wayback)
  Hub 5: 👤 Personal Data & Digital Footprint (Breaches, Phone Carrier, 40+ Social Matrix, Permutator, EXIF Scrubber)
  Utility: 📜 Live Activity Logs & Raw JSON Inspector
"""

from __future__ import annotations

import datetime
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

from PySide6.QtCore import QThreadPool, Qt, QUrl
from PySide6.QtGui import QAction, QCloseEvent, QColor, QDesktopServices, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from osint_studio.core.domain_utils import extract_brand_handle, normalize_domain, sanitize_filename
from osint_studio.core.exporter import ReconExporter
from osint_studio.core.local_llm_engine import (
    LOW_RAM_MODELS,
    HeuristicAnalyst,
    LocalLLMEngine,
    is_ollama_available_sync,
)
from osint_studio.core.metadata_engine import MetadataEngine
from osint_studio.core.personal_osint_suite import (
    PersonalOSINTSuite,
    PrivacyScrubber,
    generate_username_permutations,
)
from osint_studio.ui.settings_dialog import SettingsDialog, load_config, save_config
from osint_studio.ui.styles import (
    CATPPUCCIN_MOCHA_QSS,
    MONOCHROME_QSS,
    get_theme_stylesheet,
)
from osint_studio.ui.workers import (
    AsyncTaskWorker,
    LLMStreamWorker,
    ModelPullWorker,
    ReconWorker,
)

logger = logging.getLogger(__name__)


def get_app_icon_path() -> Optional[str]:
    """Resolves path to app_icon.ico in both developer mode and PyInstaller frozen runtime."""
    candidates = []
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).parent
        candidates.append(exe_dir / "assets" / "app_icon.ico")
        candidates.append(exe_dir / "_internal" / "assets" / "app_icon.ico")
        if hasattr(sys, "_MEIPASS"):
            candidates.append(Path(sys._MEIPASS) / "assets" / "app_icon.ico")
    else:
        pkg_dir = Path(__file__).resolve().parent.parent.parent.parent
        candidates.append(pkg_dir / "assets" / "app_icon.ico")
        candidates.append(Path(__file__).resolve().parent.parent / "assets" / "app_icon.ico")

    for c in candidates:
        if c.exists():
            return str(c)
    return None


class MainWindow(QMainWindow):
    """Main desktop application window for OSINT Recon Studio."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("OSINT Recon Studio - Defensive Reconnaissance & Privacy Suite")
        self.resize(1340, 880)
        self.setMinimumSize(1080, 700)

        icon_path = get_app_icon_path()
        if icon_path:
            self.setWindowIcon(QIcon(icon_path))

        self.thread_pool = QThreadPool.globalInstance()
        self.current_worker: Optional[ReconWorker] = None
        self.latest_results: Dict[str, Any] = {}
        self.latest_personal_results: Optional[Dict[str, Any]] = None
        self.dossier_text: str = ""
        self.current_scrubber_file: str = ""

        self.config = load_config()
        self.current_theme = self.config.get("theme", "mocha")
        self.set_theme(self.current_theme)

        self._init_ui()

        # Check local Ollama server status asynchronously
        self._check_local_ai_status()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.current_worker and not self.current_worker.is_cancelled:
            self.current_worker.cancel()
        self.thread_pool.waitForDone(1000)
        event.accept()

    # -------------------------------------------------------------------------
    # UI Layout & Control Bars
    # -------------------------------------------------------------------------

    def _init_ui(self) -> None:
        self._create_menu_bar()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(14, 10, 14, 10)
        main_layout.setSpacing(8)

        # Top Control & Domain Input Bar
        top_bar = self._create_control_bar()
        main_layout.addWidget(top_bar)

        # Active Modules Checkbox Bar
        options_bar = self._create_options_bar()
        main_layout.addWidget(options_bar)

        # Progress Indicator & Status Label
        prog_bar_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready (%p%)")

        self.status_label = QLabel("Ready to audit target domain or personal digital footprint.")
        self.status_label.setStyleSheet("color: #a6adc8; font-weight: 500;")

        prog_bar_layout.addWidget(self.status_label, 1)
        prog_bar_layout.addWidget(self.progress_bar, 2)
        main_layout.addLayout(prog_bar_layout)

        # Main Workspace Splitter: Left Sidebar + Right Stacked Hubs
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(4)

        # Left Navigation Sidebar (QListWidget)
        self.nav_sidebar = QListWidget()
        self.nav_sidebar.setObjectName("navSidebar")
        self.nav_sidebar.setFixedWidth(270)
        self._init_sidebar_items()

        # Right Stacked Widget (5 Unified Hubs + Activity Logs)
        self.stacked_widget = QStackedWidget()
        self._init_stacked_views()

        self.nav_sidebar.currentRowChanged.connect(self.stacked_widget.setCurrentIndex)
        self.nav_sidebar.setCurrentRow(0)

        splitter.addWidget(self.nav_sidebar)
        splitter.addWidget(self.stacked_widget)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        main_layout.addWidget(splitter, 1)

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready. Select a Category Hub on the left to begin.")

    def _init_sidebar_items(self) -> None:
        """Populates the navigation sidebar with 5 unified category hubs + activity logs."""
        nav_items = [
            "🏛️ Hub 1: Executive & AI Dossier",
            "🌐 Hub 2: Domain & Infrastructure",
            "☁️ Hub 3: Network, Cloud & Threat",
            "🛡️ Hub 4: Web & Email Defense",
            "👤 Hub 5: Personal Privacy & Footprint",
            "📜 Activity Logs & Raw JSON",
        ]
        for item_text in nav_items:
            item = QListWidgetItem(item_text)
            self.nav_sidebar.addItem(item)

    def _init_stacked_views(self) -> None:
        """Instantiates and registers each category hub view."""
        self.stacked_widget.addWidget(self._create_hub1_executive_ai())      # 0
        self.stacked_widget.addWidget(self._create_hub2_domain_infra())      # 1
        self.stacked_widget.addWidget(self._create_hub3_network_threat())    # 2
        self.stacked_widget.addWidget(self._create_hub4_web_defense())       # 3
        self.stacked_widget.addWidget(self._create_hub5_personal_privacy())  # 4
        self.stacked_widget.addWidget(self._create_hub6_logs_json())         # 5

    def _create_menu_bar(self) -> None:
        menubar = self.menuBar()

        # File Menu
        file_menu = menubar.addMenu("&File")

        act_export_json = QAction("Export Raw JSON...", self)
        act_export_json.setShortcut("Ctrl+J")
        act_export_json.triggered.connect(lambda: self._export_report("json"))
        file_menu.addAction(act_export_json)

        act_export_md = QAction("Export Markdown Dossier...", self)
        act_export_md.setShortcut("Ctrl+M")
        act_export_md.triggered.connect(lambda: self._export_report("markdown"))
        file_menu.addAction(act_export_md)

        act_export_html = QAction("Export HTML Report (Printable)...", self)
        act_export_html.setShortcut("Ctrl+H")
        act_export_html.triggered.connect(lambda: self._export_report("html"))
        file_menu.addAction(act_export_html)

        file_menu.addSeparator()

        act_shortcut = QAction("📌 Pin Shortcut to Desktop", self)
        act_shortcut.triggered.connect(self._create_desktop_shortcut)
        file_menu.addAction(act_shortcut)

        act_settings = QAction("&Settings...", self)
        act_settings.setShortcut("Ctrl+,")
        act_settings.triggered.connect(self._open_settings_dialog)
        file_menu.addAction(act_settings)

        file_menu.addSeparator()

        act_exit = QAction("E&xit", self)
        act_exit.setShortcut("Alt+F4")
        act_exit.triggered.connect(self.close)
        file_menu.addAction(act_exit)

        # View Menu
        view_menu = menubar.addMenu("&View")
        act_toggle_theme = QAction("🌓 Toggle Monochrome / Mocha Theme", self)
        act_toggle_theme.setShortcut("Ctrl+T")
        act_toggle_theme.triggered.connect(self.toggle_theme)
        view_menu.addAction(act_toggle_theme)

        # Help Menu
        help_menu = menubar.addMenu("&Help")
        act_ethics = QAction("&Ethical & Legal Guardrails", self)
        act_ethics.triggered.connect(self._show_ethics_dialog)
        help_menu.addAction(act_ethics)

        act_about = QAction("&About OSINT Recon Studio", self)
        act_about.triggered.connect(self._show_about_dialog)
        help_menu.addAction(act_about)

    def _create_control_bar(self) -> QWidget:
        frame = QFrame()
        self.control_frame = frame
        frame.setStyleSheet("background-color: #25273a; border-radius: 8px; padding: 4px;")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(10)

        lbl = QLabel("Target Domain:")
        self.lbl_control_title = lbl
        lbl.setStyleSheet("font-weight: 700; color: #89b4fa; font-size: 14px;")
        layout.addWidget(lbl)

        self.input_domain = QLineEdit()
        self.input_domain.setPlaceholderText("e.g. example.com, cloudflare.com, or münchen.de")
        self.input_domain.setStyleSheet("font-size: 14px; font-weight: 600;")
        self.input_domain.returnPressed.connect(self.start_recon)
        layout.addWidget(self.input_domain, 1)

        self.btn_start = QPushButton("▶ Start Passive Recon")
        self.btn_start.setObjectName("primaryButton")
        self.btn_start.setToolTip("Start passive OSINT reconnaissance on target domain")
        self.btn_start.clicked.connect(self.start_recon)
        layout.addWidget(self.btn_start)

        self.btn_cancel = QPushButton("■ Stop")
        self.btn_cancel.setObjectName("dangerButton")
        self.btn_cancel.setToolTip("Abort active reconnaissance")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self.cancel_recon)
        layout.addWidget(self.btn_cancel)

        self.btn_clear = QPushButton("Clear")
        self.btn_clear.clicked.connect(self.clear_results)
        layout.addWidget(self.btn_clear)

        self.btn_theme_toggle = QPushButton("🌓 Monochrome")
        self.btn_theme_toggle.setToolTip("Switch between Catppuccin Mocha Dark and Tactical Monochrome UI (Ctrl+T)")
        self.btn_theme_toggle.clicked.connect(self.toggle_theme)
        layout.addWidget(self.btn_theme_toggle)

        self.btn_shortcut = QPushButton("📌 Pin to Desktop")
        self.btn_shortcut.setToolTip("Create a Windows Desktop shortcut pointing to this application")
        self.btn_shortcut.clicked.connect(self._create_desktop_shortcut)
        layout.addWidget(self.btn_shortcut)

        self.btn_settings = QPushButton("⚙ Settings")
        self.btn_settings.clicked.connect(self._open_settings_dialog)
        layout.addWidget(self.btn_settings)

        self.btn_export = QPushButton("Export Report ▾")
        self.btn_export.setEnabled(False)
        export_menu = QMenu(self)
        export_menu.addAction("Export as JSON", lambda: self._export_report("json"))
        export_menu.addAction("Export as Markdown Dossier", lambda: self._export_report("markdown"))
        export_menu.addAction("Export as HTML Report", lambda: self._export_report("html"))
        export_menu.addAction("Export Subdomains CSV", lambda: self._export_report("csv"))
        self.btn_export.setMenu(export_menu)
        layout.addWidget(self.btn_export)

        return frame

    def _create_options_bar(self) -> QWidget:
        group = QGroupBox("Active Reconnaissance Pipeline Modules & Caching Controls")
        layout = QHBoxLayout(group)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(12)

        self.chk_dns = QCheckBox("DNS & CT")
        self.chk_dns.setChecked(True)
        layout.addWidget(self.chk_dns)

        self.chk_takeover = QCheckBox("Takeovers")
        self.chk_takeover.setChecked(True)
        layout.addWidget(self.chk_takeover)

        self.chk_rdap = QCheckBox("RDAP / Whois")
        self.chk_rdap.setChecked(True)
        layout.addWidget(self.chk_rdap)

        self.chk_web = QCheckBox("Web & Headers")
        self.chk_web.setChecked(True)
        layout.addWidget(self.chk_web)

        self.chk_exposure = QCheckBox("InternetDB & IPs")
        self.chk_exposure.setChecked(True)
        layout.addWidget(self.chk_exposure)

        self.chk_threat = QCheckBox("Threat Archives")
        self.chk_threat.setChecked(True)
        layout.addWidget(self.chk_threat)

        self.chk_email_sec = QCheckBox("Email Spoofing")
        self.chk_email_sec.setChecked(True)
        layout.addWidget(self.chk_email_sec)

        self.chk_tech = QCheckBox("Tech Stack")
        self.chk_tech.setChecked(True)
        layout.addWidget(self.chk_tech)

        self.chk_github = QCheckBox("GitHub Org")
        self.chk_github.setChecked(True)
        layout.addWidget(self.chk_github)

        self.chk_pgp = QCheckBox("PGP Keyservers")
        self.chk_pgp.setChecked(True)
        layout.addWidget(self.chk_pgp)

        self.chk_username = QCheckBox("Brand Handles")
        self.chk_username.setChecked(True)
        layout.addWidget(self.chk_username)

        # Force refresh checkbox for Phase 5 SQLite 24h cache bypass
        self.chk_force_refresh = QCheckBox("⚡ Force Refresh")
        self.chk_force_refresh.setToolTip("Bypass local SQLite 24-hour cache and query fresh live telemetry")
        self.chk_force_refresh.setStyleSheet("color: #fab387; font-weight: 700;")
        layout.addWidget(self.chk_force_refresh)

        return group

    def _create_standard_table(self, headers: List[str], min_height: int = 220) -> QTableWidget:
        """Helper to create standard responsive QTableWidget with interactive columns."""
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setMinimumHeight(min_height)
        self._setup_table_interactions(table)
        return table

    def _wrap_in_scroll_area(self, content_widget: QWidget) -> QScrollArea:
        """Wraps any complex multi-card view into a smooth scrollable container."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(content_widget)
        return scroll

    def populate_table_safely(
        self,
        table: QTableWidget,
        rows: List[List[Any]],
        max_rows: int = 2500,
        align_cols: Optional[Dict[int, Qt.AlignmentFlag]] = None,
    ) -> None:
        """Safely inserts rows in bulk with sorting & updates disabled to prevent GUI freeze."""
        table.setSortingEnabled(False)
        table.setUpdatesEnabled(False)
        table.setRowCount(0)

        capped_rows = rows[:max_rows]
        table.setRowCount(len(capped_rows))

        for r_idx, row_data in enumerate(capped_rows):
            for c_idx, cell_val in enumerate(row_data):
                item = QTableWidgetItem(str(cell_val if cell_val is not None else ""))
                if align_cols and c_idx in align_cols:
                    item.setTextAlignment(align_cols[c_idx])
                table.setItem(r_idx, c_idx, item)

        table.setUpdatesEnabled(True)
        table.setSortingEnabled(True)

    def _filter_table(self, table: QTableWidget, filter_text: str) -> None:
        """Fast row filtering across all columns in a table."""
        text = filter_text.strip().lower()
        if not text:
            for r in range(table.rowCount()):
                table.setRowHidden(r, False)
            return

        for r in range(table.rowCount()):
            row_visible = False
            for c in range(table.columnCount()):
                item = table.item(r, c)
                if item and text in item.text().lower():
                    row_visible = True
                    break
            table.setRowHidden(r, not row_visible)

    def _setup_table_interactions(self, table: QTableWidget) -> None:
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(
            lambda pos, t=table: self._show_table_context_menu(t, pos)
        )
        table.cellDoubleClicked.connect(
            lambda r, c, t=table: self._on_table_cell_double_clicked(t, r, c)
        )

    def _show_table_context_menu(self, table: QTableWidget, pos) -> None:
        item = table.itemAt(pos)
        if not item:
            return
        cell_text = item.text().strip()
        menu = QMenu(self)
        act_copy = menu.addAction(f"Copy '{cell_text[:35]}'")
        act_copy.triggered.connect(lambda: QApplication.clipboard().setText(cell_text))

        if cell_text.startswith("http://") or cell_text.startswith("https://"):
            act_open = menu.addAction("Open URL in Browser")
            act_open.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(cell_text)))

        menu.exec(table.viewport().mapToGlobal(pos))

    def _on_table_cell_double_clicked(self, table: QTableWidget, row: int, col: int) -> None:
        item = table.item(row, col)
        if not item:
            return
        text = item.text().strip()
        if text.startswith("http://") or text.startswith("https://"):
            QDesktopServices.openUrl(QUrl(text))
        else:
            QApplication.clipboard().setText(text)
            self.statusBar().showMessage(f"Copied '{text}' to clipboard", 3000)

    # -------------------------------------------------------------------------
    # HUB 1: Executive Overview & Local AI Dossier
    # -------------------------------------------------------------------------

    def _create_hub1_executive_ai(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(14)

        # Left Column: Posture Score, Metric Badges, Key Findings
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(12)

        # Posture Score Card
        self.card_score = QGroupBox("Overall Security Posture Score")
        score_layout = QVBoxLayout(self.card_score)
        score_layout.setAlignment(Qt.AlignCenter)

        self.lbl_grade = QLabel("–")
        self.lbl_grade.setStyleSheet("font-size: 54px; font-weight: 900; color: #89b4fa; line-height: 1;")
        self.lbl_grade.setAlignment(Qt.AlignCenter)
        score_layout.addWidget(self.lbl_grade)

        self.lbl_score_num = QLabel("Awaiting audit")
        self.lbl_score_num.setStyleSheet("font-size: 15px; color: #a6adc8; font-weight: 600;")
        self.lbl_score_num.setAlignment(Qt.AlignCenter)
        score_layout.addWidget(self.lbl_score_num)
        left_layout.addWidget(self.card_score)

        # Key Metrics Grid Card
        self.card_metrics = QGroupBox("Attack Surface Key Telemetry")
        metrics_layout = QGridLayout(self.card_metrics)
        metrics_layout.setSpacing(10)

        self.lbl_metric_takeover = QLabel("Takeovers: –")
        self.lbl_metric_email = QLabel("Email Defense: –")
        self.lbl_metric_dnssec = QLabel("DNSSEC: –")
        self.lbl_metric_headers = QLabel("Headers: –")
        self.lbl_metric_tls = QLabel("TLS Cert: –")
        self.lbl_metric_exposure = QLabel("InternetDB: –")
        self.lbl_metric_cloud = QLabel("Hosting: –")

        for lbl_widget in [
            self.lbl_metric_takeover,
            self.lbl_metric_email,
            self.lbl_metric_dnssec,
            self.lbl_metric_headers,
            self.lbl_metric_tls,
            self.lbl_metric_exposure,
            self.lbl_metric_cloud,
        ]:
            lbl_widget.setStyleSheet(
                "background-color: #181825; padding: 8px 12px; border-radius: 6px; font-weight: 600; color: #cdd6f4;"
            )

        metrics_layout.addWidget(self.lbl_metric_takeover, 0, 0)
        metrics_layout.addWidget(self.lbl_metric_email, 0, 1)
        metrics_layout.addWidget(self.lbl_metric_dnssec, 1, 0)
        metrics_layout.addWidget(self.lbl_metric_headers, 1, 1)
        metrics_layout.addWidget(self.lbl_metric_tls, 2, 0)
        metrics_layout.addWidget(self.lbl_metric_exposure, 2, 1)
        metrics_layout.addWidget(self.lbl_metric_cloud, 3, 0, 1, 2)
        left_layout.addWidget(self.card_metrics)

        # Prioritized Findings Table Card
        card_findings = QGroupBox("Prioritized Defensive Findings & Correlation Alerts")
        find_layout = QVBoxLayout(card_findings)
        self.table_findings = self._create_standard_table(
            ["Severity", "Defensive Category", "Observed Risk Finding", "Remediation Action"],
            min_height=200,
        )
        find_layout.addWidget(self.table_findings)
        left_layout.addWidget(card_findings, 1)

        # Right Column: Low-RAM Local AI Analyst Console
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)

        ai_box = QGroupBox("🧠 Low-RAM Local AI Intelligence Analyst (<2 GB RAM)")
        ai_layout = QVBoxLayout(ai_box)
        ai_layout.setSpacing(8)

        # AI Control Bar
        ai_controls = QHBoxLayout()
        ai_controls.addWidget(QLabel("AI Model:"))

        self.combo_ai_model = QComboBox()
        for model_id, model_label in LOW_RAM_MODELS:
            self.combo_ai_model.addItem(model_label, model_id)
        self.combo_ai_model.addItem("Rule-Based Heuristic Analyst (0-RAM)", "heuristic")
        ai_controls.addWidget(self.combo_ai_model, 1)

        self.btn_pull_model = QPushButton("📥 Pull Model")
        self.btn_pull_model.setToolTip("Pulls chosen lightweight model into local Ollama runtime")
        self.btn_pull_model.clicked.connect(self._pull_ai_model)
        ai_controls.addWidget(self.btn_pull_model)

        self.btn_synthesize = QPushButton("🚀 Synthesize OSINT Dossier")
        self.btn_synthesize.setObjectName("primaryButton")
        self.btn_synthesize.setToolTip("Synthesize complete multi-module intelligence assessment")
        self.btn_synthesize.clicked.connect(self._synthesize_dossier)
        ai_controls.addWidget(self.btn_synthesize)
        ai_layout.addLayout(ai_controls)

        # Status & Pull Progress
        self.lbl_llm_status = QLabel("Checking local AI status...")
        self.lbl_llm_status.setStyleSheet("color: #a6adc8; font-size: 12px;")
        ai_layout.addWidget(self.lbl_llm_status)

        self.progress_pull_model = QProgressBar()
        self.progress_pull_model.setRange(0, 100)
        self.progress_pull_model.setValue(0)
        self.progress_pull_model.setVisible(False)
        ai_layout.addWidget(self.progress_pull_model)

        # Markdown Dossier Browser
        self.dossier_browser = QTextBrowser()
        self.dossier_browser.setOpenExternalLinks(True)
        self.dossier_browser.setPlaceholderText(
            "The Executive OSINT Dossier will appear here.\n\n"
            "Click '🚀 Synthesize OSINT Dossier' to run the offline AI correlation engine on collected telemetry, "
            "or ask interactive follow-up questions in the chat box below."
        )
        ai_layout.addWidget(self.dossier_browser, 1)

        # Offline Interactive Chat Row
        chat_layout = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText(
            "Ask follow-up question offline (e.g. 'How do I fix my DMARC record?' or 'Which finding is most dangerous?')..."
        )
        self.chat_input.returnPressed.connect(self._ask_local_ai)
        chat_layout.addWidget(self.chat_input, 1)

        self.btn_ask_ai = QPushButton("Ask AI")
        self.btn_ask_ai.clicked.connect(self._ask_local_ai)
        chat_layout.addWidget(self.btn_ask_ai)
        ai_layout.addLayout(chat_layout)

        right_layout.addWidget(ai_box)

        # Splitter between left metrics and right AI console
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 5)

        layout.addWidget(splitter)
        return widget

    def _check_local_ai_status(self) -> None:
        """Asynchronously checks if local Ollama server is accessible."""
        def _bg_check():
            return is_ollama_available_sync()

        worker = AsyncTaskWorker(_bg_check)
        worker.signals.finished.connect(self._on_ollama_status)
        self.thread_pool.start(worker)

    def _on_ollama_status(self, is_online: bool) -> None:
        if is_online:
            self.lbl_llm_status.setText("🟢 Local Ollama Server Online (Ready for low-RAM streaming)")
            self.lbl_llm_status.setStyleSheet("color: #a6e3a1; font-weight: 600;")
        else:
            self.lbl_llm_status.setText("ℹ️ Local Ollama Offline — Defaulting to Fast Rule-Based Correlation (0-RAM)")
            self.lbl_llm_status.setStyleSheet("color: #fab387; font-weight: 500;")

    def _pull_ai_model(self) -> None:
        model_name = str(self.combo_ai_model.currentData() or "qwen2.5:1.5b")
        if model_name == "heuristic":
            QMessageBox.information(
                self,
                "Zero-RAM Engine",
                "The Rule-Based Heuristic Engine requires zero extra downloads and 0 MB extra RAM.",
            )
            return

        self.btn_pull_model.setEnabled(False)
        self.progress_pull_model.setVisible(True)
        self.progress_pull_model.setValue(0)
        self.lbl_llm_status.setText(f"Pulling model '{model_name}' via Ollama...")

        worker = ModelPullWorker(model_name)
        worker.signals.progress.connect(self._on_pull_progress)
        worker.signals.finished.connect(self._on_pull_finished)
        worker.signals.error.connect(self._on_pull_error)
        self.thread_pool.start(worker)

    def _on_pull_progress(self, status: str, pct: float) -> None:
        self.lbl_llm_status.setText(f"Downloading: {status} ({pct:.1f}%)")
        self.progress_pull_model.setValue(int(pct))

    def _on_pull_finished(self, msg: str) -> None:
        self.btn_pull_model.setEnabled(True)
        self.progress_pull_model.setVisible(False)
        self.lbl_llm_status.setText(f"✅ {msg}")
        self.lbl_llm_status.setStyleSheet("color: #a6e3a1; font-weight: 600;")

    def _on_pull_error(self, err: str) -> None:
        self.btn_pull_model.setEnabled(True)
        self.progress_pull_model.setVisible(False)
        self.lbl_llm_status.setText(f"⚠️ Model pull failed: {err}")
        self.lbl_llm_status.setStyleSheet("color: #f38ba8;")

    def _synthesize_dossier(self) -> None:
        if not self.latest_results:
            QMessageBox.warning(
                self,
                "No Data Available",
                "Please run a passive reconnaissance scan on a domain first or enter personal data in Hub 5.",
            )
            return

        self.btn_synthesize.setEnabled(False)
        self.dossier_text = ""
        self.dossier_browser.clear()
        self.lbl_llm_status.setText("🧠 Synthesizing OSINT Intelligence Dossier...")

        selected_model = str(self.combo_ai_model.currentData() or "qwen2.5:1.5b")
        engine = LocalLLMEngine()

        findings = dict(self.latest_results)
        if self.latest_personal_results:
            findings["personal"] = self.latest_personal_results

        worker = LLMStreamWorker(
            lambda: engine.synthesize_dossier_stream(
                findings,
                model=selected_model,
                force_heuristic=(selected_model == "heuristic"),
            )
        )
        worker.signals.token.connect(self._on_dossier_token)
        worker.signals.finished.connect(self._on_dossier_finished)
        worker.signals.error.connect(self._on_dossier_error)
        self.thread_pool.start(worker)

    def _ask_local_ai(self) -> None:
        question = self.chat_input.text().strip()
        if not question:
            return

        self.chat_input.clear()
        self.dossier_text += f"\n\n---\n### 👤 Investigator:\n{question}\n\n### 🧠 AI Analyst:\n"
        self.dossier_browser.setMarkdown(self.dossier_text)

        engine = LocalLLMEngine()
        selected_model = str(self.combo_ai_model.currentData() or "qwen2.5:1.5b")
        findings = dict(self.latest_results)
        if self.latest_personal_results:
            findings["personal"] = self.latest_personal_results

        worker = LLMStreamWorker(
            lambda: engine.ask_question_stream(
                question,
                findings,
                model=selected_model,
                force_heuristic=(selected_model == "heuristic"),
            )
        )
        worker.signals.token.connect(self._on_dossier_token)
        worker.signals.finished.connect(lambda txt: self.lbl_llm_status.setText("✅ Ready."))
        worker.signals.error.connect(self._on_dossier_error)
        self.thread_pool.start(worker)

    def _on_dossier_token(self, chunk: str) -> None:
        self.dossier_text += chunk
        self.dossier_browser.setMarkdown(self.dossier_text)
        sb = self.dossier_browser.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_dossier_finished(self, full_text: str) -> None:
        self.btn_synthesize.setEnabled(True)
        self.lbl_llm_status.setText("✅ Intelligence Dossier synthesized successfully.")
        self.lbl_llm_status.setStyleSheet("color: #a6e3a1; font-weight: 600;")

    def _on_dossier_error(self, err: str) -> None:
        self.btn_synthesize.setEnabled(True)
        self.lbl_llm_status.setText(f"⚠️ Synthesis error: {err}")

    # -------------------------------------------------------------------------
    # HUB 2: Domain & Infrastructure (DNS, Subdomains, Takeovers, RDAP)
    # -------------------------------------------------------------------------

    def _create_hub2_domain_infra(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)

        # Global Search / Filter Bar for Hub 2
        filter_row = QHBoxLayout()
        self.input_filter_hub2 = QLineEdit()
        self.input_filter_hub2.setPlaceholderText(
            "🔍 Search & filter across DNS records, subdomains, dangling CNAMEs, and RDAP registration..."
        )
        self.input_filter_hub2.textChanged.connect(self._on_filter_hub2)
        filter_row.addWidget(self.input_filter_hub2)
        layout.addLayout(filter_row)

        # Scrollable area containing the 4 infrastructure cards
        scroll_content = QWidget()
        s_layout = QVBoxLayout(scroll_content)
        s_layout.setContentsMargins(0, 0, 0, 0)
        s_layout.setSpacing(14)

        # 1. DNS Records Card
        card_dns = QGroupBox("DNS Resource Records (A, AAAA, MX, NS, TXT, SOA, CAA)")
        dns_box = QVBoxLayout(card_dns)
        self.table_dns = self._create_standard_table(
            ["Record Type", "Host / Name", "Target / Value", "TTL (sec)", "Status / Notes"],
            min_height=220,
        )
        dns_box.addWidget(self.table_dns)
        s_layout.addWidget(card_dns)

        # 2. Certificate Transparency & Subdomains Card
        card_sub = QGroupBox("Certificate Transparency & Discovered Subdomains")
        sub_box = QVBoxLayout(card_sub)
        self.table_subdomains = self._create_standard_table(
            ["Discovered Subdomain", "Discovery Source", "Resolved IP Address", "Hosting / Cloud Status"],
            min_height=220,
        )
        sub_box.addWidget(self.table_subdomains)
        s_layout.addWidget(card_sub)

        # 3. Dangling CNAMEs & Subdomain Takeovers Card
        card_takeover = QGroupBox("Dangling CNAMEs & Subdomain Takeover Vulnerabilities")
        take_box = QVBoxLayout(card_takeover)
        self.table_takeovers = self._create_standard_table(
            ["Subdomain Pointer", "Target CNAME", "Fingerprinted Cloud Service", "Vulnerability Status", "Action / Remediation"],
            min_height=200,
        )
        take_box.addWidget(self.table_takeovers)
        s_layout.addWidget(card_takeover)

        # 4. RDAP / Whois Ownership Card
        card_rdap = QGroupBox("RDAP & Whois Ownership Registration Lifecycle")
        rdap_box = QVBoxLayout(card_rdap)
        self.table_rdap = self._create_standard_table(
            ["Registration Attribute", "Value", "Audit Notes"],
            min_height=200,
        )
        rdap_box.addWidget(self.table_rdap)
        s_layout.addWidget(card_rdap)

        layout.addWidget(self._wrap_in_scroll_area(scroll_content))
        return container

    def _on_filter_hub2(self, text: str) -> None:
        for t in (self.table_dns, self.table_subdomains, self.table_takeovers, self.table_rdap):
            self._filter_table(t, text)

    # -------------------------------------------------------------------------
    # HUB 3: Network, Cloud & Threat Exposure (InternetDB, IP Intel, Threat History)
    # -------------------------------------------------------------------------

    def _create_hub3_network_threat(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)

        # Search / Filter Bar
        filter_row = QHBoxLayout()
        self.input_filter_hub3 = QLineEdit()
        self.input_filter_hub3.setPlaceholderText(
            "🔍 Search & filter across open ports, CVEs, cloud providers, and historical scans..."
        )
        self.input_filter_hub3.textChanged.connect(self._on_filter_hub3)
        filter_row.addWidget(self.input_filter_hub3)
        layout.addLayout(filter_row)

        scroll_content = QWidget()
        s_layout = QVBoxLayout(scroll_content)
        s_layout.setContentsMargins(0, 0, 0, 0)
        s_layout.setSpacing(14)

        # 1. Shodan InternetDB Passive Exposure
        card_exposure = QGroupBox("Shodan InternetDB Passive Exposure (Open Ports, CVEs, Hostnames)")
        exp_box = QVBoxLayout(card_exposure)
        self.table_exposure = self._create_standard_table(
            ["Target IP Address", "Observed Hostnames", "Open Ports", "CVE Vulnerabilities", "Tags / Banners"],
            min_height=220,
        )
        exp_box.addWidget(self.table_exposure)
        s_layout.addWidget(card_exposure)

        # 2. IP Geolocation, ASN, BGP & Cloud Provider
        card_ip = QGroupBox("IP Geolocation, ASN, BGP & Cloud Provider Fingerprinting")
        ip_box = QVBoxLayout(card_ip)
        self.table_ip_intel = self._create_standard_table(
            ["IP Address", "Country", "ASN / Network Owner", "ISP", "Detected Cloud / CDN Provider"],
            min_height=200,
        )
        ip_box.addWidget(self.table_ip_intel)
        s_layout.addWidget(card_ip)

        # 3. Threat History & Archive Records (URLScan.io & AlienVault OTX)
        card_threat = QGroupBox("Threat Archives (URLScan.io Historical Scans & AlienVault OTX Passive DNS)")
        threat_box = QVBoxLayout(card_threat)
        self.table_threat = self._create_standard_table(
            ["Intelligence Source", "Observed Date", "Observed URL / Target", "Associated IP / ASN", "Report / Archive Permalink"],
            min_height=220,
        )
        threat_box.addWidget(self.table_threat)
        s_layout.addWidget(card_threat)

        layout.addWidget(self._wrap_in_scroll_area(scroll_content))
        return container

    def _on_filter_hub3(self, text: str) -> None:
        for t in (self.table_exposure, self.table_ip_intel, self.table_threat):
            self._filter_table(t, text)

    # -------------------------------------------------------------------------
    # HUB 4: Web & Email Defensive Posture (Security Headers, SPF/DMARC, Tech Stack, Wayback)
    # -------------------------------------------------------------------------

    def _create_hub4_web_defense(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)

        filter_row = QHBoxLayout()
        self.input_filter_hub4 = QLineEdit()
        self.input_filter_hub4.setPlaceholderText(
            "🔍 Search & filter headers, anti-spoofing policies, web technologies, and archive milestones..."
        )
        self.input_filter_hub4.textChanged.connect(self._on_filter_hub4)
        filter_row.addWidget(self.input_filter_hub4)
        layout.addLayout(filter_row)

        scroll_content = QWidget()
        s_layout = QVBoxLayout(scroll_content)
        s_layout.setContentsMargins(0, 0, 0, 0)
        s_layout.setSpacing(14)

        # 1. Email Security Posture & Anti-Spoofing
        card_email_sec = QGroupBox("Email Security Posture & Anti-Spoofing (SPF, DMARC, DKIM, BIMI)")
        es_box = QVBoxLayout(card_email_sec)
        self.table_email_sec = self._create_standard_table(
            ["Defensive Mechanism", "Status", "Configured Policy / Record", "Risk Evaluation"],
            min_height=200,
        )
        es_box.addWidget(self.table_email_sec)
        s_layout.addWidget(card_email_sec)

        # 2. HTTP Security Headers & TLS Configuration
        card_web = QGroupBox("HTTP Security Headers & TLS Configuration")
        web_box = QVBoxLayout(card_web)
        self.table_web = self._create_standard_table(
            ["Defensive Security Header", "Status", "Configured Value", "Remediation Recommendation"],
            min_height=220,
        )
        web_box.addWidget(self.table_web)
        s_layout.addWidget(card_web)

        # 3. Web Technology Stack & Manifests
        card_tech = QGroupBox("Web Technology Stack, CMS & Manifests (security.txt / robots.txt)")
        tech_box = QVBoxLayout(card_tech)
        self.table_tech = self._create_standard_table(
            ["Category", "Technology / Framework", "Version / Details", "Evidence Source"],
            min_height=200,
        )
        tech_box.addWidget(self.table_tech)
        s_layout.addWidget(card_tech)

        # 4. Wayback Machine Historical Milestones
        card_archive = QGroupBox("Internet Archive (Wayback Machine) Historical Milestones")
        arch_box = QVBoxLayout(card_archive)
        self.table_archive = self._create_standard_table(
            ["Milestone Event", "Date & Timestamp", "Archive Permalink", "Status"],
            min_height=180,
        )
        arch_box.addWidget(self.table_archive)
        s_layout.addWidget(card_archive)

        layout.addWidget(self._wrap_in_scroll_area(scroll_content))
        return container

    def _on_filter_hub4(self, text: str) -> None:
        for t in (self.table_email_sec, self.table_web, self.table_tech, self.table_archive):
            self._filter_table(t, text)

    # -------------------------------------------------------------------------
    # HUB 5: Personal Data & Digital Footprint (Breaches, Phone, Social Matrix, EXIF Scrubber)
    # -------------------------------------------------------------------------

    def _create_hub5_personal_privacy(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)

        # Top Personal Input Bar
        top_box = QGroupBox("Personal Privacy & Digital Footprint Input")
        tb_layout = QHBoxLayout(top_box)
        tb_layout.setContentsMargins(10, 8, 10, 8)
        tb_layout.setSpacing(8)

        self.input_personal_email = QLineEdit()
        self.input_personal_email.setPlaceholderText("Email: target@example.com")
        tb_layout.addWidget(self.input_personal_email)

        self.input_personal_phone = QLineEdit()
        self.input_personal_phone.setPlaceholderText("Phone: +1... or E.164")
        tb_layout.addWidget(self.input_personal_phone)

        self.input_personal_handle = QLineEdit()
        self.input_personal_handle.setPlaceholderText("Handle: e.g. johnsmith")
        tb_layout.addWidget(self.input_personal_handle)

        self.btn_run_personal = QPushButton("🔍 Run Personal Privacy Audit")
        self.btn_run_personal.setObjectName("primaryButton")
        self.btn_run_personal.clicked.connect(self._run_personal_audit)
        tb_layout.addWidget(self.btn_run_personal)

        self.btn_clear_personal = QPushButton("Clear")
        self.btn_clear_personal.clicked.connect(self._clear_personal_fields)
        tb_layout.addWidget(self.btn_clear_personal)
        layout.addWidget(top_box)

        # Status & Progress Row
        status_row = QHBoxLayout()
        self.lbl_personal_status = QLabel("Ready to audit personal footprint across email, phone, and 40+ platforms.")
        self.lbl_personal_status.setStyleSheet("color: #a6adc8; font-weight: 500;")
        self.progress_personal = QProgressBar()
        self.progress_personal.setRange(0, 100)
        self.progress_personal.setValue(0)
        status_row.addWidget(self.lbl_personal_status, 1)
        status_row.addWidget(self.progress_personal, 1)
        layout.addLayout(status_row)

        scroll_content = QWidget()
        s_layout = QVBoxLayout(scroll_content)
        s_layout.setContentsMargins(0, 0, 0, 0)
        s_layout.setSpacing(14)

        # Summary Badges Row
        badge_row = QHBoxLayout()
        self.lbl_personal_risk_badge = QLabel("Privacy Score: –")
        self.lbl_personal_risk_badge.setStyleSheet(
            "background-color: #181825; padding: 10px 14px; border-radius: 8px; font-weight: 700; font-size: 14px; color: #89b4fa;"
        )
        self.lbl_personal_linkability_badge = QLabel("Identity Linkability: –")
        self.lbl_personal_linkability_badge.setStyleSheet(
            "background-color: #181825; padding: 10px 14px; border-radius: 8px; font-weight: 700; font-size: 14px; color: #fab387;"
        )
        badge_row.addWidget(self.lbl_personal_risk_badge)
        badge_row.addWidget(self.lbl_personal_linkability_badge)
        badge_row.addStretch()
        s_layout.addLayout(badge_row)

        # 1. Email Breach Analytics & Identity Leaks
        card_email = QGroupBox("Email Breach Analytics & Identity Hash Leaks (XposedOrNot / Gravatar / PGP)")
        eb_box = QVBoxLayout(card_email)
        self.table_personal_email = self._create_standard_table(
            ["Identity Asset / Source", "Breach / Leak Name", "Date / Status", "Exposed Data Classes"],
            min_height=180,
        )
        eb_box.addWidget(self.table_personal_email)
        s_layout.addWidget(card_email)

        # 2. Phone Carrier, VoIP & Messaging Deep Links
        card_phone = QGroupBox("Phone Carrier, VoIP & Public Messaging App Verification Links")
        ph_box = QVBoxLayout(card_phone)
        self.table_personal_phone = self._create_standard_table(
            ["Property", "Value", "Messaging App Verification Link"],
            min_height=150,
        )
        ph_box.addWidget(self.table_personal_phone)
        s_layout.addWidget(card_phone)

        # 3. 40+ Social & Digital Footprint Matrix
        card_social = QGroupBox("40+ Social & Digital Footprint Matrix (Strictly Passive)")
        soc_box = QVBoxLayout(card_social)
        self.table_personal_social = self._create_standard_table(
            ["Platform", "Category", "Profile Status", "Public Profile Link", "Preview Title / Bio"],
            min_height=220,
        )
        soc_box.addWidget(self.table_personal_social)
        s_layout.addWidget(card_social)

        # 4. Username Permutator & Identity Linkability Risk
        card_perms = QGroupBox("Username Permutator & Cross-Platform Linkability Risk Engine")
        perm_box = QVBoxLayout(card_perms)
        self.table_personal_permutations = self._create_standard_table(
            ["Generated Handle Variation", "Risk Assessment", "Linkability Note"],
            min_height=180,
        )
        perm_box.addWidget(self.table_personal_permutations)
        s_layout.addWidget(card_perms)

        # 5. Document & Photo Privacy Scrubber (Read + Strip 100% Metadata)
        card_scrub = QGroupBox("Document & Photo Privacy Scrubber (Inspect + Strip 100% EXIF/GPS Metadata)")
        scrub_box = QVBoxLayout(card_scrub)
        scrub_ctrls = QHBoxLayout()

        self.btn_browse_scrubber = QPushButton("Browse Image / Document...")
        self.btn_browse_scrubber.clicked.connect(self._browse_scrubber_file)
        scrub_ctrls.addWidget(self.btn_browse_scrubber)

        self.lbl_scrubber_file = QLabel("No file selected.")
        self.lbl_scrubber_file.setStyleSheet("color: #a6adc8; font-weight: 500;")
        scrub_ctrls.addWidget(self.lbl_scrubber_file, 1)

        self.btn_sanitize_file = QPushButton("🛡️ Sanitize & Save Clean Copy")
        self.btn_sanitize_file.setObjectName("primaryButton")
        self.btn_sanitize_file.setToolTip("Strips all EXIF, GPS, and metadata tags and saves a sanitized clean copy")
        self.btn_sanitize_file.clicked.connect(self._sanitize_current_file)
        scrub_ctrls.addWidget(self.btn_sanitize_file)
        scrub_box.addLayout(scrub_ctrls)

        self.table_scrubber = self._create_standard_table(
            ["Metadata Tag / Property", "Extracted Value", "Privacy Risk Assessment"],
            min_height=180,
        )
        scrub_box.addWidget(self.table_scrubber)
        s_layout.addWidget(card_scrub)

        layout.addWidget(self._wrap_in_scroll_area(scroll_content))
        return container

    def _clear_personal_fields(self) -> None:
        self.input_personal_email.clear()
        self.input_personal_phone.clear()
        self.input_personal_handle.clear()
        for t in (
            self.table_personal_email,
            self.table_personal_phone,
            self.table_personal_social,
            self.table_personal_permutations,
            self.table_scrubber,
        ):
            t.setRowCount(0)
        self.lbl_personal_risk_badge.setText("Privacy Score: –")
        self.lbl_personal_linkability_badge.setText("Identity Linkability: –")
        self.lbl_personal_status.setText("Cleared.")

    def _run_personal_audit(self) -> None:
        email = self.input_personal_email.text().strip()
        phone = self.input_personal_phone.text().strip()
        handle = self.input_personal_handle.text().strip()

        if not email and not phone and not handle:
            QMessageBox.warning(
                self,
                "Input Required",
                "Please enter at least an email address, phone number, or handle.",
            )
            return

        self.btn_run_personal.setEnabled(False)
        self.progress_personal.setRange(0, 0)  # indeterminate spinner
        self.lbl_personal_status.setText(f"Auditing personal footprint for handle='{handle}', email='{email}'...")
        force_refresh = self.chk_force_refresh.isChecked()

        def _do_audit():
            return PersonalOSINTSuite.run_suite_sync(
                handle=handle,
                email=email,
                phone=phone,
                force_refresh=force_refresh,
            )

        worker = AsyncTaskWorker(_do_audit)
        worker.signals.finished.connect(self._on_personal_audit_finished)
        worker.signals.error.connect(self._on_personal_audit_error)
        self.thread_pool.start(worker)

    def _on_personal_audit_finished(self, report: Any) -> None:
        self.progress_personal.setRange(0, 100)
        self.progress_personal.setValue(100)
        self.btn_run_personal.setEnabled(True)
        self.lbl_personal_status.setText("Personal privacy audit completed successfully.")

        self.latest_personal_results = report.to_dict()

        # Update Badges
        priv_score = 100 - report.linkability_risk_score
        self.lbl_personal_risk_badge.setText(f"Privacy Score: {priv_score}/100")
        self.lbl_personal_linkability_badge.setText(
            f"Identity Linkability: {report.linkability_risk_score}/100 ({report.linkability_rating})"
        )

        # 1. Email Report
        email_rows = []
        if report.email_report:
            er = report.email_report
            if er.gravatar_url:
                email_rows.append(["Gravatar Profile", "Avatar Published", "Active", er.gravatar_url])
            if er.pgp_keys_found:
                email_rows.append(["OpenPGP Keyserver", f"{len(er.pgp_keys_found)} Keys Found", "Active", ", ".join(er.pgp_keys_found[:2])])
            for b in er.breaches:
                email_rows.append(["Breach (XposedOrNot)", b.name, b.breach_date, ", ".join(b.exposed_data[:3])])
            if not email_rows:
                email_rows.append(["Email Privacy", "No public breaches or gravatars indexed", "Clean", "None"])
        self.populate_table_safely(self.table_personal_email, email_rows)

        # 2. Phone Report
        phone_rows = []
        if report.messaging_links:
            for k, v in report.messaging_links.items():
                phone_rows.append([k, v, v])
        if not phone_rows:
            phone_rows.append(["Phone Telemetry", "No phone number provided or standard carrier format", "N/A"])
        self.populate_table_safely(self.table_personal_phone, phone_rows)

        # 3. 40+ Social Profiles
        soc_rows = []
        for p in report.social_profiles:
            soc_rows.append([p.platform, p.category, p.status, p.url, p.title])
        self.populate_table_safely(self.table_personal_social, soc_rows)

        # 4. Username Permutations
        perm_rows = []
        for perm in report.username_permutations:
            perm_rows.append([perm, "Permutation Generated", "Candidate alias for cross-platform linking"])
        self.populate_table_safely(self.table_personal_permutations, perm_rows)

    def _on_personal_audit_error(self, err: str) -> None:
        self.progress_personal.setRange(0, 100)
        self.btn_run_personal.setEnabled(True)
        self.lbl_personal_status.setText(f"Error during audit: {err}")
        QMessageBox.critical(self, "Audit Error", f"Personal audit failed: {err}")

    def _browse_scrubber_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Photo or Document to Inspect",
            "",
            "Media & Documents (*.jpg *.jpeg *.png *.webp *.pdf *.docx);;All Files (*.*)",
        )
        if not path:
            return

        self.current_scrubber_file = path
        self.lbl_scrubber_file.setText(Path(path).name)

        # Read metadata using MetadataEngine
        report = MetadataEngine.extract(path)
        rows = []
        for prop, val in report.properties.items():
            risk = "HIGH (GPS Location)" if "gps" in prop.lower() or "lat" in prop.lower() else "MEDIUM"
            rows.append([prop, str(val), risk])

        if not rows:
            rows.append(["Status", "Clean — Zero EXIF or Document metadata detected", "LOW"])
        self.populate_table_safely(self.table_scrubber, rows)

    def _sanitize_current_file(self) -> None:
        if not self.current_scrubber_file or not os.path.exists(self.current_scrubber_file):
            QMessageBox.warning(self, "No File", "Please browse and select a file first.")
            return

        success, clean_path, count = PrivacyScrubber.scrub_file(self.current_scrubber_file)
        if success:
            QMessageBox.information(
                self,
                "Metadata Sanitized",
                f"File successfully sanitized!\n\nStripped {count} metadata fields.\n\nClean privacy copy saved at:\n{clean_path}",
            )
            self.populate_table_safely(
                self.table_scrubber,
                [["Status", f"Sanitized Clean Copy Created ({count} tags stripped)", "Clean"]],
            )
        else:
            QMessageBox.critical(self, "Sanitization Failed", f"Could not scrub file: {clean_path}")

    # -------------------------------------------------------------------------
    # HUB 6: Live Activity Logs & Raw JSON Inspector
    # -------------------------------------------------------------------------

    def _create_hub6_logs_json(self) -> QWidget:
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)

        # Left: Live Logs Console
        logs_box = QGroupBox("Live Activity Logs")
        lb_layout = QVBoxLayout(logs_box)
        self.text_logs = QTextEdit()
        self.text_logs.setReadOnly(True)
        self.text_logs.setStyleSheet("font-family: Consolas, monospace; font-size: 12px;")
        lb_layout.addWidget(self.text_logs)

        btn_clear_logs = QPushButton("Clear Logs")
        btn_clear_logs.clicked.connect(self.text_logs.clear)
        lb_layout.addWidget(btn_clear_logs)

        # Right: Raw JSON Viewer
        json_box = QGroupBox("Consolidated Raw JSON Telemetry")
        jb_layout = QVBoxLayout(json_box)
        self.text_json = QTextEdit()
        self.text_json.setReadOnly(True)
        self.text_json.setStyleSheet("font-family: Consolas, monospace; font-size: 12px;")
        jb_layout.addWidget(self.text_json)

        j_ctrls = QHBoxLayout()
        btn_copy_json = QPushButton("Copy JSON")
        btn_copy_json.clicked.connect(lambda: QApplication.clipboard().setText(self.text_json.toPlainText()))
        j_ctrls.addWidget(btn_copy_json)

        btn_save_json = QPushButton("Save JSON...")
        btn_save_json.clicked.connect(lambda: self._export_report("json"))
        j_ctrls.addWidget(btn_save_json)
        jb_layout.addLayout(j_ctrls)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(logs_box)
        splitter.addWidget(json_box)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)
        return container

    # -------------------------------------------------------------------------
    # Passive Reconnaissance Orchestration
    # -------------------------------------------------------------------------

    def start_recon(self) -> None:
        raw_target = self.input_domain.text().strip()
        if not raw_target:
            QMessageBox.warning(self, "Missing Target", "Please enter a target domain name to audit.")
            return

        domain = normalize_domain(raw_target)
        if not domain:
            QMessageBox.warning(self, "Invalid Domain", "Please enter a valid domain name.")
            return

        self.input_domain.setText(domain)

        cfg = load_config()
        rate_rps = float(cfg.get("rate_limit_rps", 2.0))
        timeout = float(cfg.get("timeout_sec", 10.0))
        ua = str(cfg.get("user_agent", "OSINTReconStudio-PassiveAudit/1.0"))
        gh_token = str(cfg.get("github_token", ""))
        force_refresh = self.chk_force_refresh.isChecked()

        enabled_modules = {
            "dns": self.chk_dns.isChecked(),
            "ct": self.chk_dns.isChecked(),
            "takeover": self.chk_takeover.isChecked(),
            "rdap": self.chk_rdap.isChecked(),
            "web": self.chk_web.isChecked(),
            "archive": True,
            "internetdb": self.chk_exposure.isChecked(),
            "ip_intel": self.chk_exposure.isChecked(),
            "urlscan": self.chk_threat.isChecked(),
            "email_sec": self.chk_email_sec.isChecked(),
            "tech_stack": self.chk_tech.isChecked(),
            "github": self.chk_github.isChecked(),
            "pgp": self.chk_pgp.isChecked(),
            "username": self.chk_username.isChecked(),
        }

        self.current_worker = ReconWorker(
            domain=domain,
            enabled_modules=enabled_modules,
            rate_limit_rps=rate_rps,
            timeout=timeout,
            user_agent=ua,
            github_token=gh_token,
            force_refresh=force_refresh,
        )

        self.current_worker.signals.started.connect(self._on_started)
        self.current_worker.signals.progress.connect(self._on_progress)
        self.current_worker.signals.log.connect(self._on_log)
        self.current_worker.signals.module_complete.connect(self._on_module_complete)
        self.current_worker.signals.error.connect(self._on_error)
        self.current_worker.signals.finished.connect(self._on_finished)

        self.thread_pool.start(self.current_worker)

    def cancel_recon(self) -> None:
        if self.current_worker:
            self.current_worker.cancel()
            self._on_log("WARNING", "Cancelling reconnaissance pipeline...")
            self.btn_cancel.setEnabled(False)

    def clear_results(self) -> None:
        self.input_domain.clear()
        self.latest_results.clear()
        self.latest_personal_results = None
        self.dossier_text = ""
        self.dossier_browser.clear()
        self.lbl_grade.setText("–")
        self.lbl_score_num.setText("Awaiting audit")
        self.progress_bar.setValue(0)
        self.status_label.setText("Ready.")
        self.btn_export.setEnabled(False)

        for t in (
            self.table_findings,
            self.table_dns,
            self.table_subdomains,
            self.table_takeovers,
            self.table_rdap,
            self.table_exposure,
            self.table_ip_intel,
            self.table_threat,
            self.table_email_sec,
            self.table_web,
            self.table_tech,
            self.table_archive,
        ):
            t.setRowCount(0)

    # -------------------------------------------------------------------------
    # Worker Signal Handlers
    # -------------------------------------------------------------------------

    def _on_started(self, domain: str) -> None:
        self.btn_start.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_export.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Auditing target: {domain}...")

    def _on_progress(self, stage: str, pct: int) -> None:
        self.progress_bar.setValue(pct)
        self.progress_bar.setFormat(f"{stage} (%p%)")
        self.status_label.setText(stage)

    def _on_log(self, level: str, msg: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        color = "#cdd6f4"
        if level == "SUCCESS":
            color = "#a6e3a1"
        elif level == "WARNING":
            color = "#fab387"
        elif level == "ERROR":
            color = "#f38ba8"
        self.text_logs.append(f'<span style="color:#6c7086;">[{ts}]</span> <b style="color:{color};">[{level}]</b> {msg}')

    def _on_module_complete(self, module_name: str, data: Dict[str, Any]) -> None:
        """Progressively populates individual hub tables as background modules finish."""
        self.latest_results[module_name] = data
        try:
            if module_name == "dns":
                self._populate_dns_data(data)
            elif module_name == "takeover":
                self._populate_takeover_data(data)
            elif module_name == "rdap":
                self._populate_rdap_data(data)
            elif module_name == "web":
                self._populate_web_data(data)
            elif module_name == "archive":
                self._populate_archive_data(data)
            elif module_name == "internetdb":
                self._populate_internetdb_data(data)
            elif module_name == "ip_intel":
                self._populate_ip_intel_data(data)
            elif module_name == "urlscan":
                self._populate_urlscan_data(data)
            elif module_name == "email_sec":
                self._populate_email_sec_data(data)
            elif module_name == "tech_stack":
                self._populate_tech_data(data)
        except Exception as exc:
            logger.debug("Progressive update error on %s: %s", module_name, exc)

    def _on_error(self, module_name: str, err: str) -> None:
        self.status_label.setText(f"Error in {module_name}: {err}")
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.progress_bar.setFormat("Error occurred")

    def _on_finished(self, consolidated: Dict[str, Any]) -> None:
        self.latest_results = consolidated
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_export.setEnabled(True)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("Complete (100%)")
        self.status_label.setText("Reconnaissance complete. Executive Dossier ready.")

        self._populate_all_views(consolidated)
        self.text_json.setText(json.dumps(consolidated, indent=2))

    # -------------------------------------------------------------------------
    # Data Population Methods
    # -------------------------------------------------------------------------

    def _populate_dns_data(self, dns_data: Dict[str, Any]) -> None:
        dns_rows = []
        for r_type, records in dns_data.get("records", {}).items():
            for rec in records:
                dns_rows.append([r_type, dns_data.get("domain", ""), rec, "300", "Resolved"])
        self.populate_table_safely(self.table_dns, dns_rows)

        sub_rows = []
        for sub in dns_data.get("subdomains", []):
            sub_rows.append([sub, "Certificate Transparency (crt.sh)", "–", "Passive Enumeration"])
        self.populate_table_safely(self.table_subdomains, sub_rows)

    def _populate_takeover_data(self, takeover_data: Dict[str, Any]) -> None:
        take_rows = []
        for v in takeover_data.get("vulnerabilities", []):
            take_rows.append([
                v.get("subdomain", ""),
                v.get("cname", ""),
                v.get("service", ""),
                "VULNERABLE (Dangling CNAME)",
                "Immediately reclaim external bucket or remove dead CNAME pointer",
            ])
        for c in takeover_data.get("cnames", []):
            take_rows.append([
                c.get("subdomain", ""),
                c.get("cname", ""),
                c.get("service", "Generic Alias"),
                "Active",
                "Monitored",
            ])
        self.populate_table_safely(self.table_takeovers, take_rows)

    def _populate_rdap_data(self, rdap_data: Dict[str, Any]) -> None:
        rdap_rows = [
            ["Registrar Name", rdap_data.get("registrar_name", "N/A"), "Official registrar"],
            ["Registered Domain", rdap_data.get("domain", "N/A"), "TLD delegation"],
            ["Created Date", rdap_data.get("created_date", "N/A"), "Initial registration"],
            ["Expiration Date", rdap_data.get("expiration_date", "N/A"), "Registry expiry"],
            ["Days Until Expiration", str(rdap_data.get("days_until_expiration", "N/A")), "Domain lifecycle health"],
            ["Organization", rdap_data.get("registrant_organization", "Redacted for Privacy"), "Registrant identity"],
        ]
        self.populate_table_safely(self.table_rdap, rdap_rows)

    def _populate_web_data(self, web_data: Dict[str, Any]) -> None:
        web_rows = []
        for h, v in web_data.get("present_headers", {}).items():
            web_rows.append([h, "Configured", str(v)[:60], "Optimal posture"])
        for h in web_data.get("missing_headers", []):
            web_rows.append([h, "MISSING", "None", f"Deploy {h} on perimeter reverse proxy"])
        self.populate_table_safely(self.table_web, web_rows)

    def _populate_archive_data(self, archive_data: Dict[str, Any]) -> None:
        arch_rows = []
        for s in archive_data.get("snapshots", []):
            arch_rows.append(["Historical Milestone", s.get("timestamp", ""), s.get("url", ""), f"HTTP {s.get('status', '200')}"])
        if not arch_rows:
            arch_rows.append(["Archive Status", "No historical snapshots indexed in CDX", "N/A", "N/A"])
        self.populate_table_safely(self.table_archive, arch_rows)

    def _populate_internetdb_data(self, internetdb_data: Dict[str, Any]) -> None:
        exp_rows = []
        ports = internetdb_data.get("all_open_ports", [])
        cves = internetdb_data.get("all_cves", [])
        tags = internetdb_data.get("all_tags", [])
        hostnames = internetdb_data.get("all_hostnames", [])
        exp_rows.append([
            self.input_domain.text().strip(),
            ", ".join(hostnames[:3]) or "None",
            str(ports),
            ", ".join(cves[:5]) or "None indexed",
            ", ".join(tags) or "None",
        ])
        self.populate_table_safely(self.table_exposure, exp_rows)

    def _populate_ip_intel_data(self, ip_data: Dict[str, Any]) -> None:
        ip_rows = []
        countries = ", ".join(ip_data.get("unique_countries", [])) or "Unknown"
        cloud = ", ".join(ip_data.get("cloud_providers_detected", [])) or "Direct Hosting"
        ip_rows.append([
            self.input_domain.text().strip(),
            countries,
            ip_data.get("primary_asn", "Unknown"),
            ip_data.get("primary_isp", "Unknown"),
            cloud,
        ])
        self.populate_table_safely(self.table_ip_intel, ip_rows)

    def _populate_urlscan_data(self, urlscan_data: Dict[str, Any]) -> None:
        threat_rows = []
        for scan in urlscan_data.get("scans", []):
            threat_rows.append([
                "URLScan.io",
                scan.get("time", ""),
                scan.get("page_url", ""),
                scan.get("ip", ""),
                scan.get("result_url", ""),
            ])
        for otx in urlscan_data.get("otx_records", []):
            threat_rows.append([
                "AlienVault OTX",
                otx.get("first", ""),
                otx.get("hostname", ""),
                otx.get("address", ""),
                "OTX Passive DNS",
            ])
        if not threat_rows:
            threat_rows.append(["Threat Archives", "No historical scan records indexed", "Clean", "N/A", "N/A"])
        self.populate_table_safely(self.table_threat, threat_rows)

    def _populate_email_sec_data(self, email_sec_data: Dict[str, Any]) -> None:
        sec_rows = [
            ["SPF (Sender Policy Framework)", email_sec_data.get("spf_status", "Missing"), email_sec_data.get("spf_record", "None"), "Spoofing Prevention"],
            ["DMARC Policy", email_sec_data.get("dmarc_policy", "Missing"), email_sec_data.get("dmarc_record", "None"), "Domain Impersonation Defense"],
            ["DKIM Status", email_sec_data.get("dkim_status", "N/A"), "Selector audit complete", "Cryptographic Signatures"],
            ["BIMI (Brand Identity)", email_sec_data.get("bimi_status", "Missing"), "Brand Logo Assertion", "Visual Verification"],
        ]
        self.populate_table_safely(self.table_email_sec, sec_rows)

    def _populate_tech_data(self, tech_data: Dict[str, Any]) -> None:
        tech_rows = []
        for t in tech_data.get("technologies", []):
            tech_rows.append([t.get("category", "General"), t.get("name", ""), t.get("version", "Latest"), "Signature Matching"])
        sec_txt = tech_data.get("security_txt", {})
        if sec_txt.get("found"):
            tech_rows.append(["Vulnerability Policy", "security.txt", "Present", "Coordinated Disclosure"])
        if not tech_rows:
            tech_rows.append(["Technology Stack", "Standard Web Server", "N/A", "Passive Fingerprinting"])
        self.populate_table_safely(self.table_tech, tech_rows)

    def _populate_all_views(self, data: Dict[str, Any]) -> None:
        scorecard = data.get("scorecard", {})
        grade = scorecard.get("grade", "N/A")
        score = scorecard.get("score", 0)

        self.lbl_grade.setText(grade)
        self.lbl_score_num.setText(f"{score}/100 Posture Score")

        # Update metrics badges
        takeovers = data.get("takeover", {}).get("vulnerabilities", [])
        self.lbl_metric_takeover.setText(f"Takeovers: {len(takeovers)} Vulnerable")
        if takeovers:
            self.lbl_metric_takeover.setStyleSheet(
                "background-color: #181825; padding: 8px 12px; border-radius: 6px; font-weight: 700; color: #f38ba8;"
            )
        else:
            self.lbl_metric_takeover.setStyleSheet(
                "background-color: #181825; padding: 8px 12px; border-radius: 6px; font-weight: 600; color: #a6e3a1;"
            )

        email_sec = data.get("email_sec", {})
        self.lbl_metric_email.setText(f"Email Def: Grade {email_sec.get('spoofing_grade', 'N/A')}")
        self.lbl_metric_dnssec.setText(f"DNSSEC: {'Enabled' if data.get('dns', {}).get('has_dnssec') else 'Disabled'}")
        self.lbl_metric_headers.setText(f"Missing Headers: {len(data.get('web', {}).get('missing_headers', []))}")
        self.lbl_metric_tls.setText(f"TLS Cert: {'Valid' if data.get('web', {}).get('tls_valid') else 'Audit OK'}")

        # Findings Table
        findings_rows = []
        for f in scorecard.get("findings", []):
            findings_rows.append([
                f.get("severity", "MEDIUM"),
                "Defensive Posture",
                f.get("title", ""),
                f.get("remediation", ""),
            ])
        self.populate_table_safely(self.table_findings, findings_rows)

    # -------------------------------------------------------------------------
    # Reports & Desktop Shortcut
    # -------------------------------------------------------------------------

    def _export_report(self, fmt: str) -> None:
        if not self.latest_results:
            QMessageBox.warning(self, "No Data", "No audit telemetry to export. Please run a reconnaissance scan first.")
            return

        domain = self.latest_results.get("domain", "recon_audit")
        safe_domain = sanitize_filename(domain)
        default_name = f"OSINT_Audit_{safe_domain}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

        if fmt == "json":
            path, _ = QFileDialog.getSaveFileName(self, "Export JSON", f"{default_name}.json", "JSON (*.json)")
            if path:
                ReconExporter.export_json(self.latest_results, path)
                QMessageBox.information(self, "Export Success", f"Exported JSON report to:\n{path}")
        elif fmt == "markdown":
            path, _ = QFileDialog.getSaveFileName(self, "Export Markdown", f"{default_name}.md", "Markdown (*.md)")
            if path:
                ReconExporter.export_markdown(self.latest_results, path)
                QMessageBox.information(self, "Export Success", f"Exported Markdown dossier to:\n{path}")
        elif fmt == "html":
            path, _ = QFileDialog.getSaveFileName(self, "Export HTML", f"{default_name}.html", "HTML (*.html)")
            if path:
                ReconExporter.export_html(self.latest_results, path)
                QMessageBox.information(self, "Export Success", f"Exported HTML report to:\n{path}")
        elif fmt == "csv":
            path, _ = QFileDialog.getSaveFileName(self, "Export Subdomains CSV", f"{default_name}_subdomains.csv", "CSV (*.csv)")
            if path:
                ReconExporter.export_subdomains_csv(self.latest_results.get("dns", {}).get("subdomains", []), path)
                QMessageBox.information(self, "Export Success", f"Exported CSV to:\n{path}")

    def _create_desktop_shortcut(self) -> None:
        """Creates a desktop shortcut pointing to the application executable or launcher."""
        try:
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            if not os.path.exists(desktop):
                desktop = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")

            shortcut_path = os.path.join(desktop, "OSINT Recon Studio.lnk")
            exe_path = sys.executable
            icon_path = get_app_icon_path() or exe_path

            vbs_script = f"""
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "{shortcut_path}"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "{exe_path}"
oLink.WorkingDirectory = "{os.path.dirname(exe_path)}"
oLink.Description = "OSINT Recon Studio - Defensive Reconnaissance & Privacy Suite"
oLink.IconLocation = "{icon_path}"
oLink.Save
"""
            vbs_path = os.path.join(os.environ.get("TEMP", os.path.expanduser("~")), "create_shortcut.vbs")
            with open(vbs_path, "w", encoding="utf-8") as f:
                f.write(vbs_script)

            subprocess.run(["cscript", "//nologo", vbs_path], check=True, capture_output=True)
            try:
                os.remove(vbs_path)
            except Exception:
                pass

            QMessageBox.information(
                self,
                "Shortcut Created",
                f"Successfully created desktop shortcut with custom icon:\n\n{shortcut_path}",
            )
        except Exception as exc:
            logger.exception("Desktop shortcut creation failed")
            QMessageBox.critical(self, "Shortcut Error", f"Failed to create desktop shortcut:\n{exc}")

    def toggle_theme(self) -> None:
        new_theme = "monochrome" if self.current_theme == "mocha" else "mocha"
        self.set_theme(new_theme)
        self.config["theme"] = new_theme
        save_config(self.config)

    def set_theme(self, theme_name: str) -> None:
        self.current_theme = theme_name
        qss = get_theme_stylesheet(theme_name)
        app = QApplication.instance()
        if app:
            app.setStyleSheet(qss)
        if hasattr(self, "btn_theme_toggle"):
            self.btn_theme_toggle.setText("🎨 Catppuccin" if theme_name == "monochrome" else "🌓 Monochrome")

    def _open_settings_dialog(self) -> None:
        dlg = SettingsDialog(self)
        dlg.exec()

    def _show_ethics_dialog(self) -> None:
        QMessageBox.information(
            self,
            "Defensive & Legal Scope",
            "OSINT Recon Studio is built strictly for authorized defensive security auditing, "
            "attack surface mapping, and personal privacy self-assessment.\n\n"
            "All queries utilize passive public DNS, Certificate Transparency logs, public APIs, "
            "and standard RFC protocols without intrusive exploitation.",
        )

    def _show_about_dialog(self) -> None:
        QMessageBox.about(
            self,
            "About OSINT Recon Studio",
            "<b>OSINT Recon Studio v1.4.0</b><br>"
            "Principal Windows Desktop Reconnaissance & Personal Privacy Suite.<br><br>"
            "Features 5 Consolidated Category Hubs, HTTP/2 multiplexing, SQLite TTL caching, "
            "and an Ultra-Low-RAM Local AI Intelligence Analyst."
        )
