"""Main Window for OSINT Recon Studio.

Provides a responsive native Windows interface for passive attack surface auditing
and personal privacy self-assessment, featuring a modern left navigation sidebar
and 19 modular views:
Domain & Attack Surface Recon:
  1. Executive Overview & Scorecard
  2. DNS & Subdomains
  3. Dangling CNAMEs & Takeover
  4. RDAP & Whois Ownership
  5. Passive Exposure (InternetDB)
  6. IP Geolocation, ASN & Cloud
  7. Threat History (URLScan/OTX)
  8. Web Posture & Headers
  9. Email Security Posture
  10. Tech Stack & Manifests
  11. GitHub Org & Footprint
  12. Public PGP Keyservers
  13. Brand / Username Checker
  14. Document Metadata (Exif)
  15. Wayback Machine History
  16. Live Activity Logs & JSON
Personal Privacy & Identity Audit:
  17. Phone Number Privacy & Carrier
  18. Email Breach & Avatar Leak
  19. Social Media Exposure & Linkability
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
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from osint_studio.core.domain_utils import extract_brand_handle, normalize_domain, sanitize_filename
from osint_studio.core.email_privacy_engine import EmailPrivacyEngine, EmailPrivacyReport
from osint_studio.core.exporter import ReconExporter
from osint_studio.core.github_osint_engine import audit_github_footprint
from osint_studio.core.metadata_engine import MetadataEngine
from osint_studio.core.phone_privacy_engine import PhonePrivacyEngine, PhonePrivacyReport
from osint_studio.core.social_privacy_engine import SocialPrivacyEngine, SocialPrivacyReport
from osint_studio.core.username_engine import check_brand_handles
from osint_studio.ui.settings_dialog import SettingsDialog, load_config
from osint_studio.ui.styles import CATPPUCCIN_MOCHA_QSS
from osint_studio.ui.workers import ReconWorker

logger = logging.getLogger(__name__)


def get_app_icon_path() -> Optional[str]:
    """Resolves path to app_icon.ico in both developer mode and PyInstaller frozen runtime."""
    candidates = []
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        candidates.append(Path(sys._MEIPASS) / "assets" / "app_icon.ico")
        candidates.append(Path(sys.executable).parent / "assets" / "app_icon.ico")

    proj_root = Path(__file__).resolve().parent.parent.parent
    candidates.append(proj_root / "assets" / "app_icon.ico")

    for c in candidates:
        if c.exists():
            return str(c)
    return None


class MainWindow(QMainWindow):
    """Main Application Window for OSINT Recon Studio with left sidebar navigation."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("OSINT Recon Studio - Passive Domain & Attack Surface Studio")
        self.resize(1420, 920)
        self.setMinimumSize(1140, 760)

        # Set window icon
        icon_path = get_app_icon_path()
        if icon_path:
            self.setWindowIcon(QIcon(icon_path))

        self.thread_pool = QThreadPool()
        self.current_worker: Optional[ReconWorker] = None
        self.current_report: Optional[Dict[str, Any]] = None
        self.metadata_engine = MetadataEngine()

        self._init_ui()
        self.setStyleSheet(CATPPUCCIN_MOCHA_QSS)

    def closeEvent(self, event: QCloseEvent) -> None:
        """Gracefully halts active background workers when closing window to avoid thread destruction crashes."""
        if self.current_worker:
            self.current_worker.cancel()
        self.thread_pool.waitForDone(1500)
        event.accept()

    # -------------------------------------------------------------------------
    # UI Initialization & Sidebar Layout
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

        self.status_label = QLabel("Ready to audit target domain or personal identity.")
        self.status_label.setStyleSheet("color: #a6adc8; font-weight: 500;")

        prog_bar_layout.addWidget(self.status_label, 1)
        prog_bar_layout.addWidget(self.progress_bar, 2)
        main_layout.addLayout(prog_bar_layout)

        # Main Workspace: Left Navigation Sidebar + Right QStackedWidget
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(4)

        # Left Navigation Sidebar (QListWidget)
        self.nav_sidebar = QListWidget()
        self.nav_sidebar.setObjectName("navSidebar")
        self.nav_sidebar.setFixedWidth(260)
        self._init_sidebar_items()

        # Right Stacked Widget
        self.stacked_widget = QStackedWidget()
        self._init_stacked_views()

        # Connect sidebar selection to stacked views
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
        self.status_bar.showMessage("Ready. Enter a target domain above or navigate to Personal Privacy Audit.")

    def _init_sidebar_items(self) -> None:
        """Populates the navigation sidebar with category items and icons."""
        nav_items = [
            # Domain Attack Surface
            "📊 Executive Overview",
            "🌐 DNS & Subdomains",
            "⚡ Dangling CNAMEs & Takeover",
            "📋 RDAP & Whois Ownership",
            "🔍 Passive Exposure (InternetDB)",
            "🌍 IP Geolocation, ASN & Cloud",
            "🗄️ Threat History (URLScan/OTX)",
            "🛡️ Web Posture & Headers",
            "✉️ Email Security Posture",
            "⚙️ Tech Stack & Manifests",
            "🐙 GitHub Org & Footprint",
            "🔑 Public PGP Keyservers",
            "👤 Brand / Username Checker",
            "📁 Document Metadata (Exif)",
            "⏳ Wayback Machine History",
            "📜 Live Activity Logs & JSON",
            # Personal Privacy & Self-Audit Suite
            "📱 Phone Privacy & Carrier",
            "📧 Email Breach & Avatar Leak",
            "👥 Social Exposure & Linkability",
        ]
        for item_text in nav_items:
            item = QListWidgetItem(item_text)
            self.nav_sidebar.addItem(item)

    def _init_stacked_views(self) -> None:
        """Instantiates and registers each view widget into the QStackedWidget."""
        # 0 - 15: Domain Attack Surface
        self.stacked_widget.addWidget(self._create_overview_view())       # 0
        self.stacked_widget.addWidget(self._create_dns_view())            # 1
        self.stacked_widget.addWidget(self._create_takeover_view())       # 2
        self.stacked_widget.addWidget(self._create_rdap_view())           # 3
        self.stacked_widget.addWidget(self._create_exposure_view())       # 4
        self.stacked_widget.addWidget(self._create_ip_intel_view())       # 5
        self.stacked_widget.addWidget(self._create_threat_history_view()) # 6
        self.stacked_widget.addWidget(self._create_web_view())            # 7
        self.stacked_widget.addWidget(self._create_email_security_view()) # 8
        self.stacked_widget.addWidget(self._create_tech_view())           # 9
        self.stacked_widget.addWidget(self._create_github_view())         # 10
        self.stacked_widget.addWidget(self._create_pgp_view())            # 11
        self.stacked_widget.addWidget(self._create_username_view())       # 12
        self.stacked_widget.addWidget(self._create_metadata_view())       # 13
        self.stacked_widget.addWidget(self._create_archive_view())        # 14
        self.stacked_widget.addWidget(self._create_logs_view())           # 15
        # 16 - 18: Personal Privacy & Identity Audit Suite
        self.stacked_widget.addWidget(self._create_phone_privacy_view())  # 16
        self.stacked_widget.addWidget(self._create_email_privacy_view())  # 17
        self.stacked_widget.addWidget(self._create_social_privacy_view()) # 18

    # -------------------------------------------------------------------------
    # Menu & Control Bars
    # -------------------------------------------------------------------------

    def _create_menu_bar(self) -> None:
        menubar = self.menuBar()

        # File Menu
        file_menu = menubar.addMenu("&File")

        act_export_json = QAction("Export JSON Report...", self)
        act_export_json.setShortcut("Ctrl+J")
        act_export_json.triggered.connect(lambda: self._export_report("json"))
        file_menu.addAction(act_export_json)

        act_export_md = QAction("Export Markdown Report...", self)
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
        frame.setStyleSheet("background-color: #25273a; border-radius: 8px; padding: 4px;")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(10)

        lbl = QLabel("Target Domain:")
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
        export_menu.addAction("Export as Markdown", lambda: self._export_report("markdown"))
        export_menu.addAction("Export as HTML (Print to PDF)", lambda: self._export_report("html"))
        self.btn_export.setMenu(export_menu)
        layout.addWidget(self.btn_export)

        return frame

    def _create_options_bar(self) -> QWidget:
        group = QGroupBox("Active Reconnaissance Pipeline Modules")
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

        self.chk_username = QCheckBox("Brand Checker")
        self.chk_username.setChecked(True)
        layout.addWidget(self.chk_username)

        layout.addStretch(1)
        return group

    # -------------------------------------------------------------------------
    # Desktop Shortcut Creator
    # -------------------------------------------------------------------------

    def _create_desktop_shortcut(self) -> None:
        """Creates an official desktop shortcut pointing to the compiled EXE or launcher."""
        try:
            desktop = Path(os.environ.get("USERPROFILE", "")) / "Desktop"
            if not desktop.exists():
                desktop = Path.home() / "Desktop"

            shortcut_path = desktop / "OSINT Recon Studio.lnk"

            proj_root = Path(__file__).resolve().parent.parent.parent
            exe_target = proj_root / "dist" / "OSINTReconStudio" / "OSINTReconStudio.exe"
            if not exe_target.exists():
                exe_target = proj_root / "run_app.bat"

            icon_target = get_app_icon_path() or ""

            ps_script = f"""
            $ws = New-Object -ComObject WScript.Shell
            $s = $ws.CreateShortcut('{shortcut_path}')
            $s.TargetPath = '{exe_target}'
            $s.WorkingDirectory = '{proj_root}'
            $s.Description = 'OSINT Recon Studio - Native Windows Passive OSINT & Privacy Studio'
            if ('{icon_target}' -ne '' -and (Test-Path '{icon_target}')) {{
                $s.IconLocation = '{icon_target},0'
            }}
            $s.Save()
            """
            subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                check=True,
                capture_output=True,
            )
            QMessageBox.information(
                self,
                "Desktop Shortcut Created",
                f"Successfully created shortcut on your Windows Desktop:\n\n{shortcut_path}",
            )
        except Exception as exc:
            QMessageBox.warning(
                self,
                "Shortcut Creation Failed",
                f"Could not automatically create desktop shortcut:\n{exc}\n\nYou can manually run 'Create_Desktop_Shortcut.bat' in the project directory.",
            )

    # -------------------------------------------------------------------------
    # Safe Table Population & Interaction Helpers
    # -------------------------------------------------------------------------

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

    def _setup_table_interactions(self, table: QTableWidget) -> None:
        """Configures right-click context menu and double-click link handler for a table."""
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

        menu = QMenu(self)
        cell_text = item.text().strip()

        act_copy = menu.addAction("Copy Cell Value")
        act_copy.triggered.connect(lambda: QApplication.clipboard().setText(cell_text))

        act_copy_row = menu.addAction("Copy Entire Row (Tab-Delimited)")
        row_idx = item.row()
        row_vals = [table.item(row_idx, c).text() if table.item(row_idx, c) else "" for c in range(table.columnCount())]
        act_copy_row.triggered.connect(lambda: QApplication.clipboard().setText("\t".join(row_vals)))

        if re.search(r"https?://[^\s]+", cell_text) or cell_text.startswith("www."):
            menu.addSeparator()
            act_open = menu.addAction("Open Link in Default Browser")
            url_target = cell_text if cell_text.startswith("http") else f"https://{cell_text}"
            act_open.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(url_target)))

        menu.exec(table.viewport().mapToGlobal(pos))

    def _on_table_cell_double_clicked(self, table: QTableWidget, row: int, col: int) -> None:
        item = table.item(row, col)
        if not item:
            return
        text = item.text().strip()
        match = re.search(r"https?://[^\s]+", text)
        if match:
            QDesktopServices.openUrl(QUrl(match.group(0)))
        elif text.startswith("www."):
            QDesktopServices.openUrl(QUrl(f"https://{text}"))

    # -------------------------------------------------------------------------
    # View 0: Executive Overview & Scorecard
    # -------------------------------------------------------------------------

    def _create_overview_view(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(14)

        left_col = QVBoxLayout()
        left_col.setSpacing(12)

        self.card_score = QGroupBox("Overall Security Posture")
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

        left_col.addWidget(self.card_score)

        self.card_metrics = QGroupBox("Attack Surface Key Metrics")
        metrics_layout = QGridLayout(self.card_metrics)
        metrics_layout.setSpacing(10)

        self.lbl_metric_takeover = QLabel("Takeover Risk: –")
        self.lbl_metric_email = QLabel("Email Defense: –")
        self.lbl_metric_dnssec = QLabel("DNSSEC: –")
        self.lbl_metric_headers = QLabel("Headers: –")
        self.lbl_metric_tls = QLabel("TLS Cert: –")
        self.lbl_metric_exposure = QLabel("InternetDB: –")
        self.lbl_metric_cloud = QLabel("Cloud / CDN: –")
        self.lbl_metric_subs = QLabel("CT Subdomains: –")

        for lbl_w in [
            self.lbl_metric_takeover,
            self.lbl_metric_email,
            self.lbl_metric_dnssec,
            self.lbl_metric_headers,
            self.lbl_metric_tls,
            self.lbl_metric_exposure,
            self.lbl_metric_cloud,
            self.lbl_metric_subs,
        ]:
            lbl_w.setStyleSheet("background-color: #181825; padding: 8px 12px; border-radius: 6px; font-weight: 600;")

        metrics_layout.addWidget(self.lbl_metric_takeover, 0, 0)
        metrics_layout.addWidget(self.lbl_metric_email, 0, 1)
        metrics_layout.addWidget(self.lbl_metric_dnssec, 1, 0)
        metrics_layout.addWidget(self.lbl_metric_headers, 1, 1)
        metrics_layout.addWidget(self.lbl_metric_tls, 2, 0)
        metrics_layout.addWidget(self.lbl_metric_exposure, 2, 1)
        metrics_layout.addWidget(self.lbl_metric_cloud, 3, 0)
        metrics_layout.addWidget(self.lbl_metric_subs, 3, 1)

        left_col.addWidget(self.card_metrics)
        left_col.addStretch(1)

        # Right Column: Action Items & Findings List
        right_col = QVBoxLayout()
        right_col.setSpacing(10)

        group_findings = QGroupBox("Actionable Findings & Remediation Guidance")
        findings_layout = QVBoxLayout(group_findings)

        self.list_findings = QListWidget()
        self.list_findings.setStyleSheet("background-color: #181825; border-radius: 6px; padding: 6px;")
        findings_layout.addWidget(self.list_findings)

        right_col.addWidget(group_findings)

        layout.addLayout(left_col, 1)
        layout.addLayout(right_col, 2)
        return widget

    # -------------------------------------------------------------------------
    # View 1: DNS & Subdomains
    # -------------------------------------------------------------------------

    def _create_dns_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        splitter = QSplitter(Qt.Vertical)

        # Standard DNS Records
        grp_dns = QGroupBox("Standard DNS Records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA)")
        v_dns = QVBoxLayout(grp_dns)

        filter_box = QHBoxLayout()
        filter_box.addWidget(QLabel("Filter Records:"))
        self.input_filter_dns = QLineEdit()
        self.input_filter_dns.setPlaceholderText("Filter by record type or value...")
        self.input_filter_dns.textChanged.connect(self._filter_dns_table)
        filter_box.addWidget(self.input_filter_dns)
        v_dns.addLayout(filter_box)

        self.table_dns = QTableWidget(0, 4)
        self.table_dns.setHorizontalHeaderLabels(["Record Type", "Name / Host", "Value / Target", "TTL"])
        self.table_dns.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_dns.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        self.table_dns.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_dns.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._setup_table_interactions(self.table_dns)
        v_dns.addWidget(self.table_dns)

        # CT & Discovered Subdomains
        grp_ct = QGroupBox("Certificate Transparency & Passive DNS Discovered Subdomains")
        v_ct = QVBoxLayout(grp_ct)

        ct_ctrl = QHBoxLayout()
        self.lbl_sub_count = QLabel("Subdomains Discovered: 0")
        self.lbl_sub_count.setStyleSheet("font-weight: 700; color: #89b4fa;")
        ct_ctrl.addWidget(self.lbl_sub_count)
        ct_ctrl.addStretch(1)

        btn_copy_subs = QPushButton("Copy All Subdomains")
        btn_copy_subs.clicked.connect(self._copy_subdomains_to_clipboard)
        ct_ctrl.addWidget(btn_copy_subs)
        v_ct.addLayout(ct_ctrl)

        self.table_ct = QTableWidget(0, 3)
        self.table_ct.setHorizontalHeaderLabels(["Discovered Subdomain", "Source / Issuer", "Logged Date"])
        self.table_ct.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table_ct.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        self.table_ct.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self._setup_table_interactions(self.table_ct)
        v_ct.addWidget(self.table_ct)

        splitter.addWidget(grp_dns)
        splitter.addWidget(grp_ct)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)
        return widget

    # -------------------------------------------------------------------------
    # View 2: Dangling CNAMEs & Subdomain Takeover
    # -------------------------------------------------------------------------

    def _create_takeover_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        banner = QGroupBox("Subdomain Takeover & Dangling DNS Risk Summary")
        b_layout = QHBoxLayout(banner)

        self.lbl_takeover_vuln = QLabel("Vulnerable: 0")
        self.lbl_takeover_vuln.setStyleSheet("font-size: 14px; font-weight: 700; color: #a6e3a1; padding: 6px 12px; background: #181825; border-radius: 6px;")
        b_layout.addWidget(self.lbl_takeover_vuln)

        self.lbl_takeover_dangling = QLabel("Dangling CNAMEs: 0")
        self.lbl_takeover_dangling.setStyleSheet("font-size: 14px; font-weight: 700; color: #fab387; padding: 6px 12px; background: #181825; border-radius: 6px;")
        b_layout.addWidget(self.lbl_takeover_dangling)

        self.lbl_takeover_total = QLabel("Total CNAMEs Analyzed: 0")
        self.lbl_takeover_total.setStyleSheet("font-size: 14px; font-weight: 700; color: #89b4fa; padding: 6px 12px; background: #181825; border-radius: 6px;")
        b_layout.addWidget(self.lbl_takeover_total)

        b_layout.addStretch(1)
        layout.addWidget(banner)

        grp_table = QGroupBox("CNAME Aliases & Target Resolution Findings")
        v_tbl = QVBoxLayout(grp_table)

        self.table_takeover = QTableWidget(0, 6)
        self.table_takeover.setHorizontalHeaderLabels([
            "Subdomain", "CNAME Target Host", "Cloud Provider", "Status", "Risk Level", "Description & Guidance"
        ])
        self.table_takeover.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table_takeover.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        self.table_takeover.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_takeover.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_takeover.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_takeover.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self._setup_table_interactions(self.table_takeover)
        v_tbl.addWidget(self.table_takeover)

        layout.addWidget(grp_table)
        return widget

    # -------------------------------------------------------------------------
    # View 3: RDAP & Whois Ownership
    # -------------------------------------------------------------------------

    def _create_rdap_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        group_reg = QGroupBox("Domain Registration Lifecycle & Registrar Details")
        reg_layout = QGridLayout(group_reg)
        reg_layout.setSpacing(10)

        self.lbl_rdap_registrar = QLabel("–")
        self.lbl_rdap_iana = QLabel("–")
        self.lbl_rdap_abuse_email = QLabel("–")
        self.lbl_rdap_abuse_phone = QLabel("–")
        self.lbl_rdap_created = QLabel("–")
        self.lbl_rdap_expires = QLabel("–")
        self.lbl_rdap_age = QLabel("–")
        self.lbl_rdap_days_left = QLabel("–")
        self.lbl_rdap_privacy = QLabel("–")
        self.lbl_rdap_nameservers = QLabel("–")

        reg_layout.addWidget(QLabel("Registrar:"), 0, 0)
        reg_layout.addWidget(self.lbl_rdap_registrar, 0, 1)
        reg_layout.addWidget(QLabel("IANA ID:"), 0, 2)
        reg_layout.addWidget(self.lbl_rdap_iana, 0, 3)

        reg_layout.addWidget(QLabel("Created Date:"), 1, 0)
        reg_layout.addWidget(self.lbl_rdap_created, 1, 1)
        reg_layout.addWidget(QLabel("Expiration Date:"), 1, 2)
        reg_layout.addWidget(self.lbl_rdap_expires, 1, 3)

        reg_layout.addWidget(QLabel("Domain Age:"), 2, 0)
        reg_layout.addWidget(self.lbl_rdap_age, 2, 1)
        reg_layout.addWidget(QLabel("Days Until Expiration:"), 2, 2)
        reg_layout.addWidget(self.lbl_rdap_days_left, 2, 3)

        reg_layout.addWidget(QLabel("Privacy Protected:"), 3, 0)
        reg_layout.addWidget(self.lbl_rdap_privacy, 3, 1)
        reg_layout.addWidget(QLabel("Abuse Email:"), 3, 2)
        reg_layout.addWidget(self.lbl_rdap_abuse_email, 3, 3)

        reg_layout.addWidget(QLabel("Delegated Nameservers:"), 4, 0)
        reg_layout.addWidget(self.lbl_rdap_nameservers, 4, 1, 1, 3)

        layout.addWidget(group_reg)

        group_ent = QGroupBox("Disclosed Entities, Contacts & Roles")
        ent_layout = QVBoxLayout(group_ent)

        self.table_entities = QTableWidget(0, 5)
        self.table_entities.setHorizontalHeaderLabels(["Roles", "Contact Name", "Organization", "Email", "Phone"])
        self.table_entities.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._setup_table_interactions(self.table_entities)
        ent_layout.addWidget(self.table_entities)

        layout.addWidget(group_ent)
        return widget

    # -------------------------------------------------------------------------
    # View 4: Passive Exposure (InternetDB)
    # -------------------------------------------------------------------------

    def _create_exposure_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        grp_idb = QGroupBox("Shodan InternetDB Passive Service Fingerprints (Zero Port Scanning)")
        v_idb = QVBoxLayout(grp_idb)

        self.table_idb = QTableWidget(0, 5)
        self.table_idb.setHorizontalHeaderLabels([
            "IP Address", "Historical Open Ports", "CPE Software Identifiers", "Tags / Infrastructure", "Indexed CVE Vulnerabilities"
        ])
        self.table_idb.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table_idb.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_idb.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_idb.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_idb.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self._setup_table_interactions(self.table_idb)
        v_idb.addWidget(self.table_idb)

        layout.addWidget(grp_idb)
        return widget

    # -------------------------------------------------------------------------
    # View 5: IP Geolocation, ASN & Cloud
    # -------------------------------------------------------------------------

    def _create_ip_intel_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        grp_geo = QGroupBox("Resolved Public IP Geolocation, ASN, and Cloud Infrastructure")
        v_geo = QVBoxLayout(grp_geo)

        self.table_ip_geo = QTableWidget(0, 6)
        self.table_ip_geo.setHorizontalHeaderLabels([
            "IP Address", "Country", "City / Region", "Autonomous System (ASN)", "ISP / Organization", "Detected Cloud / CDN"
        ])
        self.table_ip_geo.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table_ip_geo.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_ip_geo.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_ip_geo.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_ip_geo.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table_ip_geo.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self._setup_table_interactions(self.table_ip_geo)
        v_geo.addWidget(self.table_ip_geo)

        layout.addWidget(grp_geo)
        return widget

    # -------------------------------------------------------------------------
    # View 6: Threat History (URLScan & OTX)
    # -------------------------------------------------------------------------

    def _create_threat_history_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        splitter = QSplitter(Qt.Vertical)

        # URLScan.io Historical Scans
        grp_urlscan = QGroupBox("URLScan.io Historical Scans & Archived Observations")
        v_url = QVBoxLayout(grp_urlscan)

        self.lbl_threat_stats = QLabel("Total Scans: 0 | Observed IPs: None | Observed ASNs: None")
        self.lbl_threat_stats.setStyleSheet("font-weight: 600; color: #89b4fa; padding: 4px;")
        v_url.addWidget(self.lbl_threat_stats)

        self.table_urlscan = QTableWidget(0, 6)
        self.table_urlscan.setHorizontalHeaderLabels([
            "Scan Date", "Target URL", "Observed IP", "ASN", "Page Title", "Public Scan Link"
        ])
        self.table_urlscan.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_urlscan.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        self.table_urlscan.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_urlscan.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_urlscan.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table_urlscan.horizontalHeader().setSectionResizeMode(5, QHeaderView.Interactive)
        self._setup_table_interactions(self.table_urlscan)
        v_url.addWidget(self.table_urlscan)

        # AlienVault OTX Passive DNS
        grp_otx = QGroupBox("AlienVault OTX Passive DNS Transitions")
        v_otx = QVBoxLayout(grp_otx)

        self.table_otx = QTableWidget(0, 5)
        self.table_otx.setHorizontalHeaderLabels([
            "Record Type", "Resolved Address / Host", "First Seen", "Last Seen", "ASN"
        ])
        self.table_otx.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_otx.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_otx.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_otx.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_otx.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self._setup_table_interactions(self.table_otx)
        v_otx.addWidget(self.table_otx)

        splitter.addWidget(grp_urlscan)
        splitter.addWidget(grp_otx)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)
        return widget

    # -------------------------------------------------------------------------
    # View 7: Web Posture & Headers
    # -------------------------------------------------------------------------

    def _create_web_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        grp_tls = QGroupBox("TLS / SSL Handshake & Certificate Posture")
        tls_layout = QGridLayout(grp_tls)
        tls_layout.setSpacing(8)

        self.lbl_web_canonical = QLabel("Canonical URL: –")
        self.lbl_web_server = QLabel("Server Banner: –")
        self.lbl_web_tls = QLabel("TLS Version / Cipher: –")
        self.lbl_web_cert_issuer = QLabel("Cert Issuer: –")

        tls_layout.addWidget(self.lbl_web_canonical, 0, 0)
        tls_layout.addWidget(self.lbl_web_server, 0, 1)
        tls_layout.addWidget(self.lbl_web_tls, 1, 0)
        tls_layout.addWidget(self.lbl_web_cert_issuer, 1, 1)

        layout.addWidget(grp_tls)

        grp_headers = QGroupBox("HTTP Security Response Headers Audit")
        h_layout = QVBoxLayout(grp_headers)

        self.table_headers = QTableWidget(0, 4)
        self.table_headers.setHorizontalHeaderLabels(["Security Header", "Status", "Observed Value", "Hardening Recommendation"])
        self.table_headers.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table_headers.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_headers.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_headers.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self._setup_table_interactions(self.table_headers)
        h_layout.addWidget(self.table_headers)

        layout.addWidget(grp_headers)
        return widget

    # -------------------------------------------------------------------------
    # View 8: Email Security Posture
    # -------------------------------------------------------------------------

    def _create_email_security_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        grp_top = QGroupBox("Domain Email Spoofing Defense Posture")
        top_layout = QHBoxLayout(grp_top)

        self.lbl_email_grade = QLabel("Grade –")
        self.lbl_email_grade.setStyleSheet("font-size: 32px; font-weight: 800; color: #89b4fa; padding: 10px 20px; background: #181825; border-radius: 8px;")
        top_layout.addWidget(self.lbl_email_grade)

        self.lbl_email_summary = QLabel("Awaiting audit...")
        self.lbl_email_summary.setStyleSheet("font-size: 13px; color: #cdd6f4;")
        top_layout.addWidget(self.lbl_email_summary, 1)

        layout.addWidget(grp_top)

        grp_rec = QGroupBox("Email Defense Records (SPF, DMARC, BIMI, MTA-STS)")
        rec_layout = QGridLayout(grp_rec)

        self.lbl_em_spf = QLabel("SPF Status: –")
        self.lbl_em_dmarc = QLabel("DMARC Policy: –")
        self.lbl_em_dkim = QLabel("Active DKIM Selectors: –")
        self.lbl_em_bimi = QLabel("BIMI: –")
        self.lbl_em_mta = QLabel("MTA-STS: –")

        for lbl_w in [self.lbl_em_spf, self.lbl_em_dmarc, self.lbl_em_dkim, self.lbl_em_bimi, self.lbl_em_mta]:
            lbl_w.setStyleSheet("background-color: #181825; padding: 8px; border-radius: 6px;")

        rec_layout.addWidget(self.lbl_em_spf, 0, 0)
        rec_layout.addWidget(self.lbl_em_dmarc, 0, 1)
        rec_layout.addWidget(self.lbl_em_dkim, 1, 0)
        rec_layout.addWidget(self.lbl_em_bimi, 1, 1)
        rec_layout.addWidget(self.lbl_em_mta, 2, 0, 1, 2)

        layout.addWidget(grp_rec)

        grp_dkim_tbl = QGroupBox("DKIM Selector Probing Results")
        dk_layout = QVBoxLayout(grp_dkim_tbl)

        self.table_dkim = QTableWidget(0, 4)
        self.table_dkim.setHorizontalHeaderLabels(["Common Selector", "Target Host Name", "Status", "Discovered TXT Record Value"])
        self.table_dkim.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_dkim.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        self.table_dkim.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_dkim.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self._setup_table_interactions(self.table_dkim)
        dk_layout.addWidget(self.table_dkim)

        layout.addWidget(grp_dkim_tbl)
        return widget

    # -------------------------------------------------------------------------
    # View 9: Tech Stack & Manifests
    # -------------------------------------------------------------------------

    def _create_tech_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        grp_tech = QGroupBox("Detected Web Technologies, CMS, & Frameworks")
        t_layout = QVBoxLayout(grp_tech)

        self.table_tech = QTableWidget(0, 3)
        self.table_tech.setHorizontalHeaderLabels(["Technology", "Category", "Detection Evidence"])
        self.table_tech.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table_tech.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_tech.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._setup_table_interactions(self.table_tech)
        t_layout.addWidget(self.table_tech)

        layout.addWidget(grp_tech)

        splitter_man = QSplitter(Qt.Horizontal)

        grp_sec = QGroupBox("RFC 9116 security.txt")
        s_layout = QVBoxLayout(grp_sec)
        self.txt_sec_txt = QTextEdit()
        self.txt_sec_txt.setReadOnly(True)
        s_layout.addWidget(self.txt_sec_txt)

        grp_rob = QGroupBox("robots.txt Disallowed Paths")
        r_layout = QVBoxLayout(grp_rob)
        self.txt_robots_disallow = QTextEdit()
        self.txt_robots_disallow.setReadOnly(True)
        r_layout.addWidget(self.txt_robots_disallow)

        splitter_man.addWidget(grp_sec)
        splitter_man.addWidget(grp_rob)

        layout.addWidget(splitter_man)
        return widget

    # -------------------------------------------------------------------------
    # View 10: GitHub Org & Code Footprint
    # -------------------------------------------------------------------------

    def _create_github_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        top_h = QHBoxLayout()
        top_h.addWidget(QLabel("GitHub Handle / Org:"))
        self.input_gh_handle = QLineEdit()
        self.input_gh_handle.setPlaceholderText("e.g. github, google, or cloudflare")
        top_h.addWidget(self.input_gh_handle, 1)

        btn_gh_query = QPushButton("Search GitHub Footprint")
        btn_gh_query.clicked.connect(self._manual_github_lookup)
        top_h.addWidget(btn_gh_query)
        layout.addLayout(top_h)

        grp_profile = QGroupBox("GitHub Organization / User Profile")
        p_layout = QGridLayout(grp_profile)

        self.lbl_gh_name = QLabel("Name / Handle: –")
        self.lbl_gh_type = QLabel("Entity Type: –")
        self.lbl_gh_repos = QLabel("Public Repos: –")
        self.lbl_gh_stars = QLabel("Total Stars: –")
        self.lbl_gh_forks = QLabel("Total Forks: –")
        self.lbl_gh_sec_policy = QLabel("SECURITY.md Policy: –")
        self.lbl_gh_location = QLabel("Location / Blog: –")
        self.lbl_gh_url = QLabel("Profile URL: –")

        for lbl_w in [self.lbl_gh_name, self.lbl_gh_type, self.lbl_gh_repos, self.lbl_gh_stars, self.lbl_gh_forks, self.lbl_gh_sec_policy, self.lbl_gh_location, self.lbl_gh_url]:
            lbl_w.setStyleSheet("background: #181825; padding: 6px 10px; border-radius: 6px; font-weight: 600;")

        p_layout.addWidget(self.lbl_gh_name, 0, 0)
        p_layout.addWidget(self.lbl_gh_type, 0, 1)
        p_layout.addWidget(self.lbl_gh_repos, 0, 2)
        p_layout.addWidget(self.lbl_gh_stars, 1, 0)
        p_layout.addWidget(self.lbl_gh_forks, 1, 1)
        p_layout.addWidget(self.lbl_gh_sec_policy, 1, 2)
        p_layout.addWidget(self.lbl_gh_location, 2, 0, 1, 2)
        p_layout.addWidget(self.lbl_gh_url, 2, 2)

        layout.addWidget(grp_profile)

        grp_repos = QGroupBox("Public Repositories (Recent Updates)")
        r_layout = QVBoxLayout(grp_repos)

        self.table_gh_repos = QTableWidget(0, 6)
        self.table_gh_repos.setHorizontalHeaderLabels([
            "Repository Name", "Language", "Stars", "Forks", "Open Issues", "Description & Topics"
        ])
        self.table_gh_repos.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table_gh_repos.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_gh_repos.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_gh_repos.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_gh_repos.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_gh_repos.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self._setup_table_interactions(self.table_gh_repos)
        r_layout.addWidget(self.table_gh_repos)

        layout.addWidget(grp_repos)
        return widget

    def _manual_github_lookup(self) -> None:
        handle = self.input_gh_handle.text().strip() or extract_brand_handle(self.input_domain.text().strip())
        if not handle:
            QMessageBox.warning(self, "Invalid Handle", "Please enter a valid GitHub organization or username.")
            return

        cfg = load_config()
        token = cfg.get("github_token", "")
        self.status_label.setText(f"Querying GitHub API for handle '{handle}'...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            gh_report = audit_github_footprint(handle, token=token)
            self._populate_github_view(gh_report.to_dict())
            self.status_label.setText("GitHub lookup complete.")
        finally:
            QApplication.restoreOverrideCursor()

    # -------------------------------------------------------------------------
    # View 11: Public PGP Keyserver Contacts
    # -------------------------------------------------------------------------

    def _create_pgp_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        grp_summary = QGroupBox("PGP Keyserver Discovered Contacts & Key Identities")
        s_layout = QVBoxLayout(grp_summary)

        self.lbl_pgp_summary = QLabel("Total Keys Found: 0 | Discovered Domain Emails: None")
        self.lbl_pgp_summary.setStyleSheet("font-weight: 600; color: #89b4fa; padding: 4px;")
        s_layout.addWidget(self.lbl_pgp_summary)

        self.table_pgp = QTableWidget(0, 6)
        self.table_pgp.setHorizontalHeaderLabels([
            "Key ID", "Algorithm", "Bit Length", "Creation Date", "Expiration", "Associated Identities (Name & Email)"
        ])
        self.table_pgp.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table_pgp.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_pgp.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_pgp.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_pgp.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_pgp.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self._setup_table_interactions(self.table_pgp)
        s_layout.addWidget(self.table_pgp)

        layout.addWidget(grp_summary)
        return widget

    # -------------------------------------------------------------------------
    # View 12: Brand / Username Checker
    # -------------------------------------------------------------------------

    def _create_username_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        top_h = QHBoxLayout()
        top_h.addWidget(QLabel("Brand Name / Handle:"))
        self.input_brand_handle = QLineEdit()
        self.input_brand_handle.setPlaceholderText("e.g. brand handle to audit across 20 platforms")
        top_h.addWidget(self.input_brand_handle, 1)

        btn_user_query = QPushButton("Check Brand Across 20 Platforms")
        btn_user_query.clicked.connect(self._manual_username_check)
        top_h.addWidget(btn_user_query)
        layout.addLayout(top_h)

        grp_tbl = QGroupBox("Multi-Platform Identity Footprint (20 Platforms)")
        v_tbl = QVBoxLayout(grp_tbl)

        self.lbl_username_stats = QLabel("Checked: 0 platforms | Claimed: 0 | Available: 0")
        self.lbl_username_stats.setStyleSheet("font-weight: 600; color: #89b4fa; padding: 4px;")
        v_tbl.addWidget(self.lbl_username_stats)

        self.table_username = QTableWidget(0, 6)
        self.table_username.setHorizontalHeaderLabels([
            "Platform", "Category", "Registration Status", "HTTP Code", "Latency (ms)", "Public Profile URL"
        ])
        self.table_username.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table_username.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_username.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_username.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_username.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_username.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self._setup_table_interactions(self.table_username)
        v_tbl.addWidget(self.table_username)

        layout.addWidget(grp_tbl)
        return widget

    def _manual_username_check(self) -> None:
        handle = self.input_brand_handle.text().strip() or extract_brand_handle(self.input_domain.text().strip())
        if not handle:
            QMessageBox.warning(self, "Invalid Handle", "Please enter a valid brand handle to check.")
            return

        self.status_label.setText(f"Auditing brand '{handle}' across 20 platforms...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            report = check_brand_handles(handle)
            self._populate_username_view(report.to_dict())
            self.status_label.setText("Brand audit complete.")
        finally:
            QApplication.restoreOverrideCursor()

    # -------------------------------------------------------------------------
    # View 13: Document Metadata (Exif)
    # -------------------------------------------------------------------------

    def _create_metadata_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        grp_input = QGroupBox("Analyze Local or Remote Document / Image Metadata")
        v_in = QVBoxLayout(grp_input)

        h_local = QHBoxLayout()
        self.input_meta_file = QLineEdit()
        self.input_meta_file.setPlaceholderText("Select a local PDF or image file (PDF, JPEG, PNG, TIFF)...")
        btn_browse = QPushButton("Browse File...")
        btn_browse.clicked.connect(self._browse_metadata_file)
        btn_scan_file = QPushButton("Inspect File Metadata")
        btn_scan_file.clicked.connect(self._scan_local_metadata)
        h_local.addWidget(self.input_meta_file, 1)
        h_local.addWidget(btn_browse)
        h_local.addWidget(btn_scan_file)
        v_in.addLayout(h_local)

        layout.addWidget(grp_input)

        grp_res = QGroupBox("Disclosed Metadata Attributes & Author Artifacts")
        v_res = QVBoxLayout(grp_res)

        self.table_metadata = QTableWidget(0, 2)
        self.table_metadata.setHorizontalHeaderLabels(["Attribute / Field", "Disclosed Value"])
        self.table_metadata.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table_metadata.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._setup_table_interactions(self.table_metadata)
        v_res.addWidget(self.table_metadata)

        layout.addWidget(grp_res)
        return widget

    def _browse_metadata_file(self) -> None:
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Select Document or Image", "", "Documents & Images (*.pdf *.jpg *.jpeg *.png *.tiff)"
        )
        if filepath:
            self.input_meta_file.setText(filepath)

    def _scan_local_metadata(self) -> None:
        fp = self.input_meta_file.text().strip()
        if not fp:
            QMessageBox.warning(self, "No File", "Please select a file to inspect.")
            return

        report = self.metadata_engine.inspect_file(fp)
        rows: List[List[Any]] = [
            ["File Type", report.file_type],
            ["File Size", f"{report.file_size_bytes:,} bytes"],
            ["Author", report.author or "Not Disclosed"],
            ["Creator / Tool", report.creator_tool or "Not Disclosed"],
            ["Producer / Engine", report.producer or "Not Disclosed"],
            ["Creation Date", report.creation_date or "Not Disclosed"],
            ["Modification Date", report.modification_date or "Not Disclosed"],
            ["Camera Model", report.camera_model or "Not Disclosed"],
            ["Software", report.software_used or "Not Disclosed"],
            ["GPS Coordinates", report.gps_coordinates or "None"],
        ]
        for k, v in report.all_metadata.items():
            if k not in ["Author", "Creator", "Producer", "CreationDate", "ModDate"]:
                rows.append([k, v])

        self.populate_table_safely(self.table_metadata, rows)

    # -------------------------------------------------------------------------
    # View 14: Wayback Machine History
    # -------------------------------------------------------------------------

    def _create_archive_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        group_arch = QGroupBox("Internet Archive (Wayback Machine) Milestones")
        arch_layout = QGridLayout(group_arch)

        self.lbl_arch_first = QLabel("First Recorded: –")
        self.lbl_arch_latest = QLabel("Latest Recorded: –")
        self.lbl_arch_samples = QLabel("Milestone Captures: –")

        for lbl_w in [self.lbl_arch_first, self.lbl_arch_latest, self.lbl_arch_samples]:
            lbl_w.setStyleSheet("background-color: #181825; padding: 8px 12px; border-radius: 6px; font-weight: 600;")

        arch_layout.addWidget(self.lbl_arch_first, 0, 0)
        arch_layout.addWidget(self.lbl_arch_latest, 0, 1)
        arch_layout.addWidget(self.lbl_arch_samples, 0, 2)

        layout.addWidget(group_arch)

        group_snaps = QGroupBox("Wayback Historical Captures")
        snaps_layout = QVBoxLayout(group_snaps)

        self.table_archive = QTableWidget(0, 4)
        self.table_archive.setHorizontalHeaderLabels(["Capture Timestamp", "Status Code", "MIME Type", "Archive URL"])
        self.table_archive.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_archive.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_archive.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_archive.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self._setup_table_interactions(self.table_archive)
        snaps_layout.addWidget(self.table_archive)

        layout.addWidget(group_snaps)
        return widget

    # -------------------------------------------------------------------------
    # View 15: Live Activity Logs & JSON
    # -------------------------------------------------------------------------

    def _create_logs_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        splitter = QSplitter(Qt.Vertical)

        grp_logs = QGroupBox("Live Activity Log (Polite Rate Limiting & Stage Progress)")
        v_logs = QVBoxLayout(grp_logs)

        self.txt_logs = QTextEdit()
        self.txt_logs.setReadOnly(True)
        v_logs.addWidget(self.txt_logs)

        grp_json = QGroupBox("Consolidated Raw JSON Output")
        v_json = QVBoxLayout(grp_json)

        ctrl_json = QHBoxLayout()
        btn_copy_json = QPushButton("Copy Raw JSON")
        btn_copy_json.clicked.connect(self._copy_json_to_clipboard)
        ctrl_json.addWidget(btn_copy_json)
        ctrl_json.addStretch(1)
        v_json.addLayout(ctrl_json)

        self.txt_json = QTextEdit()
        self.txt_json.setReadOnly(True)
        v_json.addWidget(self.txt_json)

        splitter.addWidget(grp_logs)
        splitter.addWidget(grp_json)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)
        return widget

    # -------------------------------------------------------------------------
    # View 16: Personal Phone Number Privacy & Carrier Auditor
    # -------------------------------------------------------------------------

    def _create_phone_privacy_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Input Header
        top_h = QHBoxLayout()
        top_h.addWidget(QLabel("Phone Number:"))
        self.input_phone = QLineEdit()
        self.input_phone.setPlaceholderText("e.g. +1 555-0199 or +44 7911 123456 (international format)")
        top_h.addWidget(self.input_phone, 2)

        top_h.addWidget(QLabel("Default Region:"))
        self.combo_phone_region = QComboBox()
        self.combo_phone_region.addItems(["US", "GB", "DE", "FR", "CA", "AU", "IN", "JP", "BR", "MX", "CH", "NL"])
        top_h.addWidget(self.combo_phone_region)

        btn_phone_audit = QPushButton("Audit Phone Privacy & Carrier")
        btn_phone_audit.setObjectName("primaryButton")
        btn_phone_audit.clicked.connect(self._run_phone_privacy_audit)
        top_h.addWidget(btn_phone_audit)
        layout.addLayout(top_h)

        # Metric Banner
        banner = QGroupBox("Phone Exposure & Privacy Score")
        b_layout = QGridLayout(banner)

        self.lbl_phone_score = QLabel("Privacy Score: –")
        self.lbl_phone_risk = QLabel("Risk: –")
        self.lbl_phone_type = QLabel("Line Type: –")
        self.lbl_phone_carrier = QLabel("Carrier: –")

        for lbl_w in [self.lbl_phone_score, self.lbl_phone_risk, self.lbl_phone_type, self.lbl_phone_carrier]:
            lbl_w.setStyleSheet("background: #181825; padding: 8px 12px; border-radius: 6px; font-weight: 700;")

        b_layout.addWidget(self.lbl_phone_score, 0, 0)
        b_layout.addWidget(self.lbl_phone_risk, 0, 1)
        b_layout.addWidget(self.lbl_phone_type, 0, 2)
        b_layout.addWidget(self.lbl_phone_carrier, 0, 3)

        layout.addWidget(banner)

        # Details Grid
        details_grp = QGroupBox("Number Representations & Geolocation")
        d_layout = QGridLayout(details_grp)

        self.lbl_phone_e164 = QLabel("E.164: –")
        self.lbl_phone_intl = QLabel("International: –")
        self.lbl_phone_nat = QLabel("National: –")
        self.lbl_phone_loc = QLabel("Location: –")
        self.lbl_phone_tz = QLabel("Timezones: –")

        d_layout.addWidget(self.lbl_phone_e164, 0, 0)
        d_layout.addWidget(self.lbl_phone_intl, 0, 1)
        d_layout.addWidget(self.lbl_phone_nat, 1, 0)
        d_layout.addWidget(self.lbl_phone_loc, 1, 1)
        d_layout.addWidget(self.lbl_phone_tz, 2, 0, 1, 2)

        layout.addWidget(details_grp)

        # Privacy Recommendations
        rec_grp = QGroupBox("Privacy Hardening & SIM Security Guidance")
        r_layout = QVBoxLayout(rec_grp)
        self.txt_phone_recs = QTextEdit()
        self.txt_phone_recs.setReadOnly(True)
        self.txt_phone_recs.setMaximumHeight(90)
        r_layout.addWidget(self.txt_phone_recs)
        layout.addWidget(rec_grp)

        # Search Dorks Table
        dork_grp = QGroupBox("Safe Public Web Verification Search Dorks (Self-Audit)")
        dk_layout = QVBoxLayout(dork_grp)

        self.table_phone_dorks = QTableWidget(0, 4)
        self.table_phone_dorks.setHorizontalHeaderLabels([
            "Audit Check", "Search Dork Query", "Description", "Verification Link (Click to Open)"
        ])
        self.table_phone_dorks.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table_phone_dorks.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        self.table_phone_dorks.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_phone_dorks.horizontalHeader().setSectionResizeMode(3, QHeaderView.Interactive)
        self._setup_table_interactions(self.table_phone_dorks)
        dk_layout.addWidget(self.table_phone_dorks)

        layout.addWidget(dork_grp)
        return widget

    def _run_phone_privacy_audit(self) -> None:
        raw = self.input_phone.text().strip()
        if not raw:
            QMessageBox.warning(self, "No Phone Number", "Please enter a phone number to analyze.")
            return

        region = self.combo_phone_region.currentText()
        self.status_label.setText(f"Analyzing phone number '{raw}'...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            report = PhonePrivacyEngine.audit_phone(raw, default_region=region)
            self._populate_phone_privacy_view(report)
            self.status_label.setText("Phone privacy audit complete.")
        finally:
            QApplication.restoreOverrideCursor()

    def _populate_phone_privacy_view(self, report: PhonePrivacyReport) -> None:
        self.lbl_phone_score.setText(f"Privacy Score: {report.privacy_score}/100")
        self.lbl_phone_risk.setText(f"Exposure Risk: {report.privacy_risk_level}")
        risk_color = "#f38ba8" if report.privacy_risk_level == "HIGH" else ("#fab387" if report.privacy_risk_level == "MEDIUM" else "#a6e3a1")
        self.lbl_phone_risk.setStyleSheet(f"background: #181825; padding: 8px 12px; border-radius: 6px; font-weight: 700; color: {risk_color};")

        self.lbl_phone_type.setText(f"Line Type: {report.line_type}")
        self.lbl_phone_carrier.setText(f"Carrier: {report.carrier_name}")

        self.lbl_phone_e164.setText(f"E.164: {report.e164 or 'N/A'}")
        self.lbl_phone_intl.setText(f"International: {report.international or 'N/A'}")
        self.lbl_phone_nat.setText(f"National: {report.national or 'N/A'}")
        self.lbl_phone_loc.setText(f"Location: {report.location_name}")
        self.lbl_phone_tz.setText(f"Timezones: {', '.join(report.timezones) or 'Unknown'}")

        self.txt_phone_recs.setPlainText("\n• ".join(["Guidance:"] + report.privacy_recommendations) if report.privacy_recommendations else "No specific privacy risks flagged.")

        dork_rows = [
            [d.get("title", ""), d.get("query", ""), d.get("description", ""), d.get("url", "")]
            for d in report.dork_links
        ]
        self.populate_table_safely(self.table_phone_dorks, dork_rows)

    # -------------------------------------------------------------------------
    # View 17: Personal Email Breach & Avatar Leak Auditor
    # -------------------------------------------------------------------------

    def _create_email_privacy_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Top query input
        top_h = QHBoxLayout()
        top_h.addWidget(QLabel("Personal Email Address:"))
        self.input_privacy_email = QLineEdit()
        self.input_privacy_email.setPlaceholderText("e.g. user@example.com")
        top_h.addWidget(self.input_privacy_email, 2)

        btn_email_audit = QPushButton("Audit Email Exposure & Breaches")
        btn_email_audit.setObjectName("primaryButton")
        btn_email_audit.clicked.connect(self._run_email_privacy_audit)
        top_h.addWidget(btn_email_audit)
        layout.addLayout(top_h)

        # Metric Banner
        banner = QGroupBox("Email Identity & Public Exposure Metrics")
        b_layout = QGridLayout(banner)

        self.lbl_email_priv_score = QLabel("Privacy Score: –")
        self.lbl_email_priv_risk = QLabel("Risk: –")
        self.lbl_email_breach_count = QLabel("Breaches: –")
        self.lbl_email_gravatar = QLabel("Avatar Leaks: –")

        for lbl_w in [self.lbl_email_priv_score, self.lbl_email_priv_risk, self.lbl_email_breach_count, self.lbl_email_gravatar]:
            lbl_w.setStyleSheet("background: #181825; padding: 8px 12px; border-radius: 6px; font-weight: 700;")

        b_layout.addWidget(self.lbl_email_priv_score, 0, 0)
        b_layout.addWidget(self.lbl_email_priv_risk, 0, 1)
        b_layout.addWidget(self.lbl_email_breach_count, 0, 2)
        b_layout.addWidget(self.lbl_email_gravatar, 0, 3)

        layout.addWidget(banner)

        # Identity Details Grid
        id_grp = QGroupBox("Cryptographic Hashes & Profile Leak Details")
        id_layout = QGridLayout(id_grp)

        self.lbl_email_domain = QLabel("Domain / Disposable: –")
        self.lbl_email_mx = QLabel("MX Server: –")
        self.lbl_email_md5 = QLabel("MD5 Hash: –")
        self.lbl_email_sha256 = QLabel("SHA-256 Hash: –")
        self.lbl_email_grav_name = QLabel("Gravatar Name: –")
        self.lbl_email_grav_accs = QLabel("Linked Accounts: –")

        id_layout.addWidget(self.lbl_email_domain, 0, 0)
        id_layout.addWidget(self.lbl_email_mx, 0, 1)
        id_layout.addWidget(self.lbl_email_md5, 1, 0)
        id_layout.addWidget(self.lbl_email_sha256, 1, 1)
        id_layout.addWidget(self.lbl_email_grav_name, 2, 0)
        id_layout.addWidget(self.lbl_email_grav_accs, 2, 1)

        layout.addWidget(id_grp)

        # Recommendations
        rec_grp = QGroupBox("Email Privacy & Credential Hardening Recommendations")
        r_layout = QVBoxLayout(rec_grp)
        self.txt_email_recs = QTextEdit()
        self.txt_email_recs.setReadOnly(True)
        self.txt_email_recs.setMaximumHeight(90)
        r_layout.addWidget(self.txt_email_recs)
        layout.addWidget(rec_grp)

        # Breaches Table
        br_grp = QGroupBox("Public Data Breaches Associated with this Email")
        br_layout = QVBoxLayout(br_grp)

        self.table_email_breaches = QTableWidget(0, 3)
        self.table_email_breaches.setHorizontalHeaderLabels(["Breach / Source Name", "Domain", "Status"])
        self.table_email_breaches.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table_email_breaches.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        self.table_email_breaches.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._setup_table_interactions(self.table_email_breaches)
        br_layout.addWidget(self.table_email_breaches)

        layout.addWidget(br_grp)
        return widget

    def _run_email_privacy_audit(self) -> None:
        raw = self.input_privacy_email.text().strip()
        if not raw:
            QMessageBox.warning(self, "No Email", "Please enter an email address to analyze.")
            return

        self.status_label.setText(f"Auditing email exposure for '{raw}'...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            report = EmailPrivacyEngine.audit_email(raw)
            self._populate_email_privacy_view(report)
            self.status_label.setText("Email privacy audit complete.")
        finally:
            QApplication.restoreOverrideCursor()

    def _populate_email_privacy_view(self, report: EmailPrivacyReport) -> None:
        self.lbl_email_priv_score.setText(f"Privacy Score: {report.privacy_score}/100")
        self.lbl_email_priv_risk.setText(f"Risk: {report.privacy_risk_level}")
        risk_color = "#f38ba8" if report.privacy_risk_level in ("CRITICAL", "HIGH") else ("#fab387" if report.privacy_risk_level == "MEDIUM" else "#a6e3a1")
        self.lbl_email_priv_risk.setStyleSheet(f"background: #181825; padding: 8px 12px; border-radius: 6px; font-weight: 700; color: {risk_color};")

        self.lbl_email_breach_count.setText(f"Breaches: {report.breaches_count} Found")
        grav_str = "Exposed" if report.gravatar_found else "None"
        self.lbl_email_gravatar.setText(f"Gravatar Profile: {grav_str}")

        disp_str = "Yes (Burner)" if report.is_disposable else "Standard Provider"
        self.lbl_email_domain.setText(f"Domain: {report.domain} ({disp_str})")
        self.lbl_email_mx.setText(f"MX Records: {'Active' if report.mx_records_found else 'Missing'}")
        self.lbl_email_md5.setText(f"MD5 Hash: {report.md5_hash}")
        self.lbl_email_sha256.setText(f"SHA-256 Hash: {report.sha256_hash[:16]}...")
        self.lbl_email_grav_name.setText(f"Gravatar Name: {report.gravatar_display_name or 'None'}")
        self.lbl_email_grav_accs.setText(f"Linked Accounts: {', '.join(report.gravatar_accounts_linked) or 'None'}")

        self.txt_email_recs.setPlainText("\n• ".join(["Guidance:"] + report.recommendations) if report.recommendations else "No critical email exposures detected.")

        breach_rows = [
            [b.breach_name, b.domain or report.domain, "Compromised in public data breach"]
            for b in report.breaches
        ]
        self.populate_table_safely(self.table_email_breaches, breach_rows)

    # -------------------------------------------------------------------------
    # View 18: Social Media Exposure & Linkability Auditor
    # -------------------------------------------------------------------------

    def _create_social_privacy_view(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        top_h = QHBoxLayout()
        top_h.addWidget(QLabel("Personal Handle / Username:"))
        self.input_social_handle = QLineEdit()
        self.input_social_handle.setPlaceholderText("e.g. personal handle to audit across Instagram, Facebook, X, Reddit, etc.")
        top_h.addWidget(self.input_social_handle, 2)

        btn_social_audit = QPushButton("Audit Social Exposure & Linkability")
        btn_social_audit.setObjectName("primaryButton")
        btn_social_audit.clicked.connect(self._run_social_privacy_audit)
        top_h.addWidget(btn_social_audit)
        layout.addLayout(top_h)

        # Metric Banner
        banner = QGroupBox("Personal Dossier Linkability & Profile Correlation")
        b_layout = QGridLayout(banner)

        self.lbl_social_link_score = QLabel("Linkability Score: –")
        self.lbl_social_link_rating = QLabel("Correlation Risk: –")
        self.lbl_social_public_count = QLabel("Public Profiles: –")
        self.lbl_social_gated_count = QLabel("Login Gated: –")

        for lbl_w in [self.lbl_social_link_score, self.lbl_social_link_rating, self.lbl_social_public_count, self.lbl_social_gated_count]:
            lbl_w.setStyleSheet("background: #181825; padding: 8px 12px; border-radius: 6px; font-weight: 700;")

        b_layout.addWidget(self.lbl_social_link_score, 0, 0)
        b_layout.addWidget(self.lbl_social_link_rating, 0, 1)
        b_layout.addWidget(self.lbl_social_public_count, 0, 2)
        b_layout.addWidget(self.lbl_social_gated_count, 0, 3)

        layout.addWidget(banner)

        # Guidance Card
        guidance_grp = QGroupBox("Cross-Platform Identity Correlation & Privacy Hardening")
        g_layout = QVBoxLayout(guidance_grp)
        self.txt_social_guidance = QTextEdit()
        self.txt_social_guidance.setReadOnly(True)
        self.txt_social_guidance.setMaximumHeight(90)
        g_layout.addWidget(self.txt_social_guidance)
        layout.addWidget(guidance_grp)

        # Profiles Table
        p_grp = QGroupBox("Publicly Reachable Profiles & OpenGraph Metadata Exposure (8 Networks)")
        p_layout = QVBoxLayout(p_grp)

        self.table_social_profiles = QTableWidget(0, 7)
        self.table_social_profiles.setHorizontalHeaderLabels([
            "Platform", "Category", "Accessibility", "HTTP Code", "OpenGraph Title", "Exposed Bio / Description", "Profile URL"
        ])
        self.table_social_profiles.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table_social_profiles.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        self.table_social_profiles.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_social_profiles.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_social_profiles.horizontalHeader().setSectionResizeMode(4, QHeaderView.Interactive)
        self.table_social_profiles.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table_social_profiles.horizontalHeader().setSectionResizeMode(6, QHeaderView.Interactive)
        self._setup_table_interactions(self.table_social_profiles)
        p_layout.addWidget(self.table_social_profiles)

        layout.addWidget(p_grp)
        return widget

    def _run_social_privacy_audit(self) -> None:
        raw = self.input_social_handle.text().strip()
        if not raw:
            QMessageBox.warning(self, "No Handle", "Please enter a username or handle to inspect.")
            return

        self.status_label.setText(f"Inspecting public social exposure for handle '{raw}'...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            report = SocialPrivacyEngine.audit_social_handle(raw)
            self._populate_social_privacy_view(report)
            self.status_label.setText("Social exposure audit complete.")
        finally:
            QApplication.restoreOverrideCursor()

    def _populate_social_privacy_view(self, report: SocialPrivacyReport) -> None:
        self.lbl_social_link_score.setText(f"Linkability: {report.linkability_score}/100")
        self.lbl_social_link_rating.setText(f"Correlation: {report.linkability_rating}")
        risk_color = "#f38ba8" if report.linkability_rating in ("CRITICAL", "HIGH") else ("#fab387" if report.linkability_rating == "MEDIUM" else "#a6e3a1")
        self.lbl_social_link_rating.setStyleSheet(f"background: #181825; padding: 8px 12px; border-radius: 6px; font-weight: 700; color: {risk_color};")

        self.lbl_social_public_count.setText(f"Public Profiles: {report.public_profiles_found}")
        self.lbl_social_gated_count.setText(f"Login Gated: {report.gated_profiles_found}")

        guidance_text = "\n• ".join(["Risks & Hardening:"] + report.cross_correlation_risks + report.hardening_tips)
        self.txt_social_guidance.setPlainText(guidance_text)

        rows = [
            [
                p.platform,
                p.category,
                p.status,
                p.status_code,
                p.og_title or "–",
                p.og_description or "–",
                p.profile_url,
            ]
            for p in report.profiles
        ]
        self.populate_table_safely(self.table_social_profiles, rows)

    # -------------------------------------------------------------------------
    # Reconnaissance Execution & Signal Handlers
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
        brand = extract_brand_handle(domain)
        self.input_gh_handle.setText(brand)
        self.input_brand_handle.setText(brand)
        self.input_social_handle.setText(brand)

        cfg = load_config()
        rate_rps = float(cfg.get("rate_limit_rps", 2.0))
        timeout = float(cfg.get("timeout_sec", 10.0))
        ua = str(cfg.get("user_agent", "OSINTReconStudio-PassiveAudit/1.0"))
        gh_token = str(cfg.get("github_token", ""))

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

        self.btn_start.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_export.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Auditing target: {domain}...")
        self.txt_logs.clear()

        self.current_worker = ReconWorker(
            domain=domain,
            enabled_modules=enabled_modules,
            rate_limit_rps=rate_rps,
            timeout=timeout,
            user_agent=ua,
            github_token=gh_token,
        )

        self.current_worker.signals.started.connect(self._on_started)
        self.current_worker.signals.progress.connect(self._on_progress)
        self.current_worker.signals.log.connect(self._on_log)
        self.current_worker.signals.error.connect(self._on_error)
        self.current_worker.signals.finished.connect(self._on_finished)

        self.thread_pool.start(self.current_worker)

    def cancel_recon(self) -> None:
        if self.current_worker:
            self.current_worker.cancel()
            self._on_log("WARNING", "Cancellation requested by user. Terminating active tasks...")
            self.btn_cancel.setEnabled(False)
            self.btn_start.setEnabled(True)

    def clear_results(self) -> None:
        self.current_report = None
        self.input_domain.clear()
        self.lbl_grade.setText("–")
        self.lbl_score_num.setText("Awaiting audit")
        self.lbl_metric_takeover.setText("Takeover Risk: –")
        self.lbl_metric_email.setText("Email Defense: –")
        self.lbl_metric_dnssec.setText("DNSSEC: –")
        self.lbl_metric_headers.setText("Headers: –")
        self.lbl_metric_tls.setText("TLS Cert: –")
        self.lbl_metric_exposure.setText("InternetDB: –")
        self.lbl_metric_cloud.setText("Cloud / CDN: –")
        self.lbl_metric_subs.setText("CT Subdomains: –")
        self.list_findings.clear()
        self.table_dns.setRowCount(0)
        self.table_ct.setRowCount(0)
        self.table_takeover.setRowCount(0)
        self.table_entities.setRowCount(0)
        self.table_idb.setRowCount(0)
        self.table_ip_geo.setRowCount(0)
        self.table_urlscan.setRowCount(0)
        self.table_otx.setRowCount(0)
        self.table_headers.setRowCount(0)
        self.table_dkim.setRowCount(0)
        self.table_tech.setRowCount(0)
        self.table_gh_repos.setRowCount(0)
        self.table_pgp.setRowCount(0)
        self.table_username.setRowCount(0)
        self.table_archive.setRowCount(0)
        self.txt_logs.clear()
        self.txt_json.clear()
        self.btn_export.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("Ready.")

    def _on_started(self, domain: str) -> None:
        self.status_bar.showMessage(f"Passive reconnaissance in progress: {domain}")

    def _on_progress(self, desc: str, pct: int) -> None:
        self.progress_bar.setValue(pct)
        self.status_label.setText(desc)

    def _on_log(self, level: str, msg: str) -> None:
        color_map = {
            "INFO": "#89b4fa",
            "SUCCESS": "#a6e3a1",
            "WARNING": "#fab387",
            "ERROR": "#f38ba8",
        }
        color = color_map.get(level, "#cdd6f4")
        html_msg = f"<span style='color: {color}; font-weight: bold;'>[{level}]</span> {msg}"
        self.txt_logs.append(html_msg)

    def _on_error(self, module_name: str, err: str) -> None:
        self._on_log("ERROR", f"[{module_name}] {err}")

    def _on_finished(self, data: Dict[str, Any]) -> None:
        self.current_report = data
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_export.setEnabled(True)
        self.status_bar.showMessage("Passive reconnaissance complete.")

        self._populate_all_views(data)

    # -------------------------------------------------------------------------
    # Populate UI Views
    # -------------------------------------------------------------------------

    def _populate_all_views(self, data: Dict[str, Any]) -> None:
        scorecard = data.get("scorecard", {})
        dns_data = data.get("dns", {})
        takeover_data = data.get("takeover", {})
        rdap_data = data.get("rdap", {})
        web_data = data.get("web", {})
        archive_data = data.get("archive", {})
        internetdb_data = data.get("internetdb", {})
        ip_intel_data = data.get("ip_intel", {})
        urlscan_data = data.get("urlscan", {})
        email_sec_data = data.get("email_sec", {})
        tech_data = data.get("tech_stack", {})
        github_data = data.get("github", {})
        pgp_data = data.get("pgp", {})
        user_data = data.get("username", {})

        # Overview
        grade = scorecard.get("grade", "N/A")
        score = scorecard.get("score", 0)
        self.lbl_grade.setText(grade)
        self.lbl_score_num.setText(f"{score}/100 Posture Score")

        vuln_takeover = takeover_data.get("vulnerable_count", 0)
        self.lbl_metric_takeover.setText(f"Takeovers: {vuln_takeover} Vulnerable")
        if vuln_takeover > 0:
            self.lbl_metric_takeover.setStyleSheet("background-color: #181825; padding: 8px 12px; border-radius: 6px; font-weight: 700; color: #f38ba8;")
        else:
            self.lbl_metric_takeover.setStyleSheet("background-color: #181825; padding: 8px 12px; border-radius: 6px; font-weight: 600; color: #a6e3a1;")

        email_gr = email_sec_data.get("spoofing_grade", "F")
        self.lbl_metric_email.setText(f"Email Defense: Grade {email_gr}")
        self.lbl_metric_dnssec.setText(f"DNSSEC: {dns_data.get('dnssec', {}).get('status', 'Disabled')}")
        self.lbl_metric_headers.setText(f"Headers: Grade {web_data.get('security_grade', 'N/A')}")

        tls = web_data.get("tls_certificate", {})
        tls_exp = tls.get("days_until_expiration")
        tls_str = f"{tls_exp}d left" if tls_exp is not None else "Unknown"
        self.lbl_metric_tls.setText(f"TLS Cert: {tls_str}")

        cves = internetdb_data.get("all_cves", [])
        self.lbl_metric_exposure.setText(f"InternetDB: {len(cves)} CVEs")

        clouds = ip_intel_data.get("cloud_providers_detected", [])
        self.lbl_metric_cloud.setText(f"Cloud: {', '.join(clouds) if clouds else 'Direct IP'}")
        self.lbl_metric_subs.setText(f"CT Subdomains: {dns_data.get('subdomain_count', 0)}")

        # Findings
        self.list_findings.clear()
        findings = scorecard.get("findings", [])
        if findings:
            for f in findings:
                sev = f.get("severity", "INFO")
                title = f.get("title", "")
                remed = f.get("remediation", "")
                item = QListWidgetItem(f"[{sev}] {title}\n→ {remed}")
                if sev in ("CRITICAL", "HIGH"):
                    item.setForeground(QColor("#f38ba8"))
                elif sev == "MEDIUM":
                    item.setForeground(QColor("#fab387"))
                else:
                    item.setForeground(QColor("#89b4fa"))
                self.list_findings.addItem(item)
        else:
            item = QListWidgetItem("✓ No high-priority findings detected!")
            item.setForeground(QColor("#a6e3a1"))
            self.list_findings.addItem(item)

        # DNS Records
        dns_rows = [
            [r.get("record_type", ""), r.get("name", ""), r.get("value", ""), r.get("ttl", "")]
            for r in dns_data.get("records", [])
        ]
        self.populate_table_safely(self.table_dns, dns_rows)

        ct_subs = dns_data.get("ct_subdomains", [])
        self.lbl_sub_count.setText(f"Subdomains Discovered: {len(ct_subs)}")
        ct_rows = [
            [s.get("subdomain", ""), s.get("issuer", s.get("source", "")), s.get("logged_date", "")]
            for s in ct_subs
        ]
        self.populate_table_safely(self.table_ct, ct_rows)

        # Dangling CNAMEs & Takeovers
        self.lbl_takeover_vuln.setText(f"Vulnerable: {vuln_takeover}")
        if vuln_takeover > 0:
            self.lbl_takeover_vuln.setStyleSheet("font-size: 14px; font-weight: 700; color: #f38ba8; padding: 6px 12px; background: #181825; border-radius: 6px;")
        else:
            self.lbl_takeover_vuln.setStyleSheet("font-size: 14px; font-weight: 700; color: #a6e3a1; padding: 6px 12px; background: #181825; border-radius: 6px;")

        self.lbl_takeover_dangling.setText(f"Dangling CNAMEs: {takeover_data.get('dangling_count', 0)}")
        self.lbl_takeover_total.setText(f"Total CNAMEs Analyzed: {takeover_data.get('cname_count', 0)}")

        takeover_rows = [
            [
                r.get("subdomain", ""),
                r.get("cname_target", ""),
                r.get("provider", ""),
                r.get("status", ""),
                r.get("risk_level", ""),
                r.get("description", ""),
            ]
            for r in takeover_data.get("records", [])
        ]
        self.populate_table_safely(self.table_takeover, takeover_rows)

        # RDAP
        self.lbl_rdap_registrar.setText(rdap_data.get("registrar_name") or "–")
        self.lbl_rdap_iana.setText(str(rdap_data.get("registrar_iana_id") or "–"))
        self.lbl_rdap_abuse_email.setText(rdap_data.get("abuse_email") or "–")
        self.lbl_rdap_abuse_phone.setText(rdap_data.get("abuse_phone") or "–")
        self.lbl_rdap_created.setText(rdap_data.get("created_date") or "–")
        self.lbl_rdap_expires.setText(rdap_data.get("expiration_date") or "–")
        self.lbl_rdap_age.setText(f"{rdap_data.get('domain_age_days')} days" if rdap_data.get("domain_age_days") is not None else "–")
        self.lbl_rdap_days_left.setText(f"{rdap_data.get('days_until_expiration')} days" if rdap_data.get("days_until_expiration") is not None else "–")
        self.lbl_rdap_privacy.setText("Yes (Protected)" if rdap_data.get("is_privacy_protected") else "No / Disclosed")
        self.lbl_rdap_nameservers.setText(", ".join(rdap_data.get("nameservers", [])) or "–")

        entity_rows = [
            [", ".join(ent.get("roles", [])), ent.get("name", ""), ent.get("organization", ""), ent.get("email", ""), ent.get("phone", "")]
            for ent in rdap_data.get("entities", [])
        ]
        self.populate_table_safely(self.table_entities, entity_rows)

        # Passive Exposure (InternetDB)
        idb_rows = [
            [
                h.get("ip", ""),
                ", ".join(str(p) for p in h.get("ports", [])),
                ", ".join(h.get("cpes", [])),
                ", ".join(h.get("tags", [])),
                ", ".join(h.get("vulns", [])),
            ]
            for h in internetdb_data.get("hosts", [])
        ]
        self.populate_table_safely(self.table_idb, idb_rows)

        # IP Geolocation
        ip_rows = [
            [
                r.get("ip", ""),
                r.get("country", ""),
                r.get("city", ""),
                f"{r.get('asn', '')} ({r.get('asn_org', '')})",
                r.get("isp", ""),
                r.get("cloud_provider", "None"),
            ]
            for r in ip_intel_data.get("records", [])
        ]
        self.populate_table_safely(self.table_ip_geo, ip_rows)

        # Threat History (URLScan & OTX)
        scans = urlscan_data.get("urlscan_records", [])
        otx = urlscan_data.get("otx_records", [])
        ips_obs = ", ".join(urlscan_data.get("historical_ips_observed", [])) or "None"
        asns_obs = ", ".join(urlscan_data.get("historical_asns_observed", [])) or "None"
        self.lbl_threat_stats.setText(f"Total Scans Found: {urlscan_data.get('total_scans_found', 0)} | Observed IPs: {ips_obs} | Observed ASNs: {asns_obs}")

        urlscan_rows = [
            [
                s.get("scan_date", "")[:10],
                s.get("target_url", ""),
                s.get("ip", ""),
                s.get("asn", ""),
                s.get("page_title", ""),
                s.get("result_url", ""),
            ]
            for s in scans
        ]
        self.populate_table_safely(self.table_urlscan, urlscan_rows)

        otx_rows = [
            [
                o.get("record_type", ""),
                o.get("address", ""),
                o.get("first_seen", ""),
                o.get("last_seen", ""),
                o.get("asn", ""),
            ]
            for o in otx
        ]
        self.populate_table_safely(self.table_otx, otx_rows)

        # Web Posture
        self.lbl_web_canonical.setText(f"Canonical URL: {web_data.get('canonical_url', '–')}")
        self.lbl_web_server.setText(f"Server Banner: {web_data.get('server_header', 'Undisclosed')}")
        self.lbl_web_tls.setText(f"TLS: {tls.get('tls_version', '–')} | Cipher: {tls.get('cipher_suite', '–')}")
        self.lbl_web_cert_issuer.setText(f"Cert Issuer: {tls.get('issuer_org', 'Unknown')} ({tls.get('issuer_cn', '')})")

        header_rows = [
            [h.get("header", ""), h.get("status", ""), h.get("value", ""), h.get("recommendation", "")]
            for h in web_data.get("security_headers", [])
        ]
        self.populate_table_safely(self.table_headers, header_rows)

        # Email Security
        self.lbl_email_grade.setText(f"Grade {email_sec_data.get('spoofing_grade', 'F')}")
        self.lbl_email_summary.setText(f"{email_sec_data.get('risk_summary', '')}\nScore: {email_sec_data.get('spoofing_score', 0)}/100")
        self.lbl_em_spf.setText(f"SPF Status: {email_sec_data.get('spf_status', 'Missing')}")
        self.lbl_em_dmarc.setText(f"DMARC Policy: {email_sec_data.get('dmarc_policy', 'none')} (pct={email_sec_data.get('dmarc_pct', 100)}%)")
        self.lbl_em_dkim.setText(f"Active DKIM Selectors: {email_sec_data.get('dkim_active_count', 0)}")
        bimi = email_sec_data.get("bimi", {})
        self.lbl_em_bimi.setText(f"BIMI: {'Configured' if bimi.get('found') else 'Not Found'}")
        mta = email_sec_data.get("mta_sts", {})
        self.lbl_em_mta.setText(f"MTA-STS: {'Active' if mta.get('mta_sts_found') else 'Disabled'}")

        dkim_rows = [
            [s.get("selector", ""), s.get("record_name", ""), "Active" if s.get("found") else "Not Published", s.get("record_text", "")]
            for s in email_sec_data.get("dkim_selectors_checked", [])
        ]
        self.populate_table_safely(self.table_dkim, dkim_rows)

        # Tech Stack
        tech_rows = [
            [t.get("name", ""), t.get("category", ""), t.get("evidence", "")]
            for t in tech_data.get("technologies", [])
        ]
        self.populate_table_safely(self.table_tech, tech_rows)

        sec_txt = tech_data.get("security_txt", {})
        if sec_txt.get("found"):
            self.txt_sec_txt.setPlainText("\n".join(sec_txt.get("raw_lines", [])) or "security.txt found.")
        else:
            self.txt_sec_txt.setPlainText("No RFC 9116 security.txt discovered.")

        disallows = tech_data.get("robots_disallowed_paths", [])
        self.txt_robots_disallow.setPlainText("\n".join(disallows) if disallows else "No Disallow paths in robots.txt.")

        # GitHub Footprint
        self._populate_github_view(github_data)

        # PGP Keyservers
        self._populate_pgp_view(pgp_data)

        # Username Checker
        self._populate_username_view(user_data)

        # Wayback Machine
        self.lbl_arch_first.setText(f"First Recorded: {archive_data.get('first_seen') or 'Never'}")
        self.lbl_arch_latest.setText(f"Latest Recorded: {archive_data.get('latest_seen') or 'Never'}")
        self.lbl_arch_samples.setText(f"Milestone Captures: {archive_data.get('total_samples', 0)}")
        arch_rows = [
            [s.get("formatted_date", ""), s.get("status_code", ""), s.get("mime_type", ""), s.get("archive_url", "")]
            for s in archive_data.get("snapshots", [])
        ]
        self.populate_table_safely(self.table_archive, arch_rows)

        # Raw JSON
        self.txt_json.setPlainText(json.dumps(data, indent=2))

    def _populate_github_view(self, data: Dict[str, Any]) -> None:
        if not data:
            return
        handle = data.get("handle") or data.get("target_input") or "–"
        self.input_gh_handle.setText(handle)
        self.lbl_gh_name.setText(f"Name: {data.get('name') or handle}")
        self.lbl_gh_type.setText(f"Type: {data.get('entity_type', 'Unknown')}")
        self.lbl_gh_repos.setText(f"Public Repos: {data.get('public_repos_count', 0)}")
        self.lbl_gh_stars.setText(f"Total Stars: ⭐ {data.get('total_stars', 0)}")
        self.lbl_gh_forks.setText(f"Total Forks: 🍴 {data.get('total_forks', 0)}")
        sec_text = "Configured (Yes)" if data.get("has_security_policy") else "Missing (No)"
        self.lbl_gh_sec_policy.setText(f"SECURITY.md: {sec_text}")
        self.lbl_gh_location.setText(f"Location: {data.get('location') or '–'} | Blog: {data.get('blog') or '–'}")
        self.lbl_gh_url.setText(f"URL: {data.get('html_url') or '–'}")

        repo_rows = [
            [
                r.get("name", ""),
                r.get("language", "Unknown"),
                r.get("stars", 0),
                r.get("forks", 0),
                r.get("open_issues", 0),
                f"{r.get('description', '')} [{', '.join(r.get('topics', []))}]",
            ]
            for r in data.get("repos", [])
        ]
        self.populate_table_safely(self.table_gh_repos, repo_rows)

    def _populate_pgp_view(self, data: Dict[str, Any]) -> None:
        if not data:
            return
        keys = data.get("keys", [])
        domain_emails = ", ".join(data.get("domain_specific_emails", [])) or "None"
        self.lbl_pgp_summary.setText(f"Total Keys Found: {len(keys)} | Domain-Specific Discovered Emails: {domain_emails}")

        pgp_rows = []
        for k in keys:
            uids = ", ".join([f"{i.get('name', '')} <{i.get('email', '')}>" for i in k.get("identities", [])])
            pgp_rows.append([
                k.get("key_id", ""),
                k.get("algorithm", ""),
                k.get("key_length", 0),
                k.get("created_at", ""),
                k.get("expires_at", ""),
                uids,
            ])
        self.populate_table_safely(self.table_pgp, pgp_rows)

    def _populate_username_view(self, data: Dict[str, Any]) -> None:
        if not data:
            return
        handle = data.get("handle") or "–"
        self.input_brand_handle.setText(handle)
        claimed = data.get("claimed_count", 0)
        avail = data.get("available_count", 0)
        total = data.get("total_checked", 0)
        self.lbl_username_stats.setText(f"Handle: '{handle}' | Checked: {total} platforms | Claimed: {claimed} | Available: {avail}")

        user_rows = [
            [
                r.get("platform", ""),
                r.get("category", ""),
                r.get("status", ""),
                r.get("status_code", 0),
                r.get("response_time_ms", 0.0),
                r.get("profile_url", ""),
            ]
            for r in data.get("results", [])
        ]
        self.populate_table_safely(self.table_username, user_rows)

    # -------------------------------------------------------------------------
    # Utility Handlers
    # -------------------------------------------------------------------------

    def _filter_dns_table(self, query: str) -> None:
        q = query.lower().strip()
        for row in range(self.table_dns.rowCount()):
            match = False
            for col in range(self.table_dns.columnCount()):
                item = self.table_dns.item(row, col)
                if item and q in item.text().lower():
                    match = True
                    break
            self.table_dns.setRowHidden(row, not match)

    def _copy_subdomains_to_clipboard(self) -> None:
        subs = [
            self.table_ct.item(row, 0).text()
            for row in range(self.table_ct.rowCount())
            if self.table_ct.item(row, 0)
        ]
        if not subs:
            QMessageBox.information(self, "No Subdomains", "No subdomains to copy.")
            return

        QApplication.clipboard().setText("\n".join(subs))
        QMessageBox.information(self, "Copied", f"Copied {len(subs)} subdomains to clipboard.")

    def _copy_json_to_clipboard(self) -> None:
        text = self.txt_json.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Copied", "Raw JSON report copied to clipboard.")

    def _export_report(self, fmt: str) -> None:
        if not self.current_report:
            QMessageBox.warning(self, "No Audit Data", "Please run a reconnaissance audit first.")
            return

        domain = self.current_report.get("domain", "audit")
        safe_domain = sanitize_filename(domain)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"OSINT_Audit_{safe_domain}_{timestamp}"

        if fmt == "json":
            filepath, _ = QFileDialog.getSaveFileName(
                self, "Export JSON Report", f"{default_name}.json", "JSON Files (*.json)"
            )
            if filepath:
                ReconExporter.export_json(self.current_report, filepath)
                QMessageBox.information(self, "Export Successful", f"Saved JSON report to:\n{filepath}")

        elif fmt == "markdown":
            filepath, _ = QFileDialog.getSaveFileName(
                self, "Export Markdown Report", f"{default_name}.md", "Markdown Files (*.md)"
            )
            if filepath:
                ReconExporter.export_markdown(self.current_report, filepath)
                QMessageBox.information(self, "Export Successful", f"Saved Markdown report to:\n{filepath}")

        elif fmt == "html":
            filepath, _ = QFileDialog.getSaveFileName(
                self, "Export HTML Report", f"{default_name}.html", "HTML Files (*.html)"
            )
            if filepath:
                ReconExporter.export_html(self.current_report, filepath)
                QMessageBox.information(self, "Export Successful", f"Saved HTML report to:\n{filepath}")

    def _open_settings_dialog(self) -> None:
        dlg = SettingsDialog(self)
        dlg.exec()

    def _show_ethics_dialog(self) -> None:
        QMessageBox.information(
            self,
            "Ethical & Legal Guardrails",
            "<h3>OSINT Recon Studio: Strictly Passive Reconnaissance</h3>"
            "<p>This application enforces rigorous ethical and legal security standards:</p>"
            "<ul>"
            "<li><b>Public Data Only:</b> Audits only publicly advertised DNS records, RDAP, CT logs, HTTP headers, Shodan InternetDB, URLScan.io, and public APIs.</li>"
            "<li><b>No Active Probing:</b> Port scanning, directory brute-forcing, credential stuffing, and exploit testing are strictly forbidden and non-existent.</li>"
            "<li><b>Personal Privacy & Self-Audit:</b> Personal email, phone, and social checkers are designed for authorized self-assessment to discover public exposure.</li>"
            "<li><b>Polite Rate Limiting:</b> Configurable rate limiting (default 2 req/s) prevents denial of service or burden on public infrastructure.</li>"
            "<li><b>Transparent User-Agent:</b> Identifies itself as <code>OSINTReconStudio-PassiveAudit/1.0</code>.</li>"
            "</ul>",
        )

    def _show_about_dialog(self) -> None:
        QMessageBox.about(
            self,
            "About OSINT Recon Studio",
            "<b>OSINT Recon Studio v1.3.0</b><br>"
            "Native Windows Passive OSINT & Personal Privacy Exposure Studio<br><br>"
            "Architected with PySide6, HTTPX, DNSPython, Phonenumbers, PyPDF, and Pillow.<br>"
            "Built for enterprise defensive security auditors, privacy researchers, and domain owners."
        )
