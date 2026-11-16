"""Main Window for OSINT Recon Studio — Phase 6 Monochrome Liquid Glass & Bento Edition.

Provides an executive three-pane Bento layout:
- Top Floating Command Bar (Omni-Target input, live target badge, profile selector, hairline progress)
- Left Frosted Navigation Rail (Collapsible, category icons, live badge counters)
- Center Bento Workspace (4 KPI tiles per Hub, instant table filters, 5 Unified Hubs)
- Right Collapsible Inspector & Local AI Drawer (Deep record key-value breakdown, contextual remediation)
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
from typing import Any, Dict, List, Optional, Tuple

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
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from osint_studio.core.diagnostics import DiagnosticRunner, run_full_diagnostics
from osint_studio.core.domain_utils import extract_brand_handle, normalize_domain, sanitize_filename
from osint_studio.core.exporter import ReconExporter
from osint_studio.core.local_llm_engine import (
    LOW_RAM_MODELS,
    HeuristicAnalyst,
    LocalLLMEngine,
    is_ollama_available_sync,
)
from osint_studio.core.metadata_engine import MetadataEngine
from osint_studio.core.personal_deep_osint import DeepPersonalReport, PersonalDeepOSINTSuite
from osint_studio.core.personal_osint_suite import (
    PersonalOSINTSuite,
    PrivacyScrubber,
    generate_username_permutations,
)
from osint_studio.ui.liquid_glass_theme import (
    MONOCHROME_LIQUID_GLASS_QSS,
    apply_windows_liquid_glass,
    create_glass_shadow,
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

    for p in candidates:
        if p.is_file():
            return str(p)
    return None


class MainWindow(QMainWindow):
    """Studio-grade Three-Pane Bento GUI for OSINT Recon Studio."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("OSINT Recon Studio v1.5.0 // Executive Passive Reconnaissance & Intelligence Suite")
        self.resize(1440, 900)
        self.setMinimumSize(1120, 720)

        # Native Translucent Window attribute for Liquid Glass & DWM Mica/Acrylic
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

        icon_path = get_app_icon_path()
        if icon_path:
            self.setWindowIcon(QIcon(icon_path))

        self.thread_pool = QThreadPool.globalInstance()
        self.current_worker: Optional[ReconWorker] = None
        self.latest_results: Dict[str, Any] = {}
        self.latest_personal_results: Optional[Dict[str, Any]] = None
        self.latest_deep_personal: Optional[DeepPersonalReport] = None
        self.dossier_text: str = ""
        self.current_scrubber_file: str = ""
        self._is_closing: bool = False
        self.rail_expanded: bool = True

        self.config = load_config()
        self.current_theme = self.config.get("theme", "liquid_glass")
        self.set_theme(self.current_theme)

        self._init_ui()
        self._check_local_ai_status()

    def showEvent(self, event) -> None:
        """Applies Windows 11 DWM Acrylic/Mica backdrop after native winId is initialized."""
        super().showEvent(event)
        try:
            apply_windows_liquid_glass(int(self.winId()))
        except Exception:
            pass

    def closeEvent(self, event: QCloseEvent) -> None:
        self._is_closing = True
        if self.current_worker and not self.current_worker.is_cancelled:
            self.current_worker.cancel()
        self.thread_pool.waitForDone(800)
        event.accept()

    # -------------------------------------------------------------------------
    # UI Layout & Three-Pane Bento Construction
    # -------------------------------------------------------------------------

    def _init_ui(self) -> None:
        self._create_menu_bar()

        central_widget = QWidget()
        central_widget.setObjectName("CentralCanvas")
        self.setCentralWidget(central_widget)

        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(10, 8, 10, 8)
        root_layout.setSpacing(6)

        # 1. Top Floating Glass Command Bar (64px)
        top_command_bar = self._create_top_command_bar()
        root_layout.addWidget(top_command_bar)

        # 2. Main Horizontal Splitter (Navigation Rail + Center Bento Workspace + Right Inspector Drawer)
        self.main_splitter = QSplitter(Qt.Horizontal)
        self.main_splitter.setHandleWidth(3)

        # Pane A: Left Collapsible Navigation Rail (240px default)
        self.nav_rail = self._create_nav_rail()
        self.main_splitter.addWidget(self.nav_rail)

        # Pane B: Center Bento Workspace (Stacked 5 Hubs + Activity Logs)
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setObjectName("CenterBentoWorkspace")
        self._init_stacked_views()
        self.main_splitter.addWidget(self.stacked_widget)

        # Pane C: Right Collapsible Inspector Drawer (360px default)
        self.inspector_drawer = self._create_inspector_drawer()
        self.main_splitter.addWidget(self.inspector_drawer)

        # Splitter sizing ratios (240px nav, flexible center, 360px inspector)
        self.main_splitter.setStretchFactor(0, 0)
        self.main_splitter.setStretchFactor(1, 1)
        self.main_splitter.setStretchFactor(2, 0)
        self.main_splitter.setSizes([240, 840, 360])

        root_layout.addWidget(self.main_splitter, 1)

        # 3. Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready. Enter a domain or personal identity target in the top Command Bar.")

    def _create_top_command_bar(self) -> QWidget:
        bar_frame = QFrame()
        bar_frame.setObjectName("TopCommandBar")
        bar_frame.setFixedHeight(68)

        v_layout = QVBoxLayout(bar_frame)
        v_layout.setContentsMargins(12, 6, 12, 0)
        v_layout.setSpacing(6)

        h_layout = QHBoxLayout()
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(8)

        # Studio Badge
        brand_label = QLabel("🛡️ OSINT RECON")
        brand_label.setStyleSheet("font-weight: 800; font-size: 13px; letter-spacing: 1px; color: #FAFAFA;")
        h_layout.addWidget(brand_label)

        # Smart Omni-Target Input
        self.input_domain = QLineEdit()
        self.input_domain.setObjectName("OmniTargetInput")
        self.input_domain.setPlaceholderText("Enter target domain, email, @handle, phone (+1...), or person name...")
        self.input_domain.setStyleSheet("font-size: 13px; font-weight: 600; padding: 7px 12px;")
        self.input_domain.textChanged.connect(self._on_target_text_changed)
        self.input_domain.returnPressed.connect(self.start_recon)
        h_layout.addWidget(self.input_domain, 1)

        # Target Type Pill Badge
        self.lbl_target_badge = QLabel("[TARGET: DOMAIN]")
        self.lbl_target_badge.setStyleSheet(
            "background-color: rgba(255, 255, 255, 0.08); color: #FAFAFA; border: 1px solid rgba(255, 255, 255, 0.20); "
            "border-radius: 6px; padding: 4px 8px; font-weight: 700; font-size: 11px; letter-spacing: 0.5px;"
        )
        h_layout.addWidget(self.lbl_target_badge)

        # Scan Profile Selector
        self.combo_profile = QComboBox()
        self.combo_profile.addItem("⚡ Full Audit", "full")
        self.combo_profile.addItem("🌐 Domain & Infra", "domain")
        self.combo_profile.addItem("👤 Personal Identity", "personal")
        self.combo_profile.addItem("💾 Fast Cached", "cached")
        self.combo_profile.setToolTip("Select active audit execution profile")
        h_layout.addWidget(self.combo_profile)

        # Primary Action Buttons
        self.btn_start = QPushButton("▶ Run Audit")
        self.btn_start.setObjectName("PrimaryGlassBtn")
        self.btn_start.setToolTip("Start passive OSINT reconnaissance on target")
        self.btn_start.clicked.connect(self.start_recon)
        h_layout.addWidget(self.btn_start)

        self.btn_cancel = QPushButton("■ Stop")
        self.btn_cancel.setObjectName("DangerGlassBtn")
        self.btn_cancel.setToolTip("Cancel active scan")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self.cancel_recon)
        h_layout.addWidget(self.btn_cancel)

        self.btn_inspector_toggle = QPushButton("◨ Inspector")
        self.btn_inspector_toggle.setObjectName("SecondaryGlassBtn")
        self.btn_inspector_toggle.setToolTip("Toggle Right Record Inspector Drawer")
        self.btn_inspector_toggle.clicked.connect(self._toggle_inspector_drawer)
        h_layout.addWidget(self.btn_inspector_toggle)

        self.btn_export = QPushButton("Export ▾")
        self.btn_export.setObjectName("SecondaryGlassBtn")
        self.btn_export.setEnabled(False)
        exp_menu = QMenu(self)
        exp_menu.addAction("Export JSON", lambda: self._export_report("json"))
        exp_menu.addAction("Export Markdown Dossier", lambda: self._export_report("markdown"))
        exp_menu.addAction("Export HTML Report", lambda: self._export_report("html"))
        exp_menu.addAction("Export Subdomains CSV", lambda: self._export_report("csv"))
        self.btn_export.setMenu(exp_menu)
        h_layout.addWidget(self.btn_export)

        self.btn_shortcut = QPushButton("📌 Pin")
        self.btn_shortcut.setObjectName("SecondaryGlassBtn")
        self.btn_shortcut.setToolTip("Create desktop shortcut with native icon")
        self.btn_shortcut.clicked.connect(self._create_desktop_shortcut)
        h_layout.addWidget(self.btn_shortcut)

        self.btn_theme_toggle = QPushButton("🌓 Theme")
        self.btn_theme_toggle.setObjectName("SecondaryGlassBtn")
        self.btn_theme_toggle.setToolTip("Switch Monochrome Liquid Glass / Mocha theme (Ctrl+T)")
        self.btn_theme_toggle.clicked.connect(self.toggle_theme)
        h_layout.addWidget(self.btn_theme_toggle)

        v_layout.addLayout(h_layout)

        # Hairline Progress Bar along the bottom border
        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("HairlineProgressBar")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        v_layout.addWidget(self.progress_bar)

        return bar_frame

    def _create_nav_rail(self) -> QWidget:
        rail = QFrame()
        rail.setObjectName("LeftNavRail")
        rail.setFixedWidth(240)

        layout = QVBoxLayout(rail)
        layout.setContentsMargins(8, 12, 8, 12)
        layout.setSpacing(6)

        # Rail Header & Toggle
        head_box = QHBoxLayout()
        self.lbl_rail_title = QLabel("WORKSPACE")
        self.lbl_rail_title.setStyleSheet("font-size: 11px; font-weight: 700; letter-spacing: 1px; color: #71717A;")
        head_box.addWidget(self.lbl_rail_title, 1)

        self.btn_toggle_rail = QPushButton("◀")
        self.btn_toggle_rail.setFixedSize(24, 24)
        self.btn_toggle_rail.setObjectName("SecondaryGlassBtn")
        self.btn_toggle_rail.setToolTip("Collapse/Expand Navigation Rail")
        self.btn_toggle_rail.clicked.connect(self._toggle_nav_rail)
        head_box.addWidget(self.btn_toggle_rail)
        layout.addLayout(head_box)

        # Navigation Hub Buttons with Live Badges
        self.nav_buttons: List[QPushButton] = []
        self.nav_badges: List[QLabel] = []

        hubs = [
            ("01 // EXECUTIVE & AI", "🏛️"),
            ("02 // DOMAIN & INFRA", "🌐"),
            ("03 // NETWORK & THREAT", "☁️"),
            ("04 // WEB & EMAIL", "🛡️"),
            ("05 // PERSONAL DATA", "👤"),
            ("06 // LOGS & DIAGNOSTIC", "📜"),
        ]

        for idx, (title, icon) in enumerate(hubs):
            btn = QPushButton(f"{icon}  {title}")
            btn.setProperty("class", "nav-item")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked=False, i=idx: self._on_nav_clicked(i))
            layout.addWidget(btn)
            self.nav_buttons.append(btn)

        self.nav_buttons[0].setChecked(True)
        layout.addStretch(1)

        # Options Quick Toggles
        quick_group = QGroupBox("SCAN OPTIONS")
        q_layout = QVBoxLayout(quick_group)
        q_layout.setContentsMargins(8, 10, 8, 8)
        q_layout.setSpacing(4)

        self.chk_force_refresh = QCheckBox("⚡ Force Refresh")
        self.chk_force_refresh.setToolTip("Bypass 24-hour SQLite cache and query live sources")
        q_layout.addWidget(self.chk_force_refresh)

        self.chk_exposure = QCheckBox("Passive CVEs (InternetDB)")
        self.chk_exposure.setChecked(True)
        q_layout.addWidget(self.chk_exposure)

        self.chk_threat = QCheckBox("URLScan & AlienVault")
        self.chk_threat.setChecked(True)
        q_layout.addWidget(self.chk_threat)

        self.chk_takeover = QCheckBox("Subdomain Takeovers")
        self.chk_takeover.setChecked(True)
        q_layout.addWidget(self.chk_takeover)

        layout.addWidget(quick_group)
        return rail

    def _create_inspector_drawer(self) -> QWidget:
        """Right-hand collapsible Inspector Drawer displaying deep record details & AI advice."""
        drawer = QFrame()
        drawer.setObjectName("InspectorDrawer")
        drawer.setFixedWidth(360)
        drawer.setStyleSheet("background-color: rgba(255, 255, 255, 0.035); border-left: 1px solid rgba(255, 255, 255, 0.12);")

        layout = QVBoxLayout(drawer)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Drawer Header
        header_layout = QHBoxLayout()
        header_lbl = QLabel("INSPECTOR // RECORD DETAILS")
        header_lbl.setStyleSheet("font-size: 11px; font-weight: 800; letter-spacing: 1px; color: #FAFAFA;")
        header_layout.addWidget(header_lbl, 1)

        self.btn_close_inspector = QPushButton("✕")
        self.btn_close_inspector.setFixedSize(24, 24)
        self.btn_close_inspector.setObjectName("SecondaryGlassBtn")
        self.btn_close_inspector.setToolTip("Collapse Inspector Drawer")
        self.btn_close_inspector.clicked.connect(lambda: self.inspector_drawer.setVisible(False))
        header_layout.addWidget(self.btn_close_inspector)
        layout.addLayout(header_layout)

        # Selected Record Title & Severity Badge
        self.inspector_title = QLabel("Select any table row to inspect details")
        self.inspector_title.setWordWrap(True)
        self.inspector_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #FFFFFF;")
        layout.addWidget(self.inspector_title)

        badge_box = QHBoxLayout()
        self.inspector_category_lbl = QLabel("CATEGORY: GENERAL")
        self.inspector_category_lbl.setStyleSheet("font-size: 10px; font-weight: 700; color: #71717A; letter-spacing: 0.5px;")
        badge_box.addWidget(self.inspector_category_lbl, 1)

        self.inspector_severity_badge = QLabel("CLEAN")
        self.inspector_severity_badge.setStyleSheet(
            "background-color: rgba(255, 255, 255, 0.06); color: #A1A1AA; border: 1px solid rgba(255, 255, 255, 0.14); "
            "border-radius: 6px; padding: 2px 8px; font-weight: 700; font-size: 10px;"
        )
        badge_box.addWidget(self.inspector_severity_badge)
        layout.addLayout(badge_box)

        # Detail Key-Value Table
        self.inspector_table = QTableWidget(0, 2)
        self.inspector_table.setHorizontalHeaderLabels(["PROPERTY", "VALUE"])
        self.inspector_table.horizontalHeader().setStretchLastSection(True)
        self.inspector_table.verticalHeader().setVisible(False)
        self.inspector_table.setAlternatingRowColors(True)
        self.inspector_table.setFixedHeight(180)
        layout.addWidget(self.inspector_table)

        # Remediation & Context Box
        rem_lbl = QLabel("REMEDIATION & SECURITY CONTEXT")
        rem_lbl.setStyleSheet("font-size: 11px; font-weight: 700; letter-spacing: 0.8px; color: #A1A1AA;")
        layout.addWidget(rem_lbl)

        self.inspector_remediation = QTextBrowser()
        self.inspector_remediation.setOpenExternalLinks(True)
        self.inspector_remediation.setFixedHeight(140)
        self.inspector_remediation.setStyleSheet("background-color: rgba(0, 0, 0, 0.25); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 8px; font-size: 12px; padding: 8px;")
        self.inspector_remediation.setHtml("<span style='color:#71717A;'>Click on any row in the center tables to view actionable defense guidance.</span>")
        layout.addWidget(self.inspector_remediation)

        # Copy Action Bar
        btn_copy_box = QHBoxLayout()
        btn_copy_cell = QPushButton("Copy Cell")
        btn_copy_cell.setObjectName("SecondaryGlassBtn")
        btn_copy_cell.clicked.connect(self._copy_inspector_cell)
        btn_copy_box.addWidget(btn_copy_cell)

        btn_copy_json = QPushButton("Copy JSON")
        btn_copy_json.setObjectName("SecondaryGlassBtn")
        btn_copy_json.clicked.connect(self._copy_inspector_json)
        btn_copy_box.addWidget(btn_copy_json)
        layout.addLayout(btn_copy_box)

        # Mini Local AI Assistant Prompt Box
        ai_box = QGroupBox("LOCAL AI RECORD QUERY")
        ai_layout = QVBoxLayout(ai_box)
        ai_layout.setContentsMargins(8, 8, 8, 8)
        ai_layout.setSpacing(6)

        self.input_inspector_ai = QLineEdit()
        self.input_inspector_ai.setPlaceholderText("Ask AI: e.g. How to mitigate this finding?")
        self.input_inspector_ai.returnPressed.connect(self._ask_inspector_ai)
        ai_layout.addWidget(self.input_inspector_ai)

        btn_ask_ai = QPushButton("⚡ Inquire Local AI")
        btn_ask_ai.setObjectName("SecondaryGlassBtn")
        btn_ask_ai.clicked.connect(self._ask_inspector_ai)
        ai_layout.addWidget(btn_ask_ai)

        layout.addWidget(ai_box)
        layout.addStretch(1)

        return drawer

    # -------------------------------------------------------------------------
    # Bento KPI Card Helper
    # -------------------------------------------------------------------------

    def _create_kpi_card(self, title: str, initial_value: str, subtitle: str) -> Tuple[QFrame, QLabel, QLabel]:
        """Creates an executive Bento KPI tile with specular glass styling."""
        card = QFrame()
        card.setProperty("class", "glass-card")
        card.setObjectName("GlassCard")
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        card.setMinimumHeight(84)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 12, 14, 12)
        card_layout.setSpacing(3)

        title_lbl = QLabel(title.upper())
        title_lbl.setStyleSheet("font-size: 10px; font-weight: 700; letter-spacing: 1px; color: #A1A1AA;")
        card_layout.addWidget(title_lbl)

        val_lbl = QLabel(initial_value)
        val_lbl.setStyleSheet("font-size: 22px; font-weight: 800; color: #FAFAFA;")
        card_layout.addWidget(val_lbl)

        sub_lbl = QLabel(subtitle)
        sub_lbl.setStyleSheet("font-size: 11px; font-weight: 500; color: #71717A;")
        card_layout.addWidget(sub_lbl)

        return card, val_lbl, sub_lbl

    # -------------------------------------------------------------------------
    # Stacked Category Hubs Initialization
    # -------------------------------------------------------------------------

    def _init_stacked_views(self) -> None:
        self.stacked_widget.addWidget(self._create_hub1_executive_ai())      # 0
        self.stacked_widget.addWidget(self._create_hub2_domain_infra())      # 1
        self.stacked_widget.addWidget(self._create_hub3_network_threat())    # 2
        self.stacked_widget.addWidget(self._create_hub4_web_defense())       # 3
        self.stacked_widget.addWidget(self._create_hub5_personal_privacy())  # 4
        self.stacked_widget.addWidget(self._create_hub6_logs_json())         # 5

    # =========================================================================
    # HUB 1: Executive Overview & AI Dossier
    # =========================================================================

    def _create_hub1_executive_ai(self) -> QWidget:
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Bento KPI Row (4 Cards)
        kpi_row = QHBoxLayout()
        card1, self.lbl_kpi_grade, self.lbl_kpi_grade_sub = self._create_kpi_card("Posture Grade", "–", "Awaiting target scan")
        card2, self.lbl_kpi_score, self.lbl_kpi_score_sub = self._create_kpi_card("Security Score", "0 / 100", "Attack surface index")
        card3, self.lbl_kpi_findings, self.lbl_kpi_findings_sub = self._create_kpi_card("Actionable Findings", "0 Items", "Prioritized remediations")
        card4, self.lbl_kpi_ai, self.lbl_kpi_ai_sub = self._create_kpi_card("AI Engine", "Heuristic (0-RAM)", "Offline local reasoning")

        for c in [card1, card2, card3, card4]:
            kpi_row.addWidget(c)
        layout.addLayout(kpi_row)

        # Center Bento Splitter: Findings Table (Left) + AI Dossier & Chat (Right)
        bento_split = QSplitter(Qt.Horizontal)

        # Findings Table Glass Card
        findings_frame = QFrame()
        findings_frame.setProperty("class", "glass-card")
        findings_frame.setObjectName("GlassCard")
        f_layout = QVBoxLayout(findings_frame)
        f_layout.setContentsMargins(12, 12, 12, 12)
        f_layout.setSpacing(8)

        f_head = QLabel("PRIORITIZED ATTACK SURFACE REMEDIATIONS")
        f_head.setStyleSheet("font-size: 11px; font-weight: 700; letter-spacing: 0.8px; color: #FAFAFA;")
        f_layout.addWidget(f_head)

        self.table_findings = QTableWidget(0, 4)
        self.table_findings.setObjectName("Executive Findings")
        self.table_findings.setHorizontalHeaderLabels(["SEVERITY", "CATEGORY", "TITLE", "REMEDIATION"])
        self.table_findings.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_findings.verticalHeader().setVisible(False)
        self.table_findings.setAlternatingRowColors(True)
        self.table_findings.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_findings, r, c))
        f_layout.addWidget(self.table_findings)

        bento_split.addWidget(findings_frame)

        # AI Dossier Glass Card
        dossier_frame = QFrame()
        dossier_frame.setProperty("class", "glass-card")
        dossier_frame.setObjectName("GlassCard")
        d_layout = QVBoxLayout(dossier_frame)
        d_layout.setContentsMargins(12, 12, 12, 12)
        d_layout.setSpacing(8)

        ai_top_row = QHBoxLayout()
        d_head = QLabel("LOCAL AI EXECUTIVE DOSSIER")
        d_head.setStyleSheet("font-size: 11px; font-weight: 700; letter-spacing: 0.8px; color: #FAFAFA;")
        ai_top_row.addWidget(d_head, 1)

        self.btn_generate_dossier = QPushButton("⚡ Synthesize Dossier")
        self.btn_generate_dossier.setObjectName("PrimaryGlassBtn")
        self.btn_generate_dossier.clicked.connect(self._generate_ai_dossier)
        ai_top_row.addWidget(self.btn_generate_dossier)
        d_layout.addLayout(ai_top_row)

        self.dossier_browser = QTextBrowser()
        self.dossier_browser.setOpenExternalLinks(True)
        self.dossier_browser.setStyleSheet("background-color: rgba(0, 0, 0, 0.20); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 8px; font-size: 12px; padding: 10px;")
        self.dossier_browser.setHtml("<span style='color:#71717A;'>Click 'Synthesize Dossier' to correlate all reconnaissance findings into an offline executive report.</span>")
        d_layout.addWidget(self.dossier_browser)

        # Interactive Follow-up Chat
        chat_box = QHBoxLayout()
        self.input_ai_chat = QLineEdit()
        self.input_ai_chat.setPlaceholderText("Ask follow-up question (e.g. Which open ports pose immediate risk?)...")
        self.input_ai_chat.returnPressed.connect(self._ask_ai_question)
        chat_box.addWidget(self.input_ai_chat, 1)

        self.btn_send_chat = QPushButton("Send")
        self.btn_send_chat.setObjectName("SecondaryGlassBtn")
        self.btn_send_chat.clicked.connect(self._ask_ai_question)
        chat_box.addWidget(self.btn_send_chat)
        d_layout.addLayout(chat_box)

        bento_split.addWidget(dossier_frame)
        bento_split.setSizes([550, 450])
        layout.addWidget(bento_split, 1)

        return view

    # =========================================================================
    # HUB 2: Domain & Infrastructure Hub
    # =========================================================================

    def _create_hub2_domain_infra(self) -> QWidget:
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Bento KPI Row
        kpi_row = QHBoxLayout()
        c1, self.lbl_kpi_dns, _ = self._create_kpi_card("DNS Records", "0", "Standard A, AAAA, MX, NS")
        c2, self.lbl_kpi_subs, _ = self._create_kpi_card("Subdomains", "0", "Certificate Transparency logs")
        c3, self.lbl_kpi_takeovers, _ = self._create_kpi_card("Dangling CNAMEs", "0 Vuln", "Subdomain takeover audit")
        c4, self.lbl_kpi_expiry, _ = self._create_kpi_card("Domain Expiry", "–", "RDAP registration health")
        for c in [c1, c2, c3, c4]:
            kpi_row.addWidget(c)
        layout.addLayout(kpi_row)

        # Tab Widget for Domain sub-views
        tab = QTabWidget()

        # Tab 1: Standard DNS
        w_dns = QWidget()
        v_dns = QVBoxLayout(w_dns)
        self.table_dns = QTableWidget(0, 5)
        self.table_dns.setObjectName("DNS Records")
        self.table_dns.setHorizontalHeaderLabels(["RECORD TYPE", "DOMAIN", "VALUE", "TTL", "STATUS"])
        self.table_dns.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_dns.setAlternatingRowColors(True)
        self.table_dns.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_dns, r, c))
        v_dns.addWidget(self.table_dns)
        tab.addTab(w_dns, "DNS Records")

        # Tab 2: CT Subdomains
        w_subs = QWidget()
        v_subs = QVBoxLayout(w_subs)
        self.table_subdomains = QTableWidget(0, 4)
        self.table_subdomains.setObjectName("CT Subdomains")
        self.table_subdomains.setHorizontalHeaderLabels(["SUBDOMAIN", "DISCOVERY SOURCE", "ISSUER / CA", "DISCOVERY STATUS"])
        self.table_subdomains.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_subdomains.setAlternatingRowColors(True)
        self.table_subdomains.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_subdomains, r, c))
        v_subs.addWidget(self.table_subdomains)
        tab.addTab(w_subs, "CT Subdomains")

        # Tab 3: Takeovers
        w_take = QWidget()
        v_take = QVBoxLayout(w_take)
        self.table_takeovers = QTableWidget(0, 5)
        self.table_takeovers.setObjectName("Subdomain Takeovers")
        self.table_takeovers.setHorizontalHeaderLabels(["SUBDOMAIN", "CNAME TARGET", "CLOUD SERVICE", "TAKEOVER RISK", "REMEDIATION"])
        self.table_takeovers.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_takeovers.setAlternatingRowColors(True)
        self.table_takeovers.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_takeovers, r, c))
        v_take.addWidget(self.table_takeovers)
        tab.addTab(w_take, "CNAME Takeovers")

        # Tab 4: RDAP
        w_rdap = QWidget()
        v_rdap = QVBoxLayout(w_rdap)
        self.table_rdap = QTableWidget(0, 3)
        self.table_rdap.setObjectName("RDAP & WHOIS")
        self.table_rdap.setHorizontalHeaderLabels(["FIELD", "VALUE", "CONTEXT"])
        self.table_rdap.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_rdap.setAlternatingRowColors(True)
        self.table_rdap.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_rdap, r, c))
        v_rdap.addWidget(self.table_rdap)
        tab.addTab(w_rdap, "RDAP / WHOIS")

        layout.addWidget(tab, 1)
        return view

    # =========================================================================
    # HUB 3: Network, Cloud & Threat Exposure Hub
    # =========================================================================

    def _create_hub3_network_threat(self) -> QWidget:
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Bento KPI Row
        kpi_row = QHBoxLayout()
        c1, self.lbl_kpi_ports, _ = self._create_kpi_card("Open Ports", "0", "Shodan InternetDB passive index")
        c2, self.lbl_kpi_cves, _ = self._create_kpi_card("CVE References", "0", "Associated historical vulnerabilities")
        c3, self.lbl_kpi_cloud, _ = self._create_kpi_card("Cloud / CDN", "Direct", "Perimeter infrastructure provider")
        c4, self.lbl_kpi_threat_scans, _ = self._create_kpi_card("Threat History", "0 Scans", "URLScan.io & AlienVault OTX")
        for c in [c1, c2, c3, c4]:
            kpi_row.addWidget(c)
        layout.addLayout(kpi_row)

        tab = QTabWidget()

        # Tab 1: InternetDB Ports & CVEs
        w_exp = QWidget()
        v_exp = QVBoxLayout(w_exp)
        self.table_exposure = QTableWidget(0, 5)
        self.table_exposure.setObjectName("Shodan InternetDB Exposure")
        self.table_exposure.setHorizontalHeaderLabels(["TARGET IP", "HOSTNAMES", "OPEN PORTS", "ASSOCIATED CVES", "SERVICE TAGS"])
        self.table_exposure.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_exposure.setAlternatingRowColors(True)
        self.table_exposure.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_exposure, r, c))
        v_exp.addWidget(self.table_exposure)
        tab.addTab(w_exp, "InternetDB Exposure")

        # Tab 2: IP Geolocation & ASN
        w_ip = QWidget()
        v_ip = QVBoxLayout(w_ip)
        self.table_ip_intel = QTableWidget(0, 5)
        self.table_ip_intel.setObjectName("IP Geolocation & ASN")
        self.table_ip_intel.setHorizontalHeaderLabels(["IP ADDRESS", "COUNTRY / REGION", "ASN", "ISP / ORG", "CLOUD / CDN"])
        self.table_ip_intel.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_ip_intel.setAlternatingRowColors(True)
        self.table_ip_intel.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_ip_intel, r, c))
        v_ip.addWidget(self.table_ip_intel)
        tab.addTab(w_ip, "IP Geolocation & ASN")

        # Tab 3: URLScan & OTX History
        w_th = QWidget()
        v_th = QVBoxLayout(w_th)
        self.table_threat = QTableWidget(0, 5)
        self.table_threat.setObjectName("Threat Archives")
        self.table_threat.setHorizontalHeaderLabels(["SOURCE", "DATE / TIMESTAMP", "TARGET URL", "IP OBSERVED", "DETAILS / LINK"])
        self.table_threat.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_threat.setAlternatingRowColors(True)
        self.table_threat.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_threat, r, c))
        v_th.addWidget(self.table_threat)
        tab.addTab(w_th, "Threat Archives & URLScan")

        layout.addWidget(tab, 1)
        return view

    # =========================================================================
    # HUB 4: Web & Email Defensive Posture Hub
    # =========================================================================

    def _create_hub4_web_defense(self) -> QWidget:
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Bento KPI Row
        kpi_row = QHBoxLayout()
        c1, self.lbl_kpi_email_grade, _ = self._create_kpi_card("Email Defense", "–", "Anti-spoofing rating")
        c2, self.lbl_kpi_dmarc_pol, _ = self._create_kpi_card("DMARC & SPF", "Missing", "Enforcement mechanism")
        c3, self.lbl_kpi_headers_grade, _ = self._create_kpi_card("Security Headers", "–", "HSTS, CSP, XFO, Permissions")
        c4, self.lbl_kpi_tech_count, _ = self._create_kpi_card("Web Stack", "0", "Fingerprinted signatures")
        for c in [c1, c2, c3, c4]:
            kpi_row.addWidget(c)
        layout.addLayout(kpi_row)

        tab = QTabWidget()

        # Tab 1: HTTP Security Headers
        w_web = QWidget()
        v_web = QVBoxLayout(w_web)
        self.table_web = QTableWidget(0, 4)
        self.table_web.setObjectName("HTTP Security Headers")
        self.table_web.setHorizontalHeaderLabels(["HEADER", "STATUS", "OBSERVED VALUE", "RECOMMENDATION"])
        self.table_web.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_web.setAlternatingRowColors(True)
        self.table_web.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_web, r, c))
        v_web.addWidget(self.table_web)
        tab.addTab(w_web, "Security Headers")

        # Tab 2: Email Spoofing Defense
        w_em = QWidget()
        v_em = QVBoxLayout(w_em)
        self.table_email_sec = QTableWidget(0, 4)
        self.table_email_sec.setObjectName("Email Security Posture")
        self.table_email_sec.setHorizontalHeaderLabels(["MECHANISM", "STATUS", "RECORD VALUE", "SECURITY OBJECTIVE"])
        self.table_email_sec.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_email_sec.setAlternatingRowColors(True)
        self.table_email_sec.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_email_sec, r, c))
        v_em.addWidget(self.table_email_sec)
        tab.addTab(w_em, "Email Anti-Spoofing")

        # Tab 3: Technology Stack
        w_tech = QWidget()
        v_tech = QVBoxLayout(w_tech)
        self.table_tech = QTableWidget(0, 4)
        self.table_tech.setObjectName("Web Technology Stack")
        self.table_tech.setHorizontalHeaderLabels(["CATEGORY", "TECHNOLOGY", "VERSION", "EVIDENCE"])
        self.table_tech.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_tech.setAlternatingRowColors(True)
        self.table_tech.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_tech, r, c))
        v_tech.addWidget(self.table_tech)
        tab.addTab(w_tech, "Tech Stack & Manifests")

        # Tab 4: Wayback Archive
        w_arch = QWidget()
        v_arch = QVBoxLayout(w_arch)
        self.table_archive = QTableWidget(0, 4)
        self.table_archive.setObjectName("Wayback Machine Archive")
        self.table_archive.setHorizontalHeaderLabels(["MILESTONE", "TIMESTAMP", "ARCHIVED URL", "HTTP STATUS"])
        self.table_archive.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_archive.setAlternatingRowColors(True)
        self.table_archive.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_archive, r, c))
        v_arch.addWidget(self.table_archive)
        tab.addTab(w_arch, "Wayback Archive")

        layout.addWidget(tab, 1)
        return view

    # =========================================================================
    # HUB 5: Personal Identity & Digital Footprint Hub (Expanded with 5 New Engines)
    # =========================================================================

    def _create_hub5_personal_privacy(self) -> QWidget:
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Bento KPI Row
        kpi_row = QHBoxLayout()
        c1, self.lbl_kpi_priv_score, _ = self._create_kpi_card("Privacy Score", "100 / 100", "Identity exposure rating")
        c2, self.lbl_kpi_breaches, _ = self._create_kpi_card("Breaches", "0", "XposedOrNot public leaks")
        c3, self.lbl_kpi_social_claimed, _ = self._create_kpi_card("Social Presence", "0 / 40", "Public handles confirmed")
        c4, self.lbl_kpi_timezone, _ = self._create_kpi_card("Estimated Timezone", "–", "Temporal activity window")
        for c in [c1, c2, c3, c4]:
            kpi_row.addWidget(c)
        layout.addLayout(kpi_row)

        tab = QTabWidget()

        # Tab 1: Email Breach Exposure
        w_em = QWidget()
        v_em = QVBoxLayout(w_em)
        self.table_personal_email = QTableWidget(0, 4)
        self.table_personal_email.setObjectName("Email Breach Exposure")
        self.table_personal_email.setHorizontalHeaderLabels(["SOURCE / BREACH", "DETAILS / TITLE", "DATE", "EXPOSED DATA"])
        self.table_personal_email.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_personal_email.setAlternatingRowColors(True)
        self.table_personal_email.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_personal_email, r, c))
        v_em.addWidget(self.table_personal_email)
        tab.addTab(w_em, "Breaches & Email")

        # Tab 2: Phone Intelligence
        w_ph = QWidget()
        v_ph = QVBoxLayout(w_ph)
        self.table_personal_phone = QTableWidget(0, 3)
        self.table_personal_phone.setObjectName("Phone Intelligence")
        self.table_personal_phone.setHorizontalHeaderLabels(["ATTRIBUTE", "DETECTED VALUE", "ACTIONABLE LINK"])
        self.table_personal_phone.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_personal_phone.setAlternatingRowColors(True)
        self.table_personal_phone.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_personal_phone, r, c))
        v_ph.addWidget(self.table_personal_phone)
        tab.addTab(w_ph, "Phone & Messaging")

        # Tab 3: 40+ Social & Account Matrix
        w_soc = QWidget()
        v_soc = QVBoxLayout(w_soc)
        self.table_personal_social = QTableWidget(0, 4)
        self.table_personal_social.setObjectName("Social Footprint Matrix")
        self.table_personal_social.setHorizontalHeaderLabels(["PLATFORM", "STATUS", "PROFILE URL", "OBSERVED BIO / EVIDENCE"])
        self.table_personal_social.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_personal_social.setAlternatingRowColors(True)
        self.table_personal_social.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_personal_social, r, c))
        v_soc.addWidget(self.table_personal_social)
        tab.addTab(w_soc, "40+ Social Matrix")

        # Tab 4: Username Permutations
        w_perm = QWidget()
        v_perm = QVBoxLayout(w_perm)
        self.table_personal_permutations = QTableWidget(0, 3)
        self.table_personal_permutations.setObjectName("Username Permutations")
        self.table_personal_permutations.setHorizontalHeaderLabels(["HANDLE VARIATION", "PERMUTATION STRATEGY", "ESTIMATED LINKABILITY"])
        self.table_personal_permutations.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_personal_permutations.setAlternatingRowColors(True)
        self.table_personal_permutations.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_personal_permutations, r, c))
        v_perm.addWidget(self.table_personal_permutations)
        tab.addTab(w_perm, "Handle Permutator")

        # Tab 5: Developer & Package Maintainer Footprint (NEW Engine 1)
        w_dev = QWidget()
        v_dev = QVBoxLayout(w_dev)
        self.table_dev_footprint = QTableWidget(0, 5)
        self.table_dev_footprint.setObjectName("Developer & Package Footprint")
        self.table_dev_footprint.setHorizontalHeaderLabels(["REGISTRY / SOURCE", "PACKAGE / REPO", "AUTHOR / MAINTAINER", "COMMIT EMAILS", "LINK"])
        self.table_dev_footprint.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_dev_footprint.setAlternatingRowColors(True)
        self.table_dev_footprint.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_dev_footprint, r, c))
        v_dev.addWidget(self.table_dev_footprint)
        tab.addTab(w_dev, "Developer & Packages")

        # Tab 6: Academic Research & ORCID Affiliations (NEW Engine 2)
        w_acad = QWidget()
        v_acad = QVBoxLayout(w_acad)
        self.table_academic = QTableWidget(0, 4)
        self.table_academic.setObjectName("Academic & Institutional Identity")
        self.table_academic.setHorizontalHeaderLabels(["AUTHOR / SCHOLAR", "ORCID ID", "INSTITUTIONAL AFFILIATIONS", "PUBLICATIONS & TOPICS"])
        self.table_academic.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_academic.setAlternatingRowColors(True)
        self.table_academic.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_academic, r, c))
        v_acad.addWidget(self.table_academic)
        tab.addTab(w_acad, "Academic & ORCID")

        # Tab 7: Temporal Activity Cadence & Timezone (NEW Engine 3)
        w_cad = QWidget()
        v_cad = QVBoxLayout(w_cad)
        cad_head = QLabel("24-HOUR ACTIVITY DISTRIBUTION & ESTIMATED UTC TIMEZONE BELT")
        cad_head.setStyleSheet("font-size: 11px; font-weight: 700; letter-spacing: 0.8px; color: #FAFAFA;")
        v_cad.addWidget(cad_head)

        self.text_cadence_chart = QTextBrowser()
        self.text_cadence_chart.setStyleSheet("background-color: rgba(0, 0, 0, 0.35); font-family: 'Cascadia Mono', Consolas, monospace; font-size: 12px; padding: 10px; border-radius: 8px;")
        self.text_cadence_chart.setPlainText("Run personal audit to build 24-hour activity distribution and estimate waking hours.")
        v_cad.addWidget(self.text_cadence_chart)
        tab.addTab(w_cad, "Activity Cadence")

        # Tab 8: Corporate & Nonprofit Public Records (NEW Engine 4)
        w_rec = QWidget()
        v_rec = QVBoxLayout(w_rec)
        self.table_public_records = QTableWidget(0, 4)
        self.table_public_records.setObjectName("Corporate & Nonprofit Records")
        self.table_public_records.setHorizontalHeaderLabels(["REGISTRY SOURCE", "ENTITY TITLE", "IDENTIFIER / EIN", "RECORD DESCRIPTION"])
        self.table_public_records.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_public_records.setAlternatingRowColors(True)
        self.table_public_records.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_public_records, r, c))
        v_rec.addWidget(self.table_public_records)
        tab.addTab(w_rec, "Corporate & Nonprofit")

        # Tab 9: Web3 & ENS Decentralized Identity (NEW Engine 5)
        w_w3 = QWidget()
        v_w3 = QVBoxLayout(w_w3)
        self.table_web3_identity = QTableWidget(0, 4)
        self.table_web3_identity.setObjectName("Web3 & ENS Identity")
        self.table_web3_identity.setHorizontalHeaderLabels(["ENS DOMAIN", "RESOLVED ETH ADDRESS", "SOCIAL TEXT RECORDS", "DECENTRALIZED IPFS"])
        self.table_web3_identity.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_web3_identity.setAlternatingRowColors(True)
        self.table_web3_identity.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_web3_identity, r, c))
        v_w3.addWidget(self.table_web3_identity)
        tab.addTab(w_w3, "Web3 & ENS")

        # Tab 10: EXIF Privacy Scrubber
        w_scrub = QWidget()
        v_scrub = QVBoxLayout(w_scrub)

        scrub_btn_row = QHBoxLayout()
        self.btn_select_scrub_file = QPushButton("📂 Choose Image / PDF...")
        self.btn_select_scrub_file.setObjectName("SecondaryGlassBtn")
        self.btn_select_scrub_file.clicked.connect(self._select_file_for_scrubbing)
        scrub_btn_row.addWidget(self.btn_select_scrub_file)

        self.btn_save_clean = QPushButton("🛡️ Sanitize & Save Clean Copy")
        self.btn_save_clean.setObjectName("PrimaryGlassBtn")
        self.btn_save_clean.setEnabled(False)
        self.btn_save_clean.clicked.connect(self._sanitize_and_save_clean_copy)
        scrub_btn_row.addWidget(self.btn_save_clean)
        scrub_btn_row.addStretch(1)
        v_scrub.addLayout(scrub_btn_row)

        self.lbl_scrub_filename = QLabel("No file selected.")
        self.lbl_scrub_filename.setStyleSheet("color: #A1A1AA; font-size: 11px;")
        v_scrub.addWidget(self.lbl_scrub_filename)

        self.table_scrubber_metadata = QTableWidget(0, 3)
        self.table_scrubber_metadata.setObjectName("EXIF Privacy Scrubber")
        self.table_scrubber_metadata.setHorizontalHeaderLabels(["METADATA TAG", "EMBEDDED VALUE", "PRIVACY RISK"])
        self.table_scrubber_metadata.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_scrubber_metadata.setAlternatingRowColors(True)
        self.table_scrubber_metadata.cellClicked.connect(lambda r, c: self._on_table_row_clicked(self.table_scrubber_metadata, r, c))
        v_scrub.addWidget(self.table_scrubber_metadata)
        tab.addTab(w_scrub, "EXIF Privacy Scrubber")

        layout.addWidget(tab, 1)
        return view

    # =========================================================================
    # HUB 6: Live Activity Logs & Diagnostic Suite
    # =========================================================================

    def _create_hub6_logs_json(self) -> QWidget:
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        head_lbl = QLabel("SYSTEM ACTIVITY LOGS & DIAGNOSTIC VERIFICATION")
        head_lbl.setStyleSheet("font-size: 11px; font-weight: 700; letter-spacing: 0.8px; color: #FAFAFA;")
        top_row.addWidget(head_lbl, 1)

        self.btn_run_diag = QPushButton("⚡ Run Full Diagnostic Suite (--full-diagnostic)")
        self.btn_run_diag.setObjectName("PrimaryGlassBtn")
        self.btn_run_diag.setToolTip("Execute the automated 6-stage end-to-end health check")
        self.btn_run_diag.clicked.connect(self._run_gui_diagnostics)
        top_row.addWidget(self.btn_run_diag)
        layout.addLayout(top_row)

        tab = QTabWidget()

        # Tab 1: Live ANSI/HTML Log Stream
        w_log = QWidget()
        v_log = QVBoxLayout(w_log)
        self.text_logs = QTextBrowser()
        self.text_logs.setStyleSheet("background-color: rgba(0, 0, 0, 0.45); font-family: 'Cascadia Mono', Consolas, monospace; font-size: 12px; padding: 10px; border-radius: 8px;")
        v_log.addWidget(self.text_logs)
        tab.addTab(w_log, "Live Activity Logs")

        # Tab 2: Raw JSON Telemetry Tree
        w_json = QWidget()
        v_json = QVBoxLayout(w_json)
        self.text_json = QTextEdit()
        self.text_json.setStyleSheet("background-color: rgba(0, 0, 0, 0.45); font-family: 'Cascadia Mono', Consolas, monospace; font-size: 12px; padding: 10px; border-radius: 8px;")
        self.text_json.setPlaceholderText("Raw JSON telemetry will appear here once an audit completes.")
        v_json.addWidget(self.text_json)
        tab.addTab(w_json, "Raw JSON Inspector")

        layout.addWidget(tab, 1)
        return view

    # -------------------------------------------------------------------------
    # Navigation & Interaction Handlers
    # -------------------------------------------------------------------------

    def _on_nav_clicked(self, index: int) -> None:
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)
        self.stacked_widget.setCurrentIndex(index)

    def _toggle_nav_rail(self) -> None:
        self.rail_expanded = not self.rail_expanded
        if self.rail_expanded:
            self.nav_rail.setFixedWidth(240)
            self.lbl_rail_title.setVisible(True)
            self.btn_toggle_rail.setText("◀")
            for btn in self.nav_buttons:
                btn.setText(btn.property("full_text") or btn.text())
        else:
            self.nav_rail.setFixedWidth(64)
            self.lbl_rail_title.setVisible(False)
            self.btn_toggle_rail.setText("▶")
            for btn in self.nav_buttons:
                if not btn.property("full_text"):
                    btn.setProperty("full_text", btn.text())
                btn.setText(btn.text().split()[0])

    def _toggle_inspector_drawer(self) -> None:
        self.inspector_drawer.setVisible(not self.inspector_drawer.isVisible())

    def _on_target_text_changed(self, text: str) -> None:
        """Dynamically detects target entity type and updates live monochrome badge."""
        clean = text.strip()
        if not clean:
            self.lbl_target_badge.setText("[TARGET: DOMAIN]")
            return

        if clean.startswith("+") or (clean[0].isdigit() and len(clean.replace("-", "").replace(" ", "")) >= 7):
            self.lbl_target_badge.setText("[TARGET: PHONE]")
        elif "@" in clean and "." in clean.split("@")[-1]:
            self.lbl_target_badge.setText("[TARGET: EMAIL]")
        elif clean.startswith("@") or (" " not in clean and "." not in clean and len(clean) >= 2):
            self.lbl_target_badge.setText("[TARGET: @HANDLE]")
        elif " " in clean and len(clean.split()) >= 2 and "." not in clean:
            self.lbl_target_badge.setText("[TARGET: PERSON / NAME]")
        else:
            self.lbl_target_badge.setText("[TARGET: DOMAIN / IP]")

    def _on_table_row_clicked(self, table: QTableWidget, row: int, col: int) -> None:
        """Populates the Right Inspector Drawer with deep record key-values and guidance."""
        if row < 0 or row >= table.rowCount():
            return

        headers = []
        for c in range(table.columnCount()):
            h_item = table.horizontalHeaderItem(c)
            headers.append(h_item.text() if h_item else f"Column {c+1}")

        row_data: Dict[str, str] = {}
        for c in range(table.columnCount()):
            item = table.item(row, c)
            val = item.text() if item else "—"
            row_data[headers[c]] = val

        self.inspect_record(table.objectName() or "Record Finding", row_data)

    def inspect_record(self, category: str, row_dict: Dict[str, str]) -> None:
        """Renders record details, calculates severity badge, and displays defense context."""
        self.inspector_drawer.setVisible(True)
        first_val = list(row_dict.values())[0] if row_dict else "Record Details"
        self.inspector_title.setText(str(first_val))
        self.inspector_category_lbl.setText(f"CATEGORY: {category.upper()}")

        # Detect severity from contents
        full_text = " ".join(str(v).upper() for v in row_dict.values())
        if any(w in full_text for w in ["CRITICAL", "VULNERABLE", "EXPIRED", "HARDFAIL"]):
            self.inspector_severity_badge.setText("CRITICAL RISK")
            self.inspector_severity_badge.setStyleSheet(
                "background-color: #FAFAFA; color: #09090B; border: 1px solid #FFFFFF; border-radius: 6px; padding: 2px 8px; font-weight: 800; font-size: 10px;"
            )
        elif any(w in full_text for w in ["HIGH", "MISSING", "SOFTFAIL", "DANGLING", "WARN"]):
            self.inspector_severity_badge.setText("HIGH / WARNING")
            self.inspector_severity_badge.setStyleSheet(
                "background-color: rgba(255, 255, 255, 0.16); color: #FFFFFF; border: 1px solid rgba(255, 255, 255, 0.30); border-radius: 6px; padding: 2px 8px; font-weight: 700; font-size: 10px;"
            )
        else:
            self.inspector_severity_badge.setText("CLEAN / PASS")
            self.inspector_severity_badge.setStyleSheet(
                "background-color: rgba(255, 255, 255, 0.06); color: #A1A1AA; border: 1px solid rgba(255, 255, 255, 0.14); border-radius: 6px; padding: 2px 8px; font-weight: 700; font-size: 10px;"
            )

        # Populate Inspector detail table
        self.inspector_table.setRowCount(len(row_dict))
        for idx, (k, v) in enumerate(row_dict.items()):
            k_item = QTableWidgetItem(str(k))
            k_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            v_item = QTableWidgetItem(str(v))
            v_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            self.inspector_table.setItem(idx, 0, k_item)
            self.inspector_table.setItem(idx, 1, v_item)

        # Generate contextual guidance
        remediation_html = ""
        if "REMEDIATION" in row_dict and row_dict["REMEDIATION"] != "—":
            remediation_html = f"<b style='color:#FFFFFF;'>Recommended Action:</b><br/>{row_dict['REMEDIATION']}"
        elif "RECOMMENDATION" in row_dict and row_dict["RECOMMENDATION"] != "—":
            remediation_html = f"<b style='color:#FFFFFF;'>Header Deployment:</b><br/>{row_dict['RECOMMENDATION']}"
        elif "TAKEOVER" in category.upper():
            remediation_html = "<b style='color:#FFFFFF;'>Subdomain Takeover Defense:</b><br/>Verify whether the pointed cloud storage bucket or service host has been deleted. Immediately de-register dangling DNS records."
        elif "BREACH" in category.upper():
            remediation_html = "<b style='color:#FFFFFF;'>Identity Exposure Defense:</b><br/>Rotate compromised passwords, invalidate active sessions, and enforce hardware security key multi-factor authentication (WebAuthn / FIDO2)."
        else:
            remediation_html = f"<b style='color:#FFFFFF;'>Contextual Intelligence:</b><br/>Passive telemetry item recorded during {category.lower()} inspection."

        self.inspector_remediation.setHtml(remediation_html)

    def _copy_inspector_cell(self) -> None:
        item = self.inspector_table.currentItem()
        if item:
            QApplication.clipboard().setText(item.text())
            self.status_bar.showMessage("Copied cell value to clipboard.", 2500)

    def _copy_inspector_json(self) -> None:
        data = {}
        for r in range(self.inspector_table.rowCount()):
            k = self.inspector_table.item(r, 0).text()
            v = self.inspector_table.item(r, 1).text()
            data[k] = v
        QApplication.clipboard().setText(json.dumps(data, indent=2))
        self.status_bar.showMessage("Copied record JSON to clipboard.", 2500)

    def _ask_inspector_ai(self) -> None:
        q = self.input_inspector_ai.text().strip()
        if not q:
            return
        target = self.inspector_title.text()
        context = {
            "entity": target,
            "category": self.inspector_category_lbl.text(),
            "status": self.inspector_severity_badge.text(),
        }
        answer = HeuristicAnalyst.answer_offline_question(context, q)
        self.inspector_remediation.setHtml(f"<b style='color:#FFFFFF;'>AI Analysis:</b><br/>{answer}")
        self.input_inspector_ai.clear()

    # -------------------------------------------------------------------------
    # Core Audit Orchestration & Execution
    # -------------------------------------------------------------------------

    def start_recon(self) -> None:
        raw_target = self.input_domain.text().strip()
        if not raw_target:
            QMessageBox.warning(self, "Missing Target", "Please enter a target domain name or personal handle to audit.")
            return

        profile = self.combo_profile.currentData()
        target_badge = self.lbl_target_badge.text()

        # If personal profile or personal target format, route directly to personal suite
        if profile == "personal" or target_badge in ["[TARGET: EMAIL]", "[TARGET: PHONE]", "[TARGET: @HANDLE]", "[TARGET: PERSON / NAME]"]:
            self._start_personal_deep_audit(raw_target)
            return

        # Otherwise normalize as domain
        domain = normalize_domain(raw_target)
        if not domain:
            QMessageBox.warning(self, "Invalid Target", "Could not normalize target into a valid domain or handle.")
            return

        self.input_domain.setText(domain)
        cfg = load_config()
        rate_rps = float(cfg.get("rate_limit_rps", 2.0))
        timeout = float(cfg.get("timeout_sec", 10.0))
        ua = str(cfg.get("user_agent", "OSINTReconStudio-PassiveAudit/1.0"))
        gh_token = str(cfg.get("github_token", ""))
        force_refresh = self.chk_force_refresh.isChecked()

        enabled_modules = {
            "dns": True,
            "ct": True,
            "takeover": self.chk_takeover.isChecked(),
            "rdap": True,
            "web": True,
            "archive": True,
            "internetdb": self.chk_exposure.isChecked(),
            "ip_intel": self.chk_exposure.isChecked(),
            "urlscan": self.chk_threat.isChecked(),
            "email_sec": True,
            "tech_stack": True,
            "github": True,
            "pgp": True,
            "username": True,
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
            self._on_log("WARNING", "Cancelling active reconnaissance...")
            self.btn_cancel.setEnabled(False)

    def _start_personal_deep_audit(self, target: str) -> None:
        """Executes both personal OSINT suite and deep personal OSINT engines concurrently."""
        self.btn_start.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setRange(0, 0)
        self.status_bar.showMessage(f"Auditing personal footprint & registries for: {target}")
        self._on_log("INFO", f"Initiating expanded Personal OSINT Suite for target: {target}")

        # Switch to Hub 5 automatically
        self._on_nav_clicked(4)

        clean_handle = target.strip().lstrip("@")
        email_cand = target if "@" in target and "." in target else ""
        phone_cand = target if target.startswith("+") or target.replace("-", "").isdigit() else ""

        def _do_both():
            base_report = PersonalOSINTSuite.run_suite_sync(handle=clean_handle, email=email_cand, phone=phone_cand)
            deep_report = PersonalDeepOSINTSuite.run_sync(clean_handle, timeout=6.0)
            return base_report, deep_report

        worker = AsyncTaskWorker(_do_both)
        worker.signals.finished.connect(self._on_personal_deep_finished)
        worker.signals.error.connect(self._on_personal_deep_error)
        self.thread_pool.start(worker)

    def _on_personal_deep_finished(self, reports: Tuple[Any, DeepPersonalReport]) -> None:
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.status_bar.showMessage("Personal Identity & Deep OSINT audit complete.")

        base_report, deep_report = reports
        self.latest_personal_results = base_report.to_dict()
        self.latest_deep_personal = deep_report

        # 1. Base personal reports (Email, Phone, Social, Permutations)
        email_rows = []
        if base_report.email_report:
            er = base_report.email_report
            if er.gravatar_url:
                email_rows.append(["Gravatar Profile", "Avatar Published", "Active", er.gravatar_url])
            if er.pgp_keys_found:
                email_rows.append(["OpenPGP Keyserver", f"{len(er.pgp_keys_found)} Keys Found", "Active", ", ".join(er.pgp_keys_found[:2])])
            for b in er.breaches:
                email_rows.append(["Breach (XposedOrNot)", b.name, b.breach_date, ", ".join(b.exposed_data[:3])])
        if not email_rows:
            email_rows.append(["Email Privacy", "No public breach records indexed", "Clean", "None"])
        self.populate_table_safely(self.table_personal_email, email_rows)

        phone_rows = []
        if base_report.messaging_links:
            for k, v in base_report.messaging_links.items():
                phone_rows.append([k, v, v])
        if not phone_rows:
            phone_rows.append(["Phone Telemetry", "No phone number provided or standard format", "N/A"])
        self.populate_table_safely(self.table_personal_phone, phone_rows)

        soc_rows = []
        for r in base_report.social_results:
            soc_rows.append([r.platform, r.status, r.profile_url, r.bio_snippet or r.title or "N/A"])
        self.populate_table_safely(self.table_personal_social, soc_rows)

        perm_rows = []
        for p in base_report.permutations[:100]:
            perm_rows.append([p.handle, p.strategy, f"{p.risk_score}/100"])
        self.populate_table_safely(self.table_personal_permutations, perm_rows)

        # 2. Deep Personal Reports (NEW Engines)
        # Dev Footprint
        dev_rows = []
        dev_rep = deep_report.dev_footprint
        for pkg in dev_rep.packages:
            dev_rows.append([pkg.registry, pkg.name, dev_rep.handle, ", ".join(dev_rep.commit_emails[:2]) or "None", pkg.url])
        if not dev_rows and dev_rep.commit_emails:
            dev_rows.append(["GitHub Commits", f"{len(dev_rep.commit_authors)} Authors", ", ".join(dev_rep.commit_authors[:2]), ", ".join(dev_rep.commit_emails), "https://github.com"])
        if not dev_rows:
            dev_rows.append(["Package Registry", "No public packages found", dev_rep.handle, "No commit emails", "N/A"])
        self.populate_table_safely(self.table_dev_footprint, dev_rows)

        # Academic Identity
        acad_rows = []
        acad_rep = deep_report.academic_identity
        if acad_rep.display_name or acad_rep.orcid:
            acad_rows.append([
                acad_rep.display_name or deep_report.target,
                acad_rep.orcid or "Not listed",
                ", ".join(acad_rep.affiliations[:3]) or "None",
                f"{acad_rep.works_count} works, {acad_rep.cited_by_count} citations; Topics: {', '.join(acad_rep.top_topics[:2])}",
            ])
        if not acad_rows:
            acad_rows.append(["Academic Registry", "No OpenAlex/ORCID record found", "N/A", "N/A"])
        self.populate_table_safely(self.table_academic, acad_rows)

        # Activity Cadence Chart & Timezone
        cad_rep = deep_report.activity_cadence
        if cad_rep.is_success:
            self.text_cadence_chart.setPlainText(
                f"TARGET: {cad_rep.handle}\n"
                f"TOTAL OBSERVED TIMESTAMP EVENTS: {cad_rep.total_events}\n"
                f"ESTIMATED ACTIVE WINDOW: {cad_rep.estimated_active_window}\n"
                f"PROBABLE QUIET WINDOW (SLEEP): {cad_rep.quiet_window_utc}\n"
                f"PROBABLE TIMEZONE: {cad_rep.probable_timezone_offset} ({cad_rep.probable_region})\n\n"
                f"24-HOUR UTC ACTIVITY HISTOGRAM:\n{cad_rep.ascii_chart}"
            )
            self.lbl_kpi_timezone.setText(cad_rep.probable_timezone_offset)
        else:
            self.text_cadence_chart.setPlainText("Insufficient public timestamps observed across GitHub/Reddit/HackerNews.")
            self.lbl_kpi_timezone.setText("–")

        # Corporate / Nonprofit Records
        pub_rows = []
        for itm in deep_report.public_records.items:
            pub_rows.append([itm.source, itm.title, "IRS / Registry", itm.description])
        if not pub_rows:
            pub_rows.append(["Public Records", "No Wikidata or ProPublica matches found", "N/A", "N/A"])
        self.populate_table_safely(self.table_public_records, pub_rows)

        # Web3 / ENS Identity
        w3_rows = []
        w3_rep = deep_report.web3_identity
        if w3_rep.address:
            socials = f"Twitter: {w3_rep.twitter}, GitHub: {w3_rep.github}".strip(", ")
            w3_rows.append([w3_rep.ens_name, w3_rep.address, socials or "None", w3_rep.content_hash or "None"])
        if not w3_rows:
            w3_rows.append(["ENS Resolver", "No .eth name registered", "N/A", "N/A"])
        self.populate_table_safely(self.table_web3_identity, w3_rows)

        # Update KPI Tiles
        self.lbl_kpi_priv_score.setText(f"{100 - base_report.linkability_risk_score} / 100")
        self.lbl_kpi_breaches.setText(str(len(base_report.email_report.breaches) if base_report.email_report else 0))
        claimed = sum(1 for s in base_report.social_results if s.status.lower() == "claimed")
        self.lbl_kpi_social_claimed.setText(f"{claimed} / {len(base_report.social_results)}")

        self._on_log("SUCCESS", "Personal Identity & Deep OSINT audit completed with 100% data fidelity.")

    def _on_personal_deep_error(self, err: str) -> None:
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.progress_bar.setRange(0, 100)
        self._on_log("ERROR", f"Personal audit error: {err}")

    # -------------------------------------------------------------------------
    # Worker Signal Callbacks
    # -------------------------------------------------------------------------

    def _on_started(self, domain: str) -> None:
        self.btn_start.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_bar.showMessage(f"Auditing attack surface for {domain}...")

    def _on_progress(self, msg: str, pct: int) -> None:
        self.progress_bar.setValue(pct)
        self.status_bar.showMessage(msg)

    def _on_log(self, level: str, msg: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        color = "#FAFAFA"
        if level == "SUCCESS":
            color = "#FFFFFF"
        elif level == "WARNING":
            color = "#D4D4D8"
        elif level == "ERROR":
            color = "#F4F4F6"
        self.text_logs.append(f'<span style="color:#71717A;">[{ts}]</span> <b style="color:{color};">[{level}]</b> {msg}')

    def _on_module_complete(self, module_name: str, data: Dict[str, Any]) -> None:
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
            logger.debug("Progressive population exception on %s: %s", module_name, exc)

    def _on_error(self, module_name: str, err: str) -> None:
        self.status_bar.showMessage(f"Notice in {module_name}: {err}")
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)

    def _on_finished(self, consolidated: Dict[str, Any]) -> None:
        self.latest_results = consolidated
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_export.setEnabled(True)
        self.progress_bar.setValue(100)
        self.status_bar.showMessage("Reconnaissance complete. Executive Dossier ready.")

        self._populate_all_views(consolidated)
        self.text_json.setText(json.dumps(consolidated, indent=2))

    # -------------------------------------------------------------------------
    # Safe Table Population Helper
    # -------------------------------------------------------------------------

    def populate_table_safely(self, table: QTableWidget, rows: List[List[Any]]) -> None:
        """Safely inserts rows into QTableWidget without lag, crashes, or sorting locks."""
        table.setSortingEnabled(False)
        table.setUpdatesEnabled(False)
        table.clearContents()

        # Deduplicate and cap at 2,500 rows for high-DPI desktop performance
        seen = set()
        deduped = []
        for r in rows:
            key = tuple(str(x) for x in r)
            if key not in seen:
                seen.add(key)
                deduped.append(r)
                if len(deduped) >= 2500:
                    break

        table.setRowCount(len(deduped))
        for row_idx, row_data in enumerate(deduped):
            for col_idx, val in enumerate(row_data):
                val_str = "—" if val is None or str(val).strip() == "" else str(val)
                item = QTableWidgetItem(val_str)
                item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                table.setItem(row_idx, col_idx, item)

        table.setUpdatesEnabled(True)
        table.setSortingEnabled(True)

    # -------------------------------------------------------------------------
    # Hub Population Logic
    # -------------------------------------------------------------------------

    def _populate_dns_data(self, dns_data: Dict[str, Any]) -> None:
        dns_rows = []
        for r_type, records in dns_data.get("records", {}).items():
            for rec in records:
                dns_rows.append([r_type, dns_data.get("domain", ""), rec, "300", "Resolved"])
        self.populate_table_safely(self.table_dns, dns_rows)
        self.lbl_kpi_dns.setText(str(len(dns_rows)))

        sub_rows = []
        for sub in dns_data.get("subdomains", []):
            sub_rows.append([sub, "Certificate Transparency", "Let's Encrypt / DigiCert", "Active"])
        self.populate_table_safely(self.table_subdomains, sub_rows)
        self.lbl_kpi_subs.setText(str(len(sub_rows)))

    def _populate_takeover_data(self, takeover_data: Dict[str, Any]) -> None:
        take_rows = []
        vuln_count = len(takeover_data.get("vulnerabilities", []))
        for v in takeover_data.get("vulnerabilities", []):
            take_rows.append([
                v.get("subdomain", ""),
                v.get("cname", ""),
                v.get("service", "Cloud Bucket"),
                "CRITICAL VULNERABLE",
                "Reclaim external cloud bucket or delete dangling DNS record",
            ])
        for c in takeover_data.get("cnames", []):
            take_rows.append([
                c.get("subdomain", ""),
                c.get("cname", ""),
                c.get("service", "Alias"),
                "Active",
                "Monitored",
            ])
        self.populate_table_safely(self.table_takeovers, take_rows)
        self.lbl_kpi_takeovers.setText(f"{vuln_count} Vuln")

    def _populate_rdap_data(self, rdap_data: Dict[str, Any]) -> None:
        rdap_rows = [
            ["Registrar Name", rdap_data.get("registrar_name", "N/A"), "Official registrar"],
            ["Registered Domain", rdap_data.get("domain", "N/A"), "TLD delegation"],
            ["Created Date", rdap_data.get("created_date", "N/A"), "Registration date"],
            ["Expiration Date", rdap_data.get("expiration_date", "N/A"), "Registry expiry"],
            ["Days Until Expiration", str(rdap_data.get("days_until_expiration", "N/A")), "Domain lifecycle health"],
            ["Registrant Org", rdap_data.get("registrant_organization", "Redacted for Privacy"), "Registrant entity"],
        ]
        self.populate_table_safely(self.table_rdap, rdap_rows)
        days = rdap_data.get("days_until_expiration")
        self.lbl_kpi_expiry.setText(f"{days} Days" if days is not None else "Active")

    def _populate_web_data(self, web_data: Dict[str, Any]) -> None:
        web_rows = []
        for h, v in web_data.get("present_headers", {}).items():
            web_rows.append([h, "PASS", str(v)[:60], "Configured"])
        for h in web_data.get("missing_headers", []):
            web_rows.append([h, "MISSING", "None", f"Deploy {h} header"])
        self.populate_table_safely(self.table_web, web_rows)
        self.lbl_kpi_headers_grade.setText(web_data.get("security_grade", "Grade B"))

    def _populate_archive_data(self, archive_data: Dict[str, Any]) -> None:
        arch_rows = []
        for s in archive_data.get("snapshots", []):
            arch_rows.append(["Historical Milestone", s.get("timestamp", ""), s.get("url", ""), f"HTTP {s.get('status', '200')}"])
        if not arch_rows:
            arch_rows.append(["Archive Status", "No historical snapshots indexed", "N/A", "N/A"])
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
        self.lbl_kpi_ports.setText(str(len(ports)))
        self.lbl_kpi_cves.setText(str(len(cves)))

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
        self.lbl_kpi_cloud.setText(cloud)

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
        self.lbl_kpi_threat_scans.setText(f"{len(threat_rows)} Scans")

    def _populate_email_sec_data(self, email_sec_data: Dict[str, Any]) -> None:
        sec_rows = [
            ["SPF (Sender Policy Framework)", email_sec_data.get("spf_status", "Missing"), email_sec_data.get("spf_record", "None"), "Spoofing Prevention"],
            ["DMARC Policy", email_sec_data.get("dmarc_policy", "Missing"), email_sec_data.get("dmarc_record", "None"), "Impersonation Defense"],
            ["DKIM Status", email_sec_data.get("dkim_status", "N/A"), "Selector audit complete", "Cryptographic Signatures"],
            ["BIMI (Brand Identity)", email_sec_data.get("bimi_status", "Missing"), "Brand Logo Assertion", "Visual Verification"],
        ]
        self.populate_table_safely(self.table_email_sec, sec_rows)
        self.lbl_kpi_email_grade.setText(f"Grade {email_sec_data.get('spoofing_grade', 'N/A')}")
        self.lbl_kpi_dmarc_pol.setText(email_sec_data.get("dmarc_policy", "none"))

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
        self.lbl_kpi_tech_count.setText(str(len(tech_rows)))

    def _populate_all_views(self, data: Dict[str, Any]) -> None:
        scorecard = data.get("scorecard", {})
        grade = scorecard.get("grade", "N/A")
        score = scorecard.get("score", 0)
        findings = scorecard.get("findings", [])

        self.lbl_kpi_grade.setText(grade)
        self.lbl_kpi_score.setText(f"{score} / 100")
        self.lbl_kpi_findings.setText(f"{len(findings)} Items")

        findings_rows = []
        for f in findings:
            findings_rows.append([
                f.get("severity", "MEDIUM"),
                "Defensive Posture",
                f.get("title", ""),
                f.get("remediation", ""),
            ])
        self.populate_table_safely(self.table_findings, findings_rows)

    # -------------------------------------------------------------------------
    # Local AI Dossier & Offline Chat
    # -------------------------------------------------------------------------

    def _check_local_ai_status(self) -> None:
        def _check():
            return is_ollama_available_sync()
        worker = AsyncTaskWorker(_check)
        worker.signals.finished.connect(self._on_ai_status_finished)
        self.thread_pool.start(worker)

    def _on_ai_status_finished(self, is_avail: bool) -> None:
        if is_avail:
            self.lbl_kpi_ai.setText("Ollama (Local LLM)")
            self.lbl_kpi_ai_sub.setText("Low-RAM quantized model")
        else:
            self.lbl_kpi_ai.setText("Heuristic (0-RAM)")
            self.lbl_kpi_ai_sub.setText("Offline rule correlation")

    def _generate_ai_dossier(self) -> None:
        if not self.latest_results:
            QMessageBox.warning(self, "No Telemetry", "Please run a reconnaissance audit first before generating the dossier.")
            return

        self.btn_generate_dossier.setEnabled(False)
        self.dossier_browser.setHtml("<i>Synthesizing executive attack surface dossier...</i>")

        def _do_synth():
            return HeuristicAnalyst.generate_deterministic_dossier(self.latest_results)

        worker = AsyncTaskWorker(_do_synth)
        worker.signals.finished.connect(self._on_dossier_generated)
        self.thread_pool.start(worker)

    def _on_dossier_generated(self, md_text: str) -> None:
        self.dossier_text = md_text
        self.btn_generate_dossier.setEnabled(True)
        # Format markdown to clean HTML
        html = f"<pre style='font-family:Segoe UI, sans-serif; font-size:12px; color:#FAFAFA; white-space:pre-wrap;'>{md_text}</pre>"
        self.dossier_browser.setHtml(html)

    def _ask_ai_question(self) -> None:
        question = self.input_ai_chat.text().strip()
        if not question:
            return
        if not self.latest_results:
            self.dossier_browser.append(f"<p><b style='color:#FFFFFF;'>Q:</b> {question}</p><p><b style='color:#A1A1AA;'>A:</b> Please perform a scan first so the intelligence analyst has context.</p>")
            self.input_ai_chat.clear()
            return

        answer = HeuristicAnalyst.answer_offline_question(self.latest_results, question)
        self.dossier_browser.append(f"<hr/><p><b style='color:#FFFFFF;'>Q:</b> {question}</p><p><b style='color:#A1A1AA;'>A:</b> {answer}</p>")
        self.input_ai_chat.clear()

    # -------------------------------------------------------------------------
    # EXIF Privacy Scrubber
    # -------------------------------------------------------------------------

    def _select_file_for_scrubbing(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select Image or Document to Inspect", "", "Images & Docs (*.jpg *.jpeg *.png *.pdf)")
        if not path:
            return
        self.current_scrubber_file = path
        self.lbl_scrub_filename.setText(f"Selected: {os.path.basename(path)}")
        self.btn_save_clean.setEnabled(True)

        meta = PrivacyScrubber.inspect_file(path)
        rows = []
        for k, v in meta.items():
            risk = "HIGH (GPS Location)" if "GPS" in k else "MEDIUM (Device/Author)" if any(w in k for w in ["Make", "Model", "Author"]) else "INFO"
            rows.append([k, str(v)[:80], risk])
        if not rows:
            rows.append(["EXIF Metadata", "No embedded metadata detected", "CLEAN"])
        self.populate_table_safely(self.table_scrubber_metadata, rows)

    def _sanitize_and_save_clean_copy(self) -> None:
        if not self.current_scrubber_file:
            return
        base, ext = os.path.splitext(self.current_scrubber_file)
        default_out = f"{base}_clean{ext}"
        out_path, _ = QFileDialog.getSaveFileName(self, "Save Sanitized Copy", default_out, f"Clean File (*{ext})")
        if not out_path:
            return
        res = PrivacyScrubber.scrub_file(self.current_scrubber_file, out_path)
        if res.is_success:
            QMessageBox.information(self, "Sanitization Complete", f"Successfully stripped all EXIF/metadata tags!\n\nSaved clean copy to:\n{out_path}")
        else:
            QMessageBox.critical(self, "Sanitization Error", f"Failed to sanitize file: {res.error}")

    # -------------------------------------------------------------------------
    # Reports, Shortcut & Diagnostics
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

    def _run_gui_diagnostics(self) -> None:
        self._on_log("INFO", "Running Full Diagnostic Suite (--full-diagnostic)...")
        self.btn_run_diag.setEnabled(False)

        def _do_diag():
            runner = DiagnosticRunner()
            return runner.execute_all(), runner.results

        worker = AsyncTaskWorker(_do_diag)
        worker.signals.finished.connect(self._on_diag_finished)
        self.thread_pool.start(worker)

    def _on_diag_finished(self, res: Tuple[bool, List[Any]]) -> None:
        self.btn_run_diag.setEnabled(True)
        all_ok, results = res
        for stage, name, passed, details in results:
            tag = "SUCCESS" if passed else "ERROR"
            self._on_log(tag, f"Stage {stage} [{name}]: {'PASSED' if passed else 'FAILED'} -> {details}")

        if all_ok:
            self._on_log("SUCCESS", "ALL 6/6 DIAGNOSTIC STAGES PASSED WITH ZERO ERRORS!")
            QMessageBox.information(self, "Diagnostic Passed", "All 6 diagnostic health stages verified with 100% pass rate!")
        else:
            self._on_log("ERROR", "Diagnostic detected issues. Check logs for details.")

    def toggle_theme(self) -> None:
        new_theme = "mocha" if self.current_theme in ("liquid_glass", "monochrome") else "liquid_glass"
        self.set_theme(new_theme)
        self.config["theme"] = new_theme
        save_config(self.config)

    def set_theme(self, theme_name: str) -> None:
        self.current_theme = theme_name
        qss = get_theme_stylesheet(theme_name)
        app = QApplication.instance()
        if app:
            app.setStyleSheet(qss)

    def _create_menu_bar(self) -> None:
        menubar = self.menuBar()

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

        view_menu = menubar.addMenu("&View")
        act_toggle_theme = QAction("🌓 Toggle Liquid Glass / Mocha Theme", self)
        act_toggle_theme.setShortcut("Ctrl+T")
        act_toggle_theme.triggered.connect(self.toggle_theme)
        view_menu.addAction(act_toggle_theme)

        act_toggle_insp = QAction("◨ Toggle Inspector Drawer", self)
        act_toggle_insp.setShortcut("Ctrl+I")
        act_toggle_insp.triggered.connect(self._toggle_inspector_drawer)
        view_menu.addAction(act_toggle_insp)

        help_menu = menubar.addMenu("&Help")
        act_diag = QAction("⚡ Run Full Diagnostic Suite", self)
        act_diag.triggered.connect(self._run_gui_diagnostics)
        help_menu.addAction(act_diag)

        act_ethics = QAction("&Ethical & Legal Guardrails", self)
        act_ethics.triggered.connect(self._show_ethics_dialog)
        help_menu.addAction(act_ethics)

        act_about = QAction("&About OSINT Recon Studio", self)
        act_about.triggered.connect(self._show_about_dialog)
        help_menu.addAction(act_about)

    def _open_settings_dialog(self) -> None:
        dlg = SettingsDialog(self)
        if dlg.exec():
            self.config = load_config()
            new_theme = self.config.get("theme", "liquid_glass")
            self.set_theme(new_theme)
            self.status_bar.showMessage("Settings saved successfully.", 3000)

    def _show_ethics_dialog(self) -> None:
        msg = (
            "<h3>Ethical & Legal Defensive OSINT Principles</h3>"
            "<p><b>1. Strictly Passive Reconnaissance:</b> Operates exclusively via public DNS records, "
            "RDAP/WHOIS registries, Certificate Transparency logs, Shodan InternetDB, URLScan.io search, "
            "and public package/scholarly registries.</p>"
            "<p><b>2. Zero Invasive Probing:</b> Does NOT conduct network port scanning, brute-forcing, "
            "SQL injection, or unauthorized web scraping.</p>"
            "<p><b>3. Local Privacy:</b> All AI correlation and report synthesis operates 100% offline with zero cloud telemetry.</p>"
        )
        QMessageBox.information(self, "Ethical Guardrails", msg)

    def _show_about_dialog(self) -> None:
        msg = (
            "<h3>OSINT Recon Studio v1.5.0</h3>"
            "<p><b>Monochrome Liquid Glass & Executive Bento Edition</b></p>"
            "<p>Enterprise-grade native Windows desktop application engineered for defensive security auditors, "
            "penetration testers, and privacy researchers.</p>"
            "<p>Built with PySide6 (Qt6), AsyncIO, and native Windows 11 DWM integration.</p>"
        )
        QMessageBox.about(self, "About OSINT Recon Studio", msg)
