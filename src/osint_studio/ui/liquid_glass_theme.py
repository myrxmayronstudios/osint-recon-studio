"""Monochrome Liquid Glass Design System and Native Windows 11 DWM Integration.

Provides an executive translucent obsidian & brushed silver theme for OSINT Recon Studio,
leveraging Windows 11 Desktop Window Manager (DWM) Acrylic and Mica backdrops with
specular hairline borders, frosted cards, and crisp monochrome typography.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QGraphicsDropShadowEffect, QWidget

logger = logging.getLogger(__name__)


def apply_windows_liquid_glass(hwnd: int) -> bool:
    """Applies native Windows 11 DWM Immersive Dark Mode and Acrylic/Mica backdrop.

    Falls back cleanly and silently on Windows 10 or non-Windows platforms.
    """
    if sys.platform != "win32":
        return False

    try:
        import ctypes
        from ctypes import byref, c_int, sizeof

        dwmapi = ctypes.windll.dwmapi

        # 1. DWMWA_USE_IMMERSIVE_DARK_MODE (Attribute 20)
        dark_mode = c_int(1)
        dwmapi.DwmSetWindowAttribute(hwnd, 20, byref(dark_mode), sizeof(dark_mode))

        # 2. DWMWA_SYSTEMBACKDROP_TYPE (Attribute 38)
        # 0 = Auto, 1 = None, 2 = Mica, 3 = Acrylic (Transient), 4 = Tabbed (Mica Alt)
        backdrop_acrylic = c_int(3)
        res = dwmapi.DwmSetWindowAttribute(hwnd, 38, byref(backdrop_acrylic), sizeof(backdrop_acrylic))

        if res != 0:
            # Fallback to Mica (Value 2)
            backdrop_mica = c_int(2)
            res_mica = dwmapi.DwmSetWindowAttribute(hwnd, 38, byref(backdrop_mica), sizeof(backdrop_mica))
            if res_mica != 0:
                # Fallback to Windows 11 build 22000 legacy Mica attribute (1029)
                mica_legacy = c_int(1)
                dwmapi.DwmSetWindowAttribute(hwnd, 1029, byref(mica_legacy), sizeof(mica_legacy))

        return True
    except Exception as exc:
        logger.debug("DWM Liquid Glass backdrop application skipped: %s", exc)
        return False


def create_glass_shadow(
    parent: Optional[QWidget] = None,
    blur: float = 24.0,
    offset_y: float = 4.0,
    alpha: int = 70,
) -> QGraphicsDropShadowEffect:
    """Creates a high-performance, subtle ambient drop shadow for elevated glass cards."""
    shadow = QGraphicsDropShadowEffect(parent)
    shadow.setBlurRadius(blur)
    shadow.setOffset(0, offset_y)
    shadow.setColor(QColor(0, 0, 0, alpha))
    return shadow


MONOCHROME_LIQUID_GLASS_QSS = """
/* =========================================================================
   MONOCHROME LIQUID GLASS DESIGN SYSTEM (Qt6 / PySide6)
   Strictly Obsidian, Smoked Glass, Platinum & Pure White. Zero Neon Slices.
   ========================================================================= */

/* Root Window & Canvas */
QMainWindow, QDialog {
    background-color: rgba(7, 7, 9, 215);
    color: #FAFAFA;
    font-family: "Segoe UI Variable Display", "Segoe UI", -apple-system, BlinkMacSystemFont, "Inter", Roboto, sans-serif;
    font-size: 13px;
}

QWidget {
    background-color: transparent;
    color: #FAFAFA;
    font-family: "Segoe UI Variable Display", "Segoe UI", -apple-system, BlinkMacSystemFont, "Inter", Roboto, sans-serif;
    font-size: 13px;
    selection-background-color: rgba(255, 255, 255, 0.22);
    selection-color: #FFFFFF;
}

/* Tooltips */
QToolTip {
    background-color: #121217;
    color: #FAFAFA;
    border: 1px solid rgba(255, 255, 255, 0.20);
    border-radius: 8px;
    padding: 6px 10px;
    font-size: 12px;
}

/* Glass Cards & Containers */
QFrame#GlassCard, .glass-card {
    background-color: rgba(255, 255, 255, 0.045);
    border: 1px solid rgba(255, 255, 255, 0.14);
    border-radius: 14px;
}

QFrame#ElevatedGlassCard, .glass-card-elevated {
    background-color: rgba(255, 255, 255, 0.075);
    border: 1px solid rgba(255, 255, 255, 0.25);
    border-radius: 14px;
}

QGroupBox {
    background-color: rgba(255, 255, 255, 0.040);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 12px;
    margin-top: 14px;
    padding-top: 16px;
    font-weight: 600;
    color: #FAFAFA;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 14px;
    padding: 0 8px;
    color: #FAFAFA;
    background-color: transparent;
    font-size: 11px;
    letter-spacing: 1px;
    font-weight: 700;
}

/* Top Floating Command Bar */
QFrame#TopCommandBar {
    background-color: rgba(255, 255, 255, 0.045);
    border-bottom: 1px solid rgba(255, 255, 255, 0.12);
}

/* Left Navigation Rail */
QFrame#LeftNavRail {
    background-color: rgba(255, 255, 255, 0.030);
    border-right: 1px solid rgba(255, 255, 255, 0.10);
}

/* Navigation Buttons */
QPushButton.nav-item {
    background-color: transparent;
    color: #A1A1AA;
    border: none;
    border-radius: 8px;
    padding: 10px 14px;
    text-align: left;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.5px;
}

QPushButton.nav-item:hover {
    background-color: rgba(255, 255, 255, 0.065);
    color: #FFFFFF;
}

QPushButton.nav-item:checked, QPushButton.nav-item-active {
    background-color: rgba(255, 255, 255, 0.12);
    color: #FFFFFF;
    border-left: 3px solid #FAFAFA;
    font-weight: 700;
}

/* Primary Monochrome Action Buttons */
QPushButton#PrimaryGlassBtn, QPushButton#primaryButton {
    background-color: #F4F4F6;
    color: #09090B;
    border: 1px solid #FFFFFF;
    border-radius: 8px;
    padding: 8px 18px;
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 0.4px;
}

QPushButton#PrimaryGlassBtn:hover, QPushButton#primaryButton:hover {
    background-color: #FFFFFF;
    color: #000000;
}

QPushButton#PrimaryGlassBtn:pressed, QPushButton#primaryButton:pressed {
    background-color: #D4D4D8;
    color: #09090B;
}

QPushButton#PrimaryGlassBtn:disabled, QPushButton#primaryButton:disabled {
    background-color: rgba(255, 255, 255, 0.10);
    color: #71717A;
    border: 1px solid rgba(255, 255, 255, 0.08);
}

/* Secondary Glass Buttons */
QPushButton#SecondaryGlassBtn, QPushButton#secondaryButton, QPushButton {
    background-color: rgba(255, 255, 255, 0.055);
    color: #FAFAFA;
    border: 1px solid rgba(255, 255, 255, 0.16);
    border-radius: 8px;
    padding: 7px 14px;
    font-weight: 600;
    font-size: 12px;
}

QPushButton#SecondaryGlassBtn:hover, QPushButton#secondaryButton:hover, QPushButton:hover {
    background-color: rgba(255, 255, 255, 0.10);
    border: 1px solid rgba(255, 255, 255, 0.30);
    color: #FFFFFF;
}

QPushButton#SecondaryGlassBtn:pressed, QPushButton#secondaryButton:pressed, QPushButton:pressed {
    background-color: rgba(255, 255, 255, 0.16);
    border: 1px solid rgba(255, 255, 255, 0.38);
}

/* Danger / Stop Buttons */
QPushButton#DangerGlassBtn, QPushButton#dangerButton {
    background-color: rgba(255, 255, 255, 0.08);
    color: #FAFAFA;
    border: 1px solid rgba(255, 255, 255, 0.28);
    border-radius: 8px;
    padding: 7px 14px;
    font-weight: 700;
}

QPushButton#DangerGlassBtn:hover, QPushButton#dangerButton:hover {
    background-color: #FFFFFF;
    color: #000000;
    border: 1px solid #FFFFFF;
}

/* Input Fields & Search Bars */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: rgba(255, 255, 255, 0.05);
    color: #FAFAFA;
    border: 1px solid rgba(255, 255, 255, 0.16);
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 13px;
}

QLineEdit:hover, QTextEdit:hover, QPlainTextEdit:hover {
    border: 1px solid rgba(255, 255, 255, 0.30);
    background-color: rgba(255, 255, 255, 0.065);
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border: 1px solid rgba(255, 255, 255, 0.50);
    background-color: rgba(255, 255, 255, 0.08);
}

/* Hairline Progress Bar */
QProgressBar#HairlineProgressBar {
    background-color: rgba(255, 255, 255, 0.08);
    border: none;
    max-height: 2px;
    min-height: 2px;
    text-align: center;
}

QProgressBar#HairlineProgressBar::chunk {
    background-color: #FFFFFF;
}

QProgressBar {
    background-color: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.14);
    border-radius: 6px;
    text-align: center;
    color: #FAFAFA;
    font-size: 11px;
    font-weight: 600;
    height: 16px;
}

QProgressBar::chunk {
    background-color: rgba(255, 255, 255, 0.35);
    border-radius: 5px;
}

/* Translucent Data Tables */
QTableWidget, QTableView {
    background-color: rgba(255, 255, 255, 0.02);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 10px;
    gridline-color: rgba(255, 255, 255, 0.06);
    color: #FAFAFA;
    font-size: 12px;
    alternate-background-color: rgba(255, 255, 255, 0.035);
}

QTableWidget::item, QTableView::item {
    padding: 6px 10px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
}

QTableWidget::item:selected, QTableView::item:selected {
    background-color: rgba(255, 255, 255, 0.16);
    color: #FFFFFF;
}

QHeaderView::section {
    background-color: rgba(20, 20, 25, 0.85);
    color: #A1A1AA;
    border: none;
    border-bottom: 1px solid rgba(255, 255, 255, 0.14);
    border-right: 1px solid rgba(255, 255, 255, 0.05);
    padding: 8px 10px;
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.8px;
    text-transform: uppercase;
}

QHeaderView::section:hover {
    background-color: rgba(35, 35, 42, 0.90);
    color: #FFFFFF;
}

/* Splitters */
QSplitter::handle {
    background-color: rgba(255, 255, 255, 0.08);
}

QSplitter::handle:horizontal {
    width: 2px;
}

QSplitter::handle:vertical {
    height: 2px;
}

QSplitter::handle:hover {
    background-color: rgba(255, 255, 255, 0.30);
}

/* ScrollBars */
QScrollBar:vertical {
    background: transparent;
    width: 8px;
    margin: 0;
}

QScrollBar::handle:vertical {
    background-color: rgba(255, 255, 255, 0.18);
    border-radius: 4px;
    min-height: 24px;
}

QScrollBar::handle:vertical:hover {
    background-color: rgba(255, 255, 255, 0.38);
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: transparent;
    height: 0px;
}

QScrollBar:horizontal {
    background: transparent;
    height: 8px;
    margin: 0;
}

QScrollBar::handle:horizontal {
    background-color: rgba(255, 255, 255, 0.18);
    border-radius: 4px;
    min-width: 24px;
}

QScrollBar::handle:horizontal:hover {
    background-color: rgba(255, 255, 255, 0.38);
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal,
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
    background: transparent;
    width: 0px;
}

/* Tab Widgets */
QTabWidget::pane {
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 10px;
    background-color: rgba(255, 255, 255, 0.03);
}

QTabBar::tab {
    background-color: transparent;
    color: #A1A1AA;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 8px 16px;
    font-size: 12px;
    font-weight: 600;
}

QTabBar::tab:hover {
    color: #FFFFFF;
    background-color: rgba(255, 255, 255, 0.05);
}

QTabBar::tab:selected {
    color: #FFFFFF;
    border-bottom: 2px solid #FAFAFA;
    font-weight: 700;
}

/* CheckBoxes & RadioButtons */
QCheckBox, QRadioButton {
    color: #FAFAFA;
    font-size: 12px;
    spacing: 8px;
}

QCheckBox::indicator, QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid rgba(255, 255, 255, 0.25);
    background-color: rgba(255, 255, 255, 0.04);
    border-radius: 4px;
}

QRadioButton::indicator {
    border-radius: 8px;
}

QCheckBox::indicator:hover, QRadioButton::indicator:hover {
    border: 1px solid rgba(255, 255, 255, 0.45);
}

QCheckBox::indicator:checked, QRadioButton::indicator:checked {
    background-color: #FAFAFA;
    border: 1px solid #FFFFFF;
}

/* ComboBox */
QComboBox {
    background-color: rgba(255, 255, 255, 0.05);
    color: #FAFAFA;
    border: 1px solid rgba(255, 255, 255, 0.16);
    border-radius: 8px;
    padding: 6px 12px;
    font-size: 12px;
}

QComboBox:hover {
    border: 1px solid rgba(255, 255, 255, 0.30);
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox QAbstractItemView {
    background-color: #121217;
    color: #FAFAFA;
    border: 1px solid rgba(255, 255, 255, 0.20);
    border-radius: 8px;
    selection-background-color: rgba(255, 255, 255, 0.15);
    selection-color: #FFFFFF;
}

/* Menus & Status Bar */
QMenuBar {
    background-color: rgba(10, 10, 14, 0.90);
    color: #FAFAFA;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

QMenuBar::item:selected {
    background-color: rgba(255, 255, 255, 0.10);
    color: #FFFFFF;
}

QMenu {
    background-color: #121217;
    border: 1px solid rgba(255, 255, 255, 0.18);
    border-radius: 8px;
    padding: 4px 0;
}

QMenu::item {
    padding: 6px 20px 6px 12px;
    color: #FAFAFA;
}

QMenu::item:selected {
    background-color: rgba(255, 255, 255, 0.12);
    color: #FFFFFF;
}

QStatusBar {
    background-color: rgba(10, 10, 14, 0.90);
    color: #A1A1AA;
    border-top: 1px solid rgba(255, 255, 255, 0.08);
    font-size: 11px;
}
"""
