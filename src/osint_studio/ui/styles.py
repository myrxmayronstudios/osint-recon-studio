"""Modern dark stylesheet based on Catppuccin Mocha and Fluent design principles for PySide6.

Provides high-DPI crisp styling, subtle contrast borders, elegant tab bars,
card containers, smooth status bars, and legible data tables.
"""

CATPPUCCIN_MOCHA_QSS = """
/* Global Window & Base Widgets */
QMainWindow, QDialog {
    background-color: #1e1e2e;
    color: #cdd6f4;
    font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, "Inter", Roboto, sans-serif;
    font-size: 13px;
}

QWidget {
    background-color: transparent;
    color: #cdd6f4;
    font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, "Inter", Roboto, sans-serif;
    font-size: 13px;
    selection-background-color: #89b4fa;
    selection-color: #1e1e2e;
}

/* Tooltips */
QToolTip {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
}

/* Menu Bar & Menus */
QMenuBar {
    background-color: #181825;
    color: #cdd6f4;
    border-bottom: 1px solid #313244;
    padding: 2px 4px;
}

QMenuBar::item {
    background: transparent;
    padding: 4px 8px;
    border-radius: 4px;
}

QMenuBar::item:selected {
    background-color: #313244;
    color: #89b4fa;
}

QMenu {
    background-color: #25273a;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 4px 0;
}

QMenu::item {
    padding: 6px 24px 6px 12px;
}

QMenu::item:selected {
    background-color: #313244;
    color: #89b4fa;
}

QMenu::separator {
    height: 1px;
    background-color: #45475a;
    margin: 4px 8px;
}

/* Card Containers & GroupBoxes */
QGroupBox {
    background-color: #25273a;
    border: 1px solid #363a4f;
    border-radius: 8px;
    margin-top: 14px;
    padding-top: 16px;
    font-weight: 600;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 14px;
    padding: 0 6px;
    color: #89b4fa;
    background-color: #1e1e2e;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 700;
}

/* Form Controls & Inputs */
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background-color: #181825;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 7px 12px;
    color: #cdd6f4;
    selection-background-color: #89b4fa;
    selection-color: #1e1e2e;
    min-height: 20px;
}

QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
    border: 1px solid #89b4fa;
    background-color: #1e1e2e;
}

QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {
    background-color: #181825;
    color: #6c7086;
    border-color: #313244;
}

QComboBox::drop-down {
    border: none;
    width: 24px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #a6adc8;
    margin-right: 8px;
}

QComboBox QAbstractItemView {
    background-color: #25273a;
    border: 1px solid #45475a;
    border-radius: 6px;
    selection-background-color: #313244;
    selection-color: #89b4fa;
    padding: 4px;
}

/* Buttons */
QPushButton {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
    min-height: 18px;
}

QPushButton:hover {
    background-color: #45475a;
    border-color: #585b70;
    color: #ffffff;
}

QPushButton:pressed {
    background-color: #1e1e2e;
}

QPushButton:disabled {
    background-color: #181825;
    border-color: #313244;
    color: #585b70;
}

/* Primary Accent Button */
QPushButton#primaryButton {
    background-color: #89b4fa;
    color: #11111b;
    border: 1px solid #74c7ec;
    font-weight: 700;
}

QPushButton#primaryButton:hover {
    background-color: #b4befe;
    border-color: #89b4fa;
    color: #11111b;
}

QPushButton#primaryButton:pressed {
    background-color: #74c7ec;
}

QPushButton#primaryButton:disabled {
    background-color: #45475a;
    border-color: #313244;
    color: #6c7086;
}

/* Danger / Stop Button */
QPushButton#dangerButton {
    background-color: #f38ba8;
    color: #11111b;
    border: 1px solid #eba0ac;
    font-weight: 700;
}

QPushButton#dangerButton:hover {
    background-color: #eba0ac;
}

QPushButton#dangerButton:pressed {
    background-color: #f38ba8;
}

QPushButton#dangerButton:disabled {
    background-color: #45475a;
    border-color: #313244;
    color: #6c7086;
}

/* Checkboxes */
QCheckBox {
    spacing: 8px;
    color: #cdd6f4;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 1px solid #45475a;
    border-radius: 4px;
    background-color: #181825;
}

QCheckBox::indicator:hover {
    border-color: #89b4fa;
}

QCheckBox::indicator:checked {
    background-color: #89b4fa;
    border-color: #89b4fa;
    image: none;
}

/* Tab Widget & Bar */
QTabWidget::pane {
    background-color: #25273a;
    border: 1px solid #363a4f;
    border-radius: 8px;
    top: -1px;
    padding: 6px;
}

QTabBar::tab {
    background-color: #181825;
    color: #a6adc8;
    border: 1px solid #313244;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 9px 18px;
    margin-right: 3px;
    font-weight: 600;
}

QTabBar::tab:selected {
    background-color: #25273a;
    color: #89b4fa;
    border-color: #363a4f;
    border-bottom: 2px solid #89b4fa;
}

QTabBar::tab:hover:!selected {
    background-color: #313244;
    color: #cdd6f4;
}

/* Tables */
QTableWidget, QTableView {
    background-color: #181825;
    border: 1px solid #313244;
    border-radius: 6px;
    gridline-color: #25273a;
    color: #cdd6f4;
    selection-background-color: #313244;
    selection-color: #89b4fa;
}

QTableWidget::item {
    padding: 6px 8px;
    border-bottom: 1px solid #25273a;
}

QTableWidget::item:selected {
    background-color: #313244;
    color: #89b4fa;
}

QHeaderView::section {
    background-color: #25273a;
    color: #a6adc8;
    padding: 7px 10px;
    border: none;
    border-right: 1px solid #313244;
    border-bottom: 1px solid #363a4f;
    font-weight: 700;
    font-size: 12px;
}

/* Tree Views */
QTreeWidget, QTreeView {
    background-color: #181825;
    border: 1px solid #313244;
    border-radius: 6px;
    color: #cdd6f4;
    selection-background-color: #313244;
    selection-color: #89b4fa;
}

QTreeWidget::item {
    padding: 4px;
}

/* Plain Text & Code Viewer */
QPlainTextEdit, QTextEdit {
    background-color: #11111b;
    border: 1px solid #313244;
    border-radius: 6px;
    color: #cdd6f4;
    font-family: "Cascadia Code", "Consolas", "Courier New", monospace;
    font-size: 12px;
    padding: 8px;
}

/* Progress Bar */
QProgressBar {
    background-color: #181825;
    border: 1px solid #313244;
    border-radius: 6px;
    text-align: center;
    color: #cdd6f4;
    font-weight: 700;
    font-size: 11px;
    height: 18px;
}

QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #89b4fa, stop:1 #b4befe);
    border-radius: 5px;
}

/* Status Bar */
QStatusBar {
    background-color: #181825;
    color: #a6adc8;
    border-top: 1px solid #313244;
    font-size: 12px;
    padding: 4px;
}

/* Thin Custom Scrollbars */
QScrollBar:vertical {
    background-color: #181825;
    width: 10px;
    margin: 0;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background-color: #45475a;
    min-height: 25px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background-color: #585b70;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
    background: none;
}

QScrollBar:horizontal {
    background-color: #181825;
    height: 10px;
    margin: 0;
    border-radius: 5px;
}

QScrollBar::handle:horizontal {
    background-color: #45475a;
    min-width: 25px;
    border-radius: 5px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #585b70;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
    background: none;
}

/* Splitter */
QSplitter::handle {
    background-color: #313244;
}

QSplitter::handle:hover {
    background-color: #89b4fa;
}

/* Modern Left Navigation Sidebar */
QListWidget#navSidebar {
    background-color: #181825;
    border: 1px solid #313244;
    border-radius: 8px;
    padding: 6px;
    font-size: 13px;
    outline: none;
}

QListWidget#navSidebar::item {
    padding: 9px 12px;
    border-radius: 6px;
    color: #a6adc8;
    margin-bottom: 3px;
    font-weight: 500;
}

QListWidget#navSidebar::item:hover {
    background-color: #313244;
    color: #cdd6f4;
}

QListWidget#navSidebar::item:selected {
    background-color: #25273a;
    color: #89b4fa;
    border-left: 3px solid #89b4fa;
    font-weight: 700;
}
"""
