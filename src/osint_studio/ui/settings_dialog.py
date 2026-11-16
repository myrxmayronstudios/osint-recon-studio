"""Settings dialog for configuring network hygiene and optional free-tier API keys.

Persists settings locally to `~/.osint_studio_config.json`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

CONFIG_PATH = Path.home() / ".osint_studio_config.json"

DEFAULT_CONFIG: Dict[str, Any] = {
    "rate_limit_rps": 2.0,
    "timeout_sec": 10,
    "user_agent": "OSINTReconStudio-PassiveAudit/1.0",
    "theme": "liquid_glass",
    "github_token": "",
    "virustotal_api_key": "",
    "urlscan_api_key": "",
    "securitytrails_api_key": "",
    "shodan_api_key": "",
}


def load_config() -> Dict[str, Any]:
    """Loads configuration from user home directory or returns default settings."""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                merged = dict(DEFAULT_CONFIG)
                merged.update(data)
                return merged
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg: Dict[str, Any]) -> bool:
    """Saves configuration dict to ~/.osint_studio_config.json."""
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception:
        return False


class SettingsDialog(QDialog):
    """Configuration dialog for network limits and optional API keys."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("OSINT Recon Studio - Application Settings")
        self.resize(520, 480)
        self.setModal(True)

        self.config = load_config()
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        # Network Hygiene Group
        group_net = QGroupBox("Polite Network Hygiene")
        form_net = QFormLayout(group_net)

        self.spin_rate = QDoubleSpinBox()
        self.spin_rate.setRange(0.2, 10.0)
        self.spin_rate.setSingleStep(0.5)
        self.spin_rate.setValue(float(self.config.get("rate_limit_rps", 2.0)))
        self.spin_rate.setSuffix(" req/sec")
        form_net.addRow(QLabel("Rate Limit:"), self.spin_rate)

        self.spin_timeout = QSpinBox()
        self.spin_timeout.setRange(2, 60)
        self.spin_timeout.setValue(int(self.config.get("timeout_sec", 10)))
        self.spin_timeout.setSuffix(" seconds")
        form_net.addRow(QLabel("Request Timeout:"), self.spin_timeout)

        self.input_ua = QLineEdit()
        self.input_ua.setText(str(self.config.get("user_agent", DEFAULT_CONFIG["user_agent"])))
        form_net.addRow(QLabel("User-Agent Header:"), self.input_ua)

        layout.addWidget(group_net)

        # Appearance & GUI Theme Group
        group_theme = QGroupBox("GUI Visual Theme")
        form_theme = QFormLayout(group_theme)
        self.combo_theme = QComboBox()
        self.combo_theme.addItem("Monochrome Liquid Glass (Obsidian & Silver)", "liquid_glass")
        self.combo_theme.addItem("Catppuccin Mocha Dark (Classic)", "mocha")
        self.combo_theme.addItem("Tactical Monochrome (Pure Grayscale / OLED Black)", "monochrome")
        current_theme = self.config.get("theme", "liquid_glass").lower()
        if current_theme == "mocha":
            self.combo_theme.setCurrentIndex(1)
        elif current_theme in ("monochrome", "mono", "bw"):
            self.combo_theme.setCurrentIndex(2)
        else:
            self.combo_theme.setCurrentIndex(0)
        form_theme.addRow(QLabel("Interface Theme:"), self.combo_theme)
        layout.addWidget(group_theme)

        # Optional Free-Tier API Keys Group
        group_keys = QGroupBox("Optional Free-Tier API Keys & Tokens (Passive Lookups)")
        form_keys = QFormLayout(group_keys)

        self.input_github = QLineEdit()
        self.input_github.setEchoMode(QLineEdit.Password)
        self.input_github.setText(self.config.get("github_token", ""))
        self.input_github.setPlaceholderText("Optional GitHub token (raises rate limit from 60 to 5,000 req/hr)")
        form_keys.addRow(QLabel("GitHub Token:"), self.input_github)

        self.input_vt = QLineEdit()
        self.input_vt.setEchoMode(QLineEdit.Password)
        self.input_vt.setText(self.config.get("virustotal_api_key", ""))
        self.input_vt.setPlaceholderText("Optional free VirusTotal API key")
        form_keys.addRow(QLabel("VirusTotal Key:"), self.input_vt)

        self.input_urlscan = QLineEdit()
        self.input_urlscan.setEchoMode(QLineEdit.Password)
        self.input_urlscan.setText(self.config.get("urlscan_api_key", ""))
        self.input_urlscan.setPlaceholderText("Optional free URLScan.io API key")
        form_keys.addRow(QLabel("URLScan.io Key:"), self.input_urlscan)

        self.input_sectrails = QLineEdit()
        self.input_sectrails.setEchoMode(QLineEdit.Password)
        self.input_sectrails.setText(self.config.get("securitytrails_api_key", ""))
        self.input_sectrails.setPlaceholderText("Optional SecurityTrails API key")
        form_keys.addRow(QLabel("SecurityTrails Key:"), self.input_sectrails)

        self.input_shodan = QLineEdit()
        self.input_shodan.setEchoMode(QLineEdit.Password)
        self.input_shodan.setText(self.config.get("shodan_api_key", ""))
        self.input_shodan.setPlaceholderText("Optional Shodan Key (InternetDB is zero-key)")
        form_keys.addRow(QLabel("Shodan Key:"), self.input_shodan)

        layout.addWidget(group_keys)

        info_lbl = QLabel("Note: Shodan InternetDB and all primary engines operate with zero keys required.")
        info_lbl.setStyleSheet("color: #a6adc8; font-size: 11px;")
        layout.addWidget(info_lbl)

        layout.addStretch(1)

        # Buttons
        btn_box = QHBoxLayout()
        btn_box.addStretch(1)

        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_cancel)

        btn_save = QPushButton("Save Settings")
        btn_save.setObjectName("primaryButton")
        btn_save.clicked.connect(self._save_settings)
        btn_box.addWidget(btn_save)

        layout.addLayout(btn_box)

    def _save_settings(self) -> None:
        self.config["rate_limit_rps"] = self.spin_rate.value()
        self.config["timeout_sec"] = self.spin_timeout.value()
        self.config["user_agent"] = self.input_ua.text().strip() or DEFAULT_CONFIG["user_agent"]
        self.config["theme"] = self.combo_theme.currentData()
        self.config["github_token"] = self.input_github.text().strip()
        self.config["virustotal_api_key"] = self.input_vt.text().strip()
        self.config["urlscan_api_key"] = self.input_urlscan.text().strip()
        self.config["securitytrails_api_key"] = self.input_sectrails.text().strip()
        self.config["shodan_api_key"] = self.input_shodan.text().strip()

        if save_config(self.config):
            self.accept()
        else:
            QMessageBox.critical(self, "Error", "Failed to write configuration file.")
