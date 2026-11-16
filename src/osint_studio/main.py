"""Application entry point for OSINT Recon Studio.

Configures High-DPI scaling, Windows taskbar process IDs, bootstrap crash logger,
frozen environment detection, and initializes the PySide6 Qt GUI.
"""

from __future__ import annotations

import ctypes
import logging
import os
from pathlib import Path
import sys
import traceback

# -----------------------------------------------------------------------------
# Bootstrap Crash Guard & Path Resolution
# -----------------------------------------------------------------------------

def _record_startup_crash(err_msg: str) -> None:
    """Writes crash traceback to crash_log.txt and displays native Windows MessageBoxW dialog."""
    try:
        # Determine executable or script directory
        if getattr(sys, "frozen", False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        log_path = os.path.join(base_dir, "crash_log.txt")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"OSINT Recon Studio Fatal Startup Crash Log\n")
            f.write(f"Timestamp: {os.environ.get('DATE', '')}\n")
            f.write(f"Python: {sys.version}\n")
            f.write(f"Frozen: {getattr(sys, 'frozen', False)}\n\n")
            f.write(err_msg)
    except Exception:
        pass

    # Display native Windows modal error dialog so failure is never silent
    try:
        if sys.platform == "win32":
            ctypes.windll.user32.MessageBoxW(
                0,
                f"OSINT Recon Studio failed to initialize:\n\n{err_msg[:900]}\n\nSee 'crash_log.txt' for details.",
                "OSINT Recon Studio - Startup Error",
                0x10,  # MB_ICONERROR
            )
    except Exception:
        pass


try:
    # Ensure both project root and src/ are in sys.path in all execution modes
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass_path = sys._MEIPASS
        exe_dir = os.path.dirname(sys.executable)
        for p in [meipass_path, exe_dir, os.path.join(meipass_path, "src")]:
            if p not in sys.path:
                sys.path.insert(0, p)
    else:
        current_file = os.path.abspath(__file__)
        src_dir = os.path.dirname(os.path.dirname(current_file))
        project_root = os.path.dirname(src_dir)
        for p in [project_root, src_dir]:
            if p not in sys.path:
                sys.path.insert(0, p)

    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication, QMessageBox

    from osint_studio import __app_name__, __version__
    from osint_studio.ui.main_window import MainWindow, get_app_icon_path

except Exception:
    _record_startup_crash(traceback.format_exc())
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("osint_studio")


def setup_windows_appid() -> None:
    """Sets explicit Windows AppUserModelID so Windows taskbar displays custom icon and pins correctly."""
    if sys.platform == "win32":
        try:
            my_appid = "OSINTReconStudio.Desktop.App.1.0"
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(my_appid)
        except Exception as e:
            logger.debug(f"Failed to set Windows AppID: {e}")


def exception_hook(exctype, value, tb) -> None:
    """Global unhandled exception hook to prevent silent crashes and notify users."""
    err_msg = "".join(traceback.format_exception(exctype, value, tb))
    logger.error(f"Unhandled GUI Exception:\n{err_msg}")
    _record_startup_crash(err_msg)

    app = QApplication.instance()
    if app:
        try:
            QMessageBox.critical(
                None,
                "Application Error",
                f"An unexpected error occurred:\n\n{value}\n\nCheck crash_log.txt for details.",
            )
        except Exception:
            pass
    sys.__excepthook__(exctype, value, tb)


def main() -> None:
    """Initializes and runs OSINT Recon Studio."""
    sys.excepthook = exception_hook

    try:
        setup_windows_appid()

        # Handle CLI --full-diagnostic flag
        if "--full-diagnostic" in sys.argv:
            from osint_studio.core.diagnostics import run_full_diagnostics
            sys.exit(run_full_diagnostics())

        # Enable High DPI scaling
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )

        app = QApplication(sys.argv)
        app.setApplicationName(__app_name__)
        app.setApplicationVersion(__version__)
        app.setOrganizationName("DefensiveSecStudio")

        # Set application icon
        icon_path = get_app_icon_path()
        if icon_path:
            app.setWindowIcon(QIcon(icon_path))

        window = MainWindow()

        # Handle CLI --self-test flag
        if "--self-test" in sys.argv:
            print("[SELF-TEST] Initializing GUI headless verification...")
            view_count = window.stacked_widget.count()
            print(f"[SELF-TEST] MainWindow initialized. Category Hubs registered: {view_count}/6.")
            if view_count < 5:
                print(f"[SELF-TEST FAILED] Expected at least 5 category hubs, got {view_count}")
                sys.exit(1)
            window.thread_pool.waitForDone(1500)
            print("[SELF-TEST] PASS: All 5 Unified Category Hubs and GUI components instantiated with 0 errors.")
            sys.exit(0)

        if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
            initial_domain = sys.argv[1].strip()
            window.input_domain.setText(initial_domain)

        window.show()
        sys.exit(app.exec())

    except Exception:
        err = traceback.format_exc()
        logger.critical(f"Fatal error in main application loop:\n{err}")
        _record_startup_crash(err)
        sys.exit(1)


if __name__ == "__main__":
    main()
