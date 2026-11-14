"""Dedicated root launcher entry point for OSINT Recon Studio.

Ensures sys.path includes src/ directory in both developer mode and frozen
PyInstaller environments, bootstraps crash logging, and calls osint_studio.main.main().
"""

from __future__ import annotations

import os
from pathlib import Path
import sys

# Configure sys.path before any local imports
root_dir = Path(__file__).resolve().parent
src_dir = root_dir / "src"

for p in [str(root_dir), str(src_dir)]:
    if p not in sys.path:
        sys.path.insert(0, p)

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    meipass_src = Path(sys._MEIPASS) / "src"
    if str(meipass_src) not in sys.path:
        sys.path.insert(0, str(meipass_src))

from osint_studio.main import main

if __name__ == "__main__":
    main()
