#!/usr/bin/env python3
"""Bootstrap venv, install dependencies, and launch the AIRTA web UI."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / "airta-venv"
REQUIREMENTS = ROOT / "requirements.txt"
WEB_APP = ROOT / "web" / "app.py"


def venv_python() -> Path:
    if sys.platform == "win32":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def ensure_venv() -> bool:
    """Create the virtual environment if missing. Returns True when newly created."""
    if VENV_DIR.exists():
        return False
    print(f"Creating virtual environment at {VENV_DIR} ...")
    subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])
    return True


def install_requirements(python: Path) -> None:
    if not REQUIREMENTS.is_file():
        raise SystemExit(f"Missing requirements file: {REQUIREMENTS}")
    print("Installing requirements ...")
    subprocess.check_call([str(python), "-m", "pip", "install", "-U", "pip"])
    subprocess.check_call([str(python), "-m", "pip", "install", "-r", str(REQUIREMENTS)])


def install_playwright_browsers(python: Path) -> None:
    print("Installing Playwright Chromium browser ...")
    subprocess.check_call([str(python), "-m", "playwright", "install", "chromium"])


def launch_ui(python: Path) -> None:
    os.chdir(ROOT)
    os.execv(str(python), [str(python), str(WEB_APP)])


def main() -> None:
    created = ensure_venv()
    python = venv_python()
    if not python.is_file():
        raise SystemExit(f"Virtual environment python not found: {python}")

    install_requirements(python)
    if created:
        install_playwright_browsers(python)

    print("Starting AIRTA web UI ...")
    launch_ui(python)


if __name__ == "__main__":
    main()
