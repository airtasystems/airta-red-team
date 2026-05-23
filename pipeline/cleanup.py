"""Housekeeping helpers for cache and bytecode cleanup."""

from __future__ import annotations

import shutil
from pathlib import Path


def clear_project_pycache(root: Path) -> int:
    """Remove all ``__pycache__`` directories under ``root``. Returns count removed."""
    root = root.resolve()
    if not root.is_dir():
        return 0
    removed = 0
    for cache_dir in sorted(root.rglob("__pycache__"), key=lambda p: len(p.parts), reverse=True):
        if not cache_dir.is_dir():
            continue
        try:
            shutil.rmtree(cache_dir)
            removed += 1
        except OSError:
            continue
    return removed
