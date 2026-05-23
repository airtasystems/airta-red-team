"""
Payloads output directory from environment. Same pattern as app.config.
Project root = parent of payloads package. No Flask coupling.
"""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None  # type: ignore

# AIRTA repo root (parent of payloads package)
_ROOT = Path(__file__).resolve().parent.parent
_ENV_PATH = _ROOT / ".env"


def _ensure_env_loaded() -> None:
    if load_dotenv and _ENV_PATH.exists():
        load_dotenv(_ENV_PATH)


def _is_docker() -> bool:
    """True when running inside a Docker container (payloads should stay in container)."""
    return Path("/.dockerenv").exists()


def get_output_dir() -> Path:
    """
    Directory for generated payload assets.
    - In Docker: default is /tmp/payloads/generate (container-local, not on host mount).
    - Local: default is project_root / payloads / generate.
    Override with PAYLOADS_OUTPUT_DIR (absolute or relative to project root).
    Creates the directory if it does not exist.
    """
    _ensure_env_loaded()
    raw = os.getenv("PAYLOADS_OUTPUT_DIR", "").strip()
    if raw:
        p = Path(raw)
        if not p.is_absolute():
            p = _ROOT / p
    else:
        if _is_docker():
            p = Path("/tmp/payloads/generate")
        else:
            p = _ROOT / "payloads" / "generate"
    p.mkdir(parents=True, exist_ok=True)
    return p.resolve()


def get_project_root() -> Path:
    """Project root (parent of payloads package)."""
    return _ROOT
