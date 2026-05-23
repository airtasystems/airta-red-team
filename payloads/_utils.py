"""Shared helpers for payload generators."""
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def safe_filename(prefix: str = "payload", extension: str = "bin") -> str:
    """Return a safe filename: prefix_timestamp_random.extension (alphanumeric + underscore)."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    slug = re.sub(r"[^\w\-]", "", prefix)[:40] or "payload"
    ext = re.sub(r"[^\w\.]", "", extension).lstrip(".") or "bin"
    return f"{slug}_{ts}.{ext}"


def resolve_output_path(
    filename: Optional[str],
    subdir: str,
    extension: str,
    base_dir: Path,
) -> Path:
    """Resolve output file path: base_dir / subdir / filename (or safe default)."""
    out = base_dir / subdir
    out.mkdir(parents=True, exist_ok=True)
    if filename and filename.strip():
        name = Path(filename).name
        name = re.sub(r"[^\w\.\-]", "_", name) or safe_filename("file", extension)
        if not name.endswith(f".{extension}"):
            name = f"{name}.{extension}"
    else:
        name = safe_filename("payload", extension)
    return (out / name).resolve()
