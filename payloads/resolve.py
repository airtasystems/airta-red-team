"""Resolve suite payload specs to on-disk artifact paths."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from payloads.generators import generate_payload


def _suite_dir(suite_path: Path | str | None) -> Path | None:
    if not suite_path:
        return None
    p = Path(suite_path)
    return p.parent if p.is_file() else p


def resolve_test_artifact(
    entry: dict[str, Any],
    *,
    suite_path: Path | str | None = None,
    out_dir: Path | str | None = None,
) -> tuple[Path | None, str, bool]:
    """
    Resolve a test case entry to an artifact file.

    Returns (path, vector_type, upload_ok).
    upload_ok is True when a file path was resolved or no payload was required.
    """
    vector_type = entry.get("vector_type") or "text_direct"
    payload = entry.get("payload")
    if not payload:
        return None, vector_type, True

    if isinstance(payload, str):
        p = Path(payload)
        if not p.is_absolute() and suite_path:
            base = _suite_dir(suite_path)
            if base:
                candidate = base / p
                if candidate.is_file():
                    return candidate.resolve(), vector_type, True
        if p.is_file():
            return p.resolve(), vector_type, True
        return None, vector_type, False

    if not isinstance(payload, dict):
        return None, vector_type, False

    if payload.get("path"):
        rel = Path(str(payload["path"]))
        if not rel.is_absolute() and suite_path:
            base = _suite_dir(suite_path)
            if base and (base / rel).is_file():
                return (base / rel).resolve(), vector_type, True
        if rel.is_file():
            return rel.resolve(), vector_type, True
        # Stale path: fall through to generator+args when available.

    generator = payload.get("generator")
    if not generator:
        return None, vector_type, False

    args = payload.get("args") if isinstance(payload.get("args"), dict) else {}
    if out_dir is None:
        run_id = entry.get("id") or uuid.uuid4().hex[:8]
        if suite_path:
            base = _suite_dir(suite_path)
            if base:
                out_dir = base / "artifacts" / str(run_id)
            else:
                out_dir = Path(__file__).resolve().parent / "generate" / run_id
        else:
            out_dir = Path(__file__).resolve().parent / "generate" / run_id
    try:
        path = generate_payload(generator, args, out_dir=Path(out_dir))
        return path.resolve(), vector_type, True
    except Exception:
        return None, vector_type, False


def load_suite_test_cases(suite_path: Path | str) -> list[dict[str, Any]]:
    """Load flat test case dicts from a suite JSON file."""
    path = Path(suite_path)
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    out: list[dict[str, Any]] = []
    cats = raw.get("categories") or raw.get("mandates") or []
    if isinstance(cats, list):
        for cat in cats:
            if not isinstance(cat, dict):
                continue
            cat_name = cat.get("name", cat.get("mandate", ""))
            for p in cat.get("prompts") or []:
                if not isinstance(p, dict):
                    continue
                if isinstance(p.get("prompts"), list):
                    continue
                prompt = p.get("prompt", "")
                if not isinstance(prompt, str) or not prompt.strip():
                    continue
                out.append({
                    "id": p.get("id", ""),
                    "category": cat_name,
                    "description": p.get("description", ""),
                    "prompt": prompt.strip(),
                    "vector_type": p.get("vector_type", "text_direct"),
                    "payload": p.get("payload"),
                    "context_mode": p.get("context_mode", "upload"),
                })
    elif isinstance(raw, list):
        for i, item in enumerate(raw):
            if isinstance(item, str) and item.strip():
                out.append({"id": f"entry-{i+1}", "prompt": item.strip(), "vector_type": "text_direct"})
            elif isinstance(item, dict) and item.get("prompt"):
                out.append(item)
    return out
