"""
Convert browser-bot run logs into attack_log.json for security-assess.

browser-bot run logs have shape:
  Single: { site, component, timestamp, mode: "single", entries: [{ input, response }] }
  Multi:  { site, component, timestamp, mode: "multi",  batches: [{ turns: [{ input, response }] }] }

Generated suite JSON has shape:
  { playbook, playbook_id, categories: [{ name, prompts: [...] }] }
"""
import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

from pipeline.injection_signals import (
    response_canary_compliance_leak,
    response_contains_injection_canary,
)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _suite_categories(suite: dict) -> list:
    cats = suite.get("categories")
    if isinstance(cats, list):
        return cats
    return suite.get("mandates") or []


def _category_name(cat: dict) -> str:
    return cat.get("name", cat.get("mandate", ""))


def _detect_suite_mode(suite: dict) -> str:
    for m in _suite_categories(suite):
        for p in m.get("prompts") or []:
            if isinstance(p.get("prompts"), list):
                return "multi"
            if isinstance(p.get("prompt"), str):
                return "single"
    return "single"


def _build_single_index(suite: dict) -> list[dict]:
    out: list[dict] = []
    for m in _suite_categories(suite):
        cat_name = _category_name(m)
        for p in m.get("prompts") or []:
            row = {
                "id": p.get("id", ""),
                "category": cat_name,
                "description": p.get("description", ""),
                "prompt": p.get("prompt", ""),
            }
            if p.get("vector_type"):
                row["vector_type"] = p["vector_type"]
            if p.get("payload"):
                row["payload"] = p["payload"]
            if p.get("context_mode"):
                row["context_mode"] = p["context_mode"]
            if p.get("control_type"):
                row["control_type"] = p["control_type"]
            out.append(row)
    return out


def _build_multi_index(suite: dict) -> list[dict]:
    out: list[dict] = []
    for m in _suite_categories(suite):
        cat_name = _category_name(m)
        for p in m.get("prompts") or []:
            out.append({
                "id": p.get("id", ""),
                "category": cat_name,
                "description": p.get("description", ""),
                "prompts": p.get("prompts", []),
            })
    return out


@lru_cache(maxsize=1)
def _ui_prompt_wrapper_parts() -> tuple[str | None, str | None]:
    try:
        root = Path(__file__).resolve().parent.parent
        bb = root / "browser-bot"
        if bb.is_dir() and str(bb) not in sys.path:
            sys.path.insert(0, str(bb))
        from browser_bot.config import UI_PROMPT_PREFIX, UI_PROMPT_PREFIX_SEPARATOR

        p = UI_PROMPT_PREFIX or ""
        sep = UI_PROMPT_PREFIX_SEPARATOR or ""
        if not p:
            return (None, None)
        head = f"{p}{sep}"
        tail = f"{sep}{p}"
        return (head, tail)
    except Exception:
        return (None, None)


def _strip_ui_prefix(submitted: str) -> str:
    s = submitted.strip()
    head, tail = _ui_prompt_wrapper_parts()
    if tail and s.endswith(tail):
        s = s[: -len(tail)].rstrip()
    elif head and s.startswith(head):
        s = s[len(head) :].strip()
    elif s.startswith("["):
        bracket_end = s.find("]")
        if bracket_end != -1:
            s = s[bracket_end + 1 :].lstrip("\n")
    return s.strip()


def _prompt_matches(original: str, submitted_body: str) -> bool:
    orig = original.strip()
    sub = submitted_body.strip()
    if not sub:
        return False
    if orig == sub:
        return True
    if orig.startswith(sub) and len(sub) >= min(80, len(orig)):
        return True
    return False


def _infer_playbook_id(suite: dict) -> str:
    pid = (suite.get("playbook_id") or "").strip()
    if pid:
        return pid
    playbook = (suite.get("playbook") or suite.get("framework") or "").strip()
    if not playbook:
        return ""
    lower = playbook.lower()
    keyword_map = (
        ("multimodal", "multimodal_injection"),
        ("jailbreak", "jailbreak_core"),
        ("owasp agent", "owasp_agent"),
        ("owasp llm", "owasp_llm"),
        ("mitre", "mitre_attack"),
    )
    for needle, stem in keyword_map:
        if needle in lower:
            return stem
    for stem in ("owasp_llm", "owasp_agent", "mitre_attack", "jailbreak_core", "multimodal_injection"):
        if stem.replace("_", " ") in lower or stem in lower:
            return stem
    return ""


def _suite_meta(suite: dict) -> dict:
    return {
        "playbook": suite.get("playbook", suite.get("framework", "")),
        "playbook_id": _infer_playbook_id(suite),
    }


def _convert_single(run_log: dict, suite: dict, suite_path: str) -> dict:
    entries = run_log.get("entries") or []
    index = _build_single_index(suite)
    meta = _suite_meta(suite)
    results: list[dict] = []

    for i, entry in enumerate(entries):
        submitted = entry.get("input", "")
        response = entry.get("response")
        body = _strip_ui_prefix(submitted)

        matched: dict[str, Any] | None = None
        if i < len(index) and _prompt_matches(index[i]["prompt"], body):
            matched = index[i]
        if matched is None:
            for idx_entry in index:
                if _prompt_matches(idx_entry["prompt"], body):
                    matched = idx_entry
                    break

        vector_type = (
            entry.get("vector_type")
            or (matched.get("vector_type") if matched else None)
            or "text_direct"
        )
        response_text = response or ""
        canary_echo = response_contains_injection_canary(response_text)
        canary_leak = response_canary_compliance_leak(response_text)
        row = {
            "id": matched["id"] if matched else f"entry-{i + 1}",
            "category": matched["category"] if matched else "",
            "description": matched["description"] if matched else "",
            "prompt": matched["prompt"] if matched else submitted,
            "response": response_text,
            "ok": bool(response_text and str(response_text).strip()),
            "vector_type": vector_type,
        }
        if canary_echo:
            row["injection_canary_echo"] = True
        if canary_leak:
            row["injection_canary_leak"] = True
            row["attack_suspected"] = True
        if matched and matched.get("control_type"):
            row["control_type"] = matched["control_type"]
        if entry.get("artifact_path"):
            row["artifact_path"] = entry["artifact_path"]
        if "upload_ok" in entry:
            row["upload_ok"] = entry["upload_ok"]
        if entry.get("extracted_text_preview"):
            row["extracted_text_preview"] = entry["extracted_text_preview"]
        elif matched:
            from pipeline.artifact_preview import preview_from_suite_prompt

            preview = preview_from_suite_prompt(matched)
            if preview:
                row["extracted_text_preview"] = preview
        results.append(row)

    return {**meta, "source_file": suite_path, "results": results}


def _convert_multi(run_log: dict, suite: dict, suite_path: str) -> dict:
    batches = run_log.get("batches") or []
    index = _build_multi_index(suite)
    meta = _suite_meta(suite)
    results: list[dict] = []

    for batch_i, batch in enumerate(batches):
        turns = batch.get("turns") or []
        matched: dict[str, Any] | None = None
        if batch_i < len(index):
            matched = index[batch_i]
        if not matched and turns:
            first_body = _strip_ui_prefix(turns[0].get("input", ""))
            for idx_entry in index:
                if idx_entry["prompts"] and _prompt_matches(idx_entry["prompts"][0], first_body):
                    matched = idx_entry
                    break

        for turn_i, turn in enumerate(turns):
            response = turn.get("response")
            original_prompt = ""
            if matched and turn_i < len(matched.get("prompts", [])):
                original_prompt = matched["prompts"][turn_i]
            else:
                original_prompt = turn.get("input", "")

            results.append({
                "id": f"{matched['id']}-t{turn_i + 1}" if matched else f"batch-{batch_i + 1}-t{turn_i + 1}",
                "category": matched["category"] if matched else "",
                "description": matched["description"] if matched else "",
                "prompt": original_prompt,
                "response": response or "",
                "ok": bool(response and str(response).strip()),
            })

    return {**meta, "source_file": suite_path, "results": results}


def convert_run_log(
    run_log_path: Path,
    suite_path: Path,
    output_path: Path | None = None,
) -> Path:
    """Convert run log + suite into attack_log.json for security-assess."""
    run_log = _load_json(run_log_path)
    suite = _load_json(suite_path)
    suite_rel = str(suite_path)

    mode = run_log.get("mode", "single")
    if mode == "multi":
        attack_log = _convert_multi(run_log, suite, suite_rel)
    else:
        attack_log = _convert_single(run_log, suite, suite_rel)

    if output_path is None:
        output_path = run_log_path.parent / "attack_log.json"

    output_path.write_text(json.dumps(attack_log, indent=2, ensure_ascii=False), encoding="utf-8")
    return output_path
