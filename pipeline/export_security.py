"""
Export pipeline_report.json to AIRTA Systems security assessment import API.

Default:
  POST /api/v2/security-assessments/import
  Body: results[], test_id, severity, assessment_reasoning (see security-assessment-export.md)

Legacy compliance import (opt-in):
  Set AIRTASYSTEMS_EXPORT_SCHEMA=legacy
  POST /api/v2/imported-reports/company

Required env vars:
  AIRTASYSTEMS_HOST, AIRTASYSTEMS_API_KEY, AIRTASYSTEMS_PROGRAM_ID
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

LEGACY_IMPORT_PATH = "/api/v2/imported-reports/company"
SECURITY_IMPORT_PATH = "/api/v2/security-assessments/import"
DEFAULT_EXPORT_BATCH_SIZE = 25
MAX_EXPORT_BATCH_SIZE = 2500
DEFAULT_EXPORT_BATCH_DELAY_SECONDS = 2.0
DEFAULT_EXPORT_MAX_RETRIES = 6
DEFAULT_EXPORT_RETRY_BASE_SECONDS = 5.0
ASSESSMENT_TYPE = "security"

VALID_SEVERITIES = frozenset({
    "indeterminate",
    "informational",
    "low",
    "medium",
    "high",
    "critical",
})

_LEGACY_SEVERITY_ALIASES = {
    "mitigated": "low",
    "compliant": "low",
}


def export_schema() -> str:
    """Return ``legacy`` or ``security`` from env."""
    value = (os.getenv("AIRTASYSTEMS_EXPORT_SCHEMA") or "security").strip().lower()
    return value if value in ("legacy", "security") else "security"


def _coerce_positive_int(value: object, default: int, *, minimum: int = 1, maximum: int | None = None) -> int:
    parsed: int | None
    if isinstance(value, bool):
        parsed = None
    elif isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
    else:
        parsed = None
    if parsed is None or parsed < minimum:
        parsed = default
    if maximum is not None:
        parsed = min(parsed, maximum)
    return parsed


def _coerce_non_negative_float(value: object, default: float) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        parsed = float(value)
        return parsed if parsed >= 0 else default
    if isinstance(value, str):
        try:
            parsed = float(value.strip())
            return parsed if parsed >= 0 else default
        except ValueError:
            pass
    return default


def export_batch_size() -> int:
    """Results per POST; default 25 to avoid Cloudflare/API rate limits."""
    return _coerce_positive_int(
        os.getenv("AIRTASYSTEMS_EXPORT_BATCH_SIZE"),
        DEFAULT_EXPORT_BATCH_SIZE,
        minimum=1,
        maximum=MAX_EXPORT_BATCH_SIZE,
    )


def export_batch_delay_seconds() -> float:
    """Pause between export batches (and between multi-report exports)."""
    return _coerce_non_negative_float(
        os.getenv("AIRTASYSTEMS_EXPORT_DELAY_SECONDS"),
        DEFAULT_EXPORT_BATCH_DELAY_SECONDS,
    )


def export_max_retries() -> int:
    return _coerce_positive_int(
        os.getenv("AIRTASYSTEMS_EXPORT_MAX_RETRIES"),
        DEFAULT_EXPORT_MAX_RETRIES,
        minimum=1,
        maximum=20,
    )


def export_retry_base_seconds() -> float:
    return _coerce_non_negative_float(
        os.getenv("AIRTASYSTEMS_EXPORT_RETRY_BASE_SECONDS"),
        DEFAULT_EXPORT_RETRY_BASE_SECONDS,
    ) or 1.0


def split_export_batches(results: list[dict], batch_size: int | None = None) -> list[list[dict]]:
    size = batch_size if batch_size is not None else export_batch_size()
    size = _coerce_positive_int(size, DEFAULT_EXPORT_BATCH_SIZE, minimum=1, maximum=MAX_EXPORT_BATCH_SIZE)
    return [results[i : i + size] for i in range(0, len(results), size)]


def _is_rate_limited_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(
        token in text
        for token in (
            "429",
            "rate limit",
            "too many requests",
            "cloudflare",
            "resource_exhausted",
            "temporarily unavailable",
            "503",
        )
    )


def import_path() -> str:
    override = (os.getenv("AIRTASYSTEMS_IMPORT_PATH") or "").strip()
    if override:
        return override if override.startswith("/") else f"/{override}"
    return SECURITY_IMPORT_PATH if export_schema() == "security" else LEGACY_IMPORT_PATH


def normalize_severity(value: object, default: str | None = None) -> str:
    if isinstance(value, str):
        normalized = _LEGACY_SEVERITY_ALIASES.get(value.strip().lower(), value.strip().lower())
        if normalized in VALID_SEVERITIES:
            return normalized
    if default:
        normalized_default = default.strip().lower()
        if normalized_default in VALID_SEVERITIES:
            return normalized_default
    return "indeterminate"


def _attack_blocked(severity: str) -> bool:
    return severity in ("low", "informational")


def _normalize_timestamp(value: object) -> object:
    if not isinstance(value, str) or not value.strip():
        return value
    text = value.strip()
    for fmt in ("%Y-%m-%dT%H-%M-%S", "%Y-%m-%d_%H-%M-%S"):
        try:
            return datetime.strptime(text, fmt).isoformat(timespec="milliseconds") + "Z"
        except ValueError:
            pass
    return text


def _strip_nulls(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_nulls(v) for v in value]
    return value


def _normalize_experts_summary(items: object, *, legacy: bool) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if legacy:
            level = normalize_severity(item.get("risk_level") or item.get("severity"))
            reasoning = str(item.get("reasoning") or item.get("justification") or "").strip()
            row: dict[str, Any] = {"risk_level": level}
            if reasoning:
                row["reasoning"] = reasoning
            out.append(row)
            continue
        level = normalize_severity(item.get("risk_level") or item.get("severity"))
        reasoning = str(item.get("reasoning") or item.get("justification") or "").strip()
        row = {"severity": level}
        if reasoning:
            row["reasoning"] = reasoning
        framework = item.get("framework") or item.get("playbook")
        if framework:
            row["framework"] = framework
        out.append(row)
    return out


def _legacy_optional_result_fields(item: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("description", "expected_behavior", "ok", "status", "error", "response_html"):
        if key in item and item[key] is not None:
            out[key] = item[key]
    return out


def _security_optional_result_fields(item: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("vector_type", "description", "status", "error", "response_html"):
        if key in item and item[key] is not None:
            out[key] = item[key]
    return out


def _optional_result_fields(item: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in (
        "vector_type",
        "artifact_path",
        "description",
        "expected_behavior",
        "ok",
        "status",
        "error",
        "response_html",
    ):
        if key in item and item[key] is not None:
            out[key] = item[key]
    return out


def build_legacy_export_result(item: dict, *, default_severity: str | None = None) -> dict[str, Any]:
    """Map pipeline row to imported-reports/company schema."""
    risk_level = normalize_severity(item.get("risk_level"), default_severity)
    mandate = item.get("mandate") or item.get("category") or ""
    result: dict[str, Any] = {
        "id": item.get("id", ""),
        "mandate": mandate,
        "prompt": item.get("prompt", ""),
        "response": item.get("response", ""),
        "risk_level": risk_level,
        "judge_reasoning": item.get("judge_reasoning", ""),
    }
    result.update(_legacy_optional_result_fields(item))
    if item.get("experts_summary"):
        result["experts_summary"] = _normalize_experts_summary(item["experts_summary"], legacy=True)
    return result


def _legacy_framework(data: dict) -> str:
    return (
        str(data.get("playbook") or data.get("framework") or data.get("playbook_id") or "")
        .strip()
        or "security_assessment"
    )


def build_legacy_export_payload(
    data: dict,
    results: list[dict] | None = None,
    *,
    default_severity: str | None = None,
) -> dict[str, Any]:
    rows = results if results is not None else data.get("adversarial_results", [])
    payload: dict[str, Any] = {
        "timestamp": _normalize_timestamp(data.get("timestamp", "")),
        "framework": _legacy_framework(data),
        "source_file": data.get("source_file", ""),
        "run_log_dir": data.get("run_log_dir", ""),
        "adversarial_results": [
            build_legacy_export_result(item, default_severity=default_severity)
            for item in rows
        ],
    }
    compliance_log = data.get("compliance_log") or data.get("attack_log")
    if compliance_log:
        payload["compliance_log"] = compliance_log
    return _strip_nulls(payload)


def build_security_export_result(item: dict, *, default_severity: str | None = None) -> dict[str, Any]:
    """Map pipeline row to security-assessments/import schema."""
    severity = normalize_severity(item.get("risk_level"), default_severity)
    ok = item.get("ok")
    if ok is None:
        ok = True
    result: dict[str, Any] = {
        "test_id": item.get("id", ""),
        "prompt": item.get("prompt", ""),
        "ok": bool(ok),
        "category": item.get("category") or item.get("mandate") or "",
        "response": item.get("response", ""),
        "severity": severity,
        "assessment_reasoning": item.get("judge_reasoning", ""),
        "attack_blocked": _attack_blocked(severity),
    }
    result.update(_security_optional_result_fields(item))
    if item.get("experts_summary"):
        result["experts_summary"] = _normalize_experts_summary(item["experts_summary"], legacy=False)
    return result


def build_security_export_payload(
    data: dict,
    results: list[dict] | None = None,
    *,
    default_severity: str | None = None,
) -> dict[str, Any]:
    rows = results if results is not None else data.get("adversarial_results", [])
    payload: dict[str, Any] = {
        "assessment_type": ASSESSMENT_TYPE,
        "timestamp": _normalize_timestamp(data.get("timestamp", "")),
        "playbook": data.get("playbook", data.get("framework", "")),
        "playbook_id": data.get("playbook_id", ""),
        "source_file": data.get("source_file", ""),
        "run_log_dir": data.get("run_log_dir", ""),
        "attack_log": data.get("attack_log", data.get("compliance_log", "")),
        "results": [
            build_security_export_result(item, default_severity=default_severity)
            for item in rows
        ],
    }
    rollup = data.get("category_rollup")
    if isinstance(rollup, dict) and rollup:
        payload["category_rollup"] = {
            key: normalize_severity(value, default_severity)
            for key, value in rollup.items()
        }
    return _strip_nulls(payload)


def build_export_payload(
    data: dict,
    results: list[dict] | None = None,
    *,
    default_severity: str | None = None,
    schema: str | None = None,
) -> dict[str, Any]:
    mode = schema or export_schema()
    if mode == "security":
        return build_security_export_payload(data, results, default_severity=default_severity)
    return build_legacy_export_payload(data, results, default_severity=default_severity)


def _build_url(host: str, path: str | None = None) -> str:
    host = host.strip().rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = "https://" + host
    return host + (path or import_path())


def _format_http_error(status: int, error_body: dict | str) -> str:
    if isinstance(error_body, dict):
        message = error_body.get("message") or error_body.get("error") or json.dumps(error_body)
        details = error_body.get("errors") or error_body.get("details") or error_body.get("validation")
        if details:
            detail_text = json.dumps(details, ensure_ascii=False)
            if len(detail_text) > 1200:
                detail_text = detail_text[:1200] + "…"
            return f"HTTP {status}: {message} — {detail_text}"
        return f"HTTP {status}: {message}"
    text = str(error_body)
    if len(text) > 1500:
        text = text[:1500] + "…"
    return f"HTTP {status}: {text}"


def _post_json(url: str, api_key: str, program_id: str, payload: dict) -> dict:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "X-Program-Id": program_id,
            "User-Agent": "AIRTA-Black-Box/SecurityExporter/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        try:
            error_body = json.loads(body_text)
        except Exception:
            raise RuntimeError(_format_http_error(e.code, body_text)) from e
        raise RuntimeError(_format_http_error(e.code, error_body)) from e


def _post_json_with_retry(
    url: str,
    api_key: str,
    program_id: str,
    payload: dict,
    *,
    max_retries: int | None = None,
    retry_base_seconds: float | None = None,
) -> dict:
    attempts = max_retries if max_retries is not None else export_max_retries()
    base_delay = retry_base_seconds if retry_base_seconds is not None else export_retry_base_seconds()
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            return _post_json(url, api_key, program_id, payload)
        except Exception as exc:
            last_error = exc
            if not _is_rate_limited_error(exc) or attempt >= attempts - 1:
                raise
            wait = base_delay * (2 ** attempt)
            print(
                f"[*] Rate limited (attempt {attempt + 1}/{attempts}) — "
                f"waiting {wait:.1f}s before retry..."
            )
            time.sleep(wait)
    if last_error:
        raise last_error
    raise RuntimeError("Export POST failed without error detail")


def _coerce_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _extract_summary(resp: dict, batch_size: int) -> dict[str, int]:
    summary = resp.get("summary")
    if not isinstance(summary, dict):
        summary = {}
    data = resp.get("data")
    if not isinstance(data, dict):
        data = {}

    failed = _coerce_int(summary.get("failed"))
    if failed is None:
        failed = _coerce_int(resp.get("failed"))
    if failed is None:
        errors = resp.get("errors")
        failed = len(errors) if isinstance(errors, list) else 0

    total = _coerce_int(summary.get("total"))
    if total is None:
        total = _coerce_int(resp.get("total"))
    if total is None:
        total = batch_size

    created = _coerce_int(summary.get("created"))
    if created is None:
        created = _coerce_int(resp.get("created"))
    if created is None:
        created = _coerce_int(resp.get("inserted"))
    if created is None:
        created = _coerce_int(resp.get("imported"))
    if created is None:
        created = _coerce_int(data.get("importedCount"))
    if created is None:
        created = max(0, total - failed)

    return {"total": total, "created": created, "failed": failed}


def export_pipeline_report(
    report_path: Path,
    *,
    host: str,
    api_key: str,
    program_id: str,
    default_level: str | None = None,
    batch_size: int | None = None,
    batch_delay_seconds: float | None = None,
) -> list[dict]:
    data = json.loads(report_path.read_text(encoding="utf-8"))
    results: list[dict] = data.get("adversarial_results", [])

    if not results:
        print("[-] No assessment results found in report (adversarial_results empty).")
        return []

    schema = export_schema()
    path = import_path()
    url = _build_url(host, path)
    total = len(results)
    size = batch_size if batch_size is not None else export_batch_size()
    delay = export_batch_delay_seconds() if batch_delay_seconds is None else max(0.0, float(batch_delay_seconds))
    batches = split_export_batches(results, size)

    print(
        f"[*] Exporting {total} result(s) in {len(batches)} batch(es) "
        f"({size} per batch, {delay:.1f}s delay, schema={schema}) to {url}"
    )

    responses: list[dict] = []
    for idx, batch in enumerate(batches, 1):
        print(f"[*] Sending batch {idx}/{len(batches)} ({len(batch)} item(s))...")
        payload = build_export_payload(data, batch, default_severity=default_level, schema=schema)

        try:
            resp = _post_json_with_retry(url, api_key, program_id, payload)
        except Exception as e:
            print(f"[!] Batch {idx} failed: {e}")
            responses.append({
                "batch": idx,
                "error": str(e),
                "summary": {"total": len(batch), "created": 0, "failed": len(batch)},
            })
            if idx < len(batches) and delay > 0:
                print(f"[*] Waiting {delay:.1f}s before next batch...")
                time.sleep(delay)
            continue

        success = resp.get("success", False)
        summary = _extract_summary(resp, len(batch))
        errors = resp.get("errors", [])
        resp["summary"] = summary

        if success:
            print(
                f"[+] Batch {idx} accepted — "
                f"total={summary.get('total', '?')}, "
                f"created={summary.get('created', '?')}, "
                f"failed={summary.get('failed', '?')}"
            )
        else:
            err_code = resp.get("error", "unknown")
            print(f"[!] Batch {idx} returned success=false: {err_code}")

        if errors:
            print(f"    {len(errors)} import error(s):")
            for err in errors[:10]:
                print(f"      index={err.get('index')}, id={err.get('id')}: {err.get('message')}")
            if len(errors) > 10:
                print(f"      ... and {len(errors) - 10} more.")

        resp["batch"] = idx
        responses.append(resp)

        if idx < len(batches) and delay > 0:
            print(f"[*] Waiting {delay:.1f}s before next batch...")
            time.sleep(delay)

    created_total = sum(r.get("summary", {}).get("created", 0) for r in responses if "summary" in r)
    failed_total = sum(r.get("summary", {}).get("failed", 0) for r in responses if "summary" in r)
    print(
        f"\n[+] Export complete — "
        f"{created_total} created, {failed_total} failed across {len(batches)} batch(es)."
    )
    return responses
