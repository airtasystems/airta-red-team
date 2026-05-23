"""
Export pipeline_report.json results to AIRTA Systems via the bulk-import API.

API: POST /api/v2/imported-reports/company
Headers: Authorization: Bearer <key>, X-Program-Id: <id>
Body: pipeline_report.json fields accepted by the import endpoint.

Required env vars (or supplied via CLI / GUI):
  AIRTASYSTEMS_HOST        — hostname (e.g. app.airtasystems.com or localhost:4000)
  AIRTASYSTEMS_API_KEY     — API key scoped to write:bulk_import
  AIRTASYSTEMS_PROGRAM_ID  — MongoDB ObjectId of the target program

Optional env var:
  AIRTASYSTEMS_DEFAULT_LEVEL — indeterminate | compliant | informational | low | medium | high | critical
"""
import json
import os
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

IMPORT_PATH = "/api/v2/imported-reports/company"
# The API accepts up to 5 000 items; we stay well under to avoid timeouts.
MAX_BATCH_SIZE = 2500
TOP_LEVEL_FIELDS = {
    "timestamp",
    "framework",
    "source_file",
    "run_log_dir",
    "compliance_log",
    "adversarial_results",
}
RESULT_FIELDS = {
    "id",
    "mandate",
    "prompt",
    "response",
    "risk_level",
    "judge_reasoning",
    "experts_summary",
    "description",
    "expected_behavior",
    "ok",
    "status",
    "error",
    "response_html",
}
VALID_RISK_LEVELS = {
    "indeterminate",
    "compliant",
    "informational",
    "low",
    "medium",
    "high",
    "critical",
}


def _build_url(host: str) -> str:
    host = host.strip().rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = "https://" + host
    return host + IMPORT_PATH


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
            # Avoid edge filters that reject Python's default urllib user agent.
            "User-Agent": "AIRTA-Pipeline-Exporter/1.0",
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
            raise RuntimeError(f"HTTP {e.code}: {body_text}") from e
        message = error_body.get("message") or error_body.get("error") or body_text
        raise RuntimeError(f"HTTP {e.code}: {message}") from e


def _normalize_timestamp(value: object) -> object:
    """Convert AIRTA's filename-safe timestamp into an ISO-8601 datetime string."""
    if not isinstance(value, str) or not value.strip():
        return value

    text = value.strip()
    for fmt in ("%Y-%m-%dT%H-%M-%S", "%Y-%m-%d_%H-%M-%S"):
        try:
            return datetime.strptime(text, fmt).isoformat(timespec="milliseconds") + "Z"
        except ValueError:
            pass
    return text


def _normalize_risk_level(value: object, default_level: str | None = None) -> object:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in VALID_RISK_LEVELS:
            return normalized
    if default_level:
        normalized_default = default_level.strip().lower()
        if normalized_default in VALID_RISK_LEVELS:
            return normalized_default
    return value


def _sanitize_result(item: dict, default_level: str | None = None) -> dict:
    result = {k: item[k] for k in RESULT_FIELDS if k in item}
    if "risk_level" in result:
        result["risk_level"] = _normalize_risk_level(result["risk_level"], default_level)
    elif default_level:
        result["risk_level"] = _normalize_risk_level(default_level)
    return result


def _sanitize_payload(data: dict, results: list[dict], default_level: str | None = None) -> dict:
    """
    Keep fields accepted by the imported-reports API and drop local rollups.
    """
    payload = {k: data[k] for k in TOP_LEVEL_FIELDS if k in data and k != "adversarial_results"}
    if "timestamp" in payload:
        payload["timestamp"] = _normalize_timestamp(payload["timestamp"])
    payload["adversarial_results"] = [
        _sanitize_result(item, default_level)
        for item in results
    ]
    return payload


def _coerce_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _extract_summary(resp: dict, batch_size: int) -> dict[str, int]:
    """Return numeric import metrics, falling back to full-batch success."""
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
) -> list[dict]:
    """
    Read pipeline_report.json and POST it to the AIRTA Systems imported-reports
    endpoint.  For reports with > MAX_BATCH_SIZE results the adversarial_results
    array is split into batches while keeping the rest of the top-level metadata
    on each request.

    Returns a list of response dicts (one per batch).
    """
    data = json.loads(report_path.read_text(encoding="utf-8"))
    results: list[dict] = data.get("adversarial_results", [])

    if not results:
        print("[-] No adversarial_results found in report.")
        return []

    url = _build_url(host)
    total = len(results)
    batches = [results[i : i + MAX_BATCH_SIZE] for i in range(0, total, MAX_BATCH_SIZE)]

    print(f"[*] Exporting {total} result(s) in {len(batches)} batch(es) to {url}")

    meta = {k: data[k] for k in TOP_LEVEL_FIELDS if k in data and k != "adversarial_results"}

    responses: list[dict] = []
    for idx, batch in enumerate(batches, 1):
        print(f"[*] Sending batch {idx}/{len(batches)} ({len(batch)} item(s))...")
        payload = _sanitize_payload(meta, batch, default_level)

        try:
            resp = _post_json(url, api_key, program_id, payload)
        except Exception as e:
            print(f"[!] Batch {idx} failed: {e}")
            responses.append({
                "batch": idx,
                "error": str(e),
                "summary": {"total": len(batch), "created": 0, "failed": len(batch)},
            })
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

    created_total = sum(r.get("summary", {}).get("created", 0) for r in responses if "summary" in r)
    failed_total = sum(r.get("summary", {}).get("failed", 0) for r in responses if "summary" in r)
    print(f"\n[+] Export complete — {created_total} created, {failed_total} failed across {len(batches)} batch(es).")
    return responses
