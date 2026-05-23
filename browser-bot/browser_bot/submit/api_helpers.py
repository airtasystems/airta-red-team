"""HTTP helpers for API-based component submission."""

from __future__ import annotations

import json
import mimetypes
import uuid
from pathlib import Path
from typing import Any
import urllib.error
import urllib.request


def apply_prompt_template(obj: Any, prompt: str, *, extra: dict[str, str] | None = None) -> Any:
    """Replace ``{{prompt}}`` and optional ``{{key}}`` placeholders in nested structures."""
    extras = extra or {}

    def _sub(s: str) -> str:
        out = s.replace("{{prompt}}", prompt)
        for k, v in extras.items():
            out = out.replace(f"{{{{{k}}}}}", v)
        return out

    if isinstance(obj, str):
        return _sub(obj)
    if isinstance(obj, dict):
        return {k: apply_prompt_template(v, prompt, extra=extras) for k, v in obj.items()}
    if isinstance(obj, list):
        return [apply_prompt_template(v, prompt, extra=extras) for v in obj]
    return obj


def extract_json_path(data: Any, path: str) -> Any:
    """Extract a dotted path from parsed JSON (e.g. ``response`` or ``data.text``)."""
    path = (path or "").strip()
    if not path:
        return data
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def auth_headers_for_site(site: str | None) -> dict[str, str]:
    """Merge saved auth headers and cookies for API requests."""
    if not site:
        return {}
    from browser_bot.auth_state import load_auth_config

    cfg = load_auth_config(site) or {}
    headers = {str(k): str(v) for k, v in (cfg.get("headers") or {}).items()}
    cookies = cfg.get("cookies") or []
    if cookies:
        parts = []
        for cookie in cookies:
            if isinstance(cookie, dict) and cookie.get("name") is not None:
                parts.append(f"{cookie['name']}={cookie.get('value', '')}")
        if parts:
            headers.setdefault("Cookie", "; ".join(parts))
    return headers


def _http_request(
    url: str,
    *,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: float = 120.0,
) -> tuple[int, str]:
    req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return getattr(resp, "status", 200) or 200, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = str(exc)
        return exc.code, body


def _encode_multipart(
    fields: dict[str, str],
    files: dict[str, tuple[str, bytes, str]],
) -> tuple[bytes, str]:
    boundary = f"----airta{uuid.uuid4().hex}"
    lines: list[bytes] = []
    for name, value in fields.items():
        lines.append(f"--{boundary}\r\n".encode())
        lines.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        lines.append(value.encode("utf-8"))
        lines.append(b"\r\n")
    for name, (filename, content, mime) in files.items():
        lines.append(f"--{boundary}\r\n".encode())
        lines.append(
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
        )
        lines.append(f"Content-Type: {mime}\r\n\r\n".encode())
        lines.append(content)
        lines.append(b"\r\n")
    lines.append(f"--{boundary}--\r\n".encode())
    body = b"".join(lines)
    return body, f"multipart/form-data; boundary={boundary}"


def _upload_document(
    sub: dict[str, Any],
    artifact_path: Path,
    *,
    site: str | None = None,
    timeout: float = 120.0,
) -> tuple[str | None, str | None]:
    upload_url = sub.get("upload_url") or sub.get("api_upload_url")
    if not upload_url:
        return None, "upload_url not configured"
    file_field = sub.get("upload_file_field", "file")
    headers = dict(sub.get("api_headers") or {})
    headers.update(auth_headers_for_site(site))
    content = artifact_path.read_bytes()
    mime, _ = mimetypes.guess_type(artifact_path.name)
    mime = mime or "application/octet-stream"
    body, ctype = _encode_multipart({}, {file_field: (artifact_path.name, content, mime)})
    headers["Content-Type"] = ctype
    status, raw = _http_request(upload_url, method="POST", headers=headers, data=body, timeout=timeout)
    if status >= 400:
        return None, f"upload HTTP {status}: {raw[:500]}"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None, "upload response not JSON"
    doc_path = sub.get("upload_response_path", "document_id")
    doc_id = extract_json_path(parsed, doc_path)
    if doc_id is None and isinstance(parsed, dict):
        doc_id = parsed.get("id") or parsed.get("document_id")
    if doc_id is None:
        return None, f"document id not found at {doc_path}"
    return str(doc_id), None


def do_api_request(
    sub: dict[str, Any],
    prompt: str,
    *,
    site: str | None = None,
    timeout: float = 120.0,
    test_case: dict | None = None,
    suite_path: Path | str | None = None,
) -> tuple[int, str | None, str | None]:
    """Send one API submission. Returns ``(status_code, response_text, error)``."""
    transport = (sub.get("transport") or "api").lower()
    if transport == "api_document":
        return do_api_document_request(
            sub, prompt, site=site, timeout=timeout, test_case=test_case, suite_path=suite_path
        )
    if transport == "api_multipart":
        return do_api_multipart_request(
            sub, prompt, site=site, timeout=timeout, test_case=test_case, suite_path=suite_path
        )

    url = sub["api_url"]
    method = (sub.get("api_method") or "POST").upper()
    headers = {"Accept": "application/json", **dict(sub.get("api_headers") or {})}
    headers.update(auth_headers_for_site(site))

    body_obj = apply_prompt_template(sub.get("api_body") or {"prompt": "{{prompt}}"}, prompt)
    data: bytes | None = None
    if method in {"POST", "PUT", "PATCH"}:
        if "Content-Type" not in headers and "content-type" not in headers:
            headers["Content-Type"] = "application/json"
        data = json.dumps(body_obj).encode("utf-8")

    status, raw = _http_request(url, method=method, headers=headers, data=data, timeout=timeout)
    if status >= 400:
        parsed = _parse_response_text(raw, sub.get("api_response_path") or "response")
        if parsed:
            return status, parsed, None
        return status, None, f"HTTP {status}: {raw[:500]}"
    return status, _parse_response_text(raw, sub.get("api_response_path") or "response"), None


def do_api_document_request(
    sub: dict[str, Any],
    prompt: str,
    *,
    site: str | None = None,
    timeout: float = 120.0,
    test_case: dict | None = None,
    suite_path: Path | str | None = None,
) -> tuple[int, str | None, str | None]:
    """Upload artifact then chat with document_id (DVAIA pattern)."""
    if not test_case:
        return 0, None, "api_document requires multimodal test case with payload"
    try:
        from browser_bot.artifacts import resolve_test_artifact

        artifact_path, _, upload_ok = resolve_test_artifact(test_case, suite_path=suite_path)
    except Exception as exc:
        return 0, None, str(exc)
    if not upload_ok or not artifact_path or not artifact_path.is_file():
        return 0, None, "failed to resolve upload artifact"

    doc_id, err = _upload_document(sub, artifact_path, site=site, timeout=timeout)
    if err or not doc_id:
        return 0, None, err or "upload failed"

    url = sub["api_url"]
    method = (sub.get("api_method") or "POST").upper()
    headers = {"Accept": "application/json", **dict(sub.get("api_headers") or {})}
    headers.update(auth_headers_for_site(site))
    body_obj = apply_prompt_template(
        sub.get("api_body") or {"prompt": "{{prompt}}", "document_id": "{{document_id}}"},
        prompt,
        extra={"document_id": doc_id},
    )
    data = json.dumps(body_obj).encode("utf-8")
    if "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    status, raw = _http_request(url, method=method, headers=headers, data=data, timeout=timeout)
    if status >= 400:
        parsed = _parse_response_text(raw, sub.get("api_response_path") or "response")
        if parsed:
            return status, parsed, None
        return status, None, f"HTTP {status}: {raw[:500]}"
    return status, _parse_response_text(raw, sub.get("api_response_path") or "response"), None


def do_api_multipart_request(
    sub: dict[str, Any],
    prompt: str,
    *,
    site: str | None = None,
    timeout: float = 120.0,
    test_case: dict | None = None,
    suite_path: Path | str | None = None,
) -> tuple[int, str | None, str | None]:
    """Single multipart POST with file + prompt fields."""
    url = sub.get("api_url") or sub.get("upload_url")
    if not url:
        return 0, None, "api_url not configured"
    prompt_field = sub.get("multipart_prompt_field", "prompt")
    file_field = sub.get("multipart_file_field", "file")
    fields = {prompt_field: prompt}
    extra_fields = sub.get("multipart_fields") or {}
    if isinstance(extra_fields, dict):
        for k, v in extra_fields.items():
            fields[str(k)] = apply_prompt_template(str(v), prompt) if isinstance(v, str) else str(v)

    files: dict[str, tuple[str, bytes, str]] = {}
    if test_case:
        try:
            from browser_bot.artifacts import resolve_test_artifact

            artifact_path, _, upload_ok = resolve_test_artifact(test_case, suite_path=suite_path)
            if upload_ok and artifact_path and artifact_path.is_file():
                content = artifact_path.read_bytes()
                mime, _ = mimetypes.guess_type(artifact_path.name)
                files[file_field] = (artifact_path.name, content, mime or "application/octet-stream")
        except Exception:
            pass

    body, ctype = _encode_multipart(fields, files)
    headers = dict(sub.get("api_headers") or {})
    headers.update(auth_headers_for_site(site))
    headers["Content-Type"] = ctype
    status, raw = _http_request(url, method="POST", headers=headers, data=body, timeout=timeout)
    if status >= 400:
        parsed = _parse_response_text(raw, sub.get("api_response_path") or "response")
        if parsed:
            return status, parsed, None
        return status, None, f"HTTP {status}: {raw[:500]}"
    return status, _parse_response_text(raw, sub.get("api_response_path") or "response"), None


def _parse_response_text(raw: str, response_path: str) -> str | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    extracted = extract_json_path(parsed, response_path)
    if extracted is None:
        return None
    if isinstance(extracted, str):
        return extracted.strip() or None
    return json.dumps(extracted, ensure_ascii=False)
