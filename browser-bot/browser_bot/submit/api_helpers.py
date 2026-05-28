"""HTTP helpers for API-based component submission."""

from __future__ import annotations

import copy
import json
import mimetypes
import uuid
from pathlib import Path
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


def apply_prompt_template(
    obj: Any,
    prompt: str,
    *,
    extra: dict[str, str] | None = None,
    model: str = "",
) -> Any:
    """Replace ``{{prompt}}``, ``{{model}}``, and optional ``{{key}}`` placeholders."""
    extras = dict(extra or {})
    if model and "model" not in extras:
        extras["model"] = model

    def _sub(s: str) -> str:
        out = s.replace("{{prompt}}", prompt)
        for k, v in extras.items():
            out = out.replace(f"{{{{{k}}}}}", v)
        return out

    if isinstance(obj, str):
        return _sub(obj)
    if isinstance(obj, dict):
        return {k: apply_prompt_template(v, prompt, extra=extras, model=model) for k, v in obj.items()}
    if isinstance(obj, list):
        return [apply_prompt_template(v, prompt, extra=extras, model=model) for v in obj]
    return obj


def _body_contains_messages_placeholder(obj: Any) -> bool:
    """Return True if ``api_body`` contains a ``{{messages}}`` placeholder."""
    if isinstance(obj, str):
        return "{{messages}}" in obj
    if isinstance(obj, dict):
        return any(_body_contains_messages_placeholder(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_body_contains_messages_placeholder(v) for v in obj)
    return False


def uses_messages_context(sub: dict[str, Any]) -> bool:
    """True when multi-turn API runs should send a growing ``messages`` array."""
    if (sub.get("api_context_mode") or "").strip().lower() == "messages":
        return True
    body = sub.get("api_body") or sub.get("api_body_template")
    return _body_contains_messages_placeholder(body)


def _normalize_message(msg: Any) -> dict[str, str] | None:
    if not isinstance(msg, dict):
        return None
    role = str(msg.get("role") or "").strip()
    content = msg.get("content")
    if content is None:
        return None
    if not isinstance(content, str):
        content = json.dumps(content, ensure_ascii=False)
    content = content.strip()
    if not role or not content:
        return None
    return {"role": role, "content": content}


def build_conversation_messages(
    sub: dict[str, Any],
    conversation_history: list[tuple[str, str]] | None,
    current_prompt: str,
) -> list[dict[str, str]]:
    """Build OpenAI-style messages: optional prefix, prior user/assistant turns, current user."""
    messages: list[dict[str, str]] = []
    prefix = sub.get("api_messages_prefix") or []
    if isinstance(prefix, list):
        for msg in prefix:
            normalized = _normalize_message(msg)
            if normalized:
                messages.append(normalized)

    for user_text, assistant_text in conversation_history or []:
        user_text = (user_text or "").strip()
        assistant_text = (assistant_text or "").strip()
        if user_text:
            messages.append({"role": "user", "content": user_text})
        if assistant_text:
            messages.append({"role": "assistant", "content": assistant_text})

    current_prompt = (current_prompt or "").strip()
    if current_prompt:
        messages.append({"role": "user", "content": current_prompt})
    return messages


def _inject_messages_value(obj: Any, messages: list[dict[str, str]]) -> Any:
    """Replace ``{{messages}}`` placeholders with the built messages list."""
    if isinstance(obj, str):
        if obj.strip() == "{{messages}}":
            return copy.deepcopy(messages)
        return obj.replace("{{messages}}", json.dumps(messages, ensure_ascii=False))
    if isinstance(obj, dict):
        return {k: _inject_messages_value(v, messages) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_inject_messages_value(v, messages) for v in obj]
    return obj


def build_api_request_body(
    sub: dict[str, Any],
    prompt: str,
    *,
    conversation_history: list[tuple[str, str]] | None = None,
) -> Any:
    """Build the JSON request body, optionally with multi-turn ``messages`` context."""
    api_model = str(sub.get("api_model") or "").strip()
    template = sub.get("api_body") or {"prompt": "{{prompt}}"}

    if not uses_messages_context(sub):
        return apply_prompt_template(template, prompt, model=api_model)

    messages = build_conversation_messages(sub, conversation_history, prompt)
    body = copy.deepcopy(template)
    if _body_contains_messages_placeholder(template):
        body = _inject_messages_value(body, messages)
    elif isinstance(body, dict):
        body["messages"] = copy.deepcopy(messages)
    return apply_prompt_template(body, prompt, model=api_model)


def extract_json_path(data: Any, path: str) -> Any:
    """Extract a dotted path from parsed JSON (supports array indices, e.g. ``choices.0.message.content``)."""
    path = (path or "").strip()
    if not path:
        return data
    cur = data
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def auth_query_params_for_site(site: str | None) -> dict[str, str]:
    """Return saved auth query params for API requests."""
    if not site:
        return {}
    from browser_bot.auth_state import load_auth_config

    cfg = load_auth_config(site) or {}
    return {str(k): str(v) for k, v in (cfg.get("query_params") or {}).items()}


def _merge_url_query(url: str, extra: dict[str, str]) -> str:
    if not extra:
        return url
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for key, value in extra.items():
        if key not in qs:
            qs[key] = [value]
    new_query = urllib.parse.urlencode(
        [(key, val) for key, vals in qs.items() for val in vals],
        doseq=True,
    )
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _normalize_provider_auth(
    headers: dict[str, str],
    url: str,
    query_params: dict[str, str],
) -> tuple[dict[str, str], dict[str, str]]:
    """Map common Gemini auth shapes to ``x-goog-api-key`` / ``?key=``."""
    if "generativelanguage.googleapis.com" not in (url or ""):
        return headers, query_params

    out_headers = dict(headers)
    out_query = dict(query_params)

    key_value = ""
    auth = out_headers.pop("Authorization", "") or out_headers.pop("authorization", "")
    if auth.startswith("Bearer "):
        key_value = auth[7:].strip()
    elif auth.startswith("AIza"):
        key_value = auth.strip()

    for hname, hval in list(out_headers.items()):
        if hname.lower() == "x-goog-api-key" and hval:
            key_value = key_value or hval.strip()
            break

    if not key_value and out_query.get("key"):
        key_value = out_query["key"]

    if not key_value:
        return out_headers, out_query

    if "x-goog-api-key" not in {k.lower(): v for k, v in out_headers.items()}:
        out_headers["x-goog-api-key"] = key_value
    if "key" not in out_query:
        out_query["key"] = key_value
    return out_headers, out_query


def auth_headers_for_site(site: str | None, *, url: str = "") -> dict[str, str]:
    """Merge saved auth headers and cookies for API requests."""
    if not site:
        return {}
    from browser_bot.auth_state import load_auth_config

    cfg = load_auth_config(site) or {}
    headers = {str(k): str(v) for k, v in (cfg.get("headers") or {}).items()}
    query_params = {str(k): str(v) for k, v in (cfg.get("query_params") or {}).items()}

    if cfg.get("auth_mode") == "api_key":
        headers, _ = _normalize_provider_auth(headers, url, query_params)
        return headers

    cookies = cfg.get("cookies") or []
    if cookies:
        parts = []
        for cookie in cookies:
            if isinstance(cookie, dict) and cookie.get("name") is not None:
                parts.append(f"{cookie['name']}={cookie.get('value', '')}")
        if parts:
            headers.setdefault("Cookie", "; ".join(parts))
    headers, _ = _normalize_provider_auth(headers, url, query_params)
    return headers


def resolve_api_url(sub: dict[str, Any], *, site: str | None) -> tuple[str | None, str | None]:
    """Substitute ``{{model}}``, merge auth query params. Returns ``(url, error)``."""
    api_url = str(sub.get("api_url") or "").strip()
    if not api_url:
        return None, "api_url not configured"
    api_model = str(sub.get("api_model") or "").strip()
    if "{{model}}" in api_url and not api_model:
        return None, "api_model is required when api_url contains {{model}}"
    resolved = apply_prompt_template(api_url, "", model=api_model)
    if not isinstance(resolved, str):
        resolved = str(resolved)
    query_params = auth_query_params_for_site(site)
    _, query_params = _normalize_provider_auth({}, resolved, query_params)
    return _merge_url_query(resolved, query_params), None


def _gemini_auth_preflight(url: str, headers: dict[str, str], query_params: dict[str, str]) -> str | None:
    if "generativelanguage.googleapis.com" not in url:
        return None
    merged_query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    has_key_param = "key" in merged_query or "key" in query_params
    has_key_header = any(k.lower() == "x-goog-api-key" for k in headers)
    if not has_key_param and not has_key_header:
        return (
            "Gemini API requires auth: save an API key in Connect Target Step 1 "
            "with header x-goog-api-key or query param key"
        )
    return None


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
    headers.update(auth_headers_for_site(site, url=str(upload_url)))
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
    conversation_history: list[tuple[str, str]] | None = None,
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

    url, url_err = resolve_api_url(sub, site=site)
    if url_err or not url:
        return 0, None, url_err or "api_url not configured"

    api_model = str(sub.get("api_model") or "").strip()
    method = (sub.get("api_method") or "POST").upper()
    headers = {"Accept": "application/json", **dict(sub.get("api_headers") or {})}
    headers.update(auth_headers_for_site(site, url=url))

    preflight_err = _gemini_auth_preflight(url, headers, auth_query_params_for_site(site))
    if preflight_err:
        return 0, None, preflight_err

    body_obj = build_api_request_body(
        sub,
        prompt,
        conversation_history=conversation_history,
    )
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

    url, url_err = resolve_api_url(sub, site=site)
    if url_err or not url:
        return 0, None, url_err or "api_url not configured"

    api_model = str(sub.get("api_model") or "").strip()
    method = (sub.get("api_method") or "POST").upper()
    headers = {"Accept": "application/json", **dict(sub.get("api_headers") or {})}
    headers.update(auth_headers_for_site(site, url=url))
    body_obj = apply_prompt_template(
        sub.get("api_body") or {"prompt": "{{prompt}}", "document_id": "{{document_id}}"},
        prompt,
        extra={"document_id": doc_id},
        model=api_model,
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
    url = _merge_url_query(str(url), auth_query_params_for_site(site))
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
    headers.update(auth_headers_for_site(site, url=url))
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
