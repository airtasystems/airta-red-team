"""LLM HTTP API presets for Connect Target and component submission config."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

LLM_API_PRESETS: dict[str, dict[str, Any]] = {
    "custom": {
        "id": "custom",
        "label": "Custom / app wrapper",
        "description": "Enter URL, body, and response path manually.",
        "url": "",
        "method": "POST",
        "response_path": "response",
        "body": {"prompt": "{{prompt}}"},
        "headers": {},
        "auth_header": "",
        "auth_query_param": "",
        "default_model": "",
    },
    "openai": {
        "id": "openai",
        "label": "OpenAI Chat Completions",
        "description": "POST /v1/chat/completions — requires Bearer API key in Step 1.",
        "url": "https://api.openai.com/v1/chat/completions",
        "method": "POST",
        "response_path": "choices.0.message.content",
        "body": {
            "model": "{{model}}",
            "messages": [{"role": "user", "content": "{{prompt}}"}],
        },
        "headers": {"Content-Type": "application/json"},
        "auth_header": "Authorization",
        "auth_query_param": "",
        "default_model": "gpt-4o-mini",
    },
    "gemini": {
        "id": "gemini",
        "label": "Google Gemini (generateContent)",
        "description": "POST …/models/{model}:generateContent — use x-goog-api-key header or ?key= query param in Step 1.",
        "url": "https://generativelanguage.googleapis.com/v1beta/models/{{model}}:generateContent",
        "method": "POST",
        "response_path": "candidates.0.content.parts.0.text",
        "body": {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": "{{prompt}}"}],
                }
            ],
        },
        "headers": {"Content-Type": "application/json"},
        "auth_header": "x-goog-api-key",
        "auth_query_param": "key",
        "default_model": "gemini-3.1-flash-lite",
    },
    "anthropic": {
        "id": "anthropic",
        "label": "Anthropic Messages",
        "description": "POST /v1/messages — requires x-api-key in Step 1.",
        "url": "https://api.anthropic.com/v1/messages",
        "method": "POST",
        "response_path": "content.0.text",
        "body": {
            "model": "{{model}}",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "{{prompt}}"}],
        },
        "headers": {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        },
        "auth_header": "x-api-key",
        "auth_query_param": "",
        "default_model": "claude-3-5-sonnet-20241022",
    },
    "azure_openai": {
        "id": "azure_openai",
        "label": "Azure OpenAI (deployments API)",
        "description": "Replace {resource} in the URL with your Azure resource name. Auth: api-key header in Step 1.",
        "url": "https://{resource}.openai.azure.com/openai/deployments/{{model}}/chat/completions?api-version=2024-10-21",
        "method": "POST",
        "response_path": "choices.0.message.content",
        "body": {
            "messages": [{"role": "user", "content": "{{prompt}}"}],
        },
        "headers": {"Content-Type": "application/json"},
        "auth_header": "api-key",
        "auth_query_param": "",
        "default_model": "gpt-4o-mini",
    },
    "test_target": {
        "id": "test_target",
        "label": "AIRTA test target (local)",
        "description": "POST /api/chat on the bundled test target — no auth required.",
        "url": "http://localhost:3000/api/chat",
        "method": "POST",
        "response_path": "response",
        "body": {"prompt": "{{prompt}}"},
        "headers": {},
        "auth_header": "",
        "auth_query_param": "",
        "default_model": "",
    },
}


def get_llm_api_presets() -> list[dict[str, Any]]:
    """Return preset list for UI (safe copies without secrets)."""
    return [deepcopy(p) for p in LLM_API_PRESETS.values()]


def get_preset(preset_id: str) -> dict[str, Any] | None:
    preset = LLM_API_PRESETS.get((preset_id or "").strip())
    return deepcopy(preset) if preset else None
