"""Component-level settings overrides (config.yaml ``settings:`` + global defaults)."""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
_ENV_FILE = _ROOT / ".env"
_CONFIG_PY = _ROOT / "browser-bot" / "browser_bot" / "config.py"
_DEFAULTS_YAML = _ROOT / "config.defaults.yaml"

EDITABLE_BROWSER_VARS = frozenset({
    "FETCH_METHOD", "POOL_SIZE", "CONTEXT_COUNT", "PAGES_PER_CONTEXT",
    "POOL_CLUSTER_HUMAN_LIKE", "POOL_CLUSTER_ALLOW_STYLES", "POOL_CLUSTER_USE_STEALTH",
    "POOL_CLUSTER_USE_HUMAN_CHROME", "POOL_CLUSTER_USE_HUMAN_CONTEXT",
    "API_CONCURRENCY",
    "EVASION_REQUEST_DELAY_S", "EVASION_RETRY_WAIT_S", "EVASION_MAX_RETRIES",
    "HUMAN_COUNTRY", "HUMAN_ALLOW_STYLES", "HUMAN_READ_DELAY_MS",
    "HUMAN_SCROLL_AFTER_LOAD", "HUMAN_USER_AGENT",
    "HEADLESS", "BLOCKED_TYPES", "CHROMIUM_EXECUTABLE_PATH", "CHROME_CHANNEL",
})

CACHE_SETTING_KEYS = frozenset({"gemini_use_cache"})

ALL_SETTING_KEYS = EDITABLE_BROWSER_VARS | CACHE_SETTING_KEYS

SETTING_GROUPS: list[dict[str, Any]] = [
    {
        "id": "cache",
        "title": "Cache Control",
        "keys": ["gemini_use_cache"],
    },
    {
        "id": "fetcher",
        "title": "Fetcher",
        "keys": ["FETCH_METHOD", "POOL_SIZE", "CONTEXT_COUNT", "PAGES_PER_CONTEXT"],
    },
    {
        "id": "pool_cluster",
        "title": "Pool / Cluster Browser Enhancements",
        "keys": [
            "POOL_CLUSTER_HUMAN_LIKE", "POOL_CLUSTER_ALLOW_STYLES", "POOL_CLUSTER_USE_STEALTH",
            "POOL_CLUSTER_USE_HUMAN_CHROME", "POOL_CLUSTER_USE_HUMAN_CONTEXT",
        ],
    },
    {
        "id": "evasion",
        "title": "API / Evasion",
        "keys": ["API_CONCURRENCY", "EVASION_REQUEST_DELAY_S", "EVASION_RETRY_WAIT_S", "EVASION_MAX_RETRIES"],
    },
    {
        "id": "human",
        "title": "Human Tier",
        "keys": [
            "HUMAN_COUNTRY", "HUMAN_READ_DELAY_MS", "HUMAN_ALLOW_STYLES",
            "HUMAN_SCROLL_AFTER_LOAD", "HUMAN_USER_AGENT",
        ],
    },
    {
        "id": "browser",
        "title": "Browser",
        "keys": ["HEADLESS", "CHROME_CHANNEL", "CHROMIUM_EXECUTABLE_PATH", "BLOCKED_TYPES"],
    },
]

SETTING_META: dict[str, dict[str, Any]] = {
    "gemini_use_cache": {"type": "bool", "label": "Gemini context cache"},
    "FETCH_METHOD": {"type": "select", "label": "Fetch method", "options": ["auto", "pool", "cluster", "human"]},
    "POOL_SIZE": {"type": "int", "label": "Pool size", "min": 1, "max": 32},
    "CONTEXT_COUNT": {"type": "int", "label": "Cluster contexts", "min": 1, "max": 32},
    "PAGES_PER_CONTEXT": {"type": "int", "label": "Pages / context", "min": 1, "max": 16},
    "POOL_CLUSTER_HUMAN_LIKE": {"type": "bool", "label": "Human-like (enable all below)"},
    "POOL_CLUSTER_ALLOW_STYLES": {"type": "bool", "label": "Allow stylesheets"},
    "POOL_CLUSTER_USE_STEALTH": {"type": "bool", "label": "Playwright-stealth"},
    "POOL_CLUSTER_USE_HUMAN_CHROME": {"type": "bool", "label": "Human Chrome args"},
    "POOL_CLUSTER_USE_HUMAN_CONTEXT": {"type": "bool", "label": "Human context (locale / viewport / geo)"},
    "EVASION_REQUEST_DELAY_S": {"type": "float", "label": "Request delay (s)", "min": 0, "step": 0.1},
    "EVASION_RETRY_WAIT_S": {"type": "float", "label": "Retry wait (s)", "min": 0, "step": 1},
    "EVASION_MAX_RETRIES": {"type": "int", "label": "Max retries", "min": 0, "max": 10},
    "HUMAN_COUNTRY": {
        "type": "select", "label": "Country",
        "options": ["US", "UK", "DE", "FR", "JP", "CA", "AU", "NL", "ES", "IT"],
    },
    "HUMAN_READ_DELAY_MS": {"type": "int", "label": "Read delay (ms)", "min": 0, "step": 100},
    "HUMAN_ALLOW_STYLES": {"type": "bool", "label": "Allow stylesheets"},
    "HUMAN_SCROLL_AFTER_LOAD": {"type": "bool", "label": "Scroll after load"},
    "HUMAN_USER_AGENT": {"type": "string", "label": "User agent"},
    "HEADLESS": {"type": "bool", "label": "Headless"},
    "CHROME_CHANNEL": {
        "type": "select", "label": "Chrome channel",
        "options": ["chromium", "chrome", "chrome-beta", "msedge"],
    },
    "CHROMIUM_EXECUTABLE_PATH": {"type": "string", "label": "Chromium path"},
    "BLOCKED_TYPES": {
        "type": "set", "label": "Block types",
        "options": ["image", "font", "media", "stylesheet"],
    },
}

_FALSE = frozenset({"0", "false", "no", "off"})
_TRUE = frozenset({"1", "true", "yes", "on"})


def _env_value(key: str, default: str = "") -> str:
    if _ENV_FILE.is_file():
        try:
            for raw in _ENV_FILE.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                if k.strip() == key:
                    return v.strip().strip('"').strip("'")
        except OSError:
            pass
    return os.getenv(key, default)


def _parse_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in _FALSE:
        return False
    if s in _TRUE:
        return True
    return default


def _normalize_settings_dict(raw: dict[str, Any] | None) -> dict[str, Any]:
    if not raw:
        return {}
    return {k: v for k, v in raw.items() if k in ALL_SETTING_KEYS}


def _merge_settings_layers(*layers: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for layer in layers:
        out.update(_normalize_settings_dict(layer))
    return out


def load_defaults_yaml() -> dict[str, Any]:
    """Shipped app-wide defaults from config.defaults.yaml (settings block)."""
    if not _DEFAULTS_YAML.is_file():
        return {}
    try:
        import yaml

        data = yaml.safe_load(_DEFAULTS_YAML.read_text(encoding="utf-8")) or {}
        settings = data.get("settings")
        return _normalize_settings_dict(settings if isinstance(settings, dict) else {})
    except Exception:
        return {}


def _ensure_browser_bot_path() -> None:
    bb_dir = _ROOT / "browser-bot"
    if str(bb_dir) not in sys.path:
        sys.path.insert(0, str(bb_dir))


def _load_site_settings(site: str | None) -> dict[str, Any]:
    if not site:
        return {}
    try:
        _ensure_browser_bot_path()
        from browser_bot.sites import load_site_config

        cfg = load_site_config(site)
        return _normalize_settings_dict(cfg.get("settings") if isinstance(cfg.get("settings"), dict) else {})
    except Exception:
        return {}


def _load_component_settings_raw(site: str | None, component: str | None) -> dict[str, Any]:
    if not site or not component:
        return {}
    try:
        _ensure_browser_bot_path()
        from browser_bot.sites import load_component_config_raw

        cfg = load_component_config_raw(site, component)
        return _normalize_settings_dict(cfg.get("settings") if isinstance(cfg.get("settings"), dict) else {})
    except Exception:
        return {}


def parse_browser_config_py() -> dict[str, Any]:
    """Read editable browser settings from config.py (file, not live module)."""
    if not _CONFIG_PY.is_file():
        return {}
    source = _CONFIG_PY.read_text(encoding="utf-8")
    tree = ast.parse(source)
    result: dict[str, Any] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in EDITABLE_BROWSER_VARS:
                    try:
                        val = ast.literal_eval(node.value)
                        if isinstance(val, (set, frozenset)):
                            val = sorted(val)
                        result[target.id] = val
                    except Exception:
                        pass
        elif isinstance(node, ast.AnnAssign):
            if (
                isinstance(node.target, ast.Name)
                and node.target.id in EDITABLE_BROWSER_VARS
                and node.value is not None
            ):
                try:
                    val = ast.literal_eval(node.value)
                    if isinstance(val, (set, frozenset)):
                        val = sorted(val)
                    result[node.target.id] = val
                except Exception:
                    pass
    return result


def get_site_settings_overrides(
    site: str | None = None,
    component: str | None = None,
) -> dict[str, Any]:
    site = (site or os.getenv("AIRTA_SITE") or "").strip() or None
    return _load_site_settings(site)


def get_component_settings_overrides(
    site: str | None = None,
    component: str | None = None,
) -> dict[str, Any]:
    site = (site or os.getenv("AIRTA_SITE") or "").strip() or None
    component = (component or os.getenv("AIRTA_COMPONENT") or "").strip() or None
    return _load_component_settings_raw(site, component)


def get_target_settings_overrides(
    site: str | None = None,
    component: str | None = None,
) -> dict[str, Any]:
    """Merged site + component overrides from config.yaml."""
    site = (site or os.getenv("AIRTA_SITE") or "").strip() or None
    component = (component or os.getenv("AIRTA_COMPONENT") or "").strip() or None
    return _merge_settings_layers(
        _load_site_settings(site),
        _load_component_settings_raw(site, component),
    )


def get_component_overrides(
    site: str | None = None,
    component: str | None = None,
) -> dict[str, Any]:
    """Target overrides (site + component config.yaml settings)."""
    return get_target_settings_overrides(site=site, component=component)


def global_gemini_cache_enabled(*, default: bool | None = None) -> bool:
    raw = _env_value("GEMINI_USE_CACHE", os.getenv("GEMINI_USE_CACHE", "")).strip().lower()
    if raw:
        return raw not in _FALSE
    if default is not None:
        return default
    defs = load_defaults_yaml()
    if "gemini_use_cache" in defs:
        return _parse_bool(defs["gemini_use_cache"], False)
    return False


def get_global_settings() -> dict[str, Any]:
    """Global layer: shipped defaults + config.py + .env (later wins)."""
    out = _merge_settings_layers(load_defaults_yaml(), parse_browser_config_py())
    out["gemini_use_cache"] = global_gemini_cache_enabled()
    return out


def get_global_setting(key: str) -> Any:
    globals_ = get_global_settings()
    if key in globals_:
        return globals_[key]
    return None


def _coerce_setting(key: str, value: Any) -> Any:
    if key == "gemini_use_cache":
        return _parse_bool(value, global_gemini_cache_enabled())
    if key == "BLOCKED_TYPES":
        if value is None:
            return set()
        if isinstance(value, str):
            items = [v.strip() for v in value.split(",") if v.strip()]
            return set(items)
        if isinstance(value, (list, tuple, set, frozenset)):
            return set(value)
        return set()
    if key in {"POOL_SIZE", "CONTEXT_COUNT", "PAGES_PER_CONTEXT", "API_CONCURRENCY", "EVASION_MAX_RETRIES", "HUMAN_READ_DELAY_MS"}:
        return int(value)
    if key in {"EVASION_REQUEST_DELAY_S", "EVASION_RETRY_WAIT_S"}:
        return float(value)
    if key in {
        "POOL_CLUSTER_HUMAN_LIKE", "POOL_CLUSTER_ALLOW_STYLES", "POOL_CLUSTER_USE_STEALTH",
        "POOL_CLUSTER_USE_HUMAN_CHROME", "POOL_CLUSTER_USE_HUMAN_CONTEXT",
        "HUMAN_ALLOW_STYLES", "HUMAN_SCROLL_AFTER_LOAD", "HEADLESS",
    }:
        return _parse_bool(value, False)
    if isinstance(value, str):
        return value
    return value


def get_effective_setting(
    key: str,
    *,
    site: str | None = None,
    component: str | None = None,
) -> Any:
    return get_effective_settings(site=site, component=component).get(key)


def get_effective_settings(
    *,
    site: str | None = None,
    component: str | None = None,
) -> dict[str, Any]:
    site_id = (site or os.getenv("AIRTA_SITE") or "").strip() or None
    component_id = (component or os.getenv("AIRTA_COMPONENT") or "").strip() or None
    merged = _merge_settings_layers(
        load_defaults_yaml(),
        parse_browser_config_py(),
        {"gemini_use_cache": global_gemini_cache_enabled()},
        _load_site_settings(site_id),
        _load_component_settings_raw(site_id, component_id),
    )
    return {k: _coerce_setting(k, v) for k, v in merged.items()}


def _serialize_blocked_types(val: Any) -> Any:
    if isinstance(val, set):
        return sorted(val)
    return val


def get_effective_settings_detail(
    *,
    site: str | None = None,
    component: str | None = None,
) -> dict[str, dict[str, Any]]:
    site_id = (site or os.getenv("AIRTA_SITE") or "").strip() or None
    component_id = (component or os.getenv("AIRTA_COMPONENT") or "").strip() or None
    defaults = load_defaults_yaml()
    globals_ = get_global_settings()
    site_ov = _load_site_settings(site_id)
    comp_ov = _load_component_settings_raw(site_id, component_id)
    detail: dict[str, dict[str, Any]] = {}
    for key in ALL_SETTING_KEYS:
        inherited_at_component = key not in comp_ov
        layers = [defaults, parse_browser_config_py()]
        if key == "gemini_use_cache":
            layers.append({"gemini_use_cache": global_gemini_cache_enabled()})
        else:
            layers.append({})
        layers.extend([site_ov, comp_ov])
        merged = _merge_settings_layers(*layers)
        effective_raw = merged.get(key, globals_.get(key))
        effective = _coerce_setting(key, effective_raw) if effective_raw is not None else None
        detail[key] = {
            "defaults": _serialize_blocked_types(defaults.get(key)),
            "global": _serialize_blocked_types(globals_.get(key)),
            "site_override": site_ov.get(key),
            "override": comp_ov.get(key),
            "effective": _serialize_blocked_types(effective),
            "inherited": inherited_at_component,
        }
    return detail


def component_gemini_cache_override(
    site: str | None = None,
    component: str | None = None,
) -> bool | None:
    site_id = (site or os.getenv("AIRTA_SITE") or "").strip() or None
    component_id = (component or os.getenv("AIRTA_COMPONENT") or "").strip() or None
    merged = _merge_settings_layers(
        _load_site_settings(site_id),
        _load_component_settings_raw(site_id, component_id),
    )
    if "gemini_use_cache" not in merged:
        return None
    return _parse_bool(merged["gemini_use_cache"], global_gemini_cache_enabled())


def gemini_cache_enabled(
    *,
    site: str | None = None,
    component: str | None = None,
    default: bool = False,
) -> bool:
    override = component_gemini_cache_override(site=site, component=component)
    if override is not None:
        return override
    return global_gemini_cache_enabled(default=default)


def apply_browser_settings(
    site: str | None = None,
    component: str | None = None,
    *,
    target_module: Any | None = None,
) -> dict[str, Any]:
    """Apply browser-related target overrides (site + component) to browser_bot.config."""
    overrides = get_target_settings_overrides(site=site, component=component)
    browser_overrides = {
        k: _coerce_setting(k, v) for k, v in overrides.items() if k in EDITABLE_BROWSER_VARS
    }
    if not browser_overrides:
        return {}

    if target_module is None:
        bb_dir = _ROOT / "browser-bot"
        if str(bb_dir) not in sys.path:
            sys.path.insert(0, str(bb_dir))
        import browser_bot.config as target_module  # type: ignore[import]

    for key, value in browser_overrides.items():
        setattr(target_module, key, value)
    return browser_overrides


def settings_schema_payload() -> dict[str, Any]:
    defaults = load_defaults_yaml()
    globals_ = get_global_settings()
    for key, val in list(globals_.items()):
        if key == "BLOCKED_TYPES" and isinstance(val, set):
            globals_[key] = sorted(val)
    for key, val in list(defaults.items()):
        if key == "BLOCKED_TYPES" and isinstance(val, set):
            defaults[key] = sorted(val)
    return {
        "groups": SETTING_GROUPS,
        "meta": SETTING_META,
        "keys": sorted(ALL_SETTING_KEYS),
        "defaults": defaults,
        "defaults_path": str(_DEFAULTS_YAML.relative_to(_ROOT)),
        "globals": globals_,
    }
