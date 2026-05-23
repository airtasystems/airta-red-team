"""Configuration for browser-bot."""

import json
import random
from pathlib import Path

_CONFIG_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _CONFIG_DIR.parent
_POSTS_DIR = _PROJECT_ROOT / "posts"

# Default URL when posts.json has plain strings (legacy). Set to "" to require full {url, ...} objects.
POST_DEFAULT_URL = ""


def _load_posts():
    """Load POST configs from posts/posts.json (or posts.json at root). Each entry: {url, data?, json?, headers?}."""
    for posts_path in (_POSTS_DIR / "posts.json", _PROJECT_ROOT / "posts.json"):
        if posts_path.exists():
            break
    else:
        return []
    with open(posts_path) as f:
        raw = json.load(f)
    if not isinstance(raw, list):
        return []
    default_url = POST_DEFAULT_URL
    result = []
    for p in raw:
        if isinstance(p, dict) and p.get("url"):
            result.append({
                "url": p["url"],
                "data": p.get("data"),
                "json": p.get("json"),
                "headers": p.get("headers"),
            })
        elif isinstance(p, str) and p.strip() and default_url:
            result.append({"url": default_url, "json": {"body": p}})
    return result


POSTS = _load_posts()


def _prompts_from_mandates_bundle(data: dict) -> list[str]:
    """Extract prompt strings from suite JSON: categories[].prompts[].prompt or mandates[]."""
    out: list[str] = []
    mandates = data.get("categories") or data.get("mandates")
    if not isinstance(mandates, list):
        return out
    for m in mandates:
        if not isinstance(m, dict):
            continue
        prompts = m.get("prompts")
        if not isinstance(prompts, list):
            continue
        for item in prompts:
            if not isinstance(item, dict):
                continue
            p = item.get("prompt")
            if isinstance(p, str) and p.strip():
                out.append(p.strip())
    return out


def _prompts_from_top_level_prompts(data: dict) -> list[str]:
    """Extract from {"prompts": [{"prompt": "..."}, ...]}."""
    out: list[str] = []
    prompts = data.get("prompts")
    if not isinstance(prompts, list):
        return out
    for item in prompts:
        if not isinstance(item, dict):
            continue
        p = item.get("prompt")
        if isinstance(p, str) and p.strip():
            out.append(p.strip())
    return out


def _coerce_posts_single_raw(raw) -> list[str]:
    """Turn posts_single payload into prompt strings; [] if shape is not for UI single mode."""
    if isinstance(raw, dict):
        if isinstance(raw.get("categories"), list) or isinstance(raw.get("mandates"), list):
            return _prompts_from_mandates_bundle(raw)
        return _prompts_from_top_level_prompts(raw)
    if not isinstance(raw, list):
        return []
    result: list[str] = []
    for p in raw:
        if isinstance(p, str) and p.strip():
            result.append(p.strip())
        elif isinstance(p, dict):
            if p.get("url"):
                continue
            body = p.get("json", {}).get("body") if isinstance(p.get("json"), dict) else None
            if body and isinstance(body, str) and body.strip():
                result.append(body.strip())
    return result


def _posts_single_candidate_paths() -> list[Path]:
    """Prefer posts/posts_single.json, then project root, then legacy posts.json."""
    return [
        _POSTS_DIR / "posts_single.json",
        _PROJECT_ROOT / "posts_single.json",
        _PROJECT_ROOT / "posts.json",
    ]


def get_suite_test_cases(suite_path: Path | str | None = None) -> list[dict]:
    """Load full test case dicts (prompt, vector_type, payload) from a suite file."""
    if not suite_path:
        return []
    try:
        from browser_bot.artifacts import load_suite_test_cases

        return load_suite_test_cases(suite_path)
    except Exception:
        return []


def get_posts_strings(suite_path: Path | None = None) -> list[str]:
    """Load string bodies for UI submission mode.

    When suite_path is provided it is read directly (no fallback search).
    Otherwise tries, in order, the first path that exists and yields at least one prompt:
    - posts/posts_single.json
    - posts_single.json (project root)
    - posts.json (project root, legacy)

    Supported shapes:
    - FRIA bundle: {"mandates": [{"prompts": [{"prompt": "..."}, ...]}, ...]}
    - Flat: {"prompts": [{"prompt": "..."}, ...]}
    - Legacy: ["plain string", ...]
    - Legacy: [{"json": {"body": "..."}}, ...] (entries with \"url\" are skipped)
    """
    candidate_paths = [suite_path] if suite_path else _posts_single_candidate_paths()
    for posts_path in candidate_paths:
        if not Path(posts_path).is_file():
            continue
        try:
            with open(posts_path, encoding="utf-8-sig") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        result = _coerce_posts_single_raw(raw)
        if result:
            return [_apply_ui_prompt_transform(t) for t in result]
    return []


def _batch_from_multi_prompt_item(item: dict) -> list[str]:
    """FRIA multi test case: object with \"prompts\" array of strings (one multi-shot batch)."""
    ps = item.get("prompts")
    if not isinstance(ps, list):
        return []
    out: list[str] = []
    for s in ps:
        if isinstance(s, str) and s.strip():
            out.append(s.strip())
    return out


def _batches_from_multi_mandates_bundle(data: dict) -> list[list[str]]:
    """Multi bundle: categories[].prompts[] or mandates[].prompts[] with prompts arrays."""
    out: list[list[str]] = []
    mandates = data.get("categories") or data.get("mandates")
    if not isinstance(mandates, list):
        return out
    for m in mandates:
        if not isinstance(m, dict):
            continue
        prompts = m.get("prompts")
        if not isinstance(prompts, list):
            continue
        for item in prompts:
            if not isinstance(item, dict):
                continue
            batch = _batch_from_multi_prompt_item(item)
            if batch:
                out.append(batch)
    return out


def _coerce_posts_multi_from_list(raw: list) -> list[list[str]]:
    """Legacy: [[\"a\",\"b\"], ...], or top-level strings / json.body dicts as single-item batches."""
    result: list[list[str]] = []
    for p in raw:
        if isinstance(p, list):
            batch: list[str] = []
            for item in p:
                if isinstance(item, str) and item.strip():
                    batch.append(item.strip())
                elif isinstance(item, dict):
                    if item.get("url"):
                        continue
                    body = item.get("json", {}).get("body") if isinstance(item.get("json"), dict) else None
                    if body and isinstance(body, str) and body.strip():
                        batch.append(body.strip())
            if batch:
                result.append(batch)
        elif isinstance(p, str) and p.strip():
            result.append([p.strip()])
        elif isinstance(p, dict):
            if p.get("url"):
                continue
            body = p.get("json", {}).get("body") if isinstance(p.get("json"), dict) else None
            if body and isinstance(body, str) and body.strip():
                result.append([body.strip()])
    return result


def _coerce_posts_multi_raw(raw) -> list[list[str]]:
    if isinstance(raw, dict):
        if isinstance(raw.get("categories"), list) or isinstance(raw.get("mandates"), list):
            b = _batches_from_multi_mandates_bundle(raw)
            if b:
                return b
        batches = raw.get("batches")
        if isinstance(batches, list):
            return _coerce_posts_multi_from_list(batches)
        return []
    if isinstance(raw, list):
        return _coerce_posts_multi_from_list(raw)
    return []


def infer_ui_mode_from_suite_raw(raw) -> str | None:
    """Infer UI submission mode from suite JSON shape.

    Returns ``\"multi\"`` when multi-turn batches exist (e.g. tree-of-thoughts: ``prompts``: [str, ...]).
    Returns ``\"single\"`` when only flat single prompts exist (e.g. zero-shot: ``prompt`` per case).
    Returns ``None`` if neither coercion yields prompts.
    """
    if _coerce_posts_multi_raw(raw):
        return "multi"
    if _coerce_posts_single_raw(raw):
        return "single"
    return None


def _posts_multi_candidate_paths() -> list[Path]:
    return [
        _POSTS_DIR / "posts_multi.json",
        _PROJECT_ROOT / "posts_multi.json",
        _PROJECT_ROOT / "posts.json",
    ]


def get_posts_batches(suite_path: Path | None = None) -> list[list[str]]:
    """Load batches for multi UI submission mode.

    When suite_path is provided it is read directly (no fallback search).
    Otherwise tries, in order, the first path that exists and yields at least one batch:
    - posts/posts_multi.json
    - posts_multi.json (project root)
    - posts.json (project root, legacy)

    Supported shapes:
    - FRIA multi bundle: {\"mandates\": [{\"prompts\": [{\"prompts\": [\"...\", ...]}, ...]}, ...]}
    - Flat: {\"batches\": [[\"a\",\"b\"], ...]}
    - Legacy: [[\"a\",\"b\",\"c\"], ...] (array of arrays)
    """
    candidate_paths = [suite_path] if suite_path else _posts_multi_candidate_paths()
    for posts_path in candidate_paths:
        if not Path(posts_path).is_file():
            continue
        try:
            with open(posts_path, encoding="utf-8-sig") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        result = _coerce_posts_multi_raw(raw)
        if result:
            return [
                [_apply_ui_prompt_transform(s) for s in batch] for batch in result
            ]
    return []


# --- UI submission: optional suffix on every prompt + max submitted length ---
# Appended to each prompt (single and multi) before fill/submit. Separator sits between body and suffix.
# When UI_PROMPT_MAX_CHARS > 0, the final string is capped: suffix is kept, body is truncated if needed.
# Name UI_PROMPT_PREFIX is historical; value is appended to the user message.
UI_PROMPT_PREFIX = ""
UI_PROMPT_PREFIX_SEPARATOR = ""
UI_PROMPT_MAX_CHARS = 600  # 0 = no length cap


def _apply_ui_prompt_transform(text: str) -> str:
    """Body + optional suffix, then cap total length when UI_PROMPT_MAX_CHARS > 0."""
    suffix = UI_PROMPT_PREFIX or ""
    sep = UI_PROMPT_PREFIX_SEPARATOR or ""
    max_c = UI_PROMPT_MAX_CHARS
    body = text.strip()
    tail = f"{sep}{suffix}" if suffix else ""
    if suffix:
        if max_c and max_c > 0:
            room = max_c - len(tail)
            if room < 1:
                return tail[:max_c]
            truncated = body[:room] if len(body) > room else body
            return truncated + tail
        return body + tail
    if max_c and max_c > 0 and len(body) > max_c:
        return body[:max_c]
    return body


# --- Fetch method selection ---
# "auto" = try tiers in order (pool → cluster → human)
# "pool" | "cluster" | "human" = use only that method
FETCH_METHOD = 'pool'

# --- Pool (Tier 1: Full speed) ---
POOL_SIZE = 8

# --- Pool + cluster browser (shared by FETCH_METHOD pool and cluster) ---
# When True, enable all flags below (human Chrome, styles, stealth, context opts).
POOL_CLUSTER_HUMAN_LIKE = False
# A/B test individually (ignored when POOL_CLUSTER_HUMAN_LIKE is True):
# 1 = stylesheets   2 = playwright-stealth   3 = HUMAN_CHROME_ARGS   4 = locale/viewport/geo UA
POOL_CLUSTER_ALLOW_STYLES = False
POOL_CLUSTER_USE_STEALTH = False
POOL_CLUSTER_USE_HUMAN_CHROME = False
POOL_CLUSTER_USE_HUMAN_CONTEXT = False


def get_pool_cluster_browser_enhancements():
    """Return (use_human_chrome, allow_styles, use_stealth, use_human_context) for pool and cluster setup."""
    if POOL_CLUSTER_HUMAN_LIKE:
        return True, True, True, True
    return (
        POOL_CLUSTER_USE_HUMAN_CHROME,
        POOL_CLUSTER_ALLOW_STYLES,
        POOL_CLUSTER_USE_STEALTH,
        POOL_CLUSTER_USE_HUMAN_CONTEXT,
    )

# --- Cluster (Tier 2: Max power) ---
CONTEXT_COUNT = 8
PAGES_PER_CONTEXT = 6

# --- API submission ---
# Max concurrent HTTP requests when transport is api (1 = fully sequential).
API_CONCURRENCY: int = 8

# --- Evasion ---
# Delay inserted between consecutive sequential submissions to avoid burst-rate detection.
EVASION_REQUEST_DELAY_S: float = 0.5
# How long to wait before retrying after a non-2xx response (e.g. 429 / 5xx).
EVASION_RETRY_WAIT_S: float = 10.0
# Maximum number of retries per prompt before giving up and recording None.
EVASION_MAX_RETRIES: int = 3

# --- Auth storage ---
# Exclude localStorage/sessionStorage items with value length over this (reduces auth.json bloat)
LOCALSTORAGE_MAX_VALUE_LEN = 8192

# --- Human (Tier 3: Stealth) ---
# New context per request, no pool. Maximizes human resemblance.
HUMAN_COUNTRY = 'UK'
HUMAN_VIEWPORT = None  # None = random from common resolutions
HUMAN_ALLOW_STYLES = True
HUMAN_READ_DELAY_MS = 600
HUMAN_SCROLL_AFTER_LOAD = False
# Recent Chrome UA. None = use Playwright default (stealth still patches navigator).
HUMAN_USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
# Chrome args for human tier (fewer automation flags). None = use CHROME_ARGS.
# --disable-blink-features=AutomationControlled: avoids Google "This browser or app may not be secure"
HUMAN_CHROME_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--disable-infobars",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-sync",
    "--disable-notifications",
    "--no-first-run",
    "--no-default-browser-check",
    "--mute-audio",
]

# Country presets: locale, timezone, geolocation (lat, lon)
_COUNTRY_PRESETS = {
    "US": {"locale": "en-US", "timezone": "America/New_York", "lat": 40.7128, "lon": -74.0060},
    "UK": {"locale": "en-GB", "timezone": "Europe/London", "lat": 51.5074, "lon": -0.1278},
    "DE": {"locale": "de-DE", "timezone": "Europe/Berlin", "lat": 52.5200, "lon": 13.4050},
    "FR": {"locale": "fr-FR", "timezone": "Europe/Paris", "lat": 48.8566, "lon": 2.3522},
    "JP": {"locale": "ja-JP", "timezone": "Asia/Tokyo", "lat": 35.6762, "lon": 139.6503},
    "CA": {"locale": "en-CA", "timezone": "America/Toronto", "lat": 43.6532, "lon": -79.3832},
    "AU": {"locale": "en-AU", "timezone": "Australia/Sydney", "lat": -33.8688, "lon": 151.2093},
    "NL": {"locale": "nl-NL", "timezone": "Europe/Amsterdam", "lat": 52.3676, "lon": 4.9041},
    "ES": {"locale": "es-ES", "timezone": "Europe/Madrid", "lat": 40.4168, "lon": -3.7038},
    "IT": {"locale": "it-IT", "timezone": "Europe/Rome", "lat": 41.9028, "lon": 12.4964},
}

# Common viewport resolutions for human-like randomization
_HUMAN_VIEWPORTS = [
    {"width": 1020, "height": 880},
    {"width": 1066, "height": 668},
    {"width": 536, "height": 464},
    {"width": 400, "height": 600},
    {"width": 800, "height": 640},
]

# Fixed size for interactive discovery (login capture, selector recording, company rubric).
# Avoids tiny random viewports that make manual use awkward.
DISCOVERY_VIEWPORT = {"width": 1440, "height": 900}


def get_discovery_context_opts():
    """Locale/geo from HUMAN_COUNTRY but fixed viewport — for login & discovery UIs."""
    country = HUMAN_COUNTRY.upper()
    preset = _COUNTRY_PRESETS.get(country, _COUNTRY_PRESETS["US"])
    vp = dict(DISCOVERY_VIEWPORT)
    opts = {
        "locale": preset["locale"],
        "timezone_id": preset["timezone"],
        "geolocation": {"latitude": preset["lat"], "longitude": preset["lon"]},
        "permissions": ["geolocation"],
        "viewport": vp,
        "device_scale_factor": 1,
        "color_scheme": "light",
        "has_touch": False,
        "is_mobile": False,
        "screen": vp,
    }
    if HUMAN_USER_AGENT:
        opts["user_agent"] = HUMAN_USER_AGENT
    return opts


def get_human_context_opts():
    """Return context options for human tier (locale, timezone, geolocation, viewport)."""
    country = HUMAN_COUNTRY.upper()
    preset = _COUNTRY_PRESETS.get(country, _COUNTRY_PRESETS["US"])
    viewport = HUMAN_VIEWPORT or random.choice(_HUMAN_VIEWPORTS)
    opts = {
        "locale": preset["locale"],
        "timezone_id": preset["timezone"],
        "geolocation": {"latitude": preset["lat"], "longitude": preset["lon"]},
        "permissions": ["geolocation"],
        "viewport": viewport,
        "device_scale_factor": 1,
        "color_scheme": "light",
        "has_touch": False,
        "is_mobile": False,
        "screen": viewport,
    }
    if HUMAN_USER_AGENT:
        opts["user_agent"] = HUMAN_USER_AGENT
    return opts


# --- Browser ---
BLOCKED_TYPES = set()
HEADLESS = True
# System chromium-browser (Linux). Set to None to use Playwright's bundled Chromium.
CHROMIUM_EXECUTABLE_PATH = '/usr/bin/chromium-browser'
# Use real Chrome for human/login (Google trusts it more). Set to "chrome" if Chromium is blocked.
# Requires: playwright install chrome
CHROME_CHANNEL = 'chromium'
# Use persistent browser profile for severe login blocker issues
LOGIN_USE_PERSISTENT_CONTEXT = False

CHROME_ARGS = [
    "--disable-background-networking",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-breakpad",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-features=Translate",
    "--disable-ipc-flooding-protection",
    "--disable-popup-blocking",
    "--disable-renderer-backgrounding",
    "--disable-sync",
    "--no-first-run",
    "--no-default-browser-check",
    "--mute-audio",
    "--disable-gpu",
    "--disable-software-rasterizer",
    "--disable-logging",
    "--disable-notifications",
    "--disable-infobars",
    "--disable-session-crashed-bubble",
    "--disable-features=InterestFeedContentSuggestions",
    "--disable-client-side-phishing-detection",
    "--disable-hang-monitor"
]


def apply_component_settings(site: str | None = None, component: str | None = None) -> dict:
    """Apply per-component browser settings from config.yaml to this module."""
    import os
    import sys
    from pathlib import Path

    site = (site or os.getenv("AIRTA_SITE") or "").strip() or None
    component = (component or os.getenv("AIRTA_COMPONENT") or "").strip() or None
    if not site or not component:
        return {}

    root = Path(__file__).resolve().parent.parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from pipeline.component_settings import apply_browser_settings

    return apply_browser_settings(site, component, target_module=sys.modules[__name__])
