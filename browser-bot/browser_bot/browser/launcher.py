"""Browser and context launchers.

Unified flow: login, refresh, fetch, and POST all use launch_context_for_request()
when FETCH_METHOD=human, ensuring consistent stealth, fingerprint, and behavior.
"""

import json
from pathlib import Path

from browser_bot.browser.routes import block_resources, get_blocked_types
from browser_bot.config import (
    CHROME_ARGS,
    CHROMIUM_EXECUTABLE_PATH,
    CHROME_CHANNEL,
    FETCH_METHOD,
    HEADLESS,
    HUMAN_ALLOW_STYLES,
    HUMAN_CHROME_ARGS,
    HUMAN_USER_AGENT,
    LOCALSTORAGE_MAX_VALUE_LEN,
    LOGIN_USE_PERSISTENT_CONTEXT,
    get_discovery_context_opts,
    get_human_context_opts,
)


def _launch_options(human_mode: bool = False, headless: bool | None = None):
    """Return launch options dict for chromium.launch()."""
    args = HUMAN_CHROME_ARGS if (human_mode and HUMAN_CHROME_ARGS) else CHROME_ARGS
    opts = {"headless": headless if headless is not None else HEADLESS, "args": args}
    if human_mode and CHROME_CHANNEL:
        opts["channel"] = CHROME_CHANNEL
    elif CHROMIUM_EXECUTABLE_PATH:
        opts["executable_path"] = CHROMIUM_EXECUTABLE_PATH
    return opts


def _load_auth_config(path: Path) -> dict | list | None:
    """Load auth config from auth.json or storage_state.json."""
    if not path or not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def _normalize_auth_config(raw: dict | list) -> dict:
    """Convert auth config to standard format. Handles raw cookie list from browser extensions."""
    if isinstance(raw, dict) and "cookies" in raw:
        return raw
    if isinstance(raw, list):
        # Raw cookie export from extension (Cookie-Editor, EditThisCookie, etc.)
        cookies = []
        for c in raw:
            if not isinstance(c, dict) or "name" not in c or "value" not in c:
                continue
            pw = {
                "name": c["name"],
                "value": c["value"],
                "domain": c.get("domain", ""),
                "path": c.get("path", "/"),
                "httpOnly": c.get("httpOnly", False),
                "secure": c.get("secure", False),
            }
            exp = c.get("expirationDate") or c.get("expires")
            if exp is not None and not c.get("session"):
                pw["expires"] = int(exp) if isinstance(exp, (int, float)) else exp
            same = c.get("sameSite", "Lax")
            if same in ("Strict", "Lax", "None"):
                pw["sameSite"] = same
            else:
                pw["sameSite"] = "Lax"
            cookies.append(pw)
        return {"cookies": cookies, "origins": [], "headers": {}}
    return {"cookies": [], "origins": [], "headers": {}}


def _filter_storage_items(items: list, max_len: int) -> list:
    """Exclude storage items (localStorage/sessionStorage) with value length > max_len."""
    return [i for i in items if len(str(i.get("value", ""))) <= max_len]


def _storage_state_from_auth(config: dict) -> dict:
    """Extract Playwright storage_state (cookies + localStorage) from auth config.
    Excludes localStorage items with value length > LOCALSTORAGE_MAX_VALUE_LEN.
    """
    max_len = LOCALSTORAGE_MAX_VALUE_LEN
    return {
        "cookies": config.get("cookies", []),
        "origins": [
            {
                "origin": o["origin"],
                "localStorage": _filter_storage_items(o.get("localStorage", []), max_len),
            }
            for o in config.get("origins", [])
        ],
    }


async def launch_browser(playwright, human_mode: bool = False, headless: bool | None = None):
    """Launch ephemeral browser (no persistent profile).
    human_mode: use HUMAN_CHROME_ARGS (fewer automation flags) for stealth.
    headless: override config (e.g. False for login).
    """
    browser = await playwright.chromium.launch(
        **_launch_options(human_mode=human_mode, headless=headless)
    )
    return browser


def _is_human_mode() -> bool:
    """True when FETCH_METHOD selects human tier."""
    return FETCH_METHOD.lower() == "human"


async def apply_human_stealth_async(context) -> None:
    """Apply playwright-stealth to a browser context (same options as human tier)."""
    import platform as _platform

    from playwright_stealth import Stealth

    opts = get_human_context_opts()
    locale = opts["locale"]
    base = locale.split("-")[0] if "-" in locale else locale
    _plat = _platform.system()
    platform_override = "Win32" if _plat == "Windows" else "MacIntel" if _plat == "Darwin" else "Linux x86_64"
    stealth_opts = {
        "navigator_languages_override": (locale, base),
        "navigator_platform_override": platform_override,
    }
    if HUMAN_USER_AGENT:
        stealth_opts["navigator_user_agent_override"] = HUMAN_USER_AGENT
    stealth = Stealth(**stealth_opts)
    await stealth.apply_stealth_async(context)


async def new_pool_cluster_browser_context(
    browser,
    storage_state_path: str | None = None,
    *,
    full_human_tier_bundle: bool = False,
    allow_styles: bool = False,
    use_stealth: bool = False,
    use_human_context: bool = False,
):
    """
    Create a context for pool/cluster tiers.
    When full_human_tier_bundle=True: same as full human tier (styles, context opts, stealth).
    Otherwise combine granular flags (for A/B testing).
    """
    if full_human_tier_bundle:
        context = await launch_context_with_routes(
            browser,
            storage_state_path=storage_state_path,
            allow_styles=HUMAN_ALLOW_STYLES,
            **get_human_context_opts(),
        )
        await apply_human_stealth_async(context)
        return context

    context_opts = get_human_context_opts() if use_human_context else {}
    styles_for_route = (allow_styles and HUMAN_ALLOW_STYLES) or False
    context = await launch_context_with_routes(
        browser,
        storage_state_path=storage_state_path,
        allow_styles=styles_for_route,
        **context_opts,
    )
    if use_stealth:
        await apply_human_stealth_async(context)
    return context


def _clear_stale_profile_locks(user_data_dir: str) -> None:
    """Remove Chromium Singleton* locks that block re-launch when a prior session
    didn't shut down cleanly. Safe no-op when files don't exist."""
    p = Path(user_data_dir)
    if not p.exists():
        return
    for name in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
        target = p / name
        try:
            if target.is_symlink() or target.exists():
                target.unlink()
        except FileNotFoundError:
            pass
        except Exception:
            pass


async def launch_persistent_context(
    playwright, user_data_dir: str, *, headless: bool = False
) -> tuple[None, "BrowserContext"]:
    """
    Launch Chrome with persistent profile for login. Google trusts real profiles more.
    Returns (None, context). Caller closes context only (no separate browser).
    """
    from playwright.async_api import BrowserContext

    args = list(HUMAN_CHROME_ARGS or CHROME_ARGS)
    if "--disable-blink-features=AutomationControlled" not in args:
        args.insert(0, "--disable-blink-features=AutomationControlled")

    opts = {
        **get_discovery_context_opts(),
        "headless": headless,
        "args": args,
        "accept_downloads": True,
    }
    if CHROME_CHANNEL:
        opts["channel"] = CHROME_CHANNEL
    elif CHROMIUM_EXECUTABLE_PATH:
        opts["executable_path"] = CHROMIUM_EXECUTABLE_PATH

    _clear_stale_profile_locks(user_data_dir)

    try:
        context = await playwright.chromium.launch_persistent_context(user_data_dir, **opts)
    except Exception as exc:
        msg = str(exc).lower()
        if "closed" in msg or "target" in msg or "browser" in msg:
            _clear_stale_profile_locks(user_data_dir)
            context = await playwright.chromium.launch_persistent_context(user_data_dir, **opts)
        else:
            raise

    import platform as _platform
    from playwright_stealth import Stealth
    from browser_bot.config import get_human_context_opts

    opts_human = get_human_context_opts()
    locale = opts_human["locale"]
    base = locale.split("-")[0] if "-" in locale else locale
    _plat = _platform.system()
    platform_override = "Win32" if _plat == "Windows" else "MacIntel" if _plat == "Darwin" else "Linux x86_64"
    stealth_opts = {
        "navigator_languages_override": (locale, base),
        "navigator_platform_override": platform_override,
    }
    if HUMAN_USER_AGENT:
        stealth_opts["navigator_user_agent_override"] = HUMAN_USER_AGENT
    stealth = Stealth(**stealth_opts)
    await stealth.apply_stealth_async(context)

    return None, context


async def launch_persistent_context_for_login(playwright, user_data_dir: str) -> tuple[None, "BrowserContext"]:
    """Backward-compatible login wrapper using a visible persistent context."""
    return await launch_persistent_context(playwright, user_data_dir, headless=False)


async def launch_context_for_request(
    playwright,
    storage_state_path: str | None = None,
    storage_state: dict | None = None,
    *,
    headless: bool | None = None,
    allow_styles: bool | None = None,
    allow_all: bool = False,
    force_human: bool = False,
    discovery_layout: bool = False,
):
    """
    Unified browser+context for all requests (login, refresh, fetch, POST).
    Uses FETCH_METHOD (or force_human): when human, applies stealth, human context opts, human Chrome args.
    Returns (browser, context). Caller must close both.

    storage_state_path: path to auth.json or storage_state.json (loads from file).
    storage_state: dict storage state (overrides path when provided, e.g. for refresh with excluded cookies).
    headless: override (e.g. False for login).
    allow_styles: when True, don't block stylesheets. Default: HUMAN_ALLOW_STYLES when human.
    allow_all: when True, no resource blocking (full page load, e.g. login).
    force_human: when True, use human flow even if FETCH_METHOD != human (e.g. HumanFetcher fallback).
    discovery_layout: when True with human, use fixed DISCOVERY_VIEWPORT instead of random viewport.
    """
    human = force_human or _is_human_mode()
    browser = await launch_browser(playwright, human_mode=human, headless=headless)

    if human:
        context_opts = get_discovery_context_opts() if discovery_layout else get_human_context_opts()
    else:
        context_opts = {}
    styles = allow_styles if allow_styles is not None else (human and HUMAN_ALLOW_STYLES)

    context = await launch_context_with_routes(
        browser,
        storage_state_path=storage_state_path,
        storage_state=storage_state,
        allow_styles=styles,
        allow_all=allow_all,
        **context_opts,
    )

    if human:
        await apply_human_stealth_async(context)

    return browser, context


async def launch_context_with_routes(
    browser,
    storage_state_path: str | None = None,
    storage_state: dict | None = None,
    allow_styles: bool = False,
    allow_all: bool = False,
    **context_opts,
):
    """
    Create a new context. Optionally load full auth from path or pass storage_state dict.
    Supports auth.json (cookies, localStorage, sessionStorage, headers) and legacy storage_state.json.
    context_opts: merged into new_context() (e.g. locale, timezone_id, geolocation, viewport).
    storage_state: when provided, used directly (overrides path); e.g. for refresh with excluded cookies.
    allow_all: when True, skip resource blocking (full page load).
    """
    opts = dict(context_opts)
    session_by_origin: dict[str, list] = {}
    headers: dict[str, str] = {}

    if storage_state is not None:
        opts["storage_state"] = storage_state
    elif storage_state_path:
        path = Path(storage_state_path)
        config = _load_auth_config(path)
        if config:
            if path.name == "auth.json":
                config = _normalize_auth_config(config)
                # Full auth: apply storage_state, sessionStorage init script, headers
                opts["storage_state"] = _storage_state_from_auth(config)
                for origin in config.get("origins", []):
                    if origin.get("sessionStorage"):
                        session_by_origin[origin["origin"]] = _filter_storage_items(
                            origin["sessionStorage"], LOCALSTORAGE_MAX_VALUE_LEN
                        )
                # Don't apply Authorization header - cookies are sent automatically and
                # many APIs use cookie auth; adding Bearer can cause "invalid_api_key_format"
                headers = {k: v for k, v in config.get("headers", {}).items() if k.lower() != "authorization"}
            else:
                # Legacy storage_state.json
                opts["storage_state"] = str(path)

    context = await browser.new_context(**opts)
    if not allow_all:
        blocked = get_blocked_types(allow_styles=allow_styles)

        async def route_handler(route):
            await block_resources(route, blocked)

        await context.route("**/*", route_handler)

    # Inject sessionStorage via init script (auth.json only)
    if session_by_origin:
        import json as _json

        script = f"""
            (function() {{
                const data = {_json.dumps(session_by_origin)};
                const origin = location.origin;
                if (data[origin]) {{
                    data[origin].forEach(item => sessionStorage.setItem(item.name, item.value));
                }}
            }})();
        """
        await context.add_init_script(script)

    # Set extra HTTP headers (auth.json only)
    if headers:
        await context.set_extra_http_headers(headers)

    return context
