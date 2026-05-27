"""Login flow: open browser, user logs in, save full auth state."""

import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright

from browser_bot.auth_state import get_auth_config_path, save_auth_config
from browser_bot.browser.launcher import launch_persistent_context_for_login
from browser_bot.config import LOCALSTORAGE_MAX_VALUE_LEN, LOGIN_USE_PERSISTENT_CONTEXT
from browser_bot.sites import ensure_site_dir, get_domain_from_url, get_login_profile_path, validate_login_url


def _filter_storage_items(items: list, max_len: int) -> list:
    """Exclude storage items with value length > max_len."""
    return [i for i in items if len(str(i.get("value", ""))) <= max_len]


async def _wait_for_enter():
    """Non-blocking wait for Enter key."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, input)


def _build_config_from_page(storage: dict, session_items: list, page_origin: str, max_len: int) -> dict:
    """Build auth config from storage_state and sessionStorage."""
    config = {
        "cookies": storage["cookies"],
        "origins": [
            {
                "origin": o["origin"],
                "localStorage": _filter_storage_items(o.get("localStorage", []), max_len),
            }
            for o in storage["origins"]
        ],
        "headers": {},
    }
    session_items = _filter_storage_items(session_items, max_len)
    origin_found = False
    for origin in config["origins"]:
        if origin.get("origin") == page_origin:
            origin["sessionStorage"] = session_items
            origin_found = True
            break
    if not origin_found:
        config["origins"].append({
            "origin": page_origin,
            "localStorage": [],
            "sessionStorage": session_items,
        })
    return config


async def capture_login(login_url: str, *, force_persistent: bool = False) -> str | None:
    """
    Open headful browser, navigate to login_url, wait for user to log in,
    then save full auth state: cookies, localStorage, sessionStorage, headers.
    If auth already exists for this domain, loads it so the user starts logged in.
    Uses the human browser flow for non-persistent login.
    Returns domain on success.
    force_persistent=True forces persistent profile login flow even if config disables it.
    """
    login_url = validate_login_url(login_url)
    if not login_url:
        print("[!] Invalid login URL: must be a non-empty http(s) URL with a host.", flush=True)
        return None

    domain = get_domain_from_url(login_url)
    if not domain:
        print("[!] Could not extract domain from login URL.", flush=True)
        return None

    ensure_site_dir(domain)
    auth_path = get_auth_config_path(domain)
    storage_path = str(auth_path) if auth_path and auth_path.exists() else None

    async with async_playwright() as p:
        use_persistent = LOGIN_USE_PERSISTENT_CONTEXT or force_persistent
        if use_persistent:
            profile_path = get_login_profile_path(domain)
            profile_path.mkdir(parents=True, exist_ok=True)
            browser, context = await launch_persistent_context_for_login(p, str(profile_path), site=domain)
            page = await context.new_page()
            await page.goto(login_url, wait_until="domcontentloaded", timeout=60000)
            print(f"\n  Log in at {login_url}")
            print("  Press Enter when you're done logging in...")
            await _wait_for_enter()
            storage = await context.storage_state()
            session_items = await page.evaluate(
                """() => Object.entries(sessionStorage).map(([name, value]) => ({name, value}))"""
            )
            parsed = urlparse(page.url)
            page_origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ""
            config = _build_config_from_page(storage, session_items, page_origin, LOCALSTORAGE_MAX_VALUE_LEN)
            await context.close()
            if browser:
                await browser.close()
        else:
            from main import run_with_page_from_fetchers

            async def _do_login(page):
                await page.goto(login_url, wait_until="domcontentloaded", timeout=60000)
                print(f"\n  Log in at {login_url}")
                if storage_path:
                    print("  (Loaded existing auth. Re-login if needed, then press Enter to save.)")
                print("  Press Enter when you're done logging in...")
                await _wait_for_enter()
                storage = await page.context.storage_state()
                session_items = await page.evaluate(
                    """() => Object.entries(sessionStorage).map(([name, value]) => ({name, value}))"""
                )
                parsed = urlparse(page.url)
                page_origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ""
                return _build_config_from_page(storage, session_items, page_origin, LOCALSTORAGE_MAX_VALUE_LEN)

            config = await run_with_page_from_fetchers(
                p, domain, _do_login, storage_path=storage_path, interactive=True
            )
            if config is None:
                return None

    save_auth_config(domain, config)

    # Remove legacy storage_state.json if present (we now use auth.json)
    from browser_bot.auth_state import get_auth_path
    from browser_bot.sites import STORAGE_STATE_FILE

    legacy = get_auth_path(domain) / STORAGE_STATE_FILE
    if legacy.exists():
        legacy.unlink()

    return domain
