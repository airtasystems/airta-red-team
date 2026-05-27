"""Detect login walls, cookie banners, and submission readiness before UI submit."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from browser_bot.auth_state import load_auth_config
from browser_bot.sites import load_component_config, load_component_config_raw, save_component_config

if TYPE_CHECKING:
    from playwright.async_api import Page

LOGIN_URL_MARKERS = ("/login", "/signin", "/sign-in", "/auth", "/oauth", "/sso")

LOGIN_BODY_PHRASES = (
    "log in or sign up",
    "log in to continue",
    "sign in to continue",
    "sign in or sign up",
    "continue with google",
    "continue with apple",
    "continue with microsoft",
)

LOGIN_WALL_SELECTORS = (
    'text=Log in or sign up',
    'text=Log in to continue',
    'text=Sign in to continue',
    'button:has-text("Continue with Google")',
    'button:has-text("Continue with Apple")',
    'button:has-text("Continue with Microsoft")',
)

DEFAULT_COOKIE_SELECTORS = (
    'button:has-text("Accept all")',
    'button:has-text("Accept All")',
    'button:has-text("Accept")',
    'button:has-text("I agree")',
    'button:has-text("Allow all")',
    'button:has-text("Reject all")',
    'button:has-text("Got it")',
)

CAPTCHA_HINTS = (
    "captcha",
    "recaptcha",
    "hcaptcha",
    "verify you are human",
    "security check",
)

CLOUDFLARE_HINTS = (
    "just a moment",
    "checking your browser",
    "checking if the site connection is secure",
    "cf-browser-verification",
    "needs to review the security of your connection",
    "turnstile",
    "cloudflare",
)

CLOUDFLARE_SELECTORS = (
    'iframe[src*="challenges.cloudflare"]',
    'iframe[src*="turnstile"]',
    '#cf-turnstile',
    '[class*="cf-turnstile"]',
    'input[name="cf-turnstile-response"]',
    '[id*="turnstile"]',
)

DEFAULT_CHALLENGE_POLL_SEC = 5.0
DEFAULT_CHALLENGE_MAX_WAIT_SEC = 120.0

RATE_LIMIT_BODY_PHRASES = (
    "too many requests",
    "rate limit",
    "rate-limit",
    "rate limited",
    "slow down",
    "try again later",
    "try again in",
    "please wait",
    "usage limit",
    "request limit",
    "quota exceeded",
    "temporarily unavailable",
    "exceeded the limit",
    "too many messages",
    "too many attempts",
)

RATE_LIMIT_SELECTORS = (
    'text=Too many requests',
    'text=Rate limit exceeded',
    'text=Please try again later',
    'text=You have exceeded',
    'text=Slow down',
    'text=Try again later',
)

DEFAULT_RATE_LIMIT_BACKOFF_SEC = 60.0
DEFAULT_RATE_LIMIT_AUTO_RETRIES = 2


class PageBlockedError(Exception):
    """Submission blocked by login wall, captcha, or similar."""

    def __init__(self, kind: str, *, advice: list[str] | None = None, message: str = "") -> None:
        self.kind = kind
        self.advice = advice or []
        self.message = message or kind
        super().__init__(self.message)


def _site_has_saved_session(site: str) -> bool:
    """True only when auth.json holds a real session (not public/no-login stub)."""
    config = load_auth_config(site)
    if not config:
        return False
    if config.get("auth_mode") == "none":
        return False
    if config.get("cookies"):
        return True
    return any(
        o.get("localStorage") or o.get("sessionStorage")
        for o in config.get("origins", [])
    )


def _resolve_login_url(site: str, component: str, start_url: str) -> str:
    config = load_component_config(site, component)
    login_url = config.get("login_url") or ""
    if isinstance(login_url, str) and login_url.strip():
        return login_url.strip()
    if start_url.strip():
        return start_url.strip()
    if site.startswith("localhost") or ":" in site:
        return f"http://{site}"
    return f"https://{site}"


def get_rate_limit_settings(site: str, component: str) -> dict[str, float | int]:
    """Resolve rate-limit backoff settings from submission.rate_limit and browser settings."""
    from browser_bot.config import EVASION_MAX_RETRIES, EVASION_RETRY_WAIT_S

    config = load_component_config(site, component)
    sub = config.get("submission") if isinstance(config.get("submission"), dict) else {}
    rl = sub.get("rate_limit") if isinstance(sub.get("rate_limit"), dict) else {}
    settings = config.get("settings") if isinstance(config.get("settings"), dict) else {}

    backoff_raw = rl.get("backoff_sec")
    if backoff_raw is None:
        backoff_raw = settings.get("EVASION_RETRY_WAIT_S", EVASION_RETRY_WAIT_S)
    try:
        backoff_sec = max(1.0, float(backoff_raw))
    except (TypeError, ValueError):
        backoff_sec = DEFAULT_RATE_LIMIT_BACKOFF_SEC

    max_auto = rl.get("max_auto_retries")
    if max_auto is None:
        max_auto = min(DEFAULT_RATE_LIMIT_AUTO_RETRIES, max(0, int(EVASION_MAX_RETRIES or 0)))
    try:
        max_auto_retries = max(0, int(max_auto))
    except (TypeError, ValueError):
        max_auto_retries = DEFAULT_RATE_LIMIT_AUTO_RETRIES

    return {"backoff_sec": backoff_sec, "max_auto_retries": max_auto_retries}


async def _body_suggests_rate_limit(page: "Page") -> bool:
    try:
        body = (await page.inner_text("body")).lower()
    except Exception:
        return False
    return any(phrase in body for phrase in RATE_LIMIT_BODY_PHRASES)


async def _selector_suggests_rate_limit(page: "Page", blockers: list[dict] | None = None) -> bool:
    for sel in RATE_LIMIT_SELECTORS:
        try:
            loc = page.locator(sel).first
            if await loc.count() > 0 and await loc.is_visible():
                return True
        except Exception:
            continue
    for entry in _blocker_entries(blockers):
        if (entry.get("action") or "click") != "detect":
            continue
        label = (entry.get("label") or "").lower()
        if "rate" not in label and "limit" not in label:
            continue
        sel = entry.get("selector") or ""
        if not sel:
            continue
        try:
            loc = page.locator(sel).first
            if await loc.count() > 0 and await loc.is_visible():
                return True
        except Exception:
            continue
    return False


async def _rate_limit_visible(page: "Page", blockers: list[dict] | None = None) -> bool:
    if await _body_suggests_rate_limit(page):
        return True
    if await _selector_suggests_rate_limit(page, blockers):
        return True
    return False


def _emit_blocked_rate_limit(site: str, *, backoff_sec: float) -> None:
    from browser_bot.submit.common import log_airta_progress

    advice = [
        f"Wait at least {int(backoff_sec)} seconds before resuming tests.",
        "Reduce pool/cluster concurrency in Settings → Browser if limits persist.",
        "Switch Fetch Method to human for targets that throttle automated browsers.",
        "Click Wait and resume in the Run Tests dialog when the countdown completes.",
    ]
    log_airta_progress(
        {
            "type": "blocked",
            "kind": "rate_limited",
            "message": "Rate limit detected — too many requests.",
            "action": "prompt_rate_limit",
            "backoff_sec": round(backoff_sec, 1),
            "site": site,
            "advice": advice,
        }
    )


async def _resolve_rate_limit(
    page: "Page",
    *,
    site: str,
    component: str,
    blockers: list[dict] | None = None,
) -> None:
    if not await _rate_limit_visible(page, blockers):
        return

    cfg = get_rate_limit_settings(site, component)
    backoff_sec = float(cfg["backoff_sec"])
    max_auto_retries = int(cfg["max_auto_retries"])

    for attempt in range(1, max_auto_retries + 1):
        from browser_bot.submit.common import log_evasion

        log_evasion(
            "rate_limit_backoff",
            sleep_s=backoff_sec,
            detail=f"Rate limit visible; waiting before reload ({attempt}/{max_auto_retries})",
        )
        await asyncio.sleep(backoff_sec)
        try:
            await page.reload(wait_until="domcontentloaded", timeout=60000)
            try:
                await page.wait_for_load_state("load", timeout=10000)
            except Exception:
                pass
            await asyncio.sleep(0.5)
        except Exception:
            pass
        if not await _rate_limit_visible(page, blockers):
            print("[+] Rate limit cleared after backoff reload.", flush=True)
            return

    _emit_blocked_rate_limit(site, backoff_sec=backoff_sec)
    raise PageBlockedError(
        "rate_limited",
        advice=[
            f"Wait {int(backoff_sec)} seconds, then resume tests from the Run Tests dialog.",
            "Lower concurrency or switch to human fetch mode if this recurs.",
        ],
        message="Rate limit detected — too many requests.",
    )


async def check_rate_limit_before_submit(
    page: "Page",
    *,
    site: str,
    component: str,
    blockers: list[dict] | None = None,
) -> None:
    """Per-prompt rate-limit check for multi-turn runs."""
    await _resolve_rate_limit(page, site=site, component=component, blockers=blockers)


async def _url_suggests_login(page: "Page") -> bool:
    url = (page.url or "").lower()
    return any(marker in url for marker in LOGIN_URL_MARKERS)


async def _body_suggests_login(page: "Page") -> bool:
    try:
        body = (await page.inner_text("body")).lower()
    except Exception:
        return False
    return any(phrase in body for phrase in LOGIN_BODY_PHRASES)


async def _selector_suggests_login(page: "Page") -> bool:
    for sel in LOGIN_WALL_SELECTORS:
        try:
            loc = page.locator(sel).first
            if await loc.count() > 0 and await loc.is_visible():
                return True
        except Exception:
            continue
    return False


async def _login_wall_visible(page: "Page") -> bool:
    if await _url_suggests_login(page):
        return True
    if await _selector_suggests_login(page):
        return True
    if await _body_suggests_login(page):
        return True
    return False


def _emit_blocked_login(site: str, login_url: str) -> None:
    from browser_bot.submit.common import log_airta_progress

    advice = [
        "Click Log in in the Run Tests dialog to open a browser.",
        "Complete sign-in in the browser window.",
        "After sign-in, click Save auth to store your session.",
        "Tests will resume automatically once auth is saved.",
    ]
    log_airta_progress(
        {
            "type": "blocked",
            "kind": "login_required",
            "message": "Sign-in required to continue tests.",
            "action": "prompt_login",
            "login_url": login_url,
            "site": site,
            "advice": advice,
        }
    )


async def _resolve_login_wall(
    page: "Page",
    *,
    site: str,
    component: str,
    start_url: str,
) -> None:
    if not await _login_wall_visible(page):
        return

    if _site_has_saved_session(site):
        try:
            await page.reload(wait_until="domcontentloaded", timeout=60000)
            try:
                await page.wait_for_load_state("load", timeout=10000)
            except Exception:
                pass
            await asyncio.sleep(0.5)
        except Exception:
            pass
        if not await _login_wall_visible(page):
            print("[+] Login wall cleared after session reload.", flush=True)
            return

    login_url = _resolve_login_url(site, component, start_url)
    _emit_blocked_login(site, login_url)
    raise PageBlockedError(
        "login_required",
        advice=[
            "Sign in via the Run Tests login dialog.",
            "Save auth after completing sign-in.",
        ],
        message="Sign-in required to continue tests.",
    )


async def check_login_wall_before_submit(
    page: "Page",
    *,
    site: str,
    component: str,
    start_url: str,
) -> None:
    """Per-prompt login check for multi-turn runs."""
    await _resolve_login_wall(page, site=site, component=component, start_url=start_url)


def _blocker_entries(blockers: list[dict] | None) -> list[dict]:
    if not blockers:
        return []
    return [b for b in blockers if isinstance(b, dict) and b.get("selector")]


def _persist_blocker(site: str, component: str, selector: str, *, label: str, action: str) -> None:
    config = load_component_config_raw(site, component)
    sub = config.setdefault("submission", {})
    if not isinstance(sub, dict):
        sub = {}
        config["submission"] = sub
    entries = sub.setdefault("blockers", [])
    if not isinstance(entries, list):
        entries = []
        sub["blockers"] = entries
    for entry in entries:
        if isinstance(entry, dict) and entry.get("selector") == selector:
            return
    entries.append({"selector": selector, "label": label, "action": action})
    save_component_config(site, component, config)


async def _click_blocker(page: "Page", selector: str) -> bool:
    try:
        loc = page.locator(selector).first
        if await loc.count() == 0:
            return False
        if not await loc.is_visible():
            return False
        await loc.click(timeout=3000)
        await asyncio.sleep(0.4)
        return True
    except Exception:
        return False


async def _attempt_cookie_self_heal(
    page: "Page",
    *,
    site: str,
    component: str,
    blockers: list[dict] | None,
) -> None:
    if await _login_wall_visible(page):
        return

    configured = _blocker_entries(blockers)
    click_blockers = [b for b in configured if (b.get("action") or "click") == "click"]
    selectors = [b["selector"] for b in click_blockers if b.get("selector")]
    labels = {b["selector"]: b.get("label") or "blocker" for b in click_blockers if b.get("selector")}

    for sel in selectors:
        if await _click_blocker(page, sel):
            print(f"[+] Dismissed: {labels.get(sel, 'blocker')}", flush=True)
            return

    for sel in DEFAULT_COOKIE_SELECTORS:
        if sel in selectors:
            continue
        if await _click_blocker(page, sel):
            label = "cookie consent"
            print(f"[+] Dismissed: {label}", flush=True)
            _persist_blocker(site, component, sel, label=label, action="click")
            return


async def check_submission_readiness(
    page: "Page",
    inputs: list[dict],
    *,
    submit_selector: str = "",
) -> list[str]:
    """Check prompt inputs only — never the submit button. Returns warnings (non-blocking)."""
    warnings: list[str] = []
    _ = submit_selector  # intentionally excluded from readiness
    for inp in inputs:
        if not isinstance(inp, dict):
            continue
        sel = inp.get("selector") or ""
        if not sel:
            continue
        inp_type = (inp.get("type") or "text").lower()
        if inp_type == "file":
            continue
        try:
            loc = page.locator(sel).first
            if await loc.count() == 0:
                warnings.append(f"Input not found: {sel}")
            elif not await loc.is_visible():
                warnings.append(f"Input not visible: {sel}")
            elif not await loc.is_enabled():
                warnings.append(f"Input not enabled: {sel}")
        except Exception as exc:
            warnings.append(f"Input check failed ({sel}): {exc}")
    return warnings


async def _detect_cloudflare_turnstile(page: "Page") -> bool:
    try:
        body = (await page.inner_text("body")).lower()
    except Exception:
        body = ""
    if any(hint in body for hint in CLOUDFLARE_HINTS):
        return True
    for frame_sel in CLOUDFLARE_SELECTORS:
        try:
            if await page.locator(frame_sel).count() > 0:
                return True
        except Exception:
            continue
    return False


async def _detect_captcha(page: "Page") -> bool:
    if await _detect_cloudflare_turnstile(page):
        return True
    try:
        body = (await page.inner_text("body")).lower()
    except Exception:
        body = ""
    if any(hint in body for hint in CAPTCHA_HINTS):
        return True
    for frame_sel in ('iframe[src*="recaptcha"]', 'iframe[src*="hcaptcha"]', '[class*="captcha"]'):
        try:
            if await page.locator(frame_sel).count() > 0:
                return True
        except Exception:
            continue
    return False


def _emit_blocked_challenge(site: str) -> None:
    from browser_bot.submit.common import log_airta_progress

    advice = [
        "Complete the security challenge in the browser window.",
        "Use headed human fetch mode (HEADLESS: false, FETCH_METHOD: human) if the challenge does not appear headless.",
        "Click Resume tests after the challenge clears.",
    ]
    log_airta_progress(
        {
            "type": "blocked",
            "kind": "captcha",
            "message": "Security challenge detected (Cloudflare/Turnstile or CAPTCHA).",
            "action": "prompt_challenge",
            "site": site,
            "advice": advice,
        }
    )


async def _resolve_cloudflare_challenge(
    page: "Page",
    *,
    site: str,
    component: str,
) -> None:
    if not await _detect_cloudflare_turnstile(page):
        return

    config = load_component_config(site, component)
    sub = config.get("submission") if isinstance(config.get("submission"), dict) else {}
    challenge = sub.get("challenge") if isinstance(sub.get("challenge"), dict) else {}
    settings = config.get("settings") if isinstance(config.get("settings"), dict) else {}

    poll_raw = challenge.get("poll_sec", settings.get("CHALLENGE_POLL_SEC", DEFAULT_CHALLENGE_POLL_SEC))
    max_wait_raw = challenge.get("max_wait_sec", settings.get("CHALLENGE_MAX_WAIT_SEC", DEFAULT_CHALLENGE_MAX_WAIT_SEC))
    try:
        poll_sec = max(1.0, float(poll_raw))
    except (TypeError, ValueError):
        poll_sec = DEFAULT_CHALLENGE_POLL_SEC
    try:
        max_wait_sec = max(poll_sec, float(max_wait_raw))
    except (TypeError, ValueError):
        max_wait_sec = DEFAULT_CHALLENGE_MAX_WAIT_SEC

    elapsed = 0.0
    attempt = 0
    from browser_bot.submit.common import log_evasion

    while elapsed < max_wait_sec:
        attempt += 1
        log_evasion(
            "cloudflare_wait",
            sleep_s=poll_sec,
            detail=f"Security challenge visible; waiting ({attempt}, {int(elapsed)}s/{int(max_wait_sec)}s)",
        )
        await asyncio.sleep(poll_sec)
        elapsed += poll_sec
        if not await _detect_cloudflare_turnstile(page):
            print("[+] Security challenge cleared.", flush=True)
            return

    _emit_blocked_challenge(site)
    raise PageBlockedError(
        "captcha",
        advice=[
            "Complete the security challenge in the browser, then resume tests.",
            "Switch to headed human fetch mode if the challenge is not visible headless.",
        ],
        message="Security challenge detected.",
    )


async def detect_heuristic_blockers(
    page: "Page",
    *,
    site: str,
    component: str,
    start_url: str,
    blockers: list[dict] | None = None,
) -> None:
    if await _login_wall_visible(page):
        login_url = _resolve_login_url(site, component, start_url)
        _emit_blocked_login(site, login_url)
        raise PageBlockedError("login_required", message="Sign-in required to continue tests.")

    if await _rate_limit_visible(page, blockers):
        await _resolve_rate_limit(page, site=site, component=component, blockers=blockers)

    await _resolve_cloudflare_challenge(page, site=site, component=component)

    if await _detect_captcha(page):
        _emit_blocked_challenge(site)
        raise PageBlockedError(
            "captcha",
            advice=["Complete the CAPTCHA manually, then resume tests."],
            message="CAPTCHA detected.",
        )


async def ensure_page_ready_for_submit(
    page: "Page",
    *,
    site: str,
    component: str,
    inputs: list[dict],
    submit_selector: str,
    start_url: str,
    blockers: list[dict] | None = None,
) -> None:
    """Full pre-submit pipeline: login wall, cookies, readiness, heuristics."""
    await _resolve_login_wall(page, site=site, component=component, start_url=start_url)
    await _attempt_cookie_self_heal(page, site=site, component=component, blockers=blockers)
    await _resolve_login_wall(page, site=site, component=component, start_url=start_url)
    await _resolve_rate_limit(page, site=site, component=component, blockers=blockers)
    await _resolve_cloudflare_challenge(page, site=site, component=component)

    warnings = await check_submission_readiness(page, inputs, submit_selector=submit_selector)
    for w in warnings:
        print(f"[!] Readiness: {w}", flush=True)

    await detect_heuristic_blockers(
        page, site=site, component=component, start_url=start_url, blockers=blockers
    )
