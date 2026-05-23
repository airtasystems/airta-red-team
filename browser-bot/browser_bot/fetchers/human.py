"""Tier 5: Human mimicking - new context per request, maximum stealth.

Mimics human interaction with:
- playwright-stealth: navigator.webdriver evasion, fingerprint masking
- Country/locale/timezone/geolocation: consistent identity per region
- Human-like mouse movement: Bezier curves, variable delays
- Randomized viewport: common screen resolutions
- Fewer automation Chrome flags (HUMAN_CHROME_ARGS)
- Full stylesheet loading for realistic rendering

Uses launch_context_for_request() for unified flow with login and refresh.
TLS: Chromium uses BoringSSL, producing Chrome-like JA3 fingerprints.
"""

import asyncio
import time
from typing import Any, Optional

from browser_bot.browser.human_behavior import human_mouse_wander, human_scroll
from browser_bot.browser.launcher import launch_context_for_request
from browser_bot.config import HUMAN_SCROLL_AFTER_LOAD, HUMAN_READ_DELAY_MS
from browser_bot.submit.common import NonSuccessResponseError
from browser_bot.fetchers.base import (
    BaseFetcher,
    FetchResult,
    PostResult,
    extract_first_p_from_dom,
)
from browser_bot.sites import get_storage_state_path_for_url


class HumanFetcher(BaseFetcher):
    """Human mimicking: fresh context per request, stealth, fingerprint evasion, mouse movement."""

    tier_name = "human"

    def __init__(self, playwright):
        self.playwright = playwright

    async def _setup_context(
        self,
        storage_path: str | None = None,
        storage_state: dict | None = None,
        *,
        headless: bool | None = None,
        allow_all: bool = False,
        discovery_layout: bool = False,
    ):
        """Uses unified launch_context_for_request (same flow as login, refresh)."""
        browser, context = await launch_context_for_request(
            self.playwright,
            storage_state_path=storage_path,
            storage_state=storage_state,
            headless=headless,
            allow_all=allow_all,
            force_human=True,
            discovery_layout=discovery_layout,
        )
        return browser, context

    async def fetch(self, url: str) -> Optional[FetchResult]:
        try:
            storage_path = get_storage_state_path_for_url(url)
            storage_str = str(storage_path) if storage_path else None
            browser, context = await self._setup_context(storage_str)
            page = await context.new_page()

            # Brief pre-navigation delay (human hesitation)
            await asyncio.sleep(0.15 + time.perf_counter() % 0.15 + (time.perf_counter() % 100) * 0.01)

            start = time.perf_counter()
            response = await page.goto(url, wait_until="load", timeout=30000)

            # Read delay: humans pause before interacting
            await asyncio.sleep(HUMAN_READ_DELAY_MS / 1000.0)

            # Human-like mouse movement after load
            await human_mouse_wander(page, count=2)

            if HUMAN_SCROLL_AFTER_LOAD:
                await human_scroll(page)

            first_p = await extract_first_p_from_dom(page)
            content = await page.content()
            title = await page.title()
            elapsed = time.perf_counter() - start

            await context.close()
            await browser.close()

            status = response.status if response else None
            return FetchResult(
                content=content,
                tier=self.tier_name,
                elapsed=elapsed,
                status_code=status,
                title=title,
                first_p=first_p,
            )
        except Exception:
            return None

    async def post(
        self,
        url: str,
        *,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Optional[PostResult]:
        try:
            storage_path = get_storage_state_path_for_url(url)
            storage_str = str(storage_path) if storage_path else None
            browser, context = await self._setup_context(storage_str)
            page = await context.new_page()

            # Human-like behavior before POST
            await asyncio.sleep(0.05 + time.perf_counter() % 0.1)
            await human_mouse_wander(page, count=1)

            start = time.perf_counter()
            opts: dict[str, Any] = {}
            if json_data:
                opts["data"] = json_data
            elif data:
                opts["form"] = data
            if headers:
                opts["headers"] = headers
            response = await page.request.post(url, **opts)
            body = await response.text()
            elapsed = time.perf_counter() - start

            await context.close()
            await browser.close()

            return PostResult(url=url, tier=self.tier_name, status=response.status, body=body, elapsed=elapsed)
        except Exception:
            return None

    async def with_page(
        self,
        callback,
        storage_path: str | None = None,
        storage_state: dict | None = None,
        *,
        headless=None,
        allow_all: bool = False,
        discovery_layout: bool = False,
    ):
        try:
            storage_str = str(storage_path) if storage_path else None
            browser, context = await self._setup_context(
                storage_path=storage_str,
                storage_state=storage_state,
                headless=headless,
                allow_all=allow_all,
                discovery_layout=discovery_layout,
            )
            page = await context.new_page()
            try:
                return await callback(page)
            finally:
                await context.close()
                await browser.close()
        except NonSuccessResponseError:
            raise
        except Exception:
            return None
