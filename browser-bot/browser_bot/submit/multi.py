"""Multi-string UI submission: N prompts per page/session in sequence."""

import asyncio
import time
from pathlib import Path
from typing import TYPE_CHECKING

from browser_bot.browser.human_behavior import human_mouse_wander
from browser_bot.config import EVASION_REQUEST_DELAY_S, FETCH_METHOD, get_posts_batches
from browser_bot.live_preview import live_preview_context
from browser_bot.page_blockers import (
    PageBlockedError,
    check_login_wall_before_submit,
    check_rate_limit_before_submit,
    ensure_page_ready_for_submit,
)
from browser_bot.sites import get_storage_state_path, get_submission_config

from browser_bot.submit.common import (
    NonSuccessResponseError,
    SubmissionProgressTracker,
    _do_one_submit_step,
    _write_run_log,
    append_test_prompt_delimiter,
    log_evasion,
    parallel_fetchers_for_ui,
    run_with_evasion_retry,
)

if TYPE_CHECKING:
    from playwright.async_api import Page


async def do_ui_submit_sequence_with_page(
    page: "Page",
    start_url: str,
    inputs: list[dict],
    submit_selector: str,
    texts: list[str],
    *,
    site: str = "",
    component: str = "",
    blockers: list[dict] | None = None,
    response_selector: str = "",
    response_within_selector: str = "",
    response_text_within_selector: str = "",
    submit_via: str = "click",
    response_wait_ms: int = 5000,
    human_behavior: bool = False,
    progress_tracker: "SubmissionProgressTracker | None" = None,
) -> list[tuple[str, str | None]]:
    """Run a sequence of UI submissions on the same page. Returns list of (text, response_text)."""
    async with live_preview_context(page):
        await asyncio.sleep(0.1 + time.perf_counter() % 0.15)
        await page.goto(start_url, wait_until="domcontentloaded", timeout=60000)
        try:
            await page.wait_for_load_state("load", timeout=10000)
        except Exception:
            pass
        await asyncio.sleep(0.25)
        if human_behavior:
            await human_mouse_wander(page, count=1)

        await ensure_page_ready_for_submit(
            page,
            site=site,
            component=component,
            inputs=inputs,
            submit_selector=submit_selector,
            start_url=start_url,
            blockers=blockers,
        )

        results: list[tuple[str, str | None]] = []
        baseline = ""
        for text in texts:
            await check_login_wall_before_submit(
                page, site=site, component=component, start_url=start_url
            )
            await check_rate_limit_before_submit(
                page, site=site, component=component, blockers=blockers
            )
            prompt_text = append_test_prompt_delimiter(text)
            text_out, response_out, full_content = await _do_one_submit_step(
                page,
                inputs,
                submit_selector,
                prompt_text,
                response_selector=response_selector,
                response_within_selector=response_within_selector,
                response_text_within_selector=response_text_within_selector,
                submit_via=submit_via,
                response_wait_ms=response_wait_ms,
                baseline_text=baseline,
            )
            results.append((text_out, response_out))
            baseline = full_content
            if progress_tracker is not None:
                progress_tracker.record_completed(1)
        return results


async def run_ui_submission_multi(
    site: str,
    component: str,
    *,
    pool_fetcher=None,
    cluster_fetcher=None,
    human_fetcher=None,
    suite_path=None,
) -> tuple[list[tuple[str, str | None]], Path | None]:
    """
    Run UI submission for each batch in posts.json (array of arrays).
    Each batch runs in one page/session. Returns (flattened list of (input_string, response_text) tuples, log_path or None).
    """
    sub = get_submission_config(site, component)
    if not sub:
        return [], None

    batches_raw = get_posts_batches(suite_path=suite_path)
    if not batches_raw:
        return [], None
    batches = [[append_test_prompt_delimiter(t) for t in batch] for batch in batches_raw]

    storage_path = get_storage_state_path(site)
    if not storage_path:
        return [], None

    start_url = sub["start_url"]
    inputs: list[dict] = sub["inputs"]
    submit_selector = sub["submit_selector"]
    blockers = sub.get("blockers") if isinstance(sub.get("blockers"), list) else None
    response_selector = sub.get("response_selector") or ""
    response_within_selector = sub.get("response_within_selector") or ""
    response_text_within_selector = sub.get("response_text_within_selector") or ""
    submit_via = sub.get("submit_via", "click")
    response_wait_ms = int(sub.get("response_wait_ms", 5000) or 5000)

    fetchers_to_try: list[tuple] = []
    if pool_fetcher:
        fetchers_to_try.append((pool_fetcher, False))
    if cluster_fetcher:
        fetchers_to_try.append((cluster_fetcher, False))
    if human_fetcher:
        fetchers_to_try.append((human_fetcher, True))

    if not fetchers_to_try:
        return [], None

    all_results: list[tuple[str, str | None]] = []
    storage_str = str(storage_path)

    total_turns = sum(len(b) for b in batches)
    tracker = SubmissionProgressTracker("multi", total_turns)
    tracker.emit_run_start()

    method = FETCH_METHOD.lower()
    parallel_fetchers = []
    if len(batches) > 1:
        parallel_fetchers = parallel_fetchers_for_ui(method, pool_fetcher, cluster_fetcher)

    page_kwargs = dict(
        site=site,
        component=component,
        blockers=blockers,
        response_selector=response_selector,
        response_within_selector=response_within_selector,
        response_text_within_selector=response_text_within_selector,
        submit_via=submit_via,
        response_wait_ms=response_wait_ms,
    )

    if parallel_fetchers:
        async def _run_batch_with_human(batch: list[str]):
            if human_fetcher is None:
                return None

            async def _cb(page, b=batch):
                return await do_ui_submit_sequence_with_page(
                    page,
                    start_url,
                    inputs,
                    submit_selector,
                    b,
                    human_behavior=True,
                    progress_tracker=None,
                    **page_kwargs,
                )

            try:
                return await run_with_evasion_retry(
                    lambda f=_cb: human_fetcher.with_page(f, storage_path=storage_str)
                )
            except PageBlockedError:
                raise
            except NonSuccessResponseError:
                return None

        async def _run_batch(batch: list[str], fetcher, *, record_progress: bool = False):
            async def _cb(page, b=batch):
                return await do_ui_submit_sequence_with_page(
                    page,
                    start_url,
                    inputs,
                    submit_selector,
                    b,
                    human_behavior=False,
                    progress_tracker=tracker if record_progress else None,
                    **page_kwargs,
                )
            try:
                return await run_with_evasion_retry(
                    lambda f=_cb, fet=fetcher: fet.with_page(f, storage_path=storage_str)
                )
            except PageBlockedError:
                raise

        parallel_results = await asyncio.gather(
            *[_run_batch(batch, parallel_fetchers[0], record_progress=True) for batch in batches],
            return_exceptions=True,
        )

        async def _retry_fast_then_human(batch: list[str]):
            for fetcher in parallel_fetchers[1:]:
                try:
                    retry_result = await _run_batch(batch, fetcher)
                except PageBlockedError:
                    raise
                except Exception:
                    retry_result = None
                if retry_result and all(resp for _, resp in retry_result):
                    return retry_result
            return await _run_batch_with_human(batch)

        for batch, r in zip(batches, parallel_results):
            if isinstance(r, PageBlockedError):
                raise r
            if isinstance(r, Exception):
                fallback = await _retry_fast_then_human(batch)
                if fallback and all(resp for _, resp in fallback):
                    all_results.extend(fallback)
                else:
                    all_results.extend((t, None) for t in batch)
            elif r is not None:
                if all(resp for _, resp in r):
                    all_results.extend(r)
                else:
                    fallback = await _retry_fast_then_human(batch)
                    all_results.extend(fallback if fallback and all(resp for _, resp in fallback) else r)
            else:
                fallback = await _retry_fast_then_human(batch)
                if fallback and all(resp for _, resp in fallback):
                    all_results.extend(fallback)
                else:
                    all_results.extend((t, None) for t in batch)
    else:
        for i, batch in enumerate(batches):
            if i > 0:
                log_evasion(
                    "sequential_burst_pause",
                    sleep_s=EVASION_REQUEST_DELAY_S,
                    detail="Pause between sequential batches to reduce burst-rate detection",
                )
                await asyncio.sleep(EVASION_REQUEST_DELAY_S)
            batch_results = None
            for fetcher, human_behavior in fetchers_to_try:
                async def _cb(page, b=batch, hb=human_behavior):
                    return await do_ui_submit_sequence_with_page(
                        page,
                        start_url,
                        inputs,
                        submit_selector,
                        b,
                        human_behavior=hb,
                        progress_tracker=tracker,
                        **page_kwargs,
                    )

                try:
                    batch_results = await run_with_evasion_retry(
                        lambda f=_cb, fet=fetcher: fet.with_page(f, storage_path=storage_str)
                    )
                except PageBlockedError:
                    raise
                except NonSuccessResponseError:
                    batch_results = None
                if batch_results is not None and all(resp for _, resp in batch_results):
                    break
            if batch_results is not None:
                all_results.extend(batch_results)
            else:
                all_results.extend((t, None) for t in batch)

    tracker.emit_run_done()
    log_path = (
        _write_run_log(site, component, all_results, multi_batches=batches_raw)
        if all_results
        else None
    )
    return all_results, log_path
