"""API-based submission (direct HTTP, no browser automation)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from browser_bot.config import (
    API_CONCURRENCY,
    EVASION_REQUEST_DELAY_S,
    get_posts_batches,
    get_posts_strings,
    get_suite_test_cases,
)
from browser_bot.sites import get_submission_config

from browser_bot.submit.api_helpers import do_api_request
from browser_bot.submit.common import (
    SubmissionProgressTracker,
    _write_run_log,
    append_test_prompt_delimiter,
    log_evasion,
)


async def _api_request_one(
    sub: dict,
    text: str,
    *,
    site: str | None,
    test_case: dict | None = None,
    suite_path=None,
) -> tuple[str, str | None]:
    status, response_text, err = await asyncio.to_thread(
        do_api_request,
        sub,
        append_test_prompt_delimiter(text),
        site=site,
        test_case=test_case,
        suite_path=suite_path,
    )
    if err and not response_text:
        print(f"  [api] prompt failed ({status}): {err}")
    return text, response_text


async def _api_request_batch(
    sub: dict,
    batch: list[str],
    *,
    site: str | None,
    tracker: SubmissionProgressTracker,
) -> list[tuple[str, str | None]]:
    results: list[tuple[str, str | None]] = []
    for text in batch:
        pair = await _api_request_one(sub, text, site=site)
        results.append(pair)
        tracker.record_completed(1)
    return results


def _api_concurrency() -> int:
    return max(1, int(API_CONCURRENCY or 1))


async def run_api_submission_single(
    site: str,
    component: str,
    *,
    suite_path=None,
) -> tuple[list[tuple[str, str | None]], Path | None]:
    sub = get_submission_config(site, component)
    transport = (sub or {}).get("transport", "")
    if not sub or transport not in ("api", "api_document", "api_multipart"):
        return [], None

    test_cases = get_suite_test_cases(suite_path) if suite_path else []
    posts = [tc["prompt"] for tc in test_cases] if test_cases else get_posts_strings(suite_path=suite_path)
    if not posts:
        return [], None
    case_list = test_cases if test_cases else [None] * len(posts)

    tracker = SubmissionProgressTracker("single", len(posts))
    tracker.emit_run_start()

    concurrency = _api_concurrency()
    results: list[tuple[str, str | None]] = []

    if concurrency > 1 and len(posts) > 1:
        print(
            f"  [api] running {len(posts)} prompt(s) with concurrency={concurrency}",
            flush=True,
        )
        sem = asyncio.Semaphore(concurrency)

        async def _one(text: str, tc: dict | None) -> tuple[str, str | None]:
            async with sem:
                pair = await _api_request_one(
                    sub, text, site=site, test_case=tc, suite_path=suite_path
                )
                tracker.record_completed(1)
                return pair

        results = list(
            await asyncio.gather(*[_one(text, tc) for text, tc in zip(posts, case_list)])
        )
    else:
        for i, (text, tc) in enumerate(zip(posts, case_list)):
            if i > 0:
                log_evasion(
                    "sequential_burst_pause",
                    sleep_s=EVASION_REQUEST_DELAY_S,
                    detail="Pause between sequential API prompts",
                )
                await asyncio.sleep(EVASION_REQUEST_DELAY_S)
            pair = await _api_request_one(
                sub, text, site=site, test_case=tc, suite_path=suite_path
            )
            results.append(pair)
            tracker.record_completed(1)

    tracker.emit_run_done()
    log_path = (
        _write_run_log(site, component, results, test_cases=test_cases or None)
        if results
        else None
    )
    return results, log_path


async def run_api_submission_multi(
    site: str,
    component: str,
    *,
    suite_path=None,
) -> tuple[list[tuple[str, str | None]], Path | None]:
    sub = get_submission_config(site, component)
    if not sub or sub.get("transport") not in ("api", "api_document", "api_multipart"):
        return [], None

    batches = get_posts_batches(suite_path=suite_path)
    if not batches:
        return [], None

    total_turns = sum(len(b) for b in batches)
    tracker = SubmissionProgressTracker("multi", total_turns)
    tracker.emit_run_start()

    concurrency = _api_concurrency()
    all_results: list[tuple[str, str | None]] = []

    if concurrency > 1 and len(batches) > 1:
        print(
            f"  [api] running {len(batches)} batch(es) ({total_turns} turn(s)) "
            f"with concurrency={concurrency}",
            flush=True,
        )
        sem = asyncio.Semaphore(concurrency)

        async def _one_batch(batch: list[str]) -> list[tuple[str, str | None]]:
            async with sem:
                return await _api_request_batch(sub, batch, site=site, tracker=tracker)

        batch_results = await asyncio.gather(*[_one_batch(batch) for batch in batches])
        for batch in batch_results:
            all_results.extend(batch)
    else:
        for i, batch in enumerate(batches):
            if i > 0:
                log_evasion(
                    "sequential_burst_pause",
                    sleep_s=EVASION_REQUEST_DELAY_S,
                    detail="Pause between sequential API batches",
                )
                await asyncio.sleep(EVASION_REQUEST_DELAY_S)
            batch_results = await _api_request_batch(sub, batch, site=site, tracker=tracker)
            all_results.extend(batch_results)

    tracker.emit_run_done()
    log_path = (
        _write_run_log(site, component, all_results, multi_batches=batches)
        if all_results
        else None
    )
    return all_results, log_path
