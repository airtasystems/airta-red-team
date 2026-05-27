"""Shared helpers for UI submission (single and multi)."""

import asyncio
import json
import random
import re
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Coroutine

import tenacity

from browser_bot.config import EVASION_MAX_RETRIES, EVASION_RETRY_WAIT_S
from browser_bot.sites import ensure_component_dir, get_component_path


def log_evasion(reason: str, *, sleep_s: float | None = None, detail: str = "") -> None:
    """Emit a line for web UI / logs when an evasion delay or retry is applied."""
    parts = [f"reason={reason}"]
    if sleep_s is not None:
        parts.append(f"sleep_s={sleep_s}")
    tail = " | ".join(parts)
    if detail:
        tail = f"{tail} | {detail}"
    print(f"[evasion] {tail}", flush=True)


def log_airta_progress(payload: dict) -> None:
    """Structured progress for the AIRTA web UI (parsed from job stream)."""
    print(f"[airta_progress] {json.dumps(payload, ensure_ascii=False)}", flush=True)


TEST_PROMPT_DELIMITER = "\n[TEXT ONLY. NO HTML OR MARKUP. MAX 600 CHARS]"


def append_test_prompt_delimiter(text: str) -> str:
    """Append test delimiter if not already present."""
    if TEST_PROMPT_DELIMITER in text:
        return text
    return text + TEST_PROMPT_DELIMITER


class SubmissionProgressTracker:
    """Live ETA via throughput: elapsed/done * remaining."""

    def __init__(self, mode: str, total_prompts: int) -> None:
        self.mode = mode
        self.total = max(0, int(total_prompts))
        self.done = 0
        self._start = time.perf_counter()

    def emit_run_start(self) -> None:
        log_airta_progress(
            {
                "type": "run_start",
                "mode": self.mode,
                "total": self.total,
                "label": "UI submission",
            }
        )

    def record_completed(self, count: int = 1) -> None:
        self.done = min(self.total, self.done + max(0, count))
        self._emit()

    def _emit(self) -> None:
        elapsed = time.perf_counter() - self._start
        rem = max(0, self.total - self.done)
        eta_sec = None
        if self.done > 0 and rem > 0:
            eta_sec = (elapsed / self.done) * rem
        elif rem == 0:
            eta_sec = 0.0
        log_airta_progress(
            {
                "type": "progress",
                "mode": self.mode,
                "current": self.done,
                "total": self.total,
                "elapsed_sec": round(elapsed, 1),
                "eta_sec": round(eta_sec, 1) if eta_sec is not None else None,
            }
        )

    def emit_run_done(self) -> None:
        log_airta_progress(
            {
                "type": "run_done",
                "mode": self.mode,
                "total": self.total,
                "elapsed_sec": round(time.perf_counter() - self._start, 1),
            }
        )

if TYPE_CHECKING:
    from playwright.async_api import Locator, Page

_TEXT_TYPES = {"text", "textarea", "contenteditable", "password", "email", "search"}

# Matches a leading role label like "Assistant\n", "AI\n", "Bot\n", "User\n" etc.
# A role label is a short (≤30 char) run of non-newline characters at the very
# start of the string, followed by a newline — with no spaces (so full sentences
# are not stripped).
_ROLE_LABEL_RE = re.compile(r"^\S{1,30}\n+", re.UNICODE)
_EMPTY_RESPONSE_MARKERS = {
    "",
    "the model response will appear here.",
    "loading...",
    "generating...",
}


def _strip_role_prefix(text: str) -> str:
    """Strip a leading role label (e.g. 'Assistant\\n') from response text."""
    return _ROLE_LABEL_RE.sub("", text, count=1)


class NonSuccessResponseError(Exception):
    """Raised when a same-origin POST/PUT/PATCH request returns a non-2xx status."""

    def __init__(self, status: int, url: str = "") -> None:
        self.status = status
        self.url = url
        super().__init__(f"Non-2xx response: HTTP {status}" + (f" from {url}" if url else ""))


def parallel_fetcher_for_ui(method: str, pool_fetcher, cluster_fetcher):
    """When FETCH_METHOD is auto, prefer pool then cluster (same order as HTTP post_url)."""
    fetchers = parallel_fetchers_for_ui(method, pool_fetcher, cluster_fetcher)
    return fetchers[0] if fetchers else None


def parallel_fetchers_for_ui(method: str, pool_fetcher, cluster_fetcher) -> list:
    """Return eligible fast UI fetchers in retry order for parallel submission."""
    if pool_fetcher is None and cluster_fetcher is None:
        return []
    m = method.lower()
    if m == "pool" and pool_fetcher is not None:
        return [pool_fetcher]
    if m == "cluster" and cluster_fetcher is not None:
        return [cluster_fetcher]
    if m == "auto":
        fetchers = []
        if pool_fetcher is not None:
            fetchers.append(pool_fetcher)
        if cluster_fetcher is not None:
            fetchers.append(cluster_fetcher)
        return fetchers
    return []


def _before_sleep_evasion(retry_state: Any) -> None:
    exc = retry_state.outcome.exception()
    status = getattr(exc, "status", None) if exc else None
    attempt = retry_state.attempt_number
    log_evasion(
        "http_retry_after_non_2xx",
        sleep_s=EVASION_RETRY_WAIT_S,
        detail=f"Will retry after HTTP error (status={status}); attempt {attempt}/{EVASION_MAX_RETRIES}",
    )


async def run_with_evasion_retry(
    coro_fn: Callable[[], Coroutine[Any, Any, Any]],
) -> Any:
    """Run *coro_fn* (a zero-arg async callable) with tenacity retry on NonSuccessResponseError.

    On non-2xx: waits EVASION_RETRY_WAIT_S seconds then retries, up to EVASION_MAX_RETRIES times.
    If all retries are exhausted, returns None.
    """
    try:
        async for attempt in tenacity.AsyncRetrying(
            retry=tenacity.retry_if_exception_type(NonSuccessResponseError),
            wait=tenacity.wait_fixed(EVASION_RETRY_WAIT_S),
            stop=tenacity.stop_after_attempt(EVASION_MAX_RETRIES),
            reraise=False,
            before_sleep=_before_sleep_evasion,
        ):
            with attempt:
                return await coro_fn()
    except tenacity.RetryError:
        pass
    return None


async def _first_visible_locator(page, selector: str):
    """Return locator for first visible element matching selector. Avoids hidden elements."""
    loc = page.locator(selector)
    count = await loc.count()
    for i in range(count):
        node = loc.nth(i)
        if await node.is_visible():
            return node
    return loc.first


async def _last_visible_locator(page, selector: str):
    """Return locator for last visible element matching selector (latest chat bubble, etc.)."""
    loc = page.locator(selector)
    count = await loc.count()
    for i in range(count - 1, -1, -1):
        node = loc.nth(i)
        if await node.is_visible():
            return node
    return loc.last


async def _last_visible_within(loc: "Locator"):
    """Like _last_visible_locator but scoped to an existing locator (narrowed descendant chain)."""
    count = await loc.count()
    for i in range(count - 1, -1, -1):
        node = loc.nth(i)
        try:
            if await node.is_visible():
                return node
        except Exception:
            continue
    return loc.last


def _is_empty_response_text(text: str) -> bool:
    return text.strip().lower() in _EMPTY_RESPONSE_MARKERS


def _looks_like_skeleton_progress_line(text: str) -> bool:
    """True when the bubble clearly shows transitional status text, not a finished reply.

    Many UIs show a spinner line ("Generating...", "Thinking..."); when inner_text stabilizes
    on that line for stable_ms we used to exit before the model body appeared.
    Requires ellipsis-terminated short lines plus a known leading verb prefix (or brief wait phrases)
    so full sentences beginning with uncommon patterns are unlikely to match.
    """
    s = (text or "").strip()
    if not s or _is_empty_response_text(s):
        return False
    if "\n\n" in s:
        return False
    lines = [ln.strip() for ln in s.splitlines() if ln.strip()]
    if any(len(ln) > 240 for ln in lines):
        return False

    verbs = ("generating", "loading", "thinking", "fetching", "preparing", "assessing", "streaming")
    wait_phrases = ("please wait", "one moment", "hold on", "just a moment")

    for raw in lines:
        if len(raw) > 160:
            continue
        low = raw.lower()
        ell = low.endswith(("…", "..."))
        # Short spinner row: "Generating the …"
        if ell and len(raw) <= 140 and any(low.startswith(v) for v in verbs):
            return True
        if ell and len(raw) <= 120 and any(low.startswith(w) for w in wait_phrases):
            return True
        # Chips like "please wait for the assistant" rarely end with ellipsis; keep very short.
        if len(raw) <= 72 and any(low.startswith(w) for w in wait_phrases):
            return True
    return False


async def _first_visible_under(main_loc: "Locator", relative: str) -> "Locator | None":
    """First visible node under ``main_loc`` matching Playwright-relative ``relative``."""
    rel = (relative or "").strip()
    if not rel:
        return None
    sub = main_loc.locator(rel)
    count = await sub.count()
    for i in range(count):
        node = sub.nth(i)
        try:
            if await node.is_visible():
                return node
        except Exception:
            continue
    return None


async def _response_selector_text(
    page: "Page",
    selector: str,
    *,
    within_selector: str = "",
    text_within_selector: str = "",
) -> str:
    """Read inner_text: scope to bubble/container, optionally read from a narrower leaf only.

    Use ``text_within_selector`` when the container includes labels or footer widgets — for
    example a Playwright-relative ``> p`` on the bubble picks the assistant body paragraph
    while the bubble itself stays the visibility anchor during streaming.
    When the leaf is missing (spinner-only phase), falls back to the container's inner_text.
    """
    roots = page.locator(selector.strip())
    if await roots.count() == 0:
        return ""
    target = roots
    inner = within_selector.strip() if within_selector else ""
    if inner:
        target = roots.locator(inner)
        if await target.count() == 0:
            return ""
    main_loc = await _last_visible_within(target)
    await main_loc.wait_for(state="visible", timeout=3000)
    txt_in = text_within_selector.strip() if text_within_selector else ""
    extract_loc = main_loc
    if txt_in:
        leaf = await _first_visible_under(main_loc, txt_in)
        if leaf is not None:
            extract_loc = leaf
    return _strip_role_prefix(await extract_loc.inner_text()).strip()


async def _wait_for_response_selector_text(
    page,
    selector: str,
    *,
    previous_text: str | None,
    timeout_ms: int,
    stable_ms: int = 750,
    within_selector: str = "",
    text_within_selector: str = "",
) -> str:
    """Poll until inner text differs from baseline and stays stable (`stable_ms`), or deadline.

    `timeout_ms` is the maximum time to poll — not a minimum sleep before returning.
    If `previous_text` is ``None`` (baseline could not be read before submit), the first sample
    after waiting starts establishes the baseline so existing DOM copy is not mistaken for the
    new model reply (previously any non‑empty node satisfied `current != ""` and exited in ~1s).
    """
    deadline = time.perf_counter() + max(int(timeout_ms or 0), 1000) / 1000.0
    stable_for = stable_ms / 1000.0
    candidate = ""
    last_seen = ""
    last_changed = time.perf_counter()
    baseline_unknown = previous_text is None
    effective_baseline: str | None = previous_text if not baseline_unknown else None
    seeded_post_submit = False

    while time.perf_counter() < deadline:
        try:
            current = await _response_selector_text(
                page,
                selector,
                within_selector=within_selector,
                text_within_selector=text_within_selector,
            )
        except Exception:
            current = ""

        if baseline_unknown and not seeded_post_submit:
            effective_baseline = current
            seeded_post_submit = True
            await asyncio.sleep(0.2)
            continue

        base = effective_baseline if effective_baseline is not None else ""
        meaningful = (
            bool(current)
            and current != base
            and not _is_empty_response_text(current)
            and not _looks_like_skeleton_progress_line(current)
        )
        if meaningful:
            if current != last_seen:
                last_seen = current
                last_changed = time.perf_counter()
            candidate = current
            if time.perf_counter() - last_changed >= stable_for:
                return candidate

        await asyncio.sleep(0.25)

    return candidate


async def _fill_input(
    page,
    inp: dict,
    value: str,
    *,
    artifact_path: Path | None = None,
) -> None:
    """Fill a single input based on its type."""
    selector = inp["selector"]
    inp_type = inp.get("type", "text")

    if inp_type == "file":
        if artifact_path is None:
            path_str = inp.get("path") or inp.get("value")
            if path_str:
                artifact_path = Path(str(path_str))
        if artifact_path and artifact_path.is_file():
            loc = await _first_visible_locator(page, selector)
            await loc.set_input_files(str(artifact_path))
        return

    if inp_type in _TEXT_TYPES:
        loc = await _first_visible_locator(page, selector)
        await loc.fill(value)
    elif inp_type == "select":
        sel_loc = await _first_visible_locator(page, selector)
        options = await sel_loc.evaluate(
            """
            (el) => {
              if (!el || el.tagName !== 'SELECT') return [];
              return Array.from(el.options).map(o => o.value).filter(v => v !== '');
            }
            """
        )
        configured = inp.get("value")
        if configured and configured in options:
            chosen = configured
        else:
            chosen = random.choice(options) if options else (configured or "")
        await sel_loc.select_option(value=chosen)
    elif inp_type == "combobox":
        combo_loc = await _first_visible_locator(page, selector)
        await combo_loc.click()
        await asyncio.sleep(0.2)
        listbox = page.get_by_role("listbox")
        options = await listbox.locator('[role="option"]').all_text_contents()
        if not options:
            options = await page.locator('[role="option"]').all_text_contents()
        options = [o.strip() for o in options if o.strip()]
        chosen = random.choice(options) if options else (value or inp.get("value", ""))
        try:
            await page.get_by_role("option", name=chosen).first.click()
        except Exception:
            await page.locator(f'[role="option"]:has-text("{chosen}")').first.click()
    elif inp_type == "checkbox":
        loc = await _first_visible_locator(page, selector)
        if inp.get("value"):
            await loc.check()
        else:
            await loc.uncheck()
    elif inp_type == "radio":
        radio_loc = await _first_visible_locator(page, selector)
        if inp.get("value"):
            await radio_loc.check()
        else:
            await radio_loc.uncheck()
    else:
        loc = await _first_visible_locator(page, selector)
        await loc.fill(value)


async def _refire_text_input_events(page, inputs: list[dict]) -> None:
    """Nudge hydrated frontends that missed Playwright's first fill event."""
    for inp in inputs:
        if inp.get("type", "text") not in _TEXT_TYPES:
            continue
        selector = inp.get("selector")
        if not selector:
            continue
        try:
            loc = await _first_visible_locator(page, selector)
            await loc.evaluate(
                """
                (el) => {
                  el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: el.value }));
                  el.dispatchEvent(new Event('change', { bubbles: true }));
                }
                """
            )
        except Exception:
            continue


async def _wait_for_submit_enabled(page, submit_selector: str, timeout_ms: int = 3000) -> bool:
    deadline = time.perf_counter() + max(timeout_ms, 250) / 1000.0
    while time.perf_counter() < deadline:
        try:
            loc = await _first_visible_locator(page, submit_selector)
            if await loc.is_enabled():
                return True
        except Exception:
            pass
        await asyncio.sleep(0.1)
    return False


async def _do_one_submit_step(
    page: "Page",
    inputs: list[dict],
    submit_selector: str,
    text: str,
    *,
    response_selector: str = "",
    response_within_selector: str = "",
    response_text_within_selector: str = "",
    submit_via: str = "click",
    response_wait_ms: int = 5000,
    baseline_text: str | None = None,
    test_case: dict | None = None,
    suite_path: Path | str | None = None,
) -> tuple[str, str | None, str]:
    """Fill inputs, submit, wait for response. No goto.
    Returns (text, response_text, full_content). When baseline_text is provided (multi mode),
    response_text is only the newly added content; full_content is for the next step's baseline."""
    artifact_path: Path | None = None
    if test_case:
        try:
            from browser_bot.artifacts import resolve_test_artifact

            artifact_path, _vt, _ok = resolve_test_artifact(
                test_case, suite_path=suite_path
            )
        except Exception:
            artifact_path = None

    for inp in inputs:
        inp_type = inp.get("type", "text")
        path_from = inp.get("path_from", "")
        use_artifact = (
            inp_type == "file"
            or path_from == "payload"
            or inp.get("artifact") is True
        )
        if use_artifact and artifact_path:
            await _fill_input(page, inp, text, artifact_path=artifact_path)
        elif inp_type in _TEXT_TYPES:
            await _fill_input(page, inp, text)
        elif inp_type in ("select", "combobox"):
            await _fill_input(page, inp, "")
        else:
            default = inp.get("value", "")
            await _fill_input(page, inp, default if isinstance(default, str) else str(default))

    if not await _wait_for_submit_enabled(page, submit_selector):
        await _refire_text_input_events(page, inputs)
        await _wait_for_submit_enabled(page, submit_selector)

    previous_response_text = None
    if response_selector and str(response_selector).strip():
        sel = response_selector.strip()
        try:
            has_nodes = await page.locator(sel).count() > 0
        except Exception:
            has_nodes = False
        if has_nodes:
            for _attempt in range(4):
                try:
                    previous_response_text = await _response_selector_text(
                        page,
                        response_selector,
                        within_selector=response_within_selector,
                        text_within_selector=response_text_within_selector,
                    )
                    break
                except Exception:
                    if _attempt >= 3:
                        break
                    await asyncio.sleep(0.15)
        else:
            previous_response_text = ""

    await asyncio.sleep(0.1)

    submit_loc = await _first_visible_locator(page, submit_selector)

    captured = []

    def on_response(response):
        if response.request.method in ("POST", "PUT", "PATCH"):
            captured.append(response)

    page.on("response", on_response)
    try:
        if submit_via == "enter":
            await page.keyboard.press("Enter")
        else:
            await submit_loc.click()

        full_content = None
        if response_selector and str(response_selector).strip():
            try:
                full_content = await _wait_for_response_selector_text(
                    page,
                    response_selector,
                    previous_text=previous_response_text,
                    timeout_ms=response_wait_ms,
                    within_selector=response_within_selector,
                    text_within_selector=response_text_within_selector,
                )
            except Exception:
                pass
        else:
            await asyncio.sleep(response_wait_ms / 1000.0)
            page_origin = page.url.split("/", 3)[:3]
            page_origin_str = "/".join(page_origin) if len(page_origin) >= 3 else ""

            for resp in captured:
                try:
                    req_url = resp.request.url
                    if page_origin_str and not req_url.startswith(page_origin_str):
                        continue
                    body = await resp.text()
                    if body and body.strip():
                        full_content = body
                        break
                except Exception:
                    continue

            if full_content is None:
                for resp in captured:
                    try:
                        body = await resp.text()
                        if body and body.strip():
                            full_content = body
                            break
                    except Exception:
                        continue
    finally:
        try:
            page.remove_listener("response", on_response)
        except Exception:
            pass

    # Only retry on genuine server-side transient failures (rate-limit or 5xx).
    # Ignore 4xx from background app calls (analytics, polling, etc.) that happen
    # to fire during response_wait_ms — those are not submission failures.
    # Also skip if we already captured content: the submit succeeded.
    if full_content is None:
        page_origin = page.url.split("/", 3)[:3]
        page_origin_str = "/".join(page_origin) if len(page_origin) >= 3 else ""
        for resp in captured:
            try:
                status = resp.status
                if not (status == 429 or status >= 500):
                    continue
                req_url = resp.request.url
                if page_origin_str and not req_url.startswith(page_origin_str):
                    continue
                raise NonSuccessResponseError(status, req_url)
            except NonSuccessResponseError:
                raise
            except Exception:
                continue

    full_content = full_content or ""
    if baseline_text is not None and full_content.startswith(baseline_text):
        response_text = full_content[len(baseline_text) :].strip()
    else:
        response_text = full_content if full_content else None
    return (text, response_text, full_content)


def _write_run_log(
    site: str,
    component: str,
    results: list[tuple[str, str | None]],
    *,
    multi_batches: list[list[str]] | None = None,
    test_cases: list[dict] | None = None,
) -> Path | None:
    """Write run log to sites/{site}/{component}/logs/{timestamp}/run_log.json.

    Each call creates a fresh timestamped subdirectory so attack_log.json
    and pipeline_report.json written into the same directory are naturally
    scoped to that test run.

    When multi_batches is set (same structure as get_posts_batches), results are grouped
    one batch per multi-shot conversation. Otherwise flat entries (single-shot).
    """
    try:
        ensure_component_dir(site, component)
        logs_dir = get_component_path(site, component) / "logs"
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        run_dir = logs_dir / timestamp
        run_dir.mkdir(parents=True, exist_ok=True)
        log_path = run_dir / "run_log.json"

        entries = []
        for i, (inp, resp) in enumerate(results):
            row: dict[str, Any] = {"input": inp, "response": resp}
            if test_cases and i < len(test_cases):
                tc = test_cases[i]
                if tc.get("id"):
                    row["id"] = tc["id"]
                if tc.get("vector_type"):
                    row["vector_type"] = tc["vector_type"]
                if tc.get("payload"):
                    row["payload"] = tc["payload"]
                try:
                    from browser_bot.artifacts import resolve_test_artifact

                    ap, _, upload_ok = resolve_test_artifact(tc)
                    if ap:
                        row["artifact_path"] = str(ap)
                    row["upload_ok"] = upload_ok
                except Exception:
                    pass
            entries.append(row)

        use_grouped = (
            multi_batches is not None
            and results
            and sum(len(b) for b in multi_batches) == len(results)
        )

        if use_grouped:
            batches_out: list[dict] = []
            offset = 0
            for batch_index, batch_prompts in enumerate(multi_batches):
                n = len(batch_prompts)
                chunk = results[offset : offset + n]
                offset += n
                turns = [
                    {
                        "turn": turn_index,
                        "input": inp,
                        "response": resp,
                    }
                    for turn_index, (inp, resp) in enumerate(chunk)
                ]
                batches_out.append(
                    {
                        "batch_index": batch_index,
                        "turn_count": n,
                        "turns": turns,
                    }
                )
            log_data = {
                "site": site,
                "component": component,
                "timestamp": timestamp,
                "mode": "multi",
                "batches": batches_out,
            }
        else:
            log_data = {
                "site": site,
                "component": component,
                "timestamp": timestamp,
                "mode": "single",
                "entries": entries,
            }

        with open(log_path, "w") as f:
            json.dump(log_data, f, indent=2)
        return log_path
    except Exception:
        return None
