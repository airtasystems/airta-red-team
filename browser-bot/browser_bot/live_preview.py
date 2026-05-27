"""Periodic browser screenshots for live Run Tests preview in the web UI."""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, AsyncIterator

from browser_bot.submit.common import log_airta_progress

if TYPE_CHECKING:
    from playwright.async_api import Page

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_PREVIEW_DIR = _PROJECT_ROOT / "web" / "tmp" / "previews"
_INTERVAL_S = 1.0

_slot_lock = asyncio.Lock()
_active_job_id: str | None = None
_page_slots: dict[int, int] = {}
_next_slot = 0


def preview_path(job_id: str, slot: int = 0) -> Path:
    """Filesystem path for a job preview screenshot."""
    slotted = _PREVIEW_DIR / preview_filename(job_id, slot)
    if slotted.is_file():
        return slotted
    if slot == 0:
        legacy = _PREVIEW_DIR / f"{job_id}.png"
        if legacy.is_file():
            return legacy
    return slotted


def preview_filename(job_id: str, slot: int) -> str:
    return f"{job_id}_{slot}.png"


async def _allocate_slot(page: "Page", job_id: str) -> int:
    global _active_job_id, _page_slots, _next_slot
    async with _slot_lock:
        if job_id != _active_job_id:
            _active_job_id = job_id
            _page_slots.clear()
            _next_slot = 0
        page_id = id(page)
        if page_id not in _page_slots:
            _page_slots[page_id] = _next_slot
            _next_slot += 1
        return _page_slots[page_id]


async def _screenshot_loop(page: "Page", job_id: str, slot: int, stop: asyncio.Event) -> None:
    path = _PREVIEW_DIR / preview_filename(job_id, slot)
    _PREVIEW_DIR.mkdir(parents=True, exist_ok=True)
    while not stop.is_set():
        try:
            await page.screenshot(path=str(path), full_page=False, timeout=5000)
            log_airta_progress({"type": "screenshot", "job_id": job_id, "slot": slot})
        except Exception:
            pass
        try:
            await asyncio.wait_for(stop.wait(), timeout=_INTERVAL_S)
        except asyncio.TimeoutError:
            continue


@asynccontextmanager
async def live_preview_context(page: "Page") -> AsyncIterator[None]:
    """Capture screenshots every second while the page session is active."""
    job_id = os.environ.get("AIRTA_JOB_ID", "").strip()
    if not job_id:
        yield
        return

    slot = await _allocate_slot(page, job_id)
    stop = asyncio.Event()
    task = asyncio.create_task(_screenshot_loop(page, job_id, slot, stop))
    try:
        yield
    finally:
        stop.set()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
