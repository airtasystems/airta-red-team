"""UI- and API-based submission dispatch."""

import json
from pathlib import Path

from browser_bot.config import infer_ui_mode_from_suite_raw
from browser_bot.sites import get_submission_config

from browser_bot.submit.api import run_api_submission_multi, run_api_submission_single
from browser_bot.submit.multi import run_ui_submission_multi
from browser_bot.submit.single import run_ui_submission_single


def resolve_ui_submission_use_multi(
    sub: dict,
    suite_path: Path | str | None,
    mode_override: str | None,
) -> bool:
    """Choose single vs multi: explicit override, then suite file shape, then config.yaml."""
    if mode_override is not None:
        return mode_override == "multi"
    if suite_path:
        path = Path(suite_path)
        if path.is_file():
            try:
                raw = json.loads(path.read_text(encoding="utf-8-sig"))
            except (json.JSONDecodeError, OSError):
                raw = None
            if raw is not None:
                inferred = infer_ui_mode_from_suite_raw(raw)
                if inferred == "multi":
                    return True
                if inferred == "single":
                    return False
    return bool(sub.get("mode") == "multi" or sub.get("batch_size", 1) > 1)


def run_ui_submission(
    site: str,
    component: str,
    *,
    pool_fetcher=None,
    cluster_fetcher=None,
    human_fetcher=None,
    mode_override: str | None = None,
    suite_path=None,
) -> tuple[list[tuple[str, str | None]], Path | None]:
    """Run browser UI submission."""
    sub = get_submission_config(site, component)
    if not sub or sub.get("transport") != "ui":
        return [], None

    use_multi = resolve_ui_submission_use_multi(sub, suite_path, mode_override)

    if use_multi:
        return run_ui_submission_multi(
            site,
            component,
            pool_fetcher=pool_fetcher,
            cluster_fetcher=cluster_fetcher,
            human_fetcher=human_fetcher,
            suite_path=suite_path,
        )
    return run_ui_submission_single(
        site,
        component,
        pool_fetcher=pool_fetcher,
        cluster_fetcher=cluster_fetcher,
        human_fetcher=human_fetcher,
        suite_path=suite_path,
    )


async def run_api_submission(
    site: str,
    component: str,
    *,
    mode_override: str | None = None,
    suite_path=None,
) -> tuple[list[tuple[str, str | None]], Path | None]:
    """Run direct HTTP API submission."""
    sub = get_submission_config(site, component)
    if not sub or sub.get("transport") not in ("api", "api_document", "api_multipart"):
        return [], None

    use_multi = resolve_ui_submission_use_multi(sub, suite_path, mode_override)
    if use_multi:
        return await run_api_submission_multi(site, component, suite_path=suite_path)
    return await run_api_submission_single(site, component, suite_path=suite_path)


async def run_submission(
    site: str,
    component: str,
    *,
    pool_fetcher=None,
    cluster_fetcher=None,
    human_fetcher=None,
    mode_override: str | None = None,
    suite_path=None,
) -> tuple[list[tuple[str, str | None]], Path | None]:
    """Dispatch to UI or API submission based on component config."""
    sub = get_submission_config(site, component)
    if not sub:
        return [], None
    if sub.get("transport") in ("api", "api_document", "api_multipart"):
        return await run_api_submission(
            site,
            component,
            mode_override=mode_override,
            suite_path=suite_path,
        )
    return await run_ui_submission(
        site,
        component,
        pool_fetcher=pool_fetcher,
        cluster_fetcher=cluster_fetcher,
        human_fetcher=human_fetcher,
        mode_override=mode_override,
        suite_path=suite_path,
    )
