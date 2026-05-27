#!/usr/bin/env python3
"""
Browser Bot: Tiered fetching via Playwright browser automation.

Tiers (in order):
  1. Pool     - Full speed, page pool + queue
  2. Cluster  - Max power, multi-context
  3. Human    - Stealth, new context per request
"""

import asyncio
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

# Add project root for imports
sys.path.insert(0, str(Path(__file__).parent))

console = Console()


from playwright.async_api import async_playwright

from browser_bot.config import (
    CONTEXT_COUNT,
    FETCH_METHOD,
    POOL_CLUSTER_HUMAN_LIKE,
    PAGES_PER_CONTEXT,
    POOL_SIZE,
    POSTS,
    get_pool_cluster_browser_enhancements,
)
from browser_bot.sites import (
    get_component_urls_and_posts,
    get_domain_from_url,
    load_component_config,
    get_storage_state_path,
    get_submission_config,
    describe_submission_config_issue,
)
from browser_bot.browser.launcher import launch_browser, new_pool_cluster_browser_context
from browser_bot.fetchers.pool import PoolFetcher
from browser_bot.fetchers.cluster import ClusterFetcher
from browser_bot.fetchers.human import HumanFetcher
from browser_bot.fetchers.base import PostResult
from browser_bot.metrics import Metrics


def _describe_submission_config_issue(site: str, component: str) -> str:
    return describe_submission_config_issue(load_component_config(site, component))


async def post_url(
    url: str,
    *,
    data: dict | None = None,
    json_data: dict | None = None,
    headers: dict | None = None,
    pool_fetcher: PoolFetcher | None = None,
    cluster_fetcher: ClusterFetcher | None = None,
    human_fetcher: HumanFetcher = None,
    metrics: Metrics = None,
) -> PostResult | None:
    """Try POST tiers in order until one succeeds (same pipeline as GET)."""
    def _log(r: PostResult):
        status_style = "green" if 200 <= r.status < 300 else "yellow" if r.status < 400 else "red"
        console.print(f"  [bold cyan]{r.tier.upper()}[/] [dim]{r.url}[/] [{status_style}]{r.status}[/] {len(r.body):,} chars · {r.elapsed:.2f}s")
        if r.body:
            preview = (r.body[:120] + "…") if len(r.body) > 120 else r.body
            console.print(f"      [dim]{preview}[/]")

    method = FETCH_METHOD.lower()
    if method not in ("auto", "pool", "cluster", "human"):
        method = "auto"

    # Tier 1: Pool
    if method in ("auto", "pool") and pool_fetcher:
        result = await pool_fetcher.post(url, data=data, json_data=json_data, headers=headers)
        if result:
            if metrics:
                metrics.record(result.tier, result.elapsed)
            _log(result)
            return result
        if method == "pool":
            console.print(f"[bold red]FAIL[/] [dim]{url}[/] [red]→ Pool POST failed[/]")
            return None

    # Tier 2: Cluster
    if method in ("auto", "cluster") and cluster_fetcher:
        result = await cluster_fetcher.post(url, data=data, json_data=json_data, headers=headers)
        if result:
            if metrics:
                metrics.record(result.tier, result.elapsed)
            _log(result)
            return result
        if method == "cluster":
            console.print(f"[bold red]FAIL[/] [dim]{url}[/] [red]→ Cluster POST failed[/]")
            return None

    # Tier 3: Human
    if method in ("auto", "human") and human_fetcher:
        result = await human_fetcher.post(url, data=data, json_data=json_data, headers=headers)
        if result:
            if metrics:
                metrics.record(result.tier, result.elapsed)
            _log(result)
            return result

    console.print(f"[bold red]FAIL[/] [dim]{url}[/] [red]→ all tiers failed[/]")
    return None


async def _setup_fetchers(
    playwright,
    primary_domain: str,
    url_count: int | None = None,
    post_count: int | None = None,
    *,
    human_only: bool = False,
):
    """Shared setup for GET and POST. Returns (pool_fetcher, cluster_fetcher, human_fetcher, pool_context, cluster_browser, cluster_contexts).

    human_only: when True, behave like FETCH_METHOD=human (no pool/cluster browsers or fetchers).
    """
    p = playwright
    storage_state = get_storage_state_path(primary_domain)
    storage_state_str = str(storage_state) if storage_state else None

    pool_fetcher = None
    cluster_fetcher = None
    pool_context = None
    cluster_browser = None
    cluster_contexts = []
    url_count = url_count if url_count is not None else 0
    post_count = post_count if post_count is not None else len(POSTS)
    count = max(post_count, url_count)
    method = "human" if human_only else FETCH_METHOD.lower()
    need_pool = method in ("auto", "pool")
    need_cluster = method in ("auto", "cluster")
    pool_size = min(POOL_SIZE, count) if (count and need_pool) else 0
    cluster_workers = min(CONTEXT_COUNT * PAGES_PER_CONTEXT, count) if (count and need_cluster) else 0

    use_human_chrome, allow_styles, use_stealth, use_human_context = get_pool_cluster_browser_enhancements()

    try:
        if pool_size > 0:
            pool_browser = await launch_browser(p, human_mode=use_human_chrome)
            page_queue = asyncio.Queue()
            for _ in range(pool_size):
                ctx = await new_pool_cluster_browser_context(
                    pool_browser,
                    storage_state_path=storage_state_str,
                    full_human_tier_bundle=POOL_CLUSTER_HUMAN_LIKE,
                    allow_styles=allow_styles,
                    use_stealth=use_stealth,
                    use_human_context=use_human_context,
                )
                page = await ctx.new_page()
                await page_queue.put(page)
            pool_fetcher = PoolFetcher(page_queue)
            pool_context = pool_browser
    except Exception as e:
        console.print(f"[yellow]Pool setup skipped:[/] {e}")
        pool_fetcher = None

    try:
        if cluster_workers > 0:
            cluster_browser = await launch_browser(p, human_mode=use_human_chrome)
            cluster_page_queue = asyncio.Queue()
            pages_created = 0
            for ci in range(CONTEXT_COUNT):
                if pages_created >= cluster_workers:
                    break
                ctx = await new_pool_cluster_browser_context(
                    cluster_browser,
                    storage_state_path=storage_state_str,
                    full_human_tier_bundle=POOL_CLUSTER_HUMAN_LIKE,
                    allow_styles=allow_styles,
                    use_stealth=use_stealth,
                    use_human_context=use_human_context,
                )
                cluster_contexts.append(ctx)
                for _ in range(PAGES_PER_CONTEXT):
                    if pages_created >= cluster_workers:
                        break
                    page = await ctx.new_page()
                    await cluster_page_queue.put(page)
                    pages_created += 1
            cluster_fetcher = ClusterFetcher(cluster_page_queue)
    except Exception as e:
        console.print(f"[yellow]Cluster setup skipped:[/] {e}")
        cluster_fetcher = None

    human_fetcher = HumanFetcher(p)

    return pool_fetcher, cluster_fetcher, human_fetcher, pool_context, cluster_browser, cluster_contexts


async def run_with_page_from_fetchers(
    playwright,
    primary_domain: str,
    callback,
    storage_path: str | None = None,
    storage_state: dict | None = None,
    *,
    interactive: bool = False,
    allow_all: bool = False,
    headless: bool | None = None,
    human_only: bool = False,
):
    """
    Run callback(page) using first successful fetcher.
    interactive=True: headless=False, allow_all=True (for login, create config). Only Human supports this.
    allow_all: when True, skip resource blocking (e.g. for refresh). Can be used without interactive.
    headless: explicit override — True forces headless regardless of config, False forces visible.
              When None (default), interactive=True → False, interactive=False → uses config HEADLESS.
    storage_state: optional dict (overrides storage_path). Only Human supports this.
    human_only: when True, skip pool/cluster setup and fetchers (same as FETCH_METHOD=human). Use for discovery / selector recording.
    Returns callback result or None if all fail.
    """
    (
        pool_fetcher,
        cluster_fetcher,
        human_fetcher,
        pool_context,
        cluster_browser,
        cluster_contexts,
    ) = await _setup_fetchers(playwright, primary_domain, post_count=1, human_only=human_only)
    storage_str = str(storage_path) if storage_path else None
    if headless is not None:
        resolved_headless = headless
    else:
        resolved_headless = False if interactive else None
    allow_all_flag = interactive or allow_all

    fetchers_to_try = []
    if not interactive and pool_fetcher:
        fetchers_to_try.append(pool_fetcher)
    if not interactive and cluster_fetcher:
        fetchers_to_try.append(cluster_fetcher)
    if human_fetcher:
        fetchers_to_try.append(human_fetcher)

    result = None
    for fetcher in fetchers_to_try:
        result = await fetcher.with_page(
            callback,
            storage_path=storage_str,
            storage_state=storage_state,
            headless=resolved_headless,
            allow_all=allow_all_flag,
            discovery_layout=interactive,
        )
        if result is not None:
            break

    if pool_context:
        await pool_context.close()
    if cluster_browser:
        for ctx in cluster_contexts:
            await ctx.close()
        await cluster_browser.close()

    return result


async def run_post_from_fetchers(
    playwright,
    url: str,
    primary_domain: str,
    *,
    data: dict | None = None,
    json_data: dict | None = None,
    headers: dict | None = None,
) -> PostResult | None:
    """Run single POST through fetcher pipeline. Returns PostResult or None."""
    (
        pool_fetcher,
        cluster_fetcher,
        human_fetcher,
        pool_context,
        cluster_browser,
        cluster_contexts,
    ) = await _setup_fetchers(playwright, primary_domain, post_count=1)

    result = await post_url(
        url,
        data=data,
        json_data=json_data,
        headers=headers,
        pool_fetcher=pool_fetcher,
        cluster_fetcher=cluster_fetcher,
        human_fetcher=human_fetcher,
    )

    if pool_context:
        await pool_context.close()
    if cluster_browser:
        for ctx in cluster_contexts:
            await ctx.close()
        await cluster_browser.close()

    return result


async def run_posts(site: str | None = None, component: str | None = None, *, mode: str | None = None, suite_path=None):
    """Run POST: UI mode if component has submission config, else HTTP mode from posts.json.

    mode: optional override ("single" | "multi"). When None, single vs multi is inferred
    from suite_path JSON (e.g. tree-of-thoughts vs zero-shot), else config.yaml.
    suite_path: optional Path to the suite JSON to read prompts from directly, bypassing
    the posts/ staging directory.
    """
    if site and component:
        from browser_bot.config import apply_component_settings

        apply_component_settings(site, component)

    # UI mode: component has submission config
    if site and component:
        sub = get_submission_config(site, component)
        if suite_path and not sub:
            reason = _describe_submission_config_issue(site, component)
            console.print(
                f"[yellow]Cannot run UI test suite for {site}/{component}: {reason}. "
                "Run Discovery or complete the component submission config before running generated tests.[/]"
            )
            return
        if sub:
            from browser_bot.config import get_posts_batches, get_posts_strings
            from browser_bot.submit import resolve_ui_submission_use_multi, run_submission

            use_multi = resolve_ui_submission_use_multi(sub, suite_path, mode)
            transport = sub.get("transport", "ui")
            transport_label = "API" if transport == "api" else "UI"
            if use_multi:
                batches = get_posts_batches(suite_path=suite_path)
                if not batches:
                    console.print(
                        "[yellow]No multi batches found. "
                        "Add posts/posts_multi.json (or posts_multi.json at project root) with "
                        "mandates[].prompts[].prompts (string arrays), a top-level batches[] array-of-arrays, "
                        "or a legacy JSON [[\"a\",\"b\"], ...].[/]"
                    )
                    return
                post_count = len(batches)
                total = sum(len(b) for b in batches)
                src_label = str(suite_path) if suite_path else "posts/posts_multi.json"
                console.print(
                    f"\n[bold]{transport_label} POST[/] {site}/{component} "
                    f"({total} prompts in {post_count} batch(es) from {src_label})\n"
                )
            else:
                posts_strings = get_posts_strings(suite_path=suite_path)
                if not posts_strings:
                    console.print(
                        "[yellow]No UI prompts found. "
                        "Add posts/posts_single.json (or posts_single.json at project root) with "
                        "mandates[].prompts[].prompt, a top-level prompts[] list, or a JSON array of strings.[/]"
                    )
                    return
                post_count = len(posts_strings)
                src_label = str(suite_path) if suite_path else "posts/posts_single.json"
                console.print(
                    f"\n[bold]{transport_label} POST[/] {site}/{component} "
                    f"({post_count} prompt(s) from {src_label})\n"
                )

            if transport == "api":
                results, log_path = await run_submission(
                    site,
                    component,
                    mode_override=mode,
                    suite_path=suite_path,
                )
            else:
                primary_domain = site
                async with async_playwright() as p:
                    pool_fetcher, cluster_fetcher, human_fetcher, pool_context, cluster_browser, cluster_contexts = await _setup_fetchers(
                        p, primary_domain, post_count=post_count
                    )
                    results, log_path = await run_submission(
                        site,
                        component,
                        pool_fetcher=pool_fetcher,
                        cluster_fetcher=cluster_fetcher,
                        human_fetcher=human_fetcher,
                        mode_override=mode,
                        suite_path=suite_path,
                    )
                    if pool_context:
                        await pool_context.close()
                    if cluster_browser:
                        for ctx in cluster_contexts:
                            await ctx.close()
                        await cluster_browser.close()

            for inp, resp in results:
                inp_short = (inp[:60] + "…") if len(inp) > 60 else inp
                console.print(f"  [bold]Input:[/] {inp_short}")
                if resp:
                    resp_short = (resp[:200] + "…") if len(resp) > 200 else resp
                    console.print(f"  [dim]Response:[/] {resp_short}")
                else:
                    console.print("  [dim]Response:[/] (none)")
            console.print(f"\n[bold green]Finished:[/] {len(results)} {transport_label} submission(s)")
            if log_path:
                console.print(f"  [dim]Log:[/] {log_path}")
            return

    # HTTP mode
    posts = POSTS
    if site and component:
        _, comp_posts = get_component_urls_and_posts(site, component)
        if comp_posts:
            posts = comp_posts
    if not posts:
        console.print("[yellow]No posts in posts/posts.json. Add entries with url, data/json, headers.[/]")
        return

    from browser_bot.refresh_token import refresh_auth

    primary_domain = get_domain_from_url(posts[0]["url"]) if posts else ""
    # Refresh token if refresh_url is configured for this domain
    if primary_domain:
        result, _ = refresh_auth(primary_domain, None)
        if result:
            console.print("[dim]Refreshed auth tokens.[/]")

    metrics = Metrics()

    async with async_playwright() as p:
        pool_fetcher, cluster_fetcher, human_fetcher, pool_context, cluster_browser, cluster_contexts = await _setup_fetchers(p, primary_domain, post_count=len(posts))

        console.print(f"\n[bold]POST[/] {len(posts)} request(s) from posts/posts.json...\n")
        results: list[PostResult | None] = []
        for entry in posts:
            r = await post_url(
                entry["url"],
                data=entry.get("data"),
                json_data=entry.get("json"),
                headers=entry.get("headers"),
                pool_fetcher=pool_fetcher,
                cluster_fetcher=cluster_fetcher,
                human_fetcher=human_fetcher,
                metrics=metrics,
            )
            results.append(r)

        # Cleanup
        if pool_context:
            await pool_context.close()
        if cluster_browser:
            for ctx in cluster_contexts:
                await ctx.close()
            await cluster_browser.close()

    # Metrics table
    summary = metrics.summary()
    if summary != "No metrics":
        table = Table(title="POST Metrics", box=box.ROUNDED, show_header=True)
        table.add_column("Tier", style="cyan")
        table.add_column("Total", justify="right", style="green")
        table.add_column("Avg", justify="right", style="green")
        table.add_column("Count", justify="right", style="dim")
        for line in summary.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                tier = parts[0].strip()
                rest = parts[1].strip()
                vals = rest.replace("s", "").split()
                total = vals[1] if len(vals) > 1 else "—"
                avg = vals[3] if len(vals) > 3 else "—"
                count = vals[5] if len(vals) > 5 else "—"
                table.add_row(tier, f"{total}s", f"{avg}s", count)
        console.print()
        console.print(table)
    ok = sum(1 for r in results if r and 200 <= r.status < 300)
    console.print(f"\n[bold green]Finished:[/] {ok}/{len(results)} successful")


if __name__ == "__main__":
    from menu import main_loop
    main_loop()
