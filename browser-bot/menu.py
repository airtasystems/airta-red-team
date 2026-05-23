#!/usr/bin/env python3
"""Terminal menu for browser-bot: auth, run, manage sites."""

import asyncio
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from browser_bot.auth import capture_login
from browser_bot.refresh_token import refresh_auth
from browser_bot.sites import (
    ensure_component_dir,
    ensure_site_dir,
    get_domain_from_url,
    list_components,
    list_sites,
    load_component_config,
    load_site_config,
    remove_site,
    save_component_config,
    save_site_config,
)

# Session state - set on launch, used for duration
current_site: str | None = None
current_component: str | None = None


def _do_add_login() -> str | None:
    """Run add-login flow. Returns domain on success."""
    url = None
    from_config = False
    if current_site:
        site_cfg = load_site_config(current_site)
        if current_component:
            config = load_component_config(current_site, current_component)
            url = config.get("login_url")
        else:
            url = site_cfg.get("login_url")
        from_config = bool(url)
    if not url:
        url = input("\n  Enter login URL (e.g. https://airtasystems.com/login): ").strip()
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        url = "http://" + url if url.startswith("localhost") or url.startswith("127.") else "https://" + url
    domain = asyncio.run(capture_login(url, force_persistent=True))
    if domain:
        print(f"\n  Saved auth for {domain} -> sites/{domain}/")
        if not from_config and current_site:
            cfg = load_site_config(current_site)
            cfg["login_url"] = url
            save_site_config(current_site, cfg)
            print(f"  Saved login_url -> sites/{current_site}/config.yaml (site-level)")
    return domain


def _create_new_site() -> str | None:
    """Create site directory structure. Returns domain on success."""
    raw = input("\n  Enter domain or URL (e.g. example.com): ").strip()
    if not raw:
        return None
    domain = get_domain_from_url(raw) if "://" in raw or "/" in raw else raw.strip()
    if not domain:
        return None
    ensure_site_dir(domain)
    print(f"  Created sites/{domain}/")
    return domain


def select_site_and_component() -> bool:
    """Prompt for site and component. Returns True if set."""
    global current_site, current_component
    sites = list_sites()

    print("\n  Select site:")
    for i, s in enumerate(sites, 1):
        print(f"    {i}. {s}")
    print(f"    {len(sites) + 1}. Create new site")
    choice = input(f"  [1-{len(sites) + 1}]: ").strip()
    if not choice or not choice.isdigit():
        return False
    idx = int(choice)
    if idx == len(sites) + 1:
        domain = _create_new_site()
        if not domain:
            print("  Cancelled.")
            return False
        current_site = domain
    elif 1 <= idx <= len(sites):
        current_site = sites[idx - 1]
    else:
        return False

    components = list_components(current_site)
    print(f"\n  Select component for {current_site}:")
    for i, c in enumerate(components, 1):
        print(f"    {i}. {c}")
    print(f"    {len(components) + 1}. (new)")
    choice = input(f"  [1-{len(components) + 1}]: ").strip()
    if not choice or not choice.isdigit():
        return False
    idx = int(choice)
    if 1 <= idx <= len(components):
        current_component = components[idx - 1]
    elif idx == len(components) + 1:
        current_component = input("  New component name: ").strip()
        if current_component:
            current_component = "".join(
                c if c.isalnum() or c in "-_" else "_" for c in current_component
            ).strip("_") or "default"
            ensure_component_dir(current_site, current_component)
        else:
            return False
    else:
        return False

    if current_site and current_component:
        print(f"\n  Using: {current_site} / {current_component}")
        return True
    return False


def clear_screen():
    print("\033[2J\033[H", end="")


def show_menu():
    ctx = f" [{current_site}/{current_component}]" if (current_site and current_component) else ""
    print("\n" + "=" * 50)
    print(f"  BROWSER BOT{ctx}")
    print("=" * 50)
    print("  1. Add login (open browser, log in, save auth)")
    print("  2. Create component config")
    print("  3. Remove site config")
    print("  4. Back")
    print("=" * 50)


def menu_add_login():
    domain = _do_add_login()
    if not domain:
        print("  Cancelled.")


def menu_remove_site():
    global current_site, current_component
    sites = list_sites()
    if not sites:
        print("\n  No saved sites.")
        return
    print("\n  Sites:")
    for i, s in enumerate(sites, 1):
        print(f"    {i}. {s}")
    choice = input(f"  Select [1-{len(sites)}]: ").strip()
    if not choice or not choice.isdigit():
        print("  Cancelled.")
        return
    idx = int(choice)
    if not 1 <= idx <= len(sites):
        print("  Invalid choice.")
        return
    domain = sites[idx - 1]
    if remove_site(domain):
        print(f"  Removed {domain}")
        if domain == current_site:
            current_site = None
            current_component = None
    else:
        print(f"  {domain} not found.")


def menu_run_post():
    if not current_site or not current_component:
        print("\n  No site/component selected. Use option 6 to change.")
        return
    print("\n  Running POST requests from posts.json...")
    import main

    asyncio.run(main.run_posts(site=current_site, component=current_component))


def menu_create_component():
    """Train component: open browser with auth, record input/submit/response selectors."""
    if not current_site or not current_component:
        print("\n  No site/component selected. Use option 6 to change.")
        return
    from browser_bot.record_submission import run_training

    if not run_training(current_site, current_component):
        print("  Training cancelled or failed.")


def menu_refresh_token():
    if not current_site or not current_component:
        print("\n  No site/component selected. Use option 6 to change.")
        return
    result, err = refresh_auth(current_site, current_component, debug=True)
    if result:
        print(f"\n  Refreshed auth for {current_site} -> auth.json updated.")
    else:
        print(f"\n  Refresh failed. {err}")


def menu_change_site_component():
    select_site_and_component()


def _refresh_background_worker(stop_event: threading.Event):
    """Run refresh every 10 minutes while menu is open."""
    while not stop_event.wait(600):  # 10 minutes
        if not current_site or not current_component:
            continue
        if not load_component_config(current_site, current_component).get("refresh_url"):
            continue
        try:
            result, err = refresh_auth(current_site, current_component, debug=False)
            if result:
                print("\n  [Auto-refresh] Auth tokens updated.")
            # Silently ignore failures (token may be expired)
        except Exception:
            pass


def main_loop():
    global current_site, current_component
    while not (current_site and current_component):
        if not select_site_and_component():
            print("  Cancelled.")
            return

    stop_event = threading.Event()
    refresh_thread = threading.Thread(target=_refresh_background_worker, args=(stop_event,), daemon=True)
    refresh_thread.start()

    try:
        while True:
            show_menu()
            choice = input("  Choice [1-4]: ").strip() or "4"

            if choice == "1":
                menu_add_login()
            elif choice == "2":
                menu_create_component()
            elif choice == "3":
                menu_remove_site()
            elif choice == "4":
                print("\n  Back.")
                break
            else:
                print("  Invalid choice.")
    finally:
        stop_event.set()


if __name__ == "__main__":
    main_loop()
