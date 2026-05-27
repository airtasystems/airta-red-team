"""Subprocess wrapper for login — opens a browser, user logs in, auth state is saved."""
import asyncio
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_root / "browser-bot"))

from browser_bot.auth import capture_login  # noqa: E402
from browser_bot.sites import validate_login_url  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python login_worker.py <url>", file=sys.stderr)
        sys.exit(1)
    url = validate_login_url(sys.argv[1])
    if not url:
        print("[!] Invalid login URL: must be a non-empty http(s) URL with a host.", file=sys.stderr)
        sys.exit(1)
    domain = asyncio.run(capture_login(url))
    if domain:
        print(f"[+] Auth saved for {domain}")
        sys.exit(0)
    else:
        print("[!] Login failed or cancelled")
        sys.exit(1)
