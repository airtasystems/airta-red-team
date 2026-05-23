"""Subprocess wrapper for company discovery — opens a browser, user navigates to
company About/home page, HTML is captured and company.json is generated via LLM."""
import asyncio
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_root / "browser-bot"))

from browser_bot.rubric_discovery import run_company_discovery  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python company_discovery_worker.py <site>", file=sys.stderr)
        sys.exit(1)
    site = sys.argv[1]
    ok = asyncio.run(run_company_discovery(site, overwrite=True))
    sys.exit(0 if ok else 1)
