"""Record UI submission flow: open browser, capture HTML, extract config via AI.

Discovery runs in 7 steps:
  1. Interactive browser — user navigates to page, presses Enter / Continue
  2. Browser automation — detect whether the page supports file uploads
  3. Multimodal config — when uploads exist, capture file input selector (auto + confirm)
  4. LLM / manual — prompt input selector
  5. Submit selector
  6. Headless verify submit — fills + clicks, detects response
  7. Response selector
  Config is saved incrementally after each confirmed step.
"""

import asyncio
import json
import os
import re
from datetime import datetime
from pathlib import Path

import yaml
from playwright.async_api import async_playwright

from browser_bot.sites import (
    get_component_config_path,
    get_component_path,
    get_login_profile_path,
    get_storage_state_path,
    load_component_config,
    load_component_config_raw,
    ensure_component_dir,
    ensure_site_config_on_discovery,
    write_component_config_with_header,
)
from browser_bot.browser.launcher import launch_persistent_context
from browser_bot.config import LOGIN_USE_PERSISTENT_CONTEXT


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

def _should_use_login_profile(site: str) -> bool:
    """Persistent profiles are optional because some sites crash Chromium on reuse."""
    return LOGIN_USE_PERSISTENT_CONTEXT and get_login_profile_path(site).exists()


def _print_profile_disabled_notice(site: str) -> None:
    if get_login_profile_path(site).exists() and not LOGIN_USE_PERSISTENT_CONTEXT:
        print("  Persistent login profile exists but is disabled; using saved auth state.")

def _save_config_with_comments(site: str, component: str, config: dict) -> None:
    ensure_component_dir(site, component)
    path = get_component_config_path(site, component)
    write_component_config_with_header(path, config)


def _ensure_site_config_for_discovery(site: str, component: str) -> None:
    """Create sites/<site>/config.yaml on first discovery if it does not exist."""
    comp_raw = load_component_config_raw(site, component)
    login_url = comp_raw.get("login_url") if isinstance(comp_raw.get("login_url"), str) else None
    created = ensure_site_config_on_discovery(site, login_url=login_url)
    if created:
        print(f"  Created site config -> sites/{site}/config.yaml")


def _save_partial(site: str, component: str, submission: dict) -> None:
    """Write current submission dict to config.yaml without losing existing top-level keys."""
    comp_raw = load_component_config_raw(site, component)
    comp_raw.setdefault("urls", [])
    comp_raw.setdefault("posts", [])
    comp_raw["submission"] = submission
    _save_config_with_comments(site, component, comp_raw)


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

async def _wait_for_enter() -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, input)


_MANUAL_DISCOVERY_SCRIPT = r"""
(() => {
  if (window.__airtaManualDiscoveryInstalled) return;
  window.__airtaManualDiscoveryInstalled = true;

  const state = {
    mode: "idle",
    title: "AIRTA Manual Discovery",
    message: "Follow the steps to configure this component.",
    action: "Continue",
    secondaryAction: "",
    allowAction: false,
  };

  function cssEscape(value) {
    if (window.CSS && typeof window.CSS.escape === "function") return window.CSS.escape(value);
    return String(value).replace(/[^a-zA-Z0-9_-]/g, "\\$&");
  }

  function quoteAttr(value) {
    return String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  }

  /** Collapse whitespace for comparing button/submit labels. */
  function normalizedInnerText(elem) {
    if (!elem || elem.innerText == null) return "";
    return elem.innerText.replace(/\s+/g, " ").trim();
  }

  /** Nearest section-like region that has a uniqueness landmark (preferred for scoped selectors). */
  function nearestLandmarkSelector(startEl) {
    let cur = startEl;
    while (cur && cur.nodeType === Node.ELEMENT_NODE && cur !== document.body) {
      const tag = cur.tagName.toLowerCase();
      const alb = cur.getAttribute("aria-labelledby");
      if (alb && ["section", "aside", "article", "main", "nav"].includes(tag)) {
        const sel = `${tag}[aria-labelledby="${quoteAttr(alb)}"]`;
        try {
          const n = document.querySelectorAll(sel).length;
          if (n === 1) return sel;
        } catch (_) {}
      }
      if (tag === "section" && cur.id) {
        const sel = `section#${cssEscape(cur.id)}`;
        try {
          if (document.querySelectorAll(sel).length === 1) return sel;
        } catch (_) {}
      }
      cur = cur.parentElement;
    }
    return "";
  }

  function landmarkRootEl(landmarkSel) {
    if (!landmarkSel) return null;
    try {
      return document.querySelector(landmarkSel);
    } catch (_) {
      return null;
    }
  }

  /** Buttons whose visible label exactly equals target within root (or entire document when root null). */
  function buttonsMatchingLabel(root, label) {
    const w = label.replace(/\s+/g, " ").trim();
    if (!w) return [];
    const scope = root || document.documentElement || document.body;
    if (!scope) return [];
    return [...scope.querySelectorAll("button")].filter((b) => normalizedInnerText(b) === w);
  }

  function usefulTargetFor(el) {
    if (!el || el.nodeType !== Node.ELEMENT_NODE) return el;

    const input = el.closest('textarea, input:not([type="hidden"]), select, [contenteditable="true"], [contenteditable=""]');
    if (input) return input;

    const action = el.closest('button, [role="button"], a[href], input[type="submit"], input[type="button"]');
    if (action) return action;

    const response = el.closest('[data-message-author-role], [data-testid*="message"], [data-testid*="response"], article');
    if (response) return response;

    const stable = el.closest('[data-testid], [data-test], [data-cy], [aria-label], [name]');
    return stable || el;
  }

  function selectorFor(el) {
    if (!el || el.nodeType !== Node.ELEMENT_NODE) return "";
    if (el.id) return `#${cssEscape(el.id)}`;

    const tag = el.tagName.toLowerCase();
    const landmarkSel = nearestLandmarkSelector(el);
    const landRoot = landmarkRootEl(landmarkSel);

    const sharedStableAttrs = new Set(["data-message-author-role"]);
    const stableAttrs = ["data-testid", "data-test", "data-cy", "data-message-author-role", "aria-label", "name", "role", "placeholder", "contenteditable", "type"];
    for (const attr of stableAttrs) {
      const value = el.getAttribute(attr);
      if (value) {
        const selector = `${tag}[${attr}="${quoteAttr(value)}"]`;
        try {
          const count = document.querySelectorAll(selector).length;
          if (count === 1 || (count > 1 && sharedStableAttrs.has(attr))) return selector;
        } catch (_) {}
      }
    }

    // For buttons: try title attribute and unique class combos more aggressively
    if (tag === "button" || el.getAttribute("role") === "button") {
      const title = el.getAttribute("title");
      if (title) {
        const sel = `${tag}[title="${quoteAttr(title)}"]`;
        try { if (document.querySelectorAll(sel).length === 1) return sel; } catch (_) {}
      }
      // Try type=submit alone if unique
      if (el.getAttribute("type") === "submit") {
        try { if (document.querySelectorAll("button[type='submit']").length === 1) return "button[type='submit']"; } catch (_) {}
      }
    }

    if (el.classList && el.classList.length) {
      const classes = Array.from(el.classList)
        .filter(c => !c.startsWith("__airta_") && !c.startsWith("airta-"))
        .filter(c => !/[0-9]{4,}|:|\/|\[|\]/.test(c))
        .slice(0, 3);
      if (classes.length) {
        const selector = `${tag}.${classes.map(cssEscape).join(".")}`;
        try {
          if (document.querySelectorAll(selector).length === 1) return selector;
        } catch (_) {}
        // Try just the first class if the combo isn't unique
        if (classes.length > 1) {
          const singleClass = `${tag}.${cssEscape(classes[0])}`;
          try {
            if (document.querySelectorAll(singleClass).length === 1) return singleClass;
          } catch (_) {}
        }
      }
    }

    // Scoped class when the same markup appears several times across distinct regions/widgets.
    if (landRoot && el.classList && el.classList.length) {
      const filtered = Array.from(el.classList)
        .filter(c => !c.startsWith("__airta_") && !c.startsWith("airta-"))
        .filter(c => !/[0-9]{4,}|:|\/|\[|\]/.test(c))
        .slice(0, 3);
      if (filtered.length) {
        const selScoped = `${tag}.${filtered.map(cssEscape).join(".")}`;
        try {
          const nGlobal = document.querySelectorAll(selScoped).length;
          let nScoped = 0;
          try { nScoped = landRoot.querySelectorAll(selScoped).length; } catch (_) { nScoped = 999; }
          if (
            nGlobal > 1
            && nScoped === 1
            && landRoot.contains(el)
            && typeof el.matches === "function"
            && el.matches(selScoped)
          ) {
            return `${landmarkSel} ${selScoped}`;
          }
        } catch (_) {}
      }
    }

    // Playwright :has-text (not valid in querySelector); verify uniqueness via DOM text sweep.
    const isButtonLike = tag === "button" || el.getAttribute("role") === "button";
    if (isButtonLike) {
      const label = normalizedInnerText(el);
      if (label.length >= 4 && label.length <= 240) {
        const lit = JSON.stringify(label);
        if (landRoot) {
          const hits = buttonsMatchingLabel(landRoot, label);
          if (hits.length === 1 && hits[0] === el) return `${landmarkSel} button:has-text(${lit})`;
        }
        const allHits = buttonsMatchingLabel(document.documentElement, label);
        if (allHits.length === 1 && allHits[0] === el) return `button:has-text(${lit})`;
      }
    }

    // Structural fallback — walk up but anchor on landmarks / stable ancestor attrs early.
    // Cap at 5 levels to avoid over-specific positional paths.
    const MAX_DEPTH = 5;
    const parts = [];
    let cur = el;
    while (cur && cur.nodeType === Node.ELEMENT_NODE && cur !== document.body && parts.length < MAX_DEPTH) {
      let part = cur.tagName.toLowerCase();
      if (cur.id) {
        part += `#${cssEscape(cur.id)}`;
        parts.unshift(part);
        break;
      }
      if (cur !== el) {
        const tagLc = cur.tagName.toLowerCase();
        const alb = cur.getAttribute("aria-labelledby");
        if (alb && ["section", "aside", "article", "main", "nav"].includes(tagLc)) {
          parts.unshift(`${tagLc}[aria-labelledby="${quoteAttr(alb)}"]`);
          break;
        }
        for (const attr of ["data-testid", "data-test", "data-cy", "aria-label", "name"]) {
          const v = cur.getAttribute(attr);
          if (v) {
            parts.unshift(`${cur.tagName.toLowerCase()}[${attr}="${quoteAttr(v)}"]`);
            cur = null;
            break;
          }
        }
        if (cur === null) break;
      }
      const parent = cur.parentElement;
      if (parent) {
        const siblings = Array.from(parent.children).filter(x => x.tagName === cur.tagName);
        if (siblings.length > 1) part += `:nth-of-type(${siblings.indexOf(cur) + 1})`;
      }
      parts.unshift(part);
      cur = parent;
    }
    let positional = parts.join(" > ");
    if (!positional) return "";

    // Optionally prefix with a semantic landmark only when positional is ambiguous or relies on brittle indexing.
    if (landmarkSel) {
      const scopedTail = `${landmarkSel} ${positional}`;
      try {
        let nPos = 0;
        try {
          nPos = document.querySelectorAll(positional).length;
        } catch (_) {
          nPos = 0;
        }
        const brittle = positional.includes(":nth-of-type");
        const needScope = nPos > 1 || brittle;
        if (needScope && document.querySelector(scopedTail)) return scopedTail;
      } catch (_) {}
    }

    return positional;
  }

  function ensurePanel() {
    let panel = document.getElementById("__airta_manual_panel");
    if (panel) return panel;
    panel = document.createElement("div");
    panel.id = "__airta_manual_panel";
    panel.innerHTML = `
      <div class="airta-title"></div>
      <div class="airta-message"></div>
      <div class="airta-actions">
        <button type="button" class="airta-button airta-primary"></button>
        <button type="button" class="airta-button airta-secondary"></button>
      </div>
      <div class="airta-hint"></div>
    `;
    const style = document.createElement("style");
    style.id = "__airta_manual_style";
    style.textContent = `
      #__airta_manual_panel {
        position: fixed; top: 16px; left: 16px; z-index: 2147483647;
        width: 340px; box-sizing: border-box; padding: 12px 14px;
        background: #252525; color: #dcddde; border: 1px solid #333333;
        border-radius: 10px; box-shadow: 0 8px 24px rgba(0,0,0,.35);
        font-family: "Inter", ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        font-size: 12px; line-height: 1.55;
      }
      #__airta_manual_panel .airta-title { font-weight: 600; margin-bottom: 6px; cursor: move; user-select: none; color: #dcddde; }
      #__airta_manual_panel .airta-message { color: #999999; margin-bottom: 10px; white-space: pre-wrap; }
      #__airta_manual_panel .airta-actions { display: flex; flex-wrap: wrap; gap: 8px; }
      #__airta_manual_panel .airta-button {
        background: #7f6df2; color: #fff; border: 1px solid transparent; border-radius: 6px;
        padding: 8px 12px; font-weight: 600; cursor: pointer;
      }
      #__airta_manual_panel .airta-button:hover {
        background: #8870ff;
      }
      #__airta_manual_panel .airta-secondary {
        background: transparent; color: #dcddde; border-color: #444444;
      }
      #__airta_manual_panel .airta-secondary:hover {
        background: #333333;
      }
      #__airta_manual_panel .airta-hint { color: #727272; font-size: 11px; margin-top: 8px; }
      .__airta_manual_hover { outline: 2px solid #7f6df2 !important; outline-offset: 2px !important; }
    `;
    if (!document.getElementById(style.id)) document.documentElement.appendChild(style);
    document.documentElement.appendChild(panel);
    let dragging = false;
    let dragOffsetX = 0;
    let dragOffsetY = 0;
    panel.querySelector(".airta-title").addEventListener("mousedown", (event) => {
      dragging = true;
      const rect = panel.getBoundingClientRect();
      dragOffsetX = event.clientX - rect.left;
      dragOffsetY = event.clientY - rect.top;
      event.preventDefault();
      event.stopPropagation();
    });
    document.addEventListener("mousemove", (event) => {
      if (!dragging) return;
      const nextLeft = Math.max(8, Math.min(window.innerWidth - panel.offsetWidth - 8, event.clientX - dragOffsetX));
      const nextTop = Math.max(8, Math.min(window.innerHeight - panel.offsetHeight - 8, event.clientY - dragOffsetY));
      panel.style.left = `${nextLeft}px`;
      panel.style.top = `${nextTop}px`;
      panel.style.right = "auto";
    }, true);
    document.addEventListener("mouseup", () => {
      dragging = false;
    }, true);
    panel.querySelector(".airta-primary").addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (!window.airtaManualEvent) return;
      if (state.mode === "confirm") {
        window.airtaManualEvent({ type: "confirm" });
      } else {
        window.airtaManualEvent({ type: "continue" });
      }
    });
    panel.querySelector(".airta-secondary").addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (window.airtaManualEvent) window.airtaManualEvent({ type: "retry" });
    });
    return panel;
  }

  function render() {
    const panel = ensurePanel();
    panel.querySelector(".airta-title").textContent = state.title;
    panel.querySelector(".airta-message").textContent = state.message;
    panel.querySelector(".airta-primary").textContent = state.action;
    const secondary = panel.querySelector(".airta-secondary");
    if (state.secondaryAction) {
      secondary.style.display = "";
      secondary.textContent = state.secondaryAction;
    } else {
      secondary.style.display = "none";
      secondary.textContent = "";
    }
    panel.querySelector(".airta-hint").textContent = state.mode === "pick"
      ? "Click the highlighted target element on the page."
      : state.mode === "confirm"
      ? "Confirm saves this step to config.yaml. Try again lets you redo it."
      : "Keep this panel open while you navigate.";
  }

  let hovered = null;
  document.addEventListener("mouseover", (event) => {
    if (state.mode !== "pick") return;
    const panel = document.getElementById("__airta_manual_panel");
    if (panel && panel.contains(event.target)) return;
    if (hovered) hovered.classList.remove("__airta_manual_hover");
    hovered = usefulTargetFor(event.target);
    hovered.classList.add("__airta_manual_hover");
  }, true);

  document.addEventListener("click", (event) => {
    const panel = document.getElementById("__airta_manual_panel");
    if (panel && panel.contains(event.target)) return;
    if (state.mode !== "pick") return;
    if (!state.allowAction) {
      event.preventDefault();
      event.stopPropagation();
    }
    if (hovered) hovered.classList.remove("__airta_manual_hover");
    const target = usefulTargetFor(event.target);
    const selector = selectorFor(target);
    hovered = null;
    state.mode = "idle";
    state.message = `Captured selector:\n${selector}`;
    state.action = "Continue";
    render();
    if (window.airtaManualEvent) {
      window.airtaManualEvent({
        type: "selector",
        selector,
        tag: target.tagName.toLowerCase(),
        inputType: target.getAttribute("type") || "",
      });
    }
  }, true);

  window.__airtaManualSetStep = (next) => {
    Object.assign(state, next || {});
    render();
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", render, { once: true });
  } else {
    render();
  }

  window.__airtaScanUploads = () => {
    const fileInputs = [];
    document.querySelectorAll('input[type="file"]').forEach((el) => {
      if (!el || el.disabled) return;
      const style = window.getComputedStyle(el);
      const visible = style.display !== "none" && style.visibility !== "hidden" && !el.hidden;
      const sel = selectorFor(el);
      if (!sel) return;
      let matchCount = 0;
      try { matchCount = document.querySelectorAll(sel).length; } catch (_) {}
      fileInputs.push({
        selector: sel,
        visible,
        accept: el.getAttribute("accept") || "",
        unique: matchCount === 1,
      });
    });
    return {
      supports_upload: fileInputs.length > 0,
      file_inputs: fileInputs,
    };
  };
})();
"""


async def _install_manual_discovery_panel(page) -> None:
    await page.add_init_script(_MANUAL_DISCOVERY_SCRIPT)
    try:
        await page.evaluate(_MANUAL_DISCOVERY_SCRIPT)
    except Exception:
        pass


async def _manual_panel_event(
    page,
    message: str,
    *,
    mode: str,
    action: str = "Continue",
    secondary_action: str = "",
    allow_action: bool = False,
) -> dict:
    queue = getattr(page, "_airta_manual_queue", None)
    if queue is None:
        queue = asyncio.Queue()
        setattr(page, "_airta_manual_queue", queue)

        async def _handler(_source, payload):
            await queue.put(payload or {})

        try:
            await page.expose_binding("airtaManualEvent", _handler)
        except Exception:
            pass

    await page.evaluate(
        """({ message, mode, action, secondaryAction, allowAction }) => {
          window.__airtaManualSetStep({ message, mode, action, secondaryAction, allowAction });
        }""",
        {
            "message": message,
            "mode": mode,
            "action": action,
            "secondaryAction": secondary_action,
            "allowAction": allow_action,
        },
    )
    return await queue.get()


async def _manual_continue(page, message: str, action: str = "Continue") -> None:
    await _manual_panel_event(page, message, mode="idle", action=action)


async def _manual_confirm_step(page, title: str, summary: str) -> bool:
    """Show captured step details. Returns True when user confirms, False to retry."""
    event = await _manual_panel_event(
        page,
        f"{title}\n\n{summary}",
        mode="confirm",
        action="Confirm",
        secondary_action="Try again",
    )
    return event.get("type") == "confirm"


async def _manual_confirm_and_save(
    page,
    site: str,
    component: str,
    submission: dict,
    *,
    title: str,
    summary: str,
) -> bool:
    """Confirm step details, then write submission to config.yaml."""
    if not await _manual_confirm_step(page, title, summary):
        return False
    _save_partial(site, component, submission)
    return True


async def _manual_pick_or_skip(page, message: str) -> dict | None:
    """Wait for element pick or Skip (continue). Returns None when skipped."""
    event = await _manual_panel_event(page, message, mode="pick", action="Skip")
    if event.get("type") == "continue" or not (event.get("selector") or "").strip():
        return None
    return event


async def _manual_pick_selector(page, message: str, *, allow_action: bool = False) -> dict:
    while True:
        event = await _manual_panel_event(
            page,
            message,
            mode="pick",
            action="Waiting for click...",
            allow_action=allow_action,
        )
        selector = (event.get("selector") or "").strip()
        if selector:
            return event


async def _get_page_html(page) -> str:
    return await page.evaluate(
        """() => {
          const body = document.body;
          if (!body) return '';
          const clone = body.cloneNode(true);
          clone.querySelectorAll('script').forEach(el => el.remove());
          clone.querySelectorAll('[hidden]').forEach(el => el.remove());
          return clone.innerHTML;
        }"""
    )


def _save_html(site: str, component: str, html: str, suffix: str = "") -> Path:
    ensure_component_dir(site, component)
    html_dir = get_component_path(site, component) / "html"
    html_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = html_dir / f"{ts}{suffix}.html"
    path.write_text(html, encoding="utf-8")
    return path


def _save_screenshot(site: str, component: str, page_bytes: bytes, suffix: str = "") -> Path:
    ensure_component_dir(site, component)
    html_dir = get_component_path(site, component) / "html"
    html_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = html_dir / f"{ts}{suffix}.png"
    path.write_bytes(page_bytes)
    return path


def _clean_html_for_llm(html: str) -> str:
    """Strip noise while preserving form-critical attributes for CSS selector derivation."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return html

    soup = BeautifulSoup(html, "html.parser")

    for tag in soup.find_all(["script", "style", "svg", "head", "noscript",
                               "link", "meta", "iframe", "template", "img"]):
        tag.decompose()

    for tag in soup.find_all(True):
        # Some malformed nodes can carry attrs=None; treat as empty attrs.
        if getattr(tag, "attrs", None) is None:
            tag.attrs = {}
        style = tag.get("style", "")
        if "display:none" in style.replace(" ", "") or "visibility:hidden" in style.replace(" ", ""):
            tag.decompose()
            continue
        if tag.has_attr("hidden"):
            tag.decompose()

    _KEEP_ATTRS = {
        "id", "class", "name", "type", "role", "contenteditable",
        "placeholder", "aria-label", "for", "href", "action", "method",
    }
    for tag in soup.find_all(True):
        if getattr(tag, "attrs", None) is None:
            tag.attrs = {}
        keep = {a: tag.attrs[a] for a in list(tag.attrs)
                if a in _KEEP_ATTRS or a.startswith("data-") or a.startswith("aria-")}
        tag.attrs = keep

    return str(soup)


# ---------------------------------------------------------------------------
# LLM helpers
# ---------------------------------------------------------------------------

_DISCOVERY_SELECTOR_ATTEMPTS = 3

def _gemini_client():
    try:
        from dotenv import load_dotenv
        _root = Path(__file__).resolve().parents[2]
        _browser_root = Path(__file__).resolve().parents[1]
        load_dotenv(_root / ".config")
        load_dotenv(_browser_root / ".env")
        load_dotenv(_root / ".env")
        load_dotenv()
    except ImportError:
        pass
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("  GEMINI_API_KEY not set.")
        return None
    try:
        from google import genai
        return genai.Client(api_key=api_key)
    except ImportError:
        print("  Install google-genai: pip install google-genai")
        return None


def _gemini_model() -> str:
    return os.getenv("GEMINI_MODEL", "").strip()


def _parse_json_response(text: str) -> dict:
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
    if m:
        return json.loads(m.group(1))
    m = re.search(r"\{[\s\S]*\}", text)
    return json.loads(m.group()) if m else json.loads(text)


def _llm_extract_inputs(html: str, page_url: str) -> list[dict]:
    """Ask LLM for input field selectors only (no submit button)."""
    client = _gemini_client()
    if not client:
        return []
    model = _gemini_model()
    if not model:
        print("  GEMINI_MODEL not set.")
        return []
    cleaned = _clean_html_for_llm(html)
    print(f"  HTML cleaned: {len(html):,} → {len(cleaned):,} chars")
    prompt = f"""Analyze this HTML from an AI chat or form page.

Page URL: {page_url}

HTML:
{cleaned[:120000]}

Return ONLY valid JSON identifying the text input field(s) where a user types a prompt:
{{
  "inputs": [
    {{"selector": "css-selector", "type": "text|textarea|contenteditable|select|file", "value": "optional-for-select", "path_from": "payload when type is file"}}
  ]
}}

Rules:
- List fields in ORDER (file upload before text prompt when both exist).
- Include text inputs, textareas, contenteditable divs, select dropdowns, and file inputs (type: file with path_from: payload).
- EXCLUDE hidden inputs and submit/send buttons.
- Prefer stable selectors: #id, [data-testid="x"], [name="x"], tag.class
- Never use bare "div" or "span" — qualify with attribute or class.
- For contenteditable: use div[contenteditable="true"] or the most specific stable selector.
- NEVER produce a selector with more than 4 levels of nesting.
- NEVER use nth-of-type more than once in a selector.
- If the page has several distinct forms or chat composers, anchor the field with a nearby landmark (section[aria-labelledby], heading id, form[action], main) so the selector does not match a different widget.
"""
    try:
        resp = client.models.generate_content(model=model, contents=prompt)
        if not resp.text:
            return []
        data = _parse_json_response(resp.text)
        inputs = data.get("inputs", [])
        out = []
        for i in inputs:
            if not isinstance(i, dict):
                continue
            row = dict(i)
            if row.get("type") == "file":
                row.setdefault("path_from", "payload")
            out.append(row)
        return out
    except Exception as e:
        print(f"  LLM error (inputs): {e}")
        return []


def _llm_extract_submit(html: str, page_url: str, prompt_input_selectors: list[str] | None = None) -> str:
    """Ask LLM for the submit/send button selector only."""
    client = _gemini_client()
    if not client:
        return ""
    model = _gemini_model()
    if not model:
        print("  GEMINI_MODEL not set.")
        return ""
    cleaned = _clean_html_for_llm(html)
    region_hint = ""
    if prompt_input_selectors:
        joined = ", ".join(s.strip() for s in prompt_input_selectors if s and str(s).strip())
        if joined:
            region_hint = f"""
Region anchoring — these prompt/input field selector(s) are already verified:
  {joined}
The submit button MUST lie in the SAME closest landmark/card/section subtree as those fields
(wraps both the field and the button in the DOM). If the page repeats the same button pattern
in multiple regions, pick the control that belongs to this subtree, not a similar one elsewhere.
"""

    prompt = f"""Analyze this HTML from an AI chat or form page.

Page URL: {page_url}
{region_hint}
HTML:
{cleaned[:120000]}

Return ONLY valid JSON identifying the button that submits/sends the user's prompt:
{{
  "submit_selector": "css-selector"
}}

Rules:
- Target the send/submit control that pairs with THAT prompt/input, not an unrelated CTA on the page.
- Prefer scope from HTML landmarks when needed: section[aria-labelledby], heading ids, form boundaries, [role="region"], main, or a card/article that uniquely wraps the composer.
- You MAY use Playwright CSS: spaces for descendants, and :has-text("visible label") on buttons/links when the label is distinctive (still scope when similar labels could exist elsewhere).
  Example pattern: section[aria-labelledby="x"] .action-row button:has-text("Send")
- Prefer attributes (data-testid, type=submit, aria-label) when they are unique within that region.
- Avoid long chains of generic divs with nth-of-type — prefer landmark + short path to the control.
- Keep selectors short: at most a few descendant steps from the chosen landmark (or from document root if globally unique).
"""
    try:
        resp = client.models.generate_content(model=model, contents=prompt)
        if not resp.text:
            return ""
        data = _parse_json_response(resp.text)
        return data.get("submit_selector", "").strip()
    except Exception as e:
        print(f"  LLM error (submit): {e}")
        return ""


def _llm_extract_response_selector(html: str, page_url: str, prompt_input_selectors: list[str] | None = None) -> str:
    """Ask LLM for the AI response container selector from post-submission HTML."""
    client = _gemini_client()
    if not client:
        return ""
    model = _gemini_model()
    if not model:
        print("  GEMINI_MODEL not set.")
        return ""
    cleaned = _clean_html_for_llm(html)
    print(f"  HTML cleaned: {len(html):,} → {len(cleaned):,} chars")

    region_hint = ""
    if prompt_input_selectors:
        joined = ", ".join(s.strip() for s in prompt_input_selectors if s and str(s).strip())
        if joined:
            region_hint = f"""
Region anchoring — verified prompt/input selector(s):
  {joined}
The response container MUST stay inside the SAME landmark/section/card subtree as those fields.
If the page has multiple similar chat UIs, do not match messages from another region.
"""

    prompt = f"""Analyze this HTML captured AFTER a test prompt was submitted and an AI response was rendered.

Page URL: {page_url}
{region_hint}

HTML:
{cleaned[:120000]}

Return ONLY valid JSON identifying the element that contains the AI's text response:
{{
  "response_selector": "css-selector"
}}

Rules:
- Prefer the model/assistant message container within the SAME region as the prompt (use heading ids, aria-labelledby, form or main boundaries visible in the HTML).
- The selector SHOULD match each assistant turn in THAT conversation when possible (automation uses the last visible match) — still avoid crossing into another parallel widget on the same page.
- Prefer stable signals: [data-message-author-role], data-testid, roles, or short class paths that are not build hashes.
- Avoid deep nth-of-type ladders; use a landmark + narrow subtree.
- You MAY use Playwright :has-text only on static chrome, not on free-form model output.
- Never return an empty string — pick the best candidate if uncertain.
"""
    try:
        resp = client.models.generate_content(model=model, contents=prompt)
        if not resp.text:
            return ""
        data = _parse_json_response(resp.text)
        return data.get("response_selector", "").strip()
    except Exception as e:
        print(f"  LLM error (response selector): {e}")
        return ""


def _retry_extract_inputs(html: str, page_url: str) -> list[dict]:
    for attempt in range(1, _DISCOVERY_SELECTOR_ATTEMPTS + 1):
        inputs = _llm_extract_inputs(html, page_url)
        if inputs:
            return inputs
        if attempt < _DISCOVERY_SELECTOR_ATTEMPTS:
            print(f"  [~] Input selector not found; retrying ({attempt + 1}/{_DISCOVERY_SELECTOR_ATTEMPTS})...")
    return []


def _retry_extract_submit(
    html: str,
    page_url: str,
    prompt_input_selectors: list[str] | None = None,
) -> str:
    for attempt in range(1, _DISCOVERY_SELECTOR_ATTEMPTS + 1):
        selector = _llm_extract_submit(html, page_url, prompt_input_selectors)
        if selector:
            return selector
        if attempt < _DISCOVERY_SELECTOR_ATTEMPTS:
            print(f"  [~] Submit selector not found; retrying ({attempt + 1}/{_DISCOVERY_SELECTOR_ATTEMPTS})...")
    return ""


def _retry_extract_response_selector(
    html: str,
    page_url: str,
    prompt_input_selectors: list[str] | None = None,
) -> str:
    for attempt in range(1, _DISCOVERY_SELECTOR_ATTEMPTS + 1):
        selector = _llm_extract_response_selector(html, page_url, prompt_input_selectors)
        if selector:
            return selector
        if attempt < _DISCOVERY_SELECTOR_ATTEMPTS:
            print(f"  [~] Response selector not found; retrying ({attempt + 1}/{_DISCOVERY_SELECTOR_ATTEMPTS})...")
    return ""


def _manual_input_type(event: dict) -> str:
    tag = (event.get("tag") or "").lower()
    input_type = (event.get("inputType") or "").lower()
    if tag == "textarea":
        return "textarea"
    if tag == "select":
        return "select"
    if tag == "input":
        return input_type or "text"
    return "contenteditable" if tag in ("div", "span", "p") else "text"


def _file_input_config(selector: str) -> dict:
    return {
        "selector": selector,
        "type": "file",
        "path_from": "payload",
    }


async def _detect_upload_capabilities(page) -> dict:
    """Scan the live page for file upload controls."""
    await _install_manual_discovery_panel(page)
    try:
        result = await page.evaluate(
            """() => {
              if (typeof window.__airtaScanUploads === "function") {
                return window.__airtaScanUploads();
              }
              return { supports_upload: false, file_inputs: [] };
            }"""
        )
        if isinstance(result, dict):
            return result
    except Exception as exc:
        print(f"  [!] Upload scan failed: {exc}")
    return {"supports_upload": False, "file_inputs": []}


def _selector_for_html_tag(tag) -> str:
    if tag.get("id"):
        return f"#{tag['id']}"
    parts = [tag.name or "input"]
    for attr in ("data-testid", "name", "aria-label", "type"):
        value = tag.get(attr)
        if value:
            parts[0] = tag.name or "input"
            return f'{tag.name}[{attr}="{value}"]' if tag.name else f'[{attr}="{value}"]'
    return ""


def _detect_uploads_from_html(html: str) -> list[dict]:
    """Detect file inputs from captured HTML (automated troubleshoot flow)."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return []
    soup = BeautifulSoup(html, "html.parser")
    out: list[dict] = []
    seen: set[str] = set()
    for tag in soup.find_all("input"):
        if (tag.get("type") or "").lower() != "file":
            continue
        selector = _selector_for_html_tag(tag)
        if not selector or selector in seen:
            continue
        seen.add(selector)
        out.append(_file_input_config(selector))
    return out


def _pick_best_file_input(detection: dict) -> str | None:
    candidates = detection.get("file_inputs") or []
    if not candidates:
        return None
    visible_unique = [c for c in candidates if c.get("visible") and c.get("unique")]
    if visible_unique:
        return str(visible_unique[0].get("selector") or "").strip() or None
    visible = [c for c in candidates if c.get("visible")]
    if visible:
        return str(visible[0].get("selector") or "").strip() or None
    return str(candidates[0].get("selector") or "").strip() or None


def _merge_upload_inputs(detected_files: list[dict], llm_inputs: list[dict]) -> list[dict]:
    """Place verified file inputs before text inputs; avoid duplicate selectors."""
    file_rows = list(detected_files)
    seen = {row.get("selector") for row in file_rows if row.get("selector")}
    for inp in llm_inputs:
        if inp.get("type") == "file" and inp.get("selector") not in seen:
            row = dict(inp)
            row.setdefault("path_from", "payload")
            file_rows.append(row)
            seen.add(row.get("selector"))
    text_rows = [dict(inp) for inp in llm_inputs if inp.get("type") != "file"]
    return file_rows + text_rows


async def _verify_selector_on_page(page, selector: str) -> bool:
    if not selector:
        return False
    try:
        loc = page.locator(selector).first
        if await loc.count() == 0:
            return False
        return await loc.is_visible()
    except Exception:
        return False


async def _configure_multimodal_upload(
    page,
    *,
    step_label: str,
    auto_selector: str | None,
) -> dict | None:
    """
    Manual discovery step: confirm or override auto-detected file input selector.
    Returns file input config dict or None when no upload should be configured.
    """
    if auto_selector:
        verified = await _verify_selector_on_page(page, auto_selector)
        hint = "verified on page" if verified else "could not verify visibility"
        print(f"    suggested file selector ({hint}): {auto_selector}")
        file_event = await _manual_pick_or_skip(
            page,
            f"{step_label}. File upload detected.\n\n"
            f"Auto selector:\n{auto_selector}\n\n"
            "Click the file upload control to confirm or override,\n"
            "or press Skip to keep the auto selector.",
        )
        if file_event:
            selector = (file_event.get("selector") or "").strip()
            if selector:
                return _file_input_config(selector)
        if verified:
            return _file_input_config(auto_selector)
        print("    auto file selector not verified — skipping file upload config")
        return None

    file_event = await _manual_pick_or_skip(
        page,
        f"{step_label}. File upload detected but no unique auto selector was found.\n\n"
        "Click the file upload control on the page,\n"
        "or press Skip if this target does not support uploads.",
    )
    if not file_event:
        return None
    selector = (file_event.get("selector") or "").strip()
    return _file_input_config(selector) if selector else None


# ---------------------------------------------------------------------------
# Headless verification helpers
# ---------------------------------------------------------------------------

_TEXT_TYPES = {"text", "textarea", "contenteditable", "password", "email", "search"}


async def _headless_verify_input(
    site: str,
    component: str,
    page_url: str,
    inp: dict,
    storage_path: str,
) -> tuple[bool, Path | None]:
    """
    Navigate headlessly, fill the input with 'Hello', read the value back.
    Returns (ok, screenshot_path).
    ok=True  if the filled value is readable in the element after fill.
    ok=False if element not found, not visible, or fill did not stick.
    """
    from browser_bot.submit.common import _first_visible_locator

    result: dict = {"ok": False, "screenshot": None, "error": ""}

    async def _run(page):
        await page.goto(page_url, wait_until="domcontentloaded", timeout=60000)
        await asyncio.sleep(2)

        selector = inp["selector"]
        inp_type = inp.get("type", "text")

        try:
            loc = await _first_visible_locator(page, selector)
            visible = await loc.is_visible()
            if not visible:
                result["error"] = f"element not visible: {selector}"
                shot = await page.screenshot()
                result["screenshot"] = _save_screenshot(site, component, shot, "_input_verify_fail")
                return

            if inp_type == "file":
                import tempfile
                from payloads.generators import generate_payload

                probe_dir = Path(tempfile.mkdtemp(prefix="airta_probe_"))
                artifact = generate_payload(
                    "text",
                    {"content": "AIRTA probe upload", "filename": "probe.txt"},
                    out_dir=probe_dir,
                )
                await loc.set_input_files(str(artifact))
                result["ok"] = True
            else:
                await loc.fill("Hello")
                await asyncio.sleep(0.3)

                if inp_type == "contenteditable":
                    value = await loc.inner_text()
                else:
                    try:
                        value = await loc.input_value()
                    except Exception:
                        value = await loc.inner_text()

                result["ok"] = "Hello" in (value or "")
                if not result["ok"]:
                    result["error"] = f"fill did not stick (got: {repr(value[:80])})"
        except Exception as exc:
            result["error"] = str(exc)

        suffix = "_input_verify_ok" if result["ok"] else "_input_verify_fail"
        shot = await page.screenshot()
        result["screenshot"] = _save_screenshot(site, component, shot, suffix)

    profile_path = get_login_profile_path(site)
    if _should_use_login_profile(site):
        async with async_playwright() as p:
            browser, context = await launch_persistent_context(
                p, str(profile_path), headless=True, site=site
            )
            page = await context.new_page()
            try:
                await _run(page)
            finally:
                await context.close()
                if browser:
                    await browser.close()
    else:
        async with async_playwright() as p:
            from main import run_with_page_from_fetchers
            await run_with_page_from_fetchers(
                p,
                site,
                _run,
                storage_path=storage_path,
                interactive=False,
                headless=True,
                human_only=True,
            )

    return result["ok"], result["screenshot"]


async def _headless_capture_with_input_filled(
    site: str,
    page_url: str,
    inputs: list[dict],
    storage_path: str,
) -> str | None:
    """
    Navigate headlessly, fill all inputs with 'Hello' (do NOT submit),
    then capture and return the page HTML.
    Used so the LLM can see the submit button that only appears after text is entered.
    Returns HTML string, or None on failure.
    """
    from browser_bot.submit.common import _first_visible_locator

    result: dict = {"html": None}

    async def _run(page):
        await page.goto(page_url, wait_until="domcontentloaded", timeout=60000)
        await asyncio.sleep(2)
        for inp in inputs:
            try:
                loc = await _first_visible_locator(page, inp["selector"])
                if inp.get("type") == "file":
                    import tempfile
                    from payloads.generators import generate_payload

                    probe_dir = Path(tempfile.mkdtemp(prefix="airta_probe_"))
                    artifact = generate_payload(
                        "text",
                        {"content": "AIRTA probe upload", "filename": "probe.txt"},
                        out_dir=probe_dir,
                    )
                    await loc.set_input_files(str(artifact))
                else:
                    await loc.fill("Hello")
                await asyncio.sleep(0.2)
            except Exception:
                pass
        await asyncio.sleep(0.5)  # let UI react (e.g. show send button)
        result["html"] = await _get_page_html(page)

    profile_path = get_login_profile_path(site)
    if _should_use_login_profile(site):
        async with async_playwright() as p:
            browser, context = await launch_persistent_context(
                p, str(profile_path), headless=True, site=site
            )
            page = await context.new_page()
            try:
                await _run(page)
            finally:
                await context.close()
                if browser:
                    await browser.close()
    else:
        async with async_playwright() as p:
            from main import run_with_page_from_fetchers
            await run_with_page_from_fetchers(
                p,
                site,
                _run,
                storage_path=storage_path,
                interactive=False,
                headless=True,
                human_only=True,
            )

    return result["html"]


async def _headless_verify_submit(
    site: str,
    component: str,
    page_url: str,
    inputs: list[dict],
    submit_selector: str,
    storage_path: str,
    response_wait_ms: int = 15000,
) -> tuple[bool, str | None, Path | None]:
    """
    Navigate headlessly, fill inputs and click submit. Detect success via:
      - any POST/PUT/PATCH request captured after click, OR
      - page URL change after click.
    Captures full page HTML after the wait.
    Returns (ok, response_html, screenshot_path).
    """
    from browser_bot.submit.common import _do_one_submit_step

    result: dict = {"ok": False, "html": None, "screenshot": None, "error": ""}

    async def _run(page):
        pre_url = page.url
        captured_posts: list = []

        def _on_response(response):
            if response.request.method in ("POST", "PUT", "PATCH"):
                captured_posts.append(response.url)

        await page.goto(page_url, wait_until="domcontentloaded", timeout=60000)
        await asyncio.sleep(2)
        page.on("response", _on_response)

        try:
            await _do_one_submit_step(
                page,
                inputs,
                submit_selector,
                "Hello",
                response_selector="",
                submit_via="click",
                response_wait_ms=response_wait_ms,
            )
        except Exception as exc:
            result["error"] = str(exc)

        post_url = page.url
        url_changed = post_url != pre_url
        had_post = bool(captured_posts)

        result["ok"] = had_post or url_changed
        if not result["ok"]:
            result["error"] = "no POST request and URL did not change"

        result["html"] = await _get_page_html(page)

        suffix = "_submit_verify_ok" if result["ok"] else "_submit_verify_fail"
        shot = await page.screenshot()
        result["screenshot"] = _save_screenshot(site, component, shot, suffix)

    profile_path = get_login_profile_path(site)
    if _should_use_login_profile(site):
        async with async_playwright() as p:
            browser, context = await launch_persistent_context(
                p, str(profile_path), headless=True, site=site
            )
            page = await context.new_page()
            try:
                await _run(page)
            finally:
                await context.close()
                if browser:
                    await browser.close()
    else:
        async with async_playwright() as p:
            from main import run_with_page_from_fetchers
            await run_with_page_from_fetchers(
                p,
                site,
                _run,
                storage_path=storage_path,
                interactive=False,
                headless=True,
                human_only=True,
            )

    return result["ok"], result["html"], result["screenshot"]


# ---------------------------------------------------------------------------
# API discovery — probe endpoint and save submission config
# ---------------------------------------------------------------------------

def run_api_discovery(
    site: str,
    component: str,
    *,
    api_url: str,
    api_method: str = "POST",
    api_headers: dict | None = None,
    api_body: dict | None = None,
    api_response_path: str = "response",
    api_model: str = "",
    probe_prompt: str = "Hello from AIRTA",
    transport: str = "api",
    upload_url: str = "",
    upload_file_field: str = "file",
    upload_response_path: str = "document_id",
    multipart_prompt_field: str = "prompt",
    multipart_file_field: str = "file",
) -> bool:
    """Configure component for direct API submission by probing the endpoint."""
    from browser_bot.submit.api_helpers import do_api_document_request, do_api_multipart_request, do_api_request, resolve_api_url

    api_url = (api_url or "").strip()
    api_model = (api_model or "").strip()
    transport = (transport or "api").strip().lower()
    if transport == "api" and not api_url:
        print("  [!] api_url is required for API discovery")
        return False
    if transport == "api" and "{{model}}" in api_url and not api_model:
        print("  [!] api_model is required when api_url contains {{model}}")
        return False
    if transport == "api_document" and (not upload_url or not api_url):
        print("  [!] upload_url and api_url are required for api_document discovery")
        return False
    if transport == "api_multipart" and not api_url:
        print("  [!] api_url is required for api_multipart discovery")
        return False

    _ensure_site_config_for_discovery(site, component)

    api_body = api_body if isinstance(api_body, dict) else {"prompt": "{{prompt}}"}
    api_headers = dict(api_headers or {})
    api_response_path = (api_response_path or "response").strip()

    print("\n" + "─" * 50)
    print("  API endpoint discovery")
    print(f"  Transport: {transport}")
    print("─" * 50)

    if transport == "api_document":
        import tempfile
        from payloads.generators import generate_payload

        probe_dir = Path(tempfile.mkdtemp(prefix="airta_api_probe_"))
        artifact = generate_payload(
            "text",
            {"content": "AIRTA API upload probe", "filename": "probe.txt"},
            out_dir=probe_dir,
        )
        submission = {
            "transport": "api_document",
            "upload_url": upload_url.strip(),
            "upload_file_field": upload_file_field or "file",
            "upload_response_path": upload_response_path or "document_id",
            "api_url": api_url,
            "api_method": (api_method or "POST").upper(),
            "api_headers": api_headers,
            "api_body": api_body if "document_id" in str(api_body) else {
                **api_body,
                "prompt": "{{prompt}}",
                "document_id": "{{document_id}}",
                "context_from": "upload",
            },
            "api_response_path": api_response_path,
        }
        test_case = {
            "id": "api-discover-probe",
            "prompt": probe_prompt,
            "payload": {"path": str(artifact)},
        }
        status, response_text, err = do_api_document_request(
            submission, probe_prompt, site=site, test_case=test_case
        )
    elif transport == "api_multipart":
        submission = {
            "transport": "api_multipart",
            "api_url": api_url,
            "multipart_prompt_field": multipart_prompt_field or "prompt",
            "multipart_file_field": multipart_file_field or "file",
            "api_response_path": api_response_path,
            "api_headers": api_headers,
        }
        import tempfile
        from payloads.generators import generate_payload

        probe_dir = Path(tempfile.mkdtemp(prefix="airta_api_probe_"))
        artifact = generate_payload(
            "text",
            {"content": "AIRTA multipart probe", "filename": "probe.txt"},
            out_dir=probe_dir,
        )
        test_case = {
            "id": "api-discover-probe",
            "prompt": probe_prompt,
            "payload": {"path": str(artifact)},
        }
        status, response_text, err = do_api_multipart_request(
            submission, probe_prompt, site=site, test_case=test_case
        )
    else:
        submission = {
            "transport": "api",
            "api_url": api_url,
            "api_method": (api_method or "POST").upper(),
            "api_headers": api_headers,
            "api_body": api_body,
            "api_response_path": api_response_path,
        }
        if api_model:
            submission["api_model"] = api_model
        probe_url, probe_err = resolve_api_url(submission, site=site)
        if probe_err or not probe_url:
            print(f"  [!] {probe_err or 'Could not resolve api_url'}")
            return False
        print(f"  Probing {submission['api_method']} {probe_url}")
        status, response_text, err = do_api_request(submission, probe_prompt, site=site)
        if status == 403 and "generativelanguage.googleapis.com" in api_url:
            print("  [!] Gemini returned 403 — use x-goog-api-key header or ?key= query param in Connect Target Step 1")

    if err and not response_text:
        print(f"  [!] Probe failed ({status}): {err}")
        return False
    if not response_text:
        print("  [!] Probe returned empty response — check api_response_path")
        return False

    comp_raw = load_component_config_raw(site, component)
    comp_raw.setdefault("urls", [])
    comp_raw.setdefault("posts", [])
    comp_raw["submission"] = submission
    _save_config_with_comments(site, component, comp_raw)

    print(f"  [+] API connection OK (HTTP {status})")
    preview = (response_text[:200] + "…") if len(response_text) > 200 else response_text
    print(f"  [+] Response preview: {preview}")
    print(f"  [+] Saved -> sites/{site}/{component}/config.yaml")
    print("═" * 50)
    return True


# ---------------------------------------------------------------------------
# run_training — 6-step discovery pipeline
# ---------------------------------------------------------------------------

def run_manual_training(site: str, component: str) -> bool:
    """Manual browser-guided selector discovery using an in-page AIRTA panel."""
    profile_path = get_login_profile_path(site)
    has_profile = _should_use_login_profile(site)
    storage_path = get_storage_state_path(site)
    if not has_profile and not storage_path:
        print("  No auth for this site. Run 'Add login' first.")
        return False
    _print_profile_disabled_notice(site)
    _ensure_site_config_for_discovery(site, component)

    config = load_component_config(site, component)
    start_url = config.get("login_url") or f"https://{site}"

    submission: dict = {
        "start_url": "",
        "inputs": [],
        "submit_selector": "",
        "response_selector": "",
        "submit_via": "click",
        "response_wait_ms": 8000,
    }

    print("\n" + "─" * 50)
    print("  Manual component discovery")
    print("  A browser will open with an AIRTA guide panel.")
    print("─" * 50)

    async def _run_manual():
        async with async_playwright() as p:
            from main import run_with_page_from_fetchers

            async def _capture(page):
                await _install_manual_discovery_panel(page)
                await page.goto(start_url, wait_until="domcontentloaded", timeout=60000)

                print("  [1/7] Browser opened. Waiting for target page confirmation...")
                while True:
                    await _manual_continue(
                        page,
                        "1. Navigate to the LLM/chat page you want AIRTA to test.\n\n"
                        "When the prompt input is visible, click Continue.",
                        action="Continue",
                    )
                    page_url = page.url
                    if await _manual_confirm_and_save(
                        page,
                        site,
                        component,
                        {**submission, "start_url": page_url},
                        title="Step 1/7 — Confirm start URL",
                        summary=f"Page URL:\n{page_url}",
                    ):
                        submission["start_url"] = page_url
                        print(f"    start_url: {page_url}")
                        break
                    print("    retrying step 1...")

                inputs: list[dict] = []

                print("  [2/7] Scanning page for file upload support...")
                upload_info = await _detect_upload_capabilities(page)
                supports_upload = bool(upload_info.get("supports_upload"))
                auto_file_selector = _pick_best_file_input(upload_info)
                if supports_upload:
                    count = len(upload_info.get("file_inputs") or [])
                    print(f"    upload support: yes ({count} file input(s) found)")
                    for row in upload_info.get("file_inputs") or []:
                        vis = "visible" if row.get("visible") else "hidden"
                        uniq = "unique" if row.get("unique") else "ambiguous"
                        print(f"      - {row.get('selector')} ({vis}, {uniq})")
                else:
                    print("    upload support: no")
                    while True:
                        await _manual_continue(
                            page,
                            "2. No file upload control detected on this page.\n\n"
                            "Navigate elsewhere if uploads appear on another screen,\n"
                            "then click Continue — or confirm to skip file upload.",
                            action="Continue",
                        )
                        upload_info = await _detect_upload_capabilities(page)
                        supports_upload = bool(upload_info.get("supports_upload"))
                        auto_file_selector = _pick_best_file_input(upload_info)
                        if supports_upload:
                            count = len(upload_info.get("file_inputs") or [])
                            print(f"    upload support: yes ({count} file input(s) found after rescan)")
                            break
                        if await _manual_confirm_step(
                            page,
                            "Step 2/7 — Confirm no file upload",
                            "No file upload control will be configured.\n"
                            "AIRTA will configure the text prompt input next.",
                        ):
                            break
                        print("    retrying step 2...")

                if supports_upload:
                    print("  [3/7] Configuring multimodal file upload...")
                    while True:
                        file_cfg = await _configure_multimodal_upload(
                            page,
                            step_label="3",
                            auto_selector=auto_file_selector,
                        )
                        if not file_cfg:
                            if await _manual_confirm_step(
                                page,
                                "Step 3/7 — Confirm skip file upload",
                                "No file upload selector will be saved.\n"
                                "Continue with text prompt configuration only.",
                            ):
                                print("    file input: (not configured)")
                                break
                            print("    retrying step 3...")
                            continue

                        summary = (
                            f"File input selector:\n{file_cfg['selector']}\n\n"
                            "path_from: payload (multimodal tests)"
                        )
                        draft = {
                            **submission,
                            "inputs": inputs + [file_cfg],
                            "response_wait_ms": max(int(submission.get("response_wait_ms") or 8000), 60000),
                        }
                        if await _manual_confirm_and_save(
                            page,
                            site,
                            component,
                            draft,
                            title="Step 3/7 — Confirm file upload input",
                            summary=summary,
                        ):
                            inputs.append(file_cfg)
                            submission["inputs"] = inputs
                            submission["response_wait_ms"] = draft["response_wait_ms"]
                            print(f"    file input: {file_cfg['selector']} (path_from=payload)")
                            break
                        print("    retrying step 3...")

                print("  [4/7] Waiting for prompt input selection...")
                while True:
                    input_event = await _manual_pick_selector(
                        page,
                        "4. Write a short test prompt in the prompt/input field.\n\n"
                        "Then click that same input field once so AIRTA can save its selector.",
                    )
                    input_selector = input_event["selector"]
                    input_config = {
                        "selector": input_selector,
                        "type": _manual_input_type(input_event),
                    }
                    summary = (
                        f"Prompt input selector:\n{input_selector}\n\n"
                        f"Input type: {input_config['type']}"
                    )
                    draft = {**submission, "inputs": inputs + [input_config]}
                    if await _manual_confirm_and_save(
                        page,
                        site,
                        component,
                        draft,
                        title="Step 4/7 — Confirm prompt input",
                        summary=summary,
                    ):
                        inputs.append(input_config)
                        submission["inputs"] = inputs
                        print(f"    input: {input_selector} (type={input_config['type']})")
                        break
                    print("    retrying step 4...")

                print("  [5/7] Waiting for submit button selection...")
                while True:
                    submit_event = await _manual_pick_selector(
                        page,
                        "5. Click the real Send/Submit button.\n\n"
                        "AIRTA will save the button selector and allow the click through, "
                        "so the prompt is submitted.",
                        allow_action=True,
                    )
                    submit_selector = submit_event["selector"]
                    summary = f"Submit button selector:\n{submit_selector}"
                    draft = {**submission, "submit_selector": submit_selector}
                    if await _manual_confirm_and_save(
                        page,
                        site,
                        component,
                        draft,
                        title="Step 5/7 — Confirm submit button",
                        summary=summary,
                    ):
                        submission["submit_selector"] = submit_selector
                        print(f"    submit_selector: {submit_selector}")
                        break
                    print("    retrying step 5...")

                print("  [6/7] Waiting for response text selection...")
                while True:
                    response_event = await _manual_pick_selector(
                        page,
                        "6. Wait for the model response to appear.\n\n"
                        "Then click directly on the response text/container "
                        "so AIRTA can save its selector.",
                    )
                    response_selector = response_event["selector"]
                    summary = f"Response container selector:\n{response_selector}"
                    draft = {**submission, "response_selector": response_selector}
                    if await _manual_confirm_and_save(
                        page,
                        site,
                        component,
                        draft,
                        title="Step 6/7 — Confirm response selector",
                        summary=summary,
                    ):
                        submission["response_selector"] = response_selector
                        print(f"    response_selector: {response_selector}")
                        break
                    print("    retrying step 6...")
                return True

            if has_profile:
                browser, context = await launch_persistent_context(
                    p, str(profile_path), headless=False, site=site
                )
                page = await context.new_page()
                try:
                    return await _capture(page)
                finally:
                    await context.close()
                    if browser:
                        await browser.close()

            return await run_with_page_from_fetchers(
                p,
                site,
                _capture,
                storage_path=str(storage_path) if storage_path else None,
                interactive=True,
                human_only=True,
            )

    ok = bool(asyncio.run(_run_manual()))
    if not ok:
        print("  [!] Manual discovery failed.")
        return False

    print("\n" + "═" * 50)
    print(f"  Manual discovery complete -> sites/{site}/{component}/config.yaml")
    print(f"    start_url:         {submission.get('start_url') or '(unset)'}")
    print(f"    inputs:            {len(submission['inputs'])} field(s)")
    file_inputs = [i for i in submission["inputs"] if i.get("type") == "file"]
    if file_inputs:
        print(f"    multimodal upload: {file_inputs[0].get('selector')}")
    print(f"    submit_selector:   {submission['submit_selector']}")
    print(f"    response_selector: {submission['response_selector']}")
    print("═" * 50)
    return True


def run_training(site: str, component: str) -> bool:
    """
    Bulletproof 7-step discovery — fully automated after the first Enter:

    1. Interactive browser   — user navigates to page, presses Enter
    2. Upload detection      — scan page HTML for file inputs
    3. LLM extracts inputs   — printed, saved immediately (file inputs first)
    4. Headless verify input — fills text / probe file, screenshot
    5. LLM extracts submit   — from filled-input HTML so send button is visible
    6. Headless verify submit — fills + clicks, detects POST/URL change, captures response HTML
    7. LLM extracts response selector — from post-response HTML
    Config saved incrementally; edit config.yaml manually if any selector is wrong.
    """
    profile_path = get_login_profile_path(site)
    has_profile = _should_use_login_profile(site)
    storage_path = get_storage_state_path(site)
    if not has_profile and not storage_path:
        print("  No auth for this site. Run 'Add login' first.")
        return False
    _print_profile_disabled_notice(site)
    _ensure_site_config_for_discovery(site, component)

    config = load_component_config(site, component)
    start_url = config.get("login_url") or f"https://{site}"

    # Submission dict built up incrementally
    submission: dict = {
        "start_url": "",
        "inputs": [],
        "submit_selector": "",
        "response_selector": "",
        "submit_via": "click",
        "response_wait_ms": 8000,
    }

    # -----------------------------------------------------------------------
    # Step 1 — Interactive browser: user navigates, presses Enter
    # -----------------------------------------------------------------------
    print("\n" + "─" * 50)
    print("  [1/7] Opening browser — navigate to the submission page")
    print("        and press Enter when the input area is visible.")
    if has_profile:
        print("        Using persistent login profile for session restoration.")
    print("─" * 50)

    form_html: str = ""
    page_url: str = ""

    async def _step1():
        async with async_playwright() as p:
            from main import run_with_page_from_fetchers

            async def _capture(page):
                await page.goto(start_url, wait_until="domcontentloaded", timeout=60000)
                print("\n  Navigate to the submission page.")
                print("  Press Enter when the input area is fully visible...")
                await _wait_for_enter()
                body_html = await _get_page_html(page)
                full_html = await page.content()
                return body_html, full_html, page.url

            if has_profile:
                browser, context = await launch_persistent_context(
                    p, str(profile_path), headless=False, site=site
                )
                page = await context.new_page()
                try:
                    return await _capture(page)
                finally:
                    await context.close()
                    if browser:
                        await browser.close()
            return await run_with_page_from_fetchers(
                p,
                site,
                _capture,
                storage_path=str(storage_path) if storage_path else None,
                interactive=True,
                human_only=True,
            )

    step1_result = asyncio.run(_step1())
    if step1_result is None:
        print("  [!] Browser capture failed.")
        return False
    form_html, full_html, page_url = step1_result

    html_path = _save_html(site, component, form_html, "_form")
    print(f"  HTML saved -> {html_path}")

    submission["start_url"] = page_url
    _save_partial(site, component, submission)

    # -----------------------------------------------------------------------
    # Step 2 — Detect file upload support from captured HTML
    # -----------------------------------------------------------------------
    print("\n" + "─" * 50)
    print("  [2/7] Detecting file upload support...")
    print("─" * 50)

    detected_file_inputs = _detect_uploads_from_html(form_html)
    if detected_file_inputs:
        print(f"  Upload support: yes ({len(detected_file_inputs)} file input(s))")
        for row in detected_file_inputs:
            print(f"    file input: {row['selector']} (path_from=payload)")
        submission["response_wait_ms"] = max(int(submission.get("response_wait_ms") or 8000), 60000)
        _save_partial(site, component, submission)
    else:
        print("  Upload support: no")

    # -----------------------------------------------------------------------
    # Step 3 — LLM extracts input selector(s)
    # -----------------------------------------------------------------------
    print("\n" + "─" * 50)
    print("  [3/7] Extracting input selector via AI...")
    print("─" * 50)

    llm_inputs = _retry_extract_inputs(form_html, page_url)
    merged_inputs = _merge_upload_inputs(detected_file_inputs, llm_inputs)

    if not merged_inputs:
        print("  [!] Input selector not found after retries. Discovery cannot continue.")
        submission["inputs"] = []
        _save_partial(site, component, submission)
        return False

    for inp in merged_inputs:
        suffix = " (multimodal)" if inp.get("type") == "file" else ""
        print(f"    input: {inp['selector']} (type={inp.get('type', 'text')}){suffix}")

    submission["inputs"] = merged_inputs
    _save_partial(site, component, submission)
    print(f"  Saved {len(merged_inputs)} input(s).")

    # -----------------------------------------------------------------------
    # Step 4 — Headless verify each input
    # -----------------------------------------------------------------------
    print("\n" + "─" * 50)
    print("  [4/7] Verifying input selector(s) headlessly...")
    print("─" * 50)

    confirmed_inputs = merged_inputs
    for i, inp in enumerate(confirmed_inputs):
        print(f"\n  Verifying input [{i + 1}/{len(confirmed_inputs)}]: {inp['selector']}")
        ok, screenshot = asyncio.run(
            _headless_verify_input(site, component, page_url, inp, str(storage_path))
        )
        if ok:
            print(f"  ✓ Input verified. Screenshot: {screenshot}")
        else:
            print(f"  ✗ Verification failed. Screenshot: {screenshot}")
            print(f"    Proceeding — edit config.yaml if selector is wrong.")

    submission["inputs"] = confirmed_inputs
    _save_partial(site, component, submission)

    # -----------------------------------------------------------------------
    # Step 5 — LLM extracts submit selector
    # Capture HTML with text already in the input so the send button is visible
    # -----------------------------------------------------------------------
    print("\n" + "─" * 50)
    print("  [5/7] Extracting submit selector via AI...")
    print("        (capturing page with input filled so send button is visible)")
    print("─" * 50)

    filled_html = asyncio.run(
        _headless_capture_with_input_filled(site, page_url, confirmed_inputs, str(storage_path))
    )
    submit_source_html = filled_html or form_html
    if filled_html:
        _save_html(site, component, filled_html, "_filled")

    prompt_sel_hints = [i["selector"].strip() for i in confirmed_inputs if i.get("selector")]

    llm_submit = _retry_extract_submit(
        submit_source_html,
        page_url,
        prompt_sel_hints or None,
    )

    if not llm_submit:
        print("  [!] Submit selector not found after retries. Discovery cannot continue.")
        submission["submit_selector"] = ""
        _save_partial(site, component, submission)
        return False
    else:
        print(f"    submit_selector: {llm_submit}")

    submit_selector = llm_submit
    submission["submit_selector"] = submit_selector
    _save_partial(site, component, submission)

    # -----------------------------------------------------------------------
    # Step 6 — Headless verify submit + capture response HTML
    # -----------------------------------------------------------------------
    print("\n" + "─" * 50)
    print("  [6/7] Verifying submit selector and capturing response headlessly...")
    print("─" * 50)

    response_html: str | None = None

    print(f"  Submitting test prompt with: {submit_selector}")
    ok, response_html, screenshot = asyncio.run(
        _headless_verify_submit(
            site, component, page_url,
            confirmed_inputs, submit_selector,
            str(storage_path),
        )
    )
    if ok:
        print(f"  ✓ Submit verified. Screenshot: {screenshot}")
        if response_html:
            rhtml_path = _save_html(site, component, response_html, "_response")
            print(f"  Response HTML saved -> {rhtml_path}")
    else:
        print(f"  ✗ Submit verification failed. Screenshot: {screenshot}")
        print(f"    Proceeding — edit config.yaml if selector is wrong.")

    # -----------------------------------------------------------------------
    # Step 7 — LLM extracts response selector
    # -----------------------------------------------------------------------
    print("\n" + "─" * 50)
    print("  [7/7] Extracting response selector via AI...")
    print("─" * 50)

    response_selector = ""
    if response_html:
        response_selector = _retry_extract_response_selector(
            response_html,
            page_url,
            prompt_sel_hints or None,
        )
        if response_selector:
            print(f"    response_selector: {response_selector}")
        else:
            print("  [!] Response selector not found after retries. Discovery cannot complete.")
            submission["response_selector"] = ""
            _save_partial(site, component, submission)
            return False
    else:
        print("  No response HTML available — response selector cannot be extracted.")
        submission["response_selector"] = ""
        _save_partial(site, component, submission)
        return False

    submission["response_selector"] = response_selector
    _save_partial(site, component, submission)

    print("\n" + "═" * 50)
    print(f"  Discovery complete -> sites/{site}/{component}/config.yaml")
    print(f"    inputs:            {len(confirmed_inputs)} field(s)")
    file_inputs = [i for i in confirmed_inputs if i.get("type") == "file"]
    if file_inputs:
        print(f"    multimodal upload: {file_inputs[0].get('selector')}")
    print(f"    submit_selector:   {submit_selector or '(none)'}")
    print(f"    response_selector: {response_selector or '(empty)'}")
    print("═" * 50)
    return True
