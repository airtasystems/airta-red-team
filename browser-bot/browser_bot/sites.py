"""Site config and auth storage."""

from pathlib import Path
from urllib.parse import urlparse

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
SITES_DIR = _PROJECT_ROOT / "sites"
STORAGE_STATE_FILE = "storage_state.json"
AUTH_FILE = "auth.json"


def _domain_to_site_dir(domain: str) -> Path:
    """Convert domain (e.g. airtasystems.com) to site config directory."""
    return SITES_DIR / domain


def get_login_profile_path(domain: str) -> Path:
    """Path to persistent profile for login (Google trusts real profiles more)."""
    return _domain_to_site_dir(domain) / ".login_profile"


def get_site_company_rubric_path(domain: str) -> Path | None:
    """Path to sites/{domain}/company.json if it exists, else None."""
    p = _domain_to_site_dir(domain) / "company.json"
    return p if p.is_file() else None


def get_component_rubric_path(domain: str, component: str) -> Path | None:
    """Path to sites/{domain}/{component}/component.json if it exists, else None."""
    p = _domain_to_site_dir(domain) / component / "component.json"
    return p if p.is_file() else None


def get_domain_from_url(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split("/")[0] or ""


def get_storage_state_path(domain: str) -> Path | None:
    """Get path to auth config for domain. Prefers auth.json, falls back to storage_state.json."""
    site_dir = _domain_to_site_dir(domain)
    auth_path = site_dir / AUTH_FILE
    storage_path = site_dir / STORAGE_STATE_FILE
    if auth_path.exists():
        return auth_path
    return storage_path if storage_path.exists() else None


def get_storage_state_path_for_url(url: str) -> Path | None:
    """Get storage state path for a URL's domain."""
    return get_storage_state_path(get_domain_from_url(url))


def ensure_site_dir(domain: str) -> Path:
    """Ensure site directory exists. Creates auth.json with {} if new. Returns path."""
    path = _domain_to_site_dir(domain)
    path.mkdir(parents=True, exist_ok=True)
    auth_path = path / AUTH_FILE
    if not auth_path.exists():
        auth_path.write_text("{}", encoding="utf-8")
    return path


def get_storage_state_file(domain: str) -> Path:
    """Get the storage state file path for a domain (creates dir if needed)."""
    return ensure_site_dir(domain) / STORAGE_STATE_FILE


def list_sites() -> list[str]:
    """List all sites (any domain dir under sites/)."""
    if not SITES_DIR.exists():
        return []
    sites = []
    for item in SITES_DIR.iterdir():
        if item.is_dir() and not item.name.startswith("."):
            sites.append(item.name)
    return sorted(sites)


def remove_site(domain: str) -> bool:
    """Remove site config. Returns True if removed."""
    import shutil

    path = _domain_to_site_dir(domain)
    if path.exists():
        shutil.rmtree(path)
        return True
    return False


# --- Site config (sites/{domain}/config.yaml) ---
# Shared auth settings: login_url, refresh_url, refresh_mode, refresh_cookies.
# Components inherit these; component config overrides site config.

SITE_CONFIG_FILE = "config.yaml"


def get_site_config_path(domain: str) -> Path:
    """Path to site-level config.yaml."""
    return _domain_to_site_dir(domain) / SITE_CONFIG_FILE


def load_site_config(domain: str) -> dict:
    """Load site-level config. Returns empty dict if not found."""
    path = get_site_config_path(domain)
    if path.exists():
        import yaml

        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def save_site_config(domain: str, config: dict) -> Path:
    """Save site-level config with documented inline comments. Returns path."""
    from browser_bot.site_config_yaml import write_site_config_documented

    ensure_site_dir(domain)
    path = get_site_config_path(domain)
    write_site_config_documented(path, config)
    return path


def ensure_site_config_on_discovery(domain: str, *, login_url: str | None = None) -> Path | None:
    """Create default sites/<domain>/config.yaml on first discovery if missing."""
    from browser_bot.site_config_yaml import default_site_config, write_site_config_documented

    path = get_site_config_path(domain)
    if path.is_file():
        return None
    ensure_site_dir(domain)
    config = default_site_config(domain, login_url=login_url)
    write_site_config_documented(path, config)
    return path


# --- Component config (sites/{domain}/{component}/) ---

from browser_bot.component_config_yaml import write_component_config_documented

COMPONENT_CONFIG_FILE = "config.yaml"


def write_component_config_with_header(path: Path, config: dict) -> None:
    """Write component config.yaml with standard documentation and inline comments."""
    write_component_config_documented(path, config)


def get_component_path(domain: str, component: str) -> Path:
    """Path to component dir: sites/{domain}/{component}/."""
    return _domain_to_site_dir(domain) / component


def list_components(domain: str) -> list[str]:
    """List component names for a site (subdirs of sites/{domain}/)."""
    site_dir = _domain_to_site_dir(domain)
    if not site_dir.exists():
        return []
    components = []
    for item in site_dir.iterdir():
        if item.is_dir() and not item.name.startswith("."):
            components.append(item.name)
    return sorted(components)


def _default_login_url(domain: str) -> str:
    """Build default login_url from domain (http for localhost, https otherwise)."""
    if "localhost" in domain or domain.startswith("127."):
        return f"http://{domain}"
    return f"https://{domain}"


def ensure_component_dir(domain: str, component: str) -> Path:
    """Ensure component directory exists. Creates default config.yaml if new. Returns path."""
    path = get_component_path(domain, component)
    path.mkdir(parents=True, exist_ok=True)
    config_path = get_component_config_path(domain, component)
    if not config_path.exists():
        default_config = {
            "urls": [],
            "posts": [],
            "login_url": _default_login_url(domain),
        }
        write_component_config_with_header(config_path, default_config)
    return path


def get_component_config_path(domain: str, component: str) -> Path:
    """Path to component config.yaml."""
    return get_component_path(domain, component) / COMPONENT_CONFIG_FILE


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base. Override values take precedence. Does not mutate inputs."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_component_config_raw(domain: str, component: str) -> dict:
    """Load raw component config (no site merge). For internal use when saving."""
    path = get_component_config_path(domain, component)
    legacy_path = get_component_path(domain, component) / "config.json"
    if path.exists():
        import yaml

        with open(path) as f:
            return yaml.safe_load(f) or {}
    if legacy_path.exists():
        import json

        with open(legacy_path) as f:
            config = json.load(f)
        save_component_config(domain, component, config)
        legacy_path.unlink()
        return config
    return {}


def load_component_config(domain: str, component: str) -> dict:
    """Load component config merged with site config. Site provides defaults; component overrides.
    Returns empty dict if not found. Migrates config.json -> config.yaml if needed."""
    comp_raw = load_component_config_raw(domain, component)
    site_cfg = load_site_config(domain)
    return _deep_merge(site_cfg, comp_raw)


def save_component_config(domain: str, component: str, config: dict) -> Path:
    """Save component config. Returns path."""
    ensure_component_dir(domain, component)
    path = get_component_config_path(domain, component)
    write_component_config_with_header(path, config)
    return path


def get_component_urls_and_posts(domain: str, component: str) -> tuple[list, list]:
    """Load urls and posts from component config. Returns (urls, posts). Fallback to empty."""
    config = load_component_config(domain, component)
    urls = config.get("urls") or []
    posts_raw = config.get("posts") or []
    posts = [
        {"url": p["url"], "data": p.get("data"), "json": p.get("json"), "headers": p.get("headers")}
        for p in posts_raw
        if isinstance(p, dict) and "url" in p
    ]
    return urls, posts


def get_component_endpoint(domain: str, component: str) -> str | None:
    """Get endpoint_url from component config."""
    config = load_component_config(domain, component)
    return config.get("endpoint_url")


def set_component_endpoint(domain: str, component: str, url: str) -> Path:
    """Save endpoint_url to component config."""
    config = load_component_config_raw(domain, component)
    config.setdefault("urls", [])
    config.setdefault("posts", [])
    config["endpoint_url"] = url
    return save_component_config(domain, component, config)


def get_submission_config(domain: str, component: str) -> dict | None:
    """Get runnable submission config (UI or API transport).

    UI requires start_url, inputs, submit_selector.
    API requires api_url and api_body (defaults to ``{prompt: '{{prompt}}'}``).
    """
    config = load_component_config(domain, component)
    sub = config.get("submission")
    if not sub or not isinstance(sub, dict):
        return None
    transport = (sub.get("transport") or "ui").strip().lower()
    if transport == "api":
        return _normalize_api_submission(sub, config)
    return _normalize_ui_submission(sub)


def _normalize_ui_submission(sub: dict) -> dict | None:
    if not sub.get("start_url") or not sub.get("submit_selector"):
        return None
    sub = dict(sub)
    if "inputs" not in sub and sub.get("input_selector"):
        sub["inputs"] = [{"selector": sub["input_selector"], "type": "text"}]
    if not sub.get("inputs"):
        return None
    sub.setdefault("transport", "ui")
    return sub


def _normalize_api_submission(sub: dict, config: dict) -> dict | None:
    api_url = sub.get("api_url") or config.get("endpoint_url") or sub.get("start_url")
    if not api_url:
        return None
    api_body = sub.get("api_body")
    if api_body is None:
        api_body = sub.get("api_body_template")
    if api_body is None:
        api_body = {"prompt": "{{prompt}}"}
    return {
        "transport": "api",
        "api_url": str(api_url).strip(),
        "api_method": (sub.get("api_method") or "POST").upper(),
        "api_headers": dict(sub.get("api_headers") or {}),
        "api_body": api_body,
        "api_response_path": (sub.get("api_response_path") or "response").strip(),
        "mode": sub.get("mode"),
        "batch_size": sub.get("batch_size"),
    }


def describe_submission_config_issue(config: dict) -> str:
    """Human-readable reason submission config is not runnable."""
    sub = config.get("submission")
    if not sub or not isinstance(sub, dict):
        return "missing submission block"
    transport = (sub.get("transport") or "ui").strip().lower()
    if transport == "api":
        if not (sub.get("api_url") or config.get("endpoint_url") or sub.get("start_url")):
            return "missing submission.api_url"
        return "invalid API submission block"
    missing = []
    if not sub.get("start_url"):
        missing.append("submission.start_url")
    if not (sub.get("inputs") or sub.get("input_selector")):
        missing.append("submission.inputs")
    if not sub.get("submit_selector"):
        missing.append("submission.submit_selector")
    return "missing " + ", ".join(missing) if missing else "invalid submission block"
