#!/usr/bin/env python3
"""
AIRTA CLI — Generate adversarial test suites, discover targets, run tests, and assess risk.

Interactive mode (no subcommand):
  python main.py          Select site/component, then use the pipeline menu.

Direct subcommands:
  generate      Generate adversarial test prompts from playbooks.
  discover      Interactive browser-bot menu: login, create component config, manage sites.
  run           Run generated test suite against a browser target, convert log for security-assess.
  security-assess   Run security assessment on an attack log → pipeline_report.json.
  export        Export a pipeline report to AIRTA Systems (security assessment import API).
"""
import sys
sys.dont_write_bytecode = True

import argparse
import asyncio
import importlib.util
import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

_root = Path(__file__).resolve().parent

STRATEGIES = [
    "zero_shot", "multi_shot", "few_shot", "iterative", "chain_of_thought",
    "prompt_chaining", "tree_of_thoughts", "self_consistency", "self_reflection",
    "directional_stimulus", "jailbreak", "multimodal",
]

try:
    from dotenv import load_dotenv
    load_dotenv(_root / ".config")
    load_dotenv(_root / ".env")
except ImportError:
    pass


def _setup_paths() -> None:
    """Make risk_level_agent importable from risk-level-agent/risk_level_agent.py."""
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))
    rla_file = _root / "risk-level-agent" / "risk_level_agent.py"
    if rla_file.exists() and "risk_level_agent" not in sys.modules:
        spec = importlib.util.spec_from_file_location("risk_level_agent", rla_file)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            sys.modules["risk_level_agent"] = mod
            spec.loader.exec_module(mod)


_browser_bot_dir = _root / "browser-bot"


def _get_playbooks() -> list[str]:
    playbooks_dir = _root / "playbooks"
    if not playbooks_dir.is_dir():
        return []
    out: list[str] = []
    for p in playbooks_dir.glob("*.json"):
        if p.stem in ("company", "component"):
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8-sig"))
            if data.get("deprecated"):
                continue
        except (json.JSONDecodeError, OSError):
            pass
        out.append(p.stem.replace("-", "_"))
    return sorted(out)


def _setup_browser_bot() -> None:
    """Add browser-bot to sys.path so its modules are importable."""
    bb = str(_browser_bot_dir)
    if bb not in sys.path:
        sys.path.insert(0, bb)


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------

def _run_generate(args) -> None:
    generator_py = _root / "generate-tests" / "generator.py"
    if not generator_py.exists():
        print(f"[-] Generator not found: {generator_py}")
        sys.exit(1)

    playbooks = _get_playbooks()
    if not playbooks:
        print("[-] No playbooks found in playbooks/. Add playbooks/*.json to enable generation.")
        sys.exit(1)

    env = os.environ.copy()
    site_args: list[str] = []
    site = getattr(args, "site", "") or ""
    component = getattr(args, "component", "") or ""
    if site and component:
        site_args = ["--site", site, "--component", component]
        env["AIRTA_SITE"] = site
        env["AIRTA_COMPONENT"] = component

    def _materialize_after_generate(strategy: str, playbook: str) -> None:
        if strategy != "multimodal" or not (site and component):
            return
        suite_path = (
            _browser_bot_dir
            / "sites"
            / site
            / component
            / "tests"
            / strategy.replace("_", "-")
            / f"{playbook.replace('_', '-')}.json"
        )
        if not suite_path.is_file():
            print(f"[warn] Multimodal suite not found: {suite_path}")
            return
        try:
            from payloads.materialize import materialize_suite

            _, n, t = materialize_suite(suite_path)
            print(f"[+] Materialized {n}/{t} payload artifacts under {suite_path.parent / 'artifacts'}")
        except Exception as exc:
            print(f"[warn] Payload materialize failed: {exc}")

    def gen_one(strategy: str, playbook: str) -> None:
        cmd = [
            sys.executable, str(generator_py),
            "--strategy", strategy, "--playbook", playbook,
        ] + site_args
        print(f"[*] Generating: strategy={strategy}, playbook={playbook}...")
        result = subprocess.run(cmd, cwd=str(_root), env=env)
        if result.returncode == 0:
            if site and component:
                out = f"browser-bot/sites/{site}/{component}/tests/{strategy.replace('_', '-')}/{playbook.replace('_', '-')}.json"
            else:
                out = f"generate-tests/{strategy.replace('_', '-')}/{playbook.replace('_', '-')}.json"
            print(f"[+] Done: {out}")
            _materialize_after_generate(strategy, playbook)
        else:
            print(f"[!] Generator exited {result.returncode} for {strategy}/{playbook}.")

    if args.all:
        total = len(STRATEGIES) * len(playbooks)
        n = 0
        for strat in STRATEGIES:
            for fw in playbooks:
                n += 1
                print(f"\n[{n}/{total}]")
                gen_one(strat, fw)
    elif args.all_playbooks:
        for i, fw in enumerate(playbooks, 1):
            print(f"\n[{i}/{len(playbooks)}]")
            gen_one(args.strategy, fw)
    elif args.all_strategies:
        for i, strat in enumerate(STRATEGIES, 1):
            print(f"\n[{i}/{len(STRATEGIES)}]")
            gen_one(strat, args.playbook)
    else:
        gen_one(args.strategy, args.playbook)


# ---------------------------------------------------------------------------
# security-assess
# ---------------------------------------------------------------------------

def _run_security_assess(args) -> None:
    _setup_paths()

    attack_log_path = Path(args.attack_log)
    if not attack_log_path.is_absolute():
        attack_log_path = Path.cwd() / attack_log_path
    if not attack_log_path.exists():
        print(f"[-] Attack log not found: {attack_log_path}")
        sys.exit(1)

    from pipeline.security_assess import run_security_assessment

    print(f"[*] Running security assessment on: {attack_log_path.name}")
    risk_results = run_security_assessment(attack_log_path)

    log_data = json.loads(attack_log_path.read_text(encoding="utf-8"))
    all_log_results = log_data.get("results", [])

    compliance_by_id: dict[str, dict] = {r["id"]: r for r in all_log_results if "id" in r}
    for r in risk_results:
        entry_id = r.get("id", "")
        cl = compliance_by_id.get(entry_id, {})
        for field in ("description", "expected_behavior", "status", "ok", "error"):
            if field not in r:
                r[field] = cl.get(field)

    from pipeline.response_html import enrich_adversarial_results_with_response_html

    enrich_adversarial_results_with_response_html(risk_results)

    from risk_level_agent import normalize_risk_level

    severity_order = ("critical", "high", "medium", "low", "informational", "indeterminate")

    def severity_index(level: str) -> int:
        level = normalize_risk_level(level)
        return severity_order.index(level) if level in severity_order else len(severity_order)

    category_rollup: dict[str, str] = {}
    for r in risk_results:
        m = r.get("category", "")
        if m:
            current = category_rollup.get(m, "low")
            new_level = normalize_risk_level(r.get("risk_level", "indeterminate"))
            if severity_index(new_level) < severity_index(current):
                category_rollup[m] = new_level

    log_dir = attack_log_path.parent
    run_timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    report = {
        "timestamp": run_timestamp,
        "playbook": log_data.get("playbook", log_data.get("framework", "")),
        "playbook_id": log_data.get("playbook_id", ""),
        "source_file": log_data.get("source_file", ""),
        "run_log_dir": str(log_dir),
        "attack_log": str(attack_log_path),
        "adversarial_results": risk_results,
        "category_rollup": category_rollup,
    }
    report_path = log_dir / "pipeline_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[+] Pipeline report: {report_path}")

    print("\n=== Summary ===")
    print(f"  Assessed: {len(risk_results)}")
    if category_rollup:
        for m, level in sorted(category_rollup.items()):
            print(f"  {m[:60]}: {level}")

    if args.report_dir:
        copy_dir = Path(args.report_dir)
        if not copy_dir.is_absolute():
            copy_dir = Path.cwd() / copy_dir
        copy_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(report_path, copy_dir / f"pipeline_report_{run_timestamp}.json")
        print(f"[+] Report copied to: {copy_dir}")


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------

def _run_discover(args) -> None:
    _setup_browser_bot()
    from menu import main_loop
    main_loop()


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def _latest_run_log(site: str, component: str) -> Path | None:
    """Newest browser-bot run log (timestamped dirs or legacy run_*.json)."""
    logs_dir = _browser_bot_dir / "sites" / site / component / "logs"
    if not logs_dir.is_dir():
        return None
    candidates = list(logs_dir.glob("*/run_log.json")) + list(logs_dir.glob("run_*.json"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _run_tests(args) -> None:
    suite_path = Path(args.suite)
    if not suite_path.is_absolute():
        suite_path = Path.cwd() / suite_path
    if not suite_path.exists():
        print(f"[-] Suite not found: {suite_path}")
        sys.exit(1)

    _setup_browser_bot()
    from browser_bot.config import infer_ui_mode_from_suite_raw

    suite = json.loads(suite_path.read_text(encoding="utf-8"))
    mode = infer_ui_mode_from_suite_raw(suite) or "single"

    site = args.site
    component = args.component
    if not site or not component:
        from menu import select_site_and_component, current_site, current_component
        import menu
        if not select_site_and_component():
            print("[-] No site/component selected.")
            sys.exit(1)
        site = menu.current_site
        component = menu.current_component

    print(f"[*] Running tests: {site}/{component} ({suite_path.name}, mode={mode})...")
    bb_main_path = _browser_bot_dir / "main.py"
    bb_spec = importlib.util.spec_from_file_location("browser_bot_main", bb_main_path)
    bb_main = importlib.util.module_from_spec(bb_spec)
    bb_spec.loader.exec_module(bb_main)
    asyncio.run(bb_main.run_posts(site=site, component=component, mode=mode, suite_path=suite_path))

    run_log = _latest_run_log(site, component)
    if not run_log:
        print("[!] No run log found after test run.")
        return

    print(f"[+] Run log: {run_log}")

    from pipeline.convert_log import convert_run_log
    attack_log = convert_run_log(run_log, suite_path)
    print(f"[+] Attack log: {attack_log}")

    if args.assess:
        print("\n[*] Running security assessment...")
        _setup_paths()
        from pipeline.security_assess import run_security_assessment

        risk_results = run_security_assessment(attack_log)
        log_data = json.loads(attack_log.read_text(encoding="utf-8"))
        compliance_by_id: dict[str, dict] = {
            r["id"]: r for r in log_data.get("results", []) if "id" in r
        }
        for r in risk_results:
            cl = compliance_by_id.get(r.get("id", ""), {})
            for field in ("description", "expected_behavior", "status", "ok", "error"):
                if field not in r:
                    r[field] = cl.get(field)

        from pipeline.response_html import enrich_adversarial_results_with_response_html

        enrich_adversarial_results_with_response_html(risk_results)

        from risk_level_agent import normalize_risk_level

        severity_order = ("critical", "high", "medium", "low", "informational", "indeterminate")
        def severity_index(level: str) -> int:
            level = normalize_risk_level(level)
            return severity_order.index(level) if level in severity_order else len(severity_order)

        category_rollup: dict[str, str] = {}
        for r in risk_results:
            m = r.get("category", "")
            if m:
                current = category_rollup.get(m, "low")
                new_level = normalize_risk_level(r.get("risk_level", "indeterminate"))
                if severity_index(new_level) < severity_index(current):
                    category_rollup[m] = new_level

        run_timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        report = {
            "timestamp": run_timestamp,
            "playbook": log_data.get("playbook", log_data.get("framework", "")),
            "playbook_id": log_data.get("playbook_id", ""),
            "source_file": log_data.get("source_file", ""),
            "run_log_dir": str(run_log.parent),
            "attack_log": str(attack_log),
            "adversarial_results": risk_results,
            "category_rollup": category_rollup,
        }
        report_path = attack_log.parent / "pipeline_report.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Pipeline report: {report_path}")

        print("\n=== Summary ===")
        print(f"  Assessed: {len(risk_results)}")
        for m, level in sorted(category_rollup.items()):
            print(f"  {m[:60]}: {level}")


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

def _run_export(args) -> None:
    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = Path.cwd() / report_path
    if not report_path.exists():
        print(f"[-] Pipeline report not found: {report_path}")
        sys.exit(1)

    host = os.getenv("AIRTASYSTEMS_HOST", "").strip() or args.host
    api_key = os.getenv("AIRTASYSTEMS_API_KEY", "").strip() or args.api_key
    program_id = os.getenv("AIRTASYSTEMS_PROGRAM_ID", "").strip() or args.program_id

    if not host:
        host = input("  AIRTA Systems host (e.g. app.airtasystems.com): ").strip()
    if not api_key:
        api_key = input("  API key (write:security_assessment_import scope): ").strip()
    if not program_id:
        program_id = input("  Program ID (MongoDB ObjectId): ").strip()
    if not host or not api_key or not program_id:
        print("[-] Host, API key, and Program ID are all required.")
        sys.exit(1)

    from pipeline.export_airta import export_pipeline_report
    export_pipeline_report(
        report_path,
        host=host,
        api_key=api_key,
        program_id=program_id,
        default_level=args.default_level,
        batch_size=args.batch_size,
        batch_delay_seconds=args.batch_delay,
    )


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

_session_site: str | None = None
_session_component: str | None = None


def _pick_numbered(
    label: str,
    items: list[str],
    *,
    create_label: str | None = None,
    display: list[str] | None = None,
) -> str | None:
    """Show a numbered list and return the chosen item from *items*, or None on cancel.

    Accepts a number or the item text (case-insensitive, partial prefix match).
    If *display* is set (same length as *items*), those strings are shown instead of *items*.
    If create_label is given, an extra option is appended for creating a new entry."""
    shown = display if display is not None and len(display) == len(items) else items
    total = len(items) + (1 if create_label else 0)
    print(f"\n  {label}")
    for i, item in enumerate(items, 1):
        print(f"    [{i}] {shown[i - 1]}")
    if create_label:
        print(f"    [{len(items) + 1}] {create_label}")
    choice = input(f"  Choice [1-{total}]: ").strip()
    if not choice:
        return None
    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(items):
            return items[idx - 1]
        if create_label and idx == len(items) + 1:
            return "__create__"
        print("  Invalid choice.")
        return None
    lower = choice.lower()
    for item in items:
        if item.lower() == lower or item.lower().replace("-", "_") == lower.replace("-", "_"):
            return item
    for i, item in enumerate(items):
        if shown[i].lower() == lower or shown[i].lower().replace("-", "_") == lower.replace("-", "_"):
            return item
    for item in items:
        if item.lower().startswith(lower):
            return item
    for i, item in enumerate(items):
        if shown[i].lower().startswith(lower):
            return item
    print(f"  '{choice}' not recognised.")
    return None


def _select_site_component() -> bool:
    """Prompt for site and component. Sets _session_site/_session_component. Returns True if set."""
    global _session_site, _session_component
    _setup_browser_bot()
    from browser_bot.sites import list_sites, list_components, ensure_site_dir, ensure_component_dir, get_domain_from_url

    sites = list_sites()
    choice = _pick_numbered("Select site:", sites, create_label="Create new site")
    if choice is None:
        return False
    if choice == "__create__":
        raw = input("\n  Enter domain or URL (e.g. example.com): ").strip()
        if not raw:
            return False
        domain = get_domain_from_url(raw) if "://" in raw or "/" in raw else raw.strip()
        if not domain:
            return False
        ensure_site_dir(domain)
        print(f"  Created sites/{domain}/")
        _session_site = domain
    else:
        _session_site = choice

    components = list_components(_session_site)
    choice = _pick_numbered(f"Select component for {_session_site}:", components, create_label="Create new component")
    if choice is None:
        _session_site = None
        return False
    if choice == "__create__":
        name = input("\n  New component name: ").strip()
        name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name).strip("_")
        if not name:
            _session_site = None
            return False
        ensure_component_dir(_session_site, name)
        print(f"  Created sites/{_session_site}/{name}/")
        _session_component = name
    else:
        _session_component = choice

    print(f"\n  Using: {_session_site} / {_session_component}")
    return True


def _pretty_strategy_dir(slug: str) -> str:
    """Directory name e.g. zero-shot -> Zero-shot."""
    return "-".join(part.capitalize() for part in slug.split("-") if part)


def _pretty_playbook_stem(stem: str) -> str:
    """Suite file stem e.g. owasp-llm -> OWASP LLM."""
    labels = {
        "owasp_llm": "OWASP LLM",
        "owasp_agent": "OWASP Agent",
        "mitre_attack": "MITRE ATLAS",
        "jailbreak_core": "Jailbreak Core",
        "system_prompt_exfil": "System Prompt Exfil",
        "prompt_injection": "Prompt Injection",
        "sensitive_info_disclosure": "Sensitive Info Disclosure",
        "api_secrets_disclosure": "API Keys & Secrets",
    }
    key = stem.replace("-", "_")
    if key in labels:
        return labels[key]
    return " ".join(p.capitalize() for p in stem.replace("_", "-").split("-") if p)


def _discover_strategy_dirs(site: str, component: str) -> list[Path]:
    """Subdirs of tests/ that contain at least one JSON suite file."""
    tests = _browser_bot_dir / "sites" / site / component / "tests"
    if not tests.is_dir():
        return []
    return sorted(
        [p for p in tests.iterdir() if p.is_dir() and any(p.glob("*.json"))],
        key=lambda p: p.name.lower(),
    )


def _list_suites(site: str | None = None, component: str | None = None) -> list[Path]:
    """Return generated suite JSON files sorted by modification time (newest first).

    When *site* and *component* are set (interactive session), only suites under
    ``browser-bot/sites/<site>/<component>/tests/`` are listed.

    Otherwise scans ``generate-tests/`` and all ``browser-bot/sites/*/*/tests/``.
    """
    found: list[Path] = []
    sites_dir = _browser_bot_dir / "sites"
    if site and component:
        comp_tests = sites_dir / site / component / "tests"
        if comp_tests.is_dir():
            found.extend(comp_tests.rglob("*.json"))
        return sorted(set(found), key=lambda p: p.stat().st_mtime, reverse=True)

    gen_dir = _root / "generate-tests"
    if gen_dir.is_dir():
        found.extend(gen_dir.rglob("*.json"))
    if sites_dir.is_dir():
        found.extend(sites_dir.glob("*/*/tests/**/*.json"))
    return sorted(set(found), key=lambda p: p.stat().st_mtime, reverse=True)


def _list_attack_logs() -> list[Path]:
    """Return attack_log.json files under browser-bot/sites/."""
    sites_dir = _browser_bot_dir / "sites"
    if not sites_dir.is_dir():
        return []
    return sorted(sites_dir.rglob("attack_log.json"), key=lambda p: p.stat().st_mtime, reverse=True)


def _list_pipeline_reports() -> list[Path]:
    """Return pipeline_report.json files under browser-bot/sites/."""
    sites_dir = _browser_bot_dir / "sites"
    if not sites_dir.is_dir():
        return []
    return sorted(sites_dir.rglob("pipeline_report.json"), key=lambda p: p.stat().st_mtime, reverse=True)


def _menu_generate() -> None:
    playbooks = _get_playbooks()
    if not playbooks:
        print("  [-] No playbooks found in playbooks/.")
        return

    choice = _pick_numbered("Select playbook:", [f.replace("_", "-") for f in playbooks])
    if not choice:
        return
    playbook = choice.replace("-", "_")

    choice = _pick_numbered(
        "Select strategy:",
        [s.replace("_", "-") for s in STRATEGIES],
        create_label="All strategies (run every strategy for this playbook)",
    )
    if not choice:
        return
    all_strategies = choice == "__create__"
    strategy = "zero_shot" if all_strategies else choice.replace("-", "_")

    args = SimpleNamespace(
        strategy=strategy,
        playbook=playbook,
        all=False,
        all_playbooks=False,
        all_strategies=all_strategies,
        site=_session_site or "",
        component=_session_component or "",
    )
    _run_generate(args)


def _menu_discover() -> None:
    _setup_browser_bot()
    import menu as bb_menu
    bb_menu.current_site = _session_site
    bb_menu.current_component = _session_component
    bb_menu.main_loop()


def _menu_run() -> None:
    site = _session_site or ""
    comp = _session_component or ""
    strategy_dirs = _discover_strategy_dirs(site, comp)
    if not strategy_dirs:
        print(
            f"  [-] No test suites under browser-bot/sites/{site}/{comp}/tests/. "
            "Run 'Generate tests' first."
        )
        return

    # Collect unique playbook stems across all strategy dirs
    fw_stems_set: set[str] = set()
    for sd in strategy_dirs:
        for f in sd.glob("*.json"):
            fw_stems_set.add(f.stem)
    fw_stems = sorted(fw_stems_set)
    if not fw_stems:
        print("  [-] No test suite files found. Run 'Generate tests' first.")
        return

    fw_labels = [_pretty_playbook_stem(s) for s in fw_stems]
    choice_fw = _pick_numbered("Select playbook:", fw_stems, display=fw_labels)
    if not choice_fw:
        return

    # Find strategy dirs that have this playbook
    available_strats = [sd for sd in strategy_dirs if (sd / f"{choice_fw}.json").exists()]
    if not available_strats:
        print(f"  [-] No strategy suites found for playbook '{choice_fw}'.")
        return

    strat_slugs = [p.name for p in available_strats]
    strat_labels = [_pretty_strategy_dir(s) for s in strat_slugs]
    choice_strat = _pick_numbered(
        "Select strategy:",
        strat_slugs,
        display=strat_labels,
        create_label="All strategies (run all for this playbook)",
    )
    if not choice_strat:
        return

    assess = input("\n  Run risk assessment after? [y/N]: ").strip().lower() == "y"

    if choice_strat == "__create__":
        total = len(available_strats)
        for i, sd in enumerate(available_strats, 1):
            suite_path = sd / f"{choice_fw}.json"
            print(f"\n[{i}/{total}] Running: {sd.name}/{choice_fw}")
            _run_tests(SimpleNamespace(suite=str(suite_path), site=site, component=comp, assess=assess))
    else:
        suite_path = next(sd for sd in available_strats if sd.name == choice_strat) / f"{choice_fw}.json"
        _run_tests(SimpleNamespace(suite=str(suite_path), site=site, component=comp, assess=assess))


def _menu_security_assess() -> None:
    logs = _list_attack_logs()
    if not logs:
        path_input = input("\n  Path to attack_log.json: ").strip()
        if not path_input:
            return
        args = SimpleNamespace(attack_log=path_input, report_dir=None)
    else:
        labels = [str(p.relative_to(_root)) for p in logs]
        choice = _pick_numbered("Select attack log:", labels)
        if not choice:
            return
        args = SimpleNamespace(attack_log=str(_root / choice), report_dir=None)
    _run_security_assess(args)


def _menu_export() -> None:
    reports = _list_pipeline_reports()
    if not reports:
        path_input = input("\n  Path to pipeline_report.json: ").strip()
        if not path_input:
            return
        args = SimpleNamespace(report=path_input, host="", api_key="", program_id="", default_level=None)
    else:
        labels = [str(p.relative_to(_root)) for p in reports]
        choice = _pick_numbered("Select pipeline report:", labels)
        if not choice:
            return
        args = SimpleNamespace(report=str(_root / choice), host="", api_key="", program_id="", default_level=None)
    _run_export(args)


def _menu_clear_cache() -> None:
    confirm = input("\n  Delete server-side Gemini cached content? [y/N]: ").strip().lower()
    delete_on_server = confirm == "y"

    cleared: list[str] = []

    # Generator cache (core.py)
    try:
        gen_tests_dir = str(_root / "generate-tests")
        if gen_tests_dir not in sys.path:
            sys.path.insert(0, gen_tests_dir)
        import core as gen_core
        gen_core.clear_gemini_cache(delete_on_server=delete_on_server)
        cleared.append("generator")
    except Exception as exc:
        print(f"  [!] Generator cache clear failed: {exc}")

    # Risk-level-agent cache (risk_level_agent.py)
    try:
        _setup_paths()
        import risk_level_agent as rla
        rla.clear_gemini_cache(delete_on_server=delete_on_server)
        local_removed = rla.clear_local_result_cache()
        cleared.append("risk-level-agent")
        if local_removed:
            print(f"  [+] Cleared {local_removed} local security-assessment result cache file(s).")
    except Exception as exc:
        print(f"  [!] Risk-level-agent cache clear failed: {exc}")

    try:
        from pipeline.cleanup import clear_project_pycache

        pycache_removed = clear_project_pycache(_root)
        if pycache_removed:
            print(f"  [+] Removed {pycache_removed} __pycache__ director{'y' if pycache_removed == 1 else 'ies'}.")
    except Exception as exc:
        print(f"  [!] __pycache__ cleanup failed: {exc}")

    if cleared:
        action = "Cleared in-process + deleted server-side" if delete_on_server else "Cleared in-process"
        print(f"  [+] {action} Gemini cache ({', '.join(cleared)}).")
    else:
        print("  [-] Nothing was cleared.")


def _show_menu() -> None:
    ctx = f" [{_session_site}/{_session_component}]" if _session_site and _session_component else ""
    print("\n" + "=" * 50)
    print(f"  AIRTA{ctx}")
    print("=" * 50)
    print("  1. Generate tests")
    print("  2. Discovery (browser-bot)")
    print("  3. Run tests")
    print("  4. Risk assessment")
    print("  5. Export to AIRTA Systems")
    print("  6. Change site/component")
    print("  7. Clear Gemini cache")
    print("  8. Exit")
    print("=" * 50)


def _interactive_menu() -> None:
    while not (_session_site and _session_component):
        if not _select_site_component():
            print("  Bye.")
            return

    while True:
        _show_menu()
        choice = input("  Choice [1-8]: ").strip()
        if choice == "1":
            _menu_generate()
        elif choice == "2":
            _menu_discover()
        elif choice == "3":
            _menu_run()
        elif choice == "4":
            _menu_security_assess()
        elif choice == "5":
            _menu_export()
        elif choice == "6":
            _select_site_component()
        elif choice == "7":
            _menu_clear_cache()
        elif choice == "8":
            print("\n  Bye.")
            break
        else:
            print("  Invalid choice.")


# ---------------------------------------------------------------------------
# CLI (argparse for direct subcommand use)
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AIRTA — generate adversarial test suites and run risk assessment.\n"
                    "Run with no subcommand for interactive menu.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", help="Command (omit for interactive menu)")

    def norm(s: str) -> str:
        return s.strip().replace("-", "_")

    # --- generate ---
    gen_p = sub.add_parser("generate", help="Generate adversarial test prompts from playbooks.")
    gen_p.add_argument("--strategy", type=norm, choices=STRATEGIES, default="zero_shot",
                       help="Prompt strategy (default: zero_shot).")
    gen_p.add_argument("--playbook", type=norm, default="owasp_llm",
                       help="Framework rubric name (default: owasp_llm).")
    gen_p.add_argument("--site", default="", help="Target site (writes suite under browser-bot/sites/<site>/...).")
    gen_p.add_argument("--component", default="", help="Target component (with --site).")
    gen_p.add_argument("--all", action="store_true",
                       help="Generate all strategies x all playbooks.")
    gen_p.add_argument("--all-playbooks", action="store_true",
                       help="Generate all playbooks for the given strategy.")
    gen_p.add_argument("--all-strategies", action="store_true",
                       help="Generate all strategies for the given playbook.")

    # --- discover ---
    sub.add_parser("discover", help="Interactive browser-bot menu: login, create component config, manage sites.")

    # --- run ---
    run_p = sub.add_parser("run", help="Run a generated test suite against a browser target.")
    run_p.add_argument(
        "suite",
        help="Path to attack suite JSON (e.g. browser-bot/sites/<site>/<component>/tests/zero-shot/owasp-llm.json).",
    )
    run_p.add_argument("--site", default="", help="browser-bot site (domain). Interactive picker if omitted.")
    run_p.add_argument("--component", default="", help="browser-bot component. Interactive picker if omitted.")
    run_p.add_argument("--assess", action="store_true",
                       help="Immediately run risk assessment after the test run.")

    # --- security-assess ---
    risk_p = sub.add_parser("security-assess", help="Run risk assessment on a attack log.")
    risk_p.add_argument("attack_log", help="Path to attack_log.json.")
    risk_p.add_argument("--report-dir", metavar="DIR",
                        help="Also copy pipeline_report.json to this directory.")

    # --- export ---
    exp_p = sub.add_parser("export", help="Export pipeline report as security assessment to AIRTA Systems.")
    exp_p.add_argument("report", help="Path to pipeline_report.json.")
    exp_p.add_argument("--host", default="", help="AIRTA Systems host (or set AIRTASYSTEMS_HOST).")
    exp_p.add_argument("--api-key", default="", help="AIRTA Systems API key (or set AIRTASYSTEMS_API_KEY).")
    exp_p.add_argument("--program-id", default="", help="Program ID (or set AIRTASYSTEMS_PROGRAM_ID).")
    exp_p.add_argument(
        "--default-severity",
        "--default-level",
        dest="default_level",
        choices=["indeterminate", "informational", "low", "medium", "high", "critical"],
        help="Fallback severity when a result row lacks risk_level.",
    )
    exp_p.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help="Results per POST (default: AIRTASYSTEMS_EXPORT_BATCH_SIZE or 25).",
    )
    exp_p.add_argument(
        "--batch-delay",
        type=float,
        default=None,
        help="Seconds between batches (default: AIRTASYSTEMS_EXPORT_DELAY_SECONDS or 2).",
    )

    args = parser.parse_args()

    if args.command == "generate":
        _run_generate(args)
    elif args.command == "discover":
        _run_discover(args)
    elif args.command == "run":
        _run_tests(args)
    elif args.command == "security-assess":
        _run_security_assess(args)
    elif args.command == "export":
        _run_export(args)
    else:
        _interactive_menu()


if __name__ == "__main__":
    main()
