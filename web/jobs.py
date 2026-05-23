"""Job manager — spawn, track, stream, and cancel long-running tasks."""

from __future__ import annotations

import asyncio
import io
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

_root = Path(__file__).resolve().parent.parent


def _prepare_component_context(job: Job) -> None:
    """Set AIRTA_SITE/COMPONENT and apply per-component browser settings overrides."""
    if job.site:
        os.environ["AIRTA_SITE"] = job.site
    if job.component:
        os.environ["AIRTA_COMPONENT"] = job.component
    if not (job.site and job.component):
        return
    bb_dir = _root / "browser-bot"
    if str(bb_dir) not in sys.path:
        sys.path.insert(0, str(bb_dir))
    from browser_bot.config import apply_component_settings

    apply_component_settings(job.site, job.component)


@dataclass
class Job:
    id: str
    type: str
    status: str  # pending | running | done | failed | cancelled
    site: str
    component: str
    params: dict
    output: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    _process: asyncio.subprocess.Process | None = field(default=None, repr=False)
    _task: asyncio.Task | None = field(default=None, repr=False)
    _event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "status": self.status,
            "site": self.site,
            "component": self.component,
            "params": self.params,
            "created_at": self.created_at.isoformat(),
            "output_lines": len(self.output),
        }


class _OutputCapture(io.TextIOBase):
    """File-like that appends lines to a Job's output buffer and pokes its event."""

    def __init__(self, job: Job):
        self._job = job

    def write(self, s: str) -> int:
        if s:
            for line in s.split("\n"):
                stripped = line.rstrip("\r")
                if stripped.strip():
                    self._job.output.append(stripped)
                    self._job._event.set()
        return len(s)

    def flush(self) -> None:
        pass


_jobs: dict[str, Job] = {}

_ALL_STRATEGIES = [
    "zero_shot", "multi_shot", "few_shot", "iterative", "chain_of_thought",
    "prompt_chaining", "tree_of_thoughts", "self_consistency", "self_reflection",
    "directional_stimulus", "jailbreak", "multimodal",
]


def _suite_path_for_generate(site: str, component: str, strategy: str, playbook: str) -> Path:
    return (
        _root
        / "browser-bot"
        / "sites"
        / site
        / component
        / "tests"
        / strategy.replace("_", "-")
        / f"{playbook.replace('_', '-')}.json"
    )


def _materialize_multimodal_output(job: Job, strategy: str, playbook: str) -> None:
    if strategy != "multimodal" or job.status != "done" or not (job.site and job.component):
        return
    suite_path = _suite_path_for_generate(job.site, job.component, strategy, playbook)
    if not suite_path.is_file():
        job.output.append(f"[warn] Multimodal suite not found for materialize: {suite_path}")
        job._event.set()
        return
    try:
        from payloads.materialize import materialize_suite

        _, materialized, total = materialize_suite(suite_path)
        artifacts_dir = suite_path.parent / "artifacts"
        job.output.append(
            f"[+] Materialized {materialized}/{total} payload file(s) under {artifacts_dir}"
        )
        if materialized < total:
            job.output.append(
                f"[warn] {total - materialized} payload(s) failed — check server logs; "
                "re-run materialize or fix generator args in the suite JSON."
            )
    except Exception as exc:
        job.output.append(f"[warn] Payload materialize failed: {exc}")
    job._event.set()


def _warn_multimodal_preflight(job: Job, suite_path: Path, suite_data: dict) -> None:
    """Print warnings when suite has payloads but upload config or artifact files are missing."""
    has_payloads = False
    for cat in suite_data.get("categories") or suite_data.get("mandates") or []:
        if not isinstance(cat, dict):
            continue
        for p in cat.get("prompts") or []:
            payload = p.get("payload") if isinstance(p, dict) else None
            if isinstance(payload, dict) and (payload.get("generator") or payload.get("path")):
                has_payloads = True
                break
        if has_payloads:
            break
    if not has_payloads:
        return

    bb_dir = _root / "browser-bot"
    if str(bb_dir) not in sys.path:
        sys.path.insert(0, str(bb_dir))
    from browser_bot.sites import get_submission_config

    sub = get_submission_config(job.site, job.component) or {}
    transport = (sub.get("transport") or "ui").lower()
    upload_ok = transport in ("api_document", "api_multipart")
    if not upload_ok and transport == "ui":
        inputs = sub.get("inputs") or []
        upload_ok = any(
            i.get("type") == "file" or i.get("path_from") == "payload" for i in inputs if isinstance(i, dict)
        )
    if not upload_ok:
        print(
            "[warn] Suite includes file payloads but component config has no file upload "
            "(UI input type: file with path_from: payload, or transport api_document/api_multipart)."
        )

    try:
        from payloads.materialize import artifact_status_for_suite

        for row in artifact_status_for_suite(suite_path):
            pid = row.get("id") or "?"
            status = row.get("status")
            if status == "missing_path":
                print(f"[warn] Missing artifact file for prompt {pid}: {row.get('path')}")
            elif status == "lazy":
                print(f"[info] Prompt {pid}: will generate payload at run time ({row.get('generator')})")
    except Exception:
        pass

_SEVERITY_ORDER = (
    "critical", "high", "medium", "low", "informational", "mitigated", "compliant", "indeterminate",
)


def _category_rollup_from_results(risk_results: list) -> dict[str, str]:
    """Per-category worst severity across assessed prompts."""

    def _idx(level: str) -> int:
        return _SEVERITY_ORDER.index(level) if level in _SEVERITY_ORDER else len(_SEVERITY_ORDER)

    rollup: dict[str, str] = {}
    for r in risk_results:
        cat = r.get("category", "")
        if not cat:
            continue
        current = rollup.get(cat, "mitigated")
        new_level = r.get("risk_level", "indeterminate")
        if _idx(new_level) < _idx(current):
            rollup[cat] = new_level
    return rollup


def list_jobs() -> list[dict]:
    return [j.to_dict() for j in _jobs.values()]


def get_job(job_id: str) -> Job | None:
    return _jobs.get(job_id)


async def stream_job(job_id: str):
    """Async generator yielding SSE-formatted lines as they appear."""
    job = _jobs.get(job_id)
    if not job:
        return
    cursor = 0
    while True:
        while cursor < len(job.output):
            # Embed any residual newlines as separate SSE data lines so the
            # EventSource parser receives a single logical event per line.
            text = job.output[cursor].replace("\n", "\ndata: ")
            yield f"data: {text}\n\n"
            cursor += 1
        if job.status in ("done", "failed", "cancelled"):
            yield f"event: done\ndata: {job.status}\n\n"
            return
        job._event.clear()
        try:
            await asyncio.wait_for(job._event.wait(), timeout=30.0)
        except asyncio.TimeoutError:
            yield ": keepalive\n\n"


async def send_stdin(job_id: str, text: str) -> bool:
    """Write text to a subprocess job's stdin. Returns True if sent."""
    job = _jobs.get(job_id)
    if not job or not job._process or job._process.stdin is None:
        return False
    try:
        job._process.stdin.write(text.encode())
        await job._process.stdin.drain()
        return True
    except Exception:
        return False


async def cancel_job(job_id: str) -> bool:
    job = _jobs.get(job_id)
    if not job or job.status not in ("pending", "running"):
        return False
    job.status = "cancelled"
    if job._process:
        try:
            job._process.terminate()
        except Exception:
            pass
    if job._task and not job._task.done():
        job._task.cancel()
    job._event.set()
    return True


# ---------------------------------------------------------------------------
# Job runners
# ---------------------------------------------------------------------------

async def _run_subprocess_job(job: Job, cmd: list[str], *, cwd: str | None = None, env: dict | None = None):
    """Run a command as an async subprocess, streaming stdout line by line."""
    job.status = "running"
    job._event.set()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.PIPE,
            cwd=cwd or str(_root),
            env=env,
        )
        job._process = proc
        assert proc.stdout
        async for raw_line in proc.stdout:
            line = raw_line.decode(errors="replace").rstrip("\n")
            job.output.append(line)
            job._event.set()
        await proc.wait()
        job.status = "done" if proc.returncode == 0 else "failed"
    except asyncio.CancelledError:
        job.status = "cancelled"
    except Exception as exc:
        job.output.append(f"[error] {exc}")
        job.status = "failed"
    finally:
        job._event.set()


async def _run_thread_job(job: Job, fn, *args: Any, **kwargs: Any):
    """Run a blocking function in a thread, capturing its stdout."""
    job.status = "running"
    job._event.set()

    def _wrapped():
        cap = _OutputCapture(job)
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = cap  # type: ignore[assignment]
        sys.stderr = cap  # type: ignore[assignment]
        try:
            return fn(*args, **kwargs)
        finally:
            sys.stdout, sys.stderr = old_out, old_err

    try:
        await asyncio.to_thread(_wrapped)
        job.status = "done"
    except asyncio.CancelledError:
        job.status = "cancelled"
    except Exception as exc:
        job.output.append(f"[error] {exc}")
        job.status = "failed"
    finally:
        job._event.set()


# ---------------------------------------------------------------------------
# Public start_job dispatcher
# ---------------------------------------------------------------------------

async def start_job(job_type: str, site: str, component: str, params: dict | None = None) -> Job:
    params = params or {}
    job = Job(
        id=uuid.uuid4().hex[:12],
        type=job_type,
        status="pending",
        site=site,
        component=component,
        params=params,
    )
    _jobs[job.id] = job

    if job_type == "generate":
        job._task = asyncio.create_task(_start_generate(job))
    elif job_type == "login":
        job._task = asyncio.create_task(_start_login(job))
    elif job_type == "company_discovery":
        job._task = asyncio.create_task(_start_company_discovery(job))
    elif job_type == "discover":
        job._task = asyncio.create_task(_start_discover(job))
    elif job_type == "manual_discover":
        job._task = asyncio.create_task(_start_manual_discover(job))
    elif job_type == "api_discover":
        job._task = asyncio.create_task(_start_api_discover(job))
    elif job_type == "run_tests":
        job._task = asyncio.create_task(_start_run_tests(job))
    elif job_type == "sample_request":
        job._task = asyncio.create_task(_start_sample_request(job))
    elif job_type == "security_assess":
        job._task = asyncio.create_task(_start_security_assess(job))
    elif job_type == "export":
        job._task = asyncio.create_task(_start_export(job))
    elif job_type == "clear_cache":
        job._task = asyncio.create_task(_start_clear_cache(job))
    else:
        job.status = "failed"
        job.output.append(f"Unknown job type: {job_type}")
        job._event.set()

    return job


# ---------------------------------------------------------------------------
# Per-type starters
# ---------------------------------------------------------------------------

async def _start_generate(job: Job):
    generator_py = _root / "generate-tests" / "generator.py"
    strategy = job.params.get("strategy", "zero_shot")
    playbook = job.params.get("playbook", "owasp_llm")

    # Resolve per-site company rubric and per-component spec rubric, falling back to globals.
    bb_dir = _root / "browser-bot"
    if str(bb_dir) not in sys.path:
        sys.path.insert(0, str(bb_dir))
    try:
        from browser_bot.sites import get_site_company_rubric_path, get_component_rubric_path
        company_rubric = get_site_company_rubric_path(job.site) if job.site else None
        spec_rubric = (
            get_component_rubric_path(job.site, job.component) if (job.site and job.component) else None
        )
        global_company = _root / "playbooks" / "company.json"
        global_spec = _root / "playbooks" / "component.json"
        if job.site and not company_rubric and global_company.is_file():
            job.output.append(
                f"[warn] No browser-bot/sites/{job.site}/company.json — falling back to playbooks/company.json"
            )
            company_rubric = global_company
        elif not company_rubric and global_company.is_file():
            company_rubric = global_company
        if job.site and job.component and not spec_rubric and global_spec.is_file():
            job.output.append(
                f"[warn] No browser-bot/sites/{job.site}/{job.component}/component.json — "
                "falling back to playbooks/component.json"
            )
            spec_rubric = global_spec
        elif not spec_rubric and global_spec.is_file():
            spec_rubric = global_spec
    except ImportError:
        company_rubric = _root / "playbooks" / "company.json" if (_root / "playbooks" / "company.json").exists() else None
        spec_rubric = _root / "playbooks" / "component.json" if (_root / "playbooks" / "component.json").exists() else None

    env = os.environ.copy()
    if job.site:
        env["AIRTA_SITE"] = job.site
    if job.component:
        env["AIRTA_COMPONENT"] = job.component
    if company_rubric:
        resolved = str(company_rubric.resolve() if hasattr(company_rubric, "resolve") else company_rubric)
        env["COMPANY_RUBRIC_JSON"] = resolved
        env["COMPONENT_RUBRIC_JSON"] = resolved
        env["COMPONENT_RUBRIC_CACHE_JSON"] = resolved
    if spec_rubric:
        env["COMPONENT_SPEC_RUBRIC_JSON"] = str(
            spec_rubric.resolve() if hasattr(spec_rubric, "resolve") else spec_rubric
        )

    def _build_cmd(strat: str) -> list[str]:
        cmd = [sys.executable, str(generator_py), "--strategy", strat, "--playbook", playbook]
        if job.site and job.component:
            cmd += ["--site", job.site, "--component", job.component]
        if spec_rubric:
            cmd += ["--component-rubric", str(spec_rubric)]
        return cmd

    if strategy == "__all__":
        job.status = "running"
        job._event.set()
        total = len(_ALL_STRATEGIES)
        try:
            for i, strat in enumerate(_ALL_STRATEGIES, 1):
                job.output.append(f"[{i}/{total}] Generating: strategy={strat}, playbook={playbook}...")
                job._event.set()
                proc = await asyncio.create_subprocess_exec(
                    *_build_cmd(strat),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    stdin=asyncio.subprocess.PIPE,
                    cwd=str(_root),
                    env=env,
                )
                job._process = proc
                assert proc.stdout
                async for raw_line in proc.stdout:
                    line = raw_line.decode(errors="replace").rstrip("\n")
                    job.output.append(line)
                    job._event.set()
                await proc.wait()
                if proc.returncode != 0:
                    job.output.append(f"[!] Generator exited {proc.returncode} for {strat}/{playbook}")
                elif strat == "multimodal":
                    job.status = "done"
                    _materialize_multimodal_output(job, strat, playbook)
            job.output.append(f"[+] All {total} strategies complete for playbook={playbook}.")
            job.status = "done"
        except asyncio.CancelledError:
            job.status = "cancelled"
        except Exception as exc:
            job.output.append(f"[error] {exc}")
            job.status = "failed"
        finally:
            job._event.set()
    else:
        await _run_subprocess_job(job, _build_cmd(strategy), env=env)
        _materialize_multimodal_output(job, strategy, playbook)


async def _start_login(job: Job):
    worker = _root / "web" / "login_worker.py"
    url = job.params.get("url", "")
    if not url:
        job.output.append("[!] No URL provided for login")
        job.status = "failed"
        job._event.set()
        return
    cmd = [sys.executable, "-u", str(worker), url]
    await _run_subprocess_job(job, cmd)


async def _start_company_discovery(job: Job):
    worker = _root / "web" / "company_discovery_worker.py"
    cmd = [sys.executable, "-u", str(worker), job.site]
    await _run_subprocess_job(job, cmd)


async def _start_discover(job: Job):
    worker = _root / "web" / "discover_worker.py"
    cmd = [sys.executable, "-u", str(worker), job.site, job.component]
    await _run_subprocess_job(job, cmd)


async def _start_api_discover(job: Job):
    worker = _root / "web" / "api_discover_worker.py"
    params = {
        "api_url": job.params.get("api_url", ""),
        "api_method": job.params.get("api_method", "POST"),
        "api_headers": job.params.get("api_headers") or {},
        "api_body": job.params.get("api_body"),
        "api_response_path": job.params.get("api_response_path", "response"),
        "probe_prompt": job.params.get("probe_prompt", "Hello from AIRTA"),
    }
    import json as _json

    cmd = [sys.executable, "-u", str(worker), job.site, job.component, _json.dumps(params)]
    await _run_subprocess_job(job, cmd)


async def _start_manual_discover(job: Job):
    worker = _root / "web" / "manual_discover_worker.py"
    cmd = [sys.executable, "-u", str(worker), job.site, job.component]
    await _run_subprocess_job(job, cmd)


async def _start_run_tests(job: Job):
    suite_param = job.params.get("suite", "")
    assess = bool(job.params.get("assess", False))

    def _run_one_suite(suite_path_str: str) -> None:
        """Run a single suite file. Must be called from a thread (uses asyncio.run internally)."""
        import importlib.util
        import json as _json

        _prepare_component_context(job)

        bb_dir = _root / "browser-bot"
        if str(bb_dir) not in sys.path:
            sys.path.insert(0, str(bb_dir))
        if str(_root) not in sys.path:
            sys.path.insert(0, str(_root))

        suite_path = Path(suite_path_str)
        if not suite_path.is_absolute():
            suite_path = _root / suite_path
        suite_data = _json.loads(suite_path.read_text(encoding="utf-8"))

        _warn_multimodal_preflight(job, suite_path, suite_data)

        from browser_bot.config import infer_ui_mode_from_suite_raw
        from browser_bot.sites import describe_submission_config_issue, get_submission_config, load_component_config

        mode = infer_ui_mode_from_suite_raw(suite_data) or "single"

        if not get_submission_config(job.site, job.component):
            reason = describe_submission_config_issue(load_component_config(job.site, job.component))
            raise RuntimeError(
                f"Cannot run test suite for {job.site}/{job.component}: {reason}. "
                "Run Discovery / Connect via API or complete the component submission config first."
            )

        bb_main_path = bb_dir / "main.py"
        spec = importlib.util.spec_from_file_location("browser_bot_main", bb_main_path)
        bb_main = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bb_main)
        import asyncio as _aio
        _aio.run(bb_main.run_posts(site=job.site, component=job.component, mode=mode, suite_path=suite_path))

        logs_dir = bb_dir / "sites" / job.site / job.component / "logs"
        if logs_dir.is_dir():
            logs = sorted(
                list(logs_dir.glob("*/run_log.json")) + list(logs_dir.glob("run_*.json")),
                key=lambda p: p.stat().st_mtime, reverse=True,
            )
            if logs:
                run_log = logs[0]
                print(f"[+] Run log: {run_log}")
                from pipeline.convert_log import convert_run_log
                attack_log = convert_run_log(run_log, suite_path)
                print(f"[+] Attack log: {attack_log}")

                if assess:
                    print("[*] Running security assessment...")
                    from pipeline.security_assess import run_security_assessment
                    risk_results = run_security_assessment(attack_log)

                    log_data = _json.loads(attack_log.read_text(encoding="utf-8"))
                    attack_by_id = {r["id"]: r for r in log_data.get("results", []) if "id" in r}
                    for r in risk_results:
                        cl = attack_by_id.get(r.get("id", ""), {})
                        for fld in ("description", "expected_behavior", "status", "ok", "error"):
                            if fld not in r:
                                r[fld] = cl.get(fld)

                    from pipeline.response_html import enrich_adversarial_results_with_response_html

                    enrich_adversarial_results_with_response_html(risk_results)

                    category_rollup = _category_rollup_from_results(risk_results)

                    from datetime import datetime as _dt
                    ts = _dt.now().strftime("%Y-%m-%dT%H-%M-%S")
                    report = {
                        "timestamp": ts,
                        "playbook": log_data.get("playbook", log_data.get("framework", "")),
                        "playbook_id": log_data.get("playbook_id", ""),
                        "source_file": log_data.get("source_file", ""),
                        "run_log_dir": str(run_log.parent),
                        "attack_log": str(attack_log),
                        "adversarial_results": risk_results,
                        "category_rollup": category_rollup,
                    }
                    report_path = attack_log.parent / "pipeline_report.json"
                    report_path.write_text(_json.dumps(report, indent=2), encoding="utf-8")
                    print(f"[+] Pipeline report: {report_path}")
                    print(f"[+] Assessed: {len(risk_results)}")

    if suite_param == "__all__":
        playbook = job.params.get("playbook", "")
        bb_dir = _root / "browser-bot"
        tests_dir = bb_dir / "sites" / job.site / job.component / "tests"
        suites = sorted(tests_dir.glob(f"*/{playbook}.json")) if tests_dir.is_dir() else []

        if not suites:
            job.output.append(f"[!] No test suites found for playbook={playbook}")
            job.status = "failed"
            job._event.set()
            return

        total = len(suites)

        def _run_all():
            import json as _json

            for i, sp in enumerate(suites, 1):
                strat_name = sp.parent.name
                print(
                    f"[airta_progress] {_json.dumps({'type': 'suite', 'current': i, 'total': total, 'strategy': strat_name}, ensure_ascii=False)}",
                    flush=True,
                )
                print(f"[{i}/{total}] Running: strategy={strat_name}, playbook={playbook}...")
                _run_one_suite(str(sp))
            print(f"[+] All {total} strategy suites complete for playbook={playbook}.")

        await _run_thread_job(job, _run_all)
    else:
        await _run_thread_job(job, lambda: _run_one_suite(suite_param))


async def _start_sample_request(job: Job):
    prompt = str(job.params.get("prompt") or "capital of england")

    def _do():
        import asyncio as _aio
        import importlib.util
        import time

        _prepare_component_context(job)

        bb_dir = _root / "browser-bot"
        if str(bb_dir) not in sys.path:
            sys.path.insert(0, str(bb_dir))

        from browser_bot.sites import describe_submission_config_issue, get_storage_state_path, get_submission_config, load_component_config
        from browser_bot.submit.api_helpers import do_api_request
        from browser_bot.submit.single import do_ui_submit_with_page

        sub = get_submission_config(job.site, job.component)
        if not sub:
            reason = describe_submission_config_issue(load_component_config(job.site, job.component))
            raise RuntimeError(
                f"Cannot send sample request for {job.site}/{job.component}: {reason}. "
                "Run Discovery / Connect via API or complete the component submission config first."
            )

        if sub.get("transport") == "api":
            status, response_text, err = do_api_request(sub, prompt, site=job.site)
            print("[sample] Prompt: " + prompt)
            print("[sample] Transport: api")
            print("[sample] Status: " + str(status))
            print("[sample] Response:")
            print(response_text or err or "(none)")
            if err and not response_text:
                raise RuntimeError(f"Sample API request failed: {err}")
            return

        storage_path = get_storage_state_path(job.site)
        if not storage_path:
            raise RuntimeError(f"No saved auth available for {job.site}. Run Add Login first.")

        bb_main_path = bb_dir / "main.py"
        spec = importlib.util.spec_from_file_location("browser_bot_main", bb_main_path)
        bb_main = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bb_main)

        async def _run():
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                async def _submit(page):
                    captured = []

                    def _on_response(response):
                        if response.request.method in ("POST", "PUT", "PATCH"):
                            captured.append(response)

                    page.on("response", _on_response)
                    start = time.perf_counter()
                    try:
                        _, response_text = await do_ui_submit_with_page(
                            page,
                            sub["start_url"],
                            sub["inputs"],
                            sub["submit_selector"],
                            prompt,
                            response_selector=sub.get("response_selector") or "",
                            response_within_selector=sub.get("response_within_selector") or "",
                            response_text_within_selector=sub.get("response_text_within_selector") or "",
                            submit_via=sub.get("submit_via", "click"),
                            response_wait_ms=int(sub.get("response_wait_ms", 5000) or 5000),
                            human_behavior=True,
                        )
                    finally:
                        try:
                            page.remove_listener("response", _on_response)
                        except Exception:
                            pass

                    elapsed = time.perf_counter() - start
                    origin_parts = page.url.split("/", 3)[:3]
                    origin = "/".join(origin_parts) if len(origin_parts) >= 3 else ""
                    same_origin = [
                        resp for resp in captured
                        if not origin or resp.request.url.startswith(origin)
                    ]
                    chosen = same_origin[-1] if same_origin else (captured[-1] if captured else None)
                    return {
                        "prompt": prompt,
                        "response": response_text or "",
                        "elapsed_sec": elapsed,
                        "status": chosen.status if chosen else None,
                        "status_url": chosen.request.url if chosen else "",
                    }

                return await bb_main.run_with_page_from_fetchers(
                    p,
                    job.site,
                    _submit,
                    storage_path=str(storage_path),
                    interactive=False,
                    human_only=False,
                )

        result = _aio.run(_run())
        if not result:
            raise RuntimeError("Sample request failed: browser submission returned no result.")

        print("[sample] Prompt: " + result["prompt"])
        print("[sample] Status: " + (str(result["status"]) if result["status"] is not None else "not captured"))
        if result.get("status_url"):
            print("[sample] Status URL: " + result["status_url"])
        print(f"[sample] Timing: {result['elapsed_sec']:.2f}s")
        print("[sample] Response:")
        print(result["response"] or "(none)")

    await _run_thread_job(job, _do)


async def _start_security_assess(job: Job):
    attack_log = job.params.get("attack_log", "")

    def _do():
        if str(_root) not in sys.path:
            sys.path.insert(0, str(_root))
        try:
            from dotenv import load_dotenv

            load_dotenv(_root / ".config")
            load_dotenv(_root / ".env")
        except ImportError:
            pass
        _prepare_component_context(job)

        import importlib.util
        rla_file = _root / "risk-level-agent" / "risk_level_agent.py"
        if rla_file.exists() and "risk_level_agent" not in sys.modules:
            spec = importlib.util.spec_from_file_location("risk_level_agent", rla_file)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules["risk_level_agent"] = mod
                spec.loader.exec_module(mod)

        from pipeline.security_assess import run_security_assessment
        import json as _json

        cl_path = Path(attack_log)
        if not cl_path.is_absolute():
            cl_path = _root / cl_path
        print(f"[*] Running security assessment on: {cl_path.name}")
        risk_results = run_security_assessment(cl_path)

        log_data = _json.loads(cl_path.read_text(encoding="utf-8"))
        all_log_results = log_data.get("results", [])
        attack_by_id = {r["id"]: r for r in all_log_results if "id" in r}
        for r in risk_results:
            cl_entry = attack_by_id.get(r.get("id", ""), {})
            for fld in ("description", "expected_behavior", "status", "ok", "error"):
                if fld not in r:
                    r[fld] = cl_entry.get(fld)

        from pipeline.response_html import enrich_adversarial_results_with_response_html

        enrich_adversarial_results_with_response_html(risk_results)

        category_rollup = _category_rollup_from_results(risk_results)

        from datetime import datetime as _dt
        ts = _dt.now().strftime("%Y-%m-%dT%H-%M-%S")
        report = {
            "timestamp": ts,
            "playbook": log_data.get("playbook", log_data.get("framework", "")),
            "playbook_id": log_data.get("playbook_id", ""),
            "source_file": log_data.get("source_file", ""),
            "run_log_dir": str(cl_path.parent),
            "attack_log": str(cl_path),
            "adversarial_results": risk_results,
            "category_rollup": category_rollup,
        }
        report_path = cl_path.parent / "pipeline_report.json"
        report_path.write_text(_json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Pipeline report: {report_path}")
        print(f"[+] Assessed: {len(risk_results)}")
        for m, level in sorted(category_rollup.items()):
            print(f"  {m[:60]}: {level}")

    await _run_thread_job(job, _do)


def _load_env_vars() -> dict[str, str]:
    """Parse key=value pairs from the root .env file."""
    env_file = _root / ".env"
    result: dict[str, str] = {}
    if not env_file.exists():
        return result
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip().strip('"').strip("'")
    return result


async def _start_export(job: Job):
    report = job.params.get("report", "")
    default_level = job.params.get("default_level")

    # host + api_key come from .env; program_id is per-export from params
    env = _load_env_vars()
    host = env.get("AIRTASYSTEMS_HOST", "")
    api_key = env.get("AIRTASYSTEMS_API_KEY", "")
    program_id = job.params.get("program_id", "")

    missing = [k for k, v in [("AIRTASYSTEMS_HOST", host), ("AIRTASYSTEMS_API_KEY", api_key), ("program_id", program_id)] if not v]
    if missing:
        job.output.append(f"[!] Missing credentials in .env: {', '.join(missing)}")
        job.status = "failed"
        return

    def _do():
        if str(_root) not in sys.path:
            sys.path.insert(0, str(_root))
        from pipeline.export_airta import export_pipeline_report
        rp = Path(report)
        if not rp.is_absolute():
            rp = _root / rp
        export_pipeline_report(rp, host=host, api_key=api_key, program_id=program_id, default_level=default_level)

    await _run_thread_job(job, _do)


async def _start_clear_cache(job: Job):
    delete_on_server = job.params.get("delete_on_server", False)

    def _do():
        if str(_root) not in sys.path:
            sys.path.insert(0, str(_root))
        gen_tests_dir = str(_root / "generate-tests")
        if gen_tests_dir not in sys.path:
            sys.path.insert(0, gen_tests_dir)

        cleared = []
        try:
            import core as gen_core
            gen_core.clear_gemini_cache(delete_on_server=delete_on_server)
            cleared.append("generator")
        except Exception as exc:
            print(f"[!] Generator cache clear failed: {exc}")

        try:
            import importlib.util
            rla_file = _root / "risk-level-agent" / "risk_level_agent.py"
            if rla_file.exists() and "risk_level_agent" not in sys.modules:
                spec = importlib.util.spec_from_file_location("risk_level_agent", rla_file)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules["risk_level_agent"] = mod
                    spec.loader.exec_module(mod)
            import risk_level_agent as rla
            rla.clear_gemini_cache(delete_on_server=delete_on_server)
            local_removed = rla.clear_local_result_cache()
            cleared.append("risk-level-agent")
            if local_removed:
                print(f"[+] Cleared {local_removed} local risk-assessment result cache file(s).")
        except Exception as exc:
            print(f"[!] Risk-level-agent cache clear failed: {exc}")

        try:
            from pipeline.cleanup import clear_project_pycache

            pycache_removed = clear_project_pycache(_root)
            if pycache_removed:
                print(f"[+] Removed {pycache_removed} __pycache__ director{'y' if pycache_removed == 1 else 'ies'}.")
        except Exception as exc:
            print(f"[!] __pycache__ cleanup failed: {exc}")

        if cleared:
            action = "Cleared in-process + deleted server-side" if delete_on_server else "Cleared in-process"
            print(f"[+] {action} Gemini cache ({', '.join(cleared)}).")
        else:
            print("[-] Nothing was cleared.")

    await _run_thread_job(job, _do)
