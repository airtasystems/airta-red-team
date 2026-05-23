# AIRTA Black Box — AI Security Red Team

Black-box security testing for **LLMs and LLM-driven applications**, built for **red teams** and **whitehats** (authorized assessments only).

Generate adversarial suites from security playbooks (OWASP LLM, OWASP Agent, MITRE ATLAS, jailbreak, multimodal/file-upload), execute them against live targets via **browser UI or HTTP API**, and assess whether each attack was **exploited or mitigated** with playbook-specific experts and a judge model.

## Who this is for

| Role | Typical workflow |
|------|------------------|
| **Red team** | Map target → discover/auth → generate attacks → run → assess → export findings |
| **Whitehat / pentest** | Same pipeline on customer staging; evidence in `attack_log.json` + `pipeline_report.json` |
| **Appsec / MLsec** | Regression runs per release; compare `category_rollup` across builds |

**Scope:** Observable black-box behavior (prompts, uploads, responses, tool calls in logs)—not source-code SAST. Only test systems you are authorized to assess.

## Prerequisites

1. Copy [`.env.example`](.env.example) → `.env` and set `GEMINI_API_KEY` (generation + assessment).
2. Register the target under `browser-bot/sites/<host>/<component>/` (Connect Target / discover).
3. Optional: `playbooks/company.json` + `playbooks/component.json` or per-site copies for domain-grounded attacks.

## Requirements

- Python 3.10+
- Chromium (for browser-bot). On first run, `start.py` installs Playwright's Chromium automatically.

## Quick start (web UI)

```bash
python start.py
```

Open **http://localhost:8000**. The UI wraps: **generate → discover → run → security-assess → export**.

## Local test target

```bash
python test-target/app.py
```

Run against site `localhost:3000`, component `main`. See [test-target/README.md](test-target/README.md).

## Security playbooks

| Playbook | File | Focus |
|----------|------|--------|
| OWASP LLM | `playbooks/owasp_llm.json` | LLM01–LLM10 |
| OWASP Agent | `playbooks/owasp_agent.json` | ASI01–ASI10 |
| MITRE ATLAS | `playbooks/mitre_attack.json` | ML kill-chain tactics |
| Jailbreak Core | `playbooks/jailbreak_core.json` | DAN, encoding, injection, crescendo |
| ~~Multimodal Injection~~ | `playbooks/multimodal_injection.json` | **Deprecated** — use strategy `multimodal` + a security playbook |

## Artifact delivery (strategy `multimodal`)

**Multimodal is a delivery method, not a separate taxonomy.** Use strategy `multimodal` with any security playbook (`owasp_llm`, `jailbreak_core`, `owasp_agent`, `mitre_attack`). Tests get `vector_type`, benign `prompt`, and `payload` (`generator`, `args`); assessment uses the playbook expert (e.g. OWASP LLM01 for PDF hidden-text cases).

Generate artifacts with [`payloads/`](payloads/README.md). Reference suite (no per-site copies required):

```bash
python scripts/apply_advanced_multimodal_suite.py --playbook owasp_llm --materialize
# → generate-tests/multimodal/owasp-llm.json

python main.py generate --strategy multimodal --playbook owasp_llm
python main.py run generate-tests/multimodal/owasp-llm.json --site HOST --component COMPONENT --assess
```

Discovery supports **file upload** (`type: file` + `path_from: payload`) and API transports **`api_document`** / **`api_multipart`**.

**Run against [DVAIA](README-DVAIA.md)** (external lab):

```bash
python main.py generate --strategy multimodal --playbook owasp_llm --site 127.0.0.1:5000 --component dvaia/document
python main.py run generate-tests/multimodal/owasp-llm.json --site 127.0.0.1:5000 --component dvaia/document --assess
```

`attack_log.json` includes `vector_type` and `artifact_path` for indirect-injection assessment.

## Smoke tests (offline)

```bash
pip install pytest
pytest tests/test_smoke.py -q
```

No API key required for these tests (convert log, payloads, playbook discovery).

## CLI examples

```bash
# Generate attacks (writes under site when --site/--component set)
python main.py generate --strategy zero_shot --playbook owasp_llm \
  --site localhost:3000 --component main
python main.py generate --strategy jailbreak --playbook jailbreak_core
python main.py generate --strategy multimodal --playbook owasp_llm

# Run against target (with assessment)
python main.py run browser-bot/sites/localhost:3000/main/tests/zero-shot/owasp-llm.json \
  --site localhost:3000 --component main --assess

# Security assessment only
python main.py security-assess path/to/attack_log.json
```

## Pipeline

```
generate  →  discover  →  run  →  security-assess  →  export
(playbooks)   (auth)      (browser/API)  (expert+judge)   (AIRTA Systems)
```

Artifacts:

- Suite JSON: `playbook`, `playbook_id`, `categories[].prompts[]` (optional `vector_type`, `payload` per prompt)
- Run log → **`attack_log.json`**
- Assessment → **`pipeline_report.json`** (`category_rollup`, severity per prompt)

## Strategies

| Strategy | Description |
|----------|-------------|
| `zero_shot` | Single-message attacks (detection floor) |
| `multi_shot` | Multi-turn pressure |
| `jailbreak` | Jailbreak-focused techniques |
| `multimodal` | File-upload tests with `vector_type` + payload generators |
| `few_shot`, `iterative`, `chain_of_thought`, etc. | Additional adversarial shaping |

## Configuration

- [`.config`](.config) — `GEMINI_MODEL`, `GEMINI_JUDGE`
- [`.env`](.env) — `GEMINI_API_KEY`, cache toggles
- `browser-bot/sites/<site>/<component>/config.yaml` — UI selectors or `transport: api`

Default playbook: **`owasp_llm`**.

## Project layout

- `start.py` — Bootstrap venv and web UI
- `main.py` — CLI: `generate`, `discover`, `run`, `security-assess`, `export`
- `web/` — FastAPI + SPA
- `generate-tests/` — Attack generation (`core.py`, `strategies/`)
- `browser-bot/` — Playwright runner
- `risk-level-agent/` — Security assessment experts + judge
- `pipeline/` — `convert_log.py`, `security_assess.py`
- `playbooks/` — Security playbooks (OWASP, MITRE, jailbreak, multimodal)
- `test-target/` — Local vulnerable assistant lab
