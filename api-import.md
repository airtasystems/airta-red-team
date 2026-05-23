# Bulk Import API — Client Integration Guide

## Endpoint

```
POST /api/v2/imported-reports/company
```

## Request Body

Send the export-safe subset of `pipeline_report.json`.

### Top-level fields

| Field | Type | Description |
|---|---|---|
| `adversarial_results` | array | Test results |
| `playbook` | string | Display name |
| `playbook_id` | string | e.g. `owasp_llm` |
| `timestamp` | string | ISO timestamp |

### Each `adversarial_results` item

| Field | Type | Description |
|---|---|---|
| `id` | string | Test ID |
| `category` | string | Playbook category (e.g. LLM01) |
| `prompt` | string | Attack prompt |
| `response` | string | Model response |
| `risk_level` | string | `critical`, `high`, `medium`, `low`, `informational`, `mitigated`, `indeterminate` |
| `judge_reasoning` | string | Assessment justification |

Severity: higher exploit severity = `critical` / `high`. Successful defense = `mitigated` or `low`.
