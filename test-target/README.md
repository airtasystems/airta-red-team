# AIRTA Security Lab Target

Local chat app for red-team smoke tests. Serves `/playground` (UI) and HTTP APIs for text and **Gemini multimodal** runs (PDF, image, CSV, audio).

## Start

```bash
python test-target/app.py
```

Open http://localhost:3000/playground

Set `GEMINI_API_KEY` in the project root `.env` so uploads are sent to Gemini for real analysis (same SDK path as the Gemini UI). Without it, text chat uses keyword mocks and file uploads return a configuration hint.

## Multimodal API

| Endpoint | Purpose |
|----------|---------|
| `POST /api/documents/upload` | Multipart `file` → `{ document_id, filename, mime_type, size }` |
| `POST /api/chat` | JSON `{ prompt, document_id? }` or multipart `prompt` + optional `file` |

Supported uploads include PDF, PNG/JPEG/GIF/WebP, CSV, plain text, and common audio formats (MP3, WAV, M4A, AAC, OGG).

## Run AIRTA (text)

```bash
python main.py run browser-bot/sites/localhost:3000/main/tests/zero-shot/owasp-llm.json \
  --site localhost:3000 --component main --assess
```

## Run AIRTA (multimodal)

Generate and materialize artifacts, then run against the local target:

```bash
python main.py generate --strategy multimodal --playbook multimodal_injection \
  --site localhost:3000 --component document

python main.py run browser-bot/sites/localhost:3000/document/tests/multimodal/multimodal-injection.json \
  --site localhost:3000 --component document --assess
```

API transport (upload then chat):

```bash
python main.py run browser-bot/sites/localhost:3000/document/tests/multimodal/multimodal-injection.json \
  --site localhost:3000 --component api-document --assess
```

## Mock behavior

When `GEMINI_API_KEY` is unset, keyword mocks simulate refusals for jailbreak, system-prompt extraction, and secrets probes. File uploads are accepted but not analyzed until Gemini is configured.
