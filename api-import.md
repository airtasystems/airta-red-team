# Deprecated

This document described the legacy **compliance / risk** bulk-import format from the upstream clone.

Use **[api-security-export.md](api-security-export.md)** for the current **security assessment** export:

- **Endpoint:** `POST /api/v2/security-assessments/import`
- **Payload:** `assessment_type`, `results[]` with `severity` and `assessment_reasoning`
