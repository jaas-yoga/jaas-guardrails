---
name: rune-guardrails-conventions
description: Conventions for the rune-guardrails standalone scanning service (src/rune_guardrails) — the 4-level rule model, executor-kind pattern, offline-only constraint, and how to add a new rule. Use when reading, writing, or reviewing any code under src/rune_guardrails, catalog/, schema/, or tests/ in this repo.
---

# rune-guardrails conventions

Standalone publish-time content-safety scanning service. Own process, own
REST API (`GET /catalog`, `POST /scan`, `GET /healthz`), own test suite. No
dependency on any caller's codebase — see README.md for the full API
contract and the complete executor-kind → config-key table; this file only
covers what a future change needs to know, not the full reference.

## The 4-level model — never blur these

| Level | Directory | Posture | Enforcement |
|---|---|---|---|
| 1 — Baseline | `catalog/level-1-baseline/` | Every publish, no opt-out | BLOCK |
| 2 — Standard | `catalog/level-2-standard/` | On by default, caller may disable | WARN |
| 3 — Advanced | `catalog/level-3-advanced/` | Off by default, opt in | WARN |
| 4 — Regulatory | `catalog/level-4-regulatory/` | Off by default, opt in, lower-confidence | WARN |

Only level 1 entries may set `mandatory: true`. `engine.py`'s
`run_guardrails()` force-runs every mandatory rule regardless of a caller's
`enabledCheckIds` — this is deliberate defense against a caller bug or
malicious `/scan` payload disabling a BLOCK-level check. Never make a
non-mandatory check bypass-proof the same way; that's what makes levels
2-4 genuinely opt-in.

## Executor-kind pattern

`catalog/*/**.yaml`'s `kind` field names a function in `executors.py`,
registered in `EXECUTORS_BY_KIND`. Adding a rule that reuses an existing
`kind` is a data-only change (new YAML file, no code). Adding a new `kind`
means a new function here plus a schema update in
`schema/catalog-entry.schema.json`. `catalog_loader.py` validates every
YAML against that schema and against structural invariants (unique `id`,
known `kind`, `mandatory` only at level 1) at load time — fails loudly with
`RuntimeError`, not silently, on any violation.

## Hard constraints every rule must satisfy

- **Fully offline.** No network calls, no CVE/malware-DB lookups, no
  telemetry. Every rule must be decidable from the package's own files.
- **No ML, no entropy scoring.** Regex, size thresholds, set/count
  arithmetic, local edit-distance (`dependency_typosquat`'s Levenshtein
  check) only.
- **Must not fire on a well-formed, benign package.** Every new rule needs
  a case in `tests/unit/test_executors.py`'s
  `test_golden_package_trips_no_rule_with_everything_enabled` proving it
  stays silent on the golden fixture, in addition to its own
  positive-detection test. This is the regression gate — don't skip it to
  save time; a rule that fires on valid packages makes the whole catalog
  untrustworthy.

## Versioning

Three files must agree: `VERSION`, `pyproject.toml`'s `version`, and
`api/app.py`'s `FastAPI(version=...)`. `CHANGELOG.md` is the SemVer log —
MAJOR for a breaking catalog/API change, MINOR for a new rule/endpoint or
threshold change, PATCH for docs/metadata only. Bump all three version
strings together in the same commit as the `CHANGELOG.md` entry.

## Tests

`tests/unit/` (catalog loader + one class per executor kind) never talks
HTTP — pure function calls. `tests/integration/test_scan_api.py` is the
only place that spins up a real FastAPI `TestClient`; it's what proves the
`/scan` request/response shape callers actually depend on. Don't duplicate
HTTP-shaped assertions into the unit tests or vice versa.

## Deployment

This is a genuinely independent service — its own repo, own CI
(`.github/workflows/`), own Docker image, own release cadence. A caller
(e.g. `rune_skills`) never imports this repo's Python and never caches its
catalog beyond a single request. Don't add anything here that assumes a
specific caller's schema — `ManifestInput`/`DependencyInput` in
`models.py` are deliberately flattened, caller-agnostic shapes, not a
mirror of any particular caller's types.
