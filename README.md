# jaas-guardrails

A standalone publish-time content-safety scanning **service** — its own
codebase, its own process, its own REST API. It owns both the rule catalog
(data) and the engine that executes it (code), and has **no dependency on
any caller's codebase**, including the
[JAAS Skill Registry](https://github.com/jaas-yoga/jaas-skills).
Callers integrate exclusively over HTTP.

## Running it

```bash
uv sync
./run.sh                 # http://127.0.0.1:8028
```

or via Docker:

```bash
docker build -t jaas-guardrails .
docker run -p 8028:8028 jaas-guardrails
```

`GET /healthz` confirms it's up; `GET /catalog` lists all 19 rules;
`POST /scan` runs them against a package (see "API" below).

## Level model

Rules are organized into four levels, modeled on CIS Benchmark's
Level 1 / Level 2 / STIG tiering and on the same always-on-vs-opt-in split
GitHub uses for secret scanning vs. custom code-scanning rules:

| Level | Directory | Posture | Enforcement |
|---|---|---|---|
| 1 — Baseline | `catalog/level-1-baseline/` | Every publish, no opt-out | BLOCK |
| 2 — Standard | `catalog/level-2-standard/` | On by default; caller may disable individual checks | WARN |
| 3 — Advanced | `catalog/level-3-advanced/` | Off by default; opt in | WARN |
| 4 — Regulatory | `catalog/level-4-regulatory/` | Off by default; opt in; heavier/lower-confidence heuristics | WARN |

Only Level 1 entries may set `mandatory: true`. **The service itself**
force-runs every mandatory rule regardless of what a caller's `/scan`
request asks for — a caller can never disable one by omission or bug, since
the enforcement lives here, next to the catalog, not in the caller.

## Design constraints (why every rule looks the way it does)

- **No network calls.** No CVE/malware-database lookups, no telemetry, no
  external API calls of any kind. Every rule must be evaluable fully
  offline, deterministically, from the package's own files.
- **No ML, no entropy scoring.** Regex, size thresholds, set/count
  arithmetic, and local edit-distance only.
- **Must not fire on a well-formed, benign package.** Every rule is
  checked against a realistic valid-fixture package in this repo's own
  test suite before it ships (`tests/unit/test_executors.py::
  test_golden_package_trips_no_rule_with_everything_enabled`), to keep the
  false-positive rate low enough that WARN-level checks stay useful signal.

## API

### `GET /catalog`

Returns every rule's metadata (id, name, description, category, level,
mandatory, defaultEnabled, defaultSeverity, standardRef) — no auth, static
data.

### `POST /scan`

```json
{
  "files": { "manifest.yaml": "<base64>", "...": "<base64>" },
  "manifest": {
    "entrypoint": "executor.py",
    "runtimeFamilies": ["python"],
    "contact": "team@example.com"
  },
  "permissions": ["fs:read", "network:egress"],
  "dependencies": [{ "id": "acme.util.tokenizer", "versionConstraint": ">=1.0.0,<2.0.0" }],
  "enabledCheckIds": ["pii-pattern-scan"],
  "existingSkillIds": ["acme.util.tokenizer"],
  "customRules": []
}
```

- `files` — every packaged file, base64-encoded raw bytes (byte-exact, so
  size/binary checks work correctly).
- `manifest.contact` — optional; if set, this exact string is stripped out
  of `manifest.yaml`'s text before any PII/secret scan of that file (it's
  a legitimate contact address, not a leak). The service has no other
  knowledge of the caller's manifest schema.
- `enabledCheckIds` — only needs to name the **configurable** checks the
  caller wants on. Mandatory checks always run; don't list them.
- `customRules` — optional, ad-hoc rules the caller wants run on this
  request only (see "Custom rules" below). Being present here *is* the
  opt-in; they're never gated by `enabledCheckIds`.

Returns `{ "blocking": [...], "warnings": [...] }`, each entry
`{ checkId, file, message, severity }`.

### `POST /validate-rule`

`{ "rule": { ...same shape as one customRules entry... } }` → `{ "valid":
true }` or `{ "valid": false, "error": "..." }`. Schema + config + regex
check only — no files, no scan — for fast feedback while a rule is being
authored, before it's saved or applied to anything.

### `GET /healthz`

`{ "status": "ok", "ruleCount": 19 }` — for readiness probes.

## Custom rules

Anyone integrating with this service can attach ad-hoc rules to a single
`/scan` call via `customRules`, using the same shape as a catalog entry
minus the fields that only mean something for the maintainer-curated
catalog (`level`, `mandatory`, `default_enabled`):

```json
{
  "id": "custom:acme:no-internal-hostname",
  "name": "No internal hostname",
  "description": "Flags references to acme's internal DNS suffix.",
  "category": "SUPPLY_CHAIN",
  "severity": "WARN",
  "standardRef": "internal policy",
  "kind": "regex_file_scan",
  "config": { "scope": "all_files", "patterns": [{ "name": "host", "regex": "\\.acme\\.internal\\b" }] }
}
```

Two things are different from a catalog rule, both deliberate:

- **Only the existing `kind`s can be used** — a custom rule can never
  introduce a new executor, i.e. it can never run arbitrary code. This is
  the same boundary Semgrep and gitleaks draw between "rule" and "engine";
  it's what makes it safe to let an untrusted caller define rules at all.
- **Regex in a custom rule is compiled and matched with
  [re2](https://github.com/google/re2)**, not Python's `re`. RE2
  guarantees linear-time matching, so no pattern a caller supplies can
  cause catastrophic backtracking (CWE-1333/ReDoS) — the same mitigation
  GitHub's own secret scanning uses for user-supplied custom patterns.
  This does mean a custom pattern can't use backreferences or
  lookaround (`(?=`, `(?!`, `(?<=`, `(?<!`) — RE2 doesn't support them;
  `/validate-rule` and `/scan` both reject such a pattern with a clear
  `400` rather than silently falling back to backtracking `re`, which
  would reopen the hole this exists to close. Catalog rules are
  unaffected — they're maintainer-reviewed before they ship, so they keep
  using `re` and may use lookaround (two of the 19 do).

This service never persists a custom rule — it validates and executes
whatever arrives with a given request. A caller that wants reusable,
named custom rules (e.g. a multi-tenant caller letting each tenant define
their own) owns that storage itself and resends the relevant rules on
each `/scan` call, the same way it already resends `enabledCheckIds`.

## Rule file shape

One YAML file per rule under `catalog/level-*/`, validated against
`schema/catalog-entry.schema.json`:

```yaml
id: secret-scan
name: Secret Scan
description: >
  Human-readable explanation shown in a caller's UI.
category: SECRET
level: 1
mandatory: true
default_enabled: true
severity: BLOCK
standard_ref: "short citation of the source standard/tool"
kind: regex_file_scan
config: { ... }        # shape depends on `kind`, see below
```

`kind` names an **executor** implemented once in `src/rune_guardrails/
executors.py`; adding a new rule of an existing kind never requires a code
change, only a new YAML file here.

### Executor kinds and their `config` shape

| kind | config keys | used by |
|---|---|---|
| `regex_file_scan` | `scope` (`all_files`\|`entrypoint_only`), optional `gate.runtime_families` + `gate.match` (`exact`\|`contains`), optional `exclude_manifest_field`, `patterns: [{name, regex}]` | secret-scan, dangerous-code-patterns, unsafe-yaml-load, prompt-injection-heuristics, copyleft-license-detected, pii-pattern-scan, insecure-embedded-url, extended-pii-scan, export-control-keyword-scan |
| `filename_pattern_scan` | `match` (`basename`), `patterns: [regex,...]` | sensitive-filename-scan |
| `package_size` | `per_file_limit_bytes`, `total_limit_bytes` | package-size-limit |
| `permission_pair_risk` | `risky_pairs: [[a,b],...]` | overbroad-permissions |
| `permission_count_threshold` | `max_scopes` | excessive-permission-scope |
| `dependency_constraint` | `reject_unbounded`, `upper_bound_operators` | unpinned-dependency-range |
| `dependency_count` | `max_dependencies` | large-dependency-graph |
| `dependency_typosquat` | `max_edit_distance` | dependency-typosquat-heuristic |
| `file_extension_scan` | `rules: [{extension, allowed_runtime_families?}]` | binary-artifact-present |
| `wordlist_scan` | `scope: [filenames]`, `whole_word`, `case_sensitive`, `words` | content-safety-wordlist |
| `file_text_presence` | `filename_patterns`, `fallback_text_file`, `fallback_text_pattern`, `message_if_missing` | license-file-missing |

## Adding a new rule

1. Pick the right level directory.
2. Write a new YAML file matching `schema/catalog-entry.schema.json`.
3. Reuse an existing `kind` if at all possible — a new `kind` means adding
   a function in `executors.py` plus registering it in `EXECUTORS_BY_KIND`.
4. Add a case to `tests/unit/test_executors.py`: a positive-detection case
   and confirm it doesn't fire in
   `test_golden_package_trips_no_rule_with_everything_enabled`.
5. Open a PR — `validate-catalog.yml` lints every file against the schema;
   `ci.yml` runs the full test suite.
6. Once merged, bump `VERSION` (SemVer) and add a `CHANGELOG.md` entry, and
   deploy the new image — this is a real, independently-deployed service,
   so a new rule ships on its own release cadence, not the caller's.

## Explicitly out of scope

Network-call checks (CVE/malware-DB lookups), entropy-based secret
detection, ML-based content moderation, per-check severity overrides (this
catalog's enable/disable axis is per-check, not per-severity), and
persisted per-scan result history (a caller's own audit log is the right
place for that, not this service).

## Repository layout

```
catalog/                  the 19 rules (data)
schema/                   JSON Schema for a rule file
src/rune_guardrails/
  models.py                core dataclasses
  executors.py              one function per `kind`
  catalog_loader.py         parses catalog/ into GuardrailDefinitions
  engine.py                 run_guardrails(): dispatch + mandatory enforcement
  api/
    schemas.py               HTTP request/response Pydantic models
    routes.py                 GET /catalog, POST /scan, GET /healthz
    app.py                     FastAPI app factory
  __main__.py                uvicorn entry point (`rune-guardrails` console script)
tests/
  unit/                      executor + loader tests (offline, in-process)
  integration/               real HTTP-shaped tests via FastAPI's TestClient
```
