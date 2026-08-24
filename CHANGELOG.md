# Changelog

All notable changes are documented here. Versioning follows SemVer: a
MAJOR bump means a breaking change to the catalog (`id` removed/renamed)
or to the HTTP API contract; MINOR adds rules/endpoints or loosens/tightens
a threshold; PATCH is doc/metadata-only.

## 2.1.0 — Custom rules

`POST /scan` accepts an optional `customRules` array — ad-hoc rules a
caller attaches to a single request, restricted to the existing executor
`kind`s (no new code execution path). New `POST /validate-rule` for
dry-run validation while a rule is being authored. All custom-rule regex
now compiles and matches via `re2` instead of Python's `re`, since these
patterns are no longer maintainer-reviewed before they run — closes the
ReDoS (CWE-1333) hole that would otherwise open up. Catalog rules are
unaffected (still `re`, still support lookaround). Nothing about the
existing `/scan`/`/catalog`/`/healthz` contract changed for existing
callers — this is purely additive.

## 2.0.0 — Became a standalone service

Breaking change: this repository is no longer data-only. It now owns the
scanning engine too (`src/jaas_guardrails/`) and exposes it over its own
REST API (`GET /catalog`, `POST /scan`, `GET /healthz`), runs as its own
process on its own port, and has its own test suite and CI. Callers no
longer vendor this repo as a submodule and execute its rules in-process —
they call it over HTTP. The 19-rule catalog itself is unchanged from 1.0.0.

## 1.0.0 — Initial catalog

19 rules across 4 levels:

- **Level 1 — Baseline (mandatory, BLOCK):** secret-scan,
  sensitive-filename-scan, package-size-limit.
- **Level 2 — Standard (default on, WARN):** dangerous-code-patterns,
  unsafe-yaml-load, prompt-injection-heuristics, overbroad-permissions,
  copyleft-license-detected, unpinned-dependency-range.
- **Level 3 — Advanced (opt-in, WARN):** pii-pattern-scan,
  excessive-permission-scope, insecure-embedded-url,
  binary-artifact-present, large-dependency-graph,
  dependency-typosquat-heuristic.
- **Level 4 — Regulatory (opt-in, WARN):** extended-pii-scan,
  export-control-keyword-scan, content-safety-wordlist,
  license-file-missing.
