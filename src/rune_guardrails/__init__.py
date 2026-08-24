"""rune-guardrails: a standalone publish-time content-safety scanning
service. Owns the rule catalog (catalog/) and the engine that executes it,
exposed over its own REST API (src/rune_guardrails/api). No dependency on
any other codebase — callers integrate over HTTP only."""
