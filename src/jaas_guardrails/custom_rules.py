"""Ad-hoc, tenant-authored rules attached to a single /scan request.

Never persisted here — the caller (e.g. jaas_skills) owns storage of
which custom rules exist and which skill(s) they apply to; this service
only validates and executes whatever it's handed on each request, exactly
like it already does for the maintainer-curated catalog, just without the
trust that comes from maintainer review (see regex_engine.py for what
that changes about how a rule's regex gets executed).
"""

from __future__ import annotations

from jaas_guardrails.executors import EXECUTORS_BY_KIND
from jaas_guardrails.models import (
    GuardrailCategory,
    GuardrailDefinition,
    GuardrailLevel,
    GuardrailSeverity,
    ManifestInput,
)


class InvalidCustomRuleError(ValueError):
    """A custom rule's shape or config doesn't check out — id/category/
    severity/kind invalid, or (caught later, at compile time) a config key
    an executor requires is missing. Always a 400, never a 500."""


def build_custom_rule(
    *,
    id: str,
    name: str,
    description: str,
    category: str,
    severity: str,
    standard_ref: str,
    kind: str,
    config: dict,
) -> GuardrailDefinition:
    if not id or not id.strip():
        raise InvalidCustomRuleError("id must not be empty")
    try:
        category_enum = GuardrailCategory(category)
    except ValueError as exc:
        raise InvalidCustomRuleError(
            f"'{id}': unknown category '{category}' "
            f"(must be one of {sorted(c.value for c in GuardrailCategory)})"
        ) from exc
    try:
        severity_enum = GuardrailSeverity(severity)
    except ValueError as exc:
        raise InvalidCustomRuleError(
            f"'{id}': unknown severity '{severity}' (must be BLOCK or WARN)"
        ) from exc
    if kind not in EXECUTORS_BY_KIND:
        raise InvalidCustomRuleError(
            f"'{id}': unknown kind '{kind}' "
            f"(must be one of {sorted(EXECUTORS_BY_KIND)})"
        )
    return GuardrailDefinition(
        id=id,
        name=name,
        description=description,
        category=category_enum,
        # Level/mandatory/default_enabled only mean something for the
        # curated catalog (which level a rule ships at, whether it's
        # force-run) — a custom rule is neither leveled nor mandatory, and
        # always runs because the caller explicitly attached it to this
        # scan. These are never inspected for a custom rule; STANDARD/False
        # are filler values, not a real classification.
        level=GuardrailLevel.STANDARD,
        mandatory=False,
        default_enabled=False,
        severity=severity_enum,
        standard_ref=standard_ref,
        kind=kind,
        config=config,
        trusted=False,
    )


def dry_run_compile(definition: GuardrailDefinition) -> None:
    """Exercises a custom rule's executor against empty input — cheap way
    to catch a bad config shape (missing key, wrong type) or an
    unparseable regex before it's saved or run for real. Raises whatever
    the executor would raise on a real scan (KeyError for a missing config
    key, regex_engine.UnsafeCustomPatternError for bad RE2 syntax, ...);
    callers decide how to present that."""
    executor = EXECUTORS_BY_KIND[definition.kind]
    empty_manifest = ManifestInput(entrypoint="", runtime_families=())
    executor(
        definition=definition,
        files={},
        manifest=empty_manifest,
        permissions=[],
        dependencies=[],
        existing_skill_ids=frozenset(),
    )
