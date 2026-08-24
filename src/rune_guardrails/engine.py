"""Runs the catalog against one package's content."""

from __future__ import annotations

from dataclasses import dataclass

from rune_guardrails.executors import EXECUTORS_BY_KIND
from rune_guardrails.models import (
    DependencyInput,
    GuardrailDefinition,
    GuardrailFinding,
    GuardrailSeverity,
    ManifestInput,
)


@dataclass(frozen=True)
class GuardrailScanResult:
    blocking: tuple[GuardrailFinding, ...]
    warnings: tuple[GuardrailFinding, ...]


def run_guardrails(
    *,
    catalog: list[GuardrailDefinition],
    files: dict[str, bytes],
    manifest: ManifestInput,
    permissions: list[str],
    dependencies: list[DependencyInput],
    enabled_check_ids: frozenset[str],
    existing_skill_ids: frozenset[str] = frozenset(),
    custom_rules: tuple[GuardrailDefinition, ...] = (),
) -> GuardrailScanResult:
    """`enabled_check_ids` only needs to name the *configurable* checks the
    caller wants on — mandatory (Level 1) checks are force-run here
    regardless of what's passed, so a caller can never accidentally (or
    maliciously) disable one by omission.

    `custom_rules` are ad-hoc, tenant-authored definitions (see
    custom_rules.py) attached to this one request — unlike catalog checks
    they're never gated by `enabled_check_ids`: being present in this list
    *is* the caller opting them in for this scan."""
    blocking: list[GuardrailFinding] = []
    warnings: list[GuardrailFinding] = []

    def _execute(definition: GuardrailDefinition) -> None:
        executor = EXECUTORS_BY_KIND[definition.kind]
        raw_findings = executor(
            definition=definition,
            files=files,
            manifest=manifest,
            permissions=permissions,
            dependencies=dependencies,
            existing_skill_ids=existing_skill_ids,
        )
        findings = [
            GuardrailFinding(
                check_id=definition.id,
                file=raw.file,
                message=raw.message,
                severity=definition.severity,
            )
            for raw in raw_findings
        ]
        target = blocking if definition.severity is GuardrailSeverity.BLOCK else warnings
        target.extend(findings)

    for definition in catalog:
        if not definition.mandatory and definition.id not in enabled_check_ids:
            continue
        _execute(definition)

    for definition in custom_rules:
        _execute(definition)

    return GuardrailScanResult(blocking=tuple(blocking), warnings=tuple(warnings))
