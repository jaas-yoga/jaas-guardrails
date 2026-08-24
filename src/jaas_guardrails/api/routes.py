from __future__ import annotations

import base64

import re2
from fastapi import APIRouter, HTTPException, Request

from jaas_guardrails.api.schemas import (
    FindingResponse,
    GuardrailDefinitionResponse,
    HealthResponse,
    ScanRequest,
    ScanResponse,
    ValidateRuleRequest,
    ValidateRuleResponse,
)
from jaas_guardrails.custom_rules import InvalidCustomRuleError, build_custom_rule, dry_run_compile
from jaas_guardrails.engine import run_guardrails
from jaas_guardrails.models import DependencyInput, GuardrailDefinition, ManifestInput
from jaas_guardrails.regex_engine import UnsafeCustomPatternError

router = APIRouter()


@router.get("/healthz", response_model=HealthResponse)
def healthz(request: Request) -> HealthResponse:
    catalog: list[GuardrailDefinition] = request.app.state.catalog
    return HealthResponse(status="ok", ruleCount=len(catalog))


@router.get("/catalog", response_model=list[GuardrailDefinitionResponse])
def get_catalog(request: Request) -> list[GuardrailDefinitionResponse]:
    catalog: list[GuardrailDefinition] = request.app.state.catalog
    return [
        GuardrailDefinitionResponse(
            id=d.id,
            name=d.name,
            description=d.description,
            category=d.category.value,
            level=int(d.level),
            mandatory=d.mandatory,
            defaultEnabled=d.default_enabled,
            defaultSeverity=d.severity.value,
            standardRef=d.standard_ref,
        )
        for d in catalog
    ]


def _build_custom_rules(body: ScanRequest) -> list[GuardrailDefinition]:
    custom_rules: list[GuardrailDefinition] = []
    errors: list[str] = []
    for item in body.customRules:
        try:
            custom_rules.append(
                build_custom_rule(
                    id=item.id,
                    name=item.name,
                    description=item.description,
                    category=item.category,
                    severity=item.severity,
                    standard_ref=item.standardRef,
                    kind=item.kind,
                    config=item.config,
                )
            )
        except InvalidCustomRuleError as exc:
            errors.append(str(exc))
    if errors:
        raise HTTPException(status_code=400, detail={"invalidCustomRules": errors})
    return custom_rules


@router.post("/scan", response_model=ScanResponse)
def scan(body: ScanRequest, request: Request) -> ScanResponse:
    catalog: list[GuardrailDefinition] = request.app.state.catalog
    custom_rules = _build_custom_rules(body)

    files = {path: base64.b64decode(content) for path, content in body.files.items()}
    manifest = ManifestInput(
        entrypoint=body.manifest.entrypoint,
        runtime_families=tuple(body.manifest.runtimeFamilies),
        contact=body.manifest.contact,
    )
    dependencies: list[DependencyInput] = [
        DependencyInput(id=dep.id, version_constraint=dep.versionConstraint)
        for dep in body.dependencies
    ]

    try:
        result = run_guardrails(
            catalog=catalog,
            files=files,
            manifest=manifest,
            permissions=body.permissions,
            dependencies=dependencies,
            enabled_check_ids=frozenset(body.enabledCheckIds),
            existing_skill_ids=frozenset(body.existingSkillIds),
            custom_rules=tuple(custom_rules),
        )
    except UnsafeCustomPatternError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=400, detail=f"invalid custom rule config: {exc}"
        ) from exc

    def _to_response(finding) -> FindingResponse:
        return FindingResponse(
            checkId=finding.check_id,
            file=finding.file,
            message=finding.message,
            severity=finding.severity.value,
        )

    return ScanResponse(
        blocking=[_to_response(f) for f in result.blocking],
        warnings=[_to_response(f) for f in result.warnings],
    )


@router.post("/validate-rule", response_model=ValidateRuleResponse)
def validate_rule(body: ValidateRuleRequest) -> ValidateRuleResponse:
    """Schema + config + regex-compile check only — no scan, no files
    needed. Lets a UI or CI step give fast feedback while a tenant is
    authoring a custom rule, before it's saved or applied to anything."""
    item = body.rule
    try:
        definition = build_custom_rule(
            id=item.id,
            name=item.name,
            description=item.description,
            category=item.category,
            severity=item.severity,
            standard_ref=item.standardRef,
            kind=item.kind,
            config=item.config,
        )
    except InvalidCustomRuleError as exc:
        return ValidateRuleResponse(valid=False, error=str(exc))

    try:
        dry_run_compile(definition)
    except UnsafeCustomPatternError as exc:
        return ValidateRuleResponse(valid=False, error=str(exc))
    except (KeyError, TypeError, re2.error) as exc:
        return ValidateRuleResponse(
            valid=False, error=f"invalid config for kind '{item.kind}': {exc}"
        )
    return ValidateRuleResponse(valid=True)
