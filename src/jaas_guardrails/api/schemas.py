"""Request/response models for the public REST API. This is the entire
contract callers integrate against — no shared Python types with any
caller's codebase."""

from __future__ import annotations

from pydantic import BaseModel


class ManifestInputRequest(BaseModel):
    entrypoint: str
    runtimeFamilies: list[str] = []
    contact: str | None = None


class DependencyInputRequest(BaseModel):
    id: str
    versionConstraint: str


class CustomRuleRequest(BaseModel):
    """Ad-hoc, tenant-authored rule — same shape as a catalog entry minus
    the fields that only mean something for the maintainer-curated catalog
    (level, mandatory, defaultEnabled). Never persisted here; validated and
    executed fresh on the request it arrives with. See custom_rules.py."""

    id: str
    name: str
    description: str = ""
    category: str
    severity: str
    standardRef: str = ""
    kind: str
    config: dict = {}


class ScanRequest(BaseModel):
    files: dict[str, str]  # path -> base64-encoded raw bytes
    manifest: ManifestInputRequest
    permissions: list[str] = []
    dependencies: list[DependencyInputRequest] = []
    enabledCheckIds: list[str] = []
    existingSkillIds: list[str] = []
    customRules: list[CustomRuleRequest] = []


class FindingResponse(BaseModel):
    checkId: str
    file: str
    message: str
    severity: str


class ScanResponse(BaseModel):
    blocking: list[FindingResponse]
    warnings: list[FindingResponse]


class GuardrailDefinitionResponse(BaseModel):
    id: str
    name: str
    description: str
    category: str
    level: int
    mandatory: bool
    defaultEnabled: bool
    defaultSeverity: str
    standardRef: str


class HealthResponse(BaseModel):
    status: str
    ruleCount: int


class ValidateRuleRequest(BaseModel):
    rule: CustomRuleRequest


class ValidateRuleResponse(BaseModel):
    valid: bool
    error: str | None = None
