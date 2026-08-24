"""Core data model. See README.md for the level/category model."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum


class GuardrailSeverity(StrEnum):
    BLOCK = "BLOCK"
    WARN = "WARN"


class GuardrailLevel(IntEnum):
    BASELINE = 1
    STANDARD = 2
    ADVANCED = 3
    REGULATORY = 4


class GuardrailCategory(StrEnum):
    SECRET = "SECRET"
    SIZE = "SIZE"
    CODE_SAFETY = "CODE_SAFETY"
    PROMPT_SAFETY = "PROMPT_SAFETY"
    PERMISSIONS = "PERMISSIONS"
    LICENSING = "LICENSING"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    PRIVACY = "PRIVACY"
    COMPLIANCE = "COMPLIANCE"
    CONTENT_SAFETY = "CONTENT_SAFETY"


@dataclass(frozen=True)
class GuardrailDefinition:
    id: str
    name: str
    description: str
    category: GuardrailCategory
    level: GuardrailLevel
    mandatory: bool
    default_enabled: bool
    severity: GuardrailSeverity
    standard_ref: str
    kind: str
    config: dict
    # True for every catalog/ entry (maintainer-reviewed before it ships —
    # see catalog_loader.py, which never sets this, so it keeps the
    # default). False for an ad-hoc rule built by custom_rules.py from a
    # /scan request's `customRules` — a tenant-authored pattern nobody
    # but that tenant has ever seen. Regex-bearing executors dispatch on
    # this to choose the matching engine (see regex_engine.py); nothing
    # else in the system reads it.
    trusted: bool = True


@dataclass(frozen=True)
class ManifestInput:
    """Everything an executor needs from the caller's manifest — flattened
    and minimal on purpose. The caller owns its own manifest schema; this
    service never parses or depends on it beyond these three fields."""

    entrypoint: str
    runtime_families: tuple[str, ...]
    contact: str | None = None


@dataclass(frozen=True)
class DependencyInput:
    id: str
    version_constraint: str


@dataclass(frozen=True)
class RawFinding:
    file: str
    message: str


@dataclass(frozen=True)
class GuardrailFinding:
    check_id: str
    file: str
    message: str
    severity: GuardrailSeverity
