"""Loads the rule catalog from catalog/ — this repo's own data, not vendored
from anywhere. Fails loudly (RuntimeError) on a malformed catalog rather
than silently skipping a bad file."""

from __future__ import annotations

from pathlib import Path

import yaml

from jaas_guardrails.executors import EXECUTORS_BY_KIND
from jaas_guardrails.models import (
    GuardrailCategory,
    GuardrailDefinition,
    GuardrailLevel,
    GuardrailSeverity,
)

# repo_root/src/jaas_guardrails/catalog_loader.py -> parents[2] = repo_root
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG_DIR = REPO_ROOT / "catalog"

_REQUIRED_KEYS = {
    "id",
    "name",
    "description",
    "category",
    "level",
    "mandatory",
    "default_enabled",
    "severity",
    "standard_ref",
    "kind",
    "config",
}


def load_catalog(catalog_dir: Path = DEFAULT_CATALOG_DIR) -> list[GuardrailDefinition]:
    if not catalog_dir.is_dir():
        raise RuntimeError(f"guardrail catalog not found at '{catalog_dir}'.")

    paths = sorted(catalog_dir.glob("level-*/*.yaml"))
    if not paths:
        raise RuntimeError(f"guardrail catalog at '{catalog_dir}' has no rule files.")

    definitions: list[GuardrailDefinition] = []
    seen_ids: set[str] = set()
    for path in paths:
        data = yaml.safe_load(path.read_text())
        missing = _REQUIRED_KEYS - data.keys()
        if missing:
            raise RuntimeError(f"guardrail rule '{path}' is missing keys: {sorted(missing)}")
        if data["kind"] not in EXECUTORS_BY_KIND:
            raise RuntimeError(f"guardrail rule '{path}' has unknown kind '{data['kind']}'")
        if data["id"] in seen_ids:
            raise RuntimeError(f"guardrail catalog has duplicate id '{data['id']}' (in '{path}')")
        level = GuardrailLevel(data["level"])
        mandatory = bool(data["mandatory"])
        if mandatory and level is not GuardrailLevel.BASELINE:
            raise RuntimeError(f"guardrail rule '{path}' is mandatory but not level 1")
        seen_ids.add(data["id"])
        definitions.append(
            GuardrailDefinition(
                id=data["id"],
                name=data["name"],
                description=data["description"],
                category=GuardrailCategory(data["category"]),
                level=level,
                mandatory=mandatory,
                default_enabled=bool(data["default_enabled"]),
                severity=GuardrailSeverity(data["severity"]),
                standard_ref=data["standard_ref"],
                kind=data["kind"],
                config=data["config"],
            )
        )
    return definitions
