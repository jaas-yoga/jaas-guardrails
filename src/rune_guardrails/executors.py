"""Executors: one function per catalog `kind`. See README.md's kind table.

Every rule in catalog/ declares a `kind` naming one of these functions plus
a `config` dict this function knows how to read. Adding a new rule of an
existing kind never touches this file — only a new YAML file under
catalog/. Adding a genuinely new kind of check does.

Every function shares one signature so engine.py can dispatch uniformly;
each ignores whatever inputs its `kind` doesn't need.
"""

from __future__ import annotations

import re
from pathlib import Path

from rune_guardrails.models import DependencyInput, GuardrailDefinition, ManifestInput, RawFinding
from rune_guardrails.regex_engine import compile_all


def _entrypoint_targets(
    *, files: dict[str, bytes], manifest: ManifestInput, gate: dict | None
) -> dict[str, bytes]:
    if manifest.entrypoint not in files:
        return {}
    if gate is not None:
        allowed = [f.lower() for f in gate.get("runtime_families", [])]
        families = [f.lower() for f in manifest.runtime_families]
        match = gate.get("match", "exact")
        if match == "exact":
            hit = any(f in allowed for f in families)
        else:
            hit = any(a in f for f in families for a in allowed)
        if not hit:
            return {}
    return {manifest.entrypoint: files[manifest.entrypoint]}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def regex_file_scan(
    *,
    definition: GuardrailDefinition,
    files: dict[str, bytes],
    manifest: ManifestInput,
    permissions: list[str],
    dependencies: list[DependencyInput],
    existing_skill_ids: frozenset[str],
) -> list[RawFinding]:
    config = definition.config
    scope = config["scope"]
    if scope == "entrypoint_only":
        targets = _entrypoint_targets(files=files, manifest=manifest, gate=config.get("gate"))
    else:
        targets = files

    exclude_contact = bool(config.get("exclude_manifest_field"))
    pattern_specs = config["patterns"]
    compiled = compile_all(
        [p["regex"] for p in pattern_specs], trusted=definition.trusted, multiline=True
    )
    findings: list[RawFinding] = []
    for path, content in targets.items():
        text = content.decode("utf-8", errors="replace")
        if exclude_contact and path == "manifest.yaml" and manifest.contact:
            text = text.replace(manifest.contact, "")
        for spec, pattern in zip(pattern_specs, compiled, strict=True):
            if pattern.search(text):
                findings.append(
                    RawFinding(
                        file=path,
                        message=f"{definition.name}: pattern '{spec['name']}' matched.",
                    )
                )
    return findings


def filename_pattern_scan(
    *,
    definition: GuardrailDefinition,
    files: dict[str, bytes],
    manifest: ManifestInput,
    permissions: list[str],
    dependencies: list[DependencyInput],
    existing_skill_ids: frozenset[str],
) -> list[RawFinding]:
    patterns = compile_all(definition.config["patterns"], trusted=definition.trusted)
    findings: list[RawFinding] = []
    for path in files:
        base = Path(path).name
        if any(p.search(base) for p in patterns):
            findings.append(
                RawFinding(file=path, message=f"{definition.name}: filename '{base}' is flagged.")
            )
    return findings


def package_size(
    *,
    definition: GuardrailDefinition,
    files: dict[str, bytes],
    manifest: ManifestInput,
    permissions: list[str],
    dependencies: list[DependencyInput],
    existing_skill_ids: frozenset[str],
) -> list[RawFinding]:
    config = definition.config
    per_file_limit = config["per_file_limit_bytes"]
    total_limit = config["total_limit_bytes"]
    findings: list[RawFinding] = []
    total = 0
    for path, content in files.items():
        size = len(content)
        total += size
        if size > per_file_limit:
            findings.append(
                RawFinding(
                    file=path,
                    message=(
                        f"{definition.name}: file is {size} bytes, "
                        f"over the {per_file_limit}-byte per-file limit."
                    ),
                )
            )
    if total > total_limit:
        findings.append(
            RawFinding(
                file="<package>",
                message=(
                    f"{definition.name}: package totals {total} bytes, "
                    f"over the {total_limit}-byte limit."
                ),
            )
        )
    return findings


def permission_pair_risk(
    *,
    definition: GuardrailDefinition,
    files: dict[str, bytes],
    manifest: ManifestInput,
    permissions: list[str],
    dependencies: list[DependencyInput],
    existing_skill_ids: frozenset[str],
) -> list[RawFinding]:
    perm_set = set(permissions)
    findings: list[RawFinding] = []
    for a, b in definition.config["risky_pairs"]:
        if a in perm_set and b in perm_set:
            findings.append(
                RawFinding(
                    file="permissions.yaml",
                    message=f"{definition.name}: requests both '{a}' and '{b}' together.",
                )
            )
    return findings


def permission_count_threshold(
    *,
    definition: GuardrailDefinition,
    files: dict[str, bytes],
    manifest: ManifestInput,
    permissions: list[str],
    dependencies: list[DependencyInput],
    existing_skill_ids: frozenset[str],
) -> list[RawFinding]:
    max_scopes = definition.config["max_scopes"]
    count = len(set(permissions))
    if count > max_scopes:
        return [
            RawFinding(
                file="permissions.yaml",
                message=(
                    f"{definition.name}: requests {count} scopes, "
                    f"over the {max_scopes} guideline."
                ),
            )
        ]
    return []


def dependency_constraint(
    *,
    definition: GuardrailDefinition,
    files: dict[str, bytes],
    manifest: ManifestInput,
    permissions: list[str],
    dependencies: list[DependencyInput],
    existing_skill_ids: frozenset[str],
) -> list[RawFinding]:
    config = definition.config
    upper_bound_ops = config["upper_bound_operators"]
    findings: list[RawFinding] = []
    for dep in dependencies:
        constraint = dep.version_constraint.strip()
        if constraint == "*" or not any(op in constraint for op in upper_bound_ops):
            findings.append(
                RawFinding(
                    file="dependencies.yaml",
                    message=(
                        f"{definition.name}: dependency '{dep.id}' constraint "
                        f"'{dep.version_constraint}' has no upper bound."
                    ),
                )
            )
    return findings


def dependency_count(
    *,
    definition: GuardrailDefinition,
    files: dict[str, bytes],
    manifest: ManifestInput,
    permissions: list[str],
    dependencies: list[DependencyInput],
    existing_skill_ids: frozenset[str],
) -> list[RawFinding]:
    max_deps = definition.config["max_dependencies"]
    if len(dependencies) > max_deps:
        return [
            RawFinding(
                file="dependencies.yaml",
                message=(
                    f"{definition.name}: {len(dependencies)} direct dependencies, "
                    f"over the {max_deps} guideline."
                ),
            )
        ]
    return []


def dependency_typosquat(
    *,
    definition: GuardrailDefinition,
    files: dict[str, bytes],
    manifest: ManifestInput,
    permissions: list[str],
    dependencies: list[DependencyInput],
    existing_skill_ids: frozenset[str],
) -> list[RawFinding]:
    max_distance = definition.config["max_edit_distance"]
    findings: list[RawFinding] = []
    for dep in dependencies:
        for existing_id in existing_skill_ids:
            if existing_id == dep.id:
                continue
            if _levenshtein(dep.id, existing_id) <= max_distance:
                findings.append(
                    RawFinding(
                        file="dependencies.yaml",
                        message=(
                            f"{definition.name}: dependency '{dep.id}' closely resembles "
                            f"existing skill '{existing_id}' — check for a typo."
                        ),
                    )
                )
    return findings


def file_extension_scan(
    *,
    definition: GuardrailDefinition,
    files: dict[str, bytes],
    manifest: ManifestInput,
    permissions: list[str],
    dependencies: list[DependencyInput],
    existing_skill_ids: frozenset[str],
) -> list[RawFinding]:
    families = {f.lower() for f in manifest.runtime_families}
    findings: list[RawFinding] = []
    for rule in definition.config["rules"]:
        extension = rule["extension"]
        allowed = {f.lower() for f in rule.get("allowed_runtime_families", [])}
        if allowed and (families & allowed):
            continue
        for path in files:
            if path.endswith(extension):
                findings.append(
                    RawFinding(
                        file=path,
                        message=f"{definition.name}: packaged binary artifact ('{extension}').",
                    )
                )
    return findings


def wordlist_scan(
    *,
    definition: GuardrailDefinition,
    files: dict[str, bytes],
    manifest: ManifestInput,
    permissions: list[str],
    dependencies: list[DependencyInput],
    existing_skill_ids: frozenset[str],
) -> list[RawFinding]:
    config = definition.config
    flags = 0 if config.get("case_sensitive") else re.IGNORECASE
    whole_word = config.get("whole_word", True)
    findings: list[RawFinding] = []
    for fname in config["scope"]:
        content = files.get(fname)
        if content is None:
            continue
        text = content.decode("utf-8", errors="replace")
        for word in config["words"]:
            pattern = rf"\b{re.escape(word)}\b" if whole_word else re.escape(word)
            if re.search(pattern, text, flags):
                findings.append(
                    RawFinding(file=fname, message=f"{definition.name}: flagged word '{word}'.")
                )
    return findings


def file_text_presence(
    *,
    definition: GuardrailDefinition,
    files: dict[str, bytes],
    manifest: ManifestInput,
    permissions: list[str],
    dependencies: list[DependencyInput],
    existing_skill_ids: frozenset[str],
) -> list[RawFinding]:
    config = definition.config
    filename_patterns = compile_all(config["filename_patterns"], trusted=definition.trusted)
    found = any(p.search(Path(path).name) for path in files for p in filename_patterns)
    if not found:
        fallback_file = config.get("fallback_text_file")
        fallback_content = files.get(fallback_file) if fallback_file else None
        if fallback_content is not None:
            text = fallback_content.decode("utf-8", errors="replace")
            fallback_pattern = compile_all(
                [config["fallback_text_pattern"]], trusted=definition.trusted
            )[0]
            if fallback_pattern.search(text):
                found = True
    if found:
        return []
    return [
        RawFinding(
            file=config.get("fallback_text_file", "<package>"),
            message=config["message_if_missing"],
        )
    ]


EXECUTORS_BY_KIND = {
    "regex_file_scan": regex_file_scan,
    "filename_pattern_scan": filename_pattern_scan,
    "package_size": package_size,
    "permission_pair_risk": permission_pair_risk,
    "permission_count_threshold": permission_count_threshold,
    "dependency_constraint": dependency_constraint,
    "dependency_count": dependency_count,
    "dependency_typosquat": dependency_typosquat,
    "file_extension_scan": file_extension_scan,
    "wordlist_scan": wordlist_scan,
    "file_text_presence": file_text_presence,
}
