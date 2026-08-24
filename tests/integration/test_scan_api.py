import base64

from fastapi.testclient import TestClient

from jaas_guardrails.api.app import create_app


def _client():
    return TestClient(create_app())


def _b64(content: bytes) -> str:
    return base64.b64encode(content).decode("ascii")


def test_healthz():
    resp = _client().get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "ruleCount": 19}


def test_catalog_lists_all_rules():
    resp = _client().get("/catalog")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 19
    baseline = next(item for item in body if item["id"] == "secret-scan")
    assert baseline["level"] == 1
    assert baseline["mandatory"] is True
    assert baseline["defaultSeverity"] == "BLOCK"


def test_scan_blocks_on_mandatory_secret_finding():
    resp = _client().post(
        "/scan",
        json={
            "files": {"manifest.yaml": _b64(b"description: AKIAABCDEFGHIJKLMNOP")},
            "manifest": {"entrypoint": "executor.py", "runtimeFamilies": ["python"]},
            "permissions": [],
            "dependencies": [],
            "enabledCheckIds": [],
            "existingSkillIds": [],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["blocking"]) == 1
    assert body["blocking"][0]["checkId"] == "secret-scan"
    assert body["warnings"] == []


def test_scan_mandatory_checks_run_even_if_not_in_enabled_check_ids():
    """A caller can never disable a mandatory check by simply not naming it —
    the service enforces this itself, not the caller."""
    resp = _client().post(
        "/scan",
        json={
            "files": {".env": _b64(b"SECRET=1")},
            "manifest": {"entrypoint": "executor.py", "runtimeFamilies": ["python"]},
            "permissions": [],
            "dependencies": [],
            "enabledCheckIds": ["pii-pattern-scan"],  # deliberately omits secret-scan
            "existingSkillIds": [],
        },
    )
    body = resp.json()
    assert any(f["checkId"] == "sensitive-filename-scan" for f in body["blocking"])


def test_scan_warn_only_finding_does_not_block():
    resp = _client().post(
        "/scan",
        json={
            "files": {},
            "manifest": {"entrypoint": "executor.py", "runtimeFamilies": ["python"]},
            "permissions": [],
            "dependencies": [{"id": "acme.util.tokenizer", "versionConstraint": "*"}],
            "enabledCheckIds": ["unpinned-dependency-range"],
            "existingSkillIds": [],
        },
    )
    body = resp.json()
    assert body["blocking"] == []
    assert any(f["checkId"] == "unpinned-dependency-range" for f in body["warnings"])


def test_scan_configurable_check_not_enabled_does_not_fire():
    resp = _client().post(
        "/scan",
        json={
            "files": {"README.md": _b64(b"Contact us at someone@example.com")},
            "manifest": {"entrypoint": "executor.py", "runtimeFamilies": ["python"]},
            "permissions": [],
            "dependencies": [],
            "enabledCheckIds": [],  # pii-pattern-scan not enabled
            "existingSkillIds": [],
        },
    )
    body = resp.json()
    assert not any(f["checkId"] == "pii-pattern-scan" for f in body["warnings"])


def _custom_rule(**overrides):
    rule = {
        "id": "custom:tenant-a:no-todo",
        "name": "No TODO",
        "description": "Flags TODO comments.",
        "category": "CODE_SAFETY",
        "severity": "WARN",
        "standardRef": "",
        "kind": "regex_file_scan",
        "config": {"scope": "all_files", "patterns": [{"name": "todo", "regex": "TODO"}]},
    }
    rule.update(overrides)
    return rule


def test_scan_custom_rule_fires_without_being_in_enabled_check_ids():
    """Being present in customRules is itself the opt-in — no separate
    enabledCheckIds entry is needed or possible for a custom rule."""
    resp = _client().post(
        "/scan",
        json={
            "files": {"executor.py": _b64(b"# TODO: finish this")},
            "manifest": {"entrypoint": "executor.py", "runtimeFamilies": ["python"]},
            "permissions": [],
            "dependencies": [],
            "enabledCheckIds": [],
            "existingSkillIds": [],
            "customRules": [_custom_rule()],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["blocking"] == []
    assert any(f["checkId"] == "custom:tenant-a:no-todo" for f in body["warnings"])


def test_scan_custom_rule_can_block():
    resp = _client().post(
        "/scan",
        json={
            "files": {"executor.py": _b64(b"password = 'hardcoded'")},
            "manifest": {"entrypoint": "executor.py", "runtimeFamilies": ["python"]},
            "permissions": [],
            "dependencies": [],
            "enabledCheckIds": [],
            "existingSkillIds": [],
            "customRules": [
                _custom_rule(
                    id="custom:tenant-a:no-hardcoded-password",
                    severity="BLOCK",
                    config={
                        "scope": "all_files",
                        "patterns": [{"name": "pw", "regex": "password = 'hardcoded'"}],
                    },
                )
            ],
        },
    )
    body = resp.json()
    assert any(f["checkId"] == "custom:tenant-a:no-hardcoded-password" for f in body["blocking"])


def test_scan_rejects_invalid_custom_rule_with_400():
    resp = _client().post(
        "/scan",
        json={
            "files": {},
            "manifest": {"entrypoint": "executor.py", "runtimeFamilies": ["python"]},
            "permissions": [],
            "dependencies": [],
            "enabledCheckIds": [],
            "existingSkillIds": [],
            "customRules": [_custom_rule(category="NOT_A_CATEGORY")],
        },
    )
    assert resp.status_code == 400


def test_scan_rejects_custom_rule_with_unsafe_regex_with_400():
    resp = _client().post(
        "/scan",
        json={
            "files": {"executor.py": _b64(b"x")},
            "manifest": {"entrypoint": "executor.py", "runtimeFamilies": ["python"]},
            "permissions": [],
            "dependencies": [],
            "enabledCheckIds": [],
            "existingSkillIds": [],
            "customRules": [
                _custom_rule(
                    config={
                        "scope": "all_files",
                        "patterns": [{"name": "bad", "regex": "(a)\\1"}],
                    }
                )
            ],
        },
    )
    assert resp.status_code == 400


def test_validate_rule_accepts_valid_rule():
    resp = _client().post("/validate-rule", json={"rule": _custom_rule()})
    assert resp.status_code == 200
    assert resp.json() == {"valid": True, "error": None}


def test_validate_rule_rejects_unknown_kind():
    resp = _client().post("/validate-rule", json={"rule": _custom_rule(kind="not_a_kind")})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is False
    assert "not_a_kind" in body["error"]


def test_validate_rule_rejects_missing_config_key():
    resp = _client().post(
        "/validate-rule",
        json={"rule": _custom_rule(config={"scope": "all_files"})},  # missing "patterns"
    )
    body = resp.json()
    assert body["valid"] is False
    assert "invalid config" in body["error"]
