import pytest

from jaas_guardrails.custom_rules import InvalidCustomRuleError, build_custom_rule, dry_run_compile
from jaas_guardrails.regex_engine import UnsafeCustomPatternError


def _rule(**overrides):
    base = dict(
        id="custom:tenant-a:no-foo",
        name="No foo",
        description="Flags the word foo.",
        category="CODE_SAFETY",
        severity="WARN",
        standard_ref="",
        kind="regex_file_scan",
        config={"scope": "all_files", "patterns": [{"name": "foo", "regex": "foo"}]},
    )
    base.update(overrides)
    return build_custom_rule(**base)


def test_build_custom_rule_valid():
    definition = _rule()
    assert definition.id == "custom:tenant-a:no-foo"
    assert definition.trusted is False
    assert definition.mandatory is False


def test_build_custom_rule_rejects_empty_id():
    with pytest.raises(InvalidCustomRuleError):
        _rule(id="")


def test_build_custom_rule_rejects_unknown_category():
    with pytest.raises(InvalidCustomRuleError):
        _rule(category="NOT_A_CATEGORY")


def test_build_custom_rule_rejects_unknown_severity():
    with pytest.raises(InvalidCustomRuleError):
        _rule(severity="CRITICAL")


def test_build_custom_rule_rejects_unknown_kind():
    with pytest.raises(InvalidCustomRuleError):
        _rule(kind="not_a_real_kind")


def test_dry_run_compile_accepts_valid_rule():
    dry_run_compile(_rule())  # must not raise


def test_dry_run_compile_rejects_bad_regex_syntax():
    bad_pattern = {"name": "x", "regex": "(a)\\1"}
    definition = _rule(config={"scope": "all_files", "patterns": [bad_pattern]})
    with pytest.raises(UnsafeCustomPatternError):
        dry_run_compile(definition)


def test_dry_run_compile_rejects_missing_config_key():
    definition = _rule(config={"scope": "all_files"})  # missing "patterns"
    with pytest.raises(KeyError):
        dry_run_compile(definition)
