import pytest

from jaas_guardrails.catalog_loader import DEFAULT_CATALOG_DIR, load_catalog
from jaas_guardrails.executors import EXECUTORS_BY_KIND
from jaas_guardrails.models import GuardrailLevel

CATALOG = load_catalog(DEFAULT_CATALOG_DIR)


def test_catalog_has_nineteen_unique_ids():
    ids = [d.id for d in CATALOG]
    assert len(ids) == 19
    assert len(set(ids)) == 19


def test_every_kind_is_a_known_executor():
    for definition in CATALOG:
        assert definition.kind in EXECUTORS_BY_KIND


def test_every_level_is_one_through_four():
    for definition in CATALOG:
        assert definition.level in {
            GuardrailLevel.BASELINE,
            GuardrailLevel.STANDARD,
            GuardrailLevel.ADVANCED,
            GuardrailLevel.REGULATORY,
        }


def test_mandatory_ids_are_exactly_the_baseline_level():
    mandatory_ids = {d.id for d in CATALOG if d.mandatory}
    baseline_ids = {d.id for d in CATALOG if d.level is GuardrailLevel.BASELINE}
    assert mandatory_ids == baseline_ids
    assert mandatory_ids == {"secret-scan", "sensitive-filename-scan", "package-size-limit"}


def test_missing_catalog_dir_raises(tmp_path):
    missing = tmp_path / "does-not-exist"
    with pytest.raises(RuntimeError, match="not found"):
        load_catalog(missing)


def test_empty_catalog_dir_raises(tmp_path):
    empty = tmp_path / "catalog"
    empty.mkdir()
    with pytest.raises(RuntimeError, match="no rule files"):
        load_catalog(empty)
