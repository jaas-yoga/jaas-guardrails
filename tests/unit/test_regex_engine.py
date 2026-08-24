import time

import pytest

from jaas_guardrails.regex_engine import UnsafeCustomPatternError, compile_all


def test_trusted_pattern_uses_python_re_and_supports_lookahead():
    # RE2 can't compile this; the trusted path must still work exactly as
    # it always has for catalog rules like unsafe-yaml-load.yaml. "foo" not
    # immediately followed by "bar":
    (pattern,) = compile_all([r"foo(?!bar)"], trusted=True)
    assert pattern.search("foobaz")
    assert not pattern.search("foobar")


def test_trusted_multiline_flag_is_applied():
    (pattern,) = compile_all([r"^bar$"], trusted=True, multiline=True)
    assert pattern.search("foo\nbar\nbaz")


def test_untrusted_pattern_matches_via_re2():
    (pattern,) = compile_all([r"AKIA[0-9A-Z]{16}"], trusted=False)
    assert pattern.search("key=AKIAABCDEFGHIJKLMNOP")
    assert not pattern.search("no secret here")


def test_untrusted_pattern_rejects_lookahead():
    with pytest.raises(UnsafeCustomPatternError):
        compile_all([r"(?!foo)bar"], trusted=False)


def test_untrusted_pattern_rejects_backreference():
    with pytest.raises(UnsafeCustomPatternError):
        compile_all([r"(a)\1"], trusted=False)


def test_untrusted_catastrophic_pattern_does_not_hang():
    """The whole point of routing untrusted patterns through re2: a classic
    ReDoS pattern that would take exponential time under Python's `re`
    against an adversarial input must still complete in well under a
    second here, since RE2 matches in time linear in the input length."""
    (pattern,) = compile_all([r"(a+)+$"], trusted=False)
    adversarial = "a" * 40 + "!"

    start = time.monotonic()
    result = pattern.search(adversarial)
    elapsed = time.monotonic() - start

    assert result is None
    assert elapsed < 1.0
