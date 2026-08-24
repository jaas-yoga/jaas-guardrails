"""Bounded regex compilation for rules that didn't go through maintainer
review before running — see README.md's "Custom rules" section.

Trusted, maintainer-reviewed catalog rules (everything under catalog/)
keep using Python's `re` module unchanged — a couple of them rely on
lookahead RE2 doesn't support (unsafe-yaml-load.yaml,
insecure-embedded-url.yaml). Untrusted rules — anything arriving as
`customRules` on a /scan request, authored by a tenant and never reviewed
by a maintainer before it runs — are compiled and matched with re2
instead: RE2 guarantees linear-time matching, so no tenant-supplied
pattern can cause catastrophic backtracking (CWE-1333), the same
mitigation GitHub's own secret scanning uses for user-supplied custom
patterns.
"""

from __future__ import annotations

import re
from typing import Protocol

import re2


class UnsafeCustomPatternError(ValueError):
    """A tenant-supplied regex uses syntax re2 can't compile (backreferences,
    lookaround, possessive quantifiers, ...). Rejected outright rather than
    silently falling back to backtracking `re`, which would reopen the
    ReDoS hole this module exists to close. Use an inline flag like '(?m)'
    or '(?i)' instead of a separate flags argument — re2 supports those the
    same way Python's `re` does."""


class _CompiledPattern(Protocol):
    def search(self, text: str) -> object | None: ...


def compile_all(
    patterns: list[str], *, trusted: bool, multiline: bool = False
) -> list[_CompiledPattern]:
    """Compile every pattern once, up front — callers loop over files/
    targets afterward without recompiling per iteration. Trusted and
    untrusted patterns both end up as objects with a `.search(text)`
    method, so call sites don't need to branch on engine."""
    if trusted:
        flags = re.MULTILINE if multiline else 0
        return [re.compile(p, flags) for p in patterns]

    compiled: list[_CompiledPattern] = []
    for pattern in patterns:
        try:
            compiled.append(re2.compile(pattern))
        except re2.error as exc:
            raise UnsafeCustomPatternError(
                f"pattern {pattern!r} is not valid RE2 syntax: {exc}"
            ) from exc
    return compiled
