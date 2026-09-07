from __future__ import annotations

import pytest

from sigmwah.dnf import DNF, MAX_DNF_TERMS, DnfTooLargeError, dnf_and, dnf_not, dnf_or
from sigmwah.ir import Literal, MatchKind


def _lit(field: str, value: str) -> Literal:
    return Literal(field=field, pattern=value, kind=MatchKind.PCRE2)


def test_and_or_not() -> None:
    a = DNF.atom(_lit("Image", "a"))
    b = DNF.atom(_lit("CommandLine", "b"))
    both = dnf_and(a, b)
    assert len(both.terms) == 1
    assert len(next(iter(both.terms))) == 2
    either = dnf_or(a, b)
    assert len(either.terms) == 2
    negated = dnf_not(a)
    lit = next(iter(next(iter(negated.terms))))
    assert lit.negate is True


def test_dnf_too_large() -> None:
    terms = [frozenset({_lit("f", str(i))}) for i in range(MAX_DNF_TERMS)]
    big = DNF(terms=tuple(terms))
    extra = DNF.atom(_lit("f", "overflow"))
    with pytest.raises(DnfTooLargeError):
        dnf_or(big, extra)
