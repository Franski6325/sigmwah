"""Disjunctive normal form helpers for Sigma condition trees."""

from __future__ import annotations

from itertools import product

from sigmwah.ir import DNF, Literal

# Wazuh cannot reasonably host an unbounded cartesian product of OR branches.
MAX_DNF_TERMS = 32


class DnfTooLargeError(ValueError):
    """Raised when DNF expansion exceeds MAX_DNF_TERMS."""


def dnf_and(left: DNF, right: DNF) -> DNF:
    if left.is_empty() or right.is_empty():
        return DNF.empty()
    terms: list[frozenset[Literal]] = []
    for a, b in product(left.terms, right.terms):
        terms.append(a | b)
    return _bounded(tuple(terms))


def dnf_and_all(parts: list[DNF]) -> DNF:
    acc = DNF.unit()
    for part in parts:
        acc = dnf_and(acc, part)
    return acc


def dnf_or(left: DNF, right: DNF) -> DNF:
    if left.is_empty():
        return right
    if right.is_empty():
        return left
    merged = list(left.terms)
    for term in right.terms:
        if term not in merged:
            merged.append(term)
    return _bounded(tuple(merged))


def dnf_or_all(parts: list[DNF]) -> DNF:
    acc = DNF.empty()
    for part in parts:
        acc = dnf_or(acc, part)
    return acc


def dnf_not(inner: DNF) -> DNF:
    """Negate a DNF via De Morgan. Empty DNF (false) becomes a tautology."""
    if inner.is_empty():
        return DNF.unit()
    negated_terms: list[DNF] = []
    for term in inner.terms:
        if not term:
            return DNF.empty()
        lits = [DNF.atom(_negate_literal(lit)) for lit in term]
        negated_terms.append(dnf_or_all(lits))
    return dnf_and_all(negated_terms)


def _negate_literal(lit: Literal) -> Literal:
    return Literal(
        field=lit.field,
        pattern=lit.pattern,
        negate=not lit.negate,
        kind=lit.kind,
        case_sensitive=lit.case_sensitive,
    )


def _bounded(terms: tuple[frozenset[Literal], ...]) -> DNF:
    if len(terms) > MAX_DNF_TERMS:
        raise DnfTooLargeError(
            f"DNF expansion produced {len(terms)} terms (max {MAX_DNF_TERMS})"
        )
    return DNF(terms=terms)
