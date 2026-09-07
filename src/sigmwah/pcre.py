"""PCRE2 helpers for Sigma strings, regexes, and CIDR values."""

from __future__ import annotations

import ipaddress
import re

from sigma.types import (
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
)

_METACHAR_ESCAPE = ".*+?^$[](){}\\|"


def sigma_string_to_pcre2(value: SigmaString, *, case_insensitive: bool | None = None) -> str:
    """Convert a SigmaString (with optional wildcards) into a PCRE2 pattern."""
    if case_insensitive is None:
        case_insensitive = not isinstance(value, SigmaCasedString)
    body = value.convert(
        escape_char="\\",
        wildcard_multi=".*",
        wildcard_single=".",
        add_escaped=_METACHAR_ESCAPE,
    )
    if not value.contains_special():
        body = f"^{body}$"
    return _maybe_ci(body, case_insensitive)


def sigma_regex_to_pcre2(value: SigmaRegularExpression) -> str:
    """Pass a Sigma regular expression through as PCRE2, applying flags."""
    body = str(value.regexp)
    prefixes: list[str] = []
    if SigmaRegularExpressionFlag.IGNORECASE in value.flags:
        prefixes.append("i")
    if SigmaRegularExpressionFlag.MULTILINE in value.flags:
        prefixes.append("m")
    if SigmaRegularExpressionFlag.DOTALL in value.flags:
        prefixes.append("s")
    if prefixes:
        return f"(?{''.join(prefixes)}){body}"
    return body


def cidr_to_pcre2(value: SigmaCIDRExpression) -> str:
    """Approximate an IPv4/IPv6 CIDR as a PCRE2 pattern on a string field."""
    network = value.network
    if isinstance(network, ipaddress.IPv6Network):
        # Keep a conservative prefix match; full IPv6 CIDR-to-regex is lossy.
        prefix = str(network.network_address)
        escaped = re.escape(prefix)
        return f"^{escaped}"
    patterns = value.expand(wildcard="*")
    alts: list[str] = []
    for pattern in patterns:
        sigma = SigmaString(pattern)
        alts.append(
            sigma.convert(
                escape_char="\\",
                wildcard_multi=".*",
                wildcard_single=".",
                add_escaped=_METACHAR_ESCAPE,
            )
        )
    if len(alts) == 1:
        body = alts[0]
        if "*" not in patterns[0]:
            body = f"^{body}$"
        return body
    return "^(?:" + "|".join(alts) + ")$"


def join_alternatives(patterns: list[str]) -> str:
    """Join already-converted PCRE2 patterns with a non-capturing alternation."""
    stripped = [_strip_inline_flags(p) for p in patterns]
    ci = all(p.startswith("(?i)") for p in patterns)
    if len(stripped) == 1:
        return patterns[0]
    body = "(?:" + "|".join(stripped) + ")"
    return f"(?i){body}" if ci else body


def _strip_inline_flags(pattern: str) -> str:
    if pattern.startswith("(?i)"):
        return pattern[4:]
    return pattern


def _maybe_ci(body: str, case_insensitive: bool) -> str:
    if case_insensitive and not body.startswith("(?i)"):
        return f"(?i){body}"
    return body


def looks_like_pcre2(pattern: str) -> bool:
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True
