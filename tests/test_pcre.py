from __future__ import annotations

from sigma.types import SigmaCIDRExpression, SigmaRegularExpression, SigmaString

from sigmwah.pcre import (
    cidr_to_pcre2,
    join_alternatives,
    looks_like_pcre2,
    sigma_regex_to_pcre2,
    sigma_string_to_pcre2,
)


def test_exact_and_wildcard() -> None:
    exact = sigma_string_to_pcre2(SigmaString("cmd.exe"))
    assert exact.startswith("(?i)^")
    assert exact.endswith("$")
    contains = sigma_string_to_pcre2(SigmaString("*powershell*"))
    assert "powershell" in contains
    assert looks_like_pcre2(contains)


def test_regex_and_cidr() -> None:
    regex = sigma_regex_to_pcre2(SigmaRegularExpression(r"foo.+bar"))
    assert "foo.+bar" in regex
    pattern = cidr_to_pcre2(SigmaCIDRExpression("10.0.0.0/24"))
    assert looks_like_pcre2(pattern)
    assert "10" in pattern


def test_join_alternatives() -> None:
    joined = join_alternatives(["(?i)a", "(?i)b"])
    assert joined.startswith("(?i)")
    assert "a" in joined and "b" in joined
