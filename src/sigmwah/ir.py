"""Intermediate representation for Wazuh rules produced by WazuhBackend."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal as TypingLiteral


class MatchKind(StrEnum):
    """How a detection atom is expressed in Wazuh XML."""

    PCRE2 = "pcre2"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    KEYWORD = "keyword"
    SAME_FIELD = "same_field"
    SAME_SOURCE_IP = "same_source_ip"
    SAME_USER = "same_user"


@dataclass(frozen=True)
class Literal:
    """One atomic match in a DNF conjunction."""

    field: str | None
    pattern: str
    negate: bool = False
    kind: MatchKind = MatchKind.PCRE2
    case_sensitive: bool = False


@dataclass(frozen=True)
class DNF:
    """Disjunctive normal form: OR of AND-terms of literals."""

    terms: tuple[frozenset[Literal], ...]

    @staticmethod
    def empty() -> DNF:
        return DNF(terms=())

    @staticmethod
    def unit() -> DNF:
        """A tautology: one empty conjunction."""
        return DNF(terms=(frozenset(),))

    @staticmethod
    def atom(literal: Literal) -> DNF:
        return DNF(terms=(frozenset({literal}),))

    def is_empty(self) -> bool:
        return len(self.terms) == 0


@dataclass
class LogsourceEntrySpec:
    """Wazuh entry conditions attached from logsource mapping."""

    if_sid: str | None = None
    if_group: str | None = None
    decoded_as: str | None = None
    program_name: str | None = None
    extra_fields: dict[str, str] = field(default_factory=dict)
    groups: list[str] = field(default_factory=list)
    mapping_id: str = ""


@dataclass
class WazuhRule:
    """One Wazuh <rule> element."""

    rule_id: int
    level: int
    description: str
    if_sid: str | None = None
    if_group: str | None = None
    decoded_as: str | None = None
    program_name: str | None = None
    fields: list[Literal] = field(default_factory=list)
    frequency: int | None = None
    timeframe: int | None = None
    if_matched_sid: str | None = None
    if_matched_group: str | None = None
    same_fields: list[str] = field(default_factory=list)
    same_source_ip: bool = False
    same_user: bool = False
    mitre_ids: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    options: list[str] = field(default_factory=list)
    noalert: bool = False
    sigma_key: str = ""
    warnings: list[str] = field(default_factory=list)


@dataclass
class ConversionItem:
    """Backend output for one Sigma rule (possibly several Wazuh rules)."""

    sigma_id: str
    sigma_title: str
    rules: list[WazuhRule] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    target: TypingLiteral["wazuh4", "wazuh5"] = "wazuh4"
    wazuh5_yaml: str | None = None
