"""MITRE ATT&CK tag normalization."""

from __future__ import annotations

import re

from sigma.rule.attributes import SigmaRuleTag

_TECHNIQUE = re.compile(r"^t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)


def mitre_ids_from_tags(tags: list[SigmaRuleTag]) -> list[str]:
    """Extract and normalize attack.tXXXX(.YYY) tags to MITRE IDs."""
    found: list[str] = []
    for tag in tags:
        if tag.namespace.lower() != "attack":
            continue
        match = _TECHNIQUE.match(tag.name)
        if not match:
            continue
        technique = f"T{match.group(1)}"
        if match.group(2):
            technique = f"{technique}.{match.group(2)}"
        if technique not in found:
            found.append(technique)
    return found
