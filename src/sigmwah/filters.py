"""CLI selection filters applied before conversion."""

from __future__ import annotations

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.rule.attributes import SigmaLevel

_LEVEL_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def parse_select(expr: str | None) -> dict[str, str]:
    """Parse ``product=windows`` style selectors into a dict."""
    if not expr:
        return {}
    parts: dict[str, str] = {}
    for chunk in expr.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            raise ValueError(f"Invalid --select fragment {chunk!r}; expected key=value")
        key, value = chunk.split("=", 1)
        parts[key.strip().lower()] = value.strip()
    return parts


def parse_level_floor(expr: str | None) -> int | None:
    """Return the minimum Sigma level index for expressions like ``medium+``."""
    if not expr:
        return None
    text = expr.strip().lower()
    inclusive_plus = text.endswith("+")
    name = text[:-1] if inclusive_plus else text
    if name not in _LEVEL_ORDER:
        raise ValueError(f"Unknown Sigma level {expr!r}")
    return _LEVEL_ORDER[name]


def rule_passes(
    rule: SigmaRule | SigmaCorrelationRule,
    *,
    select: dict[str, str],
    tags: list[str],
    exclude_tags: list[str],
    level_floor: int | None,
) -> bool:
    if select and isinstance(rule, SigmaRule):
        for key, value in select.items():
            actual = getattr(rule.logsource, key, None)
            if actual is None or str(actual).lower() != value.lower():
                return False
    rule_tags = {str(tag).lower() for tag in rule.tags}
    if tags and not any(tag.lower() in rule_tags for tag in tags):
        return False
    if exclude_tags and any(tag.lower() in rule_tags for tag in exclude_tags):
        return False
    if level_floor is not None:
        if rule.level is None:
            return False
        name = _level_name(rule.level)
        if _LEVEL_ORDER.get(name, -1) < level_floor:
            return False
    return True


def _level_name(level: SigmaLevel) -> str:
    return str(level.name).lower()
