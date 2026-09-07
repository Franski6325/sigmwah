"""Sigma 2.0 correlation conversion for Wazuh 4.x frequency rules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sigma.correlations import (
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)
from sigma.exceptions import SigmaConversionError
from sigma.rule import SigmaRule

from sigmwah.ir import ConversionItem, WazuhRule
from sigmwah.mitre import mitre_ids_from_tags

if TYPE_CHECKING:
    from sigmwah.backend import WazuhBackend

_UNSUPPORTED: dict[SigmaCorrelationType, str] = {
    SigmaCorrelationType.VALUE_COUNT: (
        "Wazuh same_field requires the field value to be identical across events; "
        "it cannot count distinct values (Sigma value_count)."
    ),
    SigmaCorrelationType.TEMPORAL: (
        "Wazuh if_matched_group counts how often a group fires, not whether a set of "
        "distinct referenced rules all occurred (unordered temporal)."
    ),
    SigmaCorrelationType.TEMPORAL_ORDERED: (
        "Wazuh cannot express ordered temporal correlation (event A then B then C)."
    ),
    SigmaCorrelationType.VALUE_SUM: "Wazuh has no value-sum aggregator.",
    SigmaCorrelationType.VALUE_AVG: "Wazuh has no value-average aggregator.",
    SigmaCorrelationType.VALUE_PERCENTILE: "Wazuh has no percentile aggregator.",
    SigmaCorrelationType.VALUE_MEDIAN: "Wazuh has no median aggregator.",
}


def unsupported_message(rule: SigmaCorrelationRule) -> str:
    return _UNSUPPORTED.get(
        rule.type,
        f"Correlation type {rule.type} cannot be expressed in Wazuh 4.x XML.",
    )


def convert_event_count(backend: WazuhBackend, rule: SigmaCorrelationRule) -> ConversionItem:
    """Map event_count to frequency/timeframe/if_matched_*."""
    sigma_id = str(rule.id or rule.name or rule.title)
    condition = rule.condition
    op = condition.op
    count = int(condition.count)
    if op == SigmaCorrelationConditionOperator.GT:
        frequency = count + 1
    elif op in {
        SigmaCorrelationConditionOperator.GTE,
        SigmaCorrelationConditionOperator.EQ,
    }:
        frequency = count
    else:
        raise SigmaConversionError(
            rule,
            rule.source,
            f"Wazuh frequency cannot express correlation operator {op.name}.",
        )
    if frequency < 2:
        raise SigmaConversionError(
            rule,
            rule.source,
            "Wazuh frequency rules require frequency >= 2; Sigma event_count "
            f"resolved to {frequency}.",
        )

    referenced_ids: list[int] = []
    warnings: list[str] = []
    for ref in rule.rules or []:
        referenced = ref.rule
        if not isinstance(referenced, SigmaRule):
            warnings.append(f"Referenced rule {ref.reference} is not a Sigma detection rule")
            continue
        try:
            converted = referenced.get_conversion_result()
        except Exception:
            converted = []
        for item in converted:
            if isinstance(item, ConversionItem):
                if item.skipped:
                    warnings.append(
                        f"Referenced rule {item.sigma_id} was skipped: {item.skip_reason}"
                    )
                    continue
                referenced_ids.extend(r.rule_id for r in item.rules)
            elif isinstance(item, WazuhRule):
                referenced_ids.append(item.rule_id)

    if not referenced_ids:
        raise SigmaConversionError(
            rule,
            rule.source,
            "event_count correlation has no converted referenced Wazuh rule IDs.",
        )

    timeframe = max(1, int(rule.timespan.seconds))
    same_fields: list[str] = []
    same_source_ip = False
    same_user = False
    for group_field in rule.group_by or []:
        mapped = backend.catalog.fields.get(group_field, group_field)
        if mapped in {"srcip", "src_ip", "win.eventdata.sourceIp", "win.eventdata.ipAddress"}:
            same_source_ip = True
        elif mapped in {"dstuser", "srcuser", "user", "win.eventdata.user"}:
            same_user = True
        else:
            same_fields.append(mapped)

    corr_group = f"sigma_corr_{_slug(sigma_id)}"
    if_matched_sid: str | None = None
    if_matched_group: str | None = None
    if len(referenced_ids) == 1:
        if_matched_sid = str(referenced_ids[0])
    else:
        if_matched_group = corr_group
        for item in _iter_referenced_items(rule):
            for wazuh_rule in item.rules:
                if corr_group not in wazuh_rule.groups:
                    wazuh_rule.groups.append(corr_group)

    wazuh_id = backend.allocator.allocate(f"{sigma_id}#corr", title=rule.title)
    level = backend.catalog.severity.for_name(
        rule.level.name.lower() if rule.level is not None else None
    )
    xml_rule = WazuhRule(
        rule_id=wazuh_id,
        level=level,
        description=rule.title,
        frequency=frequency,
        timeframe=timeframe,
        if_matched_sid=if_matched_sid,
        if_matched_group=if_matched_group,
        same_fields=same_fields,
        same_source_ip=same_source_ip,
        same_user=same_user,
        mitre_ids=mitre_ids_from_tags(rule.tags),
        groups=["sigma", "correlation", corr_group],
        comments=[backend.attribution(rule)],
        sigma_key=f"{sigma_id}#corr",
        warnings=warnings,
    )
    return ConversionItem(
        sigma_id=sigma_id,
        sigma_title=rule.title,
        rules=[xml_rule],
        warnings=warnings,
    )


def _iter_referenced_items(rule: SigmaCorrelationRule) -> list[ConversionItem]:
    items: list[ConversionItem] = []
    for ref in rule.rules or []:
        referenced = getattr(ref, "rule", None)
        if referenced is None:
            continue
        try:
            converted = referenced.get_conversion_result()
        except Exception:
            continue
        for item in converted:
            if isinstance(item, ConversionItem):
                items.append(item)
    return items


def _slug(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "_" for ch in value).strip("_")[:40]
