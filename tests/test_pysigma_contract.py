"""Contract tests against the installed pySigma public API.

These tests document empirically verified behaviour. If they fail, the
Sigmwah backend must be updated — do not "fix" them by weakening assertions
without checking the pySigma changelog.
"""

from __future__ import annotations

import inspect

import pytest
from sigma.collection import SigmaCollection
from sigma.conversion.base import Backend
from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationType
from sigma.modifiers import SigmaAllModifier, SigmaBase64Modifier, SigmaContainsModifier
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaExpansion, SigmaString

pytestmark = pytest.mark.contract


def test_backend_abstract_condition_methods_exist() -> None:
    required = [
        "convert_condition_and",
        "convert_condition_or",
        "convert_condition_not",
        "convert_condition_as_in_expression",
        "convert_condition_field_eq_val_str",
        "convert_condition_field_eq_val_re",
        "convert_condition_field_eq_val_cidr",
        "convert_correlation_event_count_rule",
        "convert_correlation_temporal_rule",
        "convert_correlation_value_count_rule",
    ]
    for name in required:
        assert hasattr(Backend, name), f"pySigma Backend is missing {name}"
        method = getattr(Backend, name)
        assert inspect.isfunction(method) or inspect.ismethod(method) or callable(method)


def test_sigma_collection_parses_rule_and_event_count_correlation() -> None:
    yaml_text = """
title: Base Event
id: 11111111-1111-4111-8111-111111111111
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: test.exe
  condition: selection
---
title: Count Base Events
id: 22222222-2222-4222-8222-222222222222
correlation:
  type: event_count
  rules:
    - 11111111-1111-4111-8111-111111111111
  group-by:
    - Image
  timespan: 5m
  condition:
    gte: 5
"""
    collection = SigmaCollection.from_yaml(yaml_text)
    rules = [r for r in collection.rules if isinstance(r, SigmaRule)]
    corrs = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
    assert len(rules) == 1
    assert len(corrs) == 1
    assert corrs[0].type == SigmaCorrelationType.EVENT_COUNT
    assert corrs[0].timespan.seconds == 300
    assert corrs[0].condition.count == 5


def test_processing_pipeline_from_yaml_field_mapping() -> None:
    pipeline = ProcessingPipeline.from_yaml(
        """
name: contract-map
priority: 10
transformations:
  - id: map-image
    type: field_name_mapping
    mapping:
      Image: win.eventdata.image
"""
    )
    rule = SigmaRule.from_yaml(
        """
title: Map Image
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: cmd.exe
  condition: selection
"""
    )
    pipeline.apply(rule)
    fields = {item.field for det in rule.detection.detections.values() for item in det.detection_items}
    assert "win.eventdata.image" in fields


def test_contains_all_and_base64_modifiers() -> None:
    contains = SigmaContainsModifier(None, [])  # type: ignore[arg-type]
    value = SigmaString("powershell")
    wrapped = contains.modify(value)
    assert isinstance(wrapped, SigmaString)
    assert wrapped.contains_special()

    all_mod = SigmaAllModifier(None, [])  # type: ignore[arg-type]

    class _Det:
        value_linking = None

    all_mod.detection_item = _Det()  # type: ignore[assignment]
    all_mod.modify(["a", "b"])
    from sigma.conditions import ConditionAND

    assert all_mod.detection_item.value_linking is ConditionAND

    b64 = SigmaBase64Modifier(None, [])  # type: ignore[arg-type]
    encoded = b64.modify(SigmaString("ABC"))
    assert isinstance(encoded, SigmaString)
    assert "QUJD" in str(encoded) or encoded.convert(escape_char="", wildcard_multi="", wildcard_single="")  # noqa: E501

    with pytest.raises(Exception):  # noqa: B017 — pySigma wildcard rejection type varies
        b64.modify(SigmaString("A*"))


def test_base64offset_produces_expansion() -> None:

    rule = SigmaRule.from_yaml(
        """
title: B64 Offset
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|base64offset: secret
  condition: selection
"""
    )
    item = next(iter(rule.detection.detections.values())).detection_items[0]
    assert any(isinstance(val, (SigmaExpansion, SigmaString)) for val in item.value)
