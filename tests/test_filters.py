from __future__ import annotations

from sigma.rule import SigmaRule

from sigmwah.filters import parse_level_floor, parse_select, rule_passes


def _rule() -> SigmaRule:
    return SigmaRule.from_yaml(
        """
title: Filter Sample
id: 33333333-3333-4333-8333-333333333333
level: high
tags:
  - attack.t1059
  - detection.test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: a.exe
  condition: selection
"""
    )


def test_parse_select_and_level() -> None:
    assert parse_select("product=windows,category=process_creation")["product"] == "windows"
    assert parse_level_floor("medium+") == 2


def test_rule_passes_selectors() -> None:
    rule = _rule()
    assert rule_passes(rule, select={"product": "windows"}, tags=[], exclude_tags=[], level_floor=None)
    assert not rule_passes(rule, select={"product": "linux"}, tags=[], exclude_tags=[], level_floor=None)
    assert rule_passes(rule, select={}, tags=["attack.t1059"], exclude_tags=[], level_floor=None)
    assert not rule_passes(rule, select={}, tags=[], exclude_tags=["detection.test"], level_floor=None)
    assert rule_passes(rule, select={}, tags=[], exclude_tags=[], level_floor=2)
    assert not rule_passes(rule, select={}, tags=[], exclude_tags=[], level_floor=4)
