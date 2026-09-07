from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from sigmwah.config import ConvertSettings, SeverityMap
from sigmwah.emit import emit_xml
from sigmwah.exceptions import MappingError
from sigmwah.filters import parse_select
from sigmwah.ir import ConversionItem, Literal, MatchKind, WazuhRule
from sigmwah.mappings.catalog import load_user_mappings
from sigmwah.pcre import looks_like_pcre2
from sigmwah.pipelines import wazuh_pipeline
from sigmwah.service import write_outputs
from sigmwah.validator import validate_xml


def test_pipeline_has_items() -> None:
    pipeline = wazuh_pipeline()
    assert pipeline.name == "sigmwah-default"
    assert pipeline.items


def test_emit_per_rule_and_per_group() -> None:
    rule = WazuhRule(
        rule_id=100100,
        level=6,
        description="d",
        groups=["sigma", "windows"],
        fields=[Literal(field="win.eventdata.image", pattern="a", kind=MatchKind.PCRE2)],
        comments=["Converted with Sigmwah from SigmaHQ (DRL 1.1)"],
        sigma_key="abc#0",
    )
    item = ConversionItem(sigma_id="abc", sigma_title="d", rules=[rule])
    per_rule = emit_xml([item], group_by="per-rule")
    assert "abc" in next(iter(per_rule))
    per_group = emit_xml([item], group_by="per-group")
    assert "windows" in per_group or "sigma" in per_group


def test_write_outputs_per_rule(tmp_path: Path) -> None:
    rule = WazuhRule(rule_id=100100, level=3, description="d", groups=["sigma"], sigma_key="x#0")
    item = ConversionItem(sigma_id="x", sigma_title="d", rules=[rule])
    settings = ConvertSettings(output_format="per-rule", id_file=tmp_path / "ids.json")
    written = write_outputs([item], tmp_path / "out", settings)
    assert written
    assert written[0].exists()


def test_severity_and_id_validators() -> None:
    with pytest.raises(ValidationError):
        SeverityMap(medium=99)
    with pytest.raises(ValidationError):
        ConvertSettings(id_start=10)


def test_parse_select_rejects_junk() -> None:
    with pytest.raises(ValueError):
        parse_select("windows")


def test_invalid_mapping_yaml(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("- just a list\n", encoding="utf-8")
    with pytest.raises(MappingError):
        load_user_mappings(path)


def test_pcre_invalid() -> None:
    assert looks_like_pcre2("(") is False


def test_validate_multiple_groups(tmp_path: Path) -> None:
    path = tmp_path / "multi.xml"
    path.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<group name="sigma,">
  <rule id="100100" level="3"><description>a</description></rule>
</group>
<group name="sigma,linux,">
  <rule id="100101" level="4"><description>b</description></rule>
</group>
""",
        encoding="utf-8",
    )
    result = validate_xml(path)
    assert result.well_formed
