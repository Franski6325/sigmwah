from __future__ import annotations

from pathlib import Path

from sigma.collection import SigmaCollection

from sigmwah.config import ConvertSettings
from sigmwah.ir import ConversionItem
from sigmwah.report import ConversionReport
from sigmwah.service import convert_collection, write_outputs


def test_report_markdown(tmp_path: Path) -> None:
    report = ConversionReport()
    report.add(
        ConversionItem(sigma_id="a", sigma_title="A", rules=[], skipped=False, warnings=["w1"])
    )
    report.add(ConversionItem(sigma_id="b", sigma_title="B", skipped=True, skip_reason="nope"))
    text = report.to_markdown()
    assert "Converted: **1**" in text
    assert "Skipped: **1**" in text
    dest = tmp_path / "report.md"
    report.write(dest)
    assert dest.read_text(encoding="utf-8") == text


def test_wazuh5_yaml(tmp_path: Path) -> None:
    rule = tmp_path / "r.yml"
    rule.write_text(
        """
title: Wazuh5 Sample
id: 66666666-6666-4666-8666-666666666666
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: x.exe
  condition: selection
level: low
""",
        encoding="utf-8",
    )
    settings = ConvertSettings(
        target="wazuh5",
        id_file=tmp_path / "ids.json",
        id_start=100100,
        id_max=100110,
    )
    collection = SigmaCollection.load_ruleset([rule], collect_errors=True)
    items, _report, _alloc = convert_collection(collection, settings)
    converted = [item for item in items if not item.skipped]
    assert converted
    assert converted[0].wazuh5_yaml is not None
    assert "Wazuh5 Sample" in converted[0].wazuh5_yaml
    written = write_outputs(converted, tmp_path / "out.yaml", settings)
    assert written
    assert written[0].exists()


def test_unsupported_value_count_is_skipped(tmp_path: Path) -> None:
    path = tmp_path / "corr.yml"
    path.write_text(
        """
title: Base
id: 77777777-7777-4777-8777-777777777771
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: a.exe
  condition: selection
---
title: Value Count
id: 77777777-7777-4777-8777-777777777772
correlation:
  type: value_count
  rules:
    - 77777777-7777-4777-8777-777777777771
  group-by:
    - Image
  timespan: 5m
  condition:
    gte: 3
    field: User
""",
        encoding="utf-8",
    )
    settings = ConvertSettings(id_file=tmp_path / "ids.json")
    collection = SigmaCollection.load_ruleset([path], collect_errors=True)
    items, report, _alloc = convert_collection(collection, settings)
    skipped = [item for item in report.skipped if "Value Count" in item.sigma_title or "value_count" in (item.skip_reason or "").lower() or "distinct" in (item.skip_reason or "").lower()]
    assert skipped or any("value_count" in (item.skip_reason or "") for item in report.skipped)
