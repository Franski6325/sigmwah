from __future__ import annotations

from pathlib import Path

from sigmwah.validator import validate_xml


def test_validate_ok(tmp_path: Path) -> None:
    path = tmp_path / "ok.xml"
    path.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<group name="sigma,windows,">
  <rule id="100100" level="6">
    <description>ok</description>
  </rule>
</group>
""",
        encoding="utf-8",
    )
    result = validate_xml(path)
    assert result.well_formed
    assert not any("not well-formed" in msg for msg in result.messages)


def test_validate_bad_xml(tmp_path: Path) -> None:
    path = tmp_path / "bad.xml"
    path.write_text("<group><rule></group>", encoding="utf-8")
    result = validate_xml(path)
    assert not result.well_formed


def test_validate_duplicate_ids(tmp_path: Path) -> None:
    path = tmp_path / "dup.xml"
    path.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<group name="sigma,">
  <rule id="100100" level="3"><description>a</description></rule>
  <rule id="100100" level="4"><description>b</description></rule>
</group>
""",
        encoding="utf-8",
    )
    result = validate_xml(path)
    assert any("Duplicate" in msg for msg in result.messages)
