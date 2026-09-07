from __future__ import annotations

from pathlib import Path

import pytest

from sigmwah.validator import smoke_test_docker

SYNTHETIC_JSON = (
    '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1",'
    '"channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},'
    '"eventdata":{"image":"C\\\\Windows\\\\System32\\\\notepad.exe",'
    '"commandLine":"notepad.exe"}}}'
)


@pytest.mark.docker
def test_docker_smoke(tmp_path: Path) -> None:
    xml = tmp_path / "rules.xml"
    xml.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<group name="sigma,windows,">
  <rule id="100100" level="3">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)notepad</field>
    <description>Synthetic notepad image</description>
  </rule>
</group>
""",
        encoding="utf-8",
    )
    result = smoke_test_docker(xml, [SYNTHETIC_JSON])
    if not result.docker_ran:
        pytest.skip("Docker is not available")
    assert result.well_formed
