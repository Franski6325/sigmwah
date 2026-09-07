from __future__ import annotations

from pathlib import Path

from sigma.rule.attributes import SigmaRuleTag
from sigma.rule.logsource import SigmaLogSource

from sigmwah.mappings.catalog import load_builtin_catalog, load_user_mappings
from sigmwah.mitre import mitre_ids_from_tags


def test_windows_and_linux_logsource_match() -> None:
    catalog = load_builtin_catalog()
    sysmon = catalog.match_logsource(
        SigmaLogSource(product="windows", category="process_creation")
    )
    assert sysmon is not None
    assert sysmon.if_group == "sysmon_event1"
    security = catalog.match_logsource(
        SigmaLogSource(product="windows", service="security")
    )
    assert security is not None
    assert security.if_sid == "60001"
    sshd = catalog.match_logsource(SigmaLogSource(product="linux", service="sshd"))
    assert sshd is not None
    assert sshd.if_sid == "5700"
    nginx = catalog.match_logsource(SigmaLogSource(product="nginx"))
    assert nginx is not None
    assert nginx.program_name is not None


def test_user_mapping_override(tmp_path: Path) -> None:
    path = tmp_path / "custom.yaml"
    path.write_text(
        """
fields:
  CustomField: win.eventdata.custom
logsources:
  - id: custom-windows
    product: windows
    service: custom
    groups: [sigma, custom]
    entry:
      if_sid: "60000"
""",
        encoding="utf-8",
    )
    catalog = load_builtin_catalog()
    catalog.merge(load_user_mappings(path))
    assert catalog.fields["CustomField"] == "win.eventdata.custom"
    match = catalog.match_logsource(SigmaLogSource(product="windows", service="custom"))
    assert match is not None
    assert match.mapping_id == "custom-windows"


def test_mitre_normalization() -> None:
    tags = [
        SigmaRuleTag.from_str("attack.t1059.001"),
        SigmaRuleTag.from_str("attack.t1059"),
        SigmaRuleTag.from_str("attack.discovery"),
    ]
    ids = mitre_ids_from_tags(tags)
    assert "T1059.001" in ids
    assert "T1059" in ids
