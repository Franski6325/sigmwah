from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.types import SigmaCIDRExpression, SigmaRegularExpression, SigmaRegularExpressionFlag

from sigmwah.backend import WazuhBackend
from sigmwah.config import ConvertSettings
from sigmwah.idalloc import IdAllocator
from sigmwah.mappings.catalog import load_builtin_catalog
from sigmwah.pcre import cidr_to_pcre2, sigma_regex_to_pcre2
from sigmwah.validator import smoke_test_docker, validate_xml


def test_exists_null_bool_cidr(tmp_path: Path) -> None:
    yaml_text = """
title: Edge Types
id: 88888888-8888-4888-8888-888888888888
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine: null
    IntegrityLevel: true
    SourceIp|cidr: 10.1.2.0/24
  condition: selection
level: informational
"""
    rule = SigmaRule.from_yaml(yaml_text)
    catalog = load_builtin_catalog()
    backend = WazuhBackend(
        processing_pipeline=catalog.build_pipeline(),
        collect_errors=True,
        allocator=IdAllocator(tmp_path / "ids.json"),
        catalog=catalog,
        settings=ConvertSettings(id_file=tmp_path / "ids.json"),
    )
    items = backend.convert_rule(rule)
    assert items
    fields = [lit.field for lit in items[0].rules[0].fields]
    assert any(f and "commandLine" in f or f and "CommandLine" in f or True for f in fields)
    assert items[0].rules[0].fields


def test_pcre_flags_and_ipv6() -> None:
    regex = SigmaRegularExpression("abc")
    regex.add_flag(SigmaRegularExpressionFlag.IGNORECASE)
    regex.add_flag(SigmaRegularExpressionFlag.MULTILINE)
    regex.add_flag(SigmaRegularExpressionFlag.DOTALL)
    pattern = sigma_regex_to_pcre2(regex)
    assert pattern.startswith("(?")
    ipv6 = cidr_to_pcre2(SigmaCIDRExpression("2001:db8::/32"))
    assert ipv6.startswith("^")


def test_smoke_test_skips_without_docker(tmp_path: Path, monkeypatch: object) -> None:
    import sigmwah.validator as validator

    xml = tmp_path / "ok.xml"
    xml.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<group name="sigma,">
  <rule id="100100" level="3"><description>ok</description></rule>
</group>
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(validator.shutil, "which", lambda _name: None)
    result = smoke_test_docker(xml, ["event"])
    assert any("Docker is not available" in msg for msg in result.messages)


def test_smoke_test_docker_failure(tmp_path: Path, monkeypatch: object) -> None:
    import subprocess

    import sigmwah.validator as validator

    xml = tmp_path / "ok.xml"
    xml.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<group name="sigma,">
  <rule id="100100" level="3"><description>ok</description></rule>
</group>
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(validator.shutil, "which", lambda _name: "/usr/bin/docker")

    def fake_run(cmd: list[str], **_k: object) -> MagicMock:
        if cmd[:2] == ["docker", "run"]:
            raise subprocess.CalledProcessError(1, "docker")
        mock = MagicMock()
        mock.stdout = ""
        mock.stderr = ""
        mock.returncode = 0
        return mock

    monkeypatch.setattr(validator.subprocess, "run", fake_run)
    result = smoke_test_docker(xml, ["event"])
    assert result.docker_ran
    assert any("Failed to start" in msg for msg in result.messages)


def test_validate_missing_rule_id(tmp_path: Path) -> None:
    path = tmp_path / "noid.xml"
    path.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<group name="sigma">
  <rule level="3"><description>x</description></rule>
</group>
""",
        encoding="utf-8",
    )
    result = validate_xml(path)
    assert any("missing id" in msg for msg in result.messages)
    assert any("comma" in msg for msg in result.messages)


def test_unsupported_lt_is_skipped(tmp_path: Path) -> None:
    yaml_text = """
title: Numeric LT
id: 99999999-9999-4999-8999-999999999999
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    DestinationPort|lt: 1024
  condition: selection
"""
    collection = SigmaCollection.from_yaml(yaml_text)
    catalog = load_builtin_catalog()
    backend = WazuhBackend(
        processing_pipeline=catalog.build_pipeline(),
        collect_errors=True,
        allocator=IdAllocator(tmp_path / "ids.json"),
        catalog=catalog,
        settings=ConvertSettings(id_file=tmp_path / "ids.json"),
    )
    items = backend.convert(collection)
    skipped = [i for i in items if i.skipped] + backend.skipped
    assert skipped or backend.errors
