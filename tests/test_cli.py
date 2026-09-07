from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from sigmwah.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "sigmwah" in result.stdout.lower()


def test_cli_convert_and_ids(tmp_path: Path) -> None:
    rule = tmp_path / "rule.yml"
    rule.write_text(
        """
title: CLI Sample
id: 44444444-4444-4444-8444-444444444444
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: notepad.exe
  condition: selection
level: low
""",
        encoding="utf-8",
    )
    out = tmp_path / "out.xml"
    ids = tmp_path / "ids.json"
    report = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "convert",
            str(rule),
            "-o",
            str(out),
            "--id-file",
            str(ids),
            "--report",
            str(report),
        ],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert out.exists()
    assert "notepad" in out.read_text(encoding="utf-8").lower() or "win.eventdata.image" in out.read_text(
        encoding="utf-8"
    )
    listed = runner.invoke(app, ["ids", "--id-file", str(ids)])
    assert listed.exit_code == 0
    assert "100100" in listed.stdout
    csv_path = tmp_path / "ids.csv"
    exported = runner.invoke(app, ["ids", "--id-file", str(ids), "--csv", str(csv_path)])
    assert exported.exit_code == 0
    assert csv_path.exists()


def test_cli_validate_xml(tmp_path: Path) -> None:
    xml = tmp_path / "rules.xml"
    xml.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<group name="sigma,">
  <rule id="100100" level="3">
    <description>ok</description>
  </rule>
</group>
""",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["validate", str(xml)])
    assert result.exit_code == 0, result.stdout


def test_cli_dry_run_and_filter(tmp_path: Path) -> None:
    rule = tmp_path / "linux.yml"
    rule.write_text(
        """
title: Linux Only
id: 55555555-5555-4555-8555-555555555555
logsource:
  product: linux
  service: sshd
detection:
  selection:
    - failed
  condition: selection
level: informational
""",
        encoding="utf-8",
    )
    out = tmp_path / "out.xml"
    result = runner.invoke(
        app,
        [
            "convert",
            str(rule),
            "-o",
            str(out),
            "--select",
            "product=windows",
            "--dry-run",
            "--id-file",
            str(tmp_path / "ids.json"),
        ],
    )
    assert result.exit_code == 0
    assert not out.exists()
