from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from sigmwah.cli import app
from sigmwah.exceptions import DownloadError

runner = CliRunner()


def test_cli_ids_empty(tmp_path: Path) -> None:
    result = runner.invoke(app, ["ids", "--id-file", str(tmp_path / "missing.json")])
    assert result.exit_code == 0
    assert "No IDs" in result.stdout


def test_cli_bad_target(tmp_path: Path) -> None:
    rule = tmp_path / "r.yml"
    rule.write_text(
        """
title: x
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: a
  condition: selection
""",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["convert", str(rule), "--target", "nope", "-o", str(tmp_path / "o.xml")])
    assert result.exit_code != 0


def test_cli_download_error(monkeypatch: object, tmp_path: Path) -> None:
    import sigmwah.cli as cli

    def fail(*_a: object, **_k: object) -> None:
        raise DownloadError("boom")

    monkeypatch.setattr(cli, "download_sigmahq", fail)
    result = runner.invoke(app, ["download-sigmahq", "--dest", str(tmp_path)])
    assert result.exit_code == 1


def test_cli_validate_bad(tmp_path: Path) -> None:
    path = tmp_path / "bad.xml"
    path.write_text("<nope>", encoding="utf-8")
    result = runner.invoke(app, ["validate", str(path)])
    assert result.exit_code == 1


def test_cli_strict_skip(tmp_path: Path) -> None:
    rule = tmp_path / "r.yml"
    rule.write_text(
        """
title: Unknown Product
id: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
logsource:
  product: madeup
detection:
  selection:
    Field: value
  condition: selection
""",
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "convert",
            str(rule),
            "-o",
            str(tmp_path / "o.xml"),
            "--id-file",
            str(tmp_path / "ids.json"),
            "--strict",
        ],
    )
    # unknown product warns or skips; strict may exit 2 if skipped
    assert result.exit_code in {0, 2}
