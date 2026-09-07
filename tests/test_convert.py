from __future__ import annotations

from pathlib import Path

from sigma.collection import SigmaCollection

from sigmwah.config import ConvertSettings
from sigmwah.emit import emit_xml
from sigmwah.service import convert_collection

GOLDEN = Path(__file__).parent / "golden"


def _convert(path: Path, tmp_path: Path) -> str:
    settings = ConvertSettings(
        id_file=tmp_path / ".sigmwah_ids.json",
        id_start=100100,
        id_max=100199,
    )
    collection = SigmaCollection.load_ruleset([path], collect_errors=True)
    items, _report, _alloc = convert_collection(collection, settings)
    docs = emit_xml(items, group_by="single")
    return next(iter(docs.values()))


def test_contains_powershell(tmp_path: Path) -> None:
    xml = _convert(GOLDEN / "01_contains.yml", tmp_path)
    assert 'if_group>sysmon_event1</if_group>' in xml.replace(" ", "") or "<if_group>sysmon_event1</if_group>" in xml
    assert "win.eventdata.image" in xml
    assert "powershell" in xml
    assert "T1059.001" in xml
    assert "Converted with Sigmwah from SigmaHQ (DRL 1.1)" in xml
    assert 'level="6"' in xml


def test_contains_all(tmp_path: Path) -> None:
    xml = _convert(GOLDEN / "02_contains_all.yml", tmp_path)
    assert "Invoke-" in xml
    assert "Bypass" in xml
    assert xml.count("win.eventdata.commandLine") >= 2


def test_regex(tmp_path: Path) -> None:
    xml = _convert(GOLDEN / "03_re.yml", tmp_path)
    assert "cmd" in xml
    assert 'type="pcre2"' in xml


def test_base64(tmp_path: Path) -> None:
    xml = _convert(GOLDEN / "04_base64.yml", tmp_path)
    assert "win.eventdata.commandLine" in xml
    # "Secret" in standard base64 is U2VjcmV0
    assert "U2VjcmV0" in xml


def test_start_end(tmp_path: Path) -> None:
    xml = _convert(GOLDEN / "05_start_end.yml", tmp_path)
    assert "win.eventdata.image" in xml
    assert "win.eventdata.parentImage" in xml
    assert "explorer" in xml.lower() or "explorer.exe" in xml.lower()


def test_not(tmp_path: Path) -> None:
    xml = _convert(GOLDEN / "06_not.yml", tmp_path)
    assert "cmd" in xml
    assert "negate=\"yes\"" in xml


def test_or_dnf_two_rules(tmp_path: Path) -> None:
    xml = _convert(GOLDEN / "07_or_dnf.yml", tmp_path)
    assert xml.count("<rule ") == 2
    assert "evil" in xml
    assert "backdoor" in xml
    assert "T1218" in xml


def test_windows_security(tmp_path: Path) -> None:
    xml = _convert(GOLDEN / "08_security.yml", tmp_path)
    assert "<if_sid>60001</if_sid>" in xml
    assert "4688" in xml
    assert "cmd" in xml


def test_sshd_keywords(tmp_path: Path) -> None:
    xml = _convert(GOLDEN / "09_sshd.yml", tmp_path)
    assert "<if_sid>5700</if_sid>" in xml
    assert "Failed password" in xml or "Invalid user" in xml


def test_event_count_correlation(tmp_path: Path) -> None:
    xml = _convert(GOLDEN / "10_correlation.yml", tmp_path)
    assert 'frequency="5"' in xml
    assert 'timeframe="120"' in xml
    assert "if_matched_sid" in xml


def test_golden_xml_snapshots(tmp_path: Path) -> None:
    """Keep versioned XML next to the YAML inputs."""
    for yaml_path in sorted(GOLDEN.glob("*.yml")):
        xml = _convert(yaml_path, tmp_path / yaml_path.stem)
        expected = yaml_path.with_suffix(".xml")
        if not expected.exists():
            expected.write_text(xml, encoding="utf-8")
        # Compare structure-critical tokens rather than exact ID timestamps.
        got = _normalize(xml)
        want = _normalize(expected.read_text(encoding="utf-8"))
        assert got == want, f"Golden mismatch for {yaml_path.name}"


def _normalize(xml: str) -> str:
    lines = [line.strip() for line in xml.splitlines() if line.strip()]
    return "\n".join(lines)
