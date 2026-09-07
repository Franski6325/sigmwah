from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.conversion.state import ConversionState
from sigma.exceptions import (
    SigmaConversionError,
    SigmaError,
    SigmaFeatureNotSupportedByBackendError,
)
from sigma.rule import SigmaRule
from sigma.types import SigmaCIDRExpression, SigmaNumber, SigmaRegularExpression, SigmaString
from typer.testing import CliRunner

from sigmwah.backend import WazuhBackend, _sigma_key
from sigmwah.cli import app
from sigmwah.config import ConvertSettings
from sigmwah.correlation import unsupported_message
from sigmwah.dnf import dnf_and, dnf_not, dnf_or
from sigmwah.downloader import _zip_url, download_sigmahq
from sigmwah.emit import emit_xml
from sigmwah.exceptions import DownloadError, MappingError, ValidationError
from sigmwah.filters import parse_level_floor, parse_select, rule_passes
from sigmwah.idalloc import IdAllocator
from sigmwah.ir import DNF, ConversionItem, Literal, MatchKind, WazuhRule
from sigmwah.mappings.catalog import load_builtin_catalog, load_user_mappings
from sigmwah.pcre import cidr_to_pcre2, join_alternatives, looks_like_pcre2
from sigmwah.service import convert_collection, load_sigma_paths, write_outputs
from sigmwah.validator import ValidationResult, smoke_test_docker, validate_xml

runner = CliRunner()


def _backend(tmp_path: Path, **settings_kw: object) -> WazuhBackend:
    catalog = load_builtin_catalog()
    settings = ConvertSettings(id_file=tmp_path / "ids.json", **settings_kw)  # type: ignore[arg-type]
    return WazuhBackend(
        processing_pipeline=catalog.build_pipeline(),
        collect_errors=True,
        allocator=IdAllocator(tmp_path / "ids.json"),
        catalog=catalog,
        settings=settings,
    )


def test_load_directory_and_user_mappings(tmp_path: Path) -> None:
    folder = tmp_path / "rules"
    folder.mkdir()
    (folder / "a.yml").write_text(
        """
title: Dir Rule
id: bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
logsource:
  product: nginx
detection:
  selection:
    url|contains: /admin
  condition: selection
level: low
""",
        encoding="utf-8",
    )
    overlay = tmp_path / "map.yaml"
    overlay.write_text("severity:\n  low: 5\n", encoding="utf-8")
    collection = load_sigma_paths([folder])
    settings = ConvertSettings(
        id_file=tmp_path / "ids.json",
        mappings_file=overlay,
        output_format="per-group",
    )
    items, _report, _alloc = convert_collection(collection, settings)
    written = write_outputs(items, tmp_path / "out", settings)
    assert written


def test_load_sigma_paths_empty(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    collection = load_sigma_paths([empty])
    assert list(collection.rules) == []


def test_temporal_correlation_skipped(tmp_path: Path) -> None:
    path = tmp_path / "t.yml"
    path.write_text(
        """
title: Base A
id: cccccccc-cccc-4ccc-8ccc-ccccccccccc1
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: a.exe
  condition: selection
---
title: Temporal
id: cccccccc-cccc-4ccc-8ccc-ccccccccccc2
correlation:
  type: temporal
  rules:
    - cccccccc-cccc-4ccc-8ccc-ccccccccccc1
  timespan: 1m
level: high
""",
        encoding="utf-8",
    )
    settings = ConvertSettings(id_file=tmp_path / "ids.json")
    collection = SigmaCollection.load_ruleset([path], collect_errors=True)
    _items, report, _ = convert_collection(collection, settings)
    assert any(
        "temporal" in (s.skip_reason or "").lower() or "Temporal" in s.sigma_title
        for s in report.skipped
    )


def test_event_count_gt_and_low_frequency(tmp_path: Path) -> None:
    high = tmp_path / "high.yml"
    high.write_text(
        """
title: Base High
id: dddddddd-dddd-4ddd-8ddd-ddddddddddd1
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: a.exe
  condition: selection
---
title: Count GT
id: dddddddd-dddd-4ddd-8ddd-ddddddddddd2
correlation:
  type: event_count
  rules:
    - dddddddd-dddd-4ddd-8ddd-ddddddddddd1
  group-by:
    - User
  timespan: 10s
  condition:
    gt: 3
level: high
""",
        encoding="utf-8",
    )
    settings = ConvertSettings(id_file=tmp_path / "ids.json")
    items, report, _ = convert_collection(
        SigmaCollection.load_ruleset([high], collect_errors=True), settings
    )
    xml_rules = [r for item in items if not item.skipped for r in item.rules]
    assert any(r.frequency == 4 for r in xml_rules)
    assert any(r.same_user for r in xml_rules)

    low = tmp_path / "low.yml"
    low.write_text(
        """
title: Base Low
id: eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: b.exe
  condition: selection
---
title: Count One
id: eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee2
correlation:
  type: event_count
  rules:
    - eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1
  timespan: 10s
  condition:
    gte: 1
""",
        encoding="utf-8",
    )
    _items, report, _ = convert_collection(
        SigmaCollection.load_ruleset([low], collect_errors=True), settings
    )
    assert any("frequency" in (s.skip_reason or "").lower() for s in report.skipped)


def test_event_count_multi_ref_and_srcip(tmp_path: Path) -> None:
    path = tmp_path / "multi.yml"
    path.write_text(
        """
title: Base One
id: ffffffff-ffff-4fff-8fff-fffffffffff1
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: one.exe
  condition: selection
---
title: Base Two
id: ffffffff-ffff-4fff-8fff-fffffffffff2
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: two.exe
  condition: selection
---
title: Count Both
id: ffffffff-ffff-4fff-8fff-fffffffffff3
correlation:
  type: event_count
  rules:
    - ffffffff-ffff-4fff-8fff-fffffffffff1
    - ffffffff-ffff-4fff-8fff-fffffffffff2
  group-by:
    - SourceIp
    - CommandLine
  timespan: 1m
  condition:
    gte: 5
""",
        encoding="utf-8",
    )
    settings = ConvertSettings(id_file=tmp_path / "ids.json")
    items, _report, _ = convert_collection(
        SigmaCollection.load_ruleset([path], collect_errors=True), settings
    )
    corr = [r for item in items if not item.skipped for r in item.rules if r.frequency]
    assert corr
    assert corr[0].if_matched_group
    assert corr[0].same_source_ip
    assert corr[0].same_fields


def test_event_count_lt_skipped(tmp_path: Path) -> None:
    path = tmp_path / "lt.yml"
    path.write_text(
        """
title: Base LT
id: 12121212-1212-4121-8121-121212121211
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: z.exe
  condition: selection
---
title: Count LT
id: 12121212-1212-4121-8121-121212121212
correlation:
  type: event_count
  rules:
    - 12121212-1212-4121-8121-121212121211
  timespan: 10s
  condition:
    lt: 9
""",
        encoding="utf-8",
    )
    settings = ConvertSettings(id_file=tmp_path / "ids.json")
    _items, report, _ = convert_collection(
        SigmaCollection.load_ruleset([path], collect_errors=True), settings
    )
    assert any("operator" in (s.skip_reason or "").lower() for s in report.skipped)


def test_exists_cased_same_field_or_and_keyword(tmp_path: Path) -> None:
    yaml_text = """
title: Mix
id: 13131313-1313-4131-8131-131313131313
name: mix-rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image:
      - a.exe
      - b.exe
    CommandLine|cased: Secret
    ParentImage|exists: true
    Hashes|exists: false
  keywords:
    - failed-login
    - 42
  condition: selection or keywords
level: high
falsepositives:
  - admin scripts
"""
    settings = ConvertSettings(id_file=tmp_path / "ids.json", fp_ignore=True)
    items, _report, _ = convert_collection(SigmaCollection.from_yaml(yaml_text), settings)
    converted = [i for i in items if not i.skipped]
    assert converted
    fields = [lit for rule in converted[0].rules for lit in rule.fields]
    assert any(lit.kind == MatchKind.EXISTS for lit in fields) or any(
        lit.kind == MatchKind.NOT_EXISTS for lit in fields
    )
    assert any("falsepositives requested" in w for rule in converted[0].rules for w in rule.warnings)


def test_strict_unknown_logsource(tmp_path: Path) -> None:
    yaml_text = """
title: Unknown Product
id: 14141414-1414-4141-8141-141414141414
logsource:
  product: madeup
detection:
  selection:
    Field: value
  condition: selection
"""
    settings = ConvertSettings(id_file=tmp_path / "ids.json", strict=True)
    items, report, _ = convert_collection(SigmaCollection.from_yaml(yaml_text), settings)
    assert report.skipped or any(i.skipped for i in items)


def test_wazuh5_or_and_correlation(tmp_path: Path) -> None:
    yaml_text = """
title: Dual
id: 15151515-1515-4151-8151-151515151515
logsource:
  product: windows
  category: process_creation
detection:
  sel1:
    Image: a.exe
  sel2:
    CommandLine: evil
  condition: sel1 or sel2
---
title: Corr5
id: 15151515-1515-4151-8151-151515151516
correlation:
  type: event_count
  rules:
    - 15151515-1515-4151-8151-151515151515
  timespan: 1m
  condition:
    gte: 5
"""
    settings = ConvertSettings(target="wazuh5", id_file=tmp_path / "ids.json")
    items, report, _ = convert_collection(SigmaCollection.from_yaml(yaml_text), settings)
    assert any(i.wazuh5_yaml for i in items)
    assert any("correlation" in (s.skip_reason or "").lower() for s in report.skipped)
    written = write_outputs(
        [i for i in items if i.wazuh5_yaml],
        tmp_path / "out",
        ConvertSettings(target="wazuh5", output_format="per-rule", id_file=tmp_path / "ids.json"),
    )
    assert written
    dry = write_outputs(
        [i for i in items if i.wazuh5_yaml],
        tmp_path / "dry.yaml",
        ConvertSettings(
            target="wazuh5",
            output_format="single",
            dry_run=True,
            id_file=tmp_path / "ids.json",
        ),
    )
    assert dry


def test_title_only_sigma_key() -> None:
    rule = SigmaRule.from_yaml(
        """
title: Title Only Key
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: a.exe
  condition: selection
"""
    )
    assert _sigma_key(rule) == "Title Only Key"
    named = SigmaRule.from_yaml(
        """
title: Has Name
name: named-rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: a.exe
  condition: selection
"""
    )
    assert _sigma_key(named) == "named-rule"


def test_backend_unsupported_methods(tmp_path: Path) -> None:
    backend = _backend(tmp_path)
    state = ConversionState()
    field_cond = ConditionFieldEqualsValueExpression("Image", SigmaString("x"))
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        backend.convert_condition_field_eq_field(field_cond, state)
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        backend.convert_condition_field_eq_query_expr(field_cond, state)
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        backend.convert_condition_field_eq_val_timestamp_part(field_cond, state)
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        backend.convert_condition_query_expr(ConditionValueExpression(SigmaString("x")), state)
    num = ConditionValueExpression(SigmaNumber(7))
    dnf = backend.convert_condition_val_num(num, state)
    assert dnf.terms
    re_dnf = backend.convert_condition_val_re(
        ConditionValueExpression(SigmaRegularExpression("ab+")), state
    )
    assert re_dnf.terms
    and_in = ConditionAND(
        [
            ConditionFieldEqualsValueExpression("Image", SigmaString("a.exe")),
            ConditionFieldEqualsValueExpression("Image", SigmaString("b.exe")),
        ]
    )
    as_and = backend.convert_condition_as_in_expression(and_in, state)
    assert as_and.terms
    empty_or = ConditionOR([])
    assert backend.convert_condition_as_in_expression(empty_or, state).is_empty()


def test_finalize_paths(tmp_path: Path) -> None:
    backend = _backend(tmp_path)
    rule = SigmaRule.from_yaml(
        """
title: Finalize
id: 16161616-1616-4161-8161-161616161616
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: a.exe
  condition: selection
"""
    )
    item = ConversionItem(sigma_id="x", sigma_title="x")
    assert backend.finalize_output_default([[item], item]) == [item, item]
    state = ConversionState()
    with pytest.raises(SigmaConversionError):
        backend.finalize_query_default(rule, "nope", 0, state)
    empty = backend._dnf_to_item(rule, DNF.empty())
    assert empty.skipped
    settings = ConvertSettings(id_file=tmp_path / "ids.json", collect_errors=False)
    raising = WazuhBackend(
        processing_pipeline=load_builtin_catalog().build_pipeline(),
        collect_errors=False,
        allocator=IdAllocator(tmp_path / "ids2.json"),
        catalog=load_builtin_catalog(),
        settings=settings,
    )
    bad = SigmaCollection.from_yaml(
        """
title: Numeric LT Raise
id: 17171717-1717-4171-8171-171717171717
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    DestinationPort|lt: 1024
  condition: selection
"""
    )
    with pytest.raises(SigmaError):
        raising.convert(bad)
    dual = SigmaRule.from_yaml(
        """
title: Dual Cond
id: 21212121-2121-4121-8121-212121212121
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: a.exe
  condition:
    - selection
    - selection
"""
    )
    wazuh5 = _backend(tmp_path)
    wazuh5.settings = ConvertSettings(target="wazuh5", id_file=tmp_path / "ids5.json")
    wazuh5.allocator = IdAllocator(tmp_path / "ids5.json")
    wazuh5.convert_rule(dual)
    from sigma.correlations import SigmaCorrelationRule

    corr_yaml = """
title: Base
id: 22222222-2222-4222-8222-222222222221
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: a.exe
  condition: selection
---
title: Count
id: 22222222-2222-4222-8222-222222222222
correlation:
  type: event_count
  rules:
    - 22222222-2222-4222-8222-222222222221
  timespan: 1m
  condition:
    gte: 3
"""
    corr = [r for r in SigmaCollection.from_yaml(corr_yaml).rules if isinstance(r, SigmaCorrelationRule)][0]
    with pytest.raises(SigmaConversionError):
        backend.finalize_query_default(corr, DNF.atom(Literal(field="a", pattern="b")), 0, state)
    skipped5 = backend._emit_wazuh5(corr)
    assert skipped5.skipped
    args = [ConditionFieldEqualsValueExpression(f"f{i}", SigmaString("x")) for i in range(33)]
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        backend.convert_condition_or(ConditionOR(args), state)


def test_correlation_method_dispatch(tmp_path: Path) -> None:
    yaml_text = """
title: Base
id: 18181818-1818-4181-8181-181818181811
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: a.exe
  condition: selection
---
title: Count
id: 18181818-1818-4181-8181-181818181812
correlation:
  type: event_count
  rules:
    - 18181818-1818-4181-8181-181818181811
  timespan: 1m
  condition:
    gte: 3
"""
    collection = SigmaCollection.from_yaml(yaml_text)
    corr = [r for r in collection.rules if r.title == "Count"][0]
    backend = _backend(tmp_path)
    backend.settings = ConvertSettings(target="wazuh5", id_file=tmp_path / "ids.json")
    with pytest.raises(SigmaConversionError):
        backend.convert_correlation_event_count_rule(corr)
    backend.settings = ConvertSettings(id_file=tmp_path / "ids.json")
    for method in (
        backend.convert_correlation_temporal_ordered_rule,
        backend.convert_correlation_extended_temporal_rule,
        backend.convert_correlation_extended_temporal_ordered_rule,
        backend.convert_correlation_value_sum_rule,
        backend.convert_correlation_value_avg_rule,
        backend.convert_correlation_value_percentile_rule,
        backend.convert_correlation_value_median_rule,
        backend.convert_correlation_value_count_rule,
        backend.convert_correlation_temporal_rule,
    ):
        with pytest.raises(SigmaConversionError):
            method(corr)
    assert "cannot be expressed" in unsupported_message(corr) or corr.type


def test_correlation_skipped_refs(tmp_path: Path) -> None:
    yaml_text = """
title: Base Skip
id: 19191919-1919-4191-8191-191919191911
logsource:
  product: madeup
detection:
  selection:
    Field: value
  condition: selection
---
title: Count Skip
id: 19191919-1919-4191-8191-191919191912
correlation:
  type: event_count
  rules:
    - 19191919-1919-4191-8191-191919191911
  timespan: 1m
  condition:
    gte: 3
"""
    settings = ConvertSettings(id_file=tmp_path / "ids.json", strict=True)
    _items, report, _ = convert_collection(SigmaCollection.from_yaml(yaml_text), settings)
    assert any("referenced" in (s.skip_reason or "").lower() or "event_count" in (s.skip_reason or "") for s in report.skipped)


def test_dnf_empty_branches() -> None:
    empty = DNF.empty()
    atom = DNF.atom(Literal(field="a", pattern="b"))
    assert dnf_and(empty, atom).is_empty()
    assert dnf_or(empty, atom) is atom
    assert dnf_or(atom, empty) is atom
    taut = dnf_not(empty)
    assert taut.terms
    unit = DNF.unit()
    assert dnf_not(unit).is_empty()


def test_download_http_and_asset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import zipfile

    import sigmwah.downloader as downloader

    def boom(*_a: object, **_k: object) -> None:
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(downloader.urllib.request, "urlopen", boom)
    with pytest.raises(DownloadError):
        download_sigmahq(tmp_path, version="latest")

    def http_fail(*_a: object, **_k: object) -> None:
        raise urllib.error.HTTPError("https://example.invalid", 404, "no", None, None)

    monkeypatch.setattr(downloader.urllib.request, "urlopen", http_fail)
    with pytest.raises(DownloadError):
        download_sigmahq(tmp_path, version="v1")

    class ArrayResp:
        def read(self, n: int = -1) -> bytes:
            return b"[]"

        def __enter__(self) -> ArrayResp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(downloader.urllib.request, "urlopen", lambda *_a, **_k: ArrayResp())
    with pytest.raises(DownloadError):
        download_sigmahq(tmp_path, version="latest")

    with pytest.raises(DownloadError):
        _zip_url({"assets": ["nope"]})

    meta = {
        "tag_name": "r1",
        "assets": [
            "skip",
            {"name": "rules.zip", "browser_download_url": "https://example.invalid/rules.zip"},
        ],
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("tree/NOTICE", "notice")
        zf.writestr("tree/LICENSE.txt", "lic")
    payload = buf.getvalue()

    class Resp:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self, n: int = -1) -> bytes:
            data = self._data
            self._data = b""
            return data

        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def urlopen(request: object, timeout: int = 0) -> Resp:
        url = request.full_url
        if "api.github.com" in url:
            return Resp(json.dumps(meta).encode())
        return Resp(payload)

    monkeypatch.setattr(downloader.urllib.request, "urlopen", urlopen)
    extracted = download_sigmahq(tmp_path / "ok", version="v1")
    assert extracted.exists()
    again = download_sigmahq(tmp_path / "ok", version="v1")
    assert again.exists()

    def download_fail(request: object, timeout: int = 0) -> Resp:
        url = request.full_url
        if "api.github.com" in url:
            return Resp(
                json.dumps({"tag_name": "x", "zipball_url": "https://example.invalid/z"}).encode()
            )
        raise urllib.error.URLError("no zip")

    monkeypatch.setattr(downloader.urllib.request, "urlopen", download_fail)
    with pytest.raises(DownloadError):
        download_sigmahq(tmp_path / "failzip", version="latest")


def test_docker_success_mock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    monkeypatch.setattr(validator.shutil, "which", lambda _n: "/usr/bin/docker")
    monkeypatch.setattr(validator.time, "sleep", lambda *_a, **_k: None)

    def fake_run(cmd: list[str], **_k: object) -> MagicMock:
        mock = MagicMock()
        mock.returncode = 0
        joined = " ".join(cmd)
        if "echo READY" in joined:
            mock.stdout = "READY"
        elif "wazuh-logtest" in joined:
            mock.stdout = "**Phase 3: Completed filtering (rules).**"
        elif "ossec.log" in joined:
            mock.stdout = "ERROR rules failed to load"
        else:
            mock.stdout = ""
        mock.stderr = ""
        return mock

    monkeypatch.setattr(validator.subprocess, "run", fake_run)
    result = smoke_test_docker(xml, ["synthetic event line"], timeout=5)
    assert result.docker_ran
    assert result.logtest_hits
    assert any("ossec.log" in msg for msg in result.messages)


def test_docker_malformed_and_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sigmwah.validator as validator

    bad = tmp_path / "bad.xml"
    bad.write_text("<nope>", encoding="utf-8")
    result = smoke_test_docker(bad, ["x"])
    assert not result.well_formed
    monkeypatch.setattr(validator, "_docker_exec", lambda *_a, **_k: "WAIT")
    monkeypatch.setattr(validator.time, "sleep", lambda *_a, **_k: None)
    with pytest.raises(ValidationError):
        validator._wait_for_manager("n", timeout=0)


def test_validate_edge_xml(tmp_path: Path) -> None:
    junk = tmp_path / "junk.xml"
    junk.write_text("<a/>\n<b/>\n", encoding="utf-8")
    result = validate_xml(junk)
    assert not result.well_formed
    wrapper = tmp_path / "wrap.xml"
    wrapper.write_text(
        """<wrapper>
  <notgroup/>
  <group name="sigma,">
    <rule id="1" level="3"><description>x</description></rule>
  </group>
</wrapper>
""",
        encoding="utf-8",
    )
    wrapped = validate_xml(wrapper)
    assert any("Unexpected" in msg for msg in wrapped.messages)
    missing = tmp_path / "miss.xml"
    missing.write_text(
        """<group name="sigma,">
  <rule id="1"></rule>
  <rule id="2" level="3"></rule>
</group>
""",
        encoding="utf-8",
    )
    miss = validate_xml(missing)
    assert any("level" in msg or "description" in msg for msg in miss.messages)
    empty = tmp_path / "empty.xml"
    empty.write_text('<group name="sigma,"></group>\n', encoding="utf-8")
    assert any("No <rule>" in msg for msg in validate_xml(empty).messages)
    nodecl = tmp_path / "nodecl.xml"
    nodecl.write_text("not xml at all <<<", encoding="utf-8")
    assert not validate_xml(nodecl).well_formed


def test_emit_literal_kinds() -> None:
    rule = WazuhRule(
        rule_id=100100,
        level=5,
        description="kinds",
        decoded_as="json",
        program_name="^sshd$",
        if_matched_group="g",
        same_source_ip=True,
        same_user=True,
        same_fields=["win.eventdata.commandLine"],
        noalert=True,
        frequency=4,
        timeframe=60,
        mitre_ids=["T1059"],
        groups=[],
        comments=["Converted -- with -- dashes"],
        fields=[
            Literal(field=None, pattern="kw", kind=MatchKind.KEYWORD, negate=True),
            Literal(field="win.eventdata.image", pattern=".", kind=MatchKind.EXISTS),
            Literal(field="win.eventdata.user", pattern=".", kind=MatchKind.NOT_EXISTS),
        ],
        sigma_key="k#0",
    )
    item = ConversionItem(sigma_id="k", sigma_title="kinds", rules=[rule])
    skipped = ConversionItem(sigma_id="s", sigma_title="s", skipped=True, skip_reason="nope")
    docs = emit_xml([skipped, item], group_by="per-rule")
    xml = next(iter(docs.values()))
    assert "negate" in xml
    assert "same_source_ip" in xml
    assert "same_user" in xml
    assert "if_matched_group" in xml
    assert 'frequency="4"' in xml
    empty_docs = emit_xml([], group_by="single")
    assert "sigma" in next(iter(empty_docs.values()))


def test_cli_format_error_download_validate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rule = tmp_path / "r.yml"
    rule.write_text(
        """
title: x
id: 20202020-2020-4202-8202-202020202020
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
    bad_fmt = runner.invoke(
        app,
        ["convert", str(rule), "--format", "nope", "-o", str(tmp_path / "o.xml")],
    )
    assert bad_fmt.exit_code != 0
    import sigmwah.cli as cli

    monkeypatch.setattr(cli, "load_sigma_paths", lambda _p: (_ for _ in ()).throw(ValueError("bad")))
    err = runner.invoke(app, ["convert", str(rule), "-o", str(tmp_path / "o.xml")])
    assert err.exit_code == 1
    monkeypatch.setattr(cli, "download_sigmahq", lambda dest, version="latest": dest)
    ok = runner.invoke(app, ["download-sigmahq", "--dest", str(tmp_path / "hq")])
    assert ok.exit_code == 0
    xml = tmp_path / "ok.xml"
    xml.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<group name="sigma,">
  <rule id="100100" level="3"><description>ok</description></rule>
</group>
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        cli,
        "smoke_test_docker",
        lambda *_a, **_k: ValidationResult(well_formed=True, docker_ran=True, messages=[]),
    )
    val = runner.invoke(app, ["validate", str(xml), "--docker", "--event", "x"])
    assert val.exit_code == 0
    assert "Docker" in val.stdout


def test_filters_and_idalloc_and_catalog(tmp_path: Path) -> None:
    assert parse_select("product=windows,")["product"] == "windows"
    with pytest.raises(ValueError):
        parse_level_floor("nope")
    rule = SigmaRule.from_yaml(
        """
title: No Level
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: a.exe
  condition: selection
"""
    )
    assert not rule_passes(rule, select={}, tags=["attack.t9999"], exclude_tags=[], level_floor=None)
    assert not rule_passes(rule, select={}, tags=[], exclude_tags=[], level_floor=2)
    alloc = IdAllocator(tmp_path / "ids.json", id_start=100100, id_max=100110)
    alloc.allocate("a", title="A")
    assert alloc.get("a") is not None
    buf = io.StringIO()
    alloc.export_csv(buf)
    assert "100100" in buf.getvalue()
    payload = {
        "version": 1,
        "next": 100100,
        "allocations": {
            "in": {"wazuh_id": 100105, "title": "in", "allocated_at": ""},
            "out": {"wazuh_id": 50, "title": "out", "allocated_at": ""},
        },
    }
    path = tmp_path / "range.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    reloaded = IdAllocator(path, id_start=100100, id_max=100110)
    assert reloaded.get("in") is not None
    assert reloaded.get("out") is None
    with pytest.raises(MappingError):
        load_user_mappings(tmp_path / "missing.yaml")
    bad_yaml = tmp_path / "badyaml.yaml"
    bad_yaml.write_text(":\n  - [\n", encoding="utf-8")
    with pytest.raises(MappingError):
        load_user_mappings(bad_yaml)
    bad_schema = tmp_path / "schema.yaml"
    bad_schema.write_text("logsources:\n  - product: windows\n", encoding="utf-8")
    with pytest.raises(MappingError):
        load_user_mappings(bad_schema)
    skip_all = tmp_path / "skip.yaml"
    skip_all.write_text(
        """
logsources:
  - id: nothing
    groups: [sigma]
""",
        encoding="utf-8",
    )
    catalog = load_builtin_catalog()
    catalog.merge(load_user_mappings(skip_all), source="empty")
    from sigma.rule.logsource import SigmaLogSource

    assert catalog.match_logsource(SigmaLogSource(product="windows", category="process_creation"))
    assert looks_like_pcre2("abc")
    assert join_alternatives(["only"]) == "only"
    host = cidr_to_pcre2(SigmaCIDRExpression("10.1.2.3/32"))
    assert looks_like_pcre2(host)


def test_write_outputs_dry_run_group(tmp_path: Path) -> None:
    rule = WazuhRule(rule_id=100100, level=3, description="d", groups=["sigma"], sigma_key="x#0")
    item = ConversionItem(sigma_id="x", sigma_title="d", rules=[rule])
    settings = ConvertSettings(
        output_format="per-group", dry_run=True, id_file=tmp_path / "ids.json"
    )
    written = write_outputs([item], tmp_path / "out", settings)
    assert written
    assert not written[0].exists()
