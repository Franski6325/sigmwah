from __future__ import annotations

from pathlib import Path

import pytest

from sigmwah.exceptions import IdRangeExhaustedError
from sigmwah.idalloc import IdAllocator


def test_allocate_is_stable_and_persistent(tmp_path: Path) -> None:
    path = tmp_path / "ids.json"
    alloc = IdAllocator(path, id_start=100100, id_max=100110)
    first = alloc.allocate("rule-a", title="A")
    second = alloc.allocate("rule-b", title="B")
    assert first == 100100
    assert second == 100101
    assert alloc.allocate("rule-a") == first
    alloc.save()
    reloaded = IdAllocator(path, id_start=100100, id_max=100110)
    assert reloaded.allocate("rule-a") == first
    assert reloaded.allocate("rule-c") == 100102


def test_export_csv(tmp_path: Path) -> None:
    path = tmp_path / "ids.json"
    alloc = IdAllocator(path, id_start=100100, id_max=100110)
    alloc.allocate("k", title="Title")
    csv_path = tmp_path / "ids.csv"
    alloc.export_csv(csv_path)
    text = csv_path.read_text(encoding="utf-8")
    assert "wazuh_id" in text
    assert "100100" in text
    assert "Title" in text


def test_range_exhausted(tmp_path: Path) -> None:
    path = tmp_path / "ids.json"
    alloc = IdAllocator(path, id_start=100100, id_max=100100)
    alloc.allocate("one")
    with pytest.raises(IdRangeExhaustedError):
        alloc.allocate("two")
