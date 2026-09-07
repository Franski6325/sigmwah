from __future__ import annotations

from pathlib import Path

import pytest

from sigmwah.config import ConvertSettings
from sigmwah.idalloc import IdAllocator


@pytest.fixture
def tmp_id_file(tmp_path: Path) -> Path:
    return tmp_path / ".sigmwah_ids.json"


@pytest.fixture
def allocator(tmp_id_file: Path) -> IdAllocator:
    return IdAllocator(tmp_id_file, id_start=100100, id_max=100199)


@pytest.fixture
def settings(tmp_id_file: Path) -> ConvertSettings:
    return ConvertSettings(id_file=tmp_id_file, id_start=100100, id_max=100199)
