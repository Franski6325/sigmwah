from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sigmwah.downloader import download_sigmahq


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self, n: int = -1) -> bytes:
        data = self._payload
        self._payload = b""
        return data

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_download_sigmahq_extracts_and_preserves_license(tmp_path: Path, monkeypatch: Any) -> None:
    import io
    import zipfile

    import sigmwah.downloader as downloader

    meta = {
        "tag_name": "r2026-01-01",
        "zipball_url": "https://example.invalid/sigma.zip",
        "assets": [],
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("sigma-r2026-01-01/LICENSE", "DRL-1.1 placeholder")
        zf.writestr("sigma-r2026-01-01/rules/demo.yml", "title: demo\n")
    zip_bytes = buf.getvalue()

    calls = {"n": 0}

    def fake_urlopen(request: object, timeout: int = 0) -> _FakeResponse:
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResponse(json.dumps(meta).encode("utf-8"))
        return _FakeResponse(zip_bytes)

    monkeypatch.setattr(downloader.urllib.request, "urlopen", fake_urlopen)
    extracted = download_sigmahq(tmp_path / "out", version="latest")
    assert extracted.exists()
    assert (extracted / "SIGMWAH_DRL_NOTICE.txt").exists()
    assert (extracted / "LICENSE").exists() or list(extracted.rglob("LICENSE"))
