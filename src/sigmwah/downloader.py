"""Download SigmaHQ rule releases without vendoring them into Sigmwah."""

from __future__ import annotations

import json
import shutil
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from sigmwah.exceptions import DownloadError

GITHUB_API = "https://api.github.com/repos/SigmaHQ/sigma/releases"
USER_AGENT = "Sigmwah/0.1.0 (community Sigma to Wazuh converter)"


def download_sigmahq(dest: Path, version: str = "latest") -> Path:
    """Download a SigmaHQ release zip and extract it, preserving LICENSE/NOTICE."""
    dest.mkdir(parents=True, exist_ok=True)
    meta = _release_meta(version)
    tag = str(meta.get("tag_name") or version)
    zip_url = _zip_url(meta)
    archive = dest / f"sigmahq-{tag}.zip"
    _download(zip_url, archive)
    extract_dir = dest / f"sigmahq-{tag}"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(extract_dir)
    _ensure_license_notice(extract_dir)
    return extract_dir


def _release_meta(version: str) -> dict[str, object]:
    url = f"{GITHUB_API}/latest" if version == "latest" else f"{GITHUB_API}/tags/{version}"
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise DownloadError(f"GitHub release lookup failed for {version}: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise DownloadError(f"GitHub release lookup failed: {exc.reason}") from exc
    if not isinstance(payload, dict):
        raise DownloadError("Unexpected GitHub API payload")
    return payload


def _zip_url(meta: dict[str, object]) -> str:
    assets = meta.get("assets")
    if isinstance(assets, list):
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            name = str(asset.get("name") or "")
            url = asset.get("browser_download_url")
            if name.endswith(".zip") and isinstance(url, str):
                return url
    zipball = meta.get("zipball_url")
    if isinstance(zipball, str) and zipball:
        return zipball
    raise DownloadError("Release metadata does not include a zip download URL")


def _download(url: str, dest: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=120) as response, dest.open("wb") as handle:
            shutil.copyfileobj(response, handle)
    except urllib.error.URLError as exc:
        raise DownloadError(f"Failed to download {url}: {exc}") from exc


def _ensure_license_notice(extract_dir: Path) -> None:
    """Copy LICENSE/NOTICE from the extracted tree to the top-level dest if nested."""
    license_files = list(extract_dir.rglob("LICENSE")) + list(extract_dir.rglob("LICENSE*"))
    notice_files = list(extract_dir.rglob("NOTICE")) + list(extract_dir.rglob("NOTICE*"))
    marker = extract_dir / "SIGMWAH_DRL_NOTICE.txt"
    marker.write_text(
        "SigmaHQ rules are licensed under Detection Rule License 1.1 (DRL-1.1).\n"
        "See https://github.com/SigmaHQ/Detection-Rule-License\n"
        "Sigmwah does not relicense these rules. Keep LICENSE/NOTICE from this tree.\n",
        encoding="utf-8",
    )
    if license_files:
        shutil.copy2(license_files[0], extract_dir / "LICENSE")
    if notice_files:
        shutil.copy2(notice_files[0], extract_dir / "NOTICE")
