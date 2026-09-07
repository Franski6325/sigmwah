"""Sigmwah package: Sigma to Wazuh 4.x XML conversion."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sigmwah")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.1.0"

__all__ = ["__version__"]
