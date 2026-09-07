"""Build the default Sigmwah processing pipeline."""

from __future__ import annotations

from sigma.processing.pipeline import ProcessingPipeline

from sigmwah.mappings.catalog import load_builtin_catalog


def wazuh_pipeline() -> ProcessingPipeline:
    """Return the built-in field-mapping pipeline for Wazuh 4.x."""
    return load_builtin_catalog().build_pipeline()
