"""Pydantic configuration models for Sigmwah."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class SeverityMap(BaseModel):
    informational: int = 3
    low: int = 4
    medium: int = 6
    high: int = 10
    critical: int = 12

    @field_validator("*")
    @classmethod
    def _level_range(cls, value: int) -> int:
        if not 0 <= value <= 16:
            raise ValueError("Wazuh rule level must be between 0 and 16")
        return value

    def for_name(self, name: str | None) -> int:
        if name is None:
            return self.medium
        key = name.lower()
        mapping = {
            "informational": self.informational,
            "low": self.low,
            "medium": self.medium,
            "high": self.high,
            "critical": self.critical,
        }
        return mapping.get(key, self.medium)


class ConvertSettings(BaseModel):
    target: Literal["wazuh4", "wazuh5"] = "wazuh4"
    id_start: int = 100100
    id_max: int = 119999
    id_file: Path = Field(default_factory=lambda: Path(".sigmwah_ids.json"))
    select: str | None = None
    tags: list[str] = Field(default_factory=list)
    level: str | None = None
    exclude_tags: list[str] = Field(default_factory=list)
    output_format: Literal["single", "per-rule", "per-group"] = "single"
    mappings_file: Path | None = None
    dry_run: bool = False
    strict: bool = False
    fp_ignore: bool = False
    report_path: Path | None = None
    collect_errors: bool = True

    @field_validator("id_start", "id_max")
    @classmethod
    def _positive_id(cls, value: int) -> int:
        if value < 100000 or value > 999999:
            raise ValueError("Wazuh custom rule IDs should be in 100000–999999")
        return value
