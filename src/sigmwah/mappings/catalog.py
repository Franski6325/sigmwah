"""Load and merge Sigmwah mapping YAML documents."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.rule.logsource import SigmaLogSource

from sigmwah.config import SeverityMap
from sigmwah.exceptions import MappingError
from sigmwah.ir import LogsourceEntrySpec


class EntryModel(BaseModel):
    if_sid: str | None = None
    if_group: str | None = None
    decoded_as: str | None = None
    program_name: str | None = None
    fields: dict[str, str] = Field(default_factory=dict)


class LogsourceModel(BaseModel):
    id: str
    product: str | None = None
    category: str | None = None
    service: str | None = None
    groups: list[str] = Field(default_factory=list)
    entry: EntryModel = Field(default_factory=EntryModel)


class MappingFile(BaseModel):
    logsources: list[LogsourceModel] = Field(default_factory=list)
    fields: dict[str, str] = Field(default_factory=dict)
    severity: dict[str, int] = Field(default_factory=dict)
    status_groups: dict[str, str] = Field(default_factory=dict)


@dataclass
class FieldMap:
    mapping: dict[str, str]
    product: str | None = None
    identifier: str = "sigmwah-fields"


@dataclass
class MappingCatalog:
    logsources: list[LogsourceModel] = field(default_factory=list)
    fields: dict[str, str] = field(default_factory=dict)
    field_maps: list[FieldMap] = field(default_factory=list)
    severity: SeverityMap = field(default_factory=SeverityMap)
    status_groups: dict[str, str] = field(default_factory=dict)

    def merge(self, other: MappingFile, *, source: str = "user") -> None:
        self.logsources.extend(other.logsources)
        for key, value in other.fields.items():
            self.fields.setdefault(key, value)
        if other.fields:
            products = {item.product for item in other.logsources if item.product}
            product = next(iter(products)) if len(products) == 1 else None
            self.field_maps.append(
                FieldMap(
                    mapping=dict(other.fields),
                    product=product,
                    identifier=f"sigmwah-{source}",
                )
            )
        if other.severity:
            self.severity = SeverityMap.model_validate(
                {**self.severity.model_dump(), **other.severity}
            )
        self.status_groups.update(other.status_groups)

    def match_logsource(self, logsource: SigmaLogSource) -> LogsourceEntrySpec | None:
        scored: list[tuple[int, LogsourceModel]] = []
        for item in self.logsources:
            if item.product is not None and item.product != logsource.product:
                continue
            if item.category is not None and item.category != logsource.category:
                continue
            if item.service is not None and item.service != logsource.service:
                continue
            if item.product is None and item.category is None and item.service is None:
                continue
            score = sum(
                value is not None for value in (item.product, item.category, item.service)
            )
            scored.append((score, item))
        if not scored:
            return None
        scored.sort(key=lambda pair: pair[0], reverse=True)
        best = scored[0][1]
        return LogsourceEntrySpec(
            if_sid=best.entry.if_sid,
            if_group=best.entry.if_group,
            decoded_as=best.entry.decoded_as,
            program_name=best.entry.program_name,
            extra_fields=dict(best.entry.fields),
            groups=list(best.groups),
            mapping_id=best.id,
        )

    def build_pipeline(self) -> ProcessingPipeline:
        items: list[ProcessingItem] = []
        for group in self.field_maps:
            conditions = (
                [LogsourceCondition(product=group.product)] if group.product else []
            )
            items.append(
                ProcessingItem(
                    identifier=group.identifier,
                    transformation=FieldMappingTransformation(group.mapping),
                    rule_conditions=conditions,
                )
            )
        return ProcessingPipeline(items, name="sigmwah-default")


def load_builtin_catalog() -> MappingCatalog:
    catalog = MappingCatalog()
    package = resources.files("sigmwah.mappings")
    for name in ("windows.yaml", "linux.yaml", "web.yaml", "severity.yaml"):
        text = package.joinpath(name).read_text(encoding="utf-8")
        catalog.merge(_parse_mapping_yaml(text, source=name), source=Path(name).stem)
    return catalog


def load_user_mappings(path: Path) -> MappingFile:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MappingError(f"Cannot read mappings file {path}: {exc}") from exc
    return _parse_mapping_yaml(text, source=str(path))


def _parse_mapping_yaml(text: str, source: str) -> MappingFile:
    try:
        data: Any = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise MappingError(f"Invalid YAML in {source}: {exc}") from exc
    if not isinstance(data, dict):
        raise MappingError(f"Mapping file {source} must be a YAML mapping")
    try:
        return MappingFile.model_validate(data)
    except Exception as exc:
        raise MappingError(f"Invalid mapping schema in {source}: {exc}") from exc
