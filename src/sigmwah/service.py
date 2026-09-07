"""High-level conversion service used by the CLI and tests."""

from __future__ import annotations

from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigmwah.backend import WazuhBackend
from sigmwah.config import ConvertSettings
from sigmwah.emit import emit_xml
from sigmwah.filters import parse_level_floor, parse_select, rule_passes
from sigmwah.idalloc import IdAllocator
from sigmwah.ir import ConversionItem
from sigmwah.mappings.catalog import load_builtin_catalog, load_user_mappings
from sigmwah.report import ConversionReport


def load_sigma_paths(paths: list[Path]) -> SigmaCollection:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.rglob("*.yml")))
            files.extend(sorted(path.rglob("*.yaml")))
        else:
            files.append(path)
    if not files:
        return SigmaCollection([])
    return SigmaCollection.load_ruleset(files, collect_errors=True)


def convert_collection(
    collection: SigmaCollection,
    settings: ConvertSettings,
) -> tuple[list[ConversionItem], ConversionReport, IdAllocator]:
    catalog = load_builtin_catalog()
    if settings.mappings_file is not None:
        catalog.merge(load_user_mappings(settings.mappings_file), source="user")
    allocator = IdAllocator(settings.id_file, settings.id_start, settings.id_max)
    select = parse_select(settings.select)
    level_floor = parse_level_floor(settings.level)
    kept: list[SigmaRule | SigmaCorrelationRule] = []
    report = ConversionReport()
    for rule in collection.rules:
        if rule_passes(
            rule,
            select=select,
            tags=settings.tags,
            exclude_tags=settings.exclude_tags,
            level_floor=level_floor,
        ):
            kept.append(rule)
        else:
            report.add(
                ConversionItem(
                    sigma_id=str(getattr(rule, "id", None) or rule.title),
                    sigma_title=rule.title,
                    skipped=True,
                    skip_reason="Filtered by CLI selectors",
                )
            )
    filtered = SigmaCollection(kept)
    backend = WazuhBackend(
        processing_pipeline=catalog.build_pipeline(),
        collect_errors=settings.collect_errors,
        allocator=allocator,
        catalog=catalog,
        settings=settings,
    )
    items = backend.convert(filtered)
    for item in items:
        report.add(item)
    for item in backend.skipped:
        if item not in report.skipped and item not in report.converted:
            report.add(item)
    for _rule, error in backend.errors:
        already = any(
            skipped.sigma_id == str(getattr(_rule, "id", None) or _rule.title)
            for skipped in report.skipped
        )
        if not already:
            report.add(
                ConversionItem(
                    sigma_id=str(getattr(_rule, "id", None) or _rule.title),
                    sigma_title=_rule.title,
                    skipped=True,
                    skip_reason=str(error),
                )
            )
    allocator.save()
    return items, report, allocator


def write_outputs(
    items: list[ConversionItem],
    output: Path,
    settings: ConvertSettings,
) -> list[Path]:
    written: list[Path] = []
    wazuh5 = [item for item in items if item.target == "wazuh5" and item.wazuh5_yaml]
    if settings.target == "wazuh5":
        if settings.output_format == "single":
            text = "\n---\n".join(item.wazuh5_yaml or "" for item in wazuh5)
            dest = output if output.suffix else output / "rules_sigma.yaml"
            if not settings.dry_run:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(text, encoding="utf-8")
            written.append(dest)
            return written
        for item in wazuh5:
            dest = (
                output / f"{item.sigma_id}.yml"
                if output.is_dir() or output.suffix == ""
                else output
            )
            if not settings.dry_run:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(item.wazuh5_yaml or "", encoding="utf-8")
            written.append(dest)
        return written
    documents = emit_xml(items, group_by=settings.output_format)
    if settings.output_format == "single":
        dest = output if output.suffix else output / "rules_sigma.xml"
        if not settings.dry_run:
            dest.parent.mkdir(parents=True, exist_ok=True)
            fallback = '<group name="sigma,">\n</group>\n'
            dest.write_text(next(iter(documents.values()), fallback), encoding="utf-8")
        written.append(dest)
        return written
    output.mkdir(parents=True, exist_ok=True)
    for stem, xml in documents.items():
        dest = output / f"{stem}.xml"
        if not settings.dry_run:
            dest.write_text(xml, encoding="utf-8")
        written.append(dest)
    return written
