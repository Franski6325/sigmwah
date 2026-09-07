"""Markdown conversion reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sigmwah.ir import ConversionItem


@dataclass
class ConversionReport:
    converted: list[ConversionItem] = field(default_factory=list)
    skipped: list[ConversionItem] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add(self, item: ConversionItem) -> None:
        if item.skipped:
            self.skipped.append(item)
        else:
            self.converted.append(item)
        self.warnings.extend(item.warnings)
        for rule in item.rules:
            self.warnings.extend(rule.warnings)

    def to_markdown(self) -> str:
        lines = [
            "# Sigmwah conversion report",
            "",
            f"- Converted: **{len(self.converted)}**",
            f"- Skipped: **{len(self.skipped)}**",
            f"- Warnings: **{len(self.warnings)}**",
            "",
            "## Converted",
            "",
        ]
        if not self.converted:
            lines.append("_None._")
            lines.append("")
        for item in self.converted:
            ids = ", ".join(str(rule.rule_id) for rule in item.rules) or "(yaml)"
            lines.append(f"- `{item.sigma_id}` — {item.sigma_title} → Wazuh IDs {ids}")
        lines.extend(["", "## Skipped", ""])
        if not self.skipped:
            lines.append("_None._")
            lines.append("")
        for item in self.skipped:
            lines.append(
                f"- `{item.sigma_id}` — {item.sigma_title}: {item.skip_reason or 'unknown reason'}"
            )
        lines.extend(["", "## Warnings", ""])
        if not self.warnings:
            lines.append("_None._")
            lines.append("")
        for warning in self.warnings:
            lines.append(f"- {warning}")
        lines.append("")
        return "\n".join(lines)

    def write(self, path: Path) -> None:
        path.write_text(self.to_markdown(), encoding="utf-8")
