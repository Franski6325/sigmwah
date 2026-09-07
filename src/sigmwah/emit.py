"""Serialize WazuhRule objects to analysisd XML."""

from __future__ import annotations

import re
from collections import defaultdict
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.sax.saxutils import escape

from sigmwah.ir import ConversionItem, MatchKind, WazuhRule

_COMMENT_DASH = re.compile(r"-{2,}")


def emit_xml(
    items: list[ConversionItem],
    *,
    group_by: str = "single",
) -> dict[str, str]:
    """Return mapping of filename stem -> XML document."""
    rules = [rule for item in items if not item.skipped for rule in item.rules]
    if group_by == "per-rule":
        documents: dict[str, str] = {}
        for item in items:
            if item.skipped or not item.rules:
                continue
            stem = _safe_stem(item.sigma_id or item.sigma_title)
            documents[stem] = _document_from_rules(item.rules)
        return documents
    if group_by == "per-group":
        buckets: dict[str, list[WazuhRule]] = defaultdict(list)
        for rule in rules:
            primary = next((g for g in rule.groups if g not in {"sigma"}), "sigma")
            buckets[primary].append(rule)
        return {name: _document_from_rules(group) for name, group in buckets.items()}
    return {"rules_sigma": _document_from_rules(rules)}


def _document_from_rules(rules: list[WazuhRule]) -> str:
    grouped: dict[str, list[WazuhRule]] = defaultdict(list)
    for rule in rules:
        grouped[_group_name(rule.groups)].append(rule)
    chunks = ['<?xml version="1.0" encoding="UTF-8"?>']
    if not grouped:
        chunks.append('<group name="sigma,">\n</group>\n')
        return "\n".join(chunks)
    for group_name, group_rules in grouped.items():
        chunks.append(f'<group name="{escape(group_name)}">')
        for rule in group_rules:
            chunks.append(_render_rule(rule))
        chunks.append("</group>")
    return "\n".join(chunks) + "\n"


def _group_name(groups: list[str]) -> str:
    names = [part.strip().rstrip(",") for part in groups if part.strip()]
    if not names:
        names = ["sigma"]
    seen: list[str] = []
    for name in names:
        if name not in seen:
            seen.append(name)
    return ",".join(seen) + ","


def _render_rule(rule: WazuhRule) -> str:
    attrib = {"id": str(rule.rule_id), "level": str(rule.level)}
    if rule.frequency is not None:
        attrib["frequency"] = str(rule.frequency)
    if rule.timeframe is not None:
        attrib["timeframe"] = str(rule.timeframe)
    if rule.noalert:
        attrib["noalert"] = "1"
    element = Element("rule", attrib)
    for comment in rule.comments:
        text = _COMMENT_DASH.sub("-", comment)
        comment_el = Element("info", {"type": "comment"})
        comment_el.text = text
        # Keep DRL attribution as an XML comment plus <info> for parsers
        # that strip comments. The comment itself is injected in the string
        # form below because ElementTree pretty-print of Comment is awkward.
        element.append(comment_el)
    if rule.if_sid:
        _text_child(element, "if_sid", rule.if_sid)
    if rule.if_group:
        _text_child(element, "if_group", rule.if_group)
    if rule.decoded_as:
        _text_child(element, "decoded_as", rule.decoded_as)
    if rule.program_name:
        child = SubElement(element, "program_name", {"type": "pcre2"})
        child.text = rule.program_name
    if rule.if_matched_sid:
        _text_child(element, "if_matched_sid", rule.if_matched_sid)
    if rule.if_matched_group:
        _text_child(element, "if_matched_group", rule.if_matched_group)
    if rule.same_source_ip:
        SubElement(element, "same_source_ip")
    if rule.same_user:
        SubElement(element, "same_user")
    for same in rule.same_fields:
        _text_child(element, "same_field", same)
    for lit in rule.fields:
        _append_literal(element, lit)
    for option in rule.options:
        _text_child(element, "options", option)
    _text_child(element, "description", rule.description)
    if rule.mitre_ids:
        mitre = SubElement(element, "mitre")
        for technique in rule.mitre_ids:
            _text_child(mitre, "id", technique)
    if rule.groups:
        inner = ",".join(g.rstrip(",") for g in rule.groups if g) + ","
        _text_child(element, "group", inner)
    body = tostring(element, encoding="unicode")
    comment_xml = "".join(
        f"    <!-- {escape(_COMMENT_DASH.sub('-', c))} -->\n" for c in rule.comments
    )
    # Insert comments immediately after the opening <rule> tag.
    open_end = body.find(">")
    pretty = _pretty(body)
    if comment_xml and open_end != -1:
        # Re-pretty by reconstructing with comments for human-readable rulesets.
        pretty_lines = pretty.splitlines()
        if pretty_lines:
            pretty = pretty_lines[0] + "\n" + comment_xml + "\n".join(pretty_lines[1:])
    return pretty


def _append_literal(parent: Element, lit: object) -> None:
    from sigmwah.ir import Literal as IRLiteral

    assert isinstance(lit, IRLiteral)
    if lit.kind == MatchKind.KEYWORD:
        child = SubElement(parent, "regex", {"type": "pcre2"})
        if lit.negate:
            child.set("negate", "yes")
        child.text = lit.pattern
        return
    if lit.kind == MatchKind.EXISTS:
        field = SubElement(parent, "field", {"name": lit.field or "", "type": "pcre2"})
        field.text = "."
        return
    if lit.kind == MatchKind.NOT_EXISTS:
        field = SubElement(
            parent,
            "field",
            {"name": lit.field or "", "type": "pcre2", "negate": "yes"},
        )
        field.text = "."
        return
    attrib = {"name": lit.field or "", "type": "pcre2"}
    if lit.negate:
        attrib["negate"] = "yes"
    field = SubElement(parent, "field", attrib)
    field.text = lit.pattern


def _text_child(parent: Element, tag: str, text: str) -> None:
    child = SubElement(parent, tag)
    child.text = text


def _pretty(xml: str) -> str:
    """Indent a single-element XML fragment with two spaces."""
    xml = xml.replace("><", ">\n<")
    lines = xml.splitlines()
    indent = 0
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("</"):
            indent = max(indent - 1, 0)
        out.append("  " * (indent + 1) + stripped)
        if (
            stripped.startswith("<")
            and not stripped.startswith("</")
            and not stripped.endswith("/>")
            and not stripped.startswith("<!--")
            and "</" not in stripped[1:]
        ):
            indent += 1
    return "\n".join(out)


def _safe_stem(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
    return cleaned or "rule"


def attribution_comment(
    *,
    title: str,
    sigma_id: str,
    author: str,
    date: str,
    references: list[str],
    falsepositives: list[str],
) -> str:
    refs = "; ".join(references) if references else "-"
    fps = "; ".join(falsepositives) if falsepositives else "-"
    return (
        f"Sigma title: {title} | Sigma id: {sigma_id} | Author: {author} | "
        f"Date: {date} | References: {refs} | False positives: {fps} | "
        "Converted with Sigmwah from SigmaHQ (DRL 1.1)"
    )
