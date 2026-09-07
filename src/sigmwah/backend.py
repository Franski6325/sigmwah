"""pySigma Backend that converts Sigma rules into Wazuh XML IR."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.conversion.base import Backend
from sigma.conversion.state import ConversionState
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import (
    SigmaConversionError,
    SigmaError,
    SigmaFeatureNotSupportedByBackendError,
)
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
)

from sigmwah.config import ConvertSettings
from sigmwah.correlation import convert_event_count, unsupported_message
from sigmwah.dnf import DnfTooLargeError, dnf_and_all, dnf_not, dnf_or_all
from sigmwah.emit import attribution_comment
from sigmwah.idalloc import IdAllocator
from sigmwah.ir import (
    DNF,
    ConversionItem,
    Literal,
    LogsourceEntrySpec,
    MatchKind,
    WazuhRule,
)
from sigmwah.mappings.catalog import MappingCatalog, load_builtin_catalog
from sigmwah.mitre import mitre_ids_from_tags
from sigmwah.pcre import (
    cidr_to_pcre2,
    join_alternatives,
    sigma_regex_to_pcre2,
    sigma_string_to_pcre2,
)


class WazuhBackend(Backend):  # type: ignore[misc]
    """Convert Sigma rules to a Wazuh 4.x XML intermediate representation."""

    name = "Wazuh XML (Sigmwah)"
    formats: dict[str, str] = {
        "default": "Wazuh 4.x analysisd XML intermediate representation",
    }
    convert_or_as_in = True
    convert_and_as_in = False
    in_expressions_allow_wildcards = True
    explicit_not_exists_expression = True
    finalize_correlation_subqueries = True
    correlation_methods: dict[str, str] = {
        "default": "Wazuh frequency, timeframe, if_matched_sid/if_matched_group, same_*",
    }

    def __init__(
        self,
        processing_pipeline: ProcessingPipeline | None = None,
        collect_errors: bool = False,
        allocator: IdAllocator | None = None,
        catalog: MappingCatalog | None = None,
        settings: ConvertSettings | None = None,
        **backend_options: dict[str, Any],
    ) -> None:
        super().__init__(processing_pipeline, collect_errors, **backend_options)
        self.catalog = catalog or load_builtin_catalog()
        self.settings = settings or ConvertSettings()
        self.allocator = allocator or IdAllocator(
            Path(self.settings.id_file),
            id_start=self.settings.id_start,
            id_max=self.settings.id_max,
        )
        self.skipped: list[ConversionItem] = []

    def convert(
        self,
        rule_collection: SigmaCollection,
        output_format: str | None = None,
        correlation_method: str | None = None,
        callback: Any = None,
    ) -> list[ConversionItem]:
        self.init_processing_pipeline(output_format)
        rule_collection.resolve_rule_references()
        detections = [r for r in rule_collection.rules if isinstance(r, SigmaRule)]
        correlations = [r for r in rule_collection.rules if isinstance(r, SigmaCorrelationRule)]
        queries: list[ConversionItem] = []
        for rule in detections + correlations:
            try:
                if isinstance(rule, SigmaRule):
                    converted = self.convert_rule(
                        rule, output_format or self.default_format, callback
                    )
                else:
                    converted = self.convert_correlation_rule(
                        rule,
                        output_format or self.default_format,
                        correlation_method,
                        callback,
                    )
                items = [item for item in converted if isinstance(item, ConversionItem)]
                if not items:
                    try:
                        stored = rule.get_conversion_result()
                    except Exception:
                        stored = []
                    items = [item for item in stored if isinstance(item, ConversionItem)]
                if not items and self.errors:
                    last_rule, last_exc = self.errors[-1]
                    if last_rule is rule:
                        items = [
                            ConversionItem(
                                sigma_id=_sigma_key(rule),
                                sigma_title=rule.title,
                                skipped=True,
                                skip_reason=str(last_exc),
                            )
                        ]
                        self.skipped.extend(items)
                queries.extend(items)
            except SigmaError as exc:
                item = ConversionItem(
                    sigma_id=_sigma_key(rule),
                    sigma_title=rule.title,
                    skipped=True,
                    skip_reason=str(exc),
                )
                self.skipped.append(item)
                if self.collect_errors:
                    self.errors.append((rule, exc))
                else:
                    raise
        finalized = self.finalize(queries, output_format or self.default_format)
        return [item for item in finalized if isinstance(item, ConversionItem)]

    def finalize_output_default(self, queries: list[Any]) -> list[ConversionItem]:
        items: list[ConversionItem] = []
        for query in queries:
            if isinstance(query, ConversionItem):
                items.append(query)
            elif isinstance(query, list):
                items.extend(q for q in query if isinstance(q, ConversionItem))
        return items

    def finalize_query_default(
        self,
        rule: SigmaRule | SigmaCorrelationRule,
        query: Any,
        index: int,
        state: ConversionState,
    ) -> ConversionItem:
        if isinstance(query, ConversionItem):
            return query
        if self.settings.target == "wazuh5":
            if index > 0:
                return ConversionItem(
                    sigma_id=_sigma_key(rule),
                    sigma_title=rule.title,
                    skipped=True,
                    skip_reason="Additional Sigma condition already emitted as Wazuh 5 YAML",
                    target="wazuh5",
                )
            return self._emit_wazuh5(rule)
        if not isinstance(query, DNF):
            raise SigmaConversionError(
                rule, getattr(rule, "source", None), f"Unexpected IR type {type(query)!r}"
            )
        if isinstance(rule, SigmaCorrelationRule):
            raise SigmaConversionError(
                rule, rule.source, "Correlation finalize expected ConversionItem"
            )
        return self._dnf_to_item(rule, query)

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> DNF:
        try:
            return dnf_and_all([self.convert_condition(arg, state) for arg in cond.args])
        except DnfTooLargeError as exc:
            raise SigmaFeatureNotSupportedByBackendError(str(exc)) from exc

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> DNF:
        try:
            return dnf_or_all([self.convert_condition(arg, state) for arg in cond.args])
        except DnfTooLargeError as exc:
            raise SigmaFeatureNotSupportedByBackendError(str(exc)) from exc

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> DNF:
        inner = self.convert_condition(cond.args[0], state)
        try:
            return dnf_not(inner)
        except DnfTooLargeError as exc:
            raise SigmaFeatureNotSupportedByBackendError(str(exc)) from exc

    def convert_condition_as_in_expression(
        self, cond: ConditionOR | ConditionAND, state: ConversionState
    ) -> DNF:
        args = [
            arg
            for arg in cond.args
            if isinstance(arg, ConditionFieldEqualsValueExpression)
        ]
        if not args:
            return DNF.empty()
        field = args[0].field
        patterns: list[str] = []
        negate = False
        for arg in args:
            lit_dnf = self.convert_condition_field_eq_val(arg, state)
            for term in lit_dnf.terms:
                for lit in term:
                    patterns.append(lit.pattern)
                    negate = lit.negate
        pattern = join_alternatives(patterns) if isinstance(cond, ConditionOR) else None
        if isinstance(cond, ConditionAND):
            return dnf_and_all(
                [self.convert_condition_field_eq_val(arg, state) for arg in args]
            )
        return DNF.atom(
            Literal(field=field, pattern=pattern or "", negate=negate, kind=MatchKind.PCRE2)
        )

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DNF:
        assert isinstance(cond.value, SigmaString)
        ci = not isinstance(cond.value, SigmaCasedString)
        return DNF.atom(
            Literal(
                field=cond.field,
                pattern=sigma_string_to_pcre2(cond.value, case_insensitive=ci),
                case_sensitive=not ci,
            )
        )

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DNF:
        assert isinstance(cond.value, SigmaString)
        return DNF.atom(
            Literal(
                field=cond.field,
                pattern=sigma_string_to_pcre2(cond.value, case_insensitive=False),
                case_sensitive=True,
            )
        )

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DNF:
        assert isinstance(cond.value, SigmaNumber)
        return DNF.atom(
            Literal(field=cond.field, pattern=rf"^{cond.value.number}$", case_sensitive=True)
        )

    def convert_condition_field_eq_val_bool(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DNF:
        assert isinstance(cond.value, SigmaBool)
        token = "true" if cond.value.boolean else "false"
        return DNF.atom(
            Literal(field=cond.field, pattern=rf"(?i)^{token}$|{int(cond.value.boolean)}")
        )

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DNF:
        assert isinstance(cond.value, SigmaRegularExpression)
        return DNF.atom(
            Literal(field=cond.field, pattern=sigma_regex_to_pcre2(cond.value))
        )

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DNF:
        assert isinstance(cond.value, SigmaCIDRExpression)
        return DNF.atom(Literal(field=cond.field, pattern=cidr_to_pcre2(cond.value)))

    def convert_condition_field_eq_val_null(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DNF:
        return DNF.atom(Literal(field=cond.field, pattern="^$", kind=MatchKind.PCRE2))

    def convert_condition_field_exists(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DNF:
        return DNF.atom(Literal(field=cond.field, pattern=".", kind=MatchKind.EXISTS))

    def convert_condition_field_not_exists(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DNF:
        return DNF.atom(Literal(field=cond.field, pattern=".", kind=MatchKind.NOT_EXISTS))

    def convert_condition_field_eq_val_timestamp_part(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DNF:
        raise SigmaFeatureNotSupportedByBackendError(
            "Timestamp-part comparisons are not expressible in Wazuh XML field matches."
        )

    def convert_condition_field_compare_op_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DNF:
        raise SigmaFeatureNotSupportedByBackendError(
            "Numeric comparison modifiers (lt/lte/gt/gte) have no Wazuh XML equivalent."
        )

    def convert_condition_field_eq_field(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DNF:
        raise SigmaFeatureNotSupportedByBackendError(
            "Field-to-field comparisons are not supported by Wazuh analysisd rules."
        )

    def convert_condition_field_eq_query_expr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DNF:
        raise SigmaFeatureNotSupportedByBackendError(
            "Sigma query expressions cannot be mapped to Wazuh XML."
        )

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> DNF:
        assert isinstance(cond.value, SigmaString)
        return DNF.atom(
            Literal(
                field=None,
                pattern=sigma_string_to_pcre2(cond.value),
                kind=MatchKind.KEYWORD,
            )
        )

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> DNF:
        assert isinstance(cond.value, SigmaNumber)
        return DNF.atom(
            Literal(field=None, pattern=str(cond.value.number), kind=MatchKind.KEYWORD)
        )

    def convert_condition_val_re(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> DNF:
        assert isinstance(cond.value, SigmaRegularExpression)
        return DNF.atom(
            Literal(
                field=None,
                pattern=sigma_regex_to_pcre2(cond.value),
                kind=MatchKind.KEYWORD,
            )
        )

    def convert_condition_query_expr(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> DNF:
        raise SigmaFeatureNotSupportedByBackendError(
            "Standalone query expressions cannot be mapped to Wazuh XML."
        )

    def convert_correlation_event_count_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: str | None = None,
        method: str = "default",
    ) -> list[ConversionItem]:
        if self.settings.target == "wazuh5":
            raise SigmaConversionError(
                rule,
                rule.source,
                "Wazuh 5.x Security Analytics does not support correlation rules.",
            )
        return [convert_event_count(self, rule)]

    def convert_correlation_value_count_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: str | None = None,
        method: str = "default",
    ) -> list[ConversionItem]:
        raise SigmaConversionError(rule, rule.source, unsupported_message(rule))

    def convert_correlation_temporal_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: str | None = None,
        method: str = "default",
    ) -> list[ConversionItem]:
        raise SigmaConversionError(rule, rule.source, unsupported_message(rule))

    def convert_correlation_temporal_ordered_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: str | None = None,
        method: str = "default",
    ) -> list[ConversionItem]:
        raise SigmaConversionError(rule, rule.source, unsupported_message(rule))

    def convert_correlation_extended_temporal_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: str | None = None,
        method: str = "default",
    ) -> list[ConversionItem]:
        raise SigmaConversionError(
            rule,
            rule.source,
            "Extended temporal correlation is not expressible in Wazuh XML.",
        )

    def convert_correlation_extended_temporal_ordered_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: str | None = None,
        method: str = "default",
    ) -> list[ConversionItem]:
        raise SigmaConversionError(
            rule,
            rule.source,
            "Extended ordered temporal correlation is not expressible in Wazuh XML.",
        )

    def convert_correlation_value_sum_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: str | None = None,
        method: str = "default",
    ) -> list[ConversionItem]:
        raise SigmaConversionError(rule, rule.source, unsupported_message(rule))

    def convert_correlation_value_avg_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: str | None = None,
        method: str = "default",
    ) -> list[ConversionItem]:
        raise SigmaConversionError(rule, rule.source, unsupported_message(rule))

    def convert_correlation_value_percentile_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: str | None = None,
        method: str = "default",
    ) -> list[ConversionItem]:
        raise SigmaConversionError(rule, rule.source, unsupported_message(rule))

    def convert_correlation_value_median_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: str | None = None,
        method: str = "default",
    ) -> list[ConversionItem]:
        raise SigmaConversionError(rule, rule.source, unsupported_message(rule))

    def attribution(self, rule: SigmaRule | SigmaCorrelationRule) -> str:
        return attribution_comment(
            title=rule.title,
            sigma_id=str(rule.id or rule.name or "-"),
            author=rule.author or "-",
            date=str(rule.date or "-"),
            references=list(rule.references or []),
            falsepositives=list(rule.falsepositives or []),
        )

    def _dnf_to_item(self, rule: SigmaRule, dnf: DNF) -> ConversionItem:
        sigma_id = _sigma_key(rule)
        warnings: list[str] = []
        terms = dnf.terms
        if dnf.is_empty():
            return ConversionItem(
                sigma_id=sigma_id,
                sigma_title=rule.title,
                skipped=True,
                skip_reason="Condition tree reduced to an empty (unsatisfiable) DNF.",
            )
        entry = self.catalog.match_logsource(rule.logsource)
        if entry is None:
            msg = (
                f"No logsource mapping for product={rule.logsource.product!r} "
                f"category={rule.logsource.category!r} service={rule.logsource.service!r}"
            )
            if self.settings.strict:
                return ConversionItem(
                    sigma_id=sigma_id, sigma_title=rule.title, skipped=True, skip_reason=msg
                )
            warnings.append(msg)
            entry = LogsourceEntrySpec(groups=["sigma"])
        status_group = None
        if rule.status is not None:
            status_group = self.catalog.status_groups.get(rule.status.name.lower())
        wazuh_rules: list[WazuhRule] = []
        level = self.catalog.severity.for_name(
            rule.level.name.lower() if rule.level is not None else None
        )
        mitre = mitre_ids_from_tags(rule.tags)
        comment = self.attribution(rule)
        groups = list(entry.groups)
        if status_group:
            groups.append(status_group)
        extra = [
            Literal(field=name, pattern=pattern)
            for name, pattern in entry.extra_fields.items()
        ]
        for index, term in enumerate(terms):
            key = f"{sigma_id}#{index}"
            rule_id = self.allocator.allocate(key, title=rule.title)
            fields = extra + sorted(term, key=lambda lit: (lit.field or "", lit.pattern))
            xml_rule = WazuhRule(
                rule_id=rule_id,
                level=level,
                description=rule.title,
                if_sid=entry.if_sid,
                if_group=entry.if_group,
                decoded_as=entry.decoded_as,
                program_name=entry.program_name,
                fields=fields,
                mitre_ids=mitre,
                groups=groups,
                comments=[comment],
                options=["no_full_log"],
                sigma_key=key,
                warnings=warnings,
            )
            if self.settings.fp_ignore:
                xml_rule.warnings.append(
                    "falsepositives requested as exclusions; free-text FP notes cannot be "
                    "turned into reliable Wazuh negate rules and stay in the XML comment."
                )
            wazuh_rules.append(xml_rule)
        return ConversionItem(
            sigma_id=sigma_id,
            sigma_title=rule.title,
            rules=wazuh_rules,
            warnings=warnings,
        )

    def _emit_wazuh5(self, rule: SigmaRule | SigmaCorrelationRule) -> ConversionItem:
        if isinstance(rule, SigmaCorrelationRule):
            return ConversionItem(
                sigma_id=_sigma_key(rule),
                sigma_title=rule.title,
                skipped=True,
                skip_reason="Wazuh 5.x does not support Sigma correlation rules.",
                target="wazuh5",
            )
        payload = rule.to_dict()
        payload["converted_with"] = "Sigmwah"
        payload["wazuh_target"] = "wazuh5"
        payload["note"] = (
            "Experimental Wazuh 5.x Sigma YAML. Fields were mapped by the Sigmwah "
            "pipeline. Correlation, if_sid chaining, and numeric Wazuh IDs are not used."
        )
        text = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
        return ConversionItem(
            sigma_id=_sigma_key(rule),
            sigma_title=rule.title,
            target="wazuh5",
            wazuh5_yaml=text,
            warnings=[
                "wazuh5 output is experimental; Wazuh 5.0 is beta and uses WCS-validated fields."
            ],
        )


def _sigma_key(rule: SigmaRule | SigmaCorrelationRule) -> str:
    if rule.id is not None:
        return str(rule.id)
    if rule.name:
        return str(rule.name)
    return str(rule.title)
