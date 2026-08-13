from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

from experiments.common import canonical_json, sha256_bytes


NANO_USD = 1_000_000_000
USD_CENT_NANOS = 10_000_000


def _canonical_quote_arguments(value: Any) -> Any:
    """Normalize JSON-equivalent arguments before deriving a quote identity."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("quote arguments must use finite JSON numbers")
        if value == 0.0:
            return 0
        if value.is_integer():
            return int(value)
        return value
    if isinstance(value, dict):
        return {str(key): _canonical_quote_arguments(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_quote_arguments(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class PriceQuote:
    schema_version: str
    quote_id: str
    suite: str
    tool_name: str
    service_class: str
    merchant_id: str
    scenario: str
    currency: str
    amount_nanos: int
    amount_usd: str
    pricing_unit: str
    usage_formula: str
    observed_usage: dict[str, Any]
    pricing_source: str
    snapshot_date: str
    tariff_config_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MarketTariff:
    """Frozen deterministic quote adapter for AgentDojo paid tools."""

    def __init__(self, config: dict[str, Any], config_sha256: str) -> None:
        self.config = config
        self.config_sha256 = config_sha256
        self.schema_version = str(config["schema_version"])
        self.snapshot_date = str(config["snapshot_date"])
        self.currency = str(config["currency"])
        self.tariffs = dict(config["tariffs"])
        self.tool_mappings = dict(config["tool_mappings"])
        self.scenario_multipliers_milli = {
            str(key): int(value)
            for key, value in config["scenario_multipliers_milli"].items()
        }
        self.uniform_control_nanos = int(config["uniform_price_control_nanos"])
        self.budget_reserve_nanos = int(config["budget_reserve_nanos"])
        self.quote_quantum_nanos: int | None = None
        self.economic_amount_grid = "source-nanos-v1"
        self.source_config_sha256 = config_sha256

    @classmethod
    def load(cls, path: str | Path) -> "MarketTariff":
        source = Path(path).read_bytes()
        value = yaml.safe_load(source)
        if not isinstance(value, dict):
            raise TypeError("market tariff must be a YAML object")
        return cls(value, sha256_bytes(source))

    def with_economic_amount_grid(self, grid: str) -> "MarketTariff":
        """Return a tariff with a shared, versioned economic amount grid.

        The grid is a workload property, applied before any condition sees a
        quote.  It is deliberately not an AP2 adapter conversion.
        """
        if grid == "source-nanos-v1":
            return self
        if grid != "usd-cent-v1":
            raise ValueError(f"unsupported economic amount grid: {grid}")
        if self.currency.upper() != "USD":
            raise ValueError("usd-cent-v1 requires a USD tariff")
        projected = MarketTariff(
            self.config,
            sha256_bytes(
                canonical_json(
                    {
                        "source_config_sha256": self.source_config_sha256,
                        "economic_amount_grid": grid,
                        "quote_quantum_nanos": USD_CENT_NANOS,
                    }
                ).encode("utf-8")
            ),
        )
        projected.quote_quantum_nanos = USD_CENT_NANOS
        projected.economic_amount_grid = grid
        projected.source_config_sha256 = self.source_config_sha256
        return projected

    def _project_amount(self, amount_nanos: int) -> int:
        if amount_nanos <= 0:
            raise ValueError("paid quote amount must be positive")
        quantum = self.quote_quantum_nanos
        if quantum is None:
            return amount_nanos
        return math.ceil(amount_nanos / quantum) * quantum

    def tariff_id(self, suite: str, tool_name: str) -> str:
        suite_map = self.tool_mappings.get(suite)
        if not isinstance(suite_map, dict) or tool_name not in suite_map:
            raise KeyError(f"unmapped market tariff: {suite}.{tool_name}")
        return str(suite_map[tool_name])

    def tariff_for(self, suite: str, tool_name: str) -> dict[str, Any]:
        tariff_id = self.tariff_id(suite, tool_name)
        tariff = self.tariffs.get(tariff_id)
        if not isinstance(tariff, dict):
            raise KeyError(f"unknown tariff id: {tariff_id}")
        return tariff

    @staticmethod
    def _sequence_size(value: Any) -> int:
        return len(value) if isinstance(value, (list, tuple)) else 0

    @staticmethod
    def _payload_bytes(arguments: dict[str, Any], fields: Iterable[str]) -> int:
        return sum(len(str(arguments.get(field, "")).encode("utf-8")) for field in fields)

    def _nominal_amount(self, tariff: dict[str, Any], arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        kind = str(tariff["formula_kind"])
        base = int(tariff.get("base_nanos", 0))
        usage: dict[str, Any] = {}
        if kind == "fixed":
            amount = base
        elif kind == "per_list_item":
            field = str(tariff["argument_field"])
            count = max(1, self._sequence_size(arguments.get(field)))
            usage = {"argument_field": field, "item_count": count}
            amount = base + count * int(tariff["unit_nanos"])
        elif kind == "payload_kib":
            fields = [str(value) for value in tariff["argument_fields"]]
            payload_bytes = self._payload_bytes(arguments, fields)
            units = max(1, math.ceil(payload_bytes / 1024))
            usage = {"argument_fields": fields, "payload_bytes": payload_bytes, "kib_units": units}
            amount = base + units * int(tariff["unit_nanos"])
        elif kind == "recipient_and_payload":
            recipients = sum(
                self._sequence_size(arguments.get(field))
                for field in ("recipients", "cc", "bcc")
            )
            recipients = max(1, recipients)
            payload_bytes = self._payload_bytes(arguments, ("subject", "body"))
            usage = {"recipient_count": recipients, "payload_bytes": payload_bytes}
            amount = recipients * int(tariff["recipient_nanos"])
            amount += math.ceil(
                payload_bytes * int(tariff.get("per_gib_nanos", 0)) / (1024**3)
            )
        elif kind == "fixed_plus_bps":
            raw_business_amount = arguments.get(str(tariff["argument_field"]), 0.0)
            business_amount = max(
                0.0,
                float(0.0 if raw_business_amount is None else raw_business_amount),
            )
            variable_nanos = math.ceil(
                business_amount * NANO_USD * int(tariff["basis_points"]) / 10_000
            )
            usage = {"business_amount_usd": business_amount, "basis_points": int(tariff["basis_points"])}
            amount = base + variable_nanos
        else:
            raise ValueError(f"unsupported tariff formula: {kind}")
        return max(1, amount), usage

    def quote(
        self,
        *,
        suite: str,
        tool_name: str,
        service_class: str,
        merchant_id: str,
        arguments: dict[str, Any],
        scenario: str = "nominal",
    ) -> PriceQuote:
        tariff = self.tariff_for(suite, tool_name)
        nominal, usage = self._nominal_amount(tariff, arguments)
        quote_arguments = _canonical_quote_arguments(arguments)
        if scenario == "uniform_control":
            amount = self.uniform_control_nanos
        else:
            if scenario not in self.scenario_multipliers_milli:
                raise ValueError(f"unknown market scenario: {scenario}")
            amount = max(
                1,
                math.ceil(nominal * self.scenario_multipliers_milli[scenario] / 1000),
            )
        amount = self._project_amount(amount)
        payload = {
            "schema_version": "minmandate-price-quote-v1",
            "suite": suite,
            "tool_name": tool_name,
            "service_class": service_class,
            "merchant_id": merchant_id,
            "scenario": scenario,
            "amount_nanos": amount,
            "arguments": quote_arguments,
            "tariff_config_sha256": self.config_sha256,
        }
        quote_id = sha256_bytes(canonical_json(payload).encode("utf-8"))
        return PriceQuote(
            schema_version="minmandate-price-quote-v1",
            quote_id=quote_id,
            suite=suite,
            tool_name=tool_name,
            service_class=service_class,
            merchant_id=merchant_id,
            scenario=scenario,
            currency=self.currency,
            amount_nanos=amount,
            amount_usd=f"{amount / NANO_USD:.9f}",
            pricing_unit=str(tariff["pricing_unit"]),
            usage_formula=str(tariff["usage_formula"]),
            observed_usage=usage,
            pricing_source=str(tariff["pricing_source"]),
            snapshot_date=self.snapshot_date,
            tariff_config_sha256=self.config_sha256,
        )

    def authorization_budget(
        self,
        suite: str,
        authorizations: Iterable[dict[str, Any]],
        policy_tools: dict[str, Any],
    ) -> int:
        """Budget only the initial authorization; contingency slots add no budget."""
        suite_tools = policy_tools.get(suite, {})
        total = 0
        for authorization in authorizations:
            service_class = str(authorization["service_class"])
            merchant_id = str(authorization["merchant_id"])
            candidates = []
            for tool_name, rule in suite_tools.items():
                if not bool(rule.get("paid")):
                    continue
                if str(rule["service_class"]) != service_class or str(rule["merchant_id"]) != merchant_id:
                    continue
                tariff = self.tariff_for(suite, str(tool_name))
                candidates.append(self._project_amount(int(tariff["budget_nominal_nanos"])))
            if not candidates:
                raise KeyError(f"no tariff candidate for {suite}:{service_class}:{merchant_id}")
            total += int(authorization["capacity"]) * max(candidates)
        return total + self.budget_reserve_nanos

    def max_nominal_for_scope(
        self,
        suite: str,
        service_class: str,
        merchant_id: str | None,
        policy_tools: dict[str, Any],
    ) -> int:
        candidates = []
        for tool_name, rule in policy_tools.get(suite, {}).items():
            if not bool(rule.get("paid")) or str(rule["service_class"]) != service_class:
                continue
            if merchant_id is not None and str(rule["merchant_id"]) != merchant_id:
                continue
            candidates.append(
                self._project_amount(
                    int(self.tariff_for(suite, str(tool_name))["budget_nominal_nanos"])
                )
            )
        if not candidates:
            raise KeyError(f"no nominal tariff for {suite}:{service_class}:{merchant_id}")
        return max(candidates)

    def coverage(self, policy_tools: dict[str, Any]) -> dict[str, Any]:
        expected = {
            f"{suite}.{tool_name}"
            for suite, tools in policy_tools.items()
            for tool_name, rule in tools.items()
            if bool(rule.get("paid"))
        }
        mapped = {
            f"{suite}.{tool_name}"
            for suite, tools in self.tool_mappings.items()
            for tool_name in tools
        }
        dormant_unbilled = sorted(mapped - expected)
        return {
            "expected": len(expected),
            "mapped": len(mapped),
            "missing": sorted(expected - mapped),
            # Public tariff observations may remain in the catalog even when
            # the payment policy makes a read-only tool zero-budget. They are
            # dormant metadata, not stale coverage failures.
            "stale": [],
            "dormant_unbilled_mappings": dormant_unbilled,
            "complete": not (expected - mapped),
        }


@dataclass(frozen=True, slots=True)
class MerchantCompatibilityQuote:
    """Condition-independent quote for the appendix compatibility fixture."""

    schema_version: str
    quote_id: str
    plan_episode_id: str
    plan_call_id: str
    quote_key: str
    merchant: str
    merchant_id: str
    tool: str
    service_class: str
    currency: str
    amount_nanos: int
    amount_usd: str
    credit_units: int
    pricing_mode: str
    pricing_unit: str
    usage_formula: str
    observed_usage: dict[str, Any]
    pricing_sources: list[dict[str, Any]]
    snapshot_date: str
    normalization_status: str
    normalization_note: str
    tariff_config_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MerchantCompatibilityTariff:
    """Frozen representative pricing for offline merchant protocol fixtures.

    This tariff is intentionally separate from ``MarketTariff``. Its quotes are
    appendix protocol-fixture inputs and are never AgentDojo formal-utility
    observations.
    """

    def __init__(self, config: dict[str, Any], config_sha256: str) -> None:
        self.config = config
        self.config_sha256 = config_sha256
        self.snapshot_date = str(config["snapshot_date"])
        self.currency = str(config["currency"])
        self.quotes = dict(config["quotes"])
        self.sources: dict[str, dict[str, Any]] = {}
        source_groups = config.get("pricing_sources")
        if not isinstance(source_groups, dict):
            raise TypeError("merchant compatibility pricing_sources must be a mapping")
        for merchant, rows in source_groups.items():
            if not isinstance(rows, list):
                raise TypeError(f"pricing_sources.{merchant} must be a list")
            for row in rows:
                if not isinstance(row, dict) or not row.get("source_id"):
                    raise TypeError(f"invalid pricing source metadata for {merchant}")
                source_id = str(row["source_id"])
                if source_id in self.sources:
                    raise ValueError(f"duplicate pricing source id: {source_id}")
                self.sources[source_id] = {"merchant": str(merchant), **dict(row)}

    @classmethod
    def load(cls, path: str | Path) -> "MerchantCompatibilityTariff":
        source = Path(path).read_bytes()
        value = yaml.safe_load(source)
        if not isinstance(value, dict):
            raise TypeError("merchant compatibility tariff must be a YAML object")
        return cls(value, sha256_bytes(source))

    @staticmethod
    def _measured_units(arguments: dict[str, Any], component: dict[str, Any]) -> int:
        field = str(component["argument_field"])
        measure = str(component["measure"])
        value = arguments.get(field)
        if measure == "sequence_length":
            if value is None:
                return 0
            if not isinstance(value, (list, tuple)):
                raise TypeError(f"argument {field} must be a sequence")
            return len(value)
        if measure == "non_negative_integer":
            if isinstance(value, bool):
                raise TypeError(f"argument {field} must be an integer, not bool")
            units = int(0 if value is None else value)
            if units < 0:
                raise ValueError(f"argument {field} must be non-negative")
            return units
        raise ValueError(f"unsupported compatibility usage measure: {measure}")

    def _amount_and_usage(
        self,
        tariff: dict[str, Any],
        arguments: dict[str, Any],
    ) -> tuple[int, int, dict[str, Any]]:
        kind = str(tariff["formula_kind"])
        if kind == "free":
            return 0, 0, {"components": []}
        if kind == "fixed":
            amount = int(tariff["amount_nanos"])
            credits = int(tariff.get("credit_units", 0))
            if amount < 0 or credits < 0:
                raise ValueError("fixed compatibility prices must be non-negative")
            return amount, credits, {"components": []}
        if kind != "argument_usage":
            raise ValueError(f"unsupported compatibility tariff formula: {kind}")

        amount = int(tariff.get("base_nanos", 0))
        credits = int(tariff.get("base_credit_units", 0))
        observed: list[dict[str, Any]] = []
        for component_value in tariff.get("components", []):
            if not isinstance(component_value, dict):
                raise TypeError("compatibility tariff components must be mappings")
            component = dict(component_value)
            units = self._measured_units(arguments, component)
            unit_nanos = int(component["unit_nanos"])
            unit_credits = int(component.get("credit_units", 0))
            if unit_nanos < 0 or unit_credits < 0:
                raise ValueError("compatibility usage rates must be non-negative")
            amount += units * unit_nanos
            credits += units * unit_credits
            observed.append(
                {
                    "argument_field": str(component["argument_field"]),
                    "measure": str(component["measure"]),
                    "units": units,
                    "unit_nanos": unit_nanos,
                    "credit_units_per_unit": unit_credits,
                }
            )
        if amount < 0 or credits < 0:
            raise ValueError("compatibility quote totals must be non-negative")
        return amount, credits, {"components": observed}

    def quote(
        self,
        *,
        plan_episode_id: str,
        plan_call_id: str,
        quote_key: str,
        arguments: dict[str, Any],
    ) -> MerchantCompatibilityQuote:
        raw = self.quotes.get(quote_key)
        if not isinstance(raw, dict):
            raise KeyError(f"unknown merchant compatibility quote: {quote_key}")
        tariff = dict(raw)
        amount, credit_units, observed = self._amount_and_usage(tariff, arguments)
        source_ids = [str(value) for value in tariff.get("source_ids", [])]
        missing_sources = [value for value in source_ids if value not in self.sources]
        if missing_sources:
            raise KeyError(f"unknown compatibility pricing sources: {missing_sources}")
        payload = {
            "schema_version": "minmandate-merchant-compatibility-quote-v1",
            "plan_episode_id": plan_episode_id,
            "plan_call_id": plan_call_id,
            "quote_key": quote_key,
            "merchant": str(tariff["merchant"]),
            "merchant_id": str(tariff["merchant_id"]),
            "tool": str(tariff["tool"]),
            "service_class": str(tariff["service_class"]),
            "amount_nanos": amount,
            "credit_units": credit_units,
            "arguments": arguments,
            "tariff_config_sha256": self.config_sha256,
        }
        return MerchantCompatibilityQuote(
            schema_version="minmandate-merchant-compatibility-quote-v1",
            quote_id=sha256_bytes(canonical_json(payload).encode("utf-8")),
            plan_episode_id=plan_episode_id,
            plan_call_id=plan_call_id,
            quote_key=quote_key,
            merchant=str(tariff["merchant"]),
            merchant_id=str(tariff["merchant_id"]),
            tool=str(tariff["tool"]),
            service_class=str(tariff["service_class"]),
            currency=self.currency,
            amount_nanos=amount,
            amount_usd=f"{amount / NANO_USD:.9f}",
            credit_units=credit_units,
            pricing_mode=str(tariff["formula_kind"]),
            pricing_unit=str(tariff["pricing_unit"]),
            usage_formula=str(tariff["usage_formula"]),
            observed_usage=observed,
            pricing_sources=[dict(self.sources[value]) for value in source_ids],
            snapshot_date=self.snapshot_date,
            normalization_status=str(tariff["normalization_status"]),
            normalization_note=str(tariff["normalization_note"]),
            tariff_config_sha256=self.config_sha256,
        )
