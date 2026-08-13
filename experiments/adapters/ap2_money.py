"""Explicit Table 1 USD-nanos to AP2 v0.2 money representation adapter.

The benchmark tariff remains authoritative in nanos.  AP2 Amount and
AmountRange fields use ISO-4217 minor units, so every paid quote must first be
exactly representable in that unit before conversion.  The AP2
SDK's recurring ``Budget.max`` field is a major-unit float; its adapter value
is accepted only when the official evaluator's ``int(max * 10**exponent)``
round-trip equals the same canonical minor-unit budget.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from decimal import Decimal
import math


NANOS_PER_CURRENCY_UNIT = 1_000_000_000
ISO_4217_MINOR_EXPONENTS = {"USD": 2}


@dataclass(frozen=True, slots=True)
class CanonicalMoney:
    currency: str
    minor_units: int
    minor_exponent: int
    source_nanos: int
    nanos_per_minor_unit: int
    rounding_rule: str
    rounding_delta_nanos: int

    def audit_row(self) -> dict[str, int | str]:
        return asdict(self)


def _minor_exponent(currency: str) -> int:
    normalized = currency.upper()
    try:
        return ISO_4217_MINOR_EXPONENTS[normalized]
    except KeyError as exc:
        raise ValueError(f"unsupported ISO-4217 currency for AP2 adapter: {currency}") from exc


def nanos_per_minor_unit(currency: str = "USD") -> int:
    """Return the integer nanos represented by one AP2 minor unit."""
    return 10 ** (9 - _minor_exponent(currency))


def nanos_to_ap2_minor_units(source_nanos: int, currency: str = "USD") -> CanonicalMoney:
    """Exactly convert a positive nanos quote to AP2 minor units.

    Conversion is rejected when the nanos amount is not an integral number of
    ISO-4217 minor units. This preserves the shared economic trace without
    rounding a quote or broadening a budget.
    """
    if not isinstance(source_nanos, int) or source_nanos <= 0:
        raise ValueError("source_nanos must be a positive integer paid quote")
    normalized = currency.upper()
    exponent = _minor_exponent(normalized)
    nanos_per_minor = nanos_per_minor_unit(normalized)
    if source_nanos % nanos_per_minor:
        raise ValueError(
            "AP2 quote is not exactly representable in "
            f"{normalized} minor units: {source_nanos} nanos"
        )
    minor_units = source_nanos // nanos_per_minor
    return CanonicalMoney(
        currency=normalized,
        minor_units=minor_units,
        minor_exponent=exponent,
        source_nanos=source_nanos,
        nanos_per_minor_unit=nanos_per_minor,
        rounding_rule="exact(source_nanos / nanos_per_minor_unit)",
        rounding_delta_nanos=0,
    )


def ap2_budget_major_units(money: CanonicalMoney) -> float:
    """Encode a canonical minor-unit budget for AP2's float Budget.max field.

    The official v0.2 verifier calculates ``int(max * 10**minor_exponent)``.
    When Python binary float lands one ULP below the intended value, move one
    ULP upward only if that exact verifier calculation recovers the unchanged
    canonical minor-unit amount; otherwise fail rather than broaden a budget.
    """
    scale = 10**money.minor_exponent
    candidate = float(Decimal(money.minor_units) / Decimal(scale))
    if int(candidate * scale) == money.minor_units:
        return candidate
    adjusted = math.nextafter(candidate, math.inf)
    if int(adjusted * scale) == money.minor_units:
        return adjusted
    raise ValueError(
        "AP2 Budget.max float cannot round-trip canonical minor units: "
        f"{money.minor_units} {money.currency} minor units"
    )


def minor_units_to_nanos(money: CanonicalMoney) -> int:
    """Return the nanos amount represented by the AP2 minor-unit value."""
    return money.minor_units * money.nanos_per_minor_unit
