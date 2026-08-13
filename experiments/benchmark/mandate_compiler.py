from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx

from experiments.common import canonical_json, sha256_bytes
from experiments.offline_boundary import (
    assert_experiment_environment,
    validate_local_endpoint,
)
from experiments.pricing import MarketTariff


def _local_post(url: str, **kwargs: Any) -> httpx.Response:
    # The controlled system-overhead benchmark only consumes the canonical
    # approval-artifact data classes below.  Keep the optional model-client
    # dependency at the actual network boundary so an offline benchmark does
    # not require an unused HTTP stack.
    import httpx

    assert_experiment_environment()
    validate_local_endpoint(url)
    return httpx.post(url, **kwargs)


COMPILER_PROMPT_VERSION = "minmandate-compiler-v3"
COMPILER_SYSTEM_PROMPT = """Compile the natural-language agent task into a payment mandate draft.
Use only paid entries from the supplied authorization catalog. Free tools may appear in outcome
evidence_tools but never require payment authorization. Select the smallest set of paid service-class
and merchant pairs needed for the task. Capacity is an upper bound on paid calls for that pair, not
an ordered tool plan. Also compile only the user's explicit externally observable outcomes. Each
outcome must name the catalog tools whose successful result can serve as evidence. Do not infer a
future call sequence and do not add unstated goals. Return JSON only:
{"authorizations":[{"service_class":"...","merchant_id":"...","capacity":1}],
 "required_outcomes":[{"id":"...","description":"...","evidence_tools":["..."]}]}
An empty list is valid when the task needs no paid tool. Do not add explanations.
"""


@dataclass(frozen=True, slots=True)
class MandateDraft:
    schema_version: str
    workflow_id: str
    compiler_backend: str
    compiler_model: str
    status: str
    authorizations: list[dict[str, Any]]
    required_outcomes: list[dict[str, Any]]
    slots: list[dict[str, Any]]
    allowed_merchants: list[str]
    budget: int
    expiry: int
    canonical_draft_sha256: str
    raw_output_sha256: str | None
    compiler_latency_ms: float
    error: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


USER_APPROVAL_SCHEMA_VERSION = "minmandate-user-approval-v1"
DETERMINISTIC_TEST_SIGNATURE_SCHEME = "hmac-sha256-deterministic-test-user-v1"
FORMAL_SIGNATURE_SCHEME = "ed25519-v1"
FORMAL_APPROVAL_EVIDENCE_CLASSES = {"human", "adjudicated"}


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()


@dataclass(frozen=True, slots=True)
class ApprovedSlot:
    service_class: str
    merchant_id: str
    capacity: int
    expiry: int

    @classmethod
    def from_value(cls, value: dict[str, Any]) -> "ApprovedSlot":
        slot = cls(
            service_class=str(value.get("service_class", "")),
            merchant_id=str(value.get("merchant_id", "")),
            capacity=int(value.get("capacity", 0)),
            expiry=int(value.get("expiry", -1)),
        )
        if not slot.service_class or not slot.merchant_id:
            raise ValueError("approval slots require class and merchant")
        if slot.capacity <= 0 or slot.expiry < 0:
            raise ValueError("approval slots require positive capacity and non-negative expiry")
        return slot

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class UserApprovalArtifact:
    """Canonical, signed evidence for one exact approved policy.

    Final-v2 treats approval as an experimental input and labels the locally
    signed artifact as a preapproved evaluation assumption. Human/adjudicated
    evidence classes remain supported only for legacy studies that measure
    approval formation itself.
    """

    schema_version: str
    workflow_id: str
    approval_kind: str
    approval_sequence: int
    parent_approval_sha256: str | None
    decision: str
    slots: tuple[ApprovedSlot, ...]
    base_budget: int
    reserve_budget: int
    approved_budget: int
    allowed_service_classes: tuple[str, ...]
    allowed_merchants: tuple[str, ...]
    funding_eligible_slot_indices: tuple[int, ...]
    funding_coverage: int
    amendment_limit: int
    settlement_authorized: bool
    evidence_class: str
    signer_id: str
    evidence_locator: str
    frozen_evidence_sha256: str
    signature_scheme: str
    signer_public_key_b64: str | None
    canonical_input_sha256: str
    signature: str

    def canonical_input(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "workflow_id": self.workflow_id,
            "approval_kind": self.approval_kind,
            "approval_sequence": self.approval_sequence,
            "parent_approval_sha256": self.parent_approval_sha256,
            "decision": self.decision,
            "ordered_slots": [slot.to_dict() for slot in self.slots],
            "budget": {
                "base": self.base_budget,
                "reserve": self.reserve_budget,
                "approved_total": self.approved_budget,
            },
            "allowed_service_classes": list(self.allowed_service_classes),
            "allowed_merchants": list(self.allowed_merchants),
            "funding_eligibility": {
                "eligible_slot_indices": list(self.funding_eligible_slot_indices),
                "coverage": self.funding_coverage,
            },
            "amendment_limit": self.amendment_limit,
            "settlement_authorization": {
                "authorized": self.settlement_authorized,
                "mode": "none_local_experiment",
            },
            "approval_evidence": {
                "evidence_class": self.evidence_class,
                "signer_id": self.signer_id,
                "evidence_locator": self.evidence_locator,
                "frozen_evidence_sha256": self.frozen_evidence_sha256,
                "signature_scheme": self.signature_scheme,
                "signer_public_key_b64": self.signer_public_key_b64,
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.canonical_input(),
            "canonical_input_sha256": self.canonical_input_sha256,
            "signature": self.signature,
            "artifact_sha256": self.artifact_sha256,
        }

    @property
    def artifact_sha256(self) -> str:
        unsigned = {
            **self.canonical_input(),
            "canonical_input_sha256": self.canonical_input_sha256,
            "signature": self.signature,
        }
        return sha256_bytes(canonical_json(unsigned).encode("utf-8"))

    @classmethod
    def deterministic_test_user(
        cls,
        *,
        workflow_id: str,
        slots: list[dict[str, Any]],
        base_budget: int,
        reserve_budget: int,
        approved_budget: int,
        allowed_service_classes: list[str],
        allowed_merchants: list[str],
        funding_eligible_slot_indices: list[int],
        funding_coverage: int,
        amendment_limit: int,
        approval_kind: str = "initial",
        approval_sequence: int = 0,
        parent_approval_sha256: str | None = None,
        signer_id: str = "deterministic-test-user:development-fixture-v1",
    ) -> "UserApprovalArtifact":
        evidence_locator = "test-fixture://deterministic-test-user/development-fixture-v1"
        evidence_sha256 = sha256_bytes(evidence_locator.encode("utf-8"))
        values = {
            "schema_version": USER_APPROVAL_SCHEMA_VERSION,
            "workflow_id": str(workflow_id),
            "approval_kind": str(approval_kind),
            "approval_sequence": int(approval_sequence),
            "parent_approval_sha256": parent_approval_sha256,
            "decision": "approve",
            "slots": tuple(ApprovedSlot.from_value(slot) for slot in slots),
            "base_budget": int(base_budget),
            "reserve_budget": int(reserve_budget),
            "approved_budget": int(approved_budget),
            "allowed_service_classes": tuple(str(value) for value in allowed_service_classes),
            "allowed_merchants": tuple(str(value) for value in allowed_merchants),
            "funding_eligible_slot_indices": tuple(
                int(value) for value in funding_eligible_slot_indices
            ),
            "funding_coverage": int(funding_coverage),
            "amendment_limit": int(amendment_limit),
            "settlement_authorized": False,
            "evidence_class": "deterministic_test_user",
            "signer_id": str(signer_id),
            "evidence_locator": evidence_locator,
            "frozen_evidence_sha256": evidence_sha256,
            "signature_scheme": DETERMINISTIC_TEST_SIGNATURE_SCHEME,
            "signer_public_key_b64": None,
        }
        provisional = cls(**values, canonical_input_sha256="", signature="")
        encoded = canonical_json(provisional.canonical_input()).encode("utf-8")
        input_sha256 = sha256_bytes(encoded)
        test_key = hashlib.sha256(
            ("minmandate-test-only-user-signer-v1\0" + signer_id).encode("utf-8")
        ).digest()
        signature = hmac.new(test_key, encoded, hashlib.sha256).hexdigest()
        artifact = cls(
            **values,
            canonical_input_sha256=input_sha256,
            signature=signature,
        )
        artifact.validate()
        return artifact

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "UserApprovalArtifact":
        try:
            budget = value["budget"]
            funding = value["funding_eligibility"]
            settlement = value["settlement_authorization"]
            evidence = value["approval_evidence"]
            artifact = cls(
                schema_version=str(value["schema_version"]),
                workflow_id=str(value["workflow_id"]),
                approval_kind=str(value["approval_kind"]),
                approval_sequence=int(value["approval_sequence"]),
                parent_approval_sha256=(
                    str(value["parent_approval_sha256"])
                    if value.get("parent_approval_sha256") is not None
                    else None
                ),
                decision=str(value["decision"]),
                slots=tuple(
                    ApprovedSlot.from_value(slot) for slot in value["ordered_slots"]
                ),
                base_budget=int(budget["base"]),
                reserve_budget=int(budget["reserve"]),
                approved_budget=int(budget["approved_total"]),
                allowed_service_classes=tuple(
                    str(item) for item in value["allowed_service_classes"]
                ),
                allowed_merchants=tuple(str(item) for item in value["allowed_merchants"]),
                funding_eligible_slot_indices=tuple(
                    int(item) for item in funding["eligible_slot_indices"]
                ),
                funding_coverage=int(funding["coverage"]),
                amendment_limit=int(value["amendment_limit"]),
                settlement_authorized=bool(settlement["authorized"]),
                evidence_class=str(evidence["evidence_class"]),
                signer_id=str(evidence["signer_id"]),
                evidence_locator=str(evidence["evidence_locator"]),
                frozen_evidence_sha256=str(evidence["frozen_evidence_sha256"]),
                signature_scheme=str(evidence["signature_scheme"]),
                signer_public_key_b64=(
                    str(evidence["signer_public_key_b64"])
                    if evidence.get("signer_public_key_b64") is not None
                    else None
                ),
                canonical_input_sha256=str(value["canonical_input_sha256"]),
                signature=str(value["signature"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed UserApprovalArtifact: {exc}") from exc
        claimed_artifact_sha256 = value.get("artifact_sha256")
        if claimed_artifact_sha256 is not None and claimed_artifact_sha256 != artifact.artifact_sha256:
            raise ValueError("UserApprovalArtifact artifact hash mismatch")
        return artifact

    def validate(
        self,
        *,
        require_formal_evidence: bool = False,
        evidence_base: Path | None = None,
    ) -> None:
        if self.schema_version != USER_APPROVAL_SCHEMA_VERSION:
            raise ValueError("unsupported UserApprovalArtifact schema")
        if not self.workflow_id or self.decision != "approve":
            raise ValueError("approval artifact must explicitly approve one workflow")
        if self.approval_kind not in {"initial", "amendment"}:
            raise ValueError("approval_kind must be initial or amendment")
        if self.approval_kind == "initial":
            if self.approval_sequence != 0 or self.parent_approval_sha256 is not None:
                raise ValueError("initial approval must have sequence zero and no parent")
        elif self.approval_sequence != 1 or not _is_sha256(self.parent_approval_sha256):
            raise ValueError("the single amendment must have sequence one and a parent")
        if self.base_budget < 0 or self.reserve_budget < 0:
            raise ValueError("approval budgets must be non-negative")
        if self.base_budget + self.reserve_budget != self.approved_budget:
            raise ValueError("base and reserve budgets do not equal approved total")
        if sum(slot.capacity for slot in self.slots) != self.approved_budget:
            raise ValueError("ordered slot capacity does not equal approved budget")
        if tuple(sorted(set(self.allowed_service_classes))) != self.allowed_service_classes:
            raise ValueError("allowed service classes must be sorted and unique")
        if tuple(sorted(set(self.allowed_merchants))) != self.allowed_merchants:
            raise ValueError("allowed merchants must be sorted and unique")
        if any(slot.service_class not in self.allowed_service_classes for slot in self.slots):
            raise ValueError("approval slot widens allowed service classes")
        if any(slot.merchant_id not in self.allowed_merchants for slot in self.slots):
            raise ValueError("approval slot widens allowed merchants")
        eligible = self.funding_eligible_slot_indices
        if eligible != tuple(sorted(set(eligible))) or any(
            index < 0 or index >= len(self.slots) for index in eligible
        ):
            raise ValueError("funding-eligible slot indices are not canonical")
        eligible_capacity = sum(self.slots[index].capacity for index in eligible)
        if self.funding_coverage < 0 or self.funding_coverage > eligible_capacity:
            raise ValueError("funding coverage exceeds eligible slot capacity")
        if self.amendment_limit not in {0, 1}:
            raise ValueError("approval permits at most one amendment")
        if self.settlement_authorized:
            raise ValueError("experiment approval cannot authorize real settlement")
        if not _is_sha256(self.frozen_evidence_sha256):
            raise ValueError("approval lacks frozen evidence hash")
        encoded = canonical_json(self.canonical_input()).encode("utf-8")
        if sha256_bytes(encoded) != self.canonical_input_sha256:
            raise ValueError("approval canonical input hash mismatch")
        if self.signature_scheme == DETERMINISTIC_TEST_SIGNATURE_SCHEME:
            if self.evidence_class != "deterministic_test_user":
                raise ValueError("test signer must be labeled deterministic_test_user")
            test_key = hashlib.sha256(
                ("minmandate-test-only-user-signer-v1\0" + self.signer_id).encode("utf-8")
            ).digest()
            expected = hmac.new(test_key, encoded, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, self.signature):
                raise ValueError("deterministic test-user signature mismatch")
        elif self.signature_scheme == FORMAL_SIGNATURE_SCHEME:
            if not self.signer_public_key_b64:
                raise ValueError("formal approval lacks signer public key")
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

                public_key = Ed25519PublicKey.from_public_bytes(
                    base64.b64decode(self.signer_public_key_b64, validate=True)
                )
                public_key.verify(
                    base64.b64decode(self.signature, validate=True), encoded
                )
            except Exception as exc:
                raise ValueError(f"formal approval signature verification failed: {exc}") from exc
        else:
            raise ValueError("unsupported approval signature scheme")
        if require_formal_evidence:
            if self.evidence_class not in FORMAL_APPROVAL_EVIDENCE_CLASSES:
                raise ValueError("formal harness requires human/adjudicated approval evidence")
            if self.signature_scheme != FORMAL_SIGNATURE_SCHEME:
                raise ValueError("formal harness rejects deterministic test-user signatures")
            if evidence_base is None:
                raise ValueError("formal approval requires a frozen evidence base path")
            evidence_path = Path(self.evidence_locator)
            if not evidence_path.is_absolute():
                evidence_path = evidence_base / evidence_path
            if not evidence_path.is_file():
                raise ValueError(f"frozen approval evidence is absent: {evidence_path}")
            if sha256_bytes(evidence_path.read_bytes()) != self.frozen_evidence_sha256:
                raise ValueError("frozen approval evidence hash mismatch")


def compiler_prompt_sha256() -> str:
    return sha256_bytes(COMPILER_SYSTEM_PROMPT.encode("utf-8"))


def catalog_for_suite(policy_tools: dict[str, Any], suite: str) -> list[dict[str, Any]]:
    return [
        {
            "tool_name": str(tool_name),
            "service_class": str(rule["service_class"]),
            "merchant_id": str(rule["merchant_id"]),
            "paid": bool(rule.get("paid")),
        }
        for tool_name, rule in sorted(policy_tools.get(suite, {}).items())
    ]


def _extract_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    value = json.loads(stripped)
    if not isinstance(value, dict):
        raise ValueError("compiler output must be a JSON object")
    return value


def _validate_authorizations(
    value: dict[str, Any],
    catalog: list[dict[str, Any]],
    max_initial_slots: int,
) -> list[dict[str, Any]]:
    raw = value.get("authorizations")
    if not isinstance(raw, list):
        raise ValueError("compiler output requires an authorizations array")
    allowed = {
        (row["service_class"], row["merchant_id"])
        for row in catalog
        if bool(row.get("paid", True))
    }
    free = {
        (row["service_class"], row["merchant_id"])
        for row in catalog
        if not bool(row.get("paid", True))
    }
    merged: dict[tuple[str, str], int] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("authorization entries must be objects")
        key = (str(item.get("service_class", "")), str(item.get("merchant_id", "")))
        capacity = int(item.get("capacity", 0))
        if key in free:
            continue
        if key not in allowed:
            raise ValueError(f"authorization is outside the paid-tool catalog: {key}")
        if capacity <= 0:
            raise ValueError("authorization capacity must be positive")
        merged[key] = merged.get(key, 0) + capacity
    if sum(merged.values()) > max_initial_slots:
        raise ValueError("compiler output exceeds max_initial_slots")
    return [
        {"service_class": key[0], "merchant_id": key[1], "capacity": capacity}
        for key, capacity in sorted(merged.items())
    ]


def _validate_required_outcomes(
    value: dict[str, Any], catalog: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    raw = value.get("required_outcomes")
    if not isinstance(raw, list):
        raise ValueError("compiler output requires a required_outcomes array")
    tool_names = {str(row["tool_name"]) for row in catalog if row.get("tool_name")}
    outcomes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("required_outcomes entries must be objects")
        outcome_id = str(item.get("id", "")).strip()
        description = str(item.get("description", "")).strip()
        evidence_tools = item.get("evidence_tools")
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", outcome_id):
            raise ValueError(f"invalid required outcome id: {outcome_id!r}")
        if outcome_id in seen:
            raise ValueError(f"duplicate required outcome id: {outcome_id}")
        if not description:
            raise ValueError("required outcome description must be non-empty")
        if not isinstance(evidence_tools, list) or not evidence_tools:
            raise ValueError("required outcome must name at least one evidence tool")
        normalized_tools = sorted({str(name) for name in evidence_tools})
        if not set(normalized_tools).issubset(tool_names):
            raise ValueError("required outcome names a tool outside the supplied catalog")
        seen.add(outcome_id)
        outcomes.append(
            {
                "id": outcome_id,
                "description": description,
                "evidence_tools": normalized_tools,
            }
        )
    if len(outcomes) > 16:
        raise ValueError("compiler output exceeds 16 required outcomes")
    return outcomes


def compile_mandate(
    *,
    workflow_id: str,
    task_prompt: str,
    catalog: list[dict[str, Any]],
    backend: str,
    model_id: str,
    base_url: str,
    seed: int,
    amount: int,
    expiry: int,
    max_initial_slots: int,
    suite: str | None = None,
    policy_tools: dict[str, Any] | None = None,
    tariff: MarketTariff | None = None,
) -> MandateDraft:
    started = time.perf_counter_ns()
    raw_output: str | None = None
    error: str | None = None
    authorizations: list[dict[str, Any]] = []
    required_outcomes: list[dict[str, Any]] = []
    compiler_backend = "catalog_smoke_control" if backend == "ground_truth" else "ollama_json"
    try:
        if backend == "ground_truth":
            pairs = {
                (str(entry["service_class"]), str(entry["merchant_id"]))
                for entry in catalog
                if bool(entry.get("paid", True))
            }
            value = {
                "authorizations": [
                    {"service_class": service_class, "merchant_id": merchant_id, "capacity": 1}
                    for service_class, merchant_id in sorted(pairs)
                ],
                "required_outcomes": [],
            }
        elif backend == "ollama_openai_compatible":
            native_base = base_url.removesuffix("/v1").rstrip("/")
            response = _local_post(
                f"{native_base}/api/chat",
                json={
                    "model": model_id,
                    "messages": [
                        {"role": "system", "content": COMPILER_SYSTEM_PROMPT},
                        {
                            "role": "user",
                            "content": canonical_json(
                                {"task": task_prompt, "authorization_catalog": catalog}
                            ),
                        },
                    ],
                    "format": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["authorizations", "required_outcomes"],
                        "properties": {
                            "authorizations": {
                                "type": "array",
                                "maxItems": max_initial_slots,
                                "items": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["service_class", "merchant_id", "capacity"],
                                    "properties": {
                                        "service_class": {"enum": sorted({row["service_class"] for row in catalog})},
                                        "merchant_id": {"enum": sorted({row["merchant_id"] for row in catalog})},
                                        "capacity": {"type": "integer", "minimum": 1, "maximum": max_initial_slots},
                                    },
                                },
                            },
                            "required_outcomes": {
                                "type": "array",
                                "maxItems": 16,
                                "items": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["id", "description", "evidence_tools"],
                                    "properties": {
                                        "id": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,63}$"},
                                        "description": {"type": "string", "minLength": 1},
                                        "evidence_tools": {
                                            "type": "array",
                                            "minItems": 1,
                                            "uniqueItems": True,
                                            "items": {"enum": sorted({str(row["tool_name"]) for row in catalog if row.get("tool_name")})},
                                        },
                                    },
                                },
                            },
                        },
                    },
                    "stream": False,
                    "keep_alive": -1,
                    "options": {
                        "temperature": 0,
                        "top_p": 1,
                        "seed": seed,
                        "num_ctx": 8192,
                    },
                },
                timeout=600.0,
                trust_env=False,
            )
            response.raise_for_status()
            raw_output = str(response.json().get("message", {}).get("content", ""))
            value = _extract_json(raw_output)
        else:
            raise ValueError(f"unsupported mandate compiler backend: {backend}")
        authorizations = _validate_authorizations(value, catalog, max_initial_slots)
        required_outcomes = _validate_required_outcomes(value, catalog)
        status = "compiled"
    except Exception as exc:
        status = "rejected"
        error = f"{type(exc).__name__}: {exc}"
    slots = [dict(row) for row in authorizations]
    budget = sum(int(row["capacity"]) for row in authorizations) * amount
    if tariff is not None:
        if suite is None or policy_tools is None:
            raise ValueError("suite and policy_tools are required with a market tariff")
        budget = tariff.authorization_budget(suite, authorizations, policy_tools)
    canonical = {
        "schema_version": "minmandate-draft-v3",
        "authorizations": authorizations,
        "required_outcomes": required_outcomes,
        "budget": budget,
        "expiry": expiry,
    }
    return MandateDraft(
        schema_version="minmandate-draft-v3",
        workflow_id=workflow_id,
        compiler_backend=compiler_backend,
        compiler_model=model_id,
        status=status,
        authorizations=authorizations,
        required_outcomes=required_outcomes,
        slots=slots,
        allowed_merchants=sorted({str(row["merchant_id"]) for row in authorizations}),
        budget=int(canonical["budget"]),
        expiry=expiry,
        canonical_draft_sha256=sha256_bytes(canonical_json(canonical).encode("utf-8")),
        raw_output_sha256=(sha256_bytes(raw_output.encode("utf-8")) if raw_output else None),
        compiler_latency_ms=(time.perf_counter_ns() - started) / 1_000_000.0,
        error=error,
    )
