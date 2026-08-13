from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from experiments.benchmark.mandate_compiler import (
    ApprovedSlot,
    FORMAL_APPROVAL_EVIDENCE_CLASSES,
    FORMAL_SIGNATURE_SCHEME,
    USER_APPROVAL_SCHEMA_VERSION,
    UserApprovalArtifact,
)
from experiments.common import canonical_json, sha256_bytes


ApprovalMode = Literal["development", "preapproved", "formal"]
LOCAL_TEST_USER_SIGNER_PREFIX = "local-test-user:"
EVALUATION_USER_SIGNER_PREFIX = "evaluation-user:"
LOCAL_TEST_USER_SIGNATURE_SCHEME = FORMAL_SIGNATURE_SCHEME
PREAPPROVED_EVALUATION_EVIDENCE_CLASS = "preapproved_evaluation_assumption"
SETTLEMENT_SCHEME = "schnorr-bls12-381-sha256-v1"
DOMAIN_SETTLEMENT_KEY_ATTESTATION = "MM-settlement-key-attestation-v1"
DOMAIN_LOCAL_SETTLEMENT_AUTHORIZATION = "MM-local-settlement-authz-v1"
DOMAIN_LOCAL_RECEIPT = "MM-local-receipt-v1"
DOMAIN_LOCAL_RECEIPT_ID = "MM-local-receipt-id-v1"
DOMAIN_ACCEPT = "MM-accept-v1"
DOMAIN_REQUEST = "mm-accept-and-consume-request"
DOMAIN_MERCHANT_VIEW = "MM-view-M-v1"
DOMAIN_REDEMPTION_VIEW = "MM-view-R-preack-v1"

_BLS12_381_BASE_MODULUS = int(
    "1a0111ea397fe69a4b1ba7b6434bacd7"
    "64774b84f38512bf6730d2a0f6b0f624"
    "1eabfffeb153ffffb9feffffffffaaab",
    16,
)
_BLS12_381_SCALAR_MODULUS = int(
    "73eda753299d7d483339d80809a1d805"
    "53bda402fffe5bfeffffffff00000001",
    16,
)
_G1_GENERATOR_HEX = (
    "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac5"
    "86c55e83ff97a1aeffb3af00adb22c6bb"
)
_JACOBIAN_INFINITY = (1, 1, 0)


class MinMandateContractError(ValueError):
    pass


def _strict_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise MinMandateContractError(f"{label} must be a {qualifier} integer")
    return value


def _sha256_hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise MinMandateContractError(f"{label} must be a lowercase SHA-256 digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise MinMandateContractError(
            f"{label} must be a lowercase SHA-256 digest"
        ) from exc
    if value != value.lower():
        raise MinMandateContractError(f"{label} must be a lowercase SHA-256 digest")
    return value


def normalize_approval_slots(
    slots: list[dict[str, Any]], *, default_expiry: int | None = None
) -> list[dict[str, Any]]:
    if not isinstance(slots, list) or not slots:
        raise MinMandateContractError("approval slots must be a nonempty ordered list")
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(slots):
        if not isinstance(raw, dict):
            raise MinMandateContractError(f"approval slot {index} must be an object")
        service_class = raw.get("service_class")
        merchant_id = raw.get("merchant_id")
        if not isinstance(service_class, str) or not service_class:
            raise MinMandateContractError(
                f"approval slot {index} requires a nonempty service_class"
            )
        if not isinstance(merchant_id, str) or not merchant_id:
            raise MinMandateContractError(
                f"approval slot {index} requires a nonempty merchant_id"
            )
        expiry_value = raw.get("expiry", default_expiry)
        normalized.append(
            {
                "service_class": service_class,
                "merchant_id": merchant_id,
                "capacity": _strict_int(
                    raw.get("capacity"), f"approval slot {index} capacity", minimum=1
                ),
                "expiry": _strict_int(
                    expiry_value, f"approval slot {index} expiry", minimum=1
                ),
            }
        )
    return normalized


def _canonical_policy_parameters(
    *,
    workflow_id: str,
    slots: list[dict[str, Any]],
    base_budget: int,
    reserve_budget: int,
    approved_budget: int,
    allowed_service_classes: list[str] | None,
    allowed_merchants: list[str] | None,
    funding_eligible_slot_indices: list[int],
    funding_coverage: int,
    amendment_limit: int,
    approval_kind: str,
    approval_sequence: int,
    parent_approval_sha256: str | None,
) -> dict[str, Any]:
    if not isinstance(workflow_id, str) or not workflow_id:
        raise MinMandateContractError("approval workflow_id must be nonempty")
    normalized_slots = normalize_approval_slots(slots)
    base = _strict_int(base_budget, "approval base budget")
    reserve = _strict_int(reserve_budget, "approval reserve budget")
    approved = _strict_int(approved_budget, "approval approved budget", minimum=1)
    if base + reserve != approved:
        raise MinMandateContractError(
            "approval base and reserve budgets must equal approved budget"
        )
    derived_classes = sorted({slot["service_class"] for slot in normalized_slots})
    derived_merchants = sorted({slot["merchant_id"] for slot in normalized_slots})
    classes = derived_classes if allowed_service_classes is None else list(allowed_service_classes)
    merchants = derived_merchants if allowed_merchants is None else list(allowed_merchants)
    if classes != derived_classes:
        raise MinMandateContractError(
            "approval allowed service classes differ from ordered slots"
        )
    if merchants != derived_merchants:
        raise MinMandateContractError(
            "approval allowed merchants differ from ordered slots"
        )
    eligible = [
        _strict_int(value, "funding-eligible slot index")
        for value in funding_eligible_slot_indices
    ]
    if eligible != sorted(set(eligible)) or any(
        index >= len(normalized_slots) for index in eligible
    ):
        raise MinMandateContractError(
            "funding-eligible slot indices must be sorted, unique, and in range"
        )
    coverage = _strict_int(funding_coverage, "funding coverage", minimum=1)
    if coverage < approved:
        raise MinMandateContractError(
            "funding coverage must independently cover the approved budget"
        )
    amendment = _strict_int(amendment_limit, "approval amendment limit")
    if amendment > 1:
        raise MinMandateContractError("approval permits at most one amendment")
    sequence = _strict_int(approval_sequence, "approval sequence")
    if approval_kind == "initial":
        if sequence != 0 or parent_approval_sha256 is not None:
            raise MinMandateContractError(
                "initial approval requires sequence zero and no parent"
            )
    elif approval_kind == "amendment":
        if sequence != 1 or parent_approval_sha256 is None:
            raise MinMandateContractError(
                "the sole amendment requires sequence one and a parent"
            )
        _sha256_hex(parent_approval_sha256, "parent approval")
    else:
        raise MinMandateContractError("approval kind must be initial or amendment")
    return {
        "workflow_id": workflow_id,
        "slots": normalized_slots,
        "base_budget": base,
        "reserve_budget": reserve,
        "approved_budget": approved,
        "allowed_service_classes": classes,
        "allowed_merchants": merchants,
        "funding_eligible_slot_indices": eligible,
        "funding_coverage": coverage,
        "amendment_limit": amendment,
        "approval_kind": approval_kind,
        "approval_sequence": sequence,
        "parent_approval_sha256": parent_approval_sha256,
    }


def _approval_signature_bytes(artifact: UserApprovalArtifact) -> bytes:
    if artifact.signature_scheme != FORMAL_SIGNATURE_SCHEME:
        raise MinMandateContractError("canonical approval signature must be Ed25519")
    if not artifact.signer_public_key_b64:
        raise MinMandateContractError("canonical approval lacks an Ed25519 public key")
    encoded = canonical_json(artifact.canonical_input()).encode("utf-8")
    if sha256_bytes(encoded) != artifact.canonical_input_sha256:
        raise MinMandateContractError("approval canonical input digest mismatch")
    try:
        public_key = base64.b64decode(artifact.signer_public_key_b64, validate=True)
        signature = base64.b64decode(artifact.signature, validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, encoded)
    except Exception as exc:
        raise MinMandateContractError(
            f"approval Ed25519 signature verification failed: {exc}"
        ) from exc
    return public_key


def _frozen_evidence_path(
    artifact: UserApprovalArtifact, evidence_base: Path | None
) -> Path:
    if evidence_base is None:
        raise MinMandateContractError("formal approval requires a frozen evidence base")
    path = Path(artifact.evidence_locator)
    if not path.is_absolute():
        path = evidence_base / path
    path = path.resolve()
    if not path.is_file():
        raise MinMandateContractError(f"frozen approval evidence is absent: {path}")
    if sha256_bytes(path.read_bytes()) != artifact.frozen_evidence_sha256:
        raise MinMandateContractError("frozen approval evidence digest mismatch")
    return path


def validate_canonical_user_approval(
    artifact: UserApprovalArtifact,
    *,
    mode: ApprovalMode | None = None,
    evidence_base: Path | None = None,
    require_local_test_user: bool = True,
) -> UserApprovalArtifact:
    if not isinstance(artifact, UserApprovalArtifact):
        raise MinMandateContractError("approval must be a UserApprovalArtifact")
    if artifact.schema_version != USER_APPROVAL_SCHEMA_VERSION or artifact.decision != "approve":
        raise MinMandateContractError("approval schema or decision is invalid")
    parameters = _canonical_policy_parameters(
        workflow_id=artifact.workflow_id,
        slots=[slot.to_dict() for slot in artifact.slots],
        base_budget=artifact.base_budget,
        reserve_budget=artifact.reserve_budget,
        approved_budget=artifact.approved_budget,
        allowed_service_classes=list(artifact.allowed_service_classes),
        allowed_merchants=list(artifact.allowed_merchants),
        funding_eligible_slot_indices=list(artifact.funding_eligible_slot_indices),
        funding_coverage=artifact.funding_coverage,
        amendment_limit=artifact.amendment_limit,
        approval_kind=artifact.approval_kind,
        approval_sequence=artifact.approval_sequence,
        parent_approval_sha256=artifact.parent_approval_sha256,
    )
    if tuple(ApprovedSlot.from_value(value) for value in parameters["slots"]) != artifact.slots:
        raise MinMandateContractError("approval ordered slots are not canonical")
    if artifact.settlement_authorized:
        raise MinMandateContractError("approval cannot authorize a real settlement")
    _sha256_hex(artifact.frozen_evidence_sha256, "frozen approval evidence")
    public_key = _approval_signature_bytes(artifact)
    effective_mode = mode
    if (
        effective_mode is None
        and artifact.evidence_class == PREAPPROVED_EVALUATION_EVIDENCE_CLASS
    ):
        effective_mode = "preapproved"
    expected_signer_prefix = (
        EVALUATION_USER_SIGNER_PREFIX
        if effective_mode == "preapproved"
        else LOCAL_TEST_USER_SIGNER_PREFIX
    )
    if require_local_test_user and not artifact.signer_id.startswith(
        expected_signer_prefix
    ):
        raise MinMandateContractError(
            "canonical approval carries an invalid signer label for its evidence class"
        )
    if hashlib.sha256(public_key).hexdigest() == "0" * 64:
        raise MinMandateContractError("invalid all-zero approval public-key digest")
    if effective_mode == "development":
        if artifact.evidence_class != "deterministic_test_user":
            raise MinMandateContractError(
                "development approval must be labeled deterministic_test_user"
            )
    elif effective_mode == "preapproved":
        if artifact.evidence_class != PREAPPROVED_EVALUATION_EVIDENCE_CLASS:
            raise MinMandateContractError(
                "preapproved evaluation input has the wrong evidence class"
            )
    elif effective_mode == "formal":
        if artifact.evidence_class not in FORMAL_APPROVAL_EVIDENCE_CLASSES:
            raise MinMandateContractError(
                "formal approval requires frozen human/adjudicated evidence"
            )
        _frozen_evidence_path(artifact, evidence_base)
    return artifact


def _source_policy_matches(
    source: UserApprovalArtifact,
    expected: dict[str, Any],
    *,
    allow_workflow_rebind: bool,
) -> None:
    comparisons = {
        "slots": (
            [slot.to_dict() for slot in source.slots],
            expected["slots"],
        ),
        "base_budget": (source.base_budget, expected["base_budget"]),
        "reserve_budget": (source.reserve_budget, expected["reserve_budget"]),
        "approved_budget": (source.approved_budget, expected["approved_budget"]),
        "allowed_service_classes": (
            list(source.allowed_service_classes),
            expected["allowed_service_classes"],
        ),
        "allowed_merchants": (
            list(source.allowed_merchants),
            expected["allowed_merchants"],
        ),
        "funding_eligible_slot_indices": (
            list(source.funding_eligible_slot_indices),
            expected["funding_eligible_slot_indices"],
        ),
        "funding_coverage": (source.funding_coverage, expected["funding_coverage"]),
        "amendment_limit": (source.amendment_limit, expected["amendment_limit"]),
        "approval_kind": (source.approval_kind, expected["approval_kind"]),
        "approval_sequence": (
            source.approval_sequence,
            expected["approval_sequence"],
        ),
    }
    if not allow_workflow_rebind:
        comparisons["workflow_id"] = (source.workflow_id, expected["workflow_id"])
    mismatches = {
        key: {"source": actual, "expected": wanted}
        for key, (actual, wanted) in comparisons.items()
        if actual != wanted
    }
    if mismatches:
        raise MinMandateContractError(
            f"approval evidence differs from canonical policy: {mismatches}"
        )


def load_or_create_user_approval(
    *,
    workflow_id: str,
    slots: list[dict[str, Any]],
    base_budget: int,
    reserve_budget: int,
    approved_budget: int,
    funding_eligible_slot_indices: list[int],
    funding_coverage: int,
    amendment_limit: int,
    mode: ApprovalMode,
    artifact: UserApprovalArtifact | dict[str, Any] | None = None,
    allowed_service_classes: list[str] | None = None,
    allowed_merchants: list[str] | None = None,
    approval_kind: str = "initial",
    approval_sequence: int = 0,
    parent_approval_sha256: str | None = None,
    evidence_base: Path | None = None,
    allow_workflow_rebind: bool = False,
) -> UserApprovalArtifact:
    expected = _canonical_policy_parameters(
        workflow_id=workflow_id,
        slots=slots,
        base_budget=base_budget,
        reserve_budget=reserve_budget,
        approved_budget=approved_budget,
        allowed_service_classes=allowed_service_classes,
        allowed_merchants=allowed_merchants,
        funding_eligible_slot_indices=funding_eligible_slot_indices,
        funding_coverage=funding_coverage,
        amendment_limit=amendment_limit,
        approval_kind=approval_kind,
        approval_sequence=approval_sequence,
        parent_approval_sha256=parent_approval_sha256,
    )
    source = (
        UserApprovalArtifact.from_dict(artifact)
        if isinstance(artifact, dict)
        else artifact
    )
    if mode in {"preapproved", "formal"} and source is None:
        raise MinMandateContractError(
            f"{mode} approval requires a pre-signed artifact"
        )
    if source is not None:
        validate_canonical_user_approval(
            source,
            mode=mode,
            evidence_base=evidence_base,
            require_local_test_user=False,
        )
        _source_policy_matches(
            source, expected, allow_workflow_rebind=allow_workflow_rebind
        )
        if mode in {"preapproved", "formal"}:
            return source
        evidence_class = source.evidence_class
        evidence_locator = source.evidence_locator
        frozen_evidence_sha256 = source.frozen_evidence_sha256
    else:
        evidence_class = "deterministic_test_user"
        evidence_locator = (
            "test-fixture://local-test-user/development-deterministic-v1"
        )
        frozen_evidence_sha256 = sha256_bytes(evidence_locator.encode("utf-8"))

    signer_id = "local-test-user:development-deterministic-v1"
    seed = hashlib.sha256(
        ("minmandate-local-test-user-ed25519-v1\0" + signer_id).encode("utf-8")
    ).digest()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    values = {
        "schema_version": USER_APPROVAL_SCHEMA_VERSION,
        "workflow_id": expected["workflow_id"],
        "approval_kind": expected["approval_kind"],
        "approval_sequence": expected["approval_sequence"],
        "parent_approval_sha256": expected["parent_approval_sha256"],
        "decision": "approve",
        "slots": tuple(ApprovedSlot.from_value(slot) for slot in expected["slots"]),
        "base_budget": expected["base_budget"],
        "reserve_budget": expected["reserve_budget"],
        "approved_budget": expected["approved_budget"],
        "allowed_service_classes": tuple(expected["allowed_service_classes"]),
        "allowed_merchants": tuple(expected["allowed_merchants"]),
        "funding_eligible_slot_indices": tuple(
            expected["funding_eligible_slot_indices"]
        ),
        "funding_coverage": expected["funding_coverage"],
        "amendment_limit": expected["amendment_limit"],
        "settlement_authorized": False,
        "evidence_class": evidence_class,
        "signer_id": signer_id,
        "evidence_locator": evidence_locator,
        "frozen_evidence_sha256": frozen_evidence_sha256,
        "signature_scheme": LOCAL_TEST_USER_SIGNATURE_SCHEME,
        "signer_public_key_b64": base64.b64encode(public_key).decode("ascii"),
    }
    provisional = UserApprovalArtifact(
        **values, canonical_input_sha256="", signature=""
    )
    encoded = canonical_json(provisional.canonical_input()).encode("utf-8")
    approval = UserApprovalArtifact(
        **values,
        canonical_input_sha256=sha256_bytes(encoded),
        signature=base64.b64encode(private_key.sign(encoded)).decode("ascii"),
    )
    return validate_canonical_user_approval(
        approval, mode=mode, evidence_base=evidence_base
    )


def approval_wire_fields(artifact: UserApprovalArtifact) -> dict[str, Any]:
    validate_canonical_user_approval(artifact, require_local_test_user=False)
    return {
        "user_approval_artifact": artifact.to_dict(),
        "user_approval_artifact_sha256": artifact.artifact_sha256,
        "budget": {
            "base": artifact.base_budget,
            "reserve": artifact.reserve_budget,
            "approved_total": artifact.approved_budget,
        },
        "approved_budget": artifact.approved_budget,
        "funding_reserve": artifact.reserve_budget,
        "funding": {
            "eligible_slot_indices": list(
                artifact.funding_eligible_slot_indices
            ),
            "coverage": artifact.funding_coverage,
        },
        "allowed_service_classes": list(artifact.allowed_service_classes),
        "allowed_merchants": list(artifact.allowed_merchants),
        "amendment_limit": artifact.amendment_limit,
        "settlement_authorization": {
            "authorized": False,
            "mode": "none_local_experiment",
        },
    }


def _canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def _hash_bytes(domain: str, parts: list[bytes]) -> bytes:
    digest = hashlib.sha256()
    digest.update(domain.encode("utf-8"))
    digest.update(b"\0")
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _hash_to_scalar(domain: str, parts: list[bytes]) -> int:
    wide = _hash_bytes(f"{domain}:0", parts) + _hash_bytes(
        f"{domain}:1", parts
    )
    return int.from_bytes(wide, "little") % _BLS12_381_SCALAR_MODULUS


def _jacobian_double(point: tuple[int, int, int]) -> tuple[int, int, int]:
    x, y, z = point
    if z == 0 or y == 0:
        return _JACOBIAN_INFINITY
    modulus = _BLS12_381_BASE_MODULUS
    xx = x * x % modulus
    yy = y * y % modulus
    yyyy = yy * yy % modulus
    s = 2 * ((x + yy) ** 2 - xx - yyyy) % modulus
    m = 3 * xx % modulus
    x3 = (m * m - 2 * s) % modulus
    y3 = (m * (s - x3) - 8 * yyyy) % modulus
    z3 = ((y + z) ** 2 - yy - z * z) % modulus
    return x3, y3, z3


def _jacobian_add(
    left: tuple[int, int, int], right: tuple[int, int, int]
) -> tuple[int, int, int]:
    if left[2] == 0:
        return right
    if right[2] == 0:
        return left
    modulus = _BLS12_381_BASE_MODULUS
    x1, y1, z1 = left
    x2, y2, z2 = right
    z1z1 = z1 * z1 % modulus
    z2z2 = z2 * z2 % modulus
    u1 = x1 * z2z2 % modulus
    u2 = x2 * z1z1 % modulus
    s1 = y1 * z2 * z2z2 % modulus
    s2 = y2 * z1 * z1z1 % modulus
    if u1 == u2:
        return _jacobian_double(left) if s1 == s2 else _JACOBIAN_INFINITY
    h = (u2 - u1) % modulus
    i = (2 * h) ** 2 % modulus
    j = h * i % modulus
    r = 2 * (s2 - s1) % modulus
    v = u1 * i % modulus
    x3 = (r * r - j - 2 * v) % modulus
    y3 = (r * (v - x3) - 2 * s1 * j) % modulus
    z3 = (((z1 + z2) ** 2 - z1z1 - z2z2) * h) % modulus
    return x3, y3, z3


def _jacobian_multiply(
    point: tuple[int, int, int], scalar: int
) -> tuple[int, int, int]:
    result = _JACOBIAN_INFINITY
    addend = point
    value = scalar
    while value:
        if value & 1:
            result = _jacobian_add(result, addend)
        addend = _jacobian_double(addend)
        value >>= 1
    return result


def _jacobian_equal(
    left: tuple[int, int, int], right: tuple[int, int, int]
) -> bool:
    if left[2] == 0 or right[2] == 0:
        return left[2] == right[2]
    modulus = _BLS12_381_BASE_MODULUS
    left_z2 = left[2] * left[2] % modulus
    right_z2 = right[2] * right[2] % modulus
    return (
        left[0] * right_z2 - right[0] * left_z2
    ) % modulus == 0 and (
        left[1] * right[2] * right_z2
        - right[1] * left[2] * left_z2
    ) % modulus == 0


@lru_cache(maxsize=256)
def _decode_g1(encoded_hex: str) -> tuple[int, int, int]:
    try:
        raw = bytes.fromhex(encoded_hex)
    except (TypeError, ValueError) as exc:
        raise MinMandateContractError("malformed G1 encoding") from exc
    if len(raw) != 48 or not raw[0] & 0x80 or raw[0] & 0x40:
        raise MinMandateContractError("non-canonical or identity G1 encoding")
    sort_flag = bool(raw[0] & 0x20)
    x_bytes = bytearray(raw)
    x_bytes[0] &= 0x1F
    x = int.from_bytes(x_bytes, "big")
    modulus = _BLS12_381_BASE_MODULUS
    if x >= modulus:
        raise MinMandateContractError("non-canonical G1 x-coordinate")
    y_squared = (pow(x, 3, modulus) + 4) % modulus
    y = pow(y_squared, (modulus + 1) // 4, modulus)
    if y * y % modulus != y_squared:
        raise MinMandateContractError("compressed G1 point is not on the curve")
    if (y > (modulus - 1) // 2) != sort_flag:
        y = modulus - y
    point = (x, y, 1)
    if _jacobian_multiply(point, _BLS12_381_SCALAR_MODULUS)[2] != 0:
        raise MinMandateContractError("G1 point is outside the prime-order subgroup")
    return point


def _decode_scalar(encoded_hex: str) -> int:
    try:
        raw = bytes.fromhex(encoded_hex)
    except (TypeError, ValueError) as exc:
        raise MinMandateContractError("malformed scalar encoding") from exc
    if len(raw) != 32:
        raise MinMandateContractError("malformed scalar encoding")
    value = int.from_bytes(raw, "little")
    if value >= _BLS12_381_SCALAR_MODULUS:
        raise MinMandateContractError("non-canonical scalar encoding")
    return value


def _verify_schnorr_signature(
    verification_key: str, statement: dict[str, Any], signature: dict[str, Any]
) -> None:
    if set(signature) != {"R", "z"}:
        raise MinMandateContractError("Schnorr signature fields are not canonical")
    public_point = _decode_g1(verification_key)
    nonce_point = _decode_g1(signature["R"])
    response_scalar = _decode_scalar(signature["z"])
    challenge = _hash_to_scalar(
        "mm-schnorr-signature",
        [
            verification_key.encode("ascii"),
            signature["R"].encode("ascii"),
            _canonical_bytes(statement),
        ],
    )
    generator = _decode_g1(_G1_GENERATOR_HEX)
    left = _jacobian_multiply(generator, response_scalar)
    right = _jacobian_add(
        nonce_point, _jacobian_multiply(public_point, challenge)
    )
    if not _jacobian_equal(left, right):
        raise MinMandateContractError("Schnorr signature verification failed")


SchnorrBatchItem = tuple[str, dict[str, Any], dict[str, Any]]
SchnorrBatchVerifier = Callable[[list[SchnorrBatchItem]], None]


def _parse_signed_record(
    record: Any, *, expected_key: str, expected_domain: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if not isinstance(record, dict) or set(record) != {
        "statement",
        "signature",
        "verification_key",
    }:
        raise MinMandateContractError("signed record fields are not canonical")
    if record["verification_key"] != expected_key:
        raise MinMandateContractError("signed record uses an untrusted key")
    statement = record["statement"]
    if not isinstance(statement, dict) or set(statement) != {"domain", "body"}:
        raise MinMandateContractError("signed statement fields are not canonical")
    if statement["domain"] != expected_domain or not isinstance(
        statement["body"], dict
    ):
        raise MinMandateContractError("signed statement domain or body is invalid")
    signature = record["signature"]
    if not isinstance(signature, dict):
        raise MinMandateContractError("signed record signature is malformed")
    return statement["body"], statement, signature


def _verify_signed_record(
    record: Any, *, expected_key: str, expected_domain: str
) -> dict[str, Any]:
    body, statement, signature = _parse_signed_record(
        record,
        expected_key=expected_key,
        expected_domain=expected_domain,
    )
    _verify_schnorr_signature(expected_key, statement, signature)
    return body


def validate_settlement_trust_anchor(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "scheme",
        "verification_key",
        "verification_key_sha256",
    }:
        raise MinMandateContractError("settlement trust anchor fields are invalid")
    if value["scheme"] != SETTLEMENT_SCHEME:
        raise MinMandateContractError("unsupported settlement trust-anchor scheme")
    key = value["verification_key"]
    if not isinstance(key, str):
        raise MinMandateContractError("settlement trust-anchor key is malformed")
    raw = bytes.fromhex(key)
    _decode_g1(key)
    if hashlib.sha256(raw).hexdigest() != value["verification_key_sha256"]:
        raise MinMandateContractError("settlement trust-anchor key digest mismatch")
    return dict(value)


def validate_startup_network_attestation(
    value: Any, *, expected_path: Path, expected_sha256: str
) -> dict[str, Any]:
    expected = {
        "schema_version": "minmandate-network-boundary-attestation-v2",
        "preload_path": str(expected_path.resolve()),
        "preload_sha256": expected_sha256,
        "loader_mapping_verified": True,
        "af_inet_socket_creation_allowed": True,
        "loopback_udp_connect_allowed": True,
        "nonloopback_udp_connect_denied": True,
        "nonloopback_probe": "192.0.2.1:9/udp-no-payload",
        "denial_errno": "EPERM",
        "network_payload_transmitted": False,
        "live_service_contact_attempted": False,
        "activation_evidence": [
            "loader_mapping",
            "loopback_udp_connect",
            "nonloopback_udp_connect_eperm",
        ],
    }
    if value != expected:
        raise MinMandateContractError(
            f"Rust startup network self-attestation mismatch: {value!r}"
        )
    return dict(value)


def validate_settlement_verification(
    value: Any,
    *,
    trusted_anchor: dict[str, Any],
    workflow_id: str,
    credential_id: str,
    session_id: str,
    issuer_policy_digest_sha256: str,
    schnorr_batch_verifier: SchnorrBatchVerifier | None = None,
    verify_signature: bool = True,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "scheme",
        "verification_key",
        "verification_key_sha256",
        "trust_anchor",
        "key_attestation",
        "key_attestation_sha256",
    }:
        raise MinMandateContractError("settlement verification fields are invalid")
    if value["scheme"] != SETTLEMENT_SCHEME or value["trust_anchor"] != trusted_anchor:
        raise MinMandateContractError("settlement key is not startup-trust-anchored")
    verification_key = value["verification_key"]
    if not isinstance(verification_key, str):
        raise MinMandateContractError("settlement verification key is malformed")
    raw_key = bytes.fromhex(verification_key)
    _decode_g1(verification_key)
    if hashlib.sha256(raw_key).hexdigest() != value["verification_key_sha256"]:
        raise MinMandateContractError("settlement verification-key digest mismatch")
    key_attestation = value["key_attestation"]
    if hashlib.sha256(_canonical_bytes(key_attestation)).hexdigest() != value[
        "key_attestation_sha256"
    ]:
        raise MinMandateContractError("settlement key-attestation digest mismatch")
    body, statement, signature = _parse_signed_record(
        key_attestation,
        expected_key=trusted_anchor["verification_key"],
        expected_domain=DOMAIN_SETTLEMENT_KEY_ATTESTATION,
    )
    if verify_signature:
        if schnorr_batch_verifier is None:
            _verify_schnorr_signature(
                trusted_anchor["verification_key"], statement, signature
            )
        else:
            schnorr_batch_verifier(
                [(trusted_anchor["verification_key"], statement, signature)]
            )
    expected_body = {
        "credential_id": credential_id,
        "session_id": session_id,
        "workflow_id": workflow_id,
        "issuer_policy_digest_sha256": issuer_policy_digest_sha256,
        "settlement_verification_key": verification_key,
        "settlement_verification_key_sha256": value[
            "verification_key_sha256"
        ],
    }
    if body != expected_body:
        raise MinMandateContractError("settlement key attestation binding mismatch")
    return dict(value)


def _view_core(view: dict[str, Any], role: str) -> dict[str, Any]:
    keys = (
        (
            "presentation",
            "ihbbs1_presentation_statement",
            "issuer_hiding_evidence",
            "L",
            "context",
            "q",
            "challenge",
            "certificate",
        )
        if role == "merchant"
        else (
            "presentation",
            "ihbbs1_presentation_statement",
            "issuer_hiding_evidence",
            "L",
            "context",
            "selected_slots",
            "serials",
            "funding_tags",
            "payment_projection",
            "request_projection",
        )
    )
    if any(key not in view for key in keys):
        raise MinMandateContractError(f"{role} view lacks canonical digest fields")
    core = {key: view[key] for key in keys}
    statement = core["ihbbs1_presentation_statement"]
    if not isinstance(statement, dict):
        raise MinMandateContractError(f"{role} IHBBS statement is malformed")
    statement = dict(statement)
    core["ihbbs1_presentation_statement"] = statement
    return core


def _view_digest(core: dict[str, Any], domain: str) -> str:
    unbound = dict(core)
    statement = dict(unbound["ihbbs1_presentation_statement"])
    statement["redemption_binding"] = None
    unbound["ihbbs1_presentation_statement"] = statement
    return _hash_bytes(domain, [_canonical_bytes(unbound)]).hex()


@dataclass(frozen=True, slots=True)
class ValidatedInvokeResponse:
    outcome: Literal["fresh_accept", "idempotent_receipt", "rejected"]
    error_code: str | None
    merchant_execution_key: str | None
    receipt_id: str | None
    settlement_authorization: dict[str, Any] | None
    signed_receipt: dict[str, Any] | None

    @property
    def fresh_accept(self) -> bool:
        return self.outcome == "fresh_accept"

    @property
    def idempotent_receipt(self) -> bool:
        return self.outcome == "idempotent_receipt"

    @property
    def rejected(self) -> bool:
        return self.outcome == "rejected"

    @property
    def authorizes_merchant_result(self) -> bool:
        return self.outcome in {"fresh_accept", "idempotent_receipt"}


def validate_invoke_response(
    response: dict[str, Any],
    *,
    trusted_anchor: dict[str, Any],
    settlement_verification: dict[str, Any],
    issuer_policy_digest_sha256: str,
    workflow_id: str,
    credential_id: str,
    session_id: str,
    approved_budget: int,
    schnorr_batch_verifier: SchnorrBatchVerifier | None = None,
    settlement_verification_prevalidated: bool = False,
) -> ValidatedInvokeResponse:
    if not isinstance(response, dict):
        raise MinMandateContractError("invoke response must be an object")
    if response.get("ok") is not True:
        if response.get("accepted") is True:
            raise MinMandateContractError("failed invoke response claims acceptance")
        if response.get("settlement_authorization") not in (None, {}):
            raise MinMandateContractError("failed invoke response carries authorization")
        if response.get("signed_receipt") not in (None, {}):
            raise MinMandateContractError("failed invoke response carries a signed receipt")
        return ValidatedInvokeResponse(
            "rejected",
            str(response.get("error_code") or "request"),
            None,
            None,
            None,
            None,
        )
    if response.get("operation") != "invoke":
        raise MinMandateContractError("response is not an invoke response")
    status = response.get("status")
    if status == "fresh_accept":
        outcome: Literal["fresh_accept", "idempotent_receipt", "rejected"] = (
            "fresh_accept"
        )
        expected_flags = (True, True, True, False)
    elif status == "idempotent_receipt":
        outcome = "idempotent_receipt"
        expected_flags = (False, False, False, True)
    else:
        outcome = "rejected"
        expected_flags = (False, False, False, status == "idempotent_rejection")
    actual_flags = (
        response.get("accepted"),
        response.get("fresh_execution_authorized"),
        response.get("settlement_authorization_issued"),
        response.get("idempotent_replay"),
    )
    if actual_flags != expected_flags:
        raise MinMandateContractError(
            f"invoke outcome flags violate {outcome} invariants: {actual_flags}"
        )
    if response.get("workflow_id") != workflow_id:
        raise MinMandateContractError("invoke response workflow binding mismatch")
    if response.get("credential_id") != credential_id or response.get(
        "session_id"
    ) != session_id:
        raise MinMandateContractError("invoke response credential/session mismatch")
    if response.get("settlement_verification") != settlement_verification:
        raise MinMandateContractError("invoke changed settlement verification material")
    if not settlement_verification_prevalidated:
        validate_settlement_verification(
            response["settlement_verification"],
            trusted_anchor=trusted_anchor,
            workflow_id=workflow_id,
            credential_id=credential_id,
            session_id=session_id,
            issuer_policy_digest_sha256=issuer_policy_digest_sha256,
            schnorr_batch_verifier=schnorr_batch_verifier,
        )
    merchant = response.get("merchant_view_serialized")
    redemption = response.get("redemption_view_serialized")
    if not isinstance(merchant, dict) or not isinstance(redemption, dict):
        raise MinMandateContractError("canonical invoke response lacks both views")
    merchant_core = _view_core(merchant, "merchant")
    redemption_core = _view_core(redemption, "redemption")
    bind = response.get("Bind")
    merchant_digest = response.get("dM")
    redemption_digest = response.get("dR")
    if not all(isinstance(value, str) and value for value in (bind, merchant_digest, redemption_digest)):
        raise MinMandateContractError("invoke response lacks Bind/dM/dR")
    merchant_binding = merchant_core["ihbbs1_presentation_statement"].get(
        "redemption_binding"
    )
    redemption_binding = redemption_core["ihbbs1_presentation_statement"].get(
        "redemption_binding"
    )
    if merchant_binding != bind or redemption_binding != bind:
        raise MinMandateContractError("two views disagree on Bind")
    if outcome == "rejected":
        if response.get("settlement_authorization") is not None or response.get(
            "signed_receipt"
        ) is not None:
            raise MinMandateContractError("rejected response carries signed settlement records")
        error_code = response.get("error_code")
        if not isinstance(error_code, str) or not error_code:
            raise MinMandateContractError("rejected response lacks an error code")
        return ValidatedInvokeResponse(
            "rejected", error_code, None, None, None, None
        )
    expected_dm = _view_digest(merchant_core, DOMAIN_MERCHANT_VIEW)
    expected_dr = _view_digest(redemption_core, DOMAIN_REDEMPTION_VIEW)
    if merchant_digest != expected_dm or redemption_digest != expected_dr:
        raise MinMandateContractError("dM/dR do not digest the canonical two views")
    merchant_context = merchant_core["context"]
    redemption_context = redemption_core["context"]
    if not isinstance(merchant_context, dict) or not isinstance(redemption_context, dict):
        raise MinMandateContractError("two views lack invocation context")
    shared_context_fields = (
        "I",
        "L",
        "credential_id",
        "session_id",
        "invocation_binding",
        "issuer_hiding_authorization_statement",
        "projection_digest",
        "request_commitment",
    )
    if any(
        merchant_context.get(field) != redemption_context.get(field)
        for field in shared_context_fields
    ):
        raise MinMandateContractError("two views disagree on shared invocation binding")
    if merchant_context.get("role") != "service" or redemption_context.get(
        "role"
    ) != "redemption-bundle":
        raise MinMandateContractError("two-view role separation is malformed")
    # Credential/session identifiers are wallet-local bindings.  The canonical
    # merchant and redemption views deliberately redact them while the signed
    # top-level response remains bound to the expected values above.
    if any(
        context.get(field) is not None
        for context in (merchant_context, redemption_context)
        for field in ("credential_id", "session_id")
    ):
        raise MinMandateContractError(
            "external two-view serialization leaks credential/session identifiers"
        )
    ack = response.get("merchant_ack_serialized")
    if not isinstance(ack, dict) or set(ack) != {"body", "signature"}:
        raise MinMandateContractError("merchant acknowledgement is malformed")
    ack_body = ack["body"]
    expected_ack = {
        "profile": "MM-merchant-ack-v1",
        "I": merchant_context.get("I"),
        "R": merchant_context.get("request_commitment"),
        "L": merchant_context.get("L"),
        "dM": merchant_digest,
        "dR": redemption_digest,
        "Bind": bind,
    }
    if ack_body != expected_ack or not isinstance(ack["signature"], dict):
        raise MinMandateContractError("merchant acknowledgement binding mismatch")
    merchant_key = merchant_core.get("q", {}).get("merchant_pk")
    if not isinstance(merchant_key, str):
        raise MinMandateContractError("merchant view lacks acknowledgement key")
    ack_signature = ack["signature"]
    authorization = response.get("settlement_authorization")
    signed_receipt = response.get("signed_receipt")
    settlement_key = settlement_verification["verification_key"]
    authorization_body, authorization_statement, authorization_signature = (
        _parse_signed_record(
            authorization,
            expected_key=settlement_key,
            expected_domain=DOMAIN_LOCAL_SETTLEMENT_AUTHORIZATION,
        )
    )
    receipt_body, receipt_statement, receipt_signature = _parse_signed_record(
        signed_receipt,
        expected_key=settlement_key,
        expected_domain=DOMAIN_LOCAL_RECEIPT,
    )
    signature_batch = [
        (merchant_key, ack_body, ack_signature),
        (settlement_key, authorization_statement, authorization_signature),
        (settlement_key, receipt_statement, receipt_signature),
    ]
    if schnorr_batch_verifier is None:
        for verification_key, statement, signature in signature_batch:
            _verify_schnorr_signature(verification_key, statement, signature)
    else:
        schnorr_batch_verifier(signature_batch)
    for body in (authorization_body, receipt_body):
        if (
            body.get("credential_id") != credential_id
            or body.get("session_id") != session_id
            or body.get("dM") != merchant_digest
            or body.get("dR") != redemption_digest
            or body.get("Bind") != bind
        ):
            raise MinMandateContractError(
                "signed settlement record disagrees with Bind/dM/dR or credential"
            )
    if receipt_body.get("budget") != approved_budget:
        raise MinMandateContractError("signed receipt budget differs from approval")
    projection = redemption_core.get("payment_projection")
    if not isinstance(projection, dict):
        raise MinMandateContractError("redemption view lacks payment projection")
    if (
        authorization_body.get("payee") != projection.get("payee")
        or authorization_body.get("asset") != projection.get("asset")
        or authorization_body.get("amount") != projection.get("amount")
        or receipt_body.get("amount") != projection.get("amount")
        or authorization_body.get("mode") != "local-ledger-no-funds"
        or authorization_body.get("real_payment_rail") is not False
    ):
        raise MinMandateContractError("signed settlement terms differ from payment projection")
    authorization_digest = _hash_bytes(
        DOMAIN_LOCAL_SETTLEMENT_AUTHORIZATION,
        [_canonical_bytes(authorization)],
    ).hex()
    if receipt_body.get("settlement_authorization_digest") != authorization_digest:
        raise MinMandateContractError("signed receipt does not bind its authorization")
    selected = redemption_core.get("selected_slots")
    serials = redemption_core.get("serials")
    if not isinstance(selected, list) or not isinstance(serials, dict):
        raise MinMandateContractError("redemption view lacks ordered serials")
    try:
        serialized_points = [serials[str(index)] for index in selected]
    except KeyError as exc:
        raise MinMandateContractError("redemption view serial ordering mismatch") from exc
    if not all(isinstance(value, str) and value for value in serialized_points):
        raise MinMandateContractError("redemption view contains malformed serials")
    serial_values = [
        _hash_bytes("spent-serial", [value.encode("ascii")]).hex()
        for value in serialized_points
    ]
    acceptance_digest = _hash_bytes(
        DOMAIN_ACCEPT,
        [
            str(redemption_context.get("I")).encode("utf-8"),
            str(redemption_context.get("request_commitment")).encode("utf-8"),
            _canonical_bytes(projection),
            bind.encode("ascii"),
            _canonical_bytes(serial_values),
        ],
    ).hex()
    if authorization_body.get("acceptance_digest") != acceptance_digest or receipt_body.get(
        "acceptance_digest"
    ) != acceptance_digest:
        raise MinMandateContractError("signed settlement acceptance digest mismatch")
    request_value = {
        "merchant_view": {
            **merchant_core,
            "ihbbs1_presentation_statement": {
                **merchant_core["ihbbs1_presentation_statement"],
                "redemption_binding": None,
            },
        },
        "redemption_view": {
            **redemption_core,
            "ihbbs1_presentation_statement": {
                **redemption_core["ihbbs1_presentation_statement"],
                "redemption_binding": None,
            },
        },
        "merchant_ack": ack,
        "dM": merchant_digest,
        "dR": redemption_digest,
        "Bind": bind,
    }
    request_id = _hash_bytes(DOMAIN_REQUEST, [_canonical_bytes(request_value)]).hex()
    if authorization_body.get("request_id") != request_id or receipt_body.get(
        "request_id"
    ) != request_id:
        raise MinMandateContractError("signed records do not bind the canonical request")
    receipt_id = _hash_bytes(
        DOMAIN_LOCAL_RECEIPT_ID,
        [
            request_id.encode("ascii"),
            acceptance_digest.encode("ascii"),
            authorization_digest.encode("ascii"),
        ],
    ).hex()
    if receipt_body.get("receipt_id") != receipt_id:
        raise MinMandateContractError("signed receipt id mismatch")
    if response.get("error_code") is not None:
        raise MinMandateContractError("successful response carries an error code")
    return ValidatedInvokeResponse(
        outcome,
        None,
        request_id,
        receipt_id,
        authorization,
        signed_receipt,
    )
