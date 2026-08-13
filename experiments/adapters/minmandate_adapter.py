from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from experiments.adapters.base import PaymentArtifact, PaymentContext, RoleView
from experiments.benchmark.mandate_compiler import UserApprovalArtifact
from experiments.common import ROOT, canonical_json, load_yaml, sha256_file, sha256_json
from experiments.offline_boundary import DENY_INET_LIBRARY
from experiments.runtime.minmandate_contract import (
    MinMandateContractError,
    ValidatedInvokeResponse,
    approval_wire_fields,
    validate_canonical_user_approval,
    validate_invoke_response,
    validate_settlement_trust_anchor,
    validate_settlement_verification,
    validate_startup_network_attestation,
)


PROTOCOL_VERSION = "minmandate-v3"
WIRE_SCHEMA_VERSION = "minmandate-rs-jsonl-v3"
IMPLEMENTATION_PROFILE = "canonical-ihbbs1"
ISSUER_HIDING_SCHEME = "ihbbs1-bbs-bls12381-v1"
CRYPTO_SCHEME = ISSUER_HIDING_SCHEME
KEY_MATERIAL_PROFILE = "deterministic-public-test-secrets-non-production"
COMPACT_TRANSPORT_ENCODING = "gzip-base64-v1"
MAX_COMPACT_TRANSPORT_BYTES = 16 * 1024 * 1024
ISSUER_POLICY_PATH = ROOT / "experiments/canonical/config/issuer_policy_v1.yaml"
ISSUER_POLICY_EPOCH = "canonical-epoch-2026q3-v1"
ISSUER_POLICY_SIZE = 8
WALLET_ENTITY_MODEL = {
    "top_level_type": "WalletRuntime",
    "top_level_entity_count": 1,
    "interfaces_are_logical": True,
    "record_scope": "wallet-local-private-audit",
}
WALLET_INTERFACES = {
    "issuance": {"name": "W_iss", "lifecycle": "once-per-task"},
    "redemption": {"name": "W_red", "lifecycle": "once-per-paid-invocation"},
}
JOINED_WALLET_LEAKAGE_BOUNDARY = {
    "joinable_interfaces": ["W_iss", "W_red"],
    "joined_state_and_retained_logs": True,
    "non_collusion_assumed": False,
}
NO_LIVE_COST_BOUNDARY = {
    "paid_saas_calls": False,
    "online_paid_llm_calls": False,
    "cloud_jobs": False,
    "real_payment_rails": False,
    "transaction_broadcast": False,
    "execution": "local_offline_only",
}

_PROHIBITED_ROUTINE_FIELDS = {
    "common_alpha_proof",
    "common_alpha_randomization_proof",
    "epoch_pk",
    "ipk",
    "issuer_auth",
    "issuer_hiding_authorization",
    "issuer_identity",
    "issuer_index",
    "issuer_name",
    "issuer_public_key",
    "original_ipk",
    "original_issuer_key",
    "original_issuer_public_key",
    "selected_issuer_index",
    "selected_issuer_public_key",
    "selected_issuer_public_key_b64",
    "selected_issuer_public_key_sha256",
    "wallet_entity_id",
    "wallet_id",
    "wallet_local_audit",
}
_LOCAL_TELEMETRY_FIELDS = {
    "crypto_executed",
    "crypto_scheme",
    "issuer_hiding_crypto_executed",
    "joined_wallet_leakage_boundary",
    "stable_issuer_handle_disclosed",
    "view_count",
    "wallet_entity_model",
    "wallet_interfaces",
    "wallet_joined_state_assumed",
}


class MinMandateServerError(RuntimeError):
    pass


def _resolve_deny_inet_preload(
    path: Path | None = None,
    expected_sha256: str | None = None,
) -> tuple[Path, str]:
    canonical_path = DENY_INET_LIBRARY.resolve()
    if path is not None and path.expanduser().resolve() != canonical_path:
        raise MinMandateServerError(
            "deny-INET LD_PRELOAD path differs from the configured local path"
        )
    resolved = canonical_path
    if resolved.suffix != ".so" or not resolved.is_file():
        raise MinMandateServerError(
            f"prebuilt deny-INET LD_PRELOAD shared object is missing: {resolved}"
        )
    actual = sha256_file(resolved)
    if expected_sha256 is not None and actual != expected_sha256:
        raise MinMandateServerError(
            "deny-INET LD_PRELOAD hash mismatch: "
            f"expected={expected_sha256} actual={actual}"
        )
    return resolved, actual


def _offline_experiment_child_env(
    deny_inet_preload: Path | None = None,
) -> dict[str, str]:
    """Return a child-only environment that cannot inherit network credentials."""
    credential_markers = (
        "API_KEY",
        "ACCESS_KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "CREDENTIAL",
        "AUTHORIZATION",
    )
    env: dict[str, str] = {}
    for name, value in os.environ.items():
        folded = name.upper()
        if (
            name in {"LD_PRELOAD", "LD_LIBRARY_PATH"}
            or "PROXY" in folded
            or any(marker in folded for marker in credential_markers)
        ):
            continue
        env[name] = value
    env.update(
        {
            "MINMANDATE_EXPERIMENT_OFFLINE": "1",
            "ALLOW_NETWORK": "false",
            "ALLOW_LIVE_SERVICES": "false",
            "ALLOW_SANDBOX_SERVICES": "false",
            "ALLOW_REAL_PAYMENT": "false",
            "ALLOW_PRODUCTION_WRITES": "false",
            "NO_PROXY": "localhost,127.0.0.1,::1",
            "no_proxy": "localhost,127.0.0.1,::1",
        }
    )
    if deny_inet_preload is not None:
        env["LD_PRELOAD"] = str(deny_inet_preload.resolve())
    return env


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()


def _validate_workflow_slots(slots: Any, default_expiry: int) -> list[dict[str, Any]]:
    if not isinstance(slots, list) or not slots:
        raise MinMandateServerError("begin_workflow slots must be a nonempty list")
    normalized: list[dict[str, Any]] = []
    for index, slot in enumerate(slots):
        if not isinstance(slot, dict):
            raise MinMandateServerError(f"begin_workflow slot {index} must be an object")
        service_class = slot.get("service_class")
        if not isinstance(service_class, str) or not service_class:
            raise MinMandateServerError(
                f"begin_workflow slot {index} must have a nonempty string service_class"
            )
        merchant_id = slot.get("merchant_id")
        if not isinstance(merchant_id, str) or not merchant_id:
            raise MinMandateServerError(
                f"begin_workflow slot {index} must have a nonempty string merchant_id"
            )
        capacity = slot.get("capacity")
        if (
            not isinstance(capacity, int)
            or isinstance(capacity, bool)
            or capacity <= 0
        ):
            raise MinMandateServerError(
                f"begin_workflow slot {index} must have a positive integer capacity"
            )
        expiry = slot.get("expiry", default_expiry)
        if not isinstance(expiry, int) or isinstance(expiry, bool) or expiry <= 0:
            raise MinMandateServerError(
                f"begin_workflow slot {index} must have a positive integer expiry"
            )
        funding_eligible = slot.get("funding_eligible", True)
        if not isinstance(funding_eligible, bool):
            raise MinMandateServerError(
                f"begin_workflow slot {index} funding_eligible must be boolean"
            )
        normalized.append(
            {
                "service_class": service_class,
                "merchant_id": merchant_id,
                "capacity": capacity,
                "expiry": expiry,
                "funding_eligible": funding_eligible,
            }
        )
    return normalized


def load_frozen_issuer_policy(
    policy_path: Path = ISSUER_POLICY_PATH,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load the Rust-generated canonical policy or fail before server startup."""
    policy_path = policy_path.resolve()
    policy = load_yaml(policy_path)
    expected = {
        "schema_version": "minmandate-issuer-policy-v1",
        "status": "generated_and_frozen",
        "scheme": ISSUER_HIDING_SCHEME,
        "protocol_version": PROTOCOL_VERSION,
        "wire_version": WIRE_SCHEMA_VERSION,
        "curve": "BLS12-381",
    }
    mismatches = {
        key: {"expected": value, "actual": policy.get(key)}
        for key, value in expected.items()
        if policy.get(key) != value
    }
    if mismatches:
        raise MinMandateServerError(
            "v3 issuer policy is not generated and frozen; refusing to start Rust adapter: "
            f"{mismatches}"
        )
    epoch = policy.get("epoch")
    material = policy.get("material")
    if not isinstance(epoch, dict) or not isinstance(material, dict):
        raise MinMandateServerError("v3 issuer policy lacks epoch/material objects")
    if epoch.get("id") != ISSUER_POLICY_EPOCH or epoch.get("policy_size") != ISSUER_POLICY_SIZE:
        raise MinMandateServerError("v3 issuer policy epoch or cardinality mismatch")
    digest = material.get("policy_digest_sha256")
    public_policy = material.get("canonical_public_policy_b64")
    admitted = material.get("admitted_issuers")
    if not _is_sha256(digest) or not isinstance(public_policy, str) or not public_policy:
        raise MinMandateServerError("v3 issuer policy lacks Rust-generated public material")
    if not isinstance(admitted, list) or len(admitted) != ISSUER_POLICY_SIZE:
        raise MinMandateServerError("v3 issuer policy must contain exactly eight issuers")
    slots = sorted(
        row.get("member_slot") for row in admitted if isinstance(row, dict)
    )
    if slots != list(range(ISSUER_POLICY_SIZE)):
        raise MinMandateServerError("v3 issuer policy member slots are not canonical 0..7")
    if any(
        not isinstance(row, dict)
        or not isinstance(row.get("public_key_b64"), str)
        or not row.get("public_key_b64")
        or not _is_sha256(row.get("public_key_sha256"))
        for row in admitted
    ):
        raise MinMandateServerError("v3 issuer policy contains invalid issuer material")
    artifact_value = material.get("artifact_path")
    if not isinstance(artifact_value, str) or not artifact_value:
        raise MinMandateServerError("v3 issuer policy lacks canonical artifact_path")
    artifact_path = Path(artifact_value)
    if not artifact_path.is_absolute():
        artifact_path = ROOT / artifact_path
    artifact_path = artifact_path.resolve()
    if not artifact_path.is_file():
        raise MinMandateServerError(
            f"v3 canonical issuer policy artifact is missing: {artifact_path}"
        )
    try:
        artifact = json.loads(artifact_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise MinMandateServerError(
            f"v3 canonical issuer policy artifact is invalid: {exc}"
        ) from exc
    if not isinstance(artifact, dict):
        raise MinMandateServerError("v3 canonical issuer policy artifact is not an object")
    for key in ("schema_version", "status", "scheme", "protocol_version", "wire_version"):
        if artifact.get(key) != policy.get(key):
            raise MinMandateServerError(
                f"v3 issuer policy config/artifact mismatch for {key}"
            )
    artifact_material = artifact.get("material")
    if not isinstance(artifact_material, dict):
        raise MinMandateServerError("v3 canonical issuer policy artifact lacks material")
    if artifact_material.get("policy_digest_sha256") != digest:
        raise MinMandateServerError("v3 issuer policy config/artifact digest mismatch")
    metadata = {
        "epoch_id": ISSUER_POLICY_EPOCH,
        "policy_digest_sha256": digest,
        "policy_size": ISSUER_POLICY_SIZE,
        "policy_config_sha256": sha256_file(artifact_path),
        "metadata_class": "deployment_cohort_metadata",
    }
    return policy, metadata


def _validate_policy_metadata(value: Any, expected: dict[str, Any], where: str) -> None:
    if not isinstance(value, dict) or value != expected:
        raise MinMandateServerError(
            f"{where} issuer policy mismatch: expected={expected!r} actual={value!r}"
        )


def _forbidden_routine_paths(value: Any, prefix: tuple[str, ...] = ()) -> list[str]:
    leaked: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            folded = str(key).casefold().replace("-", "_")
            path = prefix + (str(key),)
            if (
                folded in _PROHIBITED_ROUTINE_FIELDS
                or folded in _LOCAL_TELEMETRY_FIELDS
                or folded.startswith("wallet_")
                or folded.endswith("_telemetry")
                or folded.endswith("_timing_ms")
            ):
                leaked.append(".".join(path))
            leaked.extend(_forbidden_routine_paths(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            leaked.extend(_forbidden_routine_paths(item, prefix + (str(index),)))
    return leaked


def _validate_wallet_local_audit(
    value: Any,
    expected_policy: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MinMandateServerError("v3 response lacks separate wallet_local_audit")
    expected = {
        "schema_version": "minmandate-wallet-local-audit-v1",
        "evidence_scope": "wallet_local_private_audit",
        "epoch_id": expected_policy["epoch_id"],
        "policy_digest_sha256": expected_policy["policy_digest_sha256"],
        "policy_size": expected_policy["policy_size"],
        "assignment_algorithm": "sha256_modulo_policy_size_v1",
        "external_view_exported": False,
    }
    mismatches = {
        key: {"expected": expected_value, "actual": value.get(key)}
        for key, expected_value in expected.items()
        if value.get(key) != expected_value
    }
    if mismatches:
        raise MinMandateServerError(f"invalid wallet-local audit contract: {mismatches}")
    if not isinstance(value.get("wallet_id"), str) or not value["wallet_id"]:
        raise MinMandateServerError("wallet-local audit lacks wallet_id")
    selected = value.get("selected_issuer_index")
    if not isinstance(selected, int) or isinstance(selected, bool) or not 0 <= selected < 8:
        raise MinMandateServerError("wallet-local audit selected issuer is outside 0..7")
    if not _is_sha256(value.get("selected_issuer_public_key_sha256")):
        raise MinMandateServerError("wallet-local audit lacks selected issuer key digest")
    if value.get("key_material_profile") != KEY_MATERIAL_PROFILE:
        raise MinMandateServerError("wallet-local audit lacks non-production key provenance")
    return dict(value)


def _validate_final_v3_envelope(
    response: dict[str, Any], expected_policy: dict[str, Any]
) -> None:
    expected = {
        "protocol_version": PROTOCOL_VERSION,
        "wire_schema_version": WIRE_SCHEMA_VERSION,
        "implementation_profile": IMPLEMENTATION_PROFILE,
        "issuer_hiding_scheme": ISSUER_HIDING_SCHEME,
        "key_material_profile": KEY_MATERIAL_PROFILE,
        "no_live_cost_boundary": NO_LIVE_COST_BOUNDARY,
    }
    mismatches = {
        key: {"expected": value, "actual": response.get(key)}
        for key, value in expected.items()
        if response.get(key) != value
    }
    if mismatches:
        raise MinMandateServerError(f"non-v3 Rust response: {mismatches}")
    _validate_policy_metadata(response.get("issuer_policy"), expected_policy, "response")


def _validate_ping(
    response: dict[str, Any],
    expected_policy: dict[str, Any],
    deny_inet_path: Path,
    deny_inet_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _validate_final_v3_envelope(response, expected_policy)
    if response.get("ok") is not True or response.get("operation") != "ping":
        raise MinMandateServerError(f"invalid v3 Rust ping response: {response}")
    try:
        attestation = validate_startup_network_attestation(
            response.get("network_boundary_attestation"),
            expected_path=deny_inet_path,
            expected_sha256=deny_inet_sha256,
        )
        trust_anchor = validate_settlement_trust_anchor(
            response.get("settlement_trust_anchor")
        )
    except MinMandateContractError as exc:
        raise MinMandateServerError(str(exc)) from exc
    return attestation, trust_anchor


def _validate_view_contract(
    view: dict[str, Any], role: str, expected_policy: dict[str, Any]
) -> tuple[str, str]:
    expected = {
        "protocol_version": PROTOCOL_VERSION,
        "wire_schema_version": WIRE_SCHEMA_VERSION,
        "implementation_profile": IMPLEMENTATION_PROFILE,
        "issuer_hiding_scheme": ISSUER_HIDING_SCHEME,
    }
    mismatches = {
        key: {"expected": value, "actual": view.get(key)}
        for key, value in expected.items()
        if view.get(key) != value
    }
    if mismatches:
        raise MinMandateServerError(f"invalid {role} v3 view contract: {mismatches}")
    leaked = sorted(set(_forbidden_routine_paths(view)))
    if leaked:
        raise MinMandateServerError(
            f"{role} routine view leaks issuer/wallet/local fields: {leaked}"
        )
    if "issuer_hiding_authorization" in view:
        raise MinMandateServerError(f"{role} view serialized legacy authorization envelope")
    _validate_policy_metadata(view.get("issuer_policy"), expected_policy, f"{role} view")
    evidence = view.get("issuer_hiding_evidence")
    if not isinstance(evidence, dict):
        raise MinMandateServerError(f"{role} view lacks issuer_hiding_evidence")
    if set(evidence) != {
        "randomized_verification_key_b64",
        "randomized_policy_membership_tag_b64",
        "evidence_scope",
    }:
        raise MinMandateServerError(f"{role} issuer-hiding evidence has unexpected fields")
    randomized_key = evidence.get("randomized_verification_key_b64")
    randomized_tag = evidence.get("randomized_policy_membership_tag_b64")
    if (
        not isinstance(randomized_key, str)
        or not randomized_key
        or not isinstance(randomized_tag, str)
        or not randomized_tag
        or evidence.get("evidence_scope") != "per_call"
    ):
        raise MinMandateServerError(f"{role} issuer-hiding evidence is malformed")
    return randomized_key, randomized_tag


def wallet_local_audit_from_response(
    response: dict[str, Any], expected_policy: dict[str, Any]
) -> dict[str, Any] | None:
    value = response.get("wallet_local_audit")
    if value is None:
        return None
    return _validate_wallet_local_audit(value, expected_policy)


class _NativeSchnorrValidator:
    PROFILE = "minmandate-native-schnorr-batch-v1"

    def __init__(self, binary: Path, env: dict[str, str]) -> None:
        self.process = subprocess.Popen(
            [str(binary), "--native-client-validator"],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
        response = self._request({"operation": "ping"})
        if (
            response.get("ok") is not True
            or response.get("validator_profile") != self.PROFILE
        ):
            self.close()
            raise MinMandateServerError(
                f"native Schnorr validator handshake failed: {response!r}"
            )

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.process.stdin is None or self.process.stdout is None:
            raise MinMandateServerError("native Schnorr validator pipes are unavailable")
        self.process.stdin.write(canonical_json(payload) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = (
                self.process.stderr.read() if self.process.stderr is not None else ""
            )
            raise MinMandateServerError(
                f"native Schnorr validator terminated: {stderr}"
            )
        response = json.loads(line)
        if not isinstance(response, dict):
            raise MinMandateServerError(
                "native Schnorr validator response is not an object"
            )
        return response

    def verify_batch(
        self, items: list[tuple[str, dict[str, Any], dict[str, Any]]]
    ) -> None:
        response = self._request(
            {
                "operation": "verify_schnorr_batch",
                "items": [
                    {
                        "verification_key": verification_key,
                        "statement": statement,
                        "signature": signature,
                    }
                    for verification_key, statement, signature in items
                ],
            }
        )
        if (
            response.get("ok") is not True
            or response.get("valid") is not True
            or response.get("verified_items") != len(items)
            or response.get("validator_profile") != self.PROFILE
        ):
            raise MinMandateContractError(
                f"native Schnorr signature verification failed: {response!r}"
            )

    def close(self) -> None:
        if self.process.poll() is None:
            if self.process.stdin is not None:
                self.process.stdin.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=5)
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self.process.stderr is not None:
            self.process.stderr.close()


class PersistentMinMandateClient:
    def __init__(
        self,
        binary: Path,
        policy_path: Path = ISSUER_POLICY_PATH,
        *,
        deny_inet_preload_path: Path | None = None,
        deny_inet_preload_sha256: str | None = None,
        compact_wire: bool = False,
        transport_wire_audit: bool = False,
    ) -> None:
        self.policy_document, self.policy_metadata = load_frozen_issuer_policy(policy_path)
        self.policy_identity_sha256 = sha256_json(self.policy_metadata)
        self.compact_wire = compact_wire
        self.transport_wire_audit_enabled = transport_wire_audit
        self.transport_wire_audit: list[dict[str, Any]] = []
        (
            self.deny_inet_preload_path,
            self.deny_inet_preload_sha256,
        ) = _resolve_deny_inet_preload(
            deny_inet_preload_path,
            deny_inet_preload_sha256,
        )
        artifact_path = Path(self.policy_document["material"]["artifact_path"])
        if not artifact_path.is_absolute():
            artifact_path = ROOT / artifact_path
        artifact_path = artifact_path.resolve()
        resolved = binary if binary.is_absolute() else ROOT / binary
        if not resolved.exists():
            raise FileNotFoundError(f"missing Rust benchmark binary: {resolved}")
        self.process = subprocess.Popen(
            [str(resolved), "--jsonl-server", "--issuer-policy", str(artifact_path)],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=_offline_experiment_child_env(self.deny_inet_preload_path),
        )
        self.native_schnorr_validator = _NativeSchnorrValidator(
            resolved,
            _offline_experiment_child_env(self.deny_inet_preload_path),
        )
        self._workflow_bindings: dict[str, dict[str, Any]] = {}
        self._retired_workflow_ids: set[str] = set()
        self._retired_credential_ids: set[str] = set()
        self._amendment_counts: dict[str, int] = {}
        self._issuer_evidence_owner: dict[tuple[str, str], tuple[str, str]] = {}
        self._call_issuer_evidence: dict[tuple[str, str], tuple[str, str]] = {}
        response = self.request({"operation": "ping"})
        (
            self.network_boundary_attestation,
            self.settlement_trust_anchor,
        ) = _validate_ping(
            response,
            self.policy_metadata,
            self.deny_inet_preload_path,
            self.deny_inet_preload_sha256,
        )

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.process.stdin is None or self.process.stdout is None:
            raise MinMandateServerError("Rust JSONL pipes are unavailable")
        requested_protocol = payload.get("protocol_version")
        requested_wire = payload.get("wire_schema_version")
        if requested_protocol not in (None, PROTOCOL_VERSION):
            raise MinMandateServerError(
                f"v3 adapter refuses protocol version: {requested_protocol}"
            )
        if requested_wire not in (None, WIRE_SCHEMA_VERSION):
            raise MinMandateServerError(f"v3 adapter refuses wire version: {requested_wire}")
        wire_payload = dict(payload)
        wire_payload.update(
            {
                "protocol_version": PROTOCOL_VERSION,
                "wire_schema_version": WIRE_SCHEMA_VERSION,
                "implementation_profile": IMPLEMENTATION_PROFILE,
                "key_material_profile": KEY_MATERIAL_PROFILE,
                "issuer_policy": self.policy_metadata,
                "no_live_cost_boundary": NO_LIVE_COST_BOUNDARY,
            }
        )
        serialized_request = canonical_json(wire_payload).encode("utf-8")
        if self.compact_wire:
            compressed = gzip.compress(serialized_request, compresslevel=1, mtime=0)
            transport_request = {
                "transport_encoding": COMPACT_TRANSPORT_ENCODING,
                "payload_b64": base64.b64encode(compressed).decode("ascii"),
                "uncompressed_bytes": len(serialized_request),
                "uncompressed_sha256": hashlib.sha256(serialized_request).hexdigest(),
            }
            request_line = canonical_json(transport_request)
        else:
            request_line = serialized_request.decode("utf-8")
        request_transport_bytes = len(request_line.encode("utf-8")) + 1
        self.process.stdin.write(request_line + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr is not None else ""
            raise MinMandateServerError(f"v3 Rust JSONL server terminated: {stderr}")
        response_transport_bytes = len(line.encode("utf-8"))
        response = json.loads(line)
        response_payload_bytes = len(line.rstrip("\n").encode("utf-8"))
        if self.compact_wire:
            if not isinstance(response, dict) or set(response) != {
                "transport_encoding",
                "payload_b64",
                "uncompressed_bytes",
                "uncompressed_sha256",
            }:
                raise MinMandateServerError(
                    "Rust server omitted the negotiated compact transport envelope"
                )
            if response["transport_encoding"] != COMPACT_TRANSPORT_ENCODING:
                raise MinMandateServerError("Rust server changed compact transport encoding")
            try:
                compressed_response = base64.b64decode(
                    response["payload_b64"], validate=True
                )
                decoded_response = gzip.decompress(compressed_response)
            except (TypeError, ValueError, binascii.Error, gzip.BadGzipFile) as exc:
                raise MinMandateServerError(
                    "Rust compact transport payload is malformed"
                ) from exc
            if (
                len(decoded_response) > MAX_COMPACT_TRANSPORT_BYTES
                or len(decoded_response) != response["uncompressed_bytes"]
                or hashlib.sha256(decoded_response).hexdigest()
                != response["uncompressed_sha256"]
            ):
                raise MinMandateServerError(
                    "Rust compact transport length or digest mismatch"
                )
            response_payload_bytes = len(decoded_response)
            response = json.loads(decoded_response)
        if not isinstance(response, dict):
            raise MinMandateServerError("Rust JSONL response is not an object")
        _validate_final_v3_envelope(response, self.policy_metadata)
        if hasattr(self, "network_boundary_attestation") and response.get(
            "network_boundary_attestation"
        ) != self.network_boundary_attestation:
            raise MinMandateServerError("Rust response changed startup network attestation")
        if hasattr(self, "settlement_trust_anchor") and response.get(
            "settlement_trust_anchor"
        ) != self.settlement_trust_anchor:
            raise MinMandateServerError("Rust response changed settlement trust anchor")
        if self.transport_wire_audit_enabled:
            self.transport_wire_audit.append(
                {
                    "operation": str(wire_payload.get("operation", "")),
                    "transport_encoding": (
                        COMPACT_TRANSPORT_ENCODING
                        if self.compact_wire
                        else "canonical-json"
                    ),
                    "request_payload_bytes": len(serialized_request),
                    "request_transport_bytes": request_transport_bytes,
                    "response_payload_bytes": response_payload_bytes,
                    "response_transport_bytes": response_transport_bytes,
                }
            )
        return response

    def request_raw(self, line: str) -> dict[str, Any]:
        if self.process.stdin is None or self.process.stdout is None:
            raise MinMandateServerError("Rust JSONL pipes are unavailable")
        self.process.stdin.write(line.rstrip("\n") + "\n")
        self.process.stdin.flush()
        response_line = self.process.stdout.readline()
        if not response_line:
            stderr = self.process.stderr.read() if self.process.stderr is not None else ""
            raise MinMandateServerError(f"v3 Rust JSONL server terminated: {stderr}")
        response = json.loads(response_line)
        if not isinstance(response, dict):
            raise MinMandateServerError("Rust JSONL response is not an object")
        _validate_final_v3_envelope(response, self.policy_metadata)
        if hasattr(self, "network_boundary_attestation") and response.get(
            "network_boundary_attestation"
        ) != self.network_boundary_attestation:
            raise MinMandateServerError("Rust response changed startup network attestation")
        if hasattr(self, "settlement_trust_anchor") and response.get(
            "settlement_trust_anchor"
        ) != self.settlement_trust_anchor:
            raise MinMandateServerError("Rust response changed settlement trust anchor")
        return response

    def begin_workflow(
        self,
        workflow_id: str,
        task: str,
        slots: list[dict[str, Any]],
        expiry: int,
        experiment_variant: str = "full",
        wallet_id: str | None = None,
        *,
        approval_artifact: UserApprovalArtifact | None = None,
    ) -> dict[str, Any]:
        if not isinstance(expiry, int) or isinstance(expiry, bool) or expiry <= 0:
            raise MinMandateServerError("begin_workflow expiry must be positive")
        if approval_artifact is None:
            raise MinMandateServerError("begin_workflow requires explicit UserApprovalArtifact")
        try:
            validate_canonical_user_approval(approval_artifact)
        except MinMandateContractError as exc:
            raise MinMandateServerError(f"invalid UserApprovalArtifact: {exc}") from exc
        if approval_artifact.workflow_id != workflow_id:
            raise MinMandateServerError("approval artifact workflow binding mismatch")
        normalized_slots = _validate_workflow_slots(slots, expiry)
        approved_slots = [slot.to_dict() for slot in approval_artifact.slots]
        wire_policy_slots = [
            {
                "service_class": slot["service_class"],
                "merchant_id": slot["merchant_id"],
                "capacity": slot["capacity"],
                "expiry": slot["expiry"],
            }
            for slot in normalized_slots
        ]
        if wire_policy_slots != approved_slots:
            raise MinMandateServerError("workflow slots differ from explicit approval")
        if approval_artifact.settlement_authorized:
            raise MinMandateServerError("real settlement authorization is prohibited")
        request: dict[str, Any] = {
            "operation": "begin_workflow",
            "workflow_id": workflow_id,
            "task": task,
            "slots": normalized_slots,
            "expiry": expiry,
            "experiment_variant": experiment_variant,
            **approval_wire_fields(approval_artifact),
            "replay_status": {"credential_status": "new", "request_status": "not_seen"},
        }
        if wallet_id is not None:
            request["wallet_id"] = wallet_id
        response = self.request(request)
        if response.get("accepted"):
            audit = _validate_wallet_local_audit(
                response.get("wallet_local_audit"), self.policy_metadata
            )
            returned_wallet_id = audit["wallet_id"]
            if response.get("experiment_variant") != experiment_variant:
                raise MinMandateServerError("begin_workflow changed experiment_variant")
            if wallet_id is not None and returned_wallet_id != wallet_id:
                raise MinMandateServerError("begin_workflow changed wallet_id")
            credential_id = response.get("credential_id")
            session_id = response.get("session_id")
            if credential_id != approval_artifact.artifact_sha256 or session_id != credential_id:
                raise MinMandateServerError("begin_workflow lost approval credential binding")
            try:
                settlement_verification = validate_settlement_verification(
                    response.get("settlement_verification"),
                    trusted_anchor=self.settlement_trust_anchor,
                    workflow_id=workflow_id,
                    credential_id=credential_id,
                    session_id=session_id,
                    issuer_policy_digest_sha256=self.policy_metadata[
                        "policy_digest_sha256"
                    ],
                    schnorr_batch_verifier=self.native_schnorr_validator.verify_batch,
                )
            except MinMandateContractError as exc:
                raise MinMandateServerError(str(exc)) from exc
            self._workflow_bindings[workflow_id] = {
                "experiment_variant": experiment_variant,
                "wallet_id": returned_wallet_id,
                "wallet_local_audit": audit,
                "issuer_policy": dict(self.policy_metadata),
                "approval_artifact": approval_artifact,
                "approval_workflow_id": approval_artifact.workflow_id,
                "credential_id": credential_id,
                "session_id": session_id,
                "approved_budget": approval_artifact.approved_budget,
                "settlement_verification": settlement_verification,
                "amendments_remaining": int(response.get("amendments_remaining", 0)),
            }
            self._amendment_counts[approval_artifact.workflow_id] = 0
        return response

    def replace_workflow(
        self,
        workflow_id: str,
        replacement_workflow_id: str,
        task: str,
        slots: list[dict[str, Any]],
        expiry: int,
        *,
        approval_artifact: UserApprovalArtifact,
    ) -> dict[str, Any]:
        parent = self._workflow_bindings.get(workflow_id)
        if parent is None or workflow_id in self._retired_workflow_ids:
            raise MinMandateServerError("replace_workflow parent is not active")
        lineage = str(parent["approval_workflow_id"])
        if self._amendment_counts.get(lineage, 0) >= 1:
            raise MinMandateServerError("replace_workflow exceeds one amendment")
        if approval_artifact.workflow_id != lineage:
            raise MinMandateServerError("replacement approval lineage mismatch")
        if approval_artifact.parent_approval_sha256 != parent["credential_id"]:
            raise MinMandateServerError("replacement approval parent mismatch")
        try:
            validate_canonical_user_approval(approval_artifact)
        except MinMandateContractError as exc:
            raise MinMandateServerError(f"invalid UserApprovalArtifact: {exc}") from exc
        normalized_slots = _validate_workflow_slots(slots, expiry)
        approved_slots = [slot.to_dict() for slot in approval_artifact.slots]
        if [
            {
                "service_class": slot["service_class"],
                "merchant_id": slot["merchant_id"],
                "capacity": slot["capacity"],
                "expiry": slot["expiry"],
            }
            for slot in normalized_slots
        ] != approved_slots:
            raise MinMandateServerError("replacement slots differ from explicit approval")
        request = {
            "operation": "replace_workflow",
            "workflow_id": workflow_id,
            "replacement_workflow_id": replacement_workflow_id,
            "parent_credential_id": parent["credential_id"],
            "task": task,
            "slots": normalized_slots,
            "expiry": expiry,
            "experiment_variant": parent["experiment_variant"],
            "wallet_id": parent["wallet_id"],
            **approval_wire_fields(approval_artifact),
        }
        response = self.request(request)
        if response.get("accepted") is not True:
            return response
        if (
            response.get("operation") != "replace_workflow"
            or response.get("status") != "replacement_committed"
            or response.get("parent_tombstoned") is not True
            or response.get("parent_workflow_id") != workflow_id
            or response.get("replacement_workflow_id") != replacement_workflow_id
            or response.get("parent_credential_id") != parent["credential_id"]
        ):
            raise MinMandateServerError("invalid atomic replacement response")
        replacement_credential = response.get("replacement_credential_id")
        session_id = response.get("session_id")
        if replacement_credential != approval_artifact.artifact_sha256 or session_id != replacement_credential:
            raise MinMandateServerError("replacement credential binding mismatch")
        audit = _validate_wallet_local_audit(
            response.get("wallet_local_audit"), self.policy_metadata
        )
        try:
            settlement_verification = validate_settlement_verification(
                response.get("settlement_verification"),
                trusted_anchor=self.settlement_trust_anchor,
                workflow_id=replacement_workflow_id,
                credential_id=replacement_credential,
                session_id=session_id,
                issuer_policy_digest_sha256=self.policy_metadata[
                    "policy_digest_sha256"
                ],
                schnorr_batch_verifier=self.native_schnorr_validator.verify_batch,
            )
        except MinMandateContractError as exc:
            raise MinMandateServerError(str(exc)) from exc
        self._workflow_bindings.pop(workflow_id, None)
        self._retired_workflow_ids.add(workflow_id)
        self._retired_credential_ids.add(str(parent["credential_id"]))
        self._workflow_bindings[replacement_workflow_id] = {
            "experiment_variant": parent["experiment_variant"],
            "wallet_id": audit["wallet_id"],
            "wallet_local_audit": audit,
            "issuer_policy": dict(self.policy_metadata),
            "approval_artifact": approval_artifact,
            "approval_workflow_id": lineage,
            "credential_id": replacement_credential,
            "session_id": session_id,
            "approved_budget": approval_artifact.approved_budget,
            "settlement_verification": settlement_verification,
            "amendments_remaining": int(response.get("amendments_remaining", 0)),
        }
        self._amendment_counts[lineage] = self._amendment_counts.get(lineage, 0) + 1
        return response

    def workflow_binding(self, workflow_id: str) -> dict[str, Any]:
        binding = self._workflow_bindings.get(workflow_id)
        if binding is None:
            raise MinMandateServerError(f"unknown workflow binding: {workflow_id}")
        return dict(binding)

    def invoke(
        self,
        context: PaymentContext,
        slot_indices: int | list[int] | tuple[int, ...],
        attack: str = "none",
        session_id: str | None = None,
    ) -> dict[str, Any]:
        selected = [slot_indices] if isinstance(slot_indices, int) else list(slot_indices)
        active_workflow_id = session_id or context.workflow_id
        if active_workflow_id in self._retired_workflow_ids:
            raise MinMandateServerError(
                f"retired credential rejected before transport: {active_workflow_id}"
            )
        binding = self._workflow_bindings.get(active_workflow_id)
        if binding is None:
            raise MinMandateServerError(f"unknown workflow binding: {active_workflow_id}")
        request: dict[str, Any] = {
            "operation": "invoke",
            "workflow_id": active_workflow_id,
            "call_id": context.call_id,
            "service_id": context.tool_name,
            "service_class": context.service_class,
            "merchant_id": context.merchant_id,
            "request_fields": context.canonical_arguments,
            "amount": context.amount,
            "deadline": context.trusted_now + 60,
            "trusted_now": context.trusted_now,
            "slot_indices": selected,
            "attack": attack,
            "credential_id": binding["credential_id"],
            "replay_status": {
                "request_status": "claimed_replay" if attack == "replay" else "new",
                "call_id": context.call_id,
            },
            "settlement_authorization": {
                "authorized": False,
                "mode": "none_local_experiment",
            },
        }
        if len(selected) == 1:
            request["slot_index"] = selected[0]
        response = self.request(request)
        self.validate_response(response, active_workflow_id)
        merchant = response.get("merchant_view_serialized")
        redemption = response.get("redemption_view_serialized")
        if isinstance(merchant, dict) and isinstance(redemption, dict):
            merchant_evidence = _validate_view_contract(
                merchant, "merchant", self.policy_metadata
            )
            redemption_evidence = _validate_view_contract(
                redemption, "redemption", self.policy_metadata
            )
            if merchant_evidence != redemption_evidence:
                raise MinMandateServerError(
                    "merchant/redemption issuer-hiding evidence diverges"
                )
            if attack == "none":
                call_scope = (str(request["workflow_id"]), context.call_id)
                prior_for_call = self._call_issuer_evidence.get(call_scope)
                if prior_for_call is not None and prior_for_call != merchant_evidence:
                    raise MinMandateServerError(
                        "idempotent call changed randomized issuer evidence"
                    )
                owner = self._issuer_evidence_owner.get(merchant_evidence)
                if owner is not None and owner != call_scope:
                    raise MinMandateServerError(
                        "distinct calls reused a randomized issuer key/tag handle"
                    )
                self._call_issuer_evidence[call_scope] = merchant_evidence
                self._issuer_evidence_owner[merchant_evidence] = call_scope
        return response

    def validate_response(
        self, response: dict[str, Any], workflow_id: str | None = None
    ) -> ValidatedInvokeResponse:
        active_workflow_id = workflow_id or str(response.get("workflow_id") or "")
        binding = self._workflow_bindings.get(active_workflow_id)
        if binding is None:
            raise MinMandateServerError(
                f"cannot validate response for unknown workflow: {active_workflow_id}"
            )
        try:
            return validate_invoke_response(
                response,
                trusted_anchor=self.settlement_trust_anchor,
                settlement_verification=binding["settlement_verification"],
                issuer_policy_digest_sha256=self.policy_metadata[
                    "policy_digest_sha256"
                ],
                workflow_id=active_workflow_id,
                credential_id=binding["credential_id"],
                session_id=binding["session_id"],
                approved_budget=binding["approved_budget"],
                schnorr_batch_verifier=self.native_schnorr_validator.verify_batch,
                settlement_verification_prevalidated=True,
            )
        except MinMandateContractError as exc:
            raise MinMandateServerError(str(exc)) from exc

    def end_workflow(self, workflow_id: str) -> dict[str, Any]:
        binding = self._workflow_bindings.get(workflow_id)
        response = self.request({"operation": "end_workflow", "workflow_id": workflow_id})
        if response.get("ok"):
            self._workflow_bindings.pop(workflow_id, None)
            self._retired_workflow_ids.add(workflow_id)
            if binding and binding.get("credential_id"):
                self._retired_credential_ids.add(str(binding["credential_id"]))
            if response.get("credential_tombstoned") is not True:
                raise MinMandateServerError("end_workflow omitted credential tombstone")
        return response

    def close(self) -> None:
        self.native_schnorr_validator.close()
        if self.process.poll() is None:
            if self.process.stdin is not None:
                self.process.stdin.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=5)
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self.process.stderr is not None:
            self.process.stderr.close()

    def __enter__(self) -> "PersistentMinMandateClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def artifact_from_response(
    response: dict[str, Any],
    expected_policy: dict[str, Any] | None = None,
    *,
    validated: ValidatedInvokeResponse | None = None,
) -> PaymentArtifact:
    policy = expected_policy or response.get("issuer_policy")
    if not isinstance(policy, dict):
        raise MinMandateServerError("v3 response lacks issuer policy metadata")
    _validate_final_v3_envelope(response, policy)
    accepted = (
        validated.authorizes_merchant_result
        if validated is not None
        else response.get("status") in {"fresh_accept", "idempotent_receipt"}
    )
    merchant_view = response.get("merchant_view_serialized")
    redemption_view = response.get("redemption_view_serialized")
    if not isinstance(merchant_view, dict) or not isinstance(redemption_view, dict):
        if response.get("view_count") != 0 or response.get("crypto_executed") is True:
            raise MinMandateServerError("v3 response omitted executed crypto views")
        return PaymentArtifact(
            protocol="minmandate",
            protocol_version=PROTOCOL_VERSION,
            accepted=False,
            error_code=str(response.get("error_code") or "missing-view"),
            role_views=[],
            timing_ms={},
        )
    if response.get("view_count") != 2:
        raise MinMandateServerError("v3 invoke must report two transmitted protocol views")
    if response.get("crypto_executed") is not True:
        raise MinMandateServerError("v3 views reported without crypto execution")
    if response.get("crypto_scheme") != CRYPTO_SCHEME:
        raise MinMandateServerError("unexpected v3 crypto scheme")
    if response.get("issuer_hiding_crypto_executed") is not True:
        raise MinMandateServerError("v3 views lack issuer-hiding execution evidence")
    if response.get("stable_issuer_handle_disclosed") is not False:
        raise MinMandateServerError("v3 routine views disclose a stable issuer handle")
    _validate_wallet_local_audit(response.get("wallet_local_audit"), policy)
    merchant_evidence = _validate_view_contract(merchant_view, "merchant", policy)
    redemption_evidence = _validate_view_contract(redemption_view, "redemption", policy)
    if merchant_evidence != redemption_evidence:
        raise MinMandateServerError("merchant/redemption issuer evidence diverges")
    timing = {key: value for key, value in response.items() if key.endswith("_ms")}
    return PaymentArtifact(
        protocol="minmandate",
        protocol_version=PROTOCOL_VERSION,
        accepted=accepted,
        error_code=(
            None
            if accepted
            else str(
                validated.error_code
                if validated is not None
                else response.get("error_code") or "rejected"
            )
        ),
        role_views=[
            RoleView("merchant", "merchant", merchant_view, True, "v3 Rust public view", []),
            RoleView(
                "wallet_redemption",
                "interface_transcript",
                redemption_view,
                True,
                "v3 Rust wallet-redemption public view",
                [],
            ),
        ],
        timing_ms=timing,
    )
