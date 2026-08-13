from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_b64url(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _decode_b64url_json(value: str) -> dict[str, Any]:
    padded = value + "=" * (-len(value) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def root_jwt(token: str) -> str:
    return token.split("~~", 1)[0].split("~", 1)[0]


def jwt_header(jwt: str) -> dict[str, Any]:
    return _decode_b64url_json(jwt.split(".")[0])


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    # RFC 7638 members for an EC JWK.
    public = {k: jwk[k] for k in ("crv", "kty", "x", "y") if k in jwk}
    return sha256_b64url(canonical_json_bytes(public))


@dataclass(slots=True)
class AP2WireRecord:
    workflow_id: str
    call_id: str
    pair_id: str
    open_checkout_token: str
    open_payment_token: str
    checkout_chain: str
    payment_chain: str
    checkout_jwt: str
    checkout_receipt_jwt: str
    payment_receipt_jwt: str
    effective_open_checkout: dict[str, Any]
    effective_open_payment: dict[str, Any]

    def byte_sizes(self) -> dict[str, int]:
        values = {
            "open_checkout": self.open_checkout_token,
            "open_payment": self.open_payment_token,
            "checkout_chain": self.checkout_chain,
            "payment_chain": self.payment_chain,
            "checkout_jwt": self.checkout_jwt,
            "checkout_receipt": self.checkout_receipt_jwt,
            "payment_receipt": self.payment_receipt_jwt,
        }
        sizes = {k: len(v.encode()) for k, v in values.items()}
        sizes["total_transmitted"] = sum(
            sizes[k]
            for k in (
                "checkout_chain",
                "payment_chain",
                "checkout_jwt",
                "checkout_receipt",
                "payment_receipt",
            )
        )
        return sizes

    def stable_fields(self) -> dict[str, str]:
        checkout_root = root_jwt(self.open_checkout_token)
        payment_root = root_jwt(self.open_payment_token)
        checkout_cnf = self.effective_open_checkout.get("cnf", {}).get("jwk", {})
        payment_cnf = self.effective_open_payment.get("cnf", {}).get("jwk", {})
        return {
            "checkout_root_jwt_sha256": sha256_b64url(checkout_root),
            "payment_root_jwt_sha256": sha256_b64url(payment_root),
            "checkout_issuer_kid": str(jwt_header(checkout_root).get("kid", "")),
            "payment_issuer_kid": str(jwt_header(payment_root).get("kid", "")),
            "checkout_cnf_thumbprint": jwk_thumbprint(checkout_cnf) if checkout_cnf else "",
            "payment_cnf_thumbprint": jwk_thumbprint(payment_cnf) if payment_cnf else "",
        }

    def to_sanitized_dict(self, include_tokens: bool = True) -> dict[str, Any]:
        out = {
            "workflow_id": self.workflow_id,
            "call_id": self.call_id,
            "pair_id": self.pair_id,
            "byte_sizes": self.byte_sizes(),
            "stable_fields": self.stable_fields(),
            "effective_open_checkout": self.effective_open_checkout,
            "effective_open_payment": self.effective_open_payment,
        }
        if include_tokens:
            out["wire"] = {
                "open_checkout_token": self.open_checkout_token,
                "open_payment_token": self.open_payment_token,
                "checkout_chain": self.checkout_chain,
                "payment_chain": self.payment_chain,
                "checkout_jwt": self.checkout_jwt,
                "checkout_receipt_jwt": self.checkout_receipt_jwt,
                "payment_receipt_jwt": self.payment_receipt_jwt,
            }
        return out
