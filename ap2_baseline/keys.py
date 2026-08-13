from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK


def generate_p256_jwk(kid: str) -> JWK:
    if not kid:
        raise ValueError("kid is required")
    raw = ec.generate_private_key(ec.SECP256R1())
    data = json.loads(JWK.from_pyca(raw).export())
    data["kid"] = kid
    return JWK(**data)


def public_jwk_dict(key: JWK) -> dict:
    return json.loads(key.export_public())


@dataclass(slots=True)
class KeyBundle:
    trusted_surface: JWK
    agent: JWK
    mpp: JWK
    merchants: dict[str, JWK]

    @classmethod
    def generate(cls, merchant_ids: list[str]) -> "KeyBundle":
        return cls(
            trusted_surface=generate_p256_jwk("eval-user-ap2-v0.2"),
            agent=generate_p256_jwk("eval-agent-ap2-v0.2"),
            mpp=generate_p256_jwk("eval-mpp-ap2-v0.2"),
            merchants={mid: generate_p256_jwk(f"merchant-{mid}") for mid in sorted(set(merchant_ids))},
        )
