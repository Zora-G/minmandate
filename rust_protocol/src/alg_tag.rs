use crate::{g1_hex, g2_hex, multi_pairing_check, random_scalar, Scalar, G1, G2};
use ff::Field;
use group::Group;
use serde_json::{json, Value};

#[derive(Clone)]
pub(crate) struct SecretKey(pub(crate) Scalar);

#[derive(Clone)]
pub(crate) struct VerificationKey {
    pub(crate) g_v: G1,
    pub(crate) t_v: G1,
}

impl VerificationKey {
    pub(crate) fn to_value(&self) -> Value {
        json!({"G_v": g1_hex(&self.g_v), "T_v": g1_hex(&self.t_v)})
    }
}

#[derive(Clone)]
pub(crate) struct Tag(pub(crate) G2);

impl Tag {
    pub(crate) fn to_value(&self) -> Value {
        json!(g2_hex(&self.0))
    }
}

pub(crate) fn keygen() -> (SecretKey, VerificationKey) {
    keygen_with_material(random_scalar(), G1::generator() * random_scalar())
}

pub(crate) fn keygen_with_material(x_v: Scalar, g_v: G1) -> (SecretKey, VerificationKey) {
    assert!(x_v != Scalar::ZERO, "algTag secret must be nonzero");
    assert!(
        g_v != G1::identity(),
        "algTag generator must be nonidentity"
    );
    let inv = Option::<Scalar>::from(x_v.invert()).expect("nonzero algTag secret");
    (
        SecretKey(x_v),
        VerificationKey {
            g_v,
            t_v: g_v * inv,
        },
    )
}

pub(crate) fn tag(sk: &SecretKey, issuer_pk: G2) -> Tag {
    let inv = Option::<Scalar>::from(sk.0.invert()).expect("nonzero algTag secret");
    Tag(issuer_pk * inv)
}

pub(crate) fn verify(vk: &VerificationKey, tag: &Tag, issuer_pk: G2) -> bool {
    issuer_pk != G2::identity()
        && tag.0 != G2::identity()
        && vk.g_v != G1::identity()
        && vk.t_v != G1::identity()
        && multi_pairing_check(&[(issuer_pk, vk.t_v), (-tag.0, vk.g_v)])
}
