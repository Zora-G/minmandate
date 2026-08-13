//! Optional Blind-BBS issuance extension.
//!
//! MinMandate's measured main path uses ordinary issuer-visible issuance in
//! `bbs::issue`.  This module is retained for the appendix extension and its
//! stronger issuer-privacy goal; production and benchmark dispatch must not
//! enter it implicitly.

use crate::bbs::{self, Credential, PublicKey, SecretKey, Signature, PROVER_BLIND_MESSAGE};
use crate::{
    g1_hex, g1_linear, prove_representation_g1, random_scalar, verify_representation_g1,
    RepProofG1, Result, Scalar, G1,
};
use ff::Field;
use group::Group;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
pub(crate) struct HolderState {
    pub(crate) prover_blind: Scalar,
}

#[derive(Clone)]
pub(crate) struct BlindCommitment {
    pub(crate) commitment: G1,
    pub(crate) proof: RepProofG1,
    pub(crate) hidden_names: Vec<String>,
}

impl BlindCommitment {
    pub(crate) fn to_value(&self) -> Value {
        json!({
            "commitment": g1_hex(&self.commitment),
            "proof": self.proof.to_value(),
            "hidden_names": self.hidden_names,
            "prover_blind_committed": true,
        })
    }
}

fn holder_commit_with_blind(
    pk: &PublicKey,
    hidden_messages: &BTreeMap<String, Scalar>,
    context: &Value,
    prover_blind: Scalar,
) -> Result<(BlindCommitment, HolderState)> {
    if hidden_messages.is_empty()
        || prover_blind == Scalar::ZERO
        || hidden_messages
            .keys()
            .any(|name| !pk.params.message_names.contains(name) || name == PROVER_BLIND_MESSAGE)
    {
        return Err("invalid Blind BBS hidden-message set".to_string());
    }
    let mut bases = hidden_messages
        .keys()
        .map(|name| (name.clone(), pk.params.h[name]))
        .collect::<BTreeMap<_, _>>();
    bases.insert(
        PROVER_BLIND_MESSAGE.to_string(),
        pk.params.h[PROVER_BLIND_MESSAGE],
    );
    let mut secrets = hidden_messages.clone();
    secrets.insert(PROVER_BLIND_MESSAGE.to_string(), prover_blind);
    let commitment = g1_linear(bases.iter().map(|(name, base)| (base, secrets[name])));
    if commitment == G1::identity() {
        return Err("Blind BBS commitment must be nonidentity".to_string());
    }
    let proof = prove_representation_g1(
        "mm-blind-bbs-commitment-v1",
        &bases,
        &secrets,
        &commitment,
        context,
    );
    let hidden_names = hidden_messages.keys().cloned().collect();
    Ok((
        BlindCommitment {
            commitment,
            proof,
            hidden_names,
        },
        HolderState { prover_blind },
    ))
}

pub(crate) fn holder_commit(
    pk: &PublicKey,
    hidden_messages: &BTreeMap<String, Scalar>,
    context: &Value,
) -> Result<(BlindCommitment, HolderState)> {
    holder_commit_with_blind(pk, hidden_messages, context, random_scalar())
}

fn issuer_blind_sign_with_e(
    sk: &SecretKey,
    pk: &PublicKey,
    visible_messages: &BTreeMap<String, Scalar>,
    request: &BlindCommitment,
    context: &Value,
    e: Scalar,
) -> Result<Signature> {
    if !pk.is_valid() || pk.x_tilde != pk.params.g2 * sk.x {
        return Err("Blind BBS issuer public/secret key mismatch".to_string());
    }
    if request.commitment == G1::identity() {
        return Err("Blind BBS identity commitment is forbidden".to_string());
    }
    let hidden_names = request
        .hidden_names
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if hidden_names.len() != request.hidden_names.len()
        || visible_messages
            .keys()
            .any(|name| hidden_names.contains(name) || !pk.params.message_names.contains(name))
    {
        return Err("Blind BBS issuance layout is inconsistent".to_string());
    }
    let mut bases = request
        .hidden_names
        .iter()
        .map(|name| (name.clone(), pk.params.h[name]))
        .collect::<BTreeMap<_, _>>();
    bases.insert(
        PROVER_BLIND_MESSAGE.to_string(),
        pk.params.h[PROVER_BLIND_MESSAGE],
    );
    if !verify_representation_g1(
        "mm-blind-bbs-commitment-v1",
        &bases,
        &request.commitment,
        &request.proof,
        context,
    ) {
        return Err("invalid Blind BBS commitment proof".to_string());
    }
    let expected = pk
        .params
        .message_names
        .iter()
        .filter(|name| name.as_str() != PROVER_BLIND_MESSAGE)
        .cloned()
        .collect::<BTreeSet<_>>();
    let provided = visible_messages
        .keys()
        .cloned()
        .chain(request.hidden_names.iter().cloned())
        .collect::<BTreeSet<_>>();
    if provided != expected {
        return Err("Blind BBS request does not cover the fixed message layout".to_string());
    }
    let mut b = pk.params.g1 + request.commitment;
    for (name, message) in visible_messages {
        b += pk.params.h[name] * *message;
    }
    if sk.x + e == Scalar::ZERO {
        return Err("Blind BBS signature denominator is zero".to_string());
    }
    let inv = Option::<Scalar>::from((sk.x + e).invert())
        .ok_or_else(|| "Blind BBS signature denominator is zero".to_string())?;
    Ok(Signature { a: b * inv, e })
}

pub(crate) fn issuer_blind_sign(
    sk: &SecretKey,
    pk: &PublicKey,
    visible_messages: &BTreeMap<String, Scalar>,
    request: &BlindCommitment,
    context: &Value,
) -> Result<Signature> {
    let mut e = random_scalar();
    while sk.x + e == Scalar::ZERO {
        e = random_scalar();
    }
    issuer_blind_sign_with_e(sk, pk, visible_messages, request, context, e)
}

pub(crate) fn holder_finalize(
    pk: &PublicKey,
    signature: &Signature,
    visible_messages: &BTreeMap<String, Scalar>,
    hidden_messages: &BTreeMap<String, Scalar>,
    holder_state: &HolderState,
) -> Result<Credential> {
    if visible_messages
        .keys()
        .any(|name| hidden_messages.contains_key(name))
    {
        return Err("Blind BBS holder inputs overlap".to_string());
    }
    let mut messages = visible_messages.clone();
    messages.extend(hidden_messages.clone());
    messages.insert(PROVER_BLIND_MESSAGE.to_string(), holder_state.prover_blind);
    if !bbs::verify(pk, signature, &messages) {
        return Err("issuer returned an invalid Blind BBS credential".to_string());
    }
    Ok(Credential {
        signature: signature.clone(),
        messages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{g1_hex, g2_hex};

    #[test]
    fn blind_bbs_fixed_vector_matches_independent_signature_equation() {
        let params = bbs::setup(&["visible".to_string(), "hidden".to_string()]);
        let (sk, pk) = bbs::keygen_with_secret(&params, Scalar::from(7u64));
        let visible = BTreeMap::from([("visible".to_string(), Scalar::from(3u64))]);
        let hidden = BTreeMap::from([("hidden".to_string(), Scalar::from(5u64))]);
        let context = json!({"vector": "blind-bbs-v1"});
        let (request, holder_state) =
            holder_commit_with_blind(&pk, &hidden, &context, Scalar::from(11u64)).unwrap();
        assert_eq!(
            g1_hex(&request.commitment),
            "88fce85f8d39fd2685dc78845dd48382427e189706ec2c1788415e6dbc689c5c4364695b2bd6413aef4416ea3200ee51"
        );
        assert_eq!(
            g2_hex(&pk.x_tilde),
            "849cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c0d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8"
        );
        let signature =
            issuer_blind_sign_with_e(&sk, &pk, &visible, &request, &context, Scalar::from(13u64))
                .unwrap();
        assert_eq!(
            g1_hex(&signature.a),
            "a0d7aadff3503a114198b9f920cd1318bf4bc8b49f7ed5bf34460950d0b4d55cf744c6ae42b76b28119b6d23528a7b4b"
        );
        let credential =
            holder_finalize(&pk, &signature, &visible, &hidden, &holder_state).unwrap();
        let commitment = bbs::commitment(&params, &credential.messages).unwrap();
        assert_eq!(signature.a * (sk.x + signature.e), commitment);
        assert!(bbs::verify(&pk, &signature, &credential.messages));
    }

    #[test]
    fn issuer_rejects_identity_commitment_and_key_mismatch() {
        let params = bbs::setup(&["visible".to_string(), "hidden".to_string()]);
        let (sk, pk) = bbs::keygen_with_secret(&params, Scalar::from(7u64));
        let (_, wrong_pk) = bbs::keygen_with_secret(&params, Scalar::from(9u64));
        let visible = BTreeMap::from([("visible".to_string(), Scalar::from(3u64))]);
        let hidden = BTreeMap::from([("hidden".to_string(), Scalar::from(5u64))]);
        let context = json!({"vector": "blind-bbs-boundary-v1"});
        let (mut request, _) = holder_commit(&pk, &hidden, &context).unwrap();
        assert!(issuer_blind_sign(&sk, &wrong_pk, &visible, &request, &context).is_err());
        request.commitment = G1::identity();
        assert!(issuer_blind_sign(&sk, &pk, &visible, &request, &context).is_err());
    }
}
