use crate::{
    canonical_bytes, commitment_digest, g1_hex, g1_linear, g2_hex, hash_g1, hash_to_scalar,
    multi_pairing_check, random_scalar, scalar_map_value, Result, Scalar, G1, G2,
};
use ff::Field;
use group::Group;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const PROVER_BLIND_MESSAGE: &str = "__bbs_prover_blind";
pub(crate) const CIPHERSUITE_ID: &str = "MINMANDATE_BBS_BLS12381_SHA256_V1";
pub(crate) const SCHEMA_VERSION: &str = "minmandate-capability-v1";
pub(crate) const WIRE_INTEROPERABILITY: &str = "project-owned-not-cfrg-bbs-wire-interoperable";
const BBS_E_OVER_R: &str = "__bbs_e_over_r";
const BBS_INV_R: &str = "__bbs_inv_r";

pub(crate) type G1Relation = (BTreeMap<String, G1>, G1);

#[derive(Clone)]
pub(crate) struct PublicParams {
    pub(crate) suite_id: &'static str,
    pub(crate) schema_version: &'static str,
    pub(crate) g1: G1,
    pub(crate) g2: G2,
    pub(crate) h: BTreeMap<String, G1>,
    pub(crate) message_names: Vec<String>,
}

impl PublicParams {
    fn generator_value(&self) -> Value {
        json!({
            "suite_id": self.suite_id,
            "schema_version": self.schema_version,
            "g1": g1_hex(&self.g1),
            "g2": g2_hex(&self.g2),
            "message_generators": self.message_names.iter().map(|name| {
                (name.clone(), json!(g1_hex(&self.h[name])))
            }).collect::<serde_json::Map<String, Value>>(),
        })
    }

    pub(crate) fn generator_digest(&self) -> String {
        commitment_digest("mm-bbs-public-parameters-v1", &self.generator_value())
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut value = self.generator_value();
        value["generator_digest"] = json!(self.generator_digest());
        value["wire_interoperability"] = json!(WIRE_INTEROPERABILITY);
        value
    }

    pub(crate) fn same_as(&self, other: &Self) -> bool {
        self.suite_id == other.suite_id
            && self.schema_version == other.schema_version
            && self.g1 == other.g1
            && self.g2 == other.g2
            && self.message_names == other.message_names
            && self.h == other.h
            && self.generator_digest() == other.generator_digest()
    }

    pub(crate) fn is_valid(&self) -> bool {
        self.suite_id == CIPHERSUITE_ID
            && self.schema_version == SCHEMA_VERSION
            && self.g1 != G1::identity()
            && self.g2 != G2::identity()
            && !self.message_names.is_empty()
            && self.message_names.len() == self.h.len()
            && self.message_names.iter().all(|name| {
                self.h
                    .get(name)
                    .is_some_and(|point| *point != G1::identity())
            })
    }
}

#[derive(Clone)]
pub(crate) struct SecretKey {
    pub(crate) x: Scalar,
}

#[derive(Clone)]
pub(crate) struct PublicKey {
    pub(crate) x_tilde: G2,
    pub(crate) params: PublicParams,
}

impl PublicKey {
    pub(crate) fn scale(&self, alpha: Scalar) -> Self {
        Self {
            x_tilde: self.x_tilde * alpha,
            params: self.params.clone(),
        }
    }

    pub(crate) fn issuer_value(&self) -> Value {
        json!({"X_tilde": g2_hex(&self.x_tilde)})
    }

    pub(crate) fn to_value(&self) -> Value {
        json!({
            "X_tilde": g2_hex(&self.x_tilde),
            "parameters": self.params.to_value(),
        })
    }

    pub(crate) fn same_parameters(&self, other: &Self) -> bool {
        self.params.same_as(&other.params)
    }

    pub(crate) fn is_valid(&self) -> bool {
        self.x_tilde != G2::identity() && self.params.is_valid()
    }
}

#[derive(Clone)]
pub(crate) struct Signature {
    pub(crate) a: G1,
    pub(crate) e: Scalar,
}

impl Signature {
    pub(crate) fn to_value(&self) -> Value {
        json!({"A": g1_hex(&self.a), "e": crate::scalar_hex(&self.e)})
    }
}

#[derive(Clone)]
pub(crate) struct Credential {
    pub(crate) signature: Signature,
    pub(crate) messages: BTreeMap<String, Scalar>,
}

#[derive(Clone)]
pub(crate) struct Proof {
    pub(crate) a_bar: G1,
    pub(crate) b_bar: G1,
    pub(crate) commitments: Vec<G1>,
    pub(crate) responses: BTreeMap<String, Scalar>,
}

impl Proof {
    pub(crate) fn to_value(&self) -> Value {
        json!({
            "A_bar": g1_hex(&self.a_bar),
            "B_bar": g1_hex(&self.b_bar),
            "commitments": self.commitments.iter().map(g1_hex).collect::<Vec<_>>(),
            "responses": scalar_map_value(&self.responses),
        })
    }
}

#[derive(Clone)]
pub(crate) struct Presentation {
    pub(crate) disclosed_messages: BTreeMap<String, Scalar>,
    pub(crate) proof: Proof,
}

impl Presentation {
    pub(crate) fn to_value(&self) -> Value {
        json!({
            "bbs_selective_disclosure_proof": self.proof.to_value(),
            "disclosed_messages": scalar_map_value(&self.disclosed_messages),
        })
    }
}

pub(crate) fn setup(message_names: &[String]) -> PublicParams {
    let mut names = message_names.to_vec();
    if !names.iter().any(|name| name == PROVER_BLIND_MESSAGE) {
        names.push(PROVER_BLIND_MESSAGE.to_string());
    }
    let h = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            (
                name.clone(),
                hash_g1(&format!("minmandate-bbs-h:{index}:{name}")),
            )
        })
        .collect();
    PublicParams {
        // Project-owned suite: the algebra follows BBS and IHBBS1, while the
        // generator derivation and wire objects are not CFRG BBS compatible.
        suite_id: CIPHERSUITE_ID,
        schema_version: SCHEMA_VERSION,
        g1: hash_g1("minmandate-bbs-g1"),
        g2: G2::generator(),
        h,
        message_names: names,
    }
}

pub(crate) fn keygen(params: &PublicParams) -> (SecretKey, PublicKey) {
    keygen_with_secret(params, random_scalar())
}

pub(crate) fn keygen_with_secret(params: &PublicParams, x: Scalar) -> (SecretKey, PublicKey) {
    assert!(x != Scalar::ZERO, "BBS issuer key must be nonzero");
    (
        SecretKey { x },
        PublicKey {
            x_tilde: params.g2 * x,
            params: params.clone(),
        },
    )
}

pub(crate) fn commitment(params: &PublicParams, messages: &BTreeMap<String, Scalar>) -> Result<G1> {
    if messages.keys().cloned().collect::<BTreeSet<_>>()
        != params
            .message_names
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
    {
        return Err("BBS message vector does not match the fixed layout".to_string());
    }
    let mut value = params.g1;
    for name in &params.message_names {
        value += params.h[name] * messages[name];
    }
    Ok(value)
}

pub(crate) fn sign(
    sk: &SecretKey,
    pk: &PublicKey,
    messages: &BTreeMap<String, Scalar>,
) -> Result<Signature> {
    let c = commitment(&pk.params, messages)?;
    let mut e = random_scalar();
    while sk.x + e == Scalar::ZERO {
        e = random_scalar();
    }
    let denominator_inv = Option::<Scalar>::from((sk.x + e).invert())
        .ok_or_else(|| "BBS signature denominator is zero".to_string())?;
    Ok(Signature {
        a: c * denominator_inv,
        e,
    })
}

/// Issue an ordinary BBS credential over an issuer-visible message vector.
///
/// MinMandate's main threat model trusts the wallet and excludes its joined
/// issuance/redemption state from the privacy adversary.  The main protocol
/// therefore uses ordinary issuance; the optional blind-issuance extension is
/// implemented separately in `blind_bbs`.
pub(crate) fn issue(
    sk: &SecretKey,
    pk: &PublicKey,
    messages: &BTreeMap<String, Scalar>,
) -> Result<Credential> {
    if !pk.is_valid() || pk.x_tilde != pk.params.g2 * sk.x {
        return Err("BBS issuer public/secret key mismatch".to_string());
    }
    let signature = sign(sk, pk, messages)?;
    Ok(Credential {
        signature,
        messages: messages.clone(),
    })
}

pub(crate) fn verify(
    pk: &PublicKey,
    signature: &Signature,
    messages: &BTreeMap<String, Scalar>,
) -> bool {
    if !pk.is_valid() || signature.a == G1::identity() {
        return false;
    }
    let Ok(c) = commitment(&pk.params, messages) else {
        return false;
    };
    multi_pairing_check(&[
        (pk.x_tilde + pk.params.g2 * signature.e, signature.a),
        (-pk.params.g2, c),
    ])
}

fn disclosure(
    pk: &PublicKey,
    credential: &Credential,
    disclosed_names: &[String],
) -> Result<(BTreeMap<String, Scalar>, Vec<String>)> {
    let disclosed_set = disclosed_names.iter().cloned().collect::<BTreeSet<_>>();
    if disclosed_set.len() != disclosed_names.len()
        || disclosed_names
            .iter()
            .any(|name| !pk.params.message_names.contains(name))
    {
        return Err("invalid BBS disclosure set".to_string());
    }
    let disclosed = disclosed_names
        .iter()
        .map(|name| {
            credential
                .messages
                .get(name)
                .copied()
                .map(|value| (name.clone(), value))
                .ok_or_else(|| format!("credential is missing message {name}"))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let hidden = pk
        .params
        .message_names
        .iter()
        .filter(|name| !disclosed_set.contains(*name))
        .cloned()
        .collect();
    Ok((disclosed, hidden))
}

fn bbs_relation(
    pk: &PublicKey,
    disclosed: &BTreeMap<String, Scalar>,
    hidden_names: &[String],
    a_bar: G1,
    b_bar: G1,
) -> G1Relation {
    let mut bases = hidden_names
        .iter()
        .map(|name| (name.clone(), pk.params.h[name]))
        .collect::<BTreeMap<_, _>>();
    bases.insert(BBS_E_OVER_R.to_string(), a_bar);
    bases.insert(BBS_INV_R.to_string(), b_bar);
    let mut target = -pk.params.g1;
    for (name, message) in disclosed {
        target -= pk.params.h[name] * *message;
    }
    (bases, target)
}

fn challenge(
    label: &str,
    pk: &PublicKey,
    disclosed: &BTreeMap<String, Scalar>,
    relations: &[G1Relation],
    a_bar: &G1,
    b_bar: &G1,
    commitments: &[G1],
    context: &Value,
) -> Scalar {
    let relation_values = relations
        .iter()
        .map(|(bases, target)| {
            json!({
                "bases": bases.iter().map(|(name, point)| {
                    (name.clone(), json!(g1_hex(point)))
                }).collect::<serde_json::Map<String, Value>>(),
                "target": g1_hex(target),
            })
        })
        .collect::<Vec<_>>();
    hash_to_scalar(
        label,
        &[
            canonical_bytes(context),
            canonical_bytes(&pk.to_value()),
            canonical_bytes(&scalar_map_value(disclosed)),
            canonical_bytes(&json!(relation_values)),
            g1_hex(a_bar).into_bytes(),
            g1_hex(b_bar).into_bytes(),
            canonical_bytes(&json!(commitments.iter().map(g1_hex).collect::<Vec<_>>())),
        ],
    )
}

pub(crate) fn proof_gen(
    pk: &PublicKey,
    credential: &Credential,
    adapted_signature: &Signature,
    disclosed_names: &[String],
    auxiliary_relations: &[G1Relation],
    auxiliary_secrets: &BTreeMap<String, Scalar>,
    context: &Value,
    label: &str,
) -> Result<Presentation> {
    proof_gen_inner(
        pk,
        credential,
        None,
        adapted_signature,
        disclosed_names,
        auxiliary_relations,
        auxiliary_secrets,
        context,
        label,
        true,
    )
}

/// Generate a proof after the immutable holder credential and the locally
/// derived adapted signature have been verified by the workflow setup path.
pub(crate) fn proof_gen_for_verified_credential(
    pk: &PublicKey,
    credential: &Credential,
    credential_commitment: G1,
    adapted_signature: &Signature,
    disclosed_names: &[String],
    auxiliary_relations: &[G1Relation],
    auxiliary_secrets: &BTreeMap<String, Scalar>,
    context: &Value,
    label: &str,
) -> Result<Presentation> {
    proof_gen_inner(
        pk,
        credential,
        Some(credential_commitment),
        adapted_signature,
        disclosed_names,
        auxiliary_relations,
        auxiliary_secrets,
        context,
        label,
        false,
    )
}

fn proof_gen_inner(
    pk: &PublicKey,
    credential: &Credential,
    cached_credential_commitment: Option<G1>,
    adapted_signature: &Signature,
    disclosed_names: &[String],
    auxiliary_relations: &[G1Relation],
    auxiliary_secrets: &BTreeMap<String, Scalar>,
    context: &Value,
    label: &str,
    verify_credential: bool,
) -> Result<Presentation> {
    if verify_credential && !verify(pk, adapted_signature, &credential.messages) {
        return Err("cannot present an invalid adapted BBS credential".to_string());
    }
    let (disclosed, hidden_names) = disclosure(pk, credential, disclosed_names)?;
    let c_m = cached_credential_commitment
        .map(Ok)
        .unwrap_or_else(|| commitment(&pk.params, &credential.messages))?;
    let r = random_scalar();
    let r_inv = Option::<Scalar>::from(r.invert())
        .ok_or_else(|| "BBS proof randomizer is zero".to_string())?;
    let a_bar = adapted_signature.a * r;
    let b_bar = c_m * r - a_bar * adapted_signature.e;

    let mut secrets = hidden_names
        .iter()
        .map(|name| (name.clone(), credential.messages[name]))
        .collect::<BTreeMap<_, _>>();
    secrets.insert(BBS_E_OVER_R.to_string(), -(adapted_signature.e * r_inv));
    secrets.insert(BBS_INV_R.to_string(), -r_inv);
    for (bases, _) in auxiliary_relations {
        for name in bases.keys() {
            if let Some(secret) = auxiliary_secrets.get(name) {
                if let Some(existing) = secrets.insert(name.clone(), *secret) {
                    if existing != *secret {
                        return Err(format!("conflicting witness for {name}"));
                    }
                }
            } else if !secrets.contains_key(name) {
                return Err(format!("missing auxiliary witness {name}"));
            }
        }
    }

    let mut relations = vec![bbs_relation(pk, &disclosed, &hidden_names, a_bar, b_bar)];
    relations.extend_from_slice(auxiliary_relations);
    let witness_names = relations
        .iter()
        .flat_map(|(bases, _)| bases.keys().cloned())
        .collect::<BTreeSet<_>>();
    if witness_names.iter().any(|name| !secrets.contains_key(name)) {
        return Err("BBS proof relation has an unbound witness".to_string());
    }
    let blindings = witness_names
        .iter()
        .map(|name| (name.clone(), random_scalar()))
        .collect::<BTreeMap<_, _>>();
    let commitments = relations
        .iter()
        .map(|(bases, _)| g1_linear(bases.iter().map(|(name, base)| (base, blindings[name]))))
        .collect::<Vec<_>>();
    let c = challenge(
        label,
        pk,
        &disclosed,
        &relations,
        &a_bar,
        &b_bar,
        &commitments,
        context,
    );
    let responses = witness_names
        .iter()
        .map(|name| (name.clone(), blindings[name] + c * secrets[name]))
        .collect();
    Ok(Presentation {
        disclosed_messages: disclosed,
        proof: Proof {
            a_bar,
            b_bar,
            commitments,
            responses,
        },
    })
}

pub(crate) fn proof_pairing_terms(
    pk: &PublicKey,
    presentation: &Presentation,
    auxiliary_relations: &[G1Relation],
    context: &Value,
    label: &str,
) -> Option<Vec<(G2, G1)>> {
    if !pk.is_valid()
        || presentation.proof.a_bar == G1::identity()
        || presentation.proof.b_bar == G1::identity()
    {
        return None;
    }
    let disclosed_names = presentation
        .disclosed_messages
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if disclosed_names
        .iter()
        .any(|name| !pk.params.message_names.contains(name))
    {
        return None;
    }
    let hidden_names = pk
        .params
        .message_names
        .iter()
        .filter(|name| !disclosed_names.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    let mut relations = vec![bbs_relation(
        pk,
        &presentation.disclosed_messages,
        &hidden_names,
        presentation.proof.a_bar,
        presentation.proof.b_bar,
    )];
    relations.extend_from_slice(auxiliary_relations);
    if relations.len() != presentation.proof.commitments.len() {
        return None;
    }
    let names = relations
        .iter()
        .flat_map(|(bases, _)| bases.keys().cloned())
        .collect::<BTreeSet<_>>();
    if names
        != presentation
            .proof
            .responses
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
    {
        return None;
    }
    let c = challenge(
        label,
        pk,
        &presentation.disclosed_messages,
        &relations,
        &presentation.proof.a_bar,
        &presentation.proof.b_bar,
        &presentation.proof.commitments,
        context,
    );
    for ((bases, target), commitment) in relations.iter().zip(&presentation.proof.commitments) {
        let lhs = g1_linear(
            bases
                .iter()
                .map(|(name, base)| (base, presentation.proof.responses[name])),
        );
        if lhs != *commitment + *target * c {
            return None;
        }
    }
    Some(vec![
        (pk.x_tilde, presentation.proof.a_bar),
        (-pk.params.g2, presentation.proof.b_bar),
    ])
}

pub(crate) fn proof_verify(
    pk: &PublicKey,
    presentation: &Presentation,
    auxiliary_relations: &[G1Relation],
    context: &Value,
    label: &str,
) -> bool {
    proof_pairing_terms(pk, presentation, auxiliary_relations, context, label)
        .is_some_and(|terms| multi_pairing_check(&terms))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_messages(params: &PublicParams) -> BTreeMap<String, Scalar> {
        params
            .message_names
            .iter()
            .enumerate()
            .map(|(index, name)| (name.clone(), Scalar::from((index + 1) as u64)))
            .collect()
    }

    #[test]
    fn ordinary_issue_signs_the_complete_fixed_layout() {
        let params = setup(&["policy".to_string(), "serial_seed".to_string()]);
        let (sk, pk) = keygen(&params);
        let messages = fixed_messages(&params);

        let credential = issue(&sk, &pk, &messages).expect("ordinary issuance succeeds");

        assert_eq!(credential.messages, messages);
        assert!(verify(&pk, &credential.signature, &credential.messages));
    }

    #[test]
    fn ordinary_issue_rejects_key_mismatch_and_partial_layout() {
        let params = setup(&["policy".to_string(), "serial_seed".to_string()]);
        let (sk, pk) = keygen(&params);
        let (other_sk, _) = keygen(&params);
        let messages = fixed_messages(&params);
        assert!(issue(&other_sk, &pk, &messages).is_err());

        let mut partial = messages;
        partial.remove("serial_seed");
        assert!(issue(&sk, &pk, &partial).is_err());
    }
}
