use crate::alg_tag::{self, Tag, VerificationKey};
use crate::bbs::{
    self, Credential, G1Relation, Presentation, PublicKey, PublicParams, SecretKey, Signature,
};
use crate::{
    commitment_digest, g2_hex, hash_to_scalar, random_scalar, Result, Scalar, Value, G1, G2,
};
use ff::Field;
use group::Group;
use serde_json::json;
use std::collections::BTreeSet;

pub(crate) const DETERMINISTIC_TEST_FIXTURE_ISSUERS: usize = 8;
pub(crate) const DETERMINISTIC_TEST_KEY_PROFILE: &str =
    "deterministic-public-test-secrets-non-production";

#[derive(Clone)]
pub(crate) struct PolicyBundle {
    pub(crate) suite_id: String,
    pub(crate) schema_version: String,
    pub(crate) public_parameter_digest: String,
    pub(crate) key_material_profile: String,
    pub(crate) epoch: String,
    pub(crate) valid_from: u64,
    pub(crate) valid_until: u64,
    pub(crate) registry_digest: String,
    pub(crate) issuers: Vec<PublicKey>,
    pub(crate) tag_vk: VerificationKey,
    pub(crate) issuer_tags: Vec<Tag>,
    pub(crate) policy_digest: String,
}

impl PolicyBundle {
    fn unsigned_value(&self) -> Value {
        json!({
            "suite_id": self.suite_id,
            "schema_version": self.schema_version,
            "public_parameter_digest": self.public_parameter_digest,
            "key_material_profile": self.key_material_profile,
            "epoch": self.epoch,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "registry_digest": self.registry_digest,
            "issuers": self.issuers.iter().map(PublicKey::issuer_value).collect::<Vec<_>>(),
            "tag_verification_key": self.tag_vk.to_value(),
            "issuer_tags": self.issuer_tags.iter().map(Tag::to_value).collect::<Vec<_>>(),
        })
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut value = self.unsigned_value();
        value["policy_digest"] = json!(self.policy_digest);
        value
    }

    pub(crate) fn canonical_public_bytes(&self) -> Vec<u8> {
        crate::canonical_bytes(&self.unsigned_value())
    }

    pub(crate) fn member_tag(&self, issuer_pk: &PublicKey) -> Option<Tag> {
        self.issuers
            .iter()
            .position(|candidate| candidate.x_tilde == issuer_pk.x_tilde)
            .map(|index| self.issuer_tags[index].clone())
    }
}

fn policy_parameter_digest() -> String {
    commitment_digest(
        "mm-ihbbs1-policy-parameters-v1",
        &json!({
            "suite_id": bbs::CIPHERSUITE_ID,
            "schema_version": bbs::SCHEMA_VERSION,
            "curve": "BLS12-381",
            "issuer_key_generator": g2_hex(&G2::generator()),
        }),
    )
}

#[derive(Clone)]
pub(crate) struct HolderIssuerState {
    pub(crate) issuer_pk: PublicKey,
    pub(crate) issuer_tag: Tag,
    pub(crate) epoch: String,
    pub(crate) expiry: u64,
    pub(crate) registry_digest: String,
    pub(crate) policy_digest: String,
}

#[derive(Clone)]
pub(crate) struct Authorization {
    pub(crate) epoch: String,
    pub(crate) expiry: u64,
    pub(crate) registry_digest: String,
    pub(crate) policy_digest: String,
    pub(crate) public_parameter_digest: String,
    pub(crate) issuer_count: usize,
    pub(crate) randomized_issuer_pk: RandomizedIssuerKey,
    pub(crate) randomized_policy_tag: Tag,
    pub(crate) invocation_binding: String,
}

#[derive(Clone)]
pub(crate) struct RandomizedIssuerKey {
    pub(crate) x_tilde: G2,
}

impl RandomizedIssuerKey {
    fn issuer_value(&self) -> Value {
        json!({"X_tilde": g2_hex(&self.x_tilde)})
    }
}

#[derive(Clone)]
pub(crate) struct PresentationSession {
    pub(crate) authorization: Authorization,
    randomized_issuer_pk: PublicKey,
    adapted_signature: Signature,
}

impl Authorization {
    pub(crate) fn statement_value(&self) -> Value {
        json!({
            "scheme": crate::ISSUER_HIDING_SCHEME,
            "randomized_issuer_pk": self.randomized_issuer_pk.issuer_value(),
            "randomized_policy_tag": self.randomized_policy_tag.to_value(),
            "policy_statement": {
                "profile": "IHBBS1-Type-1-policy-v1",
                "epoch": self.epoch,
                "expiry": self.expiry,
                "registry_digest": self.registry_digest,
                "policy_digest": self.policy_digest,
                "public_parameter_digest": self.public_parameter_digest,
                "issuer_count": self.issuer_count,
            },
        })
    }

    fn digest_for(&self, invocation_id: &str) -> String {
        commitment_digest(
            "MM-IHBBS1-invocation-v1",
            &json!({
                "policy_digest": self.policy_digest,
                "authorization": self.statement_value(),
                "I": invocation_id,
            }),
        )
    }

    pub(crate) fn to_value(&self) -> Value {
        self.to_value_with_redemption_binding(None)
    }

    pub(crate) fn to_value_with_redemption_binding(
        &self,
        redemption_binding: Option<&str>,
    ) -> Value {
        let mut value = self.statement_value();
        value["invocation_binding"] = json!(self.invocation_binding);
        value["redemption_binding"] = redemption_binding.map_or(Value::Null, |v| json!(v));
        value
    }

    pub(crate) fn proof_context_value(&self) -> Value {
        json!({
            "statement": self.statement_value(),
            "invocation_binding": self.invocation_binding,
        })
    }
}

pub(crate) fn setup(message_names: &[String]) -> PublicParams {
    bbs::setup(message_names)
}

pub(crate) fn issuer_keygen(params: &PublicParams) -> (SecretKey, PublicKey) {
    bbs::keygen(params)
}

pub(crate) fn set_policy(
    epoch: &str,
    valid_from: u64,
    valid_until: u64,
    registry_digest: String,
    issuers: Vec<PublicKey>,
) -> Result<PolicyBundle> {
    let (tag_sk, tag_vk) = alg_tag::keygen();
    set_policy_with_tag_key(
        epoch,
        valid_from,
        valid_until,
        registry_digest,
        issuers,
        tag_sk,
        tag_vk,
        "runtime-generated",
    )
}

fn set_policy_with_tag_key(
    epoch: &str,
    valid_from: u64,
    valid_until: u64,
    registry_digest: String,
    mut issuers: Vec<PublicKey>,
    tag_sk: alg_tag::SecretKey,
    tag_vk: VerificationKey,
    key_material_profile: &str,
) -> Result<PolicyBundle> {
    if issuers.len() < 2 || valid_from > valid_until {
        return Err("IHBBS1 policy requires multiple issuers and a valid interval".to_string());
    }
    if issuers.iter().any(|pk| !pk.is_valid()) {
        return Err("IHBBS1 policy contains an invalid issuer key".to_string());
    }
    let params = issuers[0].params.clone();
    if issuers.iter().any(|pk| !pk.params.same_as(&params)) {
        return Err("IHBBS1 policy mixes incompatible BBS parameters".to_string());
    }
    issuers.sort_by_key(|pk| g2_hex(&pk.x_tilde));
    let encodings = issuers
        .iter()
        .map(|pk| g2_hex(&pk.x_tilde))
        .collect::<Vec<_>>();
    if encodings.iter().collect::<BTreeSet<_>>().len() != encodings.len() {
        return Err("IHBBS1 policy contains duplicate issuer keys".to_string());
    }
    let issuer_tags = issuers
        .iter()
        .map(|pk| alg_tag::tag(&tag_sk, pk.x_tilde))
        .collect::<Vec<_>>();
    let mut policy = PolicyBundle {
        suite_id: params.suite_id.to_string(),
        schema_version: params.schema_version.to_string(),
        public_parameter_digest: policy_parameter_digest(),
        key_material_profile: key_material_profile.to_string(),
        epoch: epoch.to_string(),
        valid_from,
        valid_until,
        registry_digest,
        issuers,
        tag_vk,
        issuer_tags,
        policy_digest: String::new(),
    };
    policy.policy_digest = commitment_digest("mm-ihbbs1-policy-v1", &policy.unsigned_value());
    verify_policy(&policy, &params)?;
    Ok(policy)
}

pub(crate) fn fixture_policy(
    params: &PublicParams,
    epoch: &str,
    valid_from: u64,
    valid_until: u64,
    registry_digest: String,
) -> Result<(Vec<(SecretKey, PublicKey)>, PolicyBundle)> {
    let issuers = (0..DETERMINISTIC_TEST_FIXTURE_ISSUERS)
        .map(|index| {
            let x = hash_to_scalar(
                "mm-ihbbs1-fixture-issuer-v1",
                &[index.to_be_bytes().to_vec()],
            );
            bbs::keygen_with_secret(params, x)
        })
        .collect::<Vec<_>>();
    let x_v = hash_to_scalar(
        "mm-ihbbs1-fixture-tag-secret-v1",
        &[epoch.as_bytes().to_vec()],
    );
    let g_v = crate::hash_g1("mm-ihbbs1-fixture-tag-generator-v1");
    let (tag_sk, tag_vk) = alg_tag::keygen_with_material(x_v, g_v);
    let policy = set_policy_with_tag_key(
        epoch,
        valid_from,
        valid_until,
        registry_digest,
        issuers.iter().map(|(_, pk)| pk.clone()).collect(),
        tag_sk,
        tag_vk,
        DETERMINISTIC_TEST_KEY_PROFILE,
    )?;
    Ok((issuers, policy))
}

pub(crate) fn verify_policy(policy: &PolicyBundle, verifier_params: &PublicParams) -> Result<()> {
    if policy.issuers.len() < 2
        || policy.issuers.len() != policy.issuer_tags.len()
        || policy.valid_from > policy.valid_until
        || policy
            .issuers
            .iter()
            .any(|pk| !pk.is_valid() || !pk.params.same_as(verifier_params))
        || policy.suite_id != verifier_params.suite_id
        || policy.schema_version != verifier_params.schema_version
        || policy.public_parameter_digest != policy_parameter_digest()
    {
        return Err("invalid IHBBS1 policy structure".to_string());
    }
    let encodings = policy
        .issuers
        .iter()
        .map(|pk| g2_hex(&pk.x_tilde))
        .collect::<Vec<_>>();
    if encodings.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("IHBBS1 policy is not canonical".to_string());
    }
    if policy.policy_digest != commitment_digest("mm-ihbbs1-policy-v1", &policy.unsigned_value()) {
        return Err("IHBBS1 policy digest mismatch".to_string());
    }
    for (issuer, tag) in policy.issuers.iter().zip(&policy.issuer_tags) {
        if !alg_tag::verify(&policy.tag_vk, tag, issuer.x_tilde) {
            return Err("IHBBS1 policy tag verification failed".to_string());
        }
    }
    Ok(())
}

pub(crate) fn holder_state(
    policy: &PolicyBundle,
    issuer_pk: &PublicKey,
) -> Result<HolderIssuerState> {
    verify_policy(policy, &issuer_pk.params)?;
    holder_state_for_verified_policy(policy, issuer_pk)
}

/// Construct holder policy state after the immutable policy has already been
/// verified by the cached verifier material.  The issuer membership and all
/// holder-policy bindings are still checked here; only the repeated global
/// policy validation is omitted.
pub(crate) fn holder_state_for_verified_policy(
    policy: &PolicyBundle,
    issuer_pk: &PublicKey,
) -> Result<HolderIssuerState> {
    let issuer_tag = policy
        .member_tag(issuer_pk)
        .ok_or_else(|| "credential issuer is not a member of the IHBBS1 policy".to_string())?;
    Ok(HolderIssuerState {
        issuer_pk: issuer_pk.clone(),
        issuer_tag,
        epoch: policy.epoch.clone(),
        expiry: policy.valid_until,
        registry_digest: policy.registry_digest.clone(),
        policy_digest: policy.policy_digest.clone(),
    })
}

pub(crate) fn adapt(
    issuer_pk: &PublicKey,
    signature: &Signature,
    alpha: Scalar,
) -> Result<(PublicKey, Signature)> {
    if alpha == Scalar::ZERO
        || issuer_pk.x_tilde == G2::identity()
        || signature.a == crate::G1::identity()
    {
        return Err("IHBBS1 adaptation requires nonzero inputs".to_string());
    }
    let alpha_inv = Option::<Scalar>::from(alpha.invert())
        .ok_or_else(|| "IHBBS1 adaptation scalar is zero".to_string())?;
    Ok((
        issuer_pk.scale(alpha),
        Signature {
            a: signature.a * alpha_inv,
            e: signature.e * alpha,
        },
    ))
}

pub(crate) fn begin_presentation(
    verifier_params: &PublicParams,
    policy: &PolicyBundle,
    holder: &HolderIssuerState,
    credential: &Credential,
    invocation_id: &str,
) -> Result<PresentationSession> {
    verify_policy(policy, verifier_params)?;
    if !holder.issuer_pk.params.same_as(verifier_params) {
        return Err("holder uses non-verifier IHBBS1 public parameters".to_string());
    }
    if holder.policy_digest != policy.policy_digest
        || holder.epoch != policy.epoch
        || holder.expiry != policy.valid_until
        || holder.registry_digest != policy.registry_digest
    {
        return Err("holder credential does not match the public IHBBS1 policy".to_string());
    }
    let expected_tag = policy
        .member_tag(&holder.issuer_pk)
        .ok_or_else(|| "credential issuer is outside the IHBBS1 policy".to_string())?;
    if expected_tag.0 != holder.issuer_tag.0
        || !bbs::verify(
            &holder.issuer_pk,
            &credential.signature,
            &credential.messages,
        )
    {
        return Err("holder has no valid policy-member BBS credential".to_string());
    }
    let alpha = random_scalar();
    let (randomized_issuer_pk, adapted_signature) =
        adapt(&holder.issuer_pk, &credential.signature, alpha)?;
    let randomized_policy_tag = Tag(holder.issuer_tag.0 * alpha);
    let mut authorization = Authorization {
        epoch: policy.epoch.clone(),
        expiry: policy.valid_until,
        registry_digest: policy.registry_digest.clone(),
        policy_digest: policy.policy_digest.clone(),
        public_parameter_digest: policy.public_parameter_digest.clone(),
        issuer_count: policy.issuers.len(),
        randomized_issuer_pk: RandomizedIssuerKey {
            x_tilde: randomized_issuer_pk.x_tilde,
        },
        randomized_policy_tag,
        invocation_binding: String::new(),
    };
    authorization.invocation_binding = authorization.digest_for(invocation_id);
    Ok(PresentationSession {
        authorization,
        randomized_issuer_pk,
        adapted_signature,
    })
}

/// Validate the immutable holder material once when a workflow is initialized.
pub(crate) fn verify_holder_credential(
    verifier_params: &PublicParams,
    policy: &PolicyBundle,
    holder: &HolderIssuerState,
    credential: &Credential,
) -> Result<()> {
    verify_policy(policy, verifier_params)?;
    verify_holder_credential_for_verified_policy(verifier_params, policy, holder, credential)
}

/// Verify workflow credential material after the immutable policy has already
/// been checked by the cached verifier.  Credential, parameter, issuer-tag,
/// and policy-binding checks remain unchanged.
pub(crate) fn verify_holder_credential_for_verified_policy(
    verifier_params: &PublicParams,
    policy: &PolicyBundle,
    holder: &HolderIssuerState,
    credential: &Credential,
) -> Result<()> {
    if !holder.issuer_pk.params.same_as(verifier_params) {
        return Err("holder uses non-verifier IHBBS1 public parameters".to_string());
    }
    if holder.policy_digest != policy.policy_digest
        || holder.epoch != policy.epoch
        || holder.expiry != policy.valid_until
        || holder.registry_digest != policy.registry_digest
    {
        return Err("holder credential does not match the public IHBBS1 policy".to_string());
    }
    let expected_tag = policy
        .member_tag(&holder.issuer_pk)
        .ok_or_else(|| "credential issuer is outside the IHBBS1 policy".to_string())?;
    if expected_tag.0 != holder.issuer_tag.0
        || !bbs::verify(
            &holder.issuer_pk,
            &credential.signature,
            &credential.messages,
        )
    {
        return Err("holder has no valid policy-member BBS credential".to_string());
    }
    Ok(())
}

/// Internal holder path after workflow initialization has verified immutable
/// policy and credential material. Verifiers still check every presentation.
pub(crate) fn begin_presentation_for_verified_holder(
    verifier_params: &PublicParams,
    policy: &PolicyBundle,
    holder: &HolderIssuerState,
    credential: &Credential,
    invocation_id: &str,
) -> Result<PresentationSession> {
    if !holder.issuer_pk.params.same_as(verifier_params) {
        return Err("holder uses non-verifier IHBBS1 public parameters".to_string());
    }
    if holder.policy_digest != policy.policy_digest
        || holder.epoch != policy.epoch
        || holder.expiry != policy.valid_until
        || holder.registry_digest != policy.registry_digest
    {
        return Err("holder credential does not match the public IHBBS1 policy".to_string());
    }
    let expected_tag = policy
        .member_tag(&holder.issuer_pk)
        .ok_or_else(|| "credential issuer is not a member of the IHBBS1 policy".to_string())?;
    if expected_tag.0 != holder.issuer_tag.0 {
        return Err("holder credential issuer tag does not match the policy".to_string());
    }
    let alpha = random_scalar();
    let (randomized_issuer_pk, adapted_signature) =
        adapt(&holder.issuer_pk, &credential.signature, alpha)?;
    let randomized_policy_tag = Tag(holder.issuer_tag.0 * alpha);
    let mut authorization = Authorization {
        epoch: policy.epoch.clone(),
        expiry: policy.valid_until,
        registry_digest: policy.registry_digest.clone(),
        policy_digest: policy.policy_digest.clone(),
        public_parameter_digest: policy.public_parameter_digest.clone(),
        issuer_count: policy.issuers.len(),
        randomized_issuer_pk: RandomizedIssuerKey {
            x_tilde: randomized_issuer_pk.x_tilde,
        },
        randomized_policy_tag,
        invocation_binding: String::new(),
    };
    authorization.invocation_binding = authorization.digest_for(invocation_id);
    Ok(PresentationSession {
        authorization,
        randomized_issuer_pk,
        adapted_signature,
    })
}

pub(crate) fn present(
    session: &PresentationSession,
    credential: &Credential,
    disclosed_names: &[String],
    relations: &[G1Relation],
    relation_secrets: &std::collections::BTreeMap<String, Scalar>,
    context: &Value,
    label: &str,
) -> Result<Presentation> {
    bbs::proof_gen(
        &session.randomized_issuer_pk,
        credential,
        &session.adapted_signature,
        disclosed_names,
        relations,
        relation_secrets,
        context,
        label,
    )
}

/// Internal presentation path for a holder validated during workflow setup.
/// Verifiers still validate every emitted presentation independently.
pub(crate) fn present_for_verified_holder(
    session: &PresentationSession,
    credential: &Credential,
    credential_commitment: &G1,
    disclosed_names: &[String],
    relations: &[G1Relation],
    relation_secrets: &std::collections::BTreeMap<String, Scalar>,
    context: &Value,
    label: &str,
) -> Result<Presentation> {
    bbs::proof_gen_for_verified_credential(
        &session.randomized_issuer_pk,
        credential,
        *credential_commitment,
        &session.adapted_signature,
        disclosed_names,
        relations,
        relation_secrets,
        context,
        label,
    )
}

pub(crate) fn verify_authorization(
    verifier_params: &PublicParams,
    policy: &PolicyBundle,
    authorization: &Authorization,
    invocation_id: &str,
    trusted_now: u64,
) -> bool {
    verify_policy(policy, verifier_params).is_ok()
        && verify_authorization_with_verified_policy(
            policy,
            authorization,
            invocation_id,
            trusted_now,
        )
}

/// Runtime authorization path for a policy bundle already validated when the
/// workflow verifier was constructed.  It retains every call-local binding,
/// expiry, randomized-key, and algebraic-tag check; only the repeated scan of
/// immutable epoch policy material is omitted.
pub(crate) fn verify_authorization_with_verified_policy(
    policy: &PolicyBundle,
    authorization: &Authorization,
    invocation_id: &str,
    trusted_now: u64,
) -> bool {
    authorization.epoch == policy.epoch
        && authorization.expiry == policy.valid_until
        && policy.valid_from <= trusted_now
        && trusted_now <= policy.valid_until
        && authorization.registry_digest == policy.registry_digest
        && authorization.policy_digest == policy.policy_digest
        && authorization.public_parameter_digest == policy.public_parameter_digest
        && authorization.issuer_count == policy.issuers.len()
        && authorization.invocation_binding == authorization.digest_for(invocation_id)
        && authorization.randomized_issuer_pk.x_tilde != G2::identity()
        && authorization.randomized_policy_tag.0 != G2::identity()
        && alg_tag::verify(
            &policy.tag_vk,
            &authorization.randomized_policy_tag,
            authorization.randomized_issuer_pk.x_tilde,
        )
}

pub(crate) fn verify(
    verifier_params: &PublicParams,
    policy: &PolicyBundle,
    authorization: &Authorization,
    presentation: &Presentation,
    relations: &[G1Relation],
    context: &Value,
    label: &str,
    invocation_id: &str,
    trusted_now: u64,
) -> bool {
    let randomized_issuer_pk = PublicKey {
        x_tilde: authorization.randomized_issuer_pk.x_tilde,
        params: verifier_params.clone(),
    };
    verify_authorization(
        verifier_params,
        policy,
        authorization,
        invocation_id,
        trusted_now,
    ) && bbs::proof_verify(
        &randomized_issuer_pk,
        presentation,
        relations,
        context,
        label,
    )
}

/// Runtime verifier path for a policy bundle checked at workflow creation.
/// It retains all dynamic authorization, tag, and BBS proof checks.
pub(crate) fn verify_with_verified_policy(
    verifier_params: &PublicParams,
    policy: &PolicyBundle,
    authorization: &Authorization,
    presentation: &Presentation,
    relations: &[G1Relation],
    context: &Value,
    label: &str,
    invocation_id: &str,
    trusted_now: u64,
) -> bool {
    let randomized_issuer_pk = PublicKey {
        x_tilde: authorization.randomized_issuer_pk.x_tilde,
        params: verifier_params.clone(),
    };
    verify_authorization_with_verified_policy(policy, authorization, invocation_id, trusted_now)
        && bbs::proof_verify(
            &randomized_issuer_pk,
            presentation,
            relations,
            context,
            label,
        )
}

/// Return the BBS pairing equation after the caller has verified the shared
/// IHBBS authorization and all view-local linear relations.  This lets a
/// wallet batch the service and redemption equations without repeating the
/// authorization/tag checks.
pub(crate) fn proof_pairing_terms_for_verified_authorization(
    verifier_params: &PublicParams,
    authorization: &Authorization,
    presentation: &Presentation,
    relations: &[G1Relation],
    context: &Value,
    label: &str,
) -> Option<Vec<(G2, G1)>> {
    let randomized_issuer_pk = PublicKey {
        x_tilde: authorization.randomized_issuer_pk.x_tilde,
        params: verifier_params.clone(),
    };
    bbs::proof_pairing_terms(
        &randomized_issuer_pk,
        presentation,
        relations,
        context,
        label,
    )
}
