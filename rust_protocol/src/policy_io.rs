use crate::bbs::{PublicKey, PublicParams, SecretKey};
use crate::ihbbs1::{self, PolicyBundle};
use crate::wire::{base64_decode, base64_encode, encode_g2};
use crate::{canonical_bytes, Result, Value, ISSUER_HIDING_SCHEME};
use serde_json::{json, Map};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const FINAL_V2_EPOCH: &str = "canonical-epoch-2026q3-v1";
pub(crate) const FINAL_V2_POLICY_SIZE: usize = 8;
pub(crate) const FINAL_V2_VALID_FROM: u64 = 0;
pub(crate) const FINAL_V2_VALID_UNTIL: u64 = 4_102_444_800;
pub(crate) const POLICY_SCHEMA_VERSION: &str = "minmandate-issuer-policy-v1";
pub(crate) const POLICY_CANONICALIZATION: &str = "minmandate-ihbbs1-policy-canonical-v1";
pub(crate) const ASSIGNMENT_ALGORITHM: &str = "sha256_modulo_policy_size_v1";
pub(crate) const ASSIGNMENT_DOMAIN: &str = "minmandate/canonical/issuer-assignment/v1";

const SOURCE_FILES: &[(&str, &str)] = &[
    ("Cargo.toml", include_str!("../Cargo.toml")),
    ("Cargo.lock", include_str!("../Cargo.lock")),
    ("src/main.rs", include_str!("main.rs")),
    ("src/lib.rs", include_str!("lib.rs")),
    ("src/alg_tag.rs", include_str!("alg_tag.rs")),
    ("src/bbs.rs", include_str!("bbs.rs")),
    ("src/blind_bbs.rs", include_str!("blind_bbs.rs")),
    ("src/ihbbs1.rs", include_str!("ihbbs1.rs")),
    ("src/policy_io.rs", include_str!("policy_io.rs")),
    ("src/wire.rs", include_str!("wire.rs")),
];

#[derive(Clone)]
pub(crate) struct LoadedIssuerPolicy {
    pub(crate) epoch: String,
    pub(crate) registry_digest: String,
    pub(crate) metadata: Value,
    canonical_public_policy: Vec<u8>,
}

impl LoadedIssuerPolicy {
    pub(crate) fn instantiate(
        &self,
        params: &PublicParams,
        registry_digest: &str,
    ) -> Result<(Vec<(SecretKey, PublicKey)>, PolicyBundle)> {
        if registry_digest != self.registry_digest {
            return Err("frozen issuer policy registry digest mismatch".to_string());
        }
        let (keys, policy) = ihbbs1::fixture_policy(
            params,
            &self.epoch,
            FINAL_V2_VALID_FROM,
            FINAL_V2_VALID_UNTIL,
            registry_digest.to_string(),
        )?;
        if policy.canonical_public_bytes() != self.canonical_public_policy {
            return Err("runtime issuer policy differs from frozen canonical policy".to_string());
        }
        Ok((keys, policy))
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    crate::hex_encode(&Sha256::digest(bytes))
}

fn source_snapshot_sha256() -> String {
    let value = Value::Object(
        SOURCE_FILES
            .iter()
            .map(|(path, contents)| ((*path).to_string(), json!(sha256_hex(contents.as_bytes()))))
            .collect::<Map<_, _>>(),
    );
    sha256_hex(&canonical_bytes(&value))
}

fn current_binary_sha256() -> Result<String> {
    let path =
        std::env::current_exe().map_err(|error| format!("resolve current binary: {error}"))?;
    let bytes = fs::read(&path)
        .map_err(|error| format!("read current binary {}: {error}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

fn assignment_value() -> Value {
    json!({
        "algorithm": ASSIGNMENT_ALGORITHM,
        "domain_separator": ASSIGNMENT_DOMAIN,
        "inputs": ["wallet_local_assignment_seed", "epoch_id"],
        "task_ground_truth_allowed": false,
        "task_text_allowed": false,
        "model_output_allowed": false,
        "selected_issuer_visibility": "wallet_local_audit_only",
        "deterministic_within_wallet_epoch": true,
    })
}

fn routine_view_value() -> Value {
    json!({
        "public_policy_metadata": [
            "epoch_id", "policy_digest_sha256", "policy_size", "policy_config_sha256"
        ],
        "metadata_class": "deployment_cohort_metadata",
        "per_call_evidence": [
            "randomized_verification_key", "randomized_policy_membership_tag"
        ],
        "prohibited_fields": [
            "issuer_identity", "issuer_name", "selected_issuer_index",
            "selected_issuer_public_key", "wallet_id"
        ],
    })
}

fn freeze_gate_value() -> Value {
    json!({
        "require_status": "generated_and_frozen",
        "require_rust_generated_material": true,
        "require_exact_policy_size": FINAL_V2_POLICY_SIZE,
        "reject_placeholder_or_synthetic_bytes": true,
        "reject_selected_issuer_identity_in_public_policy": true,
    })
}

fn fixture_policy() -> Result<(Vec<(SecretKey, PublicKey)>, PolicyBundle)> {
    let params = ihbbs1::setup(&["policy-fixture".to_string()]);
    ihbbs1::fixture_policy(
        &params,
        FINAL_V2_EPOCH,
        FINAL_V2_VALID_FROM,
        FINAL_V2_VALID_UNTIL,
        crate::canonical_registry_digest(),
    )
}

fn generator_command(output: &Path) -> String {
    format!(
        "artifact-rs/target/release/minmandate-rs generate-issuer-policy --scheme {} --issuer-count {} --epoch {} --output {}",
        ISSUER_HIDING_SCHEME,
        FINAL_V2_POLICY_SIZE,
        FINAL_V2_EPOCH,
        output.display()
    )
}

fn generated_document(output: &Path) -> Result<Value> {
    let (_keys, policy) = fixture_policy()?;
    let admitted_issuers = policy
        .issuers
        .iter()
        .enumerate()
        .map(|(member_slot, issuer)| {
            let encoded = encode_g2(&issuer.x_tilde);
            json!({
                "member_slot": member_slot,
                "public_key_b64": base64_encode(&encoded),
                "public_key_sha256": sha256_hex(&encoded),
            })
        })
        .collect::<Vec<_>>();
    let generated_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock before Unix epoch: {error}"))?
        .as_secs();
    Ok(json!({
        "schema_version": POLICY_SCHEMA_VERSION,
        "status": "generated_and_frozen",
        "scheme": ISSUER_HIDING_SCHEME,
        "protocol_version": crate::PROTOCOL_VERSION,
        "wire_version": crate::WIRE_SCHEMA_VERSION,
        "curve": "BLS12-381",
        "epoch": {
            "id": FINAL_V2_EPOCH,
            "sequence": 1,
            "policy_size": FINAL_V2_POLICY_SIZE,
            "metadata_class": "deployment_cohort_metadata",
            "immutable_for_formal_run": true,
        },
        "assignment": assignment_value(),
        "routine_view": routine_view_value(),
        "material": {
            "generator": "artifact-rs",
            "generator_command": generator_command(output),
            "canonicalization": POLICY_CANONICALIZATION,
            "canonical_public_policy_b64": base64_encode(&policy.canonical_public_bytes()),
            "policy_digest_sha256": policy.policy_digest,
            "generator_binary_sha256": current_binary_sha256()?,
            "generator_source_snapshot_sha256": source_snapshot_sha256(),
            "generated_utc": format!("unix:{generated_unix}"),
            "admitted_issuers": admitted_issuers,
        },
        "freeze_gate": freeze_gate_value(),
    }))
}

fn object<'a>(value: &'a Value, name: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| format!("issuer policy {name} must be an object"))
}

fn string<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .as_str()
        .ok_or_else(|| format!("issuer policy {name} must be a string"))
}

fn exact_keys(map: &Map<String, Value>, expected: &[&str], name: &str) -> Result<()> {
    let actual = map.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!("issuer policy {name} has noncanonical fields"));
    }
    Ok(())
}

fn validate_document_shape(document: &Value) -> Result<()> {
    let top = object(document, "document")?;
    exact_keys(
        top,
        &[
            "schema_version",
            "status",
            "scheme",
            "protocol_version",
            "wire_version",
            "curve",
            "epoch",
            "assignment",
            "routine_view",
            "material",
            "freeze_gate",
        ],
        "document",
    )?;
    let fixed = [
        ("schema_version", POLICY_SCHEMA_VERSION),
        ("status", "generated_and_frozen"),
        ("scheme", ISSUER_HIDING_SCHEME),
        ("protocol_version", crate::PROTOCOL_VERSION),
        ("wire_version", crate::WIRE_SCHEMA_VERSION),
        ("curve", "BLS12-381"),
    ];
    for (field, expected) in fixed {
        if top.get(field).and_then(Value::as_str) != Some(expected) {
            return Err(format!("issuer policy {field} mismatch"));
        }
    }
    let epoch = object(&top["epoch"], "epoch")?;
    exact_keys(
        epoch,
        &[
            "id",
            "sequence",
            "policy_size",
            "metadata_class",
            "immutable_for_formal_run",
        ],
        "epoch",
    )?;
    if epoch.get("id").and_then(Value::as_str) != Some(FINAL_V2_EPOCH)
        || epoch.get("sequence").and_then(Value::as_u64) != Some(1)
        || epoch.get("policy_size").and_then(Value::as_u64) != Some(FINAL_V2_POLICY_SIZE as u64)
        || epoch.get("metadata_class").and_then(Value::as_str) != Some("deployment_cohort_metadata")
        || epoch
            .get("immutable_for_formal_run")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("issuer policy epoch is invalid".to_string());
    }
    if top["assignment"] != assignment_value()
        || top["routine_view"] != routine_view_value()
        || top["freeze_gate"] != freeze_gate_value()
    {
        return Err("issuer policy fixed contract mismatch".to_string());
    }
    Ok(())
}

pub(crate) fn load(path: &Path) -> Result<LoadedIssuerPolicy> {
    let raw = fs::read(path)
        .map_err(|error| format!("read issuer policy {}: {error}", path.display()))?;
    let document: Value = serde_json::from_slice(&raw)
        .map_err(|error| format!("issuer policy must be canonical JSON: {error}"))?;
    validate_document_shape(&document)?;
    let material = object(&document["material"], "material")?;
    exact_keys(
        material,
        &[
            "generator",
            "generator_command",
            "canonicalization",
            "canonical_public_policy_b64",
            "policy_digest_sha256",
            "generator_binary_sha256",
            "generator_source_snapshot_sha256",
            "generated_utc",
            "admitted_issuers",
        ],
        "material",
    )?;
    if material.get("generator").and_then(Value::as_str) != Some("artifact-rs")
        || material.get("canonicalization").and_then(Value::as_str) != Some(POLICY_CANONICALIZATION)
        || string(&material["generated_utc"], "generated_utc")?.is_empty()
    {
        return Err("issuer policy generator metadata mismatch".to_string());
    }
    if material
        .get("generator_source_snapshot_sha256")
        .and_then(Value::as_str)
        != Some(source_snapshot_sha256().as_str())
        || material
            .get("generator_binary_sha256")
            .and_then(Value::as_str)
            != Some(current_binary_sha256()?.as_str())
    {
        return Err("issuer policy was not generated by this frozen source and binary".to_string());
    }

    let canonical_b64 = string(
        &material["canonical_public_policy_b64"],
        "canonical_public_policy_b64",
    )?;
    let canonical_public_policy = base64_decode(canonical_b64)?;
    let decoded_value: Value = serde_json::from_slice(&canonical_public_policy)
        .map_err(|error| format!("decode canonical public policy: {error}"))?;
    if canonical_bytes(&decoded_value) != canonical_public_policy {
        return Err("public issuer policy encoding is noncanonical".to_string());
    }

    let (_keys, expected_policy) = fixture_policy()?;
    if canonical_public_policy != expected_policy.canonical_public_bytes()
        || material.get("policy_digest_sha256").and_then(Value::as_str)
            != Some(expected_policy.policy_digest.as_str())
    {
        return Err("deterministic issuer policy material or digest mismatch".to_string());
    }
    let admitted = material["admitted_issuers"]
        .as_array()
        .ok_or_else(|| "admitted_issuers must be an array".to_string())?;
    if admitted.len() != FINAL_V2_POLICY_SIZE {
        return Err("issuer policy must contain exactly eight issuers".to_string());
    }
    for (index, (row, issuer)) in admitted.iter().zip(&expected_policy.issuers).enumerate() {
        let row = object(row, "admitted issuer")?;
        exact_keys(
            row,
            &["member_slot", "public_key_b64", "public_key_sha256"],
            "admitted issuer",
        )?;
        let encoded = encode_g2(&issuer.x_tilde);
        if row.get("member_slot").and_then(Value::as_u64) != Some(index as u64)
            || row.get("public_key_b64").and_then(Value::as_str)
                != Some(base64_encode(&encoded).as_str())
            || row.get("public_key_sha256").and_then(Value::as_str)
                != Some(sha256_hex(&encoded).as_str())
        {
            return Err("issuer policy member material is noncanonical".to_string());
        }
        let bytes = base64_decode(string(&row["public_key_b64"], "public_key_b64")?)?;
        crate::wire::decode_g2(&bytes)?;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock before Unix epoch: {error}"))?
        .as_secs();
    if expected_policy.valid_until < now {
        return Err("issuer policy is expired".to_string());
    }
    let metadata = json!({
        "epoch_id": FINAL_V2_EPOCH,
        "policy_digest_sha256": expected_policy.policy_digest,
        "policy_size": FINAL_V2_POLICY_SIZE,
        "policy_config_sha256": sha256_hex(&raw),
        "metadata_class": "deployment_cohort_metadata",
    });
    Ok(LoadedIssuerPolicy {
        epoch: FINAL_V2_EPOCH.to_string(),
        registry_digest: expected_policy.registry_digest,
        metadata,
        canonical_public_policy,
    })
}

fn write_atomic_json(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("create issuer policy directory: {error}"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "issuer policy output has no UTF-8 file name".to_string())?;
    let temp = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize issuer policy: {error}"))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|error| format!("create temporary issuer policy {}: {error}", temp.display()))?;
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|error| format!("write temporary issuer policy: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync temporary issuer policy: {error}"))?;
        fs::rename(&temp, path)
            .map_err(|error| format!("atomically install issuer policy: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub(crate) fn run_generate_cli<I>(arguments: I) -> Result<PathBuf>
where
    I: IntoIterator<Item = String>,
{
    let mut scheme = ISSUER_HIDING_SCHEME.to_string();
    let mut issuer_count = FINAL_V2_POLICY_SIZE;
    let mut epoch = FINAL_V2_EPOCH.to_string();
    let mut output = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/canonical-test-output/issuer_policy_v1.json");
    let mut iter = arguments.into_iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--scheme" => scheme = iter.next().ok_or("--scheme needs a value")?,
            "--issuer-count" => {
                issuer_count = iter
                    .next()
                    .ok_or("--issuer-count needs a value")?
                    .parse()
                    .map_err(|_| "bad --issuer-count")?;
            }
            "--epoch" => epoch = iter.next().ok_or("--epoch needs a value")?,
            "--output" => output = PathBuf::from(iter.next().ok_or("--output needs a value")?),
            other => return Err(format!("unknown generate-issuer-policy argument: {other}")),
        }
    }
    if scheme != ISSUER_HIDING_SCHEME
        || issuer_count != FINAL_V2_POLICY_SIZE
        || epoch != FINAL_V2_EPOCH
    {
        return Err(
            "canonical generator requires the frozen scheme, epoch, and eight issuers".to_string(),
        );
    }
    let document = generated_document(&output)?;
    write_atomic_json(&output, &document)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_policy_round_trips_and_tampering_fails_closed() {
        let output = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/canonical-test-output/unit-issuer-policy.json");
        let _ = fs::remove_file(&output);
        let document = generated_document(&output).unwrap();
        write_atomic_json(&output, &document).unwrap();
        let loaded = load(&output).unwrap();
        assert_eq!(loaded.epoch, FINAL_V2_EPOCH);

        let mut wrong_suite = document.clone();
        wrong_suite["scheme"] = json!("mismatched-suite");
        write_atomic_json(&output, &wrong_suite).unwrap();
        assert!(load(&output).is_err());

        let mut singleton = document.clone();
        singleton["epoch"]["policy_size"] = json!(1);
        write_atomic_json(&output, &singleton).unwrap();
        assert!(load(&output).is_err());

        let canonical = base64_decode(
            document["material"]["canonical_public_policy_b64"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let mut expired_value: Value = serde_json::from_slice(&canonical).unwrap();
        expired_value["valid_until"] = json!(1);
        let mut expired = document.clone();
        expired["material"]["canonical_public_policy_b64"] =
            json!(base64_encode(&canonical_bytes(&expired_value)));
        write_atomic_json(&output, &expired).unwrap();
        assert!(load(&output).is_err());

        let mut noncanonical_bytes = canonical;
        noncanonical_bytes.push(b'\n');
        let mut noncanonical = document;
        noncanonical["material"]["canonical_public_policy_b64"] =
            json!(base64_encode(&noncanonical_bytes));
        write_atomic_json(&output, &noncanonical).unwrap();
        assert!(load(&output).is_err());

        let _ = fs::remove_file(&output);
    }

    #[test]
    fn generator_rejects_nonfinal_policy_dimensions() {
        for arguments in [
            vec!["--issuer-count".to_string(), "1".to_string()],
            vec!["--epoch".to_string(), "expired-epoch".to_string()],
            vec!["--scheme".to_string(), "other-suite".to_string()],
        ] {
            assert!(run_generate_cli(arguments).is_err());
        }
    }
}
