#![recursion_limit = "256"]

mod alg_tag;
mod bbs;
// Optional appendix-only extension. The measured main protocol calls
// `bbs::issue` directly and never dispatches through this module.
mod blind_bbs;
mod ihbbs1;
mod policy_io;
mod wire;

use bbs::{
    Credential as BbsCredential, G1Relation, Presentation as BbsPresentation,
    PublicKey as BbsPublicKey, PublicParams as BbsPublicParams, SecretKey as BbsSecretKey,
};
use ff::{Field, FromUniformBytes, PrimeField};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use fs2::FileExt;
use group::{Curve, Group};
use halo2curves::bls12381::{multi_miller_loop, Fr, G1Affine, G2Affine, Gt, G1, G2};
use halo2curves::msm::msm_serial;
use halo2curves::CurveExt;
use pairing::MillerLoopResult;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::Instant;

pub(crate) type Scalar = Fr;
type Result<T> = std::result::Result<T, String>;

pub(crate) const PROTOCOL_VERSION: &str = "minmandate-v3";
pub(crate) const WIRE_SCHEMA_VERSION: &str = "minmandate-rs-jsonl-v3";
pub(crate) const ORDINARY_ISSUANCE_MODE: &str = "ordinary_bbs_issuer_visible";
const IMPLEMENTATION_PROFILE: &str = "canonical-ihbbs1";
pub(crate) const ISSUER_HIDING_SCHEME: &str = "ihbbs1-bbs-bls12381-v1";
const CRYPTO_SCHEME: &str = "ihbbs1-bbs-bls12381-v1";
const EXECUTION_MODE: &str = "local-offline-no-charge";
const DOMAIN_MERCHANT_VIEW: &str = "MM-view-M-v1";
const DOMAIN_REDEMPTION_PREACK_VIEW: &str = "MM-view-R-preack-v1";
const DOMAIN_BIND: &str = "MM-bind-v1";
const DOMAIN_ACCEPT: &str = "MM-accept-v1";
const DOMAIN_LOCAL_SETTLEMENT_AUTHORIZATION: &str = "MM-local-settlement-authz-v1";
const DOMAIN_LOCAL_RECEIPT: &str = "MM-local-receipt-v1";
const DOMAIN_LOCAL_RECEIPT_ID: &str = "MM-local-receipt-id-v1";
const DOMAIN_SETTLEMENT_KEY_ATTESTATION: &str = "MM-settlement-key-attestation-v1";
const DOMAIN_JSONL_REQUEST: &str = "MM-jsonl-request-v1";
const COMPACT_TRANSPORT_ENCODING: &str = "gzip-base64-v1";
const MAX_COMPACT_TRANSPORT_BYTES: usize = 16 * 1024 * 1024;
const BUDGET_NAME: &str = "budget";
const EXPIRY_NAME: &str = "expiry";
const FUND_NAME: &str = "fund";
const CREDENTIAL_ID_NAME: &str = "credential_id";
const FINAL_V2_FUNDING_BUCKET: &str = policy_io::FINAL_V2_EPOCH;
const DEFAULT_CLASSES: &[&str] = &["business", "patent", "litigation", "security"];
const AUTH_WALLET_ID: &str = "wallet_id";
const AUTH_ISSUER_PK: &str = "issuer_verification_key";
const AUTH_EPOCH: &str = "epoch";
const AUTH_MEMBER: &str = "member";
const AUTH_NOT_REVOKED: &str = "not_revoked";
const AUTH_EXPIRY: &str = "expiry";
const DEFAULT_ISSUER_REGISTRY_SIZES: &[usize] = &[128, 1024, 8192, 65536];
const DEFAULT_REDACTION_HIDDEN_FIELDS: &[usize] = &[4, 8, 16, 32, 64];
const DEFAULT_RACE_JOBS: usize = 1;
const MAX_RACE_JOBS: usize = 32;
const MAX_RACE_CONTENDER_THREADS: usize = 64;
const RECOMMENDED_RACE_JOBS_80_LOGICAL_CPUS: usize = 16;
const MM_H2C_DST: &str = "MINMANDATE-H2C-V1_";
const MAX_HASH_G1_CACHE_ENTRIES: usize = 256;

static HASH_G1_CACHE: OnceLock<RwLock<HashMap<String, G1>>> = OnceLock::new();

fn wallet_entity_model_value() -> Value {
    json!({
        "top_level_type": "WalletRuntime",
        "top_level_entity_count": 1,
        "interfaces_are_logical": true,
        "record_scope": "wallet-local-private-audit",
    })
}

fn no_live_cost_boundary_value() -> Value {
    json!({
        "paid_saas_calls": false,
        "online_paid_llm_calls": false,
        "cloud_jobs": false,
        "real_payment_rails": false,
        "transaction_broadcast": false,
        "execution": "local_offline_only",
    })
}

fn wallet_interfaces_value() -> Value {
    json!({
        "issuance": {"name": "W_iss", "lifecycle": "once-per-task"},
        "redemption": {"name": "W_red", "lifecycle": "once-per-paid-invocation"},
    })
}

fn joined_wallet_leakage_boundary_value() -> Value {
    json!({
        "joinable_interfaces": ["W_iss", "W_red"],
        "joined_state_and_retained_logs": true,
        "non_collusion_assumed": false,
    })
}

fn add_wire_contract_fields(value: &mut Value, policy: &policy_io::LoadedIssuerPolicy) {
    let Value::Object(map) = value else {
        return;
    };
    map.insert("protocol_version".to_string(), json!(PROTOCOL_VERSION));
    map.insert(
        "wire_schema_version".to_string(),
        json!(WIRE_SCHEMA_VERSION),
    );
    map.insert(
        "issuer_hiding_scheme".to_string(),
        json!(ISSUER_HIDING_SCHEME),
    );
    map.insert(
        "implementation_profile".to_string(),
        json!(IMPLEMENTATION_PROFILE),
    );
    map.insert(
        "key_material_profile".to_string(),
        json!(ihbbs1::DETERMINISTIC_TEST_KEY_PROFILE),
    );
    map.insert("issuer_policy".to_string(), policy.metadata.clone());
    map.insert(
        "no_live_cost_boundary".to_string(),
        no_live_cost_boundary_value(),
    );
    map.insert("execution_mode".to_string(), json!(EXECUTION_MODE));
    map.insert("allow_network".to_string(), json!(false));
    map.insert("allow_live_services".to_string(), json!(false));
    map.insert("allow_sandbox_services".to_string(), json!(false));
    map.insert("allow_real_payment".to_string(), json!(false));
    map.insert("allow_production_writes".to_string(), json!(false));
    map.insert("quote_mode".to_string(), json!("virtual-deterministic"));
    map.insert(
        "settlement_mode".to_string(),
        json!("local-ledger-no-funds"),
    );
    map.insert("live_external_calls".to_string(), json!(false));
    map.insert("real_charges".to_string(), json!(false));
    map.insert("transaction_broadcast".to_string(), json!(false));
    map.insert(
        "offline_guard_scope".to_string(),
        json!("experiment-child-process-only; no host firewall, DNS, or Codex changes"),
    );
    map.insert(
        "wallet_entity_model".to_string(),
        wallet_entity_model_value(),
    );
    map.insert("wallet_interfaces".to_string(), wallet_interfaces_value());
    map.insert(
        "joined_wallet_leakage_boundary".to_string(),
        joined_wallet_leakage_boundary_value(),
    );
    map.entry("crypto_executed".to_string())
        .or_insert(json!(false));
    map.entry("crypto_scheme".to_string())
        .or_insert(Value::Null);
    map.entry("view_count".to_string()).or_insert(json!(0));
    map.entry("issuer_hiding_crypto_executed".to_string())
        .or_insert(json!(false));
    map.entry("stable_issuer_handle_disclosed".to_string())
        .or_insert(json!(false));
}

fn add_transmitted_view_fields(value: &mut Value, policy: &policy_io::LoadedIssuerPolicy) {
    if let Value::Object(map) = value {
        let nested_issuer_hiding_evidence = map
            .get("slot")
            .and_then(Value::as_object)
            .and_then(|slot| slot.get("issuer_hiding_evidence"))
            .cloned();
        if let Some(evidence) = nested_issuer_hiding_evidence {
            map.insert("issuer_hiding_evidence".to_string(), evidence);
        }
        map.insert("protocol_version".to_string(), json!(PROTOCOL_VERSION));
        map.insert(
            "wire_schema_version".to_string(),
            json!(WIRE_SCHEMA_VERSION),
        );
        map.insert(
            "issuer_hiding_scheme".to_string(),
            json!(ISSUER_HIDING_SCHEME),
        );
        map.insert(
            "implementation_profile".to_string(),
            json!(IMPLEMENTATION_PROFILE),
        );
        map.insert("issuer_policy".to_string(), policy.metadata.clone());
        map.insert("execution_mode".to_string(), json!(EXECUTION_MODE));
        map.insert("allow_network".to_string(), json!(false));
        map.insert("allow_live_services".to_string(), json!(false));
        map.insert("allow_sandbox_services".to_string(), json!(false));
        map.insert("allow_real_payment".to_string(), json!(false));
        map.insert("allow_production_writes".to_string(), json!(false));
        map.insert("quote_mode".to_string(), json!("virtual-deterministic"));
        map.insert(
            "settlement_mode".to_string(),
            json!("local-ledger-no-funds"),
        );
        map.insert("live_external_calls".to_string(), json!(false));
        map.insert("real_charges".to_string(), json!(false));
        map.insert("transaction_broadcast".to_string(), json!(false));
    }
}

const OFFLINE_PERMISSION_FLAGS: &[&str] = &[
    "ALLOW_NETWORK",
    "ALLOW_LIVE_SERVICES",
    "ALLOW_SANDBOX_SERVICES",
    "ALLOW_REAL_PAYMENT",
    "ALLOW_PRODUCTION_WRITES",
];

const THIRD_PARTY_PREFIXES: &[&str] = &[
    "CLAY", "ATTIO", "HUBSPOT", "INTERCOM", "STRIPE", "ALPACA", "BINANCE",
];

const PROXY_ENV_NAMES: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "FTP_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "ftp_proxy",
];

fn env_flag_is_false(name: &str, value: &str) -> Result<()> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => Ok(()),
        _ => Err(format!(
            "{name} must remain false for formal offline experiments"
        )),
    }
}

fn is_third_party_credential_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    THIRD_PARTY_PREFIXES
        .iter()
        .any(|prefix| upper.starts_with(prefix))
        && [
            "API_KEY",
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "OAUTH",
            "CLIENT_ID",
            "CREDENTIAL",
            "ACCOUNT_KEY",
        ]
        .iter()
        .any(|marker| upper.contains(marker))
}

fn is_relevant_endpoint_env(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let relevant_namespace = THIRD_PARTY_PREFIXES
        .iter()
        .any(|prefix| upper.starts_with(prefix))
        || [
            "MINMANDATE",
            "MERCHANT",
            "PAYMENT",
            "SETTLEMENT",
            "TOOL",
            "OLLAMA",
        ]
        .iter()
        .any(|prefix| upper.starts_with(prefix));
    relevant_namespace
        && ["URL", "URI", "ENDPOINT", "HOST"]
            .iter()
            .any(|marker| upper.contains(marker))
}

fn is_loopback_endpoint(endpoint: &str) -> bool {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return true;
    }
    if endpoint == "::1" {
        return true;
    }
    let authority = if let Some((scheme, rest)) = endpoint.split_once("://") {
        if !matches!(scheme, "http" | "https" | "ws" | "wss" | "tcp") {
            return false;
        }
        rest.split('/').next().unwrap_or_default()
    } else {
        endpoint.split('/').next().unwrap_or_default()
    };
    if authority.contains('@') {
        return false;
    }
    let host = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, _)) = rest.split_once(']') else {
            return false;
        };
        host
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
}

fn initialize_offline_child_process() -> Result<()> {
    for flag in OFFLINE_PERMISSION_FLAGS {
        if let Ok(value) = std::env::var(flag) {
            env_flag_is_false(flag, &value)?;
        }
    }

    let mut credential_names = Vec::new();
    for (name, value) in std::env::vars() {
        if PROXY_ENV_NAMES.contains(&name.as_str()) {
            std::env::remove_var(&name);
            continue;
        }
        if is_third_party_credential_name(&name) {
            std::env::remove_var(&name);
            credential_names.push(name);
            continue;
        }
        if is_relevant_endpoint_env(&name)
            && !value.trim().is_empty()
            && !is_loopback_endpoint(&value)
        {
            return Err(format!(
                "non-local experiment endpoint in {name}; only localhost/127.0.0.1/::1 are allowed"
            ));
        }
    }
    if !credential_names.is_empty() {
        credential_names.sort();
        return Err(format!(
            "third-party credentials were stripped and rejected: {}",
            credential_names.join(",")
        ));
    }
    Ok(())
}

extern "C" {
    #[link_name = "socket"]
    fn libc_socket(domain: i32, socket_type: i32, protocol: i32) -> i32;
    #[link_name = "close"]
    fn libc_close(file_descriptor: i32) -> i32;
    #[link_name = "connect"]
    fn libc_connect(
        file_descriptor: i32,
        address: *const std::ffi::c_void,
        address_length: u32,
    ) -> i32;
}

#[repr(C)]
struct LibcSockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

fn udp_connect_probe(address: [u8; 4]) -> Result<(i32, Option<i32>)> {
    const AF_INET: i32 = 2;
    const SOCK_DGRAM: i32 = 2;

    let descriptor = unsafe { libc_socket(AF_INET, SOCK_DGRAM, 0) };
    if descriptor < 0 {
        return Err(format!(
            "create AF_INET UDP probe socket: {}",
            std::io::Error::last_os_error()
        ));
    }
    let socket_address = LibcSockAddrIn {
        sin_family: AF_INET as u16,
        sin_port: 9_u16.to_be(),
        sin_addr: u32::from_ne_bytes(address),
        sin_zero: [0; 8],
    };
    let result = unsafe {
        libc_connect(
            descriptor,
            (&socket_address as *const LibcSockAddrIn).cast::<std::ffi::c_void>(),
            std::mem::size_of::<LibcSockAddrIn>() as u32,
        )
    };
    let errno = if result == 0 {
        None
    } else {
        std::io::Error::last_os_error().raw_os_error()
    };
    unsafe {
        libc_close(descriptor);
    }
    Ok((result, errno))
}

fn startup_network_boundary_attestation() -> Result<Value> {
    const EPERM: i32 = 1;

    let preload = std::env::var("LD_PRELOAD")
        .map_err(|_| "JSONL startup requires the frozen deny-INET LD_PRELOAD".to_string())?;
    let entries = preload
        .split(|character: char| character == ':' || character.is_ascii_whitespace())
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();
    if entries.len() != 1 {
        return Err("JSONL startup requires exactly one deny-INET preload".to_string());
    }
    let preload_path = fs::canonicalize(entries[0])
        .map_err(|error| format!("resolve deny-INET preload: {error}"))?;
    if preload_path.file_name().and_then(|name| name.to_str()) != Some("libminmandate_deny_inet.so")
    {
        return Err("JSONL startup preload is not the frozen deny-INET library".to_string());
    }
    let preload_bytes =
        fs::read(&preload_path).map_err(|error| format!("read deny-INET preload: {error}"))?;
    let preload_digest = sha256_plain_hex(&preload_bytes);
    let maps = fs::read_to_string("/proc/self/maps")
        .map_err(|error| format!("read process loader map: {error}"))?;
    let path_text = preload_path
        .to_str()
        .ok_or_else(|| "deny-INET preload path is not UTF-8".to_string())?;
    if !maps.lines().any(|line| line.contains(path_text)) {
        return Err("deny-INET preload is configured but absent from the loader map".to_string());
    }

    let (loopback_result, loopback_errno) = udp_connect_probe([127, 0, 0, 1])?;
    if loopback_result != 0 {
        return Err(format!(
            "deny-INET preload blocked the required loopback UDP connect: {loopback_errno:?}"
        ));
    }

    // TEST-NET-1 is reserved for documentation. UDP connect sends no payload;
    // without the interposer it only configures a peer, while the frozen guard
    // must reject the non-loopback address before any network I/O.
    let (external_result, denial_errno) = udp_connect_probe([192, 0, 2, 1])?;
    if external_result == 0 {
        return Err("deny-INET preload allowed a non-loopback UDP connect".to_string());
    }
    if denial_errno != Some(EPERM) {
        return Err(format!(
            "deny-INET non-loopback probe failed with unexpected errno: {denial_errno:?}"
        ));
    }
    Ok(json!({
        "schema_version": "minmandate-network-boundary-attestation-v2",
        "preload_path": path_text,
        "preload_sha256": preload_digest,
        "loader_mapping_verified": true,
        "af_inet_socket_creation_allowed": true,
        "loopback_udp_connect_allowed": true,
        "nonloopback_udp_connect_denied": true,
        "nonloopback_probe": "192.0.2.1:9/udp-no-payload",
        "denial_errno": "EPERM",
        "network_payload_transmitted": false,
        "live_service_contact_attempted": false,
        "activation_evidence": [
            "loader_mapping",
            "loopback_udp_connect",
            "nonloopback_udp_connect_eperm"
        ],
    }))
}

fn request_key_is_endpoint(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "endpoint"
            | "base_url"
            | "api_endpoint"
            | "service_endpoint"
            | "merchant_endpoint"
            | "payment_endpoint"
            | "settlement_endpoint"
            | "ollama_host"
    )
}

fn request_key_is_external_credential(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    matches!(
        key.as_str(),
        "api_key"
            | "apikey"
            | "access_token"
            | "refresh_token"
            | "oauth_token"
            | "client_secret"
            | "payment_intent"
            | "paymentintent"
            | "payment_credentials"
    ) || (THIRD_PARTY_PREFIXES
        .iter()
        .any(|prefix| key.starts_with(&prefix.to_ascii_lowercase()))
        && ["key", "token", "secret", "oauth", "credential"]
            .iter()
            .any(|marker| key.contains(marker)))
}

fn enforce_local_request_value(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if request_key_is_external_credential(key) && !child.is_null() {
                    return Err(format!(
                        "external credential or PaymentIntent field is forbidden: {child_path}"
                    ));
                }
                if request_key_is_endpoint(key) {
                    let endpoint = child.as_str().ok_or_else(|| {
                        format!("experiment endpoint must be a string: {child_path}")
                    })?;
                    if !is_loopback_endpoint(endpoint) {
                        return Err(format!(
                            "non-local experiment endpoint is forbidden: {child_path}"
                        ));
                    }
                }
                enforce_local_request_value(child, &child_path)?;
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                enforce_local_request_value(child, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn enforce_no_live_cost(request: &Value) -> Result<()> {
    for field in [
        "live_execution",
        "paid_saas",
        "real_payment_rail",
        "broadcast_transaction",
        "allow_charge",
        "allow_network",
        "allow_live_services",
        "allow_sandbox_services",
        "allow_real_payment",
        "allow_production_writes",
    ] {
        if request.get(field).and_then(Value::as_bool) == Some(true) {
            return Err(format!(
                "{field}=true is forbidden: this artifact is local/offline and no-charge"
            ));
        }
    }
    if let Some(mode) = request.get("execution_mode").and_then(Value::as_str) {
        if mode != EXECUTION_MODE {
            return Err(format!("unsupported execution_mode: {mode}"));
        }
    }
    enforce_local_request_value(request, "")?;
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
        })
        .collect()
}

pub(crate) fn canonical_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("serializable JSON value")
}

fn canonical_ascii_bytes(value: &Value) -> Vec<u8> {
    fn write_string(value: &str, out: &mut Vec<u8>) {
        out.push(b'"');
        for character in value.chars() {
            match character {
                '"' => out.extend_from_slice(br#"\""#),
                '\\' => out.extend_from_slice(br#"\\"#),
                '\u{08}' => out.extend_from_slice(br#"\b"#),
                '\u{0c}' => out.extend_from_slice(br#"\f"#),
                '\n' => out.extend_from_slice(br#"\n"#),
                '\r' => out.extend_from_slice(br#"\r"#),
                '\t' => out.extend_from_slice(br#"\t"#),
                character if character <= '\u{1f}' => {
                    out.extend_from_slice(format!("\\u{:04x}", character as u32).as_bytes());
                }
                character if character.is_ascii() => out.push(character as u8),
                character => {
                    let codepoint = character as u32;
                    if codepoint <= 0xffff {
                        out.extend_from_slice(format!("\\u{codepoint:04x}").as_bytes());
                    } else {
                        let adjusted = codepoint - 0x1_0000;
                        let high = 0xd800 + (adjusted >> 10);
                        let low = 0xdc00 + (adjusted & 0x3ff);
                        out.extend_from_slice(format!("\\u{high:04x}\\u{low:04x}").as_bytes());
                    }
                }
            }
        }
        out.push(b'"');
    }

    fn write_value(value: &Value, out: &mut Vec<u8>) {
        match value {
            Value::Null => out.extend_from_slice(b"null"),
            Value::Bool(true) => out.extend_from_slice(b"true"),
            Value::Bool(false) => out.extend_from_slice(b"false"),
            Value::Number(number) => out.extend_from_slice(number.to_string().as_bytes()),
            Value::String(string) => write_string(string, out),
            Value::Array(values) => {
                out.push(b'[');
                for (index, item) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    write_value(item, out);
                }
                out.push(b']');
            }
            Value::Object(map) => {
                out.push(b'{');
                let mut entries = map.iter().collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));
                for (index, (key, item)) in entries.into_iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    write_string(key, out);
                    out.push(b':');
                    write_value(item, out);
                }
                out.push(b'}');
            }
        }
    }

    let mut out = Vec::new();
    write_value(value, &mut out);
    out
}

fn sha256_plain_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

const EVP_PKEY_ED25519: i32 = 1087;

#[link(name = "crypto")]
extern "C" {
    fn EVP_PKEY_new_raw_public_key(
        key_type: i32,
        engine: *mut c_void,
        key: *const u8,
        key_len: usize,
    ) -> *mut c_void;
    fn EVP_PKEY_new_raw_private_key(
        key_type: i32,
        engine: *mut c_void,
        key: *const u8,
        key_len: usize,
    ) -> *mut c_void;
    fn EVP_PKEY_get_raw_public_key(
        key: *const c_void,
        output: *mut u8,
        output_len: *mut usize,
    ) -> i32;
    fn EVP_PKEY_free(key: *mut c_void);
    fn EVP_MD_CTX_new() -> *mut c_void;
    fn EVP_MD_CTX_free(context: *mut c_void);
    fn EVP_DigestVerifyInit(
        context: *mut c_void,
        key_context: *mut *mut c_void,
        digest: *const c_void,
        engine: *mut c_void,
        key: *mut c_void,
    ) -> i32;
    fn EVP_DigestVerify(
        context: *mut c_void,
        signature: *const u8,
        signature_len: usize,
        message: *const u8,
        message_len: usize,
    ) -> i32;
    fn EVP_DigestSignInit(
        context: *mut c_void,
        key_context: *mut *mut c_void,
        digest: *const c_void,
        engine: *mut c_void,
        key: *mut c_void,
    ) -> i32;
    fn EVP_DigestSign(
        context: *mut c_void,
        signature: *mut u8,
        signature_len: *mut usize,
        message: *const u8,
        message_len: usize,
    ) -> i32;
}

fn verify_ed25519(public_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    unsafe {
        let key = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519,
            std::ptr::null_mut(),
            public_key.as_ptr(),
            public_key.len(),
        );
        if key.is_null() {
            return false;
        }
        let context = EVP_MD_CTX_new();
        if context.is_null() {
            EVP_PKEY_free(key);
            return false;
        }
        let initialized = EVP_DigestVerifyInit(
            context,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            key,
        ) == 1;
        let verified = initialized
            && EVP_DigestVerify(
                context,
                signature.as_ptr(),
                signature.len(),
                message.as_ptr(),
                message.len(),
            ) == 1;
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(key);
        verified
    }
}

#[cfg(test)]
fn sign_ed25519_for_test(seed: &[u8; 32], message: &[u8]) -> Result<([u8; 32], [u8; 64])> {
    unsafe {
        let key = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519,
            std::ptr::null_mut(),
            seed.as_ptr(),
            seed.len(),
        );
        if key.is_null() {
            return Err("OpenSSL could not construct an Ed25519 test key".to_string());
        }
        let mut public_key = [0u8; 32];
        let mut public_key_len = public_key.len();
        if EVP_PKEY_get_raw_public_key(key, public_key.as_mut_ptr(), &mut public_key_len) != 1
            || public_key_len != public_key.len()
        {
            EVP_PKEY_free(key);
            return Err("OpenSSL could not derive an Ed25519 test public key".to_string());
        }
        let context = EVP_MD_CTX_new();
        if context.is_null()
            || EVP_DigestSignInit(
                context,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
                key,
            ) != 1
        {
            if !context.is_null() {
                EVP_MD_CTX_free(context);
            }
            EVP_PKEY_free(key);
            return Err("OpenSSL could not initialize Ed25519 signing".to_string());
        }
        let mut signature = [0u8; 64];
        let mut signature_len = signature.len();
        let signed = EVP_DigestSign(
            context,
            signature.as_mut_ptr(),
            &mut signature_len,
            message.as_ptr(),
            message.len(),
        ) == 1
            && signature_len == signature.len();
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(key);
        if !signed {
            return Err("OpenSSL could not sign Ed25519 test input".to_string());
        }
        Ok((public_key, signature))
    }
}

pub(crate) fn hash_bytes(dst: &str, parts: &[Vec<u8>]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(dst.as_bytes());
    h.update([0u8]);
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().to_vec()
}

pub(crate) fn hash_to_scalar(dst: &str, parts: &[Vec<u8>]) -> Scalar {
    let left = hash_bytes(&format!("{dst}:0"), parts);
    let right = hash_bytes(&format!("{dst}:1"), parts);
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&left);
    wide[32..].copy_from_slice(&right);
    Scalar::from_uniform_bytes(&wide)
}

pub(crate) fn random_scalar() -> Scalar {
    loop {
        let s = Scalar::random(OsRng);
        if s != Scalar::ZERO {
            return s;
        }
    }
}

fn scalar_from_value(value: &Value) -> Scalar {
    match value {
        Value::Number(n) => Scalar::from(n.as_u64().unwrap_or(0)),
        Value::String(s) => hash_to_scalar("mm-value-json", &[canonical_bytes(&json!(s))]),
        _ => hash_to_scalar("mm-value-json", &[canonical_bytes(value)]),
    }
}

pub(crate) fn scalar_hex(s: &Scalar) -> String {
    hex_encode(&wire::encode_scalar(s))
}

pub(crate) fn g1_hex(p: &G1) -> String {
    hex_encode(&wire::encode_g1(p))
}

pub(crate) fn g2_hex(p: &G2) -> String {
    hex_encode(&wire::encode_g2(p))
}

pub(crate) fn g1_linear<'a, I>(terms: I) -> G1
where
    I: IntoIterator<Item = (&'a G1, Scalar)>,
{
    let terms = terms.into_iter().collect::<Vec<_>>();
    if terms.len() < 4 {
        return terms
            .into_iter()
            .fold(G1::identity(), |acc, (base, scalar)| acc + (*base * scalar));
    }
    let projective_bases = terms.iter().map(|(base, _)| **base).collect::<Vec<_>>();
    let scalars = terms.iter().map(|(_, scalar)| *scalar).collect::<Vec<_>>();
    let mut affine_bases = vec![G1Affine::from(G1::identity()); projective_bases.len()];
    G1::batch_normalize(&projective_bases, &mut affine_bases);
    let mut acc = G1::identity();
    msm_serial(&scalars, &affine_bases, &mut acc);
    acc
}

pub(crate) fn hash_g1(label: &str) -> G1 {
    let cache = HASH_G1_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(values) = cache.read() {
        if let Some(value) = values.get(label) {
            return *value;
        }
    }
    let value = G1::hash_to_curve(MM_H2C_DST)(label.as_bytes());
    if let Ok(mut values) = cache.write() {
        if values.len() < MAX_HASH_G1_CACHE_ENTRIES {
            values.entry(label.to_string()).or_insert(value);
        }
    }
    value
}

fn registry_wallet_id(index: usize) -> Scalar {
    hash_to_scalar("mm-auth-wallet-id", &[index.to_le_bytes().to_vec()])
}

fn registry_issuer_pk(wallet_id: Scalar) -> G2 {
    G2::generator()
        * hash_to_scalar(
            "mm-auth-issuer-verification-key-attr",
            &[wallet_id.to_repr().as_ref().to_vec()],
        )
}

fn registry_digest(label: &str, set: &BTreeSet<String>) -> String {
    let parts = set
        .iter()
        .map(|entry| entry.as_bytes().to_vec())
        .collect::<Vec<_>>();
    hex_encode(&hash_bytes(label, &parts))
}

pub(crate) fn multi_pairing_check(terms: &[(G2, G1)]) -> bool {
    let g1_terms: Vec<G1Affine> = terms.iter().map(|(_, p)| G1Affine::from(*p)).collect();
    let g2_terms: Vec<G2Affine> = terms.iter().map(|(q, _)| G2Affine::from(*q)).collect();
    let refs: Vec<(&G1Affine, &G2Affine)> = g1_terms.iter().zip(g2_terms.iter()).collect();
    multi_miller_loop(&refs).final_exponentiation() == Gt::identity()
}

fn point_digest(point: &G1) -> String {
    hex_encode(&hash_bytes("spent-serial", &[g1_hex(point).into_bytes()]))
}

#[derive(Clone)]
struct SchnorrKey {
    sk: Scalar,
    pk: G1,
}

#[derive(Clone)]
struct SchnorrSignature {
    r: G1,
    z: Scalar,
}

impl SchnorrKey {
    fn new() -> Self {
        let sk = random_scalar();
        Self {
            sk,
            pk: G1::generator() * sk,
        }
    }

    fn sign(&self, value: &Value) -> SchnorrSignature {
        let nonce = random_scalar();
        let r = G1::generator() * nonce;
        let c = hash_to_scalar(
            "mm-schnorr-signature",
            &[
                g1_hex(&self.pk).into_bytes(),
                g1_hex(&r).into_bytes(),
                canonical_bytes(value),
            ],
        );
        SchnorrSignature {
            r,
            z: nonce + c * self.sk,
        }
    }
}

impl SchnorrSignature {
    fn verify(&self, pk: &G1, value: &Value) -> bool {
        let c = hash_to_scalar(
            "mm-schnorr-signature",
            &[
                g1_hex(pk).into_bytes(),
                g1_hex(&self.r).into_bytes(),
                canonical_bytes(value),
            ],
        );
        G1::generator() * self.z == self.r + (*pk * c)
    }

    fn to_value(&self) -> Value {
        json!({
            "R": g1_hex(&self.r),
            "z": scalar_hex(&self.z),
        })
    }

    fn from_value(value: &Value) -> Option<Self> {
        let r = wire::decode_g1(&hex_decode(value.get("R")?.as_str()?)?).ok()?;
        let z = wire::decode_scalar(&hex_decode(value.get("z")?.as_str()?)?).ok()?;
        Some(Self { r, z })
    }
}

fn local_signed_record(key: &SchnorrKey, domain: &str, body: Value) -> Value {
    let statement = json!({
        "domain": domain,
        "body": body,
    });
    json!({
        "statement": statement,
        "signature": key.sign(&statement).to_value(),
        "verification_key": g1_hex(&key.pk),
    })
}

fn verify_local_signed_record(record: &Value, expected_pk: &G1) -> bool {
    record.get("verification_key").and_then(Value::as_str) == Some(g1_hex(expected_pk).as_str())
        && record
            .get("signature")
            .and_then(SchnorrSignature::from_value)
            .is_some_and(|signature| {
                record
                    .get("statement")
                    .is_some_and(|statement| signature.verify(expected_pk, statement))
            })
}

fn verify_native_schnorr_item_with_cache(
    item: &Value,
    verification_keys: &mut HashMap<String, G1>,
) -> bool {
    let Some(object) = item.as_object() else {
        return false;
    };
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != ["verification_key", "statement", "signature"]
            .into_iter()
            .collect::<BTreeSet<_>>()
    {
        return false;
    }
    let Some(verification_key) = object.get("verification_key").and_then(Value::as_str) else {
        return false;
    };
    let Some(statement) = object.get("statement") else {
        return false;
    };
    let Some(signature_value) = object.get("signature") else {
        return false;
    };
    let Some(signature_object) = signature_value.as_object() else {
        return false;
    };
    if signature_object
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != ["R", "z"].into_iter().collect::<BTreeSet<_>>()
    {
        return false;
    }
    let pk = if let Some(cached) = verification_keys.get(verification_key) {
        *cached
    } else {
        let Some(pk_bytes) = hex_decode(verification_key) else {
            return false;
        };
        let Ok(decoded) = wire::decode_g1(&pk_bytes) else {
            return false;
        };
        if verification_keys.len() < 64 {
            verification_keys.insert(verification_key.to_string(), decoded);
        }
        decoded
    };
    SchnorrSignature::from_value(signature_value)
        .is_some_and(|signature| signature.verify(&pk, statement))
}

fn verify_native_schnorr_item(item: &Value) -> bool {
    verify_native_schnorr_item_with_cache(item, &mut HashMap::new())
}

fn run_native_client_validator() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    let mut verification_keys = HashMap::new();
    for line in stdin.lock().lines() {
        let response = match line {
            Ok(line) if !line.trim().is_empty() => match serde_json::from_str::<Value>(&line) {
                Ok(request) => match request.get("operation").and_then(Value::as_str) {
                    Some("ping") => json!({
                        "ok": true,
                        "validator_profile": "minmandate-native-schnorr-batch-v1",
                    }),
                    Some("verify_schnorr_batch") => {
                        match request.get("items").and_then(Value::as_array) {
                            Some(items) if !items.is_empty() && items.len() <= 16 => json!({
                            "ok": true,
                            "valid": items.iter().all(|item| {
                                verify_native_schnorr_item_with_cache(
                                    item,
                                    &mut verification_keys,
                                )
                            }),
                                "verified_items": items.len(),
                                "validator_profile": "minmandate-native-schnorr-batch-v1",
                            }),
                            _ => json!({
                                "ok": false,
                                "valid": false,
                                "error_code": "invalid-batch",
                            }),
                        }
                    }
                    _ => json!({
                        "ok": false,
                        "valid": false,
                        "error_code": "unknown-operation",
                    }),
                },
                Err(error) => json!({
                    "ok": false,
                    "valid": false,
                    "error_code": "malformed-json",
                    "detail": error.to_string(),
                }),
            },
            Ok(_) => continue,
            Err(error) => json!({
                "ok": false,
                "valid": false,
                "error_code": "stdin",
                "detail": error.to_string(),
            }),
        };
        writeln!(output, "{response}").map_err(|error| error.to_string())?;
        output.flush().map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[derive(Clone)]
struct RepProofG1 {
    commitment: G1,
    responses: BTreeMap<String, Scalar>,
}

impl RepProofG1 {
    fn to_value(&self) -> Value {
        json!({
            "commitment": g1_hex(&self.commitment),
            "responses": scalar_map_value(&self.responses),
        })
    }
}

fn scalar_map_value(map: &BTreeMap<String, Scalar>) -> Value {
    let mut out = Map::new();
    for (k, v) in map {
        out.insert(k.clone(), json!(scalar_hex(v)));
    }
    Value::Object(out)
}

fn prove_representation_g1(
    label: &str,
    bases: &BTreeMap<String, G1>,
    secrets: &BTreeMap<String, Scalar>,
    target: &G1,
    context: &Value,
) -> RepProofG1 {
    let names: Vec<String> = bases.keys().cloned().collect();
    let mut blind = BTreeMap::new();
    for name in &names {
        blind.insert(name.clone(), random_scalar());
    }
    let commitment = g1_linear(names.iter().map(|n| (&bases[n], blind[n])));
    let base_json = Value::Array(names.iter().map(|n| json!(g1_hex(&bases[n]))).collect());
    let challenge = hash_to_scalar(
        label,
        &[
            canonical_bytes(context),
            canonical_bytes(&json!(names)),
            canonical_bytes(&base_json),
            g1_hex(target).into_bytes(),
            g1_hex(&commitment).into_bytes(),
        ],
    );
    let mut responses = BTreeMap::new();
    for name in bases.keys() {
        responses.insert(name.clone(), blind[name] + challenge * secrets[name]);
    }
    RepProofG1 {
        commitment,
        responses,
    }
}

fn verify_representation_g1(
    label: &str,
    bases: &BTreeMap<String, G1>,
    target: &G1,
    proof: &RepProofG1,
    context: &Value,
) -> bool {
    if proof.responses.keys().collect::<BTreeSet<_>>() != bases.keys().collect::<BTreeSet<_>>() {
        return false;
    }
    let names: Vec<String> = bases.keys().cloned().collect();
    let base_json = Value::Array(names.iter().map(|n| json!(g1_hex(&bases[n]))).collect());
    let challenge = hash_to_scalar(
        label,
        &[
            canonical_bytes(context),
            canonical_bytes(&json!(names)),
            canonical_bytes(&base_json),
            g1_hex(target).into_bytes(),
            g1_hex(&proof.commitment).into_bytes(),
        ],
    );
    let lhs = g1_linear(names.iter().map(|n| (&bases[n], proof.responses[n])));
    let rhs = proof.commitment + (*target * challenge);
    lhs == rhs
}

fn auth_name(cls: &str) -> String {
    format!("auth:{cls}")
}

fn scope_name(cls: &str) -> String {
    format!("scope:{cls}")
}

fn serial_seed_name(cls: &str) -> String {
    format!("s_slot:{cls}")
}

fn fund_seed_name(cls: &str) -> String {
    format!("s_fund:{cls}")
}

fn slot_name(k: usize, field: &str) -> String {
    format!("slot:{k}:{field}")
}

fn message_names(classes: &[String], slot_count: usize) -> Vec<String> {
    let mut names = vec![
        BUDGET_NAME.to_string(),
        EXPIRY_NAME.to_string(),
        FUND_NAME.to_string(),
        CREDENTIAL_ID_NAME.to_string(),
    ];
    for cls in classes {
        names.push(auth_name(cls));
        names.push(scope_name(cls));
        names.push(serial_seed_name(cls));
        names.push(fund_seed_name(cls));
    }
    for k in 0..slot_count {
        names.push(slot_name(k, "capacity"));
        names.push(slot_name(k, "class"));
        names.push(slot_name(k, "merchant"));
        names.push(slot_name(k, "expiry"));
        names.push(slot_name(k, "funding_eligible"));
    }
    names
}

fn link_bases(cls: &str) -> BTreeMap<String, G1> {
    BTreeMap::from([
        (
            CREDENTIAL_ID_NAME.to_string(),
            hash_g1("mm-link-approval-digest"),
        ),
        (scope_name(cls), hash_g1("mm-link-scope")),
        ("link_rho".to_string(), hash_g1("mm-link-rho")),
    ])
}

fn funding_relation(funding_bucket: &str) -> G1Relation {
    let base = hash_g1("mm-funding-coordinate");
    let value = scalar_from_value(&json!(funding_bucket));
    (
        BTreeMap::from([(FUND_NAME.to_string(), base)]),
        base * value,
    )
}

fn slot_serial_base(k: usize) -> G1 {
    hash_g1(&format!("mm-slot-serial:{k}"))
}

fn derive_slot_serial(seed: Scalar, k: usize) -> G1 {
    slot_serial_base(k) * seed
}

fn slot_funding_base(k: usize) -> G1 {
    hash_g1(&format!("mm-slot-funding-tag:{k}"))
}

fn derive_funding_tag(seed: Scalar, k: usize) -> G1 {
    slot_funding_base(k) * seed
}

pub(crate) fn commitment_digest(label: &str, value: &Value) -> String {
    hex_encode(&hash_bytes(label, &[canonical_bytes(value)]))
}

fn credential_key_digest(pk: &BbsPublicKey) -> String {
    commitment_digest("epoch-credential-verification-key", &pk.to_value())
}

fn service_input_digest(input: &Value) -> String {
    commitment_digest("service-input", input)
}

fn typed_request_digest(service_id: &str, cls: &str, service_input_digest: &str) -> String {
    commitment_digest(
        "request",
        &json!({
            "service_id": service_id,
            "class": cls,
            "service_input_digest": service_input_digest,
        }),
    )
}

fn presentation_digest(label: &str, presentation: &BbsPresentation) -> String {
    commitment_digest(label, &presentation.to_value())
}

struct FundingState {
    configured: bool,
    eligible: bool,
    available: u64,
    reserved: u64,
}

struct WalletRuntime {
    // Immutable identity of the one top-level wallet object. W_iss and W_red
    // are logical interfaces owned by this object, not independent entities.
    wallet_entity_id: String,
    wallet_id: Scalar,
    selected_issuer_index: usize,
    funding_epoch: String,
    funding: Arc<Mutex<FundingState>>,
    issuance: EpochIssuer,
    redemption: RedemptionService,
}

#[derive(Clone)]
struct EpochAuthorizationBody {
    epoch: String,
    policy_digest: String,
    valid_from: u64,
    valid_until: u64,
}

impl EpochAuthorizationBody {
    fn to_value(&self) -> Value {
        json!({
            "profile": "minmandate-ihbbs1-policy-epoch-v1",
            "epoch": self.epoch,
            "policy_digest": self.policy_digest,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        })
    }
}

#[derive(Clone)]
struct EpochAuthorization {
    body: EpochAuthorizationBody,
    signature: SchnorrSignature,
}

impl EpochAuthorization {
    fn to_value(&self) -> Value {
        json!({
            "body": self.body.to_value(),
            "signature": self.signature.to_value(),
        })
    }
}

#[derive(Clone)]
struct CredentialVerifier {
    authorization_pk: G1,
    authorization: EpochAuthorization,
    public_params: BbsPublicParams,
    policy: ihbbs1::PolicyBundle,
}

impl CredentialVerifier {
    fn new(
        authorization_pk: G1,
        authorization: EpochAuthorization,
        public_params: BbsPublicParams,
        policy: ihbbs1::PolicyBundle,
    ) -> Result<Self> {
        ihbbs1::verify_policy(&policy, &public_params)?;
        Ok(Self {
            authorization_pk,
            authorization,
            public_params,
            policy,
        })
    }

    fn verify_authorization(&self, trusted_now: u64) -> bool {
        let body = &self.authorization.body;
        body.policy_digest == self.policy.policy_digest
            && body.valid_from <= trusted_now
            && trusted_now <= body.valid_until
            && self
                .authorization
                .signature
                .verify(&self.authorization_pk, &body.to_value())
    }

    fn shared_config_digest(&self) -> String {
        commitment_digest(
            "epoch-verifier-config",
            &json!({
                "epoch": self.authorization.body.epoch,
                "policy_digest": self.authorization.body.policy_digest,
                "authorization_pk": g1_hex(&self.authorization_pk),
                "issuer_hiding_policy_digest": self.policy.policy_digest,
                "public_parameter_digest": self.public_params.generator_digest(),
            }),
        )
    }
}

const MAX_ISSUER_MATERIAL_CACHE_ENTRIES: usize = 16;

#[derive(Clone)]
struct CachedIssuerMaterial {
    issuer_keys: Vec<(BbsSecretKey, BbsPublicKey)>,
    verifier: CredentialVerifier,
}

static ISSUER_MATERIAL_CACHE: OnceLock<RwLock<HashMap<String, Arc<CachedIssuerMaterial>>>> =
    OnceLock::new();

fn issuer_material_cache_key(
    slot_count: usize,
    classes: &[String],
    frozen_policy: Option<&policy_io::LoadedIssuerPolicy>,
) -> String {
    commitment_digest(
        "mm-issuer-material-cache-v1",
        &json!({
            "slot_count": slot_count,
            "classes": classes,
            "policy_metadata": frozen_policy.map(|policy| policy.metadata.clone()),
            "policy_profile": frozen_policy.is_some(),
        }),
    )
}

fn cached_issuer_material(
    slot_count: usize,
    classes: &[String],
    frozen_policy: Option<&policy_io::LoadedIssuerPolicy>,
) -> Result<Arc<CachedIssuerMaterial>> {
    let key = issuer_material_cache_key(slot_count, classes, frozen_policy);
    let cache = ISSUER_MATERIAL_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(values) = cache.read() {
        if let Some(material) = values.get(&key) {
            return Ok(Arc::clone(material));
        }
    }

    let params = ihbbs1::setup(&message_names(classes, slot_count));
    let funding_epoch = frozen_policy
        .map(|policy| policy.epoch.clone())
        .unwrap_or_else(|| policy_io::FINAL_V2_EPOCH.to_string());
    let registry_digest = canonical_registry_digest();
    let (issuer_keys, issuer_hiding_policy) = if let Some(policy) = frozen_policy {
        policy.instantiate(&params, &registry_digest)?
    } else {
        ihbbs1::fixture_policy(
            &params,
            &funding_epoch,
            policy_io::FINAL_V2_VALID_FROM,
            policy_io::FINAL_V2_VALID_UNTIL,
            registry_digest,
        )?
    };
    let authorization_secret = hash_to_scalar(
        "mm-ihbbs1-policy-authorization-key-v1",
        &[funding_epoch.as_bytes().to_vec()],
    );
    let authorization_key = SchnorrKey {
        sk: authorization_secret,
        pk: G1::generator() * authorization_secret,
    };
    let authorization_body = EpochAuthorizationBody {
        epoch: funding_epoch,
        policy_digest: issuer_hiding_policy.policy_digest.clone(),
        valid_from: issuer_hiding_policy.valid_from,
        valid_until: issuer_hiding_policy.valid_until,
    };
    let authorization = EpochAuthorization {
        signature: authorization_key.sign(&authorization_body.to_value()),
        body: authorization_body,
    };
    let verifier = CredentialVerifier::new(
        authorization_key.pk,
        authorization,
        params,
        issuer_hiding_policy,
    )?;
    let material = Arc::new(CachedIssuerMaterial {
        issuer_keys,
        verifier,
    });
    if let Ok(mut values) = cache.write() {
        if let Some(existing) = values.get(&key) {
            return Ok(Arc::clone(existing));
        }
        if values.len() < MAX_ISSUER_MATERIAL_CACHE_ENTRIES {
            values.insert(key, Arc::clone(&material));
        }
    }
    Ok(material)
}

fn derive_issuer_hidden_authorization(
    holder: &HolderState,
    verifier: &CredentialVerifier,
    invocation_id: &str,
) -> Result<ihbbs1::PresentationSession> {
    ihbbs1::begin_presentation_for_verified_holder(
        &verifier.public_params,
        &verifier.policy,
        &holder.issuer_hiding,
        &holder.credential,
        invocation_id,
    )
}

fn verify_issuer_hidden_authorization(
    verifier: &CredentialVerifier,
    authorization: &ihbbs1::Authorization,
    invocation_id: &str,
    trusted_now: u64,
) -> bool {
    verifier.verify_authorization(trusted_now)
        && ihbbs1::verify_authorization(
            &verifier.public_params,
            &verifier.policy,
            authorization,
            invocation_id,
            trusted_now,
        )
}

#[derive(Clone)]
struct EpochIssuer {
    sk: BbsSecretKey,
    issuer_pk: BbsPublicKey,
    verifier: CredentialVerifier,
    admission: AdmissionRegistry,
}

#[derive(Clone)]
struct User {
    key: SchnorrKey,
}

#[derive(Clone)]
struct TaxonomyAuthority {
    key: SchnorrKey,
}

#[derive(Clone)]
struct Merchant {
    merchant_id: String,
    key: SchnorrKey,
}

#[derive(Clone)]
struct PricePolicy {
    max_amount: u64,
    cert_expiry: u64,
}

impl PricePolicy {
    fn to_value(&self) -> Value {
        json!({
            "max_amount": self.max_amount,
            "cert_expiry": self.cert_expiry,
        })
    }
}

fn issuer_hiding_evidence_value(authorization: &ihbbs1::Authorization) -> Value {
    json!({
        "randomized_verification_key_b64": wire::base64_encode(&wire::encode_g2(
            &authorization.randomized_issuer_pk.x_tilde,
        )),
        "randomized_policy_membership_tag_b64": wire::base64_encode(&wire::encode_g2(
            &authorization.randomized_policy_tag.0,
        )),
        "evidence_scope": "per_call",
    })
}

fn validate_paid_wire_boundary(
    authorization: &ihbbs1::Authorization,
    presentation: &BbsPresentation,
    evidence: &Value,
) -> bool {
    let Some(object) = evidence.as_object() else {
        return false;
    };
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != [
            "randomized_verification_key_b64",
            "randomized_policy_membership_tag_b64",
            "evidence_scope",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
        || object.get("evidence_scope").and_then(Value::as_str) != Some("per_call")
    {
        return false;
    }
    let decode_evidence = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| "missing issuer-hiding wire evidence".to_string())
            .and_then(wire::base64_decode)
            .and_then(|bytes| wire::decode_g2(&bytes))
    };
    let Ok(randomized_key) = decode_evidence("randomized_verification_key_b64") else {
        return false;
    };
    let Ok(randomized_tag) = decode_evidence("randomized_policy_membership_tag_b64") else {
        return false;
    };
    if randomized_key != authorization.randomized_issuer_pk.x_tilde
        || randomized_tag != authorization.randomized_policy_tag.0
    {
        return false;
    }
    let round_trip_g1 = |point: &G1| {
        wire::decode_g1(&wire::encode_g1(point))
            .map(|decoded| decoded == *point)
            .unwrap_or(false)
    };
    let round_trip_scalar = |scalar: &Scalar| {
        wire::decode_scalar(&wire::encode_scalar(scalar))
            .map(|decoded| decoded == *scalar)
            .unwrap_or(false)
    };
    round_trip_g1(&presentation.proof.a_bar)
        && round_trip_g1(&presentation.proof.b_bar)
        && presentation.proof.commitments.iter().all(round_trip_g1)
        && presentation.proof.responses.values().all(round_trip_scalar)
        && presentation
            .disclosed_messages
            .values()
            .all(round_trip_scalar)
}

fn corrupt_external_issuer_evidence(evidence: &mut Value) {
    if let Value::Object(object) = evidence {
        object.insert("randomized_verification_key_b64".to_string(), json!("AA=="));
    }
}

#[derive(Clone)]
struct CertificateBody {
    merchant: String,
    merchant_pk: G1,
    service_id: String,
    class_name: String,
    price_policy: PricePolicy,
}

impl CertificateBody {
    fn to_value(&self) -> Value {
        json!({
            "merchant": self.merchant,
            "merchant_pk": g1_hex(&self.merchant_pk),
            "service_id": self.service_id,
            "class": self.class_name,
            "price_policy": self.price_policy.to_value(),
        })
    }
}

#[derive(Clone)]
struct Certificate {
    body: CertificateBody,
    signature: SchnorrSignature,
}

impl Certificate {
    fn to_value(&self) -> Value {
        json!({
            "body": self.body.to_value(),
            "signature": self.signature.to_value(),
        })
    }
}

impl TaxonomyAuthority {
    fn certify_service(
        &self,
        merchant: &str,
        merchant_pk: G1,
        service_id: &str,
        cls: &str,
        max_amount: u64,
        cert_expiry: u64,
    ) -> Certificate {
        let body = CertificateBody {
            merchant: merchant.to_string(),
            merchant_pk,
            service_id: service_id.to_string(),
            class_name: cls.to_string(),
            price_policy: PricePolicy {
                max_amount,
                cert_expiry,
            },
        };
        let signature = self.key.sign(&body.to_value());
        Certificate { body, signature }
    }
}

#[derive(Clone)]
struct Query {
    merchant: String,
    merchant_pk: G1,
    service_id: String,
    class_name: String,
    amount_bucket: u64,
    time: u64,
    nonce: u64,
    service_input_digest: String,
    digest: String,
    funding_bucket: String,
}

impl Query {
    fn to_value(&self) -> Value {
        json!({
            "merchant": self.merchant,
            "merchant_pk": g1_hex(&self.merchant_pk),
            "service_id": self.service_id,
            "class": self.class_name,
            "amount_bucket": self.amount_bucket,
            "time": self.time,
            "nonce": self.nonce,
            "service_input_digest": self.service_input_digest,
            "digest": self.digest,
            "funding_bucket": self.funding_bucket,
        })
    }
}

#[derive(Clone)]
struct PaymentRequest {
    payee: String,
    asset: String,
    amount: u64,
    fee_policy: String,
    settle_class: String,
    nonce: u64,
    memo: Option<String>,
}

impl PaymentRequest {
    fn to_value(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("payee".to_string(), json!(self.payee));
        obj.insert("asset".to_string(), json!(self.asset));
        obj.insert("amount".to_string(), json!(self.amount));
        obj.insert("fee_policy".to_string(), json!(self.fee_policy));
        obj.insert("settle_class".to_string(), json!(self.settle_class));
        obj.insert("nonce".to_string(), json!(self.nonce));
        if let Some(memo) = &self.memo {
            obj.insert("memo".to_string(), json!(memo));
        }
        Value::Object(obj)
    }
}

#[derive(Clone)]
struct ChallengeBody {
    q: Query,
    preq: PaymentRequest,
}

impl ChallengeBody {
    fn to_value(&self) -> Value {
        json!({
            "q": self.q.to_value(),
            "preq": self.preq.to_value(),
        })
    }
}

#[derive(Clone)]
struct Challenge {
    body: ChallengeBody,
    signature: SchnorrSignature,
}

impl Challenge {
    fn to_value(&self) -> Value {
        json!({
            "body": self.body.to_value(),
            "signature": self.signature.to_value(),
        })
    }
}

impl Merchant {
    fn challenge(&self, q: Query, preq: PaymentRequest) -> Challenge {
        let body = ChallengeBody { q, preq };
        let signature = self.key.sign(&body.to_value());
        Challenge { body, signature }
    }
}

#[derive(Clone)]
struct HolderState {
    credential: BbsCredential,
    credential_commitment: G1,
    messages: BTreeMap<String, Scalar>,
    slot_count: usize,
    credential_id: String,
    session_id: String,
    issuer_hiding: ihbbs1::HolderIssuerState,
}

#[derive(Clone)]
struct ServicePresentation {
    presentation: BbsPresentation,
    issuer_hiding_authorization: ihbbs1::Authorization,
    issuer_hiding_evidence: Value,
    l: G1,
    context: Value,
    q: Query,
    preq: PaymentRequest,
    challenge: Challenge,
    certificate: Certificate,
}

fn external_presentation_context(context: &Value) -> Value {
    let mut redacted = context.clone();
    if let Some(fields) = redacted.as_object_mut() {
        fields.remove("credential_id");
        fields.remove("session_id");
        fields.remove("selected_slots");
        fields.remove("preq");
    }
    redacted
}

impl ServicePresentation {
    fn to_value(&self) -> Value {
        self.to_value_with_redemption_binding(None)
    }

    fn to_value_with_redemption_binding(&self, redemption_binding: Option<&str>) -> Value {
        json!({
            "presentation": self.presentation.to_value(),
            "ihbbs1_presentation_statement": self
                .issuer_hiding_authorization
                .to_value_with_redemption_binding(redemption_binding),
            "issuer_hiding_evidence": self.issuer_hiding_evidence,
            "L": g1_hex(&self.l),
            "context": external_presentation_context(&self.context),
            "q": self.q.to_value(),
            "challenge": self.challenge.to_value(),
            "certificate": self.certificate.to_value(),
        })
    }
}

#[derive(Clone)]
struct PaymentProjection {
    merchant: String,
    merchant_pk: G1,
    service_id: String,
    class_name: String,
    amount_bucket: u64,
    time: u64,
    nonce: u64,
    funding_bucket: String,
    preq: PaymentRequest,
    certificate: Certificate,
}

impl PaymentProjection {
    fn to_value(&self) -> Value {
        json!({
            "amount": self.preq.amount,
            "payee": self.preq.payee,
            "asset": self.preq.asset,
            "class": self.class_name,
            "merchant": self.merchant,
            "quote_nonce": self.nonce,
            "time": self.time,
        })
    }
}

#[derive(Clone)]
struct RequestProjection {
    commitment: G1,
    redacted_target: G1,
    hidden_fields: Vec<String>,
    disclosed_messages: BTreeMap<String, Scalar>,
}

impl RequestProjection {
    fn to_value(&self) -> Value {
        json!({
            "commitment": g1_hex(&self.commitment),
            "redacted_target": g1_hex(&self.redacted_target),
            "hidden_fields": self.hidden_fields,
            "disclosed_messages": scalar_map_value(&self.disclosed_messages),
        })
    }
}

#[derive(Clone)]
struct MerchantAck {
    body: Value,
    signature: SchnorrSignature,
}

impl MerchantAck {
    fn to_value(&self) -> Value {
        json!({
            "body": self.body,
            "signature": self.signature.to_value(),
        })
    }
}

#[derive(Clone)]
struct SlotPresentation {
    presentation: BbsPresentation,
    issuer_hiding_authorization: ihbbs1::Authorization,
    issuer_hiding_evidence: Value,
    l: G1,
    context: Value,
    selected_slots: Vec<usize>,
    serials: BTreeMap<usize, G1>,
    funding_tags: BTreeMap<usize, G1>,
    projection: PaymentProjection,
    request_projection: RequestProjection,
    // Sidecar populated only after the complete pre-ack redemption statement
    // has been proved and digested. It is intentionally absent from to_value().
    merchant_ack: Option<MerchantAck>,
}

impl SlotPresentation {
    fn to_value(&self) -> Value {
        self.to_value_with_redemption_binding(None)
    }

    fn to_value_with_redemption_binding(&self, redemption_binding: Option<&str>) -> Value {
        let mut serials = Map::new();
        let mut funding_tags = Map::new();
        for k in &self.selected_slots {
            serials.insert(k.to_string(), json!(g1_hex(&self.serials[k])));
            funding_tags.insert(k.to_string(), json!(g1_hex(&self.funding_tags[k])));
        }
        json!({
            "presentation": self.presentation.to_value(),
            "ihbbs1_presentation_statement": self
                .issuer_hiding_authorization
                .to_value_with_redemption_binding(redemption_binding),
            "issuer_hiding_evidence": self.issuer_hiding_evidence,
            "L": g1_hex(&self.l),
            "context": external_presentation_context(&self.context),
            "selected_slots": self.selected_slots,
            "serials": Value::Object(serials),
            "funding_tags": Value::Object(funding_tags),
            "payment_projection": self.projection.to_value(),
            "request_projection": self.request_projection.to_value(),
        })
    }
}

#[derive(Clone)]
struct RedeemRequest {
    service: ServicePresentation,
    slot: SlotPresentation,
    ack: MerchantAck,
    merchant_digest: String,
    redemption_digest: String,
    bind: String,
}

impl RedeemRequest {
    fn to_value(&self) -> Value {
        json!({
            "merchant_view": self.service.to_value(),
            "redemption_view": self.slot.to_value(),
            "merchant_ack": self.ack.to_value(),
            "dM": self.merchant_digest,
            "dR": self.redemption_digest,
            "Bind": self.bind,
        })
    }
}

fn merchant_view_digest(service: &ServicePresentation) -> String {
    commitment_digest(DOMAIN_MERCHANT_VIEW, &service.to_value())
}

fn redemption_view_digest(slot: &SlotPresentation) -> String {
    commitment_digest(DOMAIN_REDEMPTION_PREACK_VIEW, &slot.to_value())
}

fn one_call_bind(
    service: &ServicePresentation,
    slot: &SlotPresentation,
    merchant_digest: &str,
    redemption_digest: &str,
) -> Result<String> {
    let invocation_id = service
        .context
        .get("I")
        .and_then(Value::as_str)
        .ok_or_else(|| "merchant view lacks invocation id".to_string())?;
    let request_commitment = service
        .context
        .get("request_commitment")
        .and_then(Value::as_str)
        .ok_or_else(|| "merchant view lacks request commitment".to_string())?;
    let link = service
        .context
        .get("L")
        .and_then(Value::as_str)
        .ok_or_else(|| "merchant view lacks invocation link".to_string())?;
    if slot.context.get("I") != service.context.get("I")
        || slot.context.get("request_commitment") != service.context.get("request_commitment")
        || slot.context.get("L") != service.context.get("L")
        || slot.l != service.l
    {
        return Err("merchant and redemption statements disagree on I, R, or L".to_string());
    }
    Ok(hex_encode(&hash_bytes(
        DOMAIN_BIND,
        &[
            invocation_id.as_bytes().to_vec(),
            request_commitment.as_bytes().to_vec(),
            link.as_bytes().to_vec(),
            merchant_digest.as_bytes().to_vec(),
            redemption_digest.as_bytes().to_vec(),
        ],
    )))
}

struct RedemptionService {
    // Logical W_red interface of the same wallet role that owns EpochIssuer.
    // A benchmark session keeps this state beside W_iss and assumes their
    // retained logs are joinable wallet leakage.
    verifier: CredentialVerifier,
    taxonomy_pk: G1,
    settlement_key: SchnorrKey,
    spent: SpentStore,
}

enum SpentStore {
    Memory {
        serial_owner: HashMap<String, String>,
        receipts: HashMap<String, Value>,
        budget_limit: Option<u64>,
        cumulative_spend: u64,
    },
    Durable(PathBuf),
}

enum ConsumeOutcome {
    Accepted(Value),
    Idempotent(Value),
    Conflict,
    BudgetExceeded,
    BudgetMismatch,
}

impl SpentStore {
    fn memory() -> Self {
        Self::Memory {
            serial_owner: HashMap::new(),
            receipts: HashMap::new(),
            budget_limit: None,
            cumulative_spend: 0,
        }
    }

    fn durable(path: PathBuf) -> Self {
        Self::Durable(path)
    }

    fn accept_and_consume<F>(
        &mut self,
        request_id: &str,
        serials: &[String],
        signed_budget: u64,
        amount: u64,
        make_receipt: F,
    ) -> Result<ConsumeOutcome>
    where
        F: FnOnce() -> Value,
    {
        match self {
            SpentStore::Memory {
                serial_owner,
                receipts,
                budget_limit,
                cumulative_spend,
            } => {
                if let Some(stored) = receipts.get(request_id) {
                    if serials.iter().all(|serial| {
                        serial_owner.get(serial).map(String::as_str) == Some(request_id)
                    }) {
                        return Ok(ConsumeOutcome::Idempotent(stored.clone()));
                    }
                    return Err("inconsistent in-memory consumption journal".to_string());
                }
                if serials
                    .iter()
                    .any(|serial| serial_owner.contains_key(serial))
                {
                    return Ok(ConsumeOutcome::Conflict);
                }
                if amount == 0 || amount > signed_budget {
                    return Ok(ConsumeOutcome::BudgetExceeded);
                }
                if budget_limit.is_some_and(|limit| limit != signed_budget) {
                    return Ok(ConsumeOutcome::BudgetMismatch);
                }
                let next_spend = cumulative_spend
                    .checked_add(amount)
                    .ok_or_else(|| "cumulative budget overflow".to_string())?;
                if next_spend > signed_budget {
                    return Ok(ConsumeOutcome::BudgetExceeded);
                }
                let receipt = make_receipt();
                for serial in serials {
                    serial_owner.insert(serial.clone(), request_id.to_string());
                }
                *budget_limit = Some(signed_budget);
                *cumulative_spend = next_spend;
                receipts.insert(request_id.to_string(), receipt.clone());
                Ok(ConsumeOutcome::Accepted(receipt))
            }
            SpentStore::Durable(path) => durable_accept_and_consume(
                path,
                request_id,
                serials,
                signed_budget,
                amount,
                make_receipt,
            ),
        }
    }
}

fn durable_accept_and_consume<F>(
    path: &Path,
    request_id: &str,
    serials: &[String],
    signed_budget: u64,
    amount: u64,
    make_receipt: F,
) -> Result<ConsumeOutcome>
where
    F: FnOnce() -> Value,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create spent-store directory: {error}"))?;
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "spent-store path has no UTF-8 file name".to_string())?;
    let lock_path = path.with_file_name(format!("{file_name}.lock"));
    let temp_path = path.with_file_name(format!("{file_name}.tmp"));
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| format!("open spent-store lock: {error}"))?;
    lock_file
        .lock_exclusive()
        .map_err(|error| format!("lock spent store: {error}"))?;
    let result = (|| {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(format!("read spent store: {error}")),
        };
        if !contents.is_empty() && !contents.ends_with('\n') {
            return Err("spent-store journal ends in a partial record".to_string());
        }

        let mut serial_owner = HashMap::<String, String>::new();
        let mut receipts = HashMap::<String, Value>::new();
        let mut budget_limit = None;
        let mut cumulative_spend = 0u64;
        for (line_index, line) in contents.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            if !line.trim_start().starts_with('{') {
                serial_owner.insert(line.to_string(), "legacy-record".to_string());
                continue;
            }
            let record: Value = serde_json::from_str(line)
                .map_err(|error| format!("parse spent-store record {}: {error}", line_index + 1))?;
            let owner = record
                .get("request_id")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("spent-store record {} lacks request_id", line_index + 1))?;
            let recorded_serials = record
                .get("serials")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("spent-store record {} lacks serials", line_index + 1))?;
            let recorded_receipt = record
                .get("receipt")
                .cloned()
                .ok_or_else(|| format!("spent-store record {} lacks receipt", line_index + 1))?;
            let recorded_budget = record
                .get("budget")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("spent-store record {} lacks budget", line_index + 1))?;
            let recorded_amount = record
                .get("amount")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("spent-store record {} lacks amount", line_index + 1))?;
            if budget_limit.is_some_and(|limit| limit != recorded_budget) {
                return Err("spent-store journal mixes funding reserves".to_string());
            }
            budget_limit = Some(recorded_budget);
            cumulative_spend = cumulative_spend
                .checked_add(recorded_amount)
                .ok_or_else(|| "spent-store cumulative budget overflow".to_string())?;
            if cumulative_spend > recorded_budget {
                return Err("spent-store journal exceeds its signed budget".to_string());
            }
            if let Some(previous) = receipts.insert(owner.to_string(), recorded_receipt) {
                if previous != record["receipt"] {
                    return Err(format!(
                        "spent-store request_id {owner} has conflicting receipts"
                    ));
                }
            }
            for serial in recorded_serials {
                let serial = serial.as_str().ok_or_else(|| {
                    format!(
                        "spent-store record {} has a non-string serial",
                        line_index + 1
                    )
                })?;
                if let Some(previous_owner) =
                    serial_owner.insert(serial.to_string(), owner.to_string())
                {
                    if previous_owner != owner {
                        return Err(format!(
                            "spent serial is assigned to both {previous_owner} and {owner}"
                        ));
                    }
                }
            }
        }

        if let Some(stored) = receipts.get(request_id) {
            if serials
                .iter()
                .all(|serial| serial_owner.get(serial).map(String::as_str) == Some(request_id))
            {
                return Ok(ConsumeOutcome::Idempotent(stored.clone()));
            }
            return Err(format!(
                "spent-store request_id {request_id} does not own its serial set"
            ));
        }
        if serials
            .iter()
            .any(|serial| serial_owner.contains_key(serial))
        {
            return Ok(ConsumeOutcome::Conflict);
        }
        if amount == 0 || amount > signed_budget {
            return Ok(ConsumeOutcome::BudgetExceeded);
        }
        if budget_limit.is_some_and(|limit| limit != signed_budget) {
            return Ok(ConsumeOutcome::BudgetMismatch);
        }
        let next_spend = cumulative_spend
            .checked_add(amount)
            .ok_or_else(|| "cumulative budget overflow".to_string())?;
        if next_spend > signed_budget {
            return Ok(ConsumeOutcome::BudgetExceeded);
        }

        let receipt = make_receipt();

        let record = json!({
            "version": 2,
            "request_id": request_id,
            "serials": serials,
            "budget": signed_budget,
            "amount": amount,
            "receipt": receipt,
        });
        let mut updated = contents;
        updated.push_str(
            &serde_json::to_string(&record)
                .map_err(|error| format!("serialize spent-store record: {error}"))?,
        );
        updated.push('\n');
        let mut temp_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp_path)
            .map_err(|error| format!("open spent-store transaction: {error}"))?;
        temp_file
            .write_all(updated.as_bytes())
            .map_err(|error| format!("write spent-store transaction: {error}"))?;
        temp_file
            .flush()
            .map_err(|error| format!("flush spent-store transaction: {error}"))?;
        temp_file
            .sync_all()
            .map_err(|error| format!("sync spent-store transaction: {error}"))?;
        fs::rename(&temp_path, path)
            .map_err(|error| format!("commit spent-store transaction: {error}"))?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("sync spent-store directory: {error}"))?;
        }
        Ok(ConsumeOutcome::Accepted(receipt))
    })();
    let unlock_result =
        FileExt::unlock(&lock_file).map_err(|error| format!("unlock spent store: {error}"));
    match (result, unlock_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(outcome), Ok(())) => Ok(outcome),
    }
}

#[cfg(test)]
mod canonical_accept_and_consume_tests {
    use super::{ConsumeOutcome, SpentStore};
    use serde_json::{json, Value};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_journal(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "minmandate-{name}-{}-{nonce}.jsonl",
            std::process::id()
        ))
    }

    fn remove_journal(path: &Path) {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("journal has a file name");
        for candidate in [
            path.to_path_buf(),
            path.with_file_name(format!("{file_name}.lock")),
            path.with_file_name(format!("{file_name}.tmp")),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }

    fn receipt(request_id: &str) -> Value {
        json!({
            "operation": "AcceptAndConsume",
            "request_id": request_id,
            "receipt_id": request_id,
            "atomicity_scope": "prototype-local",
        })
    }

    #[test]
    fn identical_memory_retry_returns_the_original_receipt() {
        let mut store = SpentStore::memory();
        let expected = receipt("request-a");
        assert!(matches!(
            store.accept_and_consume(
                "request-a",
                &["serial-a".to_string()],
                10,
                1,
                || expected.clone(),
            ),
            Ok(ConsumeOutcome::Accepted(value)) if value == expected
        ));
        assert!(matches!(
            store.accept_and_consume(
                "request-a",
                &["serial-a".to_string()],
                10,
                1,
                || expected.clone(),
            ),
            Ok(ConsumeOutcome::Idempotent(value)) if value == expected
        ));
    }

    #[test]
    fn altered_request_reusing_a_serial_is_rejected() {
        let mut store = SpentStore::memory();
        assert!(matches!(
            store.accept_and_consume("request-a", &["serial-a".to_string()], 10, 1, || receipt(
                "request-a"
            ),),
            Ok(ConsumeOutcome::Accepted(_))
        ));
        assert!(matches!(
            store.accept_and_consume("request-b", &["serial-a".to_string()], 10, 1, || receipt(
                "request-b"
            ),),
            Ok(ConsumeOutcome::Conflict)
        ));
    }

    #[test]
    fn durable_retry_recovers_the_receipt_after_reopen() {
        let path = unique_journal("recovery");
        remove_journal(&path);
        let expected = receipt("request-a");
        {
            let mut store = SpentStore::durable(path.clone());
            assert!(matches!(
                store.accept_and_consume(
                    "request-a",
                    &["serial-a".to_string()],
                    10,
                    1,
                    || expected.clone(),
                ),
                Ok(ConsumeOutcome::Accepted(value)) if value == expected
            ));
        }
        {
            let mut reopened = SpentStore::durable(path.clone());
            assert!(matches!(
                reopened.accept_and_consume(
                    "request-a",
                    &["serial-a".to_string()],
                    10,
                    1,
                    || expected.clone(),
                ),
                Ok(ConsumeOutcome::Idempotent(value)) if value == expected
            ));
        }
        remove_journal(&path);
    }

    #[test]
    fn durable_race_accepts_exactly_one_distinct_request() {
        const THREADS: usize = 8;
        let path = unique_journal("race");
        remove_journal(&path);
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();
        for index in 0..THREADS {
            let thread_path = path.clone();
            let thread_barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let request_id = format!("request-{index}");
                let mut store = SpentStore::durable(thread_path);
                thread_barrier.wait();
                store
                    .accept_and_consume(&request_id, &["shared-serial".to_string()], 10, 1, || {
                        receipt(&request_id)
                    })
                    .expect("durable transaction failed")
            }));
        }
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().expect("race worker panicked"))
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ConsumeOutcome::Accepted(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ConsumeOutcome::Conflict))
                .count(),
            THREADS - 1
        );
        remove_journal(&path);
    }
}

fn canonical_payment_request(preq: &PaymentRequest) -> bool {
    preq.memo.is_none() && preq.amount > 0 && preq.nonce < (1u64 << 32)
}

#[derive(Clone)]
enum PolicyAtom {
    Eq(&'static str, &'static str),
    In(&'static str, &'static [&'static str]),
    Le(&'static str, &'static str),
    CertService,
    CredentialClass,
    CanonicalPayment,
    RequestDigest,
    MerchantChallenge,
}

impl PolicyAtom {
    fn name(&self) -> String {
        match self {
            PolicyAtom::Eq(left, right) => format!("eq:{left}:{right}"),
            PolicyAtom::In(field, values) => format!("in:{field}:{}", values.join(",")),
            PolicyAtom::Le(left, right) => format!("le:{left}:{right}"),
            PolicyAtom::CertService => "cert:service".to_string(),
            PolicyAtom::CredentialClass => "credential:class".to_string(),
            PolicyAtom::CanonicalPayment => "canonical:payment".to_string(),
            PolicyAtom::RequestDigest => "digest:request".to_string(),
            PolicyAtom::MerchantChallenge => "challenge:merchant".to_string(),
        }
    }
}

fn policy_field_str(service: &ServicePresentation, field: &str) -> Option<String> {
    let cert = &service.certificate.body;
    match field {
        "q.merchant" => Some(service.q.merchant.clone()),
        "q.merchant_pk" => Some(g1_hex(&service.q.merchant_pk)),
        "q.service_id" => Some(service.q.service_id.clone()),
        "q.class" => Some(service.q.class_name.clone()),
        "q.funding_bucket" => Some(service.q.funding_bucket.clone()),
        "q.service_input_digest" => Some(service.q.service_input_digest.clone()),
        "q.digest" => Some(service.q.digest.clone()),
        "preq.payee" => Some(service.preq.payee.clone()),
        "preq.asset" => Some(service.preq.asset.clone()),
        "preq.settle_class" => Some(service.preq.settle_class.clone()),
        "cert.merchant" => Some(cert.merchant.clone()),
        "cert.merchant_pk" => Some(g1_hex(&cert.merchant_pk)),
        "cert.service_id" => Some(cert.service_id.clone()),
        "cert.class" => Some(cert.class_name.clone()),
        _ => None,
    }
}

fn policy_field_u64(service: &ServicePresentation, field: &str) -> Option<u64> {
    let cert = &service.certificate.body;
    match field {
        "q.amount_bucket" => Some(service.q.amount_bucket),
        "q.time" => Some(service.q.time),
        "preq.amount" => Some(service.preq.amount),
        "cert.max_amount" => Some(cert.price_policy.max_amount),
        "cert.expiry" => Some(cert.price_policy.cert_expiry),
        _ => None,
    }
}

fn eval_policy_atom(atom: &PolicyAtom, service: &ServicePresentation, taxonomy_pk: &G1) -> bool {
    match atom {
        PolicyAtom::Eq(left, right) => policy_field_str(service, left)
            .zip(policy_field_str(service, right))
            .map_or(false, |(l, r)| l == r),
        PolicyAtom::In(field, allowed) => policy_field_str(service, field)
            .map(|value| allowed.iter().any(|candidate| *candidate == value))
            .unwrap_or(false),
        PolicyAtom::Le(left, right) => policy_field_u64(service, left)
            .zip(policy_field_u64(service, right))
            .map_or(false, |(l, r)| l <= r),
        PolicyAtom::CertService => service
            .certificate
            .signature
            .verify(taxonomy_pk, &service.certificate.body.to_value()),
        PolicyAtom::CredentialClass => {
            let expected_scope = scalar_from_value(&json!({
                "service_class": service.q.class_name,
                "authorized": true,
            }));
            service
                .presentation
                .disclosed_messages
                .get(&scope_name(&service.q.class_name))
                == Some(&expected_scope)
        }
        PolicyAtom::CanonicalPayment => canonical_payment_request(&service.preq),
        PolicyAtom::RequestDigest => {
            service.q.digest
                == typed_request_digest(
                    &service.q.service_id,
                    &service.q.class_name,
                    &service.q.service_input_digest,
                )
                && !service.q.service_input_digest.is_empty()
        }
        PolicyAtom::MerchantChallenge => {
            service
                .challenge
                .signature
                .verify(&service.q.merchant_pk, &service.challenge.body.to_value())
                && service.challenge.body.q.to_value() == service.q.to_value()
                && service.challenge.body.preq.to_value() == service.preq.to_value()
        }
    }
}

fn service_policy_atoms() -> Vec<PolicyAtom> {
    vec![
        PolicyAtom::CertService,
        PolicyAtom::Eq("cert.merchant", "q.merchant"),
        PolicyAtom::Eq("cert.merchant_pk", "q.merchant_pk"),
        PolicyAtom::Eq("cert.service_id", "q.service_id"),
        PolicyAtom::Eq("cert.class", "q.class"),
        PolicyAtom::Eq("preq.payee", "q.merchant"),
        PolicyAtom::Le("preq.amount", "cert.max_amount"),
        PolicyAtom::Le("preq.amount", "q.amount_bucket"),
        PolicyAtom::Le("q.time", "cert.expiry"),
        PolicyAtom::In("preq.asset", &["USD-test"]),
        PolicyAtom::In("preq.settle_class", &["pool"]),
        PolicyAtom::CredentialClass,
        PolicyAtom::CanonicalPayment,
        PolicyAtom::RequestDigest,
        PolicyAtom::MerchantChallenge,
    ]
}

fn payment_projection(
    q: &Query,
    preq: &PaymentRequest,
    certificate: &Certificate,
) -> PaymentProjection {
    PaymentProjection {
        merchant: q.merchant.clone(),
        merchant_pk: q.merchant_pk,
        service_id: q.service_id.clone(),
        class_name: q.class_name.clone(),
        amount_bucket: q.amount_bucket,
        time: q.time,
        nonce: q.nonce,
        funding_bucket: q.funding_bucket.clone(),
        preq: preq.clone(),
        certificate: certificate.clone(),
    }
}

fn projection_scalar_fields(
    q: &Query,
    preq: &PaymentRequest,
) -> (BTreeMap<String, Scalar>, BTreeMap<String, Scalar>) {
    let mut disclosed = BTreeMap::new();
    disclosed.insert(
        "merchant".to_string(),
        scalar_from_value(&json!(q.merchant)),
    );
    disclosed.insert("class".to_string(), scalar_from_value(&json!(q.class_name)));
    disclosed.insert("time".to_string(), Scalar::from(q.time));
    disclosed.insert("quote_nonce".to_string(), Scalar::from(q.nonce));
    disclosed.insert("payee".to_string(), scalar_from_value(&json!(preq.payee)));
    disclosed.insert("asset".to_string(), scalar_from_value(&json!(preq.asset)));
    disclosed.insert("amount".to_string(), Scalar::from(preq.amount));

    let mut hidden = BTreeMap::new();
    hidden.insert(
        "service_input_digest".to_string(),
        scalar_from_value(&json!(q.service_input_digest)),
    );
    hidden.insert(
        "typed_request_digest".to_string(),
        scalar_from_value(&json!(q.digest)),
    );
    hidden.insert(
        "challenge_body".to_string(),
        scalar_from_value(&json!({
            "q": q.to_value(),
            "preq": preq.to_value(),
        })),
    );
    (disclosed, hidden)
}

fn request_projection_bases(
    disclosed: &BTreeMap<String, Scalar>,
    hidden: &BTreeMap<String, Scalar>,
) -> BTreeMap<String, G1> {
    let mut bases = BTreeMap::new();
    bases.insert("eta".to_string(), hash_g1("mm-request-projection:eta"));
    for name in disclosed.keys() {
        bases.insert(
            format!("public:{name}"),
            hash_g1(&format!("mm-request-projection:public:{name}")),
        );
    }
    for name in hidden.keys() {
        bases.insert(
            format!("hidden:{name}"),
            hash_g1(&format!("mm-request-projection:hidden:{name}")),
        );
    }
    bases
}

fn build_request_projection(
    q: &Query,
    preq: &PaymentRequest,
    certificate: &Certificate,
) -> (
    PaymentProjection,
    RequestProjection,
    G1Relation,
    BTreeMap<String, Scalar>,
) {
    let projection = payment_projection(q, preq, certificate);
    let (disclosed, hidden) = projection_scalar_fields(q, preq);
    let bases = request_projection_bases(&disclosed, &hidden);
    let eta = random_scalar();
    let hidden_names = hidden.keys().cloned().collect::<Vec<_>>();
    let mut hidden_secrets = BTreeMap::new();
    hidden_secrets.insert("eta".to_string(), eta);
    for (name, value) in &hidden {
        hidden_secrets.insert(format!("hidden:{name}"), *value);
    }
    let disclosed_part = g1_linear(
        disclosed
            .iter()
            .map(|(name, value)| (&bases[&format!("public:{name}")], *value)),
    );
    let hidden_part = g1_linear(
        hidden
            .iter()
            .map(|(name, value)| (&bases[&format!("hidden:{name}")], *value)),
    ) + (bases["eta"] * eta);
    let commitment = disclosed_part + hidden_part;
    let redacted_target = commitment - disclosed_part;
    let hidden_bases = hidden_secrets
        .keys()
        .map(|name| (name.clone(), bases[name]))
        .collect::<BTreeMap<_, _>>();
    (
        projection,
        RequestProjection {
            commitment,
            redacted_target,
            hidden_fields: hidden_names,
            disclosed_messages: disclosed,
        },
        (hidden_bases, redacted_target),
        hidden_secrets,
    )
}

fn request_projection_relation(
    projection: &PaymentProjection,
    proof: &RequestProjection,
) -> Option<G1Relation> {
    let dummy_q = Query {
        merchant: projection.merchant.clone(),
        merchant_pk: projection.merchant_pk,
        service_id: projection.service_id.clone(),
        class_name: projection.class_name.clone(),
        amount_bucket: projection.amount_bucket,
        time: projection.time,
        nonce: projection.nonce,
        service_input_digest: String::new(),
        digest: String::new(),
        funding_bucket: projection.funding_bucket.clone(),
    };
    let (expected_disclosed, hidden_shape) = projection_scalar_fields(&dummy_q, &projection.preq);
    if proof.disclosed_messages != expected_disclosed {
        return None;
    }
    let expected_hidden = hidden_shape.keys().cloned().collect::<Vec<_>>();
    if proof.hidden_fields != expected_hidden {
        return None;
    }
    let bases = request_projection_bases(&expected_disclosed, &hidden_shape);
    let disclosed_part = expected_disclosed
        .iter()
        .fold(G1::identity(), |acc, (name, value)| {
            acc + (bases[&format!("public:{name}")] * *value)
        });
    if proof.redacted_target != proof.commitment - disclosed_part {
        return None;
    }
    let mut hidden_bases = BTreeMap::new();
    hidden_bases.insert("eta".to_string(), bases["eta"]);
    for name in &proof.hidden_fields {
        hidden_bases.insert(
            format!("hidden:{name}"),
            hash_g1(&format!("mm-request-projection:hidden:{name}")),
        );
    }
    Some((hidden_bases, proof.redacted_target))
}

fn eval_redemption_projection(
    projection: &PaymentProjection,
    taxonomy_pk: &G1,
    trusted_now: u64,
) -> bool {
    let cert = &projection.certificate.body;
    projection
        .certificate
        .signature
        .verify(taxonomy_pk, &cert.to_value())
        && cert.merchant == projection.merchant
        && cert.merchant_pk == projection.merchant_pk
        && cert.service_id == projection.service_id
        && cert.class_name == projection.class_name
        && projection.preq.payee == projection.merchant
        && projection.preq.amount <= cert.price_policy.max_amount
        && projection.preq.amount <= projection.amount_bucket
        && projection.time <= trusted_now
        && trusted_now <= cert.price_policy.cert_expiry
        && projection.preq.asset == "USD-test"
        && projection.preq.settle_class == "pool"
        && canonical_payment_request(&projection.preq)
}

pub(crate) fn canonical_registry_digest() -> String {
    FINAL_V2_ISSUER_REGISTRY_DIGEST
        .get_or_init(|| {
            let admission = canonical_admission_registry();
            let admitted = admission.registry.iter().cloned().collect::<Vec<_>>();
            let revoked = admission.revoked.iter().cloned().collect::<Vec<_>>();
            commitment_digest(
                "issuer-admission-registry",
                &json!({"admitted": admitted, "revoked": revoked}),
            )
        })
        .clone()
}

fn issuer_assignment_index(wallet_local_seed: &str, epoch: &str, policy_size: usize) -> usize {
    let mut hash = Sha256::new();
    hash.update(policy_io::ASSIGNMENT_DOMAIN.as_bytes());
    hash.update([0]);
    hash.update(wallet_local_seed.as_bytes());
    hash.update([0]);
    hash.update(epoch.as_bytes());
    let digest = hash.finalize();
    let mut word = [0u8; 8];
    word.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(word) as usize) % policy_size
}

fn build_system(slot_count: usize, classes: &[String]) -> (User, WalletRuntime, TaxonomyAuthority) {
    build_system_with_wallet_entity_id(slot_count, classes, None)
}

fn build_system_with_wallet_entity_id(
    slot_count: usize,
    classes: &[String],
    requested_wallet_entity_id: Option<String>,
) -> (User, WalletRuntime, TaxonomyAuthority) {
    build_system_with_policy(slot_count, classes, requested_wallet_entity_id, None)
        .expect("valid deterministic canonical IHBBS1 fixture policy")
}

fn build_system_with_policy(
    slot_count: usize,
    classes: &[String],
    requested_wallet_entity_id: Option<String>,
    frozen_policy: Option<&policy_io::LoadedIssuerPolicy>,
) -> Result<(User, WalletRuntime, TaxonomyAuthority)> {
    let material = cached_issuer_material(slot_count, classes, frozen_policy)?;
    let funding_epoch = frozen_policy
        .map(|policy| policy.epoch.clone())
        .unwrap_or_else(|| policy_io::FINAL_V2_EPOCH.to_string());
    let admission = canonical_admission_registry().clone();
    let wallet_id = registry_wallet_id(nonrevoked_wallet_index(128));
    let wallet_entity_id = requested_wallet_entity_id.unwrap_or_else(|| {
        commitment_digest(
            "wallet-runtime-entity-v2",
            &json!({"nonce": scalar_hex(&random_scalar())}),
        )
    });
    let selection = issuer_assignment_index(
        &wallet_entity_id,
        &funding_epoch,
        material.verifier.policy.issuers.len(),
    );
    let issuer_pk = material.verifier.policy.issuers[selection].clone();
    let (sk, _) = material
        .issuer_keys
        .iter()
        .find(|(_, candidate)| candidate.x_tilde == issuer_pk.x_tilde)
        .cloned()
        .ok_or_else(|| {
            "selected issuer secret is missing from deterministic fixture".to_string()
        })?;
    let issuance = EpochIssuer {
        sk,
        issuer_pk,
        verifier: material.verifier.clone(),
        admission,
    };
    let taxonomy = TaxonomyAuthority {
        key: SchnorrKey::new(),
    };
    let redemption = RedemptionService::new_ephemeral(issuance.verifier.clone(), taxonomy.key.pk);
    Ok((
        User {
            key: SchnorrKey::new(),
        },
        WalletRuntime {
            wallet_entity_id,
            wallet_id,
            selected_issuer_index: selection,
            funding_epoch,
            funding: Arc::new(Mutex::new(FundingState {
                configured: false,
                eligible: false,
                available: 0,
                reserved: 0,
            })),
            issuance,
            redemption,
        },
        taxonomy,
    ))
}

fn issue_task_credential_with_goal_and_expiries_bound(
    user: &User,
    wallet: &WalletRuntime,
    allowed_classes: &[String],
    capacities: &[u64],
    slot_classes: &[String],
    slot_merchants: &[String],
    slot_expiries: &[u64],
    budget: u64,
    task_goal: &str,
    slot_funding_eligibility: &[bool],
    approval_digest: Option<&str>,
) -> Result<(HolderState, Value)> {
    let wallet_id = scalar_hex(&wallet.wallet_id);
    if !wallet.issuance.admission.registry.contains(&wallet_id) {
        return Err("wallet is not admitted for the credential epoch".to_string());
    }
    if wallet.issuance.admission.revoked.contains(&wallet_id) {
        return Err("wallet is revoked for the credential epoch".to_string());
    }
    if allowed_classes.is_empty()
        || capacities.is_empty()
        || budget == 0
        || slot_expiries.iter().any(|expiry| *expiry == 0)
    {
        return Err("mandate schema is incomplete".to_string());
    }
    if capacities.len() != slot_classes.len()
        || capacities.len() != slot_merchants.len()
        || capacities.len() != slot_expiries.len()
        || capacities.len() != slot_funding_eligibility.len()
    {
        return Err("slot vectors differ in length".to_string());
    }
    if slot_merchants.iter().any(|merchant| merchant.is_empty()) {
        return Err("slot merchant is empty".to_string());
    }
    if slot_classes
        .iter()
        .any(|cls| !allowed_classes.contains(cls))
    {
        return Err("slot class outside policy".to_string());
    }
    let mandate_expiry = *slot_expiries
        .iter()
        .max()
        .ok_or_else(|| "mandate has no slot expiry".to_string())?;
    let mut funding = wallet
        .funding
        .lock()
        .map_err(|_| "wallet funding state is poisoned".to_string())?;
    if !funding.configured {
        return Err("wallet funding must be configured before credential issuance".to_string());
    }
    if !funding.eligible {
        return Err("wallet is not funding-eligible".to_string());
    }
    if funding.available < budget {
        return Err("insufficient wallet funding for requested budget reserve".to_string());
    }
    let task = json!({
        "goal": task_goal,
        "target_commit": commitment_digest("task", &json!(task_goal)),
    });
    let approved_slot_plan = capacities
        .iter()
        .zip(slot_classes)
        .zip(slot_merchants)
        .zip(slot_expiries)
        .zip(slot_funding_eligibility)
        .enumerate()
        .map(
            |(
                index,
                ((((capacity, service_class), merchant_id), slot_expiry), funding_eligible),
            )| {
                (
                    index,
                    *capacity,
                    service_class.clone(),
                    merchant_id.clone(),
                    *slot_expiry,
                    *funding_eligible,
                )
            },
        )
        .collect::<Vec<_>>();
    let allowed_merchants = slot_merchants
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let policy = json!({
        "allowed_classes": allowed_classes,
        "allowed_merchants": allowed_merchants,
        "policy_atoms": service_policy_atoms()
            .iter()
            .map(PolicyAtom::name)
            .collect::<Vec<_>>(),
        "budget": budget,
        "expiry": mandate_expiry,
        "slots": approved_slot_plan
            .iter()
            .map(|(index, capacity, service_class, merchant_id, slot_expiry, funding_eligible)| json!({
                "slot_index": index,
                "service_class": service_class,
                "merchant_id": merchant_id,
                "capacity": capacity,
                "expiry": slot_expiry,
                "funding_eligible": funding_eligible,
            }))
            .collect::<Vec<_>>(),
    });
    let mandate = json!({
        "task_commitment": commitment_digest("mandate-task", &task),
        "policy_commitment": commitment_digest("mandate-policy", &policy),
        "policy": policy,
        "wallet_epoch": wallet.funding_epoch,
        "user_approval_artifact_sha256": approval_digest,
    });
    let credential_id = approval_digest
        .map(str::to_string)
        .unwrap_or_else(|| commitment_digest("credential-id", &mandate));
    let session_id = credential_id.clone();
    let mandate_sig = user.key.sign(&mandate);
    if !mandate_sig.verify(&user.key.pk, &mandate) {
        return Err("user approval evidence is invalid".to_string());
    }

    let mut hidden_values = BTreeMap::new();

    let mut public = BTreeMap::new();
    let credential_classes = wallet
        .issuance
        .issuer_pk
        .params
        .message_names
        .iter()
        .filter_map(|name| name.strip_prefix("auth:").map(|s| s.to_string()))
        .collect::<Vec<_>>();
    for cls in credential_classes {
        hidden_values.insert(serial_seed_name(&cls), random_scalar());
        hidden_values.insert(fund_seed_name(&cls), random_scalar());
        let authorized = allowed_classes.contains(&cls);
        public.insert(
            auth_name(&cls),
            if authorized {
                Scalar::ONE
            } else {
                Scalar::ZERO
            },
        );
        public.insert(
            scope_name(&cls),
            if authorized {
                scalar_from_value(&json!({"service_class": cls, "authorized": true}))
            } else {
                Scalar::ZERO
            },
        );
    }
    public.insert(BUDGET_NAME.to_string(), Scalar::from(budget));
    public.insert(EXPIRY_NAME.to_string(), Scalar::from(mandate_expiry));
    public.insert(
        FUND_NAME.to_string(),
        scalar_from_value(&json!(FINAL_V2_FUNDING_BUCKET)),
    );
    public.insert(
        CREDENTIAL_ID_NAME.to_string(),
        scalar_from_value(&json!(credential_id)),
    );
    for (k, capacity, cls, merchant, slot_expiry, funding_eligible) in &approved_slot_plan {
        public.insert(slot_name(*k, "capacity"), Scalar::from(*capacity));
        public.insert(slot_name(*k, "class"), scalar_from_value(&json!(cls)));
        public.insert(
            slot_name(*k, "merchant"),
            scalar_from_value(&json!(merchant)),
        );
        public.insert(slot_name(*k, "expiry"), Scalar::from(*slot_expiry));
        public.insert(
            slot_name(*k, "funding_eligible"),
            if *funding_eligible {
                Scalar::ONE
            } else {
                Scalar::ZERO
            },
        );
    }
    // The wallet is trusted by the main threat model, so issuance need not
    // hide the agent's serial and funding-tag seeds from W_iss.  Keep the
    // values undisclosed in later presentations, but send the complete signed
    // vector to the issuer for ordinary BBS signing.  `blind_bbs` remains an
    // appendix-only extension for deployments with a stronger issuer-privacy
    // goal.
    let mut issuer_visible_messages = public.clone();
    issuer_visible_messages.extend(hidden_values.clone());
    issuer_visible_messages.insert(bbs::PROVER_BLIND_MESSAGE.to_string(), random_scalar());
    // Measurement-only instrumentation.  It observes the existing ordinary
    // issuer-visible issuance path without changing its inputs, outputs, or
    // authorization decisions.
    let (credential_result, issuer_sign_ms) = timed(|| {
        bbs::issue(
            &wallet.issuance.sk,
            &wallet.issuance.issuer_pk,
            &issuer_visible_messages,
        )
    });
    let credential = credential_result?;
    let credential_commitment =
        bbs::commitment(&wallet.issuance.issuer_pk.params, &credential.messages)?;
    // Record only data already exchanged during issuance.  The conversion is
    // performed before the credential moves into HolderState.
    let credential_signature = credential.signature.to_value();
    let (issuer_hiding_result, holder_policy_prepare_ms) = timed(|| {
        ihbbs1::holder_state_for_verified_policy(
            &wallet.issuance.verifier.policy,
            &wallet.issuance.issuer_pk,
        )
    });
    let issuer_hiding = issuer_hiding_result?;
    let (funding_reserve_result, budget_reservation_ms) = timed(|| -> Result<()> {
        funding.available -= budget;
        funding.reserved = funding
            .reserved
            .checked_add(budget)
            .ok_or_else(|| "wallet funding reserve overflow".to_string())?;
        Ok(())
    });
    funding_reserve_result?;
    Ok((
        HolderState {
            messages: credential.messages.clone(),
            credential_commitment,
            credential,
            slot_count: capacities.len(),
            credential_id: credential_id.clone(),
            session_id: session_id.clone(),
            issuer_hiding,
        },
        json!({
            "issuance_mode": ORDINARY_ISSUANCE_MODE,
            "mandate": mandate,
            "mandate_signature": mandate_sig.to_value(),
            "issuer_visible_message_names": issuer_visible_messages.keys().cloned().collect::<Vec<_>>(),
            "credential_id": credential_id,
            "session_id": session_id,
            "funding_reserve": {
                "eligible": true,
                "funding_bucket": FINAL_V2_FUNDING_BUCKET,
                "reserved_budget": budget,
                "remaining_available": funding.available,
            },
            "setup_stage_timings_ms": {
                "issuer_sign": issuer_sign_ms,
                "holder_policy_prepare": holder_policy_prepare_ms,
                "budget_reservation": budget_reservation_ms,
            },
            "setup_wire_material": {
                "holder_to_issuer": {
                    "mandate": mandate,
                    "mandate_signature": mandate_sig.to_value(),
                    "signed_messages": scalar_map_value(&issuer_visible_messages),
                },
                "issuer_to_holder": {
                    "credential_signature": credential_signature,
                },
            },
        }),
    ))
}

fn issue_task_credential_with_goal_and_expiries(
    user: &User,
    wallet: &WalletRuntime,
    allowed_classes: &[String],
    capacities: &[u64],
    slot_classes: &[String],
    slot_merchants: &[String],
    slot_expiries: &[u64],
    budget: u64,
    task_goal: &str,
) -> Result<(HolderState, Value)> {
    {
        let mut funding = wallet
            .funding
            .lock()
            .map_err(|_| "wallet funding state is poisoned".to_string())?;
        if !funding.configured {
            funding.configured = true;
            funding.eligible = true;
            funding.available = budget;
        }
    }
    issue_task_credential_with_goal_and_expiries_bound(
        user,
        wallet,
        allowed_classes,
        capacities,
        slot_classes,
        slot_merchants,
        slot_expiries,
        budget,
        task_goal,
        &vec![true; capacities.len()],
        None,
    )
}

fn issue_task_credential_with_goal(
    user: &User,
    wallet: &WalletRuntime,
    allowed_classes: &[String],
    capacities: &[u64],
    slot_classes: &[String],
    slot_merchants: &[String],
    expiry: u64,
    budget: u64,
    task_goal: &str,
) -> Result<(HolderState, Value)> {
    issue_task_credential_with_goal_and_expiries(
        user,
        wallet,
        allowed_classes,
        capacities,
        slot_classes,
        slot_merchants,
        &vec![expiry; capacities.len()],
        budget,
        task_goal,
    )
}

fn issue_task_credential_with_expiries(
    user: &User,
    wallet: &WalletRuntime,
    allowed_classes: &[String],
    capacities: &[u64],
    slot_classes: &[String],
    slot_merchants: &[String],
    slot_expiries: &[u64],
    budget: u64,
) -> Result<(HolderState, Value)> {
    issue_task_credential_with_goal_and_expiries(
        user,
        wallet,
        allowed_classes,
        capacities,
        slot_classes,
        slot_merchants,
        slot_expiries,
        budget,
        "evaluate Company X",
    )
}

fn issue_task_credential(
    user: &User,
    wallet: &WalletRuntime,
    allowed_classes: &[String],
    capacities: &[u64],
    slot_classes: &[String],
    slot_merchants: &[String],
    expiry: u64,
    budget: u64,
) -> Result<(HolderState, Value)> {
    issue_task_credential_with_goal(
        user,
        wallet,
        allowed_classes,
        capacities,
        slot_classes,
        slot_merchants,
        expiry,
        budget,
        "evaluate Company X",
    )
}

fn nonce32() -> u64 {
    let mut rng = OsRng;
    rng.next_u32() as u64
}

fn default_service_input(service_id: &str, cls: &str) -> Value {
    json!({
        "workflow": "single-call-benchmark",
        "service": service_id,
        "class": cls,
    })
}

fn merchant_request(
    merchant: &Merchant,
    taxonomy: &TaxonomyAuthority,
    service_id: &str,
    cls: &str,
    service_input_digest: &str,
    amount: u64,
    now: u64,
    malicious_tag: bool,
) -> (Query, PaymentRequest, Challenge, Certificate) {
    let cert = taxonomy.certify_service(
        &merchant.merchant_id,
        merchant.key.pk,
        service_id,
        cls,
        amount + 5,
        now + 1000,
    );
    let q = Query {
        merchant: merchant.merchant_id.clone(),
        merchant_pk: merchant.key.pk,
        service_id: service_id.to_string(),
        class_name: cls.to_string(),
        amount_bucket: amount,
        time: now,
        nonce: nonce32(),
        service_input_digest: service_input_digest.to_string(),
        digest: typed_request_digest(service_id, cls, service_input_digest),
        funding_bucket: FINAL_V2_FUNDING_BUCKET.to_string(),
    };
    let mut preq = PaymentRequest {
        payee: merchant.merchant_id.clone(),
        asset: "USD-test".to_string(),
        amount,
        fee_policy: "standard".to_string(),
        settle_class: "pool".to_string(),
        nonce: nonce32(),
        memo: None,
    };
    if malicious_tag {
        preq.memo = Some(hex_encode(&hash_bytes(
            "merchant-tag",
            &[canonical_bytes(&q.to_value())],
        )));
    }
    let challenge = merchant.challenge(q.clone(), preq.clone());
    (q, preq, challenge, cert)
}

fn expected_service_context(service: &ServicePresentation) -> Option<Value> {
    let request_commitment = service.context.get("request_commitment")?.as_str()?;
    let projection = payment_projection(&service.q, &service.preq, &service.certificate);
    let projection_digest = commitment_digest("payment-projection", &projection.to_value());
    let invocation_id = hex_encode(&hash_bytes(
        "mm-invocation",
        &[
            request_commitment.as_bytes().to_vec(),
            projection_digest.as_bytes().to_vec(),
            g1_hex(&service.l).into_bytes(),
            canonical_bytes(&service.certificate.body.to_value()),
        ],
    ));
    Some(json!({
        "role": "service",
        "credential_id": service.context.get("credential_id")?,
        "session_id": service.context.get("session_id")?,
        "L": g1_hex(&service.l),
        "I": invocation_id,
        "request_commitment": request_commitment,
        "projection_digest": projection_digest,
        "q": service.q.to_value(),
        "preq": service.preq.to_value(),
        "challenge": service.challenge.to_value(),
        "certificate_body": service.certificate.body.to_value(),
        "issuer_hiding_authorization_statement": service
            .issuer_hiding_authorization
            .proof_context_value(),
        "invocation_binding": service.issuer_hiding_authorization.invocation_binding,
    }))
}

fn verify_signed_slot_coordinates(
    presentation: &BbsPresentation,
    selected_slots: &[usize],
    class_name: &str,
    merchant: &str,
    amount: u64,
    trusted_now: u64,
) -> std::result::Result<(), &'static str> {
    if selected_slots.is_empty()
        || selected_slots.iter().collect::<BTreeSet<_>>().len() != selected_slots.len()
    {
        return Err("slot-fields");
    }
    let class_scalar = scalar_from_value(&json!(class_name));
    let merchant_scalar = scalar_from_value(&json!(merchant));
    let admitted_scope_scalar = scalar_from_value(&json!(format!("policy:admitted:{class_name}")));
    let mut total_capacity = 0u64;
    for slot in selected_slots {
        let capacity = presentation
            .disclosed_messages
            .get(&slot_name(*slot, "capacity"))
            .and_then(scalar_to_u64)
            .ok_or("capacity")?;
        let signed_class = presentation
            .disclosed_messages
            .get(&slot_name(*slot, "class"))
            .ok_or("slot-fields")?;
        let signed_merchant = presentation
            .disclosed_messages
            .get(&slot_name(*slot, "merchant"))
            .ok_or("slot-fields")?;
        let expiry = presentation
            .disclosed_messages
            .get(&slot_name(*slot, "expiry"))
            .and_then(scalar_to_u64)
            .ok_or("expiry")?;
        let funding_eligible = presentation
            .disclosed_messages
            .get(&slot_name(*slot, "funding_eligible"))
            .ok_or("funding-eligibility")?;
        if capacity == 0 {
            return Err("capacity");
        }
        if *signed_class != class_scalar {
            return Err("class");
        }
        if *signed_merchant != merchant_scalar && *signed_merchant != admitted_scope_scalar {
            return Err("merchant");
        }
        if expiry < trusted_now {
            return Err("expiry");
        }
        if *funding_eligible != Scalar::ONE {
            return Err("funding-eligibility");
        }
        total_capacity = total_capacity.checked_add(capacity).ok_or("capacity")?;
    }
    if total_capacity < amount {
        return Err("capacity");
    }
    Ok(())
}

fn service_presentation_relations<'a>(
    taxonomy_pk: &G1,
    service: &'a ServicePresentation,
    trusted_now: u64,
) -> std::result::Result<(&'a str, Vec<G1Relation>), &'static str> {
    if service.q.time > trusted_now {
        return Err("future-time");
    }
    if trusted_now > service.certificate.body.price_policy.cert_expiry {
        return Err("certificate-expiry");
    }
    let credential_expiry = service
        .presentation
        .disclosed_messages
        .get(EXPIRY_NAME)
        .and_then(scalar_to_u64)
        .ok_or("expiry")?;
    if trusted_now > credential_expiry {
        return Err("expiry");
    }
    if !service_policy_atoms()
        .iter()
        .all(|atom| eval_policy_atom(atom, service, taxonomy_pk))
    {
        return Err("policy");
    }
    if expected_service_context(service).as_ref() != Some(&service.context) {
        return Err("service-context");
    }
    let invocation_id = service.context["I"]
        .as_str()
        .ok_or("issuer-authorization")?;
    Ok((
        invocation_id,
        vec![(link_bases(&service.q.class_name), service.l)],
    ))
}

fn verify_service_presentation(
    verifier: &CredentialVerifier,
    taxonomy_pk: &G1,
    service: &ServicePresentation,
    trusted_now: u64,
) -> std::result::Result<(), &'static str> {
    let (invocation_id, relation) =
        service_presentation_relations(taxonomy_pk, service, trusted_now)?;
    if !verifier.verify_authorization(trusted_now) {
        return Err("issuer-authorization");
    }
    if !validate_paid_wire_boundary(
        &service.issuer_hiding_authorization,
        &service.presentation,
        &service.issuer_hiding_evidence,
    ) {
        return Err("wire-encoding");
    }
    if !ihbbs1::verify_with_verified_policy(
        &verifier.public_params,
        &verifier.policy,
        &service.issuer_hiding_authorization,
        &service.presentation,
        &relation,
        &service.context,
        "mm-service-presentation",
        invocation_id,
        trusted_now,
    ) {
        return if verify_issuer_hidden_authorization(
            verifier,
            &service.issuer_hiding_authorization,
            invocation_id,
            trusted_now,
        ) {
            Err("service-proof")
        } else {
            Err("issuer-authorization")
        };
    }
    Ok(())
}

fn merchant_acknowledge_service(
    merchant: &Merchant,
    verifier: &CredentialVerifier,
    taxonomy_pk: &G1,
    service: &ServicePresentation,
    redemption_digest: &str,
    bind: &str,
    trusted_now: u64,
) -> Result<MerchantAck> {
    if service.q.merchant != merchant.merchant_id || service.q.merchant_pk != merchant.key.pk {
        return Err("service presentation targets a different merchant".to_string());
    }
    verify_service_presentation(verifier, taxonomy_pk, service, trusted_now)
        .map_err(|reason| format!("merchant rejected service presentation: {reason}"))?;
    let merchant_digest = merchant_view_digest(service);
    let expected_bind = hex_encode(&hash_bytes(
        DOMAIN_BIND,
        &[
            service.context["I"].as_str().unwrap().as_bytes().to_vec(),
            service.context["request_commitment"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
            service.context["L"].as_str().unwrap().as_bytes().to_vec(),
            merchant_digest.as_bytes().to_vec(),
            redemption_digest.as_bytes().to_vec(),
        ],
    ));
    if bind != expected_bind {
        return Err("merchant received an inconsistent one-call binding".to_string());
    }
    let body = json!({
        "profile": "MM-merchant-ack-v1",
        "I": service.context["I"],
        "R": service.context["request_commitment"],
        "L": service.context["L"],
        "dM": merchant_digest,
        "dR": redemption_digest,
        "Bind": bind,
    });
    Ok(MerchantAck {
        signature: merchant.key.sign(&body),
        body,
    })
}

fn derive_presentations_with_merchant_timing(
    holder: &HolderState,
    verifier: &CredentialVerifier,
    taxonomy_pk: &G1,
    merchant: &Merchant,
    q: &Query,
    preq: &PaymentRequest,
    challenge: &Challenge,
    certificate: &Certificate,
    selected_slots: &[usize],
    trusted_now: u64,
) -> Result<(ServicePresentation, SlotPresentation, f64, f64)> {
    let evidence_start = Instant::now();
    if !canonical_payment_request(preq) {
        return Err("non-canonical payment request".to_string());
    }
    if selected_slots.is_empty() {
        return Err("empty slot selection".to_string());
    }
    if selected_slots.iter().any(|k| *k >= holder.slot_count) {
        return Err("slot outside credential".to_string());
    }
    let rho = random_scalar();
    let mut link_secrets = BTreeMap::new();
    link_secrets.insert(
        CREDENTIAL_ID_NAME.to_string(),
        holder.messages[CREDENTIAL_ID_NAME],
    );
    let scope = scope_name(&q.class_name);
    link_secrets.insert(scope.clone(), holder.messages[&scope]);
    link_secrets.insert("link_rho".to_string(), rho);
    let bases = link_bases(&q.class_name);
    let l = g1_linear(bases.iter().map(|(name, base)| (base, link_secrets[name])));
    let (projection, request_projection, request_relation, request_secrets) =
        build_request_projection(q, preq, certificate);
    let projection_digest = commitment_digest("payment-projection", &projection.to_value());
    let request_commitment = g1_hex(&request_projection.commitment);
    let invocation_id = hex_encode(&hash_bytes(
        "mm-invocation",
        &[
            request_commitment.as_bytes().to_vec(),
            projection_digest.as_bytes().to_vec(),
            g1_hex(&l).into_bytes(),
            canonical_bytes(&certificate.body.to_value()),
        ],
    ));
    let issuer_hiding_session =
        derive_issuer_hidden_authorization(holder, verifier, &invocation_id)?;
    let issuer_hiding_authorization = issuer_hiding_session.authorization.clone();
    let issuer_hiding_evidence = issuer_hiding_evidence_value(&issuer_hiding_authorization);
    let service_context = json!({
        "role": "service",
        "credential_id": holder.credential_id,
        "session_id": holder.session_id,
        "L": g1_hex(&l),
        "I": invocation_id,
        "request_commitment": request_commitment,
        "projection_digest": projection_digest,
        "q": q.to_value(),
        "preq": preq.to_value(),
        "challenge": challenge.to_value(),
        "certificate_body": certificate.body.to_value(),
        "issuer_hiding_authorization_statement": issuer_hiding_authorization.proof_context_value(),
        "invocation_binding": issuer_hiding_authorization.invocation_binding,
    });
    let service_relation = vec![(bases.clone(), l)];
    let service_disclosed = vec![scope.clone(), EXPIRY_NAME.to_string()];
    let mut serials = BTreeMap::new();
    let mut funding_tags = BTreeMap::new();
    let serial_seed = serial_seed_name(&q.class_name);
    let fund_seed = fund_seed_name(&q.class_name);
    for k in selected_slots {
        serials.insert(*k, derive_slot_serial(holder.messages[&serial_seed], *k));
        funding_tags.insert(*k, derive_funding_tag(holder.messages[&fund_seed], *k));
    }
    let mut serials_json = Map::new();
    let mut funding_tags_json = Map::new();
    for k in selected_slots {
        serials_json.insert(k.to_string(), json!(g1_hex(&serials[k])));
        funding_tags_json.insert(k.to_string(), json!(g1_hex(&funding_tags[k])));
    }
    let slot_context = json!({
        "role": "redemption-bundle",
        "credential_id": holder.credential_id,
        "session_id": holder.session_id,
        "L": g1_hex(&l),
        "I": invocation_id,
        "request_commitment": request_commitment,
        "payment_projection": projection.to_value(),
        "projection_digest": projection_digest,
        "issuer_hiding_authorization_statement": issuer_hiding_authorization.proof_context_value(),
        "invocation_binding": issuer_hiding_authorization.invocation_binding,
        "serial_prf": "G1-H(slot)^s_slot[class]",
        "funding_tag_prf": "G1-H(funding-slot)^s_fund[class]",
        "serials": Value::Object(serials_json),
        "funding_tags": Value::Object(funding_tags_json),
    });
    let mut slot_disclosed = vec![BUDGET_NAME.to_string()];
    for k in selected_slots {
        slot_disclosed.push(slot_name(*k, "capacity"));
        slot_disclosed.push(slot_name(*k, "class"));
        slot_disclosed.push(slot_name(*k, "merchant"));
        slot_disclosed.push(slot_name(*k, "expiry"));
        slot_disclosed.push(slot_name(*k, "funding_eligible"));
    }
    let mut slot_relations = vec![
        (bases, l),
        funding_relation(&projection.funding_bucket),
        request_relation,
    ];
    let mut slot_link_secrets = link_secrets.clone();
    slot_link_secrets.extend(request_secrets);
    slot_link_secrets.insert(serial_seed.clone(), holder.messages[&serial_seed]);
    slot_link_secrets.insert(fund_seed.clone(), holder.messages[&fund_seed]);
    for k in selected_slots {
        slot_relations.push((
            BTreeMap::from([(serial_seed.clone(), slot_serial_base(*k))]),
            serials[k],
        ));
        slot_relations.push((
            BTreeMap::from([(fund_seed.clone(), slot_funding_base(*k))]),
            funding_tags[k],
        ));
    }
    let generate_service = || {
        ihbbs1::present_for_verified_holder(
            &issuer_hiding_session,
            &holder.credential,
            &holder.credential_commitment,
            &service_disclosed,
            &service_relation,
            &link_secrets,
            &service_context,
            "mm-service-presentation",
        )
    };
    let generate_slot = || {
        ihbbs1::present_for_verified_holder(
            &issuer_hiding_session,
            &holder.credential,
            &holder.credential_commitment,
            &slot_disclosed,
            &slot_relations,
            &slot_link_secrets,
            &slot_context,
            "mm-slot-presentation",
        )
    };
    // The role-specific proofs are independent.  Avoid thread creation when
    // the process is pinned to one CPU (the paper's measurement regime), while
    // retaining parallel generation when the deployment has multiple CPUs.
    let available_cpus = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let (service_pres, slot_pres) = if available_cpus > 1 {
        std::thread::scope(|scope| {
            let service_handle = scope.spawn(generate_service);
            let slot_handle = scope.spawn(generate_slot);
            let service_pres = service_handle
                .join()
                .map_err(|_| "service proof generation thread panicked".to_string())??;
            let slot_pres = slot_handle
                .join()
                .map_err(|_| "slot proof generation thread panicked".to_string())??;
            Ok::<_, String>((service_pres, slot_pres))
        })?
    } else {
        (generate_service()?, generate_slot()?)
    };
    let service_obj = ServicePresentation {
        presentation: service_pres,
        issuer_hiding_authorization: issuer_hiding_authorization.clone(),
        issuer_hiding_evidence: issuer_hiding_evidence.clone(),
        l,
        context: service_context,
        q: q.clone(),
        preq: preq.clone(),
        challenge: challenge.clone(),
        certificate: certificate.clone(),
    };
    let mut slot_obj = SlotPresentation {
        presentation: slot_pres,
        issuer_hiding_authorization,
        issuer_hiding_evidence,
        l,
        context: slot_context,
        selected_slots: selected_slots.to_vec(),
        serials,
        funding_tags,
        projection,
        request_projection,
        merchant_ack: None,
    };
    let merchant_digest = merchant_view_digest(&service_obj);
    let redemption_digest = redemption_view_digest(&slot_obj);
    let bind = one_call_bind(
        &service_obj,
        &slot_obj,
        &merchant_digest,
        &redemption_digest,
    )?;
    let evidence_create_ms = evidence_start.elapsed().as_secs_f64() * 1000.0;
    let (merchant_ack_result, merchant_verify_ms) = timed(|| {
        merchant_acknowledge_service(
            merchant,
            verifier,
            taxonomy_pk,
            &service_obj,
            &redemption_digest,
            &bind,
            trusted_now,
        )
    });
    let merchant_ack = merchant_ack_result?;
    slot_obj.merchant_ack = Some(merchant_ack);
    Ok((
        service_obj,
        slot_obj,
        evidence_create_ms,
        merchant_verify_ms,
    ))
}

fn derive_presentations(
    holder: &HolderState,
    verifier: &CredentialVerifier,
    taxonomy_pk: &G1,
    merchant: &Merchant,
    q: &Query,
    preq: &PaymentRequest,
    challenge: &Challenge,
    certificate: &Certificate,
    selected_slots: &[usize],
    trusted_now: u64,
) -> Result<(ServicePresentation, SlotPresentation)> {
    let (service, slot, _, _) = derive_presentations_with_merchant_timing(
        holder,
        verifier,
        taxonomy_pk,
        merchant,
        q,
        preq,
        challenge,
        certificate,
        selected_slots,
        trusted_now,
    )?;
    Ok((service, slot))
}

fn make_redeem_request(service: ServicePresentation, slot: SlotPresentation) -> RedeemRequest {
    let ack = slot
        .merchant_ack
        .clone()
        .expect("derived redemption statement has a merchant acknowledgement");
    let merchant_digest = merchant_view_digest(&service);
    let redemption_digest = redemption_view_digest(&slot);
    let bind = one_call_bind(&service, &slot, &merchant_digest, &redemption_digest)
        .expect("derived views agree on I, R, and L");
    RedeemRequest {
        service,
        slot,
        ack,
        merchant_digest,
        redemption_digest,
        bind,
    }
}

fn fresh_local_settlement_receipt(
    settlement_key: &SchnorrKey,
    req: &RedeemRequest,
    request_id: &str,
    serials: &[String],
    signed_budget: u64,
) -> Value {
    let serial_value = json!(serials);
    let acceptance_digest = hex_encode(&hash_bytes(
        DOMAIN_ACCEPT,
        &[
            req.slot.context["I"].as_str().unwrap().as_bytes().to_vec(),
            req.slot.context["request_commitment"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
            canonical_bytes(&req.slot.projection.to_value()),
            req.bind.as_bytes().to_vec(),
            canonical_bytes(&serial_value),
        ],
    ));
    let settlement_authorization = local_signed_record(
        settlement_key,
        DOMAIN_LOCAL_SETTLEMENT_AUTHORIZATION,
        json!({
            "credential_id": req.slot.context["credential_id"],
            "session_id": req.slot.context["session_id"],
            "acceptance_digest": acceptance_digest,
            "request_id": request_id,
            "dM": req.merchant_digest,
            "dR": req.redemption_digest,
            "Bind": req.bind,
            "payee": req.slot.projection.preq.payee,
            "asset": req.slot.projection.preq.asset,
            "amount": req.slot.projection.preq.amount,
            "mode": "local-ledger-no-funds",
            "real_payment_rail": false,
        }),
    );
    let authorization_digest = commitment_digest(
        DOMAIN_LOCAL_SETTLEMENT_AUTHORIZATION,
        &settlement_authorization,
    );
    let receipt_id = hex_encode(&hash_bytes(
        DOMAIN_LOCAL_RECEIPT_ID,
        &[
            request_id.as_bytes().to_vec(),
            acceptance_digest.as_bytes().to_vec(),
            authorization_digest.as_bytes().to_vec(),
        ],
    ));
    let signed_receipt = local_signed_record(
        settlement_key,
        DOMAIN_LOCAL_RECEIPT,
        json!({
            "credential_id": req.slot.context["credential_id"],
            "session_id": req.slot.context["session_id"],
            "receipt_id": receipt_id,
            "request_id": request_id,
            "acceptance_digest": acceptance_digest,
            "settlement_authorization_digest": authorization_digest,
            "dM": req.merchant_digest,
            "dR": req.redemption_digest,
            "Bind": req.bind,
            "amount": req.slot.projection.preq.amount,
            "budget": signed_budget,
        }),
    );
    json!({
        "operation": "AcceptAndConsume",
        "atomicity_scope": "prototype-local",
        "outcome": "fresh_accept",
        "fresh_execution_authorized": true,
        "settlement_authorization_issued": true,
        "serial_freshness_enforced": true,
        "idempotent_replay": false,
        "request_id": request_id,
        "receipt_id": receipt_id,
        "merchant_execution_key": request_id,
        "redemption": "accepted",
        "Bind": req.bind,
        "serial_count": serials.len(),
        "amount": req.slot.projection.preq.amount,
        "signed_budget": signed_budget,
        "settlement_mode": "local-ledger-no-funds",
        "real_payment_rail": false,
        "transaction_broadcast": false,
        "settlement_authorization": settlement_authorization,
        "signed_receipt": signed_receipt,
    })
}

impl RedemptionService {
    fn with_store(verifier: CredentialVerifier, taxonomy_pk: G1, spent: SpentStore) -> Self {
        let settlement_secret = random_scalar();
        Self {
            verifier,
            taxonomy_pk,
            settlement_key: SchnorrKey {
                sk: settlement_secret,
                pk: G1::generator() * settlement_secret,
            },
            spent,
        }
    }

    fn new_ephemeral(verifier: CredentialVerifier, taxonomy_pk: G1) -> Self {
        Self::with_store(verifier, taxonomy_pk, SpentStore::memory())
    }

    fn new_durable(verifier: CredentialVerifier, taxonomy_pk: G1, path: PathBuf) -> Self {
        Self::with_store(verifier, taxonomy_pk, SpentStore::durable(path))
    }

    fn slot_relations(&self, slot: &SlotPresentation) -> Option<Vec<G1Relation>> {
        let serial_seed = serial_seed_name(&slot.projection.class_name);
        let fund_seed = fund_seed_name(&slot.projection.class_name);
        let mut relations = vec![
            (link_bases(&slot.projection.class_name), slot.l),
            funding_relation(&slot.projection.funding_bucket),
        ];
        relations.push(request_projection_relation(
            &slot.projection,
            &slot.request_projection,
        )?);
        for k in &slot.selected_slots {
            relations.push((
                BTreeMap::from([(serial_seed.clone(), slot_serial_base(*k))]),
                slot.serials[k],
            ));
            relations.push((
                BTreeMap::from([(fund_seed.clone(), slot_funding_base(*k))]),
                slot.funding_tags[k],
            ));
        }
        Some(relations)
    }

    fn verify_combined_presentations(
        &self,
        req: &RedeemRequest,
        service_relations: &[G1Relation],
        invocation_id: &str,
        trusted_now: u64,
    ) -> std::result::Result<(), &'static str> {
        let Some(slot_relations) = self.slot_relations(&req.slot) else {
            return Err("slot-proof");
        };
        if !self.verifier.verify_authorization(trusted_now)
            || !ihbbs1::verify_authorization_with_verified_policy(
                &self.verifier.policy,
                &req.slot.issuer_hiding_authorization,
                invocation_id,
                trusted_now,
            )
        {
            return Err("issuer-authorization");
        }
        if !validate_paid_wire_boundary(
            &req.service.issuer_hiding_authorization,
            &req.service.presentation,
            &req.service.issuer_hiding_evidence,
        ) {
            return Err("wire-encoding");
        }
        if !validate_paid_wire_boundary(
            &req.slot.issuer_hiding_authorization,
            &req.slot.presentation,
            &req.slot.issuer_hiding_evidence,
        ) {
            return Err("wire-encoding");
        }
        let service_terms = ihbbs1::proof_pairing_terms_for_verified_authorization(
            &self.verifier.public_params,
            &req.service.issuer_hiding_authorization,
            &req.service.presentation,
            service_relations,
            &req.service.context,
            "mm-service-presentation",
        )
        .ok_or("service-proof")?;
        let slot_terms = ihbbs1::proof_pairing_terms_for_verified_authorization(
            &self.verifier.public_params,
            &req.slot.issuer_hiding_authorization,
            &req.slot.presentation,
            &slot_relations,
            &req.slot.context,
            "mm-slot-presentation",
        )
        .ok_or("slot-proof")?;

        // Fiat--Shamir weights prevent cross-equation cancellation when the
        // two independent BBS equations share one final exponentiation.
        let batch_transcript = canonical_bytes(&json!({
            "service": req.service.presentation.to_value(),
            "slot": req.slot.presentation.to_value(),
            "I": invocation_id,
            "Bind": req.bind,
        }));
        let candidate = hash_to_scalar("mm-wallet-proof-batch-v1", &[batch_transcript]);
        let slot_weight = if candidate == Scalar::ZERO {
            Scalar::ONE
        } else {
            candidate
        };
        let batched_terms = service_terms
            .iter()
            .copied()
            .chain(slot_terms.iter().map(|(g2, g1)| (*g2, *g1 * slot_weight)))
            .collect::<Vec<_>>();
        if multi_pairing_check(&batched_terms) {
            return Ok(());
        }
        // Invalid paths retain the original fail-closed reason taxonomy.
        if !multi_pairing_check(&service_terms) {
            return Err("service-proof");
        }
        if !multi_pairing_check(&slot_terms) {
            return Err("slot-proof");
        }
        Err("proof-batch")
    }

    fn precheck_spend_fields(
        &self,
        req: &RedeemRequest,
        trusted_now: u64,
    ) -> std::result::Result<(Vec<String>, u64), &'static str> {
        let mut expected = Map::new();
        for k in &req.slot.selected_slots {
            expected.insert(k.to_string(), json!(g1_hex(&req.slot.serials[k])));
        }
        if req.slot.context.get("serials") != Some(&Value::Object(expected)) {
            return Err("serial");
        }
        let mut expected_funding = Map::new();
        for k in &req.slot.selected_slots {
            expected_funding.insert(k.to_string(), json!(g1_hex(&req.slot.funding_tags[k])));
        }
        if req.slot.context.get("funding_tags") != Some(&Value::Object(expected_funding)) {
            return Err("funding-tag");
        }
        let mut serial_keys = Vec::new();
        let mut funding_keys = Vec::new();
        verify_signed_slot_coordinates(
            &req.slot.presentation,
            &req.slot.selected_slots,
            &req.slot.projection.class_name,
            &req.slot.projection.merchant,
            req.slot.projection.preq.amount,
            trusted_now,
        )?;
        let signed_budget = req
            .slot
            .presentation
            .disclosed_messages
            .get(BUDGET_NAME)
            .and_then(scalar_to_u64)
            .ok_or("budget")?;
        if signed_budget == 0 {
            return Err("budget");
        }
        for k in &req.slot.selected_slots {
            serial_keys.push(point_digest(&req.slot.serials[k]));
            funding_keys.push(point_digest(&req.slot.funding_tags[k]));
        }
        let unique = serial_keys.iter().collect::<BTreeSet<_>>();
        if unique.len() != serial_keys.len() {
            return Err("double-spend");
        }
        let unique_funding = funding_keys.iter().collect::<BTreeSet<_>>();
        if unique_funding.len() != funding_keys.len() {
            return Err("funding-tag");
        }
        Ok((serial_keys, signed_budget))
    }

    fn accept_and_consume(&mut self, req: &RedeemRequest, trusted_now: u64) -> (bool, Value) {
        self.accept_and_consume_with_policy(req, trusted_now, true, true)
    }

    fn accept_and_consume_with_policy(
        &mut self,
        req: &RedeemRequest,
        trusted_now: u64,
        enforce_bind: bool,
        enforce_serial_freshness: bool,
    ) -> (bool, Value) {
        match self.verify_redemption_request(req, trusted_now, enforce_bind) {
            Ok((serials, signed_budget)) => self.consume_verified_redemption(
                req,
                serials,
                signed_budget,
                enforce_serial_freshness,
            ),
            Err(reason) => Self::reject_redemption(reason),
        }
    }

    fn reject_redemption(reason: &str) -> (bool, Value) {
        (
            false,
            json!({
                "outcome": "rejected",
                "fresh_execution_authorized": false,
                "settlement_authorization_issued": false,
                "reason": reason,
            }),
        )
    }

    fn verify_redemption_request(
        &self,
        req: &RedeemRequest,
        trusted_now: u64,
        enforce_bind: bool,
    ) -> std::result::Result<(Vec<String>, u64), &'static str> {
        if req.slot.context.get("I").and_then(Value::as_str).is_none() {
            return Err("issuer-authorization");
        }
        let invocation_id = req.slot.context["I"].as_str().unwrap();
        if merchant_view_digest(&req.service) != req.merchant_digest
            || redemption_view_digest(&req.slot) != req.redemption_digest
        {
            return Err("view-digest");
        }
        let Ok(expected_bind) = one_call_bind(
            &req.service,
            &req.slot,
            &req.merchant_digest,
            &req.redemption_digest,
        ) else {
            return Err("cross-view");
        };
        if enforce_bind && expected_bind != req.bind {
            return Err("bind");
        }
        let (service_invocation_id, service_relations) =
            service_presentation_relations(&self.taxonomy_pk, &req.service, trusted_now)?;
        if service_invocation_id != invocation_id {
            return Err("cross-view");
        }
        if req.service.context.get("I") != req.slot.context.get("I")
            || req.service.context.get("request_commitment")
                != req.slot.context.get("request_commitment")
            || req.service.context.get("L") != req.slot.context.get("L")
            || req.service.q.merchant != req.slot.projection.merchant
            || req.service.q.merchant_pk != req.slot.projection.merchant_pk
            || req.service.q.class_name != req.slot.projection.class_name
            || req.service.issuer_hiding_authorization.statement_value()
                != req.slot.issuer_hiding_authorization.statement_value()
            || req.service.issuer_hiding_authorization.invocation_binding
                != req.slot.issuer_hiding_authorization.invocation_binding
        {
            return Err("cross-view");
        }
        let expected_ack_body = json!({
            "profile": "MM-merchant-ack-v1",
            "I": req.slot.context["I"],
            "R": req.slot.context["request_commitment"],
            "L": req.slot.context["L"],
            "dM": req.merchant_digest,
            "dR": req.redemption_digest,
            "Bind": req.bind,
        });
        if req.ack.body != expected_ack_body {
            return Err("ack");
        }
        if !req
            .ack
            .signature
            .verify(&req.slot.projection.merchant_pk, &req.ack.body)
        {
            return Err("ack");
        }
        if !eval_redemption_projection(&req.slot.projection, &self.taxonomy_pk, trusted_now) {
            return Err("projection");
        }
        if request_projection_relation(&req.slot.projection, &req.slot.request_projection).is_none()
        {
            return Err("request-projection");
        }
        let (serials, signed_budget) = match self.precheck_spend_fields(req, trusted_now) {
            Ok(fields) => fields,
            Err(reason) => return Err(reason),
        };
        self.verify_combined_presentations(req, &service_relations, invocation_id, trusted_now)?;
        Ok((serials, signed_budget))
    }

    fn consume_verified_redemption(
        &mut self,
        req: &RedeemRequest,
        serials: Vec<String>,
        signed_budget: u64,
        enforce_serial_freshness: bool,
    ) -> (bool, Value) {
        let request_id = hex_encode(&hash_bytes(
            "mm-accept-and-consume-request",
            &[canonical_bytes(&req.to_value())],
        ));
        if enforce_serial_freshness {
            let settlement_key = self.settlement_key.clone();
            match self.spent.accept_and_consume(
                &request_id,
                &serials,
                signed_budget,
                req.slot.projection.preq.amount,
                || {
                    fresh_local_settlement_receipt(
                        &settlement_key,
                        req,
                        &request_id,
                        &serials,
                        signed_budget,
                    )
                },
            ) {
                Ok(ConsumeOutcome::Accepted(receipt)) => (true, receipt),
                Ok(ConsumeOutcome::Idempotent(mut receipt)) => {
                    if let Some(object) = receipt.as_object_mut() {
                        object.insert("outcome".to_string(), json!("idempotent_receipt"));
                        object.insert("fresh_execution_authorized".to_string(), json!(false));
                        object.insert("settlement_authorization_issued".to_string(), json!(false));
                        object.insert("idempotent_replay".to_string(), json!(true));
                    }
                    (false, receipt)
                }
                Ok(ConsumeOutcome::Conflict) => Self::reject_redemption("double-spend"),
                Ok(ConsumeOutcome::BudgetExceeded) => Self::reject_redemption("budget"),
                Ok(ConsumeOutcome::BudgetMismatch) => Self::reject_redemption("budget-reserve"),
                Err(error) => (
                    false,
                    json!({
                        "outcome": "rejected",
                        "fresh_execution_authorized": false,
                        "settlement_authorization_issued": false,
                        "reason": "spent-store",
                        "detail": error,
                    }),
                ),
            }
        } else {
            let mut receipt = fresh_local_settlement_receipt(
                &self.settlement_key,
                req,
                &request_id,
                &serials,
                signed_budget,
            );
            if let Some(object) = receipt.as_object_mut() {
                object.insert("serial_freshness_enforced".to_string(), json!(false));
            }
            (true, receipt)
        }
    }

    // Compatibility wrappers for development-only callers. Final-v2 uses the
    // explicit atomic transition above.
    fn redeem(&mut self, req: &RedeemRequest, trusted_now: u64) -> (bool, Value) {
        self.accept_and_consume(req, trusted_now)
    }

    fn redeem_with_policy(
        &mut self,
        req: &RedeemRequest,
        trusted_now: u64,
        enforce_bind: bool,
        enforce_serial_freshness: bool,
    ) -> (bool, Value) {
        self.accept_and_consume_with_policy(
            req,
            trusted_now,
            enforce_bind,
            enforce_serial_freshness,
        )
    }
}

fn scalar_to_u64(s: &Scalar) -> Option<u64> {
    let repr = s.to_repr();
    let bytes = repr.as_ref();
    if bytes[8..].iter().any(|b| *b != 0) {
        return None;
    }
    let mut low = [0u8; 8];
    low.copy_from_slice(&bytes[..8]);
    Some(u64::from_le_bytes(low))
}

fn json_size(value: &Value) -> usize {
    canonical_bytes(value).len()
}

fn corrupt_presentation_response(presentation: &mut BbsPresentation) -> Result<()> {
    let name = presentation
        .proof
        .responses
        .keys()
        .next()
        .cloned()
        .ok_or_else(|| "cannot corrupt an empty proof response set".to_string())?;
    let response = presentation.proof.responses[&name];
    presentation
        .proof
        .responses
        .insert(name, response + Scalar::ONE);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BenchAblationVariant {
    DirectRawCapability,
    BbsOnly,
    Serials,
    OneCallBinding,
    Full,
}

impl BenchAblationVariant {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "direct_raw_capability" => Ok(Self::DirectRawCapability),
            "bbs_only" => Ok(Self::BbsOnly),
            "serials" => Ok(Self::Serials),
            "one_call_binding" => Ok(Self::OneCallBinding),
            "full" => Ok(Self::Full),
            other => Err(format!("unknown experiment_variant: {other}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::DirectRawCapability => "direct_raw_capability",
            Self::BbsOnly => "bbs_only",
            Self::Serials => "serials",
            Self::OneCallBinding => "one_call_binding",
            Self::Full => "full",
        }
    }

    fn enforce_serial_freshness(self) -> bool {
        matches!(self, Self::Serials | Self::OneCallBinding | Self::Full)
    }

    fn enforce_bind(self) -> bool {
        matches!(self, Self::OneCallBinding | Self::Full)
    }

    fn hide_issuer(self) -> bool {
        matches!(self, Self::Full)
    }

    fn expose_raw_capability(self) -> bool {
        matches!(self, Self::DirectRawCapability)
    }
}

struct BenchWorkflowSession {
    holder: HolderState,
    wallet: WalletRuntime,
    taxonomy: TaxonomyAuthority,
    issue_ms: f64,
    variant: BenchAblationVariant,
    issuer_handle: String,
    raw_capability_handle: String,
    credential_id: String,
    session_id: String,
    approval_workflow_id: String,
    approval_sequence: u64,
    amendments_remaining: u64,
    approval_public_key_sha256: String,
    settlement_verification: Value,
}

#[derive(Clone)]
struct JsonlCacheEntry {
    request_digest: String,
    response: Value,
}

struct JsonlState {
    sessions: HashMap<String, BenchWorkflowSession>,
    idempotency: HashMap<(String, String), JsonlCacheEntry>,
    credential_tombstones: BTreeSet<String>,
    session_tombstones: BTreeSet<String>,
    settlement_trust_key: SchnorrKey,
    network_boundary_attestation: Value,
}

impl JsonlState {
    fn new(network_boundary_attestation: Value) -> Self {
        Self {
            sessions: HashMap::new(),
            idempotency: HashMap::new(),
            credential_tombstones: BTreeSet::new(),
            session_tombstones: BTreeSet::new(),
            settlement_trust_key: SchnorrKey::new(),
            network_boundary_attestation,
        }
    }

    fn settlement_trust_anchor(&self) -> Value {
        let key_bytes = wire::encode_g1(&self.settlement_trust_key.pk);
        json!({
            "scheme": "schnorr-bls12-381-sha256-v1",
            "verification_key": g1_hex(&self.settlement_trust_key.pk),
            "verification_key_sha256": sha256_plain_hex(&key_bytes),
        })
    }
}

#[derive(Clone)]
struct VerifiedApprovalSlot {
    service_class: String,
    merchant_id: String,
    capacity: u64,
    expiry: u64,
    funding_eligible: bool,
}

struct VerifiedUserApproval {
    artifact_sha256: String,
    workflow_id: String,
    approval_kind: String,
    approval_sequence: u64,
    parent_approval_sha256: Option<String>,
    slots: Vec<VerifiedApprovalSlot>,
    base_budget: u64,
    reserve_budget: u64,
    approved_budget: u64,
    allowed_service_classes: Vec<String>,
    allowed_merchants: Vec<String>,
    funding_coverage: u64,
    amendment_limit: u64,
    settlement_policy: Value,
    signer_public_key_sha256: String,
}

fn exact_object<'a>(
    value: &'a Value,
    keys: &[&str],
    label: &str,
) -> Result<&'a Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = keys.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "{label} fields differ: expected={expected:?} actual={actual:?}"
        ));
    }
    Ok(object)
}

fn strict_string(value: &Value, label: &str) -> Result<String> {
    let string = value
        .as_str()
        .ok_or_else(|| format!("{label} must be a string"))?;
    if string.is_empty() {
        return Err(format!("{label} must be non-empty"));
    }
    Ok(string.to_string())
}

fn strict_u64(value: &Value, label: &str) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| format!("{label} must be a non-negative integer"))
}

fn strict_positive_u64(value: &Value, label: &str) -> Result<u64> {
    let number = strict_u64(value, label)?;
    if number == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(number)
}

fn strict_string_array(value: &Value, label: &str) -> Result<Vec<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| format!("{label} must be an array"))?;
    array
        .iter()
        .enumerate()
        .map(|(index, item)| strict_string(item, &format!("{label}[{index}]")))
        .collect()
}

fn require_sorted_unique(values: &[String], label: &str) -> Result<()> {
    let mut canonical = values.to_vec();
    canonical.sort();
    canonical.dedup();
    if canonical != values {
        return Err(format!("{label} must be sorted and unique"));
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_user_approval_artifact(request: &Value) -> Result<VerifiedUserApproval> {
    let artifact_value = request
        .get("user_approval_artifact")
        .ok_or("begin_workflow requires user_approval_artifact")?;
    let artifact = exact_object(
        artifact_value,
        &[
            "schema_version",
            "workflow_id",
            "approval_kind",
            "approval_sequence",
            "parent_approval_sha256",
            "decision",
            "ordered_slots",
            "budget",
            "allowed_service_classes",
            "allowed_merchants",
            "funding_eligibility",
            "amendment_limit",
            "settlement_authorization",
            "approval_evidence",
            "canonical_input_sha256",
            "signature",
            "artifact_sha256",
        ],
        "user_approval_artifact",
    )?;
    if artifact["schema_version"] != json!("minmandate-user-approval-v1")
        || artifact["decision"] != json!("approve")
    {
        return Err("approval artifact does not explicitly approve this workflow".to_string());
    }

    let canonical_input = json!({
        "schema_version": artifact["schema_version"].clone(),
        "workflow_id": artifact["workflow_id"].clone(),
        "approval_kind": artifact["approval_kind"].clone(),
        "approval_sequence": artifact["approval_sequence"].clone(),
        "parent_approval_sha256": artifact["parent_approval_sha256"].clone(),
        "decision": artifact["decision"].clone(),
        "ordered_slots": artifact["ordered_slots"].clone(),
        "budget": artifact["budget"].clone(),
        "allowed_service_classes": artifact["allowed_service_classes"].clone(),
        "allowed_merchants": artifact["allowed_merchants"].clone(),
        "funding_eligibility": artifact["funding_eligibility"].clone(),
        "amendment_limit": artifact["amendment_limit"].clone(),
        "settlement_authorization": artifact["settlement_authorization"].clone(),
        "approval_evidence": artifact["approval_evidence"].clone(),
    });
    let canonical_input_bytes = canonical_ascii_bytes(&canonical_input);
    let canonical_input_sha256 = strict_string(
        &artifact["canonical_input_sha256"],
        "approval canonical_input_sha256",
    )?;
    if !is_sha256_hex(&canonical_input_sha256)
        || sha256_plain_hex(&canonical_input_bytes) != canonical_input_sha256
    {
        return Err("approval canonical input digest mismatch".to_string());
    }

    let signature_text = strict_string(&artifact["signature"], "approval signature")?;
    let mut unsigned = canonical_input
        .as_object()
        .expect("canonical approval input is an object")
        .clone();
    unsigned.insert(
        "canonical_input_sha256".to_string(),
        json!(canonical_input_sha256),
    );
    unsigned.insert("signature".to_string(), json!(signature_text));
    let artifact_sha256 = sha256_plain_hex(&canonical_ascii_bytes(&Value::Object(unsigned)));
    let claimed_artifact_sha256 =
        strict_string(&artifact["artifact_sha256"], "approval artifact_sha256")?;
    let outer_artifact_sha256 = value_string(request, "user_approval_artifact_sha256")?;
    if !is_sha256_hex(&claimed_artifact_sha256)
        || claimed_artifact_sha256 != artifact_sha256
        || outer_artifact_sha256 != artifact_sha256
    {
        return Err("approval artifact digest mismatch".to_string());
    }

    let evidence = exact_object(
        &artifact["approval_evidence"],
        &[
            "evidence_class",
            "signer_id",
            "evidence_locator",
            "frozen_evidence_sha256",
            "signature_scheme",
            "signer_public_key_b64",
        ],
        "approval_evidence",
    )?;
    strict_string(&evidence["evidence_class"], "approval evidence_class")?;
    strict_string(&evidence["signer_id"], "approval signer_id")?;
    strict_string(&evidence["evidence_locator"], "approval evidence_locator")?;
    let frozen_evidence_sha256 = strict_string(
        &evidence["frozen_evidence_sha256"],
        "approval frozen_evidence_sha256",
    )?;
    if !is_sha256_hex(&frozen_evidence_sha256)
        || evidence["signature_scheme"] != json!("ed25519-v1")
    {
        return Err("approval evidence is not frozen Ed25519 evidence".to_string());
    }
    let public_key_text = strict_string(
        &evidence["signer_public_key_b64"],
        "approval signer_public_key_b64",
    )?;
    let public_key = wire::base64_decode(&public_key_text)?;
    let signature = wire::base64_decode(&signature_text)?;
    if !verify_ed25519(&public_key, &signature, &canonical_input_bytes) {
        return Err("approval Ed25519 signature verification failed".to_string());
    }

    let ordered_slots = artifact["ordered_slots"]
        .as_array()
        .ok_or("approval ordered_slots must be an array")?;
    if ordered_slots.is_empty() {
        return Err("approval ordered_slots must be non-empty".to_string());
    }
    let mut slots = Vec::with_capacity(ordered_slots.len());
    for (index, slot_value) in ordered_slots.iter().enumerate() {
        let slot = exact_object(
            slot_value,
            &["service_class", "merchant_id", "capacity", "expiry"],
            &format!("approval ordered_slots[{index}]"),
        )?;
        slots.push(VerifiedApprovalSlot {
            service_class: strict_string(
                &slot["service_class"],
                &format!("approval ordered_slots[{index}].service_class"),
            )?,
            merchant_id: strict_string(
                &slot["merchant_id"],
                &format!("approval ordered_slots[{index}].merchant_id"),
            )?,
            capacity: strict_positive_u64(
                &slot["capacity"],
                &format!("approval ordered_slots[{index}].capacity"),
            )?,
            expiry: strict_positive_u64(
                &slot["expiry"],
                &format!("approval ordered_slots[{index}].expiry"),
            )?,
            funding_eligible: false,
        });
    }

    let budget = exact_object(
        &artifact["budget"],
        &["base", "reserve", "approved_total"],
        "approval budget",
    )?;
    let base_budget = strict_u64(&budget["base"], "approval budget.base")?;
    let reserve_budget = strict_u64(&budget["reserve"], "approval budget.reserve")?;
    let approved_budget =
        strict_positive_u64(&budget["approved_total"], "approval budget.approved_total")?;
    if base_budget.checked_add(reserve_budget) != Some(approved_budget) {
        return Err("approval base and reserve do not equal approved budget".to_string());
    }

    let allowed_service_classes = strict_string_array(
        &artifact["allowed_service_classes"],
        "approval allowed_service_classes",
    )?;
    let allowed_merchants =
        strict_string_array(&artifact["allowed_merchants"], "approval allowed_merchants")?;
    require_sorted_unique(&allowed_service_classes, "approval allowed_service_classes")?;
    require_sorted_unique(&allowed_merchants, "approval allowed_merchants")?;
    let mut derived_classes = slots
        .iter()
        .map(|slot| slot.service_class.clone())
        .collect::<Vec<_>>();
    derived_classes.sort();
    derived_classes.dedup();
    let mut derived_merchants = slots
        .iter()
        .map(|slot| slot.merchant_id.clone())
        .collect::<Vec<_>>();
    derived_merchants.sort();
    derived_merchants.dedup();
    if allowed_service_classes != derived_classes || allowed_merchants != derived_merchants {
        return Err("approval classes or merchants differ from its ordered slots".to_string());
    }

    let funding = exact_object(
        &artifact["funding_eligibility"],
        &["eligible_slot_indices", "coverage"],
        "approval funding_eligibility",
    )?;
    let eligible_values = funding["eligible_slot_indices"]
        .as_array()
        .ok_or("approval eligible_slot_indices must be an array")?;
    let mut eligible_indices = Vec::with_capacity(eligible_values.len());
    for (index, value) in eligible_values.iter().enumerate() {
        let eligible = strict_u64(value, &format!("approval eligible_slot_indices[{index}]"))?;
        let eligible = usize::try_from(eligible)
            .map_err(|_| "approval eligible slot index does not fit usize".to_string())?;
        if eligible >= slots.len() {
            return Err("approval funding-eligible slot index is out of range".to_string());
        }
        eligible_indices.push(eligible);
    }
    if !eligible_indices.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err("approval eligible_slot_indices must be sorted and unique".to_string());
    }
    for index in eligible_indices {
        slots[index].funding_eligible = true;
    }
    let funding_coverage = strict_u64(&funding["coverage"], "approval funding coverage")?;
    if funding_coverage < approved_budget {
        return Err("approval funding coverage is below the approved budget".to_string());
    }

    let amendment_limit = strict_u64(&artifact["amendment_limit"], "approval amendment_limit")?;
    if amendment_limit > 1 {
        return Err("approval amendment_limit exceeds one".to_string());
    }
    let settlement_policy = artifact["settlement_authorization"].clone();
    exact_object(
        &settlement_policy,
        &["authorized", "mode"],
        "approval settlement_authorization",
    )?;
    if settlement_policy != json!({"authorized": false, "mode": "none_local_experiment"}) {
        return Err("approval settlement policy is not local no-settlement".to_string());
    }

    let workflow_id = strict_string(&artifact["workflow_id"], "approval workflow_id")?;
    let approval_kind = strict_string(&artifact["approval_kind"], "approval approval_kind")?;
    let approval_sequence =
        strict_u64(&artifact["approval_sequence"], "approval approval_sequence")?;
    let parent_approval_sha256 = match &artifact["parent_approval_sha256"] {
        Value::Null => None,
        value => {
            let digest = strict_string(value, "approval parent_approval_sha256")?;
            if !is_sha256_hex(&digest) {
                return Err("approval parent digest is malformed".to_string());
            }
            Some(digest)
        }
    };
    match approval_kind.as_str() {
        "initial" if approval_sequence == 0 && parent_approval_sha256.is_none() => {}
        "amendment" if approval_sequence > 0 && parent_approval_sha256.is_some() => {}
        _ => return Err("approval kind, sequence, and parent are inconsistent".to_string()),
    }

    let request_slots = request
        .get("slots")
        .and_then(Value::as_array)
        .ok_or("begin_workflow requires a slots array")?;
    if request_slots.len() != slots.len() {
        return Err("request and approval ordered slot counts differ".to_string());
    }
    for (index, (request_slot_value, approved_slot)) in
        request_slots.iter().zip(slots.iter()).enumerate()
    {
        let request_slot = exact_object(
            request_slot_value,
            &[
                "service_class",
                "merchant_id",
                "capacity",
                "expiry",
                "funding_eligible",
            ],
            &format!("request slots[{index}]"),
        )?;
        let funding_eligible = request_slot["funding_eligible"]
            .as_bool()
            .ok_or_else(|| format!("request slots[{index}].funding_eligible must be boolean"))?;
        if strict_string(&request_slot["service_class"], "request slot class")?
            != approved_slot.service_class
            || strict_string(&request_slot["merchant_id"], "request slot merchant")?
                != approved_slot.merchant_id
            || strict_positive_u64(&request_slot["capacity"], "request slot capacity")?
                != approved_slot.capacity
            || strict_positive_u64(&request_slot["expiry"], "request slot expiry")?
                != approved_slot.expiry
            || funding_eligible != approved_slot.funding_eligible
        {
            return Err(format!(
                "request slots[{index}] differs from the signed approval"
            ));
        }
    }
    if request.get("budget") != Some(&artifact["budget"])
        || value_u64(request, "approved_budget")? != approved_budget
        || value_u64(request, "funding_reserve")? != reserve_budget
        || request.get("funding") != Some(&artifact["funding_eligibility"])
        || request.get("allowed_service_classes") != Some(&artifact["allowed_service_classes"])
        || request.get("allowed_merchants") != Some(&artifact["allowed_merchants"])
        || value_u64(request, "amendment_limit")? != amendment_limit
        || request.get("settlement_authorization") != Some(&settlement_policy)
    {
        return Err("request policy fields differ from the signed approval".to_string());
    }
    strict_string(
        request.get("task").ok_or("begin_workflow requires task")?,
        "begin_workflow task",
    )?;

    Ok(VerifiedUserApproval {
        artifact_sha256,
        workflow_id,
        approval_kind,
        approval_sequence,
        parent_approval_sha256,
        slots,
        base_budget,
        reserve_budget,
        approved_budget,
        allowed_service_classes,
        allowed_merchants,
        funding_coverage,
        amendment_limit,
        settlement_policy,
        signer_public_key_sha256: sha256_plain_hex(&public_key),
    })
}

fn add_jsonl_state_fields(value: &mut Value, state: &JsonlState) {
    if let Value::Object(map) = value {
        map.insert(
            "network_boundary_attestation".to_string(),
            state.network_boundary_attestation.clone(),
        );
        map.insert(
            "settlement_trust_anchor".to_string(),
            state.settlement_trust_anchor(),
        );
    }
}

fn wallet_local_audit_value(
    wallet: &WalletRuntime,
    policy: &policy_io::LoadedIssuerPolicy,
) -> Value {
    let selected_key = wire::encode_g2(&wallet.issuance.issuer_pk.x_tilde);
    json!({
        "schema_version": "minmandate-wallet-local-audit-v1",
        "evidence_scope": "wallet_local_private_audit",
        "epoch_id": policy.metadata["epoch_id"],
        "policy_digest_sha256": policy.metadata["policy_digest_sha256"],
        "policy_size": policy.metadata["policy_size"],
        "assignment_algorithm": policy_io::ASSIGNMENT_ALGORITHM,
        "key_material_profile": ihbbs1::DETERMINISTIC_TEST_KEY_PROFILE,
        "external_view_exported": false,
        "wallet_id": wallet.wallet_entity_id,
        "selected_issuer_index": wallet.selected_issuer_index,
        "selected_issuer_public_key_sha256": policy_io::sha256_hex(&selected_key),
    })
}

fn prepare_jsonl_workflow(
    request: &Value,
    workflow_id: &str,
    expected_approval_workflow_id: &str,
    expected_kind: &str,
    expected_sequence: u64,
    expected_parent: Option<&str>,
    lineage_remaining_after_issue: Option<u64>,
    state: &JsonlState,
    policy: &policy_io::LoadedIssuerPolicy,
) -> Result<(BenchWorkflowSession, Value)> {
    let approval = verify_user_approval_artifact(request)?;
    if approval.workflow_id != expected_approval_workflow_id
        || approval.approval_kind != expected_kind
        || approval.approval_sequence != expected_sequence
        || approval.parent_approval_sha256.as_deref() != expected_parent
    {
        return Err(
            "approval lineage does not match the requested workflow transition".to_string(),
        );
    }
    let amendments_remaining = match lineage_remaining_after_issue {
        Some(remaining) => {
            if approval.amendment_limit > remaining {
                return Err("replacement approval widens the parent amendment limit".to_string());
            }
            remaining
        }
        None => approval.amendment_limit,
    };
    if state
        .credential_tombstones
        .contains(&approval.artifact_sha256)
        || state
            .sessions
            .values()
            .any(|session| session.credential_id == approval.artifact_sha256)
    {
        return Err("approval credential is already active or tombstoned".to_string());
    }

    let capacities = approval
        .slots
        .iter()
        .map(|slot| slot.capacity)
        .collect::<Vec<_>>();
    let slot_classes = approval
        .slots
        .iter()
        .map(|slot| slot.service_class.clone())
        .collect::<Vec<_>>();
    let slot_merchants = approval
        .slots
        .iter()
        .map(|slot| slot.merchant_id.clone())
        .collect::<Vec<_>>();
    let slot_expiries = approval
        .slots
        .iter()
        .map(|slot| slot.expiry)
        .collect::<Vec<_>>();
    let slot_funding_eligibility = approval
        .slots
        .iter()
        .map(|slot| slot.funding_eligible)
        .collect::<Vec<_>>();
    let task_goal = request
        .get("task")
        .and_then(Value::as_str)
        .ok_or("begin_workflow requires a non-empty task")?;
    let variant = BenchAblationVariant::parse(
        request
            .get("experiment_variant")
            .and_then(Value::as_str)
            .unwrap_or("full"),
    )?;
    let requested_wallet_entity_id = match request.get("wallet_id") {
        None => None,
        Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
        Some(_) => return Err("wallet_id must be a non-empty string".to_string()),
    };
    let (user, wallet, taxonomy) = build_system_with_policy(
        approval.slots.len(),
        &approval.allowed_service_classes,
        requested_wallet_entity_id,
        Some(policy),
    )?;
    {
        let mut funding = wallet
            .funding
            .lock()
            .map_err(|_| "wallet funding state is poisoned".to_string())?;
        funding.configured = true;
        funding.eligible = true;
        funding.available = approval.funding_coverage;
        funding.reserved = 0;
    }
    let (holder_result, issue_ms) = timed(|| {
        issue_task_credential_with_goal_and_expiries_bound(
            &user,
            &wallet,
            &approval.allowed_service_classes,
            &capacities,
            &slot_classes,
            &slot_merchants,
            &slot_expiries,
            approval.approved_budget,
            task_goal,
            &slot_funding_eligibility,
            Some(&approval.artifact_sha256),
        )
    });
    let (holder, issue_meta) = holder_result?;
    let (holder_validation_result, holder_validation_ms) = timed(|| {
        ihbbs1::verify_holder_credential_for_verified_policy(
            &wallet.issuance.verifier.public_params,
            &wallet.issuance.verifier.policy,
            &holder.issuer_hiding,
            &holder.credential,
        )
    });
    holder_validation_result?;
    let issue_ms = issue_ms + holder_validation_ms;
    let holder_credential_verify_ms = issue_meta["setup_stage_timings_ms"]["holder_policy_prepare"]
        .as_f64()
        .unwrap_or(0.0)
        + holder_validation_ms;
    if holder.credential_id != approval.artifact_sha256
        || holder.session_id != approval.artifact_sha256
    {
        return Err("issued credential lost its approval binding".to_string());
    }
    let issuer_handle = credential_key_digest(&wallet.issuance.issuer_pk);
    let raw_capability_handle = commitment_digest(
        "ablation-raw-capability",
        &holder.credential.signature.to_value(),
    );
    let wallet_local_audit = wallet_local_audit_value(&wallet, policy);
    let settlement_key_bytes = wire::encode_g1(&wallet.redemption.settlement_key.pk);
    let settlement_key_sha256 = sha256_plain_hex(&settlement_key_bytes);
    let key_attestation = local_signed_record(
        &state.settlement_trust_key,
        DOMAIN_SETTLEMENT_KEY_ATTESTATION,
        json!({
            "credential_id": approval.artifact_sha256,
            "session_id": approval.artifact_sha256,
            "workflow_id": workflow_id,
            "issuer_policy_digest_sha256": policy.metadata["policy_digest_sha256"],
            "settlement_verification_key": g1_hex(&wallet.redemption.settlement_key.pk),
            "settlement_verification_key_sha256": settlement_key_sha256,
        }),
    );
    let settlement_verification = json!({
        "scheme": "schnorr-bls12-381-sha256-v1",
        "verification_key": g1_hex(&wallet.redemption.settlement_key.pk),
        "verification_key_sha256": settlement_key_sha256,
        "trust_anchor": state.settlement_trust_anchor(),
        "key_attestation": key_attestation.clone(),
        "key_attestation_sha256": sha256_plain_hex(&canonical_ascii_bytes(&key_attestation)),
    });
    let response = json!({
        "ok": true,
        "accepted": true,
        "status": "fresh_credential",
        "operation": "begin_workflow",
        "protocol_version": PROTOCOL_VERSION,
        "wire_schema_version": WIRE_SCHEMA_VERSION,
        "workflow_id": workflow_id,
        "credential_id": approval.artifact_sha256,
        "session_id": approval.artifact_sha256,
        "approval_digest_sha256": approval.artifact_sha256,
        "approval_public_key_sha256": approval.signer_public_key_sha256,
        "approval_sequence": approval.approval_sequence,
        "amendments_remaining": amendments_remaining,
        "slot_count": approval.slots.len(),
        "approved_budget": approval.approved_budget,
        "funding_coverage": approval.funding_coverage,
        "funding_reserve": issue_meta["funding_reserve"].clone(),
        "issuance_mode": issue_meta["issuance_mode"].clone(),
        "issuer_visible_message_names": issue_meta["issuer_visible_message_names"].clone(),
        "settlement_policy": approval.settlement_policy,
        "settlement_verification": settlement_verification,
        "issue_ms": issue_ms,
        "setup_stage_timings_ms": {
            "budget_reservation": issue_meta["setup_stage_timings_ms"]["budget_reservation"],
            "issuer_sign": issue_meta["setup_stage_timings_ms"]["issuer_sign"],
            "holder_credential_verify": holder_credential_verify_ms,
        },
        "setup_wire_material": issue_meta["setup_wire_material"].clone(),
        "experiment_variant": variant.as_str(),
        "wallet_local_audit": wallet_local_audit,
        "wallet_entity_model": wallet_entity_model_value(),
        "wallet_interfaces": wallet_interfaces_value(),
        "joined_wallet_leakage_boundary": joined_wallet_leakage_boundary_value(),
        "wallet_joined_state_assumed": true,
    });
    Ok((
        BenchWorkflowSession {
            holder,
            wallet,
            taxonomy,
            issue_ms,
            variant,
            issuer_handle,
            raw_capability_handle,
            credential_id: approval.artifact_sha256.clone(),
            session_id: approval.artifact_sha256,
            approval_workflow_id: approval.workflow_id,
            approval_sequence: approval.approval_sequence,
            amendments_remaining,
            approval_public_key_sha256: approval.signer_public_key_sha256,
            settlement_verification,
        },
        response,
    ))
}

fn jsonl_begin_workflow(
    request: &Value,
    state: &mut JsonlState,
    policy: &policy_io::LoadedIssuerPolicy,
) -> Result<Value> {
    let workflow_id = value_string(request, "workflow_id")?;
    if state.sessions.contains_key(&workflow_id) || state.session_tombstones.contains(&workflow_id)
    {
        return Err(format!(
            "workflow is already active or tombstoned: {workflow_id}"
        ));
    }
    let (session, response) = prepare_jsonl_workflow(
        request,
        &workflow_id,
        &workflow_id,
        "initial",
        0,
        None,
        None,
        state,
        policy,
    )?;
    state.sessions.insert(workflow_id, session);
    Ok(response)
}

fn add_ablation_disclosure(value: &mut Value, session: &BenchWorkflowSession) {
    let Value::Object(map) = value else {
        return;
    };
    map.insert(
        "experiment_variant".to_string(),
        json!(session.variant.as_str()),
    );
    if !session.variant.hide_issuer() {
        map.insert("issuer_handle".to_string(), json!(session.issuer_handle));
    }
    if session.variant.expose_raw_capability() {
        map.insert(
            "raw_capability_handle".to_string(),
            json!(session.raw_capability_handle),
        );
    }
}

fn idempotent_jsonl_response(entry: &JsonlCacheEntry) -> Value {
    let mut response = entry.response.clone();
    if let Value::Object(map) = &mut response {
        let has_signed_receipt = map
            .get("signed_receipt")
            .is_some_and(|value| !value.is_null());
        map.insert("accepted".to_string(), json!(false));
        map.insert(
            "status".to_string(),
            json!(if has_signed_receipt {
                "idempotent_receipt"
            } else {
                "idempotent_rejection"
            }),
        );
        map.insert("fresh_execution_authorized".to_string(), json!(false));
        map.insert("settlement_authorization_issued".to_string(), json!(false));
        map.insert("idempotent_replay".to_string(), json!(true));
        map.insert(
            "canonical_request_digest_sha256".to_string(),
            json!(entry.request_digest),
        );
    }
    response
}

fn jsonl_invoke(
    request: &Value,
    state: &mut JsonlState,
    policy: &policy_io::LoadedIssuerPolicy,
) -> Result<Value> {
    let workflow_id = value_string(request, "workflow_id")?;
    let call_id = value_string(request, "call_id")?;
    let credential_id = value_string(request, "credential_id")?;
    if state.session_tombstones.contains(&workflow_id)
        || state.credential_tombstones.contains(&credential_id)
    {
        return Err("invoke references a tombstoned workflow or credential".to_string());
    }
    let canonical_request_digest_sha256 = hex_encode(&hash_bytes(
        DOMAIN_JSONL_REQUEST,
        &[canonical_ascii_bytes(request)],
    ));
    let idempotency_key = (workflow_id.clone(), call_id.clone());
    if let Some(entry) = state.idempotency.get(&idempotency_key) {
        if entry.request_digest != canonical_request_digest_sha256 {
            return Err(
                "workflow/call idempotency key was reused with a different canonical request"
                    .to_string(),
            );
        }
        return Ok(idempotent_jsonl_response(entry));
    }
    let service_id = value_string(request, "service_id")?;
    let class_name = value_string(request, "service_class")?;
    let merchant_id = value_string(request, "merchant_id")?;
    let amount = value_u64(request, "amount")?;
    let slot_indices = if let Some(values) = request.get("slot_indices").and_then(Value::as_array) {
        values
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .map(|index| index as usize)
                    .ok_or_else(|| "invoke slot_indices must contain integers".to_string())
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        vec![request
            .get("slot_index")
            .and_then(Value::as_u64)
            .ok_or("invoke requires slot_indices or an integer slot_index")? as usize]
    };
    let trusted_now = request
        .get("trusted_now")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let service_input = request
        .get("request_fields")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let session = state
        .sessions
        .get_mut(&workflow_id)
        .ok_or_else(|| format!("unknown workflow: {workflow_id}"))?;
    if credential_id != session.credential_id || session.session_id != session.credential_id {
        return Err("invoke credential_id does not match the active approval session".to_string());
    }
    if slot_indices.is_empty() {
        return Err("invoke requires at least one selected slot".into());
    }
    if slot_indices.iter().collect::<BTreeSet<_>>().len() != slot_indices.len() {
        return Err("invoke slot_indices must be unique".into());
    }
    if let Some(slot_index) = slot_indices
        .iter()
        .find(|slot_index| **slot_index >= session.holder.slot_count)
    {
        return Err(format!(
            "slot_index {slot_index} outside workflow credential"
        ));
    }
    let authorization_name = format!("auth:{class_name}");
    if !session.holder.messages.contains_key(&authorization_name) {
        return Err(format!(
            "service class is outside the credential scope: {class_name}"
        ));
    }

    let merchant = Merchant {
        merchant_id: merchant_id.clone(),
        key: SchnorrKey::new(),
    };
    let input_digest = service_input_digest(&service_input);
    let online_start = Instant::now();
    let ((q, preq, challenge, cert), merchant_request_ms) = timed(|| {
        merchant_request(
            &merchant,
            &session.taxonomy,
            &service_id,
            &class_name,
            &input_digest,
            amount,
            trusted_now,
            false,
        )
    });
    let (mut service, mut slot, presentation_ms, merchant_verify_ms) =
        derive_presentations_with_merchant_timing(
            &session.holder,
            &session.wallet.issuance.verifier,
            &session.taxonomy.key.pk,
            &merchant,
            &q,
            &preq,
            &challenge,
            &cert,
            &slot_indices,
            trusted_now,
        )?;
    let attack = request
        .get("attack")
        .and_then(Value::as_str)
        .unwrap_or("none");
    match attack {
        "unadmitted_issuer" => {
            service
                .issuer_hiding_authorization
                .randomized_issuer_pk
                .x_tilde += G2::generator();
        }
        "wrong_policy_digest" => {
            service.issuer_hiding_authorization.policy_digest =
                "attacker-selected-policy-digest".to_string();
        }
        "wrong_policy_tag" => {
            service.issuer_hiding_authorization.randomized_policy_tag.0 += G2::generator();
        }
        "wrong_policy_epoch" => {
            service.issuer_hiding_authorization.epoch = "attacker-selected-epoch".to_string();
        }
        "different_alpha" => {
            service.issuer_hiding_authorization.randomized_policy_tag.0 *= Scalar::from(2u64);
        }
        "cross_policy_presentation" => {
            service.issuer_hiding_authorization.registry_digest =
                "cross-policy-registry".to_string();
            service.issuer_hiding_authorization.policy_digest = "cross-policy-digest".to_string();
        }
        "reused_randomized_issuer_evidence" => {
            service.issuer_hiding_authorization.invocation_binding =
                "binding-from-a-different-invocation".to_string();
        }
        _ => {}
    }
    if matches!(
        attack,
        "unadmitted_issuer"
            | "wrong_policy_digest"
            | "wrong_policy_tag"
            | "wrong_policy_epoch"
            | "different_alpha"
            | "cross_policy_presentation"
            | "reused_randomized_issuer_evidence"
    ) {
        slot.issuer_hiding_authorization = service.issuer_hiding_authorization.clone();
        service.issuer_hiding_evidence =
            issuer_hiding_evidence_value(&service.issuer_hiding_authorization);
        slot.issuer_hiding_evidence =
            issuer_hiding_evidence_value(&slot.issuer_hiding_authorization);
    }
    let merchant_attack_rejection = if matches!(
        attack,
        "corrupted_merchant_proof" | "malformed_external_encoding"
    ) {
        if attack == "corrupted_merchant_proof" {
            corrupt_presentation_response(&mut service.presentation)?;
        } else {
            corrupt_external_issuer_evidence(&mut service.issuer_hiding_evidence);
            corrupt_external_issuer_evidence(&mut slot.issuer_hiding_evidence);
        }
        match verify_service_presentation(
            &session.wallet.issuance.verifier,
            &session.taxonomy.key.pk,
            &service,
            trusted_now,
        ) {
            Ok(_) => return Err("corrupted merchant proof was accepted".to_string()),
            Err(_) => Some(if attack == "malformed_external_encoding" {
                "wire-encoding"
            } else {
                "merchant-proof"
            }),
        }
    } else {
        None
    };
    let (mut redeem_request, bind_ms) = timed(|| make_redeem_request(service.clone(), slot));
    match attack {
        "none"
        | "replay"
        | "corrupted_merchant_proof"
        | "malformed_external_encoding"
        | "unadmitted_issuer"
        | "wrong_policy_digest"
        | "wrong_policy_tag"
        | "wrong_policy_epoch"
        | "different_alpha"
        | "cross_policy_presentation"
        | "reused_randomized_issuer_evidence" => {}
        "bind_tamper" => redeem_request.bind = "tampered-ablation-bind".to_string(),
        "request_projection_mismatch" => {
            redeem_request.slot.request_projection.commitment += G1::generator();
        }
        "corrupted_redemption_proof" => {
            corrupt_presentation_response(&mut redeem_request.slot.presentation)?;
            redeem_request.redemption_digest = redemption_view_digest(&redeem_request.slot);
            redeem_request.bind = one_call_bind(
                &redeem_request.service,
                &redeem_request.slot,
                &redeem_request.merchant_digest,
                &redeem_request.redemption_digest,
            )?;
        }
        "wrong_merchant" => {
            redeem_request.slot.projection.merchant = "wrong-merchant".to_string();
        }
        other => return Err(format!("unknown benchmark attack: {other}")),
    }
    let (verification, redemption_verify_ms) = if let Some(reason) = merchant_attack_rejection {
        (Err(reason), 0.0)
    } else {
        timed(|| {
            session.wallet.redemption.verify_redemption_request(
                &redeem_request,
                trusted_now,
                session.variant.enforce_bind(),
            )
        })
    };
    let ((accepted, receipt), settlement_or_receipt_ms) = match verification {
        Ok((serials, signed_budget)) => timed(|| {
            session.wallet.redemption.consume_verified_redemption(
                &redeem_request,
                serials,
                signed_budget,
                session.variant.enforce_serial_freshness(),
            )
        }),
        Err(reason) => (RedemptionService::reject_redemption(reason), 0.0),
    };
    let ((merchant_view, redemption_view, merchant_ack), serialize_ms) = timed(|| {
        let mut merchant_view =
            service.to_value_with_redemption_binding(Some(&redeem_request.bind));
        let mut redemption_view = redeem_request
            .slot
            .to_value_with_redemption_binding(Some(&redeem_request.bind));
        add_ablation_disclosure(&mut merchant_view, session);
        add_ablation_disclosure(&mut redemption_view, session);
        add_transmitted_view_fields(&mut merchant_view, policy);
        add_transmitted_view_fields(&mut redemption_view, policy);
        (
            merchant_view,
            redemption_view,
            redeem_request.ack.to_value(),
        )
    });
    let merchant_payload_bytes = json_size(&merchant_view);
    let redemption_payload_bytes = json_size(&redemption_view);
    let online_total_ms = online_start.elapsed().as_secs_f64() * 1000.0;
    let status = receipt
        .get("outcome")
        .and_then(Value::as_str)
        .unwrap_or("rejected");
    let fresh_accept = accepted && status == "fresh_accept";
    let error_code = if fresh_accept || status == "idempotent_receipt" {
        Value::Null
    } else {
        receipt
            .get("reason")
            .cloned()
            .unwrap_or_else(|| json!("rejected"))
    };
    let settlement_authorization = receipt
        .get("settlement_authorization")
        .cloned()
        .unwrap_or(Value::Null);
    let signed_receipt = receipt
        .get("signed_receipt")
        .cloned()
        .unwrap_or(Value::Null);
    let response = json!({
        "ok": true,
        "accepted": fresh_accept,
        "status": status,
        "fresh_execution_authorized": fresh_accept,
        "settlement_authorization_issued": fresh_accept,
        "idempotent_replay": false,
        "operation": "invoke",
        "protocol_version": PROTOCOL_VERSION,
        "wire_schema_version": WIRE_SCHEMA_VERSION,
        "issuer_hiding_scheme": ISSUER_HIDING_SCHEME,
        "wallet_local_audit": wallet_local_audit_value(&session.wallet, policy),
        "wallet_entity_model": wallet_entity_model_value(),
        "wallet_interfaces": wallet_interfaces_value(),
        "joined_wallet_leakage_boundary": joined_wallet_leakage_boundary_value(),
        "crypto_executed": true,
        "crypto_scheme": CRYPTO_SCHEME,
        "view_count": 2,
        "issuer_hiding_crypto_executed": true,
        "stable_issuer_handle_disclosed": !session.variant.hide_issuer(),
        "workflow_id": workflow_id,
        "call_id": call_id,
        "credential_id": session.credential_id,
        "session_id": session.session_id,
        "approval_digest_sha256": session.credential_id,
        "approval_public_key_sha256": session.approval_public_key_sha256,
        "canonical_request_digest_sha256": canonical_request_digest_sha256,
        "experiment_variant": session.variant.as_str(),
        "attack": attack,
        "enforce_serial_freshness": session.variant.enforce_serial_freshness(),
        "enforce_bind": session.variant.enforce_bind(),
        "issuer_hiding": session.variant.hide_issuer(),
        "error_code": error_code,
        "merchant_view_serialized": merchant_view,
        "redemption_view_serialized": redemption_view,
        "merchant_ack_serialized": merchant_ack,
        "dM": redeem_request.merchant_digest,
        "dR": redeem_request.redemption_digest,
        "Bind": redeem_request.bind,
        "settlement_authorization": settlement_authorization,
        "signed_receipt": signed_receipt,
        "settlement_verification": session.settlement_verification,
        "setup_ms": Value::Null,
        "issue_ms": session.issue_ms,
        "request_commit_ms": Value::Null,
        "merchant_prove_ms": Value::Null,
        "redemption_prove_ms": Value::Null,
        "merchant_request_ms": merchant_request_ms,
        "presentation_ms": presentation_ms,
        "bind_ms": bind_ms,
        "merchant_verify_ms": merchant_verify_ms,
        "redemption_verify_ms": redemption_verify_ms,
        "settlement_or_receipt_ms": settlement_or_receipt_ms,
        "serialize_ms": serialize_ms,
        "online_total_ms": online_total_ms,
        "workflow_total_ms": session.issue_ms + online_total_ms,
        "merchant_payload_bytes": merchant_payload_bytes,
        "redemption_payload_bytes": redemption_payload_bytes,
        "timing_unavailable": [
            "setup_ms",
            "request_commit_ms",
            "merchant_prove_ms",
            "redemption_prove_ms"
        ],
    });
    state.idempotency.insert(
        idempotency_key,
        JsonlCacheEntry {
            request_digest: canonical_request_digest_sha256,
            response: response.clone(),
        },
    );
    Ok(response)
}

fn jsonl_replace_workflow(
    request: &Value,
    state: &mut JsonlState,
    policy: &policy_io::LoadedIssuerPolicy,
) -> Result<Value> {
    let parent_workflow_id = value_string(request, "workflow_id")?;
    let replacement_workflow_id = value_string(request, "replacement_workflow_id")?;
    let parent_credential_id = value_string(request, "parent_credential_id")?;
    if parent_workflow_id == replacement_workflow_id {
        return Err("replace_workflow requires a distinct replacement_workflow_id".to_string());
    }
    if state.session_tombstones.contains(&parent_workflow_id) {
        return Err("replace_workflow parent session is tombstoned".to_string());
    }
    if state.sessions.contains_key(&replacement_workflow_id)
        || state.session_tombstones.contains(&replacement_workflow_id)
    {
        return Err("replacement workflow is already active or tombstoned".to_string());
    }
    let (
        active_parent_credential,
        parent_session_id,
        approval_workflow_id,
        parent_sequence,
        parent_remaining,
    ) = {
        let parent = state
            .sessions
            .get(&parent_workflow_id)
            .ok_or_else(|| format!("unknown replacement parent: {parent_workflow_id}"))?;
        (
            parent.credential_id.clone(),
            parent.session_id.clone(),
            parent.approval_workflow_id.clone(),
            parent.approval_sequence,
            parent.amendments_remaining,
        )
    };
    if parent_credential_id != active_parent_credential {
        return Err("replace_workflow parent credential binding mismatch".to_string());
    }
    if parent_remaining == 0 {
        return Err("replace_workflow exceeds the approved amendment limit".to_string());
    }
    let replacement_sequence = parent_sequence
        .checked_add(1)
        .ok_or_else(|| "replacement approval sequence overflow".to_string())?;
    let replacement_remaining = parent_remaining - 1;

    // Preparation performs all validation, funding reservation, credential
    // issuance, and settlement-key attestation without mutating active state.
    let (replacement_session, mut response) = prepare_jsonl_workflow(
        request,
        &replacement_workflow_id,
        &approval_workflow_id,
        "amendment",
        replacement_sequence,
        Some(&active_parent_credential),
        Some(replacement_remaining),
        state,
        policy,
    )?;
    let replacement_credential_id = replacement_session.credential_id.clone();
    if replacement_credential_id == active_parent_credential {
        return Err("replacement credential must have a fresh approval digest".to_string());
    }

    // Nothing after this point can fail: atomically swap active state only
    // after the complete replacement has been issued.
    let old_session = state
        .sessions
        .remove(&parent_workflow_id)
        .expect("validated replacement parent remains active");
    state
        .sessions
        .insert(replacement_workflow_id.clone(), replacement_session);
    state
        .credential_tombstones
        .insert(active_parent_credential.clone());
    state.session_tombstones.insert(parent_workflow_id.clone());
    state.session_tombstones.insert(parent_session_id.clone());
    drop(old_session);
    if let Value::Object(map) = &mut response {
        map.insert("operation".to_string(), json!("replace_workflow"));
        map.insert("status".to_string(), json!("replacement_committed"));
        map.insert("parent_workflow_id".to_string(), json!(parent_workflow_id));
        map.insert(
            "parent_credential_id".to_string(),
            json!(active_parent_credential),
        );
        map.insert("parent_session_id".to_string(), json!(parent_session_id));
        map.insert(
            "replacement_workflow_id".to_string(),
            json!(replacement_workflow_id),
        );
        map.insert(
            "replacement_credential_id".to_string(),
            json!(replacement_credential_id),
        );
        map.insert("parent_tombstoned".to_string(), json!(true));
    }
    Ok(response)
}

fn jsonl_end_workflow(request: &Value, state: &mut JsonlState) -> Result<Value> {
    let workflow_id = value_string(request, "workflow_id")?;
    let Some(session) = state.sessions.remove(&workflow_id) else {
        return Ok(json!({
            "ok": false,
            "accepted": false,
            "operation": "end_workflow",
            "workflow_id": workflow_id,
            "error_code": "unknown-workflow",
        }));
    };
    state
        .credential_tombstones
        .insert(session.credential_id.clone());
    state.session_tombstones.insert(session.session_id.clone());
    state.session_tombstones.insert(workflow_id.clone());
    Ok(json!({
        "ok": true,
        "accepted": false,
        "status": "credential_tombstoned",
        "operation": "end_workflow",
        "workflow_id": workflow_id,
        "credential_id": session.credential_id,
        "session_id": session.session_id,
        "credential_tombstoned": true,
        "session_tombstoned": true,
        "error_code": Value::Null,
    }))
}

fn validate_jsonl_contract(request: &Value, policy: &policy_io::LoadedIssuerPolicy) -> Result<()> {
    if request.get("protocol_version").and_then(Value::as_str) != Some(PROTOCOL_VERSION) {
        return Err("JSONL request protocol_version mismatch".to_string());
    }
    if request.get("wire_schema_version").and_then(Value::as_str) != Some(WIRE_SCHEMA_VERSION) {
        return Err("JSONL request wire_schema_version mismatch".to_string());
    }
    if request.get("issuer_policy") != Some(&policy.metadata) {
        return Err("JSONL request issuer policy metadata mismatch".to_string());
    }
    if request.get("no_live_cost_boundary") != Some(&no_live_cost_boundary_value()) {
        return Err("JSONL request no-live/no-charge boundary mismatch".to_string());
    }
    Ok(())
}

fn handle_jsonl_request(
    request: &Value,
    state: &mut JsonlState,
    policy: &policy_io::LoadedIssuerPolicy,
) -> Result<Value> {
    enforce_no_live_cost(request)?;
    validate_jsonl_contract(request, policy)?;
    let mut response = match request.get("operation").and_then(Value::as_str) {
        Some("ping") => Ok(json!({
            "ok": true,
            "operation": "ping",
            "protocol_version": PROTOCOL_VERSION,
            "wire_schema_version": WIRE_SCHEMA_VERSION,
            "issuer_hiding_scheme": ISSUER_HIDING_SCHEME,
            "execution_mode": EXECUTION_MODE,
            "allow_network": false,
            "allow_live_services": false,
            "allow_sandbox_services": false,
            "allow_real_payment": false,
            "allow_production_writes": false,
            "quote_mode": "virtual-deterministic",
            "settlement_mode": "local-ledger-no-funds",
            "live_external_calls": false,
            "real_charges": false,
            "transaction_broadcast": false,
            "wallet_entity_model": wallet_entity_model_value(),
            "wallet_interfaces": wallet_interfaces_value(),
            "joined_wallet_leakage_boundary": joined_wallet_leakage_boundary_value(),
        })),
        Some("begin_workflow") => jsonl_begin_workflow(request, state, policy),
        Some("replace_workflow") => jsonl_replace_workflow(request, state, policy),
        Some("invoke") => jsonl_invoke(request, state, policy),
        Some("end_workflow") => jsonl_end_workflow(request, state),
        Some(other) => Err(format!("unknown JSONL operation: {other}")),
        None => Err("JSONL request requires operation".to_string()),
    }?;
    add_jsonl_state_fields(&mut response, state);
    Ok(response)
}

fn decode_jsonl_transport(line: &str) -> Result<(Value, bool)> {
    let outer = serde_json::from_str::<Value>(line).map_err(|error| error.to_string())?;
    if outer.get("transport_encoding").and_then(Value::as_str) != Some(COMPACT_TRANSPORT_ENCODING) {
        return Ok((outer, false));
    }
    let object = outer
        .as_object()
        .ok_or_else(|| "compact transport envelope is not an object".to_string())?;
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != [
            "transport_encoding",
            "payload_b64",
            "uncompressed_bytes",
            "uncompressed_sha256",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
    {
        return Err("compact transport envelope fields are not canonical".to_string());
    }
    let payload = wire::base64_decode(
        object
            .get("payload_b64")
            .and_then(Value::as_str)
            .ok_or_else(|| "compact transport payload is missing".to_string())?,
    )?;
    let expected_bytes = object
        .get("uncompressed_bytes")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "compact transport length is invalid".to_string())?;
    if expected_bytes > MAX_COMPACT_TRANSPORT_BYTES {
        return Err("compact transport payload exceeds the size limit".to_string());
    }
    let mut decoded = Vec::with_capacity(expected_bytes);
    GzDecoder::new(payload.as_slice())
        .take((MAX_COMPACT_TRANSPORT_BYTES + 1) as u64)
        .read_to_end(&mut decoded)
        .map_err(|error| format!("compact transport decompression failed: {error}"))?;
    if decoded.len() != expected_bytes
        || sha256_plain_hex(&decoded)
            != object
                .get("uncompressed_sha256")
                .and_then(Value::as_str)
                .unwrap_or_default()
    {
        return Err("compact transport length or digest mismatch".to_string());
    }
    let request = serde_json::from_slice::<Value>(&decoded)
        .map_err(|error| format!("compact transport JSON is invalid: {error}"))?;
    Ok((request, true))
}

fn encode_jsonl_transport(response: &Value) -> Result<Value> {
    let uncompressed = canonical_bytes(response);
    if uncompressed.len() > MAX_COMPACT_TRANSPORT_BYTES {
        return Err("compact transport response exceeds the size limit".to_string());
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(&uncompressed)
        .map_err(|error| format!("compact transport compression failed: {error}"))?;
    let payload = encoder
        .finish()
        .map_err(|error| format!("compact transport compression failed: {error}"))?;
    Ok(json!({
        "transport_encoding": COMPACT_TRANSPORT_ENCODING,
        "payload_b64": wire::base64_encode(&payload),
        "uncompressed_bytes": uncompressed.len(),
        "uncompressed_sha256": sha256_plain_hex(&uncompressed),
    }))
}

fn run_jsonl_server(policy: &policy_io::LoadedIssuerPolicy) -> Result<()> {
    let network_boundary_attestation = startup_network_boundary_attestation()?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    let mut state = JsonlState::new(network_boundary_attestation);
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                let mut response =
                    json!({"ok": false, "error_code": "stdin", "detail": error.to_string()});
                add_wire_contract_fields(&mut response, policy);
                writeln!(output, "{response}").map_err(|e| e.to_string())?;
                output.flush().map_err(|e| e.to_string())?;
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let (mut response, compact_transport) = match decode_jsonl_transport(&line) {
            Ok((request, compact_transport)) => (
                match handle_jsonl_request(&request, &mut state, policy) {
                    Ok(response) => response,
                    Err(error) => {
                        json!({"ok": false, "error_code": "request", "detail": error})
                    }
                },
                compact_transport,
            ),
            Err(error) => (
                json!({
                    "ok": false,
                    "error_code": "malformed-json",
                    "detail": error.to_string()
                }),
                false,
            ),
        };
        add_wire_contract_fields(&mut response, policy);
        add_jsonl_state_fields(&mut response, &state);
        let transport_response = if compact_transport {
            encode_jsonl_transport(&response)?
        } else {
            response
        };
        writeln!(output, "{transport_response}").map_err(|e| e.to_string())?;
        output.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[derive(Clone)]
struct Args {
    runs: usize,
    slots: usize,
    spend_slots: usize,
    matrix: bool,
    workflow_trace: bool,
    planner_trace_file: Option<PathBuf>,
    issuer_bench: bool,
    redaction_bench: bool,
    race_bench: bool,
    jsonl_server: bool,
    native_client_validator: bool,
    issuer_policy: Option<PathBuf>,
    issuer_registry_sizes: Vec<usize>,
    redaction_hidden_fields: Vec<usize>,
    race_concurrency: Vec<usize>,
    race_jobs: usize,
    redaction_disclosed_fields: usize,
    classes: Vec<String>,
    amount: u64,
    expiry_delta: u64,
    output_dir: PathBuf,
    skip_corruption_check: bool,
    experiment_variant: String,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            runs: 1,
            slots: 1,
            spend_slots: 1,
            matrix: false,
            workflow_trace: false,
            planner_trace_file: None,
            issuer_bench: false,
            redaction_bench: false,
            race_bench: false,
            jsonl_server: false,
            native_client_validator: false,
            issuer_policy: None,
            issuer_registry_sizes: DEFAULT_ISSUER_REGISTRY_SIZES.to_vec(),
            redaction_hidden_fields: DEFAULT_REDACTION_HIDDEN_FIELDS.to_vec(),
            race_concurrency: vec![2, 4, 8, 16, 32],
            race_jobs: DEFAULT_RACE_JOBS,
            redaction_disclosed_fields: 6,
            classes: vec!["business".to_string()],
            amount: 5,
            expiry_delta: 100,
            output_dir: PathBuf::from("results"),
            skip_corruption_check: false,
            experiment_variant: "full".to_string(),
        }
    }
}

#[derive(Clone)]
struct RunRow {
    run: usize,
    curve: String,
    credential_backend: String,
    classes: String,
    slots: usize,
    spend_slots: usize,
    amount: u64,
    serial_derivation: String,
    pairing_optimization: String,
    auxiliary_signature_backend: String,
    prf_seed_scalars_stored: usize,
    legacy_random_serial_scalars: usize,
    serial_storage_saved_scalars: usize,
    credential_bytes: usize,
    experiment_variant: String,
    stable_issuer_handle_disclosed: bool,
    setup_ms: f64,
    issue_ms: f64,
    merchant_request_ms: f64,
    presentation_ms: f64,
    merchant_verify_ms: f64,
    redeem_valid_ms: f64,
    redeem_idempotent_retry_ms: f64,
    redeem_bad_bind_ms: f64,
    reject_noncanonical_ms: f64,
    redeem_corrupted_proof_ms: Option<f64>,
    valid_redemption: bool,
    valid_outcome: String,
    valid_fresh_execution_authorized: bool,
    valid_settlement_authorization_issued: bool,
    same_randomized_issuer_key: bool,
    idempotent_retry_status: String,
    idempotent_retry_outcome: String,
    idempotent_retry_fresh_execution_authorized: bool,
    idempotent_retry_settlement_authorization_issued: bool,
    bad_bind_reason: String,
    bad_bind_outcome: String,
    bad_bind_fresh_execution_authorized: bool,
    bad_bind_settlement_authorization_issued: bool,
    replay_fresh_execution_authorized: bool,
    noncanonical_rejected: bool,
    corrupted_proof_reason: Option<String>,
    corrupted_proof_outcome: Option<String>,
    corrupted_proof_fresh_execution_authorized: Option<bool>,
    corrupted_proof_settlement_authorization_issued: Option<bool>,
    merchant_proof_bytes: usize,
    redemption_proof_bytes: usize,
    redeem_request_bytes: usize,
    merchant_disclosed_fields: usize,
    redemption_disclosed_fields: usize,
    slot_serial_count: usize,
    slot_serial_bytes: usize,
}

impl RunRow {
    fn to_value(&self) -> Value {
        json!({
            "run": self.run,
            "curve": self.curve,
            "credential_backend": self.credential_backend,
            "classes": self.classes,
            "slots": self.slots,
            "spend_slots": self.spend_slots,
            "amount": self.amount,
            "serial_derivation": self.serial_derivation,
            "pairing_optimization": self.pairing_optimization,
            "auxiliary_signature_backend": self.auxiliary_signature_backend,
            "prf_seed_scalars_stored": self.prf_seed_scalars_stored,
            "legacy_random_serial_scalars": self.legacy_random_serial_scalars,
            "serial_storage_saved_scalars": self.serial_storage_saved_scalars,
            "credential_bytes": self.credential_bytes,
            "experiment_variant": self.experiment_variant,
            "stable_issuer_handle_disclosed": self.stable_issuer_handle_disclosed,
            "setup_ms": self.setup_ms,
            "issue_ms": self.issue_ms,
            "merchant_request_ms": self.merchant_request_ms,
            "presentation_ms": self.presentation_ms,
            "merchant_verify_ms": self.merchant_verify_ms,
            "redeem_valid_ms": self.redeem_valid_ms,
            "redeem_idempotent_retry_ms": self.redeem_idempotent_retry_ms,
            "redeem_bad_bind_ms": self.redeem_bad_bind_ms,
            "reject_noncanonical_ms": self.reject_noncanonical_ms,
            "redeem_corrupted_proof_ms": self.redeem_corrupted_proof_ms,
            "valid_redemption": self.valid_redemption,
            "valid_outcome": self.valid_outcome,
            "valid_fresh_execution_authorized": self.valid_fresh_execution_authorized,
            "valid_settlement_authorization_issued": self.valid_settlement_authorization_issued,
            "same_randomized_issuer_key": self.same_randomized_issuer_key,
            "idempotent_retry_status": self.idempotent_retry_status,
            "idempotent_retry_outcome": self.idempotent_retry_outcome,
            "idempotent_retry_fresh_execution_authorized": self.idempotent_retry_fresh_execution_authorized,
            "idempotent_retry_settlement_authorization_issued": self.idempotent_retry_settlement_authorization_issued,
            "bad_bind_reason": self.bad_bind_reason,
            "bad_bind_outcome": self.bad_bind_outcome,
            "bad_bind_fresh_execution_authorized": self.bad_bind_fresh_execution_authorized,
            "bad_bind_settlement_authorization_issued": self.bad_bind_settlement_authorization_issued,
            "replay_fresh_execution_authorized": self.replay_fresh_execution_authorized,
            "noncanonical_rejected": self.noncanonical_rejected,
            "corrupted_proof_reason": self.corrupted_proof_reason,
            "corrupted_proof_outcome": self.corrupted_proof_outcome,
            "corrupted_proof_fresh_execution_authorized": self.corrupted_proof_fresh_execution_authorized,
            "corrupted_proof_settlement_authorization_issued": self.corrupted_proof_settlement_authorization_issued,
            "merchant_proof_bytes": self.merchant_proof_bytes,
            "redemption_proof_bytes": self.redemption_proof_bytes,
            "redeem_request_bytes": self.redeem_request_bytes,
            "merchant_disclosed_fields": self.merchant_disclosed_fields,
            "redemption_disclosed_fields": self.redemption_disclosed_fields,
            "slot_serial_count": self.slot_serial_count,
            "slot_serial_bytes": self.slot_serial_bytes,
        })
    }

    fn csv_values(&self) -> Vec<String> {
        vec![
            self.run.to_string(),
            self.curve.clone(),
            self.credential_backend.clone(),
            self.classes.clone(),
            self.slots.to_string(),
            self.spend_slots.to_string(),
            self.amount.to_string(),
            self.serial_derivation.clone(),
            self.pairing_optimization.clone(),
            self.auxiliary_signature_backend.clone(),
            self.prf_seed_scalars_stored.to_string(),
            self.legacy_random_serial_scalars.to_string(),
            self.serial_storage_saved_scalars.to_string(),
            self.credential_bytes.to_string(),
            self.experiment_variant.clone(),
            self.stable_issuer_handle_disclosed.to_string(),
            format!("{:.6}", self.setup_ms),
            format!("{:.6}", self.issue_ms),
            format!("{:.6}", self.merchant_request_ms),
            format!("{:.6}", self.presentation_ms),
            format!("{:.6}", self.merchant_verify_ms),
            format!("{:.6}", self.redeem_valid_ms),
            format!("{:.6}", self.redeem_idempotent_retry_ms),
            format!("{:.6}", self.redeem_bad_bind_ms),
            format!("{:.6}", self.reject_noncanonical_ms),
            self.redeem_corrupted_proof_ms
                .map(|v| format!("{v:.6}"))
                .unwrap_or_default(),
            self.valid_redemption.to_string(),
            self.valid_outcome.clone(),
            self.valid_fresh_execution_authorized.to_string(),
            self.valid_settlement_authorization_issued.to_string(),
            self.same_randomized_issuer_key.to_string(),
            self.idempotent_retry_status.clone(),
            self.idempotent_retry_outcome.clone(),
            self.idempotent_retry_fresh_execution_authorized.to_string(),
            self.idempotent_retry_settlement_authorization_issued
                .to_string(),
            self.bad_bind_reason.clone(),
            self.bad_bind_outcome.clone(),
            self.bad_bind_fresh_execution_authorized.to_string(),
            self.bad_bind_settlement_authorization_issued.to_string(),
            self.replay_fresh_execution_authorized.to_string(),
            self.noncanonical_rejected.to_string(),
            self.corrupted_proof_reason.clone().unwrap_or_default(),
            self.corrupted_proof_outcome.clone().unwrap_or_default(),
            self.corrupted_proof_fresh_execution_authorized
                .map(|v| v.to_string())
                .unwrap_or_default(),
            self.corrupted_proof_settlement_authorization_issued
                .map(|v| v.to_string())
                .unwrap_or_default(),
            self.merchant_proof_bytes.to_string(),
            self.redemption_proof_bytes.to_string(),
            self.redeem_request_bytes.to_string(),
            self.merchant_disclosed_fields.to_string(),
            self.redemption_disclosed_fields.to_string(),
            self.slot_serial_count.to_string(),
            self.slot_serial_bytes.to_string(),
        ]
    }
}

#[derive(Clone)]
struct WorkflowTraceRow {
    call: usize,
    workflow: String,
    service_id: String,
    class_name: String,
    merchant: String,
    service_input_digest: String,
    amount: u64,
    selected_slot: usize,
    valid_redemption: bool,
    policy_atoms_checked: usize,
    baseline_reusable_handles: usize,
    minmandate_reusable_handles: usize,
    one_time_redemption_handles: usize,
    baseline_reusable_handle_names: String,
    minmandate_one_time_handle_names: String,
    baseline_payload_bytes: usize,
    merchant_sees_service_input: bool,
    redemption_sees_service_input: bool,
    merchant_request_ms: f64,
    proof_generation_ms: f64,
    redemption_verify_ms: f64,
    middleware_ms: f64,
    merchant_proof_bytes: usize,
    redemption_proof_bytes: usize,
    redeem_request_bytes: usize,
}

impl WorkflowTraceRow {
    fn to_value(&self) -> Value {
        json!({
            "call": self.call,
            "workflow": self.workflow,
            "service_id": self.service_id,
            "class": self.class_name,
            "merchant": self.merchant,
            "service_input_digest": self.service_input_digest,
            "amount": self.amount,
            "selected_slot": self.selected_slot,
            "valid_redemption": self.valid_redemption,
            "policy_atoms_checked": self.policy_atoms_checked,
            "baseline_reusable_handles": self.baseline_reusable_handles,
            "minmandate_reusable_handles": self.minmandate_reusable_handles,
            "one_time_redemption_handles": self.one_time_redemption_handles,
            "baseline_reusable_handle_names": self.baseline_reusable_handle_names,
            "minmandate_one_time_handle_names": self.minmandate_one_time_handle_names,
            "baseline_payload_bytes": self.baseline_payload_bytes,
            "merchant_sees_service_input": self.merchant_sees_service_input,
            "redemption_sees_service_input": self.redemption_sees_service_input,
            "merchant_request_ms": self.merchant_request_ms,
            "proof_generation_ms": self.proof_generation_ms,
            "redemption_verify_ms": self.redemption_verify_ms,
            "middleware_ms": self.middleware_ms,
            "merchant_proof_bytes": self.merchant_proof_bytes,
            "redemption_proof_bytes": self.redemption_proof_bytes,
            "redeem_request_bytes": self.redeem_request_bytes,
        })
    }

    fn csv_values(&self) -> Vec<String> {
        vec![
            self.call.to_string(),
            self.workflow.clone(),
            self.service_id.clone(),
            self.class_name.clone(),
            self.merchant.clone(),
            self.service_input_digest.clone(),
            self.amount.to_string(),
            self.selected_slot.to_string(),
            self.valid_redemption.to_string(),
            self.policy_atoms_checked.to_string(),
            self.baseline_reusable_handles.to_string(),
            self.minmandate_reusable_handles.to_string(),
            self.one_time_redemption_handles.to_string(),
            self.baseline_reusable_handle_names.clone(),
            self.minmandate_one_time_handle_names.clone(),
            self.baseline_payload_bytes.to_string(),
            self.merchant_sees_service_input.to_string(),
            self.redemption_sees_service_input.to_string(),
            format!("{:.6}", self.merchant_request_ms),
            format!("{:.6}", self.proof_generation_ms),
            format!("{:.6}", self.redemption_verify_ms),
            format!("{:.6}", self.middleware_ms),
            self.merchant_proof_bytes.to_string(),
            self.redemption_proof_bytes.to_string(),
            self.redeem_request_bytes.to_string(),
        ]
    }
}

#[derive(Clone)]
struct PlannerTraceCall {
    service_id: String,
    class_name: String,
    merchant: String,
    amount: u64,
    service_input: Value,
}

#[derive(Clone)]
struct PlannerTrace {
    trace_id: String,
    task: String,
    planner: Value,
    calls: Vec<PlannerTraceCall>,
}

#[derive(Clone)]
struct AdmissionRegistry {
    registry: BTreeSet<String>,
    revoked: BTreeSet<String>,
    registry_digest: String,
    revocation_digest: String,
}

static FINAL_V2_ADMISSION_REGISTRY: OnceLock<AdmissionRegistry> = OnceLock::new();
static FINAL_V2_ISSUER_REGISTRY_DIGEST: OnceLock<String> = OnceLock::new();

fn canonical_admission_registry() -> &'static AdmissionRegistry {
    FINAL_V2_ADMISSION_REGISTRY.get_or_init(|| build_admission_registry(128))
}

#[derive(Clone)]
struct IssuerAuthRow {
    run: usize,
    registry_size: usize,
    revoked_size: usize,
    registry_setup_ms: f64,
    auth_issue_ms: f64,
    auth_present_ms: f64,
    auth_verify_ms: f64,
    revoked_reject_ms: f64,
    auth_proof_bytes: usize,
    auth_disclosed_fields: usize,
    auth_hidden_fields: usize,
    auth_g1_relations: usize,
    auth_pairing_terms: usize,
    auth_valid: bool,
    revoked_rejected: bool,
    backend: String,
}

impl IssuerAuthRow {
    fn to_value(&self) -> Value {
        json!({
            "run": self.run,
            "registry_size": self.registry_size,
            "revoked_size": self.revoked_size,
            "registry_setup_ms": self.registry_setup_ms,
            "auth_issue_ms": self.auth_issue_ms,
            "auth_present_ms": self.auth_present_ms,
            "auth_verify_ms": self.auth_verify_ms,
            "revoked_reject_ms": self.revoked_reject_ms,
            "auth_proof_bytes": self.auth_proof_bytes,
            "auth_disclosed_fields": self.auth_disclosed_fields,
            "auth_hidden_fields": self.auth_hidden_fields,
            "auth_g1_relations": self.auth_g1_relations,
            "auth_pairing_terms": self.auth_pairing_terms,
            "auth_valid": self.auth_valid,
            "revoked_rejected": self.revoked_rejected,
            "backend": self.backend,
        })
    }

    fn csv_values(&self) -> Vec<String> {
        vec![
            self.run.to_string(),
            self.registry_size.to_string(),
            self.revoked_size.to_string(),
            format!("{:.6}", self.registry_setup_ms),
            format!("{:.6}", self.auth_issue_ms),
            format!("{:.6}", self.auth_present_ms),
            format!("{:.6}", self.auth_verify_ms),
            format!("{:.6}", self.revoked_reject_ms),
            self.auth_proof_bytes.to_string(),
            self.auth_disclosed_fields.to_string(),
            self.auth_hidden_fields.to_string(),
            self.auth_g1_relations.to_string(),
            self.auth_pairing_terms.to_string(),
            self.auth_valid.to_string(),
            self.revoked_rejected.to_string(),
            self.backend.clone(),
        ]
    }
}

#[derive(Clone)]
struct RedactionRow {
    run: usize,
    hidden_fields: usize,
    disclosed_fields: usize,
    total_fields: usize,
    commit_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
    payload_bytes: usize,
    proof_responses: usize,
    valid: bool,
    backend: String,
}

impl RedactionRow {
    fn to_value(&self) -> Value {
        json!({
            "run": self.run,
            "hidden_fields": self.hidden_fields,
            "disclosed_fields": self.disclosed_fields,
            "total_fields": self.total_fields,
            "commit_ms": self.commit_ms,
            "prove_ms": self.prove_ms,
            "verify_ms": self.verify_ms,
            "proof_bytes": self.proof_bytes,
            "payload_bytes": self.payload_bytes,
            "proof_responses": self.proof_responses,
            "valid": self.valid,
            "backend": self.backend,
        })
    }

    fn csv_values(&self) -> Vec<String> {
        vec![
            self.run.to_string(),
            self.hidden_fields.to_string(),
            self.disclosed_fields.to_string(),
            self.total_fields.to_string(),
            format!("{:.6}", self.commit_ms),
            format!("{:.6}", self.prove_ms),
            format!("{:.6}", self.verify_ms),
            self.proof_bytes.to_string(),
            self.payload_bytes.to_string(),
            self.proof_responses.to_string(),
            self.valid.to_string(),
            self.backend.clone(),
        ]
    }
}

#[derive(Clone)]
struct RaceRow {
    run: usize,
    concurrency: usize,
    accepted: usize,
    rejected: usize,
    double_spend_rejected: usize,
    other_rejected: usize,
    median_latency_ms: f64,
    p95_latency_ms: f64,
    max_latency_ms: f64,
    accepted_latency_ms: f64,
    loser_median_latency_ms: f64,
    elapsed_ms: f64,
    state_backend: String,
    locking_mechanism: String,
    linearizable: bool,
}

impl RaceRow {
    fn to_value(&self) -> Value {
        json!({
            "run": self.run,
            "concurrency": self.concurrency,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "double_spend_rejected": self.double_spend_rejected,
            "other_rejected": self.other_rejected,
            "median_latency_ms": self.median_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "accepted_latency_ms": self.accepted_latency_ms,
            "loser_median_latency_ms": self.loser_median_latency_ms,
            "elapsed_ms": self.elapsed_ms,
            "state_backend": self.state_backend,
            "locking_mechanism": self.locking_mechanism,
            "linearizable": self.linearizable,
        })
    }

    fn csv_values(&self) -> Vec<String> {
        vec![
            self.run.to_string(),
            self.concurrency.to_string(),
            self.accepted.to_string(),
            self.rejected.to_string(),
            self.double_spend_rejected.to_string(),
            self.other_rejected.to_string(),
            format!("{:.6}", self.median_latency_ms),
            format!("{:.6}", self.p95_latency_ms),
            format!("{:.6}", self.max_latency_ms),
            format!("{:.6}", self.accepted_latency_ms),
            format!("{:.6}", self.loser_median_latency_ms),
            format!("{:.6}", self.elapsed_ms),
            self.state_backend.clone(),
            self.locking_mechanism.clone(),
            self.linearizable.to_string(),
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RaceJob {
    run_id: usize,
    concurrency: usize,
    repetition: usize,
}

fn materialize_race_jobs(args: &Args) -> Vec<RaceJob> {
    let mut jobs = Vec::with_capacity(args.race_concurrency.len() * args.runs);
    let mut run_id = 1;
    for &concurrency in &args.race_concurrency {
        for repetition in 1..=args.runs {
            jobs.push(RaceJob {
                run_id,
                concurrency,
                repetition,
            });
            run_id += 1;
        }
    }
    jobs
}

fn run_race_jobs_with<T, Run, Emit>(
    race_jobs: usize,
    jobs: &[RaceJob],
    run: Run,
    mut emit: Emit,
) -> Result<Vec<T>>
where
    T: Send,
    Run: Fn(RaceJob) -> Result<T> + Sync,
    Emit: FnMut(RaceJob, &T),
{
    if !(1..=MAX_RACE_JOBS).contains(&race_jobs) {
        return Err(format!("--race-jobs must be between 1 and {MAX_RACE_JOBS}"));
    }
    if let Some(job) = jobs
        .iter()
        .find(|job| !(2..=MAX_RACE_CONTENDER_THREADS).contains(&job.concurrency))
    {
        return Err(format!(
            "race job {} concurrency must be between 2 and {MAX_RACE_CONTENDER_THREADS}",
            job.run_id
        ));
    }

    let run = &run;
    let mut rows = Vec::with_capacity(jobs.len());
    let mut batch_start = 0;
    while batch_start < jobs.len() {
        let mut batch_end = batch_start;
        let mut contender_threads = 0;
        while batch_end < jobs.len() && batch_end - batch_start < race_jobs {
            let concurrency = jobs[batch_end].concurrency;
            if concurrency > MAX_RACE_CONTENDER_THREADS - contender_threads {
                break;
            }
            contender_threads += concurrency;
            batch_end += 1;
        }
        if batch_end == batch_start {
            return Err("race scheduler could not form a bounded batch".to_string());
        }

        let completed = thread::scope(|scope| {
            let handles = jobs[batch_start..batch_end]
                .iter()
                .copied()
                .map(|job| {
                    let handle = scope.spawn(move || run(job));
                    (job, handle)
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|(job, handle)| {
                    let result = match handle.join() {
                        Ok(result) => result,
                        Err(_) => Err(format!("race job {} panicked", job.run_id)),
                    };
                    (job, result)
                })
                .collect::<Vec<_>>()
        });

        for (job, result) in completed {
            let row = result?;
            emit(job, &row);
            rows.push(row);
        }
        batch_start = batch_end;
    }
    Ok(rows)
}

fn run_race_jobs<Emit>(args: &Args, jobs: &[RaceJob], emit: Emit) -> Result<Vec<RaceRow>>
where
    Emit: FnMut(RaceJob, &RaceRow),
{
    run_race_jobs_with(
        args.race_jobs,
        jobs,
        |job| run_double_spend_race_one(job.run_id, args, job.concurrency),
        emit,
    )
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, f64) {
    let start = Instant::now();
    let value = f();
    (value, start.elapsed().as_secs_f64() * 1000.0)
}

fn require(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn build_admission_registry(size: usize) -> AdmissionRegistry {
    let mut registry = BTreeSet::new();
    let mut revoked = BTreeSet::new();
    for index in 0..size {
        let wallet = scalar_hex(&registry_wallet_id(index));
        registry.insert(wallet.clone());
        if index % 97 == 0 {
            revoked.insert(wallet);
        }
    }
    let registry_root = registry_digest("mm-auth-registry", &registry);
    let revocation_digest = registry_digest("mm-auth-revocation", &revoked);
    AdmissionRegistry {
        registry,
        revoked,
        registry_digest: registry_root,
        revocation_digest,
    }
}

// Legacy/bench-only compatibility boundary. The canonical JSONL protocol calls
// build_admission_registry directly and never enters the old issuer-auth
// microbenchmark path below.
fn build_issuer_auth_registry(size: usize) -> AdmissionRegistry {
    build_admission_registry(size)
}

fn nonrevoked_wallet_index(size: usize) -> usize {
    for index in (size / 2)..size {
        if index % 97 != 0 {
            return index;
        }
    }
    for index in 0..size {
        if index % 97 != 0 {
            return index;
        }
    }
    0
}

fn revoked_wallet_index(size: usize) -> usize {
    for index in 0..size {
        if index % 97 == 0 {
            return index;
        }
    }
    0
}

fn auth_context(registry_size: usize, registry: &AdmissionRegistry, epoch: Scalar) -> Value {
    json!({
        "relation": "issuer-authorized-wallet-status",
        "profile": "group-key-attribute",
        "registry_size": registry_size,
        "registry_digest": registry.registry_digest,
        "revocation_digest": registry.revocation_digest,
        "epoch": scalar_hex(&epoch),
        "public_status_fields": [AUTH_EPOCH, AUTH_MEMBER, AUTH_NOT_REVOKED, AUTH_EXPIRY],
        "hidden_fields": [AUTH_WALLET_ID, AUTH_ISSUER_PK],
    })
}

fn auth_disclosed_messages(epoch: Scalar, expiry: Scalar) -> BTreeMap<String, Scalar> {
    BTreeMap::from([
        (AUTH_EPOCH.to_string(), epoch),
        (AUTH_MEMBER.to_string(), Scalar::ONE),
        (AUTH_NOT_REVOKED.to_string(), Scalar::ONE),
        (AUTH_EXPIRY.to_string(), expiry),
    ])
}

#[derive(Clone)]
struct GroupStatusSecretKey {
    x_v: Scalar,
}

#[derive(Clone)]
struct GroupStatusPublicKey {
    g_v: G1,
    t_v: G1,
}

#[derive(Clone)]
struct GroupStatusCredential {
    issuer_pk: G2,
    issuer_tag: G2,
    epoch: Scalar,
    expiry: Scalar,
}

#[derive(Clone)]
struct GroupStatusPresentation {
    randomized_issuer_pk: G2,
    randomized_issuer_tag: G2,
    disclosed_messages: BTreeMap<String, Scalar>,
}

impl GroupStatusPresentation {
    fn to_value(&self) -> Value {
        json!({
            "randomized_issuer_pk": g2_hex(&self.randomized_issuer_pk),
            "randomized_issuer_tag": g2_hex(&self.randomized_issuer_tag),
            "disclosed_messages": scalar_map_value(&self.disclosed_messages),
        })
    }
}

fn group_status_keygen() -> (GroupStatusSecretKey, GroupStatusPublicKey) {
    let x_v = random_scalar();
    let g_v = G1::generator() * random_scalar();
    (
        GroupStatusSecretKey { x_v },
        GroupStatusPublicKey {
            g_v,
            t_v: g_v * x_v.invert().unwrap(),
        },
    )
}

fn issue_auth_credential(
    auth_sk: &GroupStatusSecretKey,
    registry: &AdmissionRegistry,
    wallet_id: Scalar,
    issuer_pk: G2,
    epoch: Scalar,
    expiry: Scalar,
    _context: &Value,
) -> Result<GroupStatusCredential> {
    let wallet_hex = scalar_hex(&wallet_id);
    if !registry.registry.contains(&wallet_hex) {
        return Err("wallet issuer is not in epoch registry".to_string());
    }
    if registry.revoked.contains(&wallet_hex) {
        return Err("wallet issuer is revoked for epoch".to_string());
    }
    Ok(GroupStatusCredential {
        issuer_pk,
        issuer_tag: issuer_pk * auth_sk.x_v.invert().unwrap(),
        epoch,
        expiry,
    })
}

fn present_auth_credential(
    credential: &GroupStatusCredential,
    _context: &Value,
) -> GroupStatusPresentation {
    let alpha = random_scalar();
    let disclosed_messages = auth_disclosed_messages(credential.epoch, credential.expiry);
    let randomized_issuer_pk = credential.issuer_pk * alpha;
    let randomized_issuer_tag = credential.issuer_tag * alpha;
    GroupStatusPresentation {
        randomized_issuer_pk,
        randomized_issuer_tag,
        disclosed_messages,
    }
}

fn issuer_auth_pairing_terms(
    auth_pk: &GroupStatusPublicKey,
    presentation: &GroupStatusPresentation,
) -> Option<Vec<(G2, G1)>> {
    if presentation.randomized_issuer_pk == G2::identity()
        || presentation.randomized_issuer_tag == G2::identity()
        || auth_pk.g_v == G1::identity()
        || auth_pk.t_v == G1::identity()
    {
        return None;
    }
    Some(vec![
        (presentation.randomized_issuer_pk, auth_pk.t_v),
        (-presentation.randomized_issuer_tag, auth_pk.g_v),
    ])
}

fn verify_auth_presentation(
    auth_pk: &GroupStatusPublicKey,
    presentation: &GroupStatusPresentation,
    epoch: Scalar,
    expiry: Scalar,
    context: &Value,
) -> bool {
    let expected_names = [AUTH_EPOCH, AUTH_MEMBER, AUTH_NOT_REVOKED, AUTH_EXPIRY]
        .iter()
        .map(|s| s.to_string())
        .collect::<BTreeSet<_>>();
    if presentation
        .disclosed_messages
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_names
    {
        return false;
    }
    if presentation.disclosed_messages.get(AUTH_EPOCH) != Some(&epoch) {
        return false;
    }
    if presentation.disclosed_messages.get(AUTH_MEMBER) != Some(&Scalar::ONE) {
        return false;
    }
    if presentation.disclosed_messages.get(AUTH_NOT_REVOKED) != Some(&Scalar::ONE) {
        return false;
    }
    if presentation.disclosed_messages.get(AUTH_EXPIRY) != Some(&expiry) {
        return false;
    }
    let _ = context;
    let Some(terms) = issuer_auth_pairing_terms(auth_pk, presentation) else {
        return false;
    };
    multi_pairing_check(&terms)
}

fn issuer_auth_proof_size(presentation: &GroupStatusPresentation, context: &Value) -> usize {
    json_size(&json!({
        "presentation": presentation.to_value(),
        "context": context,
    }))
}

fn run_issuer_auth_one(run_id: usize, registry_size: usize) -> Result<IssuerAuthRow> {
    let ((registry, auth_sk, auth_pk), registry_setup_ms) = timed(|| {
        let registry = build_issuer_auth_registry(registry_size);
        let (auth_sk, auth_pk) = group_status_keygen();
        (registry, auth_sk, auth_pk)
    });
    let epoch = scalar_from_value(&json!("epoch-2026-06"));
    let expiry = Scalar::from(1_000_000u64);
    let context = auth_context(registry_size, &registry, epoch);
    let wallet_index = nonrevoked_wallet_index(registry_size);
    let wallet_id = registry_wallet_id(wallet_index);
    let issuer_pk = registry_issuer_pk(wallet_id);
    let (credential_result, auth_issue_ms) = timed(|| {
        issue_auth_credential(
            &auth_sk, &registry, wallet_id, issuer_pk, epoch, expiry, &context,
        )
    });
    let credential = credential_result?;
    let (presentation, auth_present_ms) = timed(|| present_auth_credential(&credential, &context));
    let (auth_valid, auth_verify_ms) =
        timed(|| verify_auth_presentation(&auth_pk, &presentation, epoch, expiry, &context));
    require(
        auth_valid,
        format!("run {run_id}: valid issuer authorization rejected"),
    )?;
    let revoked_index = revoked_wallet_index(registry_size);
    let revoked_wallet_id = registry_wallet_id(revoked_index);
    let revoked_issuer_pk = registry_issuer_pk(revoked_wallet_id);
    let (revoked_result, revoked_reject_ms) = timed(|| {
        issue_auth_credential(
            &auth_sk,
            &registry,
            revoked_wallet_id,
            revoked_issuer_pk,
            epoch,
            expiry,
            &context,
        )
    });
    let revoked_rejected = revoked_result.is_err();
    require(
        revoked_rejected,
        format!("run {run_id}: revoked issuer received authorization credential"),
    )?;
    let auth_pairing_terms = issuer_auth_pairing_terms(&auth_pk, &presentation)
        .map(|terms| terms.len())
        .unwrap_or(0);
    Ok(IssuerAuthRow {
        run: run_id,
        registry_size,
        revoked_size: registry.revoked.len(),
        registry_setup_ms,
        auth_issue_ms,
        auth_present_ms,
        auth_verify_ms,
        revoked_reject_ms,
        auth_proof_bytes: issuer_auth_proof_size(&presentation, &context),
        auth_disclosed_fields: presentation.disclosed_messages.len(),
        auth_hidden_fields: 1,
        auth_g1_relations: 0,
        auth_pairing_terms,
        auth_valid,
        revoked_rejected,
        backend: "BLS12-381 IHBBS1 policy tag and BBS presentation".to_string(),
    })
}

fn redaction_bases(hidden_fields: usize, disclosed_fields: usize) -> BTreeMap<String, G1> {
    let mut bases = BTreeMap::new();
    bases.insert("eta".to_string(), hash_g1("mm-redact-open-eta"));
    for j in 0..hidden_fields {
        bases.insert(
            format!("hidden_{j}"),
            hash_g1(&format!("mm-redact-open-hidden-{j}")),
        );
    }
    for j in 0..disclosed_fields {
        bases.insert(
            format!("public_{j}"),
            hash_g1(&format!("mm-redact-open-public-{j}")),
        );
    }
    bases
}

fn run_redaction_one(
    run_id: usize,
    hidden_fields: usize,
    disclosed_fields: usize,
) -> Result<RedactionRow> {
    let all_bases = redaction_bases(hidden_fields, disclosed_fields);
    let mut hidden_secrets = BTreeMap::new();
    hidden_secrets.insert("eta".to_string(), random_scalar());
    for j in 0..hidden_fields {
        hidden_secrets.insert(format!("hidden_{j}"), random_scalar());
    }
    let disclosed_values = (0..disclosed_fields)
        .map(|j| (format!("public_{j}"), random_scalar()))
        .collect::<Vec<_>>();
    let context = json!({
        "relation": "redacted-request-opening",
        "hidden_fields": hidden_fields,
        "disclosed_fields": disclosed_fields,
        "schema": "fixed MCP paid-tool request vector",
    });
    let hidden_bases = all_bases
        .iter()
        .filter(|(name, _)| name.as_str() == "eta" || name.starts_with("hidden_"))
        .map(|(name, base)| (name.clone(), *base))
        .collect::<BTreeMap<_, _>>();

    let ((request_commitment, redacted_target), commit_ms) = timed(|| {
        let hidden_part = g1_linear(
            hidden_bases
                .iter()
                .map(|(name, base)| (base, hidden_secrets[name])),
        );
        let disclosed_part = g1_linear(
            disclosed_values
                .iter()
                .map(|(name, value)| (&all_bases[name], *value)),
        );
        let request_commitment = hidden_part + disclosed_part;
        let redacted_target = request_commitment - disclosed_part;
        (request_commitment, redacted_target)
    });

    let (proof, prove_ms) = timed(|| {
        prove_representation_g1(
            "mm-redact-open-proof",
            &hidden_bases,
            &hidden_secrets,
            &redacted_target,
            &context,
        )
    });
    let (valid, verify_ms) = timed(|| {
        verify_representation_g1(
            "mm-redact-open-proof",
            &hidden_bases,
            &redacted_target,
            &proof,
            &context,
        )
    });
    require(
        valid,
        format!("run {run_id}: valid redaction proof rejected"),
    )?;

    let disclosed_json = Value::Array(
        disclosed_values
            .iter()
            .map(|(name, value)| json!({"name": name, "value": scalar_hex(value)}))
            .collect(),
    );
    let proof_value = proof.to_value();
    let payload = json!({
        "R": g1_hex(&request_commitment),
        "disclosed": disclosed_json,
        "hidden_count": hidden_fields,
        "proof": proof_value,
        "context": context,
    });

    Ok(RedactionRow {
        run: run_id,
        hidden_fields,
        disclosed_fields,
        total_fields: hidden_fields + disclosed_fields,
        commit_ms,
        prove_ms,
        verify_ms,
        proof_bytes: json_size(&proof.to_value()),
        payload_bytes: json_size(&payload),
        proof_responses: proof.responses.len(),
        valid,
        backend: "BLS12-381 Pedersen vector commitment plus Schnorr representation proof"
            .to_string(),
    })
}

fn proof_sizes(
    service: &ServicePresentation,
    slot: &SlotPresentation,
    redeem: &RedeemRequest,
) -> (usize, usize, usize, usize, usize, usize, usize) {
    let mut serials = Map::new();
    for k in &slot.selected_slots {
        serials.insert(k.to_string(), json!(g1_hex(&slot.serials[k])));
    }
    (
        json_size(&service.to_value()),
        json_size(&slot.to_value()),
        json_size(&redeem.to_value()),
        service.presentation.disclosed_messages.len(),
        slot.presentation.disclosed_messages.len(),
        slot.serials.len(),
        json_size(&Value::Object(serials)),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ControlledRedemptionOutcome {
    outcome: String,
    fresh_execution_authorized: bool,
    settlement_authorization_issued: bool,
}

impl ControlledRedemptionOutcome {
    fn parse(context: &str, returned_fresh: bool, response: &Value) -> Result<Self> {
        let outcome = response
            .get("outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{context}: response omitted outcome: {response}"))?
            .to_string();
        let fresh_execution_authorized = response
            .get("fresh_execution_authorized")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                format!("{context}: response omitted fresh_execution_authorized: {response}")
            })?;
        let settlement_authorization_issued = response
            .get("settlement_authorization_issued")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                format!("{context}: response omitted settlement_authorization_issued: {response}")
            })?;
        let expected_authorization = match outcome.as_str() {
            "fresh_accept" => true,
            "rejected" | "idempotent_receipt" => false,
            _ => {
                return Err(format!(
                    "{context}: unknown outcome {outcome:?}: {response}"
                ))
            }
        };
        require(
            fresh_execution_authorized == expected_authorization
                && settlement_authorization_issued == expected_authorization
                && returned_fresh == expected_authorization,
            format!(
                "{context}: inconsistent outcome/authorization semantics: {response}; returned_fresh={returned_fresh}"
            ),
        )?;
        Ok(Self {
            outcome,
            fresh_execution_authorized,
            settlement_authorization_issued,
        })
    }

    fn is_fresh_accept(&self) -> bool {
        self.outcome == "fresh_accept"
    }

    fn is_rejected(&self) -> bool {
        self.outcome == "rejected"
    }

    fn is_idempotent_receipt(&self) -> bool {
        self.outcome == "idempotent_receipt"
    }
}

fn run_one(run_id: usize, args: &Args, slots: usize, spend_slots: usize) -> Result<RunRow> {
    let variant = BenchAblationVariant::parse(&args.experiment_variant)?;
    let classes = args.classes.clone();
    let capacities = vec![args.amount; slots];
    let slot_classes = vec![classes[0].clone(); slots];
    let slot_merchants = vec![format!("merchant-{run_id}"); slots];
    let selected_slots = (0..spend_slots).collect::<Vec<_>>();
    let now = 1u64;

    let ((user, wallet, taxonomy), setup_ms) = timed(|| build_system(slots, &classes));
    let (issue_result, issue_ms) = timed(|| {
        issue_task_credential(
            &user,
            &wallet,
            &classes,
            &capacities,
            &slot_classes,
            &slot_merchants,
            now + args.expiry_delta,
            capacities.iter().sum(),
        )
    });
    let (holder, _meta) = issue_result?;
    let merchant = Merchant {
        merchant_id: slot_merchants[0].clone(),
        key: SchnorrKey::new(),
    };
    let input_digest = service_input_digest(&default_service_input("company-profile", &classes[0]));
    let ((q, preq, challenge, cert), merchant_request_ms) = timed(|| {
        merchant_request(
            &merchant,
            &taxonomy,
            "company-profile",
            &classes[0],
            &input_digest,
            args.amount * spend_slots as u64,
            now,
            false,
        )
    });
    let (presentation_result, presentation_ms) = timed(|| {
        derive_presentations(
            &holder,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &merchant,
            &q,
            &preq,
            &challenge,
            &cert,
            &selected_slots,
            now,
        )
    });
    let (service, slot) = presentation_result?;
    let (merchant_verify_result, merchant_verify_ms) = timed(|| {
        verify_service_presentation(&wallet.issuance.verifier, &taxonomy.key.pk, &service, now)
    });
    require(
        merchant_verify_result.is_ok(),
        format!("run {run_id}: valid service presentation rejected"),
    )?;
    let redeem_request = make_redeem_request(service.clone(), slot.clone());
    let same_randomized_issuer_key = service
        .issuer_hiding_authorization
        .randomized_issuer_pk
        .x_tilde
        == slot
            .issuer_hiding_authorization
            .randomized_issuer_pk
            .x_tilde;
    require(
        same_randomized_issuer_key,
        format!("run {run_id}: service and slot presentations used different signatures"),
    )?;

    let credential_bytes = json_size(&json!({
        "signature": holder.credential.signature.to_value(),
        "messages": scalar_map_value(&holder.credential.messages),
    }));
    let mut redemption =
        RedemptionService::new_ephemeral(wallet.issuance.verifier.clone(), taxonomy.key.pk);
    let ((valid_result, valid_receipt), redeem_valid_ms) =
        timed(|| redemption.redeem_with_policy(
            &redeem_request, now, variant.enforce_bind(), variant.enforce_serial_freshness(),
        ));
    let valid_semantics = ControlledRedemptionOutcome::parse(
        &format!("run {run_id}: valid redemption"),
        valid_result,
        &valid_receipt,
    )?;
    require(
        valid_semantics.is_fresh_accept(),
        format!("run {run_id}: valid redemption rejected: {valid_receipt}"),
    )?;

    let ((retry_result, retry_receipt), redeem_idempotent_retry_ms) =
        timed(|| redemption.redeem_with_policy(
            &redeem_request, now, variant.enforce_bind(), variant.enforce_serial_freshness(),
        ));
    let retry_semantics = ControlledRedemptionOutcome::parse(
        &format!("run {run_id}: idempotent retry"),
        retry_result,
        &retry_receipt,
    )?;
    let retry_marked_idempotent = retry_receipt["idempotent_replay"].as_bool() == Some(true);
    let mut valid_receipt_core = valid_receipt.clone();
    let mut retry_receipt_core = retry_receipt.clone();
    if let Some(object) = valid_receipt_core.as_object_mut() {
        object.remove("idempotent_replay");
        object.remove("outcome");
        object.remove("fresh_execution_authorized");
        object.remove("settlement_authorization_issued");
    }
    if let Some(object) = retry_receipt_core.as_object_mut() {
        object.remove("idempotent_replay");
        object.remove("outcome");
        object.remove("fresh_execution_authorized");
        object.remove("settlement_authorization_issued");
    }
    let idempotent_retry_status = if variant.enforce_serial_freshness() {
        require(
            retry_semantics.is_idempotent_receipt()
                && retry_marked_idempotent
                && retry_receipt_core == valid_receipt_core,
            format!(
                "run {run_id}: identical retry did not return the original receipt: {retry_receipt}"
            ),
        )?;
        "retrieved-original-receipt-no-execution".to_string()
    } else {
        require(
            retry_semantics.is_fresh_accept(),
            format!("run {run_id}: no-serial variant unexpectedly rejected replay: {retry_receipt}"),
        )?;
        "fresh-execution-accepted-without-serial-freshness".to_string()
    };

    let mut bad_bind = RedeemRequest {
        bind: "tampered".to_string(),
        ..redeem_request.clone()
    };
    // The no-binding counterfactual models a merchant that has acknowledged
    // the substituted binding.  This keeps the acknowledgement well formed
    // and isolates the wallet's one-call binding check rather than testing a
    // malformed signature.
    if !variant.enforce_bind() {
        bad_bind.ack.body["Bind"] = json!(bad_bind.bind);
        bad_bind.ack.signature = merchant.key.sign(&bad_bind.ack.body);
    }
    let ((bad_bind_result, bad_bind_reason), redeem_bad_bind_ms) = timed(|| {
        RedemptionService::new_ephemeral(wallet.issuance.verifier.clone(), taxonomy.key.pk)
            .redeem_with_policy(
                &bad_bind, now, variant.enforce_bind(), variant.enforce_serial_freshness(),
            )
    });
    let bad_bind_semantics = ControlledRedemptionOutcome::parse(
        &format!("run {run_id}: bad binding"),
        bad_bind_result,
        &bad_bind_reason,
    )?;
    let bad_bind_reason_s = bad_bind_reason["reason"].as_str().unwrap_or("").to_string();
    if variant.enforce_bind() {
        require(
            bad_bind_semantics.is_rejected(),
            format!("run {run_id}: bad binding was not rejected: {bad_bind_reason}"),
        )?;
    } else {
        require(
            bad_bind_semantics.is_fresh_accept(),
            format!("run {run_id}: unbound variant unexpectedly rejected bind tampering: {bad_bind_reason}"),
        )?;
    }

    let ((_bad_q, bad_preq, bad_challenge, bad_cert), noncanonical_make_ms) = timed(|| {
        merchant_request(
            &merchant,
            &taxonomy,
            "company-profile",
            &classes[0],
            &input_digest,
            args.amount,
            now,
            true,
        )
    });
    let start = Instant::now();
    let noncanonical_rejected = derive_presentations(
        &holder,
        &wallet.issuance.verifier,
        &taxonomy.key.pk,
        &merchant,
        &_bad_q,
        &bad_preq,
        &bad_challenge,
        &bad_cert,
        &selected_slots,
        now,
    )
    .is_err();
    let reject_noncanonical_ms = noncanonical_make_ms + start.elapsed().as_secs_f64() * 1000.0;
    require(
        noncanonical_rejected,
        format!("run {run_id}: non-canonical request accepted"),
    )?;

    let mut corrupted_ms = None;
    let mut corrupted_reason = None;
    let mut corrupted_outcome = None;
    let mut corrupted_fresh_execution_authorized = None;
    let mut corrupted_settlement_authorization_issued = None;
    if !args.skip_corruption_check {
        let mut bad_slot = slot.clone();
        let first = bad_slot
            .presentation
            .proof
            .responses
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "empty proof response set".to_string())?;
        let old = bad_slot.presentation.proof.responses[&first];
        bad_slot
            .presentation
            .proof
            .responses
            .insert(first, old + Scalar::ONE);
        let bad_proof_request = make_redeem_request(service.clone(), bad_slot);
        let ((bad_proof_result, bad_proof_reason), elapsed) = timed(|| {
            RedemptionService::new_ephemeral(wallet.issuance.verifier.clone(), taxonomy.key.pk)
                .redeem(&bad_proof_request, now)
        });
        let bad_proof_semantics = ControlledRedemptionOutcome::parse(
            &format!("run {run_id}: corrupted proof"),
            bad_proof_result,
            &bad_proof_reason,
        )?;
        corrupted_ms = Some(elapsed);
        let reason = bad_proof_reason["reason"]
            .as_str()
            .unwrap_or("")
            .to_string();
        corrupted_reason = Some(reason.clone());
        corrupted_outcome = Some(bad_proof_semantics.outcome.clone());
        corrupted_fresh_execution_authorized = Some(bad_proof_semantics.fresh_execution_authorized);
        corrupted_settlement_authorization_issued =
            Some(bad_proof_semantics.settlement_authorization_issued);
        require(
            bad_proof_semantics.is_rejected(),
            format!("run {run_id}: corrupted proof was not rejected: {bad_proof_reason}"),
        )?;
    }

    let (
        merchant_proof_bytes,
        redemption_proof_bytes,
        redeem_request_bytes,
        merchant_disclosed_fields,
        redemption_disclosed_fields,
        slot_serial_count,
        slot_serial_bytes,
    ) = proof_sizes(&service, &slot, &redeem_request);

    Ok(RunRow {
        run: run_id,
        curve: "halo2curves.bls12381".to_string(),
        credential_backend:
            "pairing-based MinMandate credential prototype, not CFRG/W3C wire encoding".to_string(),
        classes: classes.join(","),
        slots,
        spend_slots,
        amount: args.amount,
        serial_derivation: "G1 PRF from hidden subtask seed".to_string(),
        pairing_optimization:
            "G2 aggregate proof encoding plus service/slot multi-pairing verification".to_string(),
        auxiliary_signature_backend: "Schnorr over BLS12-381 G1".to_string(),
        prf_seed_scalars_stored: 1,
        legacy_random_serial_scalars: slots,
        serial_storage_saved_scalars: slots.saturating_sub(1),
        credential_bytes,
        experiment_variant: variant.as_str().to_string(),
        stable_issuer_handle_disclosed: !variant.hide_issuer(),
        setup_ms,
        issue_ms,
        merchant_request_ms,
        presentation_ms,
        merchant_verify_ms,
        redeem_valid_ms,
        redeem_idempotent_retry_ms,
        redeem_bad_bind_ms,
        reject_noncanonical_ms,
        redeem_corrupted_proof_ms: corrupted_ms,
        valid_redemption: valid_semantics.is_fresh_accept(),
        valid_outcome: valid_semantics.outcome,
        valid_fresh_execution_authorized: valid_semantics.fresh_execution_authorized,
        valid_settlement_authorization_issued: valid_semantics.settlement_authorization_issued,
        same_randomized_issuer_key,
        idempotent_retry_status,
        idempotent_retry_outcome: retry_semantics.outcome,
        idempotent_retry_fresh_execution_authorized: retry_semantics.fresh_execution_authorized,
        idempotent_retry_settlement_authorization_issued: retry_semantics
            .settlement_authorization_issued,
        bad_bind_reason: bad_bind_reason_s,
        bad_bind_outcome: bad_bind_semantics.outcome,
        bad_bind_fresh_execution_authorized: bad_bind_semantics.fresh_execution_authorized,
        bad_bind_settlement_authorization_issued: bad_bind_semantics
            .settlement_authorization_issued,
        replay_fresh_execution_authorized: retry_semantics.fresh_execution_authorized,
        noncanonical_rejected,
        corrupted_proof_reason: corrupted_reason,
        corrupted_proof_outcome: corrupted_outcome,
        corrupted_proof_fresh_execution_authorized: corrupted_fresh_execution_authorized,
        corrupted_proof_settlement_authorization_issued: corrupted_settlement_authorization_issued,
        merchant_proof_bytes,
        redemption_proof_bytes,
        redeem_request_bytes,
        merchant_disclosed_fields,
        redemption_disclosed_fields,
        slot_serial_count,
        slot_serial_bytes,
    })
}

fn build_race_requests(
    args: &Args,
    concurrency: usize,
) -> Result<(Vec<RedeemRequest>, CredentialVerifier, G1)> {
    let slots = args.slots.max(args.spend_slots);
    let classes = args.classes.clone();
    let capacities = vec![args.amount; slots];
    let slot_classes = vec![classes[0].clone(); slots];
    let slot_merchants = vec!["merchant-race".to_string(); slots];
    let selected_slots = (0..args.spend_slots).collect::<Vec<_>>();
    let now = 1u64;
    let (user, wallet, taxonomy) = build_system(slots, &classes);
    let (holder, _meta) = issue_task_credential(
        &user,
        &wallet,
        &classes,
        &capacities,
        &slot_classes,
        &slot_merchants,
        now + args.expiry_delta,
        capacities.iter().sum(),
    )?;
    let merchant = Merchant {
        merchant_id: slot_merchants[0].clone(),
        key: SchnorrKey::new(),
    };
    let mut requests = Vec::with_capacity(concurrency);
    for worker in 0..concurrency {
        let service_id = format!("company-profile-race-{worker}");
        let input_digest = service_input_digest(&default_service_input(&service_id, &classes[0]));
        let (q, preq, challenge, cert) = merchant_request(
            &merchant,
            &taxonomy,
            &service_id,
            &classes[0],
            &input_digest,
            args.amount * args.spend_slots as u64,
            now,
            false,
        );
        let (service, slot) = derive_presentations(
            &holder,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &merchant,
            &q,
            &preq,
            &challenge,
            &cert,
            &selected_slots,
            now,
        )?;
        requests.push(make_redeem_request(service, slot));
    }
    Ok((requests, wallet.issuance.verifier.clone(), taxonomy.key.pk))
}

fn run_double_spend_race_one(run_id: usize, args: &Args, concurrency: usize) -> Result<RaceRow> {
    let (redeem_requests, verifier, taxonomy_pk) = build_race_requests(args, concurrency)?;
    let redemption = Arc::new(Mutex::new(RedemptionService::new_ephemeral(
        verifier,
        taxonomy_pk,
    )));
    let barrier = Arc::new(Barrier::new(concurrency));
    let mut handles = Vec::new();

    for (worker, req) in redeem_requests.into_iter().enumerate() {
        let service = Arc::clone(&redemption);
        let start = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            start.wait();
            let t0 = Instant::now();
            let (accepted, receipt) = service
                .lock()
                .expect("redemption lock poisoned")
                .redeem(&req, 1);
            let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
            let reason = if accepted {
                "accepted".to_string()
            } else {
                receipt["reason"].as_str().unwrap_or("unknown").to_string()
            };
            (worker, accepted, reason, elapsed)
        }));
    }

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut double_spend_rejected = 0usize;
    let mut other_rejected = 0usize;
    let mut latencies = Vec::new();
    let mut rejected_latencies = Vec::new();
    let mut accepted_latency_ms = 0.0;
    for handle in handles {
        let (_worker, ok, reason, elapsed) = handle
            .join()
            .map_err(|_| "race worker panicked".to_string())?;
        latencies.push(elapsed);
        if ok {
            accepted += 1;
            accepted_latency_ms = elapsed;
        } else {
            rejected += 1;
            rejected_latencies.push(elapsed);
            if reason == "double-spend" {
                double_spend_rejected += 1;
            } else {
                other_rejected += 1;
            }
        }
    }

    let linearizable =
        accepted == 1 && rejected == concurrency.saturating_sub(1) && other_rejected == 0;
    require(
        linearizable,
        format!(
            "race run {run_id}: expected exactly one accept and only double-spend rejects, got accepted={accepted}, rejected={rejected}, other={other_rejected}"
        ),
    )?;
    let max_latency_ms = latencies
        .iter()
        .copied()
        .fold(0.0_f64, |acc, value| acc.max(value));
    Ok(RaceRow {
        run: run_id,
        concurrency,
        accepted,
        rejected,
        double_spend_rejected,
        other_rejected,
        median_latency_ms: percentile(latencies.clone(), 0.5),
        p95_latency_ms: percentile(latencies.clone(), 0.95),
        max_latency_ms,
        accepted_latency_ms,
        loser_median_latency_ms: percentile(rejected_latencies, 0.5),
        elapsed_ms: max_latency_ms,
        state_backend: "in-memory serial set".to_string(),
        locking_mechanism: "Arc<Mutex<RedemptionService>>".to_string(),
        linearizable,
    })
}

fn workflow_templates() -> Vec<(&'static str, &'static str, &'static str, u64)> {
    vec![
        ("business-profile", "business", "merchant-profile", 5),
        ("patent-search", "patent", "merchant-patent", 5),
        ("litigation-search", "litigation", "merchant-litigation", 5),
        ("security-scan", "security", "merchant-security", 5),
    ]
}

fn builtin_workflow_trace() -> PlannerTrace {
    let calls = workflow_templates()
        .into_iter()
        .map(
            |(service_id, class_name, merchant, amount)| PlannerTraceCall {
                service_id: service_id.to_string(),
                class_name: class_name.to_string(),
                merchant: merchant.to_string(),
                amount,
                service_input: json!({
                    "workflow": "company-diligence",
                    "target": "Company X",
                    "service": service_id,
                    "class": class_name,
                }),
            },
        )
        .collect::<Vec<_>>();
    PlannerTrace {
        trace_id: "company-diligence".to_string(),
        task: "Evaluate Company X as an acquisition target.".to_string(),
        planner: json!({
            "source": "built-in deterministic workflow template",
            "mode": "artifact fixture",
        }),
        calls,
    }
}

fn baseline_handle_fields() -> [&'static str; 6] {
    [
        "wallet_id",
        "mandate_id",
        "issuer_key",
        "funding_ref",
        "payment_session",
        "receipt_handle",
    ]
}

fn json_has_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(map) => {
            map.contains_key(key) || map.values().any(|child| json_has_key(child, key))
        }
        Value::Array(items) => items.iter().any(|child| json_has_key(child, key)),
        _ => false,
    }
}

fn reusable_handle_count(payload: &Value) -> usize {
    baseline_handle_fields()
        .iter()
        .filter(|name| json_has_key(payload, name))
        .count()
}

fn baseline_payment_payload(
    signer: &SchnorrKey,
    wallet: &WalletRuntime,
    _verifier: &CredentialVerifier,
    mandate_id: &str,
    workflow: &str,
    call_index: usize,
    q: &Query,
    preq: &PaymentRequest,
) -> Value {
    let body = json!({
        "profile": "direct-signed-agentic-payment",
        "wallet_id": commitment_digest("baseline-wallet", &json!(scalar_hex(&wallet.wallet_id))),
        "mandate_id": mandate_id,
        "issuer_key": credential_key_digest(&wallet.issuance.issuer_pk),
        "funding_ref": wallet.funding_epoch.clone(),
        "payment_session": format!("{workflow}:payment-session"),
        "receipt_handle": format!("{workflow}:receipt"),
        "call_index": call_index,
        "service_input_digest": q.service_input_digest.clone(),
        "typed_request_digest": q.digest.clone(),
        "query": q.to_value(),
        "payment_request": preq.to_value(),
    });
    json!({
        "body": body,
        "signature": signer.sign(&body).to_value(),
    })
}

fn trace_class_universe(trace: &PlannerTrace) -> Vec<String> {
    let mut classes = BTreeSet::new();
    for class in DEFAULT_CLASSES {
        classes.insert((*class).to_string());
    }
    for call in &trace.calls {
        classes.insert(call.class_name.clone());
    }
    classes.into_iter().collect()
}

fn run_planner_trace(trace: &PlannerTrace) -> Result<Vec<WorkflowTraceRow>> {
    if trace.calls.is_empty() {
        return Err("planner trace contains no calls".to_string());
    }
    let classes = trace_class_universe(trace);
    let capacities = trace
        .calls
        .iter()
        .map(|call| call.amount)
        .collect::<Vec<_>>();
    let slot_classes = trace
        .calls
        .iter()
        .map(|call| call.class_name.clone())
        .collect::<Vec<_>>();
    let slot_merchants = trace
        .calls
        .iter()
        .map(|call| call.merchant.clone())
        .collect::<Vec<_>>();
    let now = 1u64;
    let (user, wallet, taxonomy) = build_system(trace.calls.len(), &classes);
    let (holder, issue_meta) = issue_task_credential(
        &user,
        &wallet,
        &classes,
        &capacities,
        &slot_classes,
        &slot_merchants,
        now + 100,
        capacities.iter().sum(),
    )?;
    let mandate_id = commitment_digest("baseline-mandate", &issue_meta["mandate"]);
    let mut redemption =
        RedemptionService::new_ephemeral(wallet.issuance.verifier.clone(), taxonomy.key.pk);
    let baseline_handles = baseline_handle_fields();
    let one_time_handles = ["serial", "funding_tag", "bind"];
    let mut rows = Vec::new();

    for (index, call) in trace.calls.iter().enumerate() {
        let merchant = Merchant {
            merchant_id: call.merchant.clone(),
            key: SchnorrKey::new(),
        };
        let input_digest = service_input_digest(&call.service_input);
        let middleware_start = Instant::now();
        let ((q, preq, challenge, cert), merchant_request_ms) = timed(|| {
            merchant_request(
                &merchant,
                &taxonomy,
                &call.service_id,
                &call.class_name,
                &input_digest,
                call.amount,
                now + index as u64,
                false,
            )
        });
        let (presentation_result, proof_generation_ms) = timed(|| {
            derive_presentations(
                &holder,
                &wallet.issuance.verifier,
                &taxonomy.key.pk,
                &merchant,
                &q,
                &preq,
                &challenge,
                &cert,
                &[index],
                now + index as u64,
            )
        });
        let (service, slot) = presentation_result?;
        let baseline_payload = baseline_payment_payload(
            &user.key,
            &wallet,
            &wallet.issuance.verifier,
            &mandate_id,
            &trace.trace_id,
            index + 1,
            &q,
            &preq,
        );
        require(
            service.q.digest == q.digest,
            format!("workflow call {}: request digest mismatch", index + 1),
        )?;
        let atom_count = service_policy_atoms().len();
        require(
            service_policy_atoms()
                .iter()
                .all(|atom| eval_policy_atom(atom, &service, &taxonomy.key.pk)),
            format!("workflow call {}: typed atom evaluation failed", index + 1),
        )?;
        let redeem_request = make_redeem_request(service.clone(), slot.clone());
        let ((valid_redemption, receipt), redemption_verify_ms) =
            timed(|| redemption.redeem(&redeem_request, now + index as u64));
        require(
            valid_redemption,
            format!("workflow call {}: redemption failed: {receipt}", index + 1),
        )?;
        let middleware_ms = middleware_start.elapsed().as_secs_f64() * 1000.0;
        let (
            merchant_proof_bytes,
            redemption_proof_bytes,
            redeem_request_bytes,
            _merchant_disclosed_fields,
            _redemption_disclosed_fields,
            _slot_serial_count,
            _slot_serial_bytes,
        ) = proof_sizes(&service, &slot, &redeem_request);
        let baseline_handle_count = reusable_handle_count(&baseline_payload);
        let minmandate_handle_count = reusable_handle_count(&redeem_request.to_value());

        rows.push(WorkflowTraceRow {
            call: index + 1,
            workflow: trace.trace_id.clone(),
            service_id: call.service_id.clone(),
            class_name: call.class_name.clone(),
            merchant: call.merchant.clone(),
            service_input_digest: input_digest.clone(),
            amount: call.amount,
            selected_slot: index,
            valid_redemption,
            policy_atoms_checked: atom_count,
            baseline_reusable_handles: baseline_handle_count,
            minmandate_reusable_handles: minmandate_handle_count,
            one_time_redemption_handles: one_time_handles.len(),
            baseline_reusable_handle_names: baseline_handles.join("|"),
            minmandate_one_time_handle_names: one_time_handles.join("|"),
            baseline_payload_bytes: json_size(&baseline_payload),
            merchant_sees_service_input: true,
            redemption_sees_service_input: false,
            merchant_request_ms,
            proof_generation_ms,
            redemption_verify_ms,
            middleware_ms,
            merchant_proof_bytes,
            redemption_proof_bytes,
            redeem_request_bytes,
        });

        require(!input_digest.is_empty(), "empty service input digest")?;
    }

    Ok(rows)
}

fn run_workflow_trace() -> Result<Vec<WorkflowTraceRow>> {
    run_planner_trace(&builtin_workflow_trace())
}

fn value_string(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("missing or non-string field `{key}`"))
}

fn value_u64(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or non-u64 field `{key}`"))
}

fn parse_planner_trace(value: &Value) -> Result<PlannerTrace> {
    let trace_id = value_string(value, "trace_id")?;
    let task = value_string(value, "task")?;
    let planner = value.get("planner").cloned().unwrap_or_else(|| json!({}));
    let calls_value = value
        .get("calls")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing or non-array field `calls`".to_string())?;
    let mut calls = Vec::new();
    for (index, call) in calls_value.iter().enumerate() {
        let service_input = call
            .get("service_input")
            .cloned()
            .ok_or_else(|| format!("call {} missing `service_input`", index + 1))?;
        calls.push(PlannerTraceCall {
            service_id: value_string(call, "service_id")?,
            class_name: value_string(call, "class")?,
            merchant: value_string(call, "merchant")?,
            amount: value_u64(call, "amount")?,
            service_input,
        });
    }
    Ok(PlannerTrace {
        trace_id,
        task,
        planner,
        calls,
    })
}

fn read_planner_trace(path: &PathBuf) -> Result<PlannerTrace> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse planner trace {}: {e}", path.display()))?;
    parse_planner_trace(&value)
}

fn percentile(mut values: Vec<f64>, q: f64) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if values.len() == 1 {
        return values[0];
    }
    let pos = (values.len() as f64 - 1.0) * q;
    let lower = pos.floor() as usize;
    let upper = (lower + 1).min(values.len() - 1);
    let weight = pos - lower as f64;
    values[lower] * (1.0 - weight) + values[upper] * weight
}

fn metric_summary(values: Vec<f64>) -> Value {
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let mut sorted = values.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    json!({
        "mean": mean,
        "median": percentile(values.clone(), 0.5),
        "p95": percentile(values.clone(), 0.95),
        "min": sorted[0],
        "max": sorted[sorted.len() - 1],
    })
}

fn summarize(rows: &[RunRow]) -> Value {
    let metrics: Vec<(&str, Box<dyn Fn(&RunRow) -> Option<f64>>)> = vec![
        ("setup_ms", Box::new(|r| Some(r.setup_ms))),
        ("issue_ms", Box::new(|r| Some(r.issue_ms))),
        (
            "merchant_request_ms",
            Box::new(|r| Some(r.merchant_request_ms)),
        ),
        ("presentation_ms", Box::new(|r| Some(r.presentation_ms))),
        (
            "merchant_verify_ms",
            Box::new(|r| Some(r.merchant_verify_ms)),
        ),
        ("redeem_valid_ms", Box::new(|r| Some(r.redeem_valid_ms))),
        (
            "redeem_idempotent_retry_ms",
            Box::new(|r| Some(r.redeem_idempotent_retry_ms)),
        ),
        (
            "redeem_bad_bind_ms",
            Box::new(|r| Some(r.redeem_bad_bind_ms)),
        ),
        (
            "reject_noncanonical_ms",
            Box::new(|r| Some(r.reject_noncanonical_ms)),
        ),
        (
            "redeem_corrupted_proof_ms",
            Box::new(|r| r.redeem_corrupted_proof_ms),
        ),
        (
            "merchant_proof_bytes",
            Box::new(|r| Some(r.merchant_proof_bytes as f64)),
        ),
        (
            "redemption_proof_bytes",
            Box::new(|r| Some(r.redemption_proof_bytes as f64)),
        ),
        (
            "redeem_request_bytes",
            Box::new(|r| Some(r.redeem_request_bytes as f64)),
        ),
        (
            "credential_bytes",
            Box::new(|r| Some(r.credential_bytes as f64)),
        ),
        (
            "serial_storage_saved_scalars",
            Box::new(|r| Some(r.serial_storage_saved_scalars as f64)),
        ),
    ];
    let mut out = Map::new();
    for (name, f) in metrics {
        let values = rows.iter().filter_map(f).collect::<Vec<_>>();
        if !values.is_empty() {
            out.insert(name.to_string(), metric_summary(values));
        }
    }
    Value::Object(out)
}

fn summarize_by_config(rows: &[RunRow]) -> Value {
    let mut configs = BTreeMap::<(usize, usize), Vec<RunRow>>::new();
    for row in rows {
        configs
            .entry((row.slots, row.spend_slots))
            .or_default()
            .push(row.clone());
    }
    let mut out = Map::new();
    for ((slots, spend_slots), config_rows) in configs {
        out.insert(
            format!("slots={slots},spend_slots={spend_slots}"),
            summarize(&config_rows),
        );
    }
    Value::Object(out)
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn write_outputs(rows: &[RunRow], output_dir: &PathBuf) -> Result<()> {
    fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;
    let payload = json!({
        "description": "Real MinMandate/MMCred Rust reference experiment: no simulated signatures, proofs, or verifier outcomes.",
        "rows": rows.iter().map(RunRow::to_value).collect::<Vec<_>>(),
        "summary": summarize(rows),
        "summary_by_config": summarize_by_config(rows),
    });
    fs::write(
        output_dir.join("latest-rust.json"),
        serde_json::to_vec_pretty(&payload).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let header = [
        "run",
        "curve",
        "credential_backend",
        "classes",
        "slots",
        "spend_slots",
        "amount",
        "serial_derivation",
        "pairing_optimization",
        "auxiliary_signature_backend",
        "prf_seed_scalars_stored",
        "legacy_random_serial_scalars",
        "serial_storage_saved_scalars",
        "credential_bytes",
        "experiment_variant",
        "stable_issuer_handle_disclosed",
        "setup_ms",
        "issue_ms",
        "merchant_request_ms",
        "presentation_ms",
        "merchant_verify_ms",
        "redeem_valid_ms",
        "redeem_idempotent_retry_ms",
        "redeem_bad_bind_ms",
        "reject_noncanonical_ms",
        "redeem_corrupted_proof_ms",
        "valid_redemption",
        "valid_outcome",
        "valid_fresh_execution_authorized",
        "valid_settlement_authorization_issued",
        "same_randomized_issuer_key",
        "idempotent_retry_status",
        "idempotent_retry_outcome",
        "idempotent_retry_fresh_execution_authorized",
        "idempotent_retry_settlement_authorization_issued",
        "bad_bind_reason",
        "bad_bind_outcome",
        "bad_bind_fresh_execution_authorized",
        "bad_bind_settlement_authorization_issued",
        "replay_fresh_execution_authorized",
        "noncanonical_rejected",
        "corrupted_proof_reason",
        "corrupted_proof_outcome",
        "corrupted_proof_fresh_execution_authorized",
        "corrupted_proof_settlement_authorization_issued",
        "merchant_proof_bytes",
        "redemption_proof_bytes",
        "redeem_request_bytes",
        "merchant_disclosed_fields",
        "redemption_disclosed_fields",
        "slot_serial_count",
        "slot_serial_bytes",
    ];
    let mut csv = String::new();
    csv.push_str(&header.join(","));
    csv.push('\n');
    for row in rows {
        csv.push_str(
            &row.csv_values()
                .iter()
                .map(|v| csv_escape(v))
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    fs::write(output_dir.join("latest-rust.csv"), csv).map_err(|e| e.to_string())?;
    Ok(())
}

fn summarize_workflow_trace(rows: &[WorkflowTraceRow]) -> Value {
    let total_payload_bytes = rows.iter().map(|r| r.redeem_request_bytes).sum::<usize>();
    let total_baseline_payload_bytes = rows.iter().map(|r| r.baseline_payload_bytes).sum::<usize>();
    let total_middleware_ms = rows.iter().map(|r| r.middleware_ms).sum::<f64>();
    let total_proof_generation_ms = rows.iter().map(|r| r.proof_generation_ms).sum::<f64>();
    let total_redemption_verify_ms = rows.iter().map(|r| r.redemption_verify_ms).sum::<f64>();
    let all_valid = rows.iter().all(|r| r.valid_redemption);
    let success_rate = if rows.is_empty() {
        0.0
    } else {
        rows.iter().filter(|r| r.valid_redemption).count() as f64 / rows.len() as f64
    };
    let min_baseline_handles = rows
        .iter()
        .map(|r| r.baseline_reusable_handles)
        .min()
        .unwrap_or(0);
    let max_mm_handles = rows
        .iter()
        .map(|r| r.minmandate_reusable_handles)
        .max()
        .unwrap_or(0);
    json!({
        "calls": rows.len(),
        "all_redemptions_accepted": all_valid,
        "success_rate": success_rate,
        "total_middleware_ms": total_middleware_ms,
        "total_proof_generation_ms": total_proof_generation_ms,
        "total_redemption_verify_ms": total_redemption_verify_ms,
        "baseline_reusable_handles_per_call": min_baseline_handles,
        "minmandate_reusable_handles_per_call": max_mm_handles,
        "one_time_redemption_handles_per_call": rows.first().map(|r| r.one_time_redemption_handles).unwrap_or(0),
        "redemption_sees_service_input": rows.iter().any(|r| r.redemption_sees_service_input),
        "total_baseline_payload_bytes": total_baseline_payload_bytes,
        "total_redeem_request_bytes": total_payload_bytes,
    })
}

fn write_workflow_trace_outputs(rows: &[WorkflowTraceRow], output_dir: &PathBuf) -> Result<()> {
    fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;
    let payload = json!({
        "description": "Concrete four-call Company-diligence workflow trace generated by the Rust MinMandate artifact.",
        "scope": "Each row runs real credential issuance, merchant-proof and joint-redemption-proof generation, typed policy-atom evaluation, redemption verification, one-time serial insertion, and funding-tag checks. The baseline is a concrete signed direct-payment payload serialized from the same request records; it is a field and payload baseline, not a separate payment-rail implementation.",
        "rows": rows.iter().map(WorkflowTraceRow::to_value).collect::<Vec<_>>(),
        "summary": summarize_workflow_trace(rows),
    });
    fs::write(
        output_dir.join("latest-workflow.json"),
        serde_json::to_vec_pretty(&payload).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    let header = [
        "call",
        "workflow",
        "service_id",
        "class",
        "merchant",
        "service_input_digest",
        "amount",
        "selected_slot",
        "valid_redemption",
        "policy_atoms_checked",
        "baseline_reusable_handles",
        "minmandate_reusable_handles",
        "one_time_redemption_handles",
        "baseline_reusable_handle_names",
        "minmandate_one_time_handle_names",
        "baseline_payload_bytes",
        "merchant_sees_service_input",
        "redemption_sees_service_input",
        "merchant_request_ms",
        "proof_generation_ms",
        "redemption_verify_ms",
        "middleware_ms",
        "merchant_proof_bytes",
        "redemption_proof_bytes",
        "redeem_request_bytes",
    ];
    let mut csv = String::new();
    csv.push_str(&header.join(","));
    csv.push('\n');
    for row in rows {
        csv.push_str(
            &row.csv_values()
                .iter()
                .map(|v| csv_escape(v))
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    fs::write(output_dir.join("latest-workflow.csv"), csv).map_err(|e| e.to_string())?;
    Ok(())
}

fn write_planner_trace_outputs(
    trace: &PlannerTrace,
    rows: &[WorkflowTraceRow],
    output_dir: &PathBuf,
) -> Result<()> {
    fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;
    let payload = json!({
        "description": "Record-and-replay LLM-planner paid-tool trace executed by the Rust MinMandate artifact.",
        "scope": "The planner output is read from a recorded JSON trace. The runner does not call an online LLM API; it replays the normalized paid-tool calls through real credential issuance, merchant-proof and joint-redemption-proof generation, typed policy-atom evaluation, redemption verification, one-time serial insertion, and funding-tag checks.",
        "trace": {
            "trace_id": trace.trace_id,
            "task": trace.task,
            "planner": trace.planner,
            "recorded_calls": trace.calls.len(),
        },
        "rows": rows.iter().map(WorkflowTraceRow::to_value).collect::<Vec<_>>(),
        "summary": summarize_workflow_trace(rows),
    });
    fs::write(
        output_dir.join("latest-planner-trace.json"),
        serde_json::to_vec_pretty(&payload).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    let header = [
        "call",
        "workflow",
        "service_id",
        "class",
        "merchant",
        "service_input_digest",
        "amount",
        "selected_slot",
        "valid_redemption",
        "policy_atoms_checked",
        "baseline_reusable_handles",
        "minmandate_reusable_handles",
        "one_time_redemption_handles",
        "baseline_reusable_handle_names",
        "minmandate_one_time_handle_names",
        "baseline_payload_bytes",
        "merchant_sees_service_input",
        "redemption_sees_service_input",
        "merchant_request_ms",
        "proof_generation_ms",
        "redemption_verify_ms",
        "middleware_ms",
        "merchant_proof_bytes",
        "redemption_proof_bytes",
        "redeem_request_bytes",
    ];
    let mut csv = String::new();
    csv.push_str(&header.join(","));
    csv.push('\n');
    for row in rows {
        csv.push_str(
            &row.csv_values()
                .iter()
                .map(|v| csv_escape(v))
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    fs::write(output_dir.join("latest-planner-trace.csv"), csv).map_err(|e| e.to_string())?;
    Ok(())
}

fn summarize_issuer_auth(rows: &[IssuerAuthRow]) -> Value {
    let metrics: Vec<(&str, Box<dyn Fn(&IssuerAuthRow) -> Option<f64>>)> = vec![
        ("registry_setup_ms", Box::new(|r| Some(r.registry_setup_ms))),
        ("auth_issue_ms", Box::new(|r| Some(r.auth_issue_ms))),
        ("auth_present_ms", Box::new(|r| Some(r.auth_present_ms))),
        ("auth_verify_ms", Box::new(|r| Some(r.auth_verify_ms))),
        ("revoked_reject_ms", Box::new(|r| Some(r.revoked_reject_ms))),
        (
            "auth_proof_bytes",
            Box::new(|r| Some(r.auth_proof_bytes as f64)),
        ),
    ];
    let mut out = Map::new();
    for (name, f) in metrics {
        let values = rows.iter().filter_map(f).collect::<Vec<_>>();
        if !values.is_empty() {
            out.insert(name.to_string(), metric_summary(values));
        }
    }
    Value::Object(out)
}

fn summarize_issuer_auth_by_size(rows: &[IssuerAuthRow]) -> Value {
    let mut configs = BTreeMap::<usize, Vec<IssuerAuthRow>>::new();
    for row in rows {
        configs
            .entry(row.registry_size)
            .or_default()
            .push(row.clone());
    }
    let mut out = Map::new();
    for (registry_size, config_rows) in configs {
        out.insert(
            format!("registry_size={registry_size}"),
            summarize_issuer_auth(&config_rows),
        );
    }
    Value::Object(out)
}

fn write_issuer_auth_outputs(rows: &[IssuerAuthRow], output_dir: &PathBuf) -> Result<()> {
    fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;
    let payload = json!({
        "description": "Hidden issuer authorization microbenchmark over BLS12-381 with policy-only verifier state.",
        "scope": "This is a subrelation microbenchmark for issuer-hidden authorization. It does not expose the wallet issuer signing scalar, is not a W3C/CFRG wire encoding, and is not a dynamic accumulator witness-update benchmark.",
        "rows": rows.iter().map(IssuerAuthRow::to_value).collect::<Vec<_>>(),
        "summary": summarize_issuer_auth(rows),
        "summary_by_registry_size": summarize_issuer_auth_by_size(rows),
    });
    fs::write(
        output_dir.join("latest-issuer-auth.json"),
        serde_json::to_vec_pretty(&payload).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let header = [
        "run",
        "registry_size",
        "revoked_size",
        "registry_setup_ms",
        "auth_issue_ms",
        "auth_present_ms",
        "auth_verify_ms",
        "revoked_reject_ms",
        "auth_proof_bytes",
        "auth_disclosed_fields",
        "auth_hidden_fields",
        "auth_g1_relations",
        "auth_pairing_terms",
        "auth_valid",
        "revoked_rejected",
        "backend",
    ];
    let mut csv = String::new();
    csv.push_str(&header.join(","));
    csv.push('\n');
    for row in rows {
        csv.push_str(
            &row.csv_values()
                .iter()
                .map(|v| csv_escape(v))
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    fs::write(output_dir.join("latest-issuer-auth.csv"), csv).map_err(|e| e.to_string())?;
    Ok(())
}

fn summarize_redaction(rows: &[RedactionRow]) -> Value {
    let metrics: Vec<(&str, Box<dyn Fn(&RedactionRow) -> Option<f64>>)> = vec![
        ("commit_ms", Box::new(|r| Some(r.commit_ms))),
        ("prove_ms", Box::new(|r| Some(r.prove_ms))),
        ("verify_ms", Box::new(|r| Some(r.verify_ms))),
        ("proof_bytes", Box::new(|r| Some(r.proof_bytes as f64))),
        ("payload_bytes", Box::new(|r| Some(r.payload_bytes as f64))),
    ];
    let mut out = Map::new();
    for (name, f) in metrics {
        let values = rows.iter().filter_map(f).collect::<Vec<_>>();
        if !values.is_empty() {
            out.insert(name.to_string(), metric_summary(values));
        }
    }
    Value::Object(out)
}

fn summarize_redaction_by_hidden(rows: &[RedactionRow]) -> Value {
    let mut configs = BTreeMap::<usize, Vec<RedactionRow>>::new();
    for row in rows {
        configs
            .entry(row.hidden_fields)
            .or_default()
            .push(row.clone());
    }
    let mut out = Map::new();
    for (hidden_fields, config_rows) in configs {
        out.insert(
            format!("hidden_fields={hidden_fields}"),
            summarize_redaction(&config_rows),
        );
    }
    Value::Object(out)
}

fn write_redaction_outputs(rows: &[RedactionRow], output_dir: &PathBuf) -> Result<()> {
    fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;
    let payload = json!({
        "description": "Redacted redemption microbenchmark: BLS12-381 Pedersen vector commitment and Schnorr representation proof for a redacted fixed-schema paid-tool request.",
        "scope": "Measures only the request-redaction subproof used by the redacted redemption profile. It does not include merchant or redemption credential presentations or JSON canonical request parsing.",
        "rows": rows.iter().map(RedactionRow::to_value).collect::<Vec<_>>(),
        "summary": summarize_redaction(rows),
        "summary_by_hidden_fields": summarize_redaction_by_hidden(rows),
    });
    fs::write(
        output_dir.join("latest-redaction.json"),
        serde_json::to_vec_pretty(&payload).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let header = [
        "run",
        "hidden_fields",
        "disclosed_fields",
        "total_fields",
        "commit_ms",
        "prove_ms",
        "verify_ms",
        "proof_bytes",
        "payload_bytes",
        "proof_responses",
        "valid",
        "backend",
    ];
    let mut csv = String::new();
    csv.push_str(&header.join(","));
    csv.push('\n');
    for row in rows {
        csv.push_str(
            &row.csv_values()
                .iter()
                .map(|v| csv_escape(v))
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    fs::write(output_dir.join("latest-redaction.csv"), csv).map_err(|e| e.to_string())?;
    Ok(())
}

fn summarize_race(rows: &[RaceRow]) -> Value {
    json!({
        "runs": rows.len(),
        "all_linearizable": rows.iter().all(|row| row.linearizable),
        "max_concurrency": rows.iter().map(|row| row.concurrency).max().unwrap_or(0),
        "accepted_per_race": rows.iter().map(|row| row.accepted).collect::<Vec<_>>(),
        "median_latency_ms": metric_summary(rows.iter().map(|row| row.median_latency_ms).collect()),
        "p95_latency_ms": metric_summary(rows.iter().map(|row| row.p95_latency_ms).collect()),
    })
}

fn race_execution_manifest(args: &Args) -> Value {
    json!({
        "race_jobs": args.race_jobs,
        "default_race_jobs": DEFAULT_RACE_JOBS,
        "max_race_jobs": MAX_RACE_JOBS,
        "max_batch_contender_threads": MAX_RACE_CONTENDER_THREADS,
        "recommended_race_jobs_80_logical_cpus": RECOMMENDED_RACE_JOBS_80_LOGICAL_CPUS,
        "job_order": "concurrency-major/repetition-minor",
        "batching": "bounded-scoped-thread-batches",
        "row_and_progress_order": "canonical-job-order",
        "redemption_state_scope": "one-shared-service-per-individual-race",
        "contender_execution": "unchanged-per-race-atomicity",
        "race_concurrency": args.race_concurrency,
        "repetitions_per_concurrency": args.runs,
    })
}

fn write_race_outputs(rows: &[RaceRow], args: &Args) -> Result<()> {
    fs::create_dir_all(&args.output_dir).map_err(|e| e.to_string())?;
    let payload = json!({
        "description": "Concurrent double-spend race benchmark for the MinMandate redemption service.",
        "scope": "Each row submits the same valid redemption request concurrently to one in-memory linearizable redemption service. The test passes only if exactly one request is accepted and every other request is rejected as double-spend.",
        "manifest": race_execution_manifest(args),
        "rows": rows.iter().map(RaceRow::to_value).collect::<Vec<_>>(),
        "summary": summarize_race(rows),
    });
    fs::write(
        args.output_dir.join("latest-race.json"),
        serde_json::to_vec_pretty(&payload).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let header = [
        "run",
        "concurrency",
        "accepted",
        "rejected",
        "double_spend_rejected",
        "other_rejected",
        "median_latency_ms",
        "p95_latency_ms",
        "max_latency_ms",
        "accepted_latency_ms",
        "loser_median_latency_ms",
        "elapsed_ms",
        "state_backend",
        "locking_mechanism",
        "linearizable",
    ];
    let mut csv = String::new();
    csv.push_str(&header.join(","));
    csv.push('\n');
    for row in rows {
        csv.push_str(
            &row.csv_values()
                .iter()
                .map(|v| csv_escape(v))
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    fs::write(args.output_dir.join("latest-race.csv"), csv).map_err(|e| e.to_string())?;
    Ok(())
}

fn parse_usize_list(value: &str, flag: &str) -> Result<Vec<usize>> {
    let mut out = Vec::new();
    for item in value.split(',').filter(|s| !s.is_empty()) {
        let parsed = item
            .parse::<usize>()
            .map_err(|_| format!("bad {flag}: {item}"))?;
        if parsed == 0 {
            return Err(format!("{flag} entries must be positive"));
        }
        out.push(parsed);
    }
    if out.is_empty() {
        return Err(format!("{flag} needs at least one value"));
    }
    Ok(out)
}

fn parse_args() -> Result<Args> {
    let mut args = Args::default();
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--runs" => {
                args.runs = iter
                    .next()
                    .ok_or("--runs needs a value")?
                    .parse()
                    .map_err(|_| "bad --runs")?
            }
            "--slots" => {
                args.slots = iter
                    .next()
                    .ok_or("--slots needs a value")?
                    .parse()
                    .map_err(|_| "bad --slots")?
            }
            "--spend-slots" => {
                args.spend_slots = iter
                    .next()
                    .ok_or("--spend-slots needs a value")?
                    .parse()
                    .map_err(|_| "bad --spend-slots")?
            }
            "--matrix" => args.matrix = true,
            "--workflow-trace" => args.workflow_trace = true,
            "--planner-trace-file" => {
                args.planner_trace_file = Some(PathBuf::from(
                    iter.next().ok_or("--planner-trace-file needs a value")?,
                ))
            }
            "--issuer-bench" => args.issuer_bench = true,
            "--redaction-bench" => args.redaction_bench = true,
            "--race-bench" => args.race_bench = true,
            "--jsonl-server" => args.jsonl_server = true,
            "--native-client-validator" => args.native_client_validator = true,
            "--issuer-policy" => {
                args.issuer_policy = Some(PathBuf::from(
                    iter.next().ok_or("--issuer-policy needs a value")?,
                ))
            }
            "--issuer-registry-sizes" => {
                args.issuer_registry_sizes = parse_usize_list(
                    &iter.next().ok_or("--issuer-registry-sizes needs a value")?,
                    "--issuer-registry-sizes",
                )?;
            }
            "--redaction-hidden-fields" => {
                args.redaction_hidden_fields = parse_usize_list(
                    &iter
                        .next()
                        .ok_or("--redaction-hidden-fields needs a value")?,
                    "--redaction-hidden-fields",
                )?;
            }
            "--race-concurrency" => {
                args.race_concurrency = parse_usize_list(
                    &iter.next().ok_or("--race-concurrency needs a value")?,
                    "--race-concurrency",
                )?;
            }
            "--race-jobs" => {
                args.race_jobs = iter
                    .next()
                    .ok_or("--race-jobs needs a value")?
                    .parse()
                    .map_err(|_| "bad --race-jobs")?
            }
            "--redaction-disclosed-fields" => {
                args.redaction_disclosed_fields = iter
                    .next()
                    .ok_or("--redaction-disclosed-fields needs a value")?
                    .parse()
                    .map_err(|_| "bad --redaction-disclosed-fields")?
            }
            "--classes" => {
                args.classes = iter
                    .next()
                    .ok_or("--classes needs a value")?
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
            }
            "--amount" => {
                args.amount = iter
                    .next()
                    .ok_or("--amount needs a value")?
                    .parse()
                    .map_err(|_| "bad --amount")?
            }
            "--expiry-delta" => {
                args.expiry_delta = iter
                    .next()
                    .ok_or("--expiry-delta needs a value")?
                    .parse()
                    .map_err(|_| "bad --expiry-delta")?
            }
            "--output-dir" => {
                args.output_dir = PathBuf::from(iter.next().ok_or("--output-dir needs a value")?)
            }
            "--skip-corruption-check" => args.skip_corruption_check = true,
            "--experiment-variant" => {
                args.experiment_variant = iter
                    .next()
                    .ok_or("--experiment-variant needs a value")?
            }
            "--jobs" => {
                let _ = iter.next().ok_or("--jobs needs a value")?;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if args.runs == 0 || args.slots == 0 || args.spend_slots == 0 {
        return Err("runs, slots, and spend-slots must be positive".to_string());
    }
    if args.issuer_registry_sizes.is_empty() {
        return Err("issuer registry size list must not be empty".to_string());
    }
    if args.redaction_hidden_fields.is_empty() {
        return Err("redaction hidden field list must not be empty".to_string());
    }
    if args.race_concurrency.is_empty() {
        return Err("race concurrency list must not be empty".to_string());
    }
    if args.race_concurrency.iter().any(|&value| value < 2) {
        return Err("race concurrency entries must be at least 2".to_string());
    }
    if args
        .race_concurrency
        .iter()
        .any(|&value| value > MAX_RACE_CONTENDER_THREADS)
    {
        return Err(format!(
            "race concurrency entries must be at most {MAX_RACE_CONTENDER_THREADS}"
        ));
    }
    if !(1..=MAX_RACE_JOBS).contains(&args.race_jobs) {
        return Err(format!("--race-jobs must be between 1 and {MAX_RACE_JOBS}"));
    }
    if args.redaction_disclosed_fields == 0 {
        return Err("redaction disclosed field count must be positive".to_string());
    }
    if args.spend_slots > args.slots {
        return Err("spend-slots cannot exceed slots".to_string());
    }
    if args.classes.is_empty() {
        args.classes = DEFAULT_CLASSES.iter().map(|s| s.to_string()).collect();
    }
    BenchAblationVariant::parse(&args.experiment_variant)?;
    Ok(args)
}

fn experiment_configs(args: &Args) -> Vec<(usize, usize)> {
    if !args.matrix {
        return vec![(args.slots, args.spend_slots)];
    }
    [(8, 1), (8, 2), (16, 2), (16, 4), (32, 4), (64, 8)]
        .into_iter()
        .collect()
}

fn run_issuer_auth_cli(args: &Args) -> Result<()> {
    let total = args.issuer_registry_sizes.len() * args.runs;
    let mut rows = Vec::new();
    let mut run_id = 1;
    for registry_size in &args.issuer_registry_sizes {
        for repetition in 1..=args.runs {
            println!(
                "issuer-auth run {run_id}/{total}: registry_size={registry_size}, repetition={repetition}/{}",
                args.runs
            );
            rows.push(run_issuer_auth_one(run_id, *registry_size)?);
            run_id += 1;
        }
    }
    write_issuer_auth_outputs(&rows, &args.output_dir)?;
    println!(
        "wrote {} issuer-auth rows to {}",
        rows.len(),
        args.output_dir.join("latest-issuer-auth.json").display()
    );
    Ok(())
}

fn run_redaction_cli(args: &Args) -> Result<()> {
    let total = args.redaction_hidden_fields.len() * args.runs;
    let mut rows = Vec::new();
    let mut run_id = 1;
    for hidden_fields in &args.redaction_hidden_fields {
        for repetition in 1..=args.runs {
            println!(
                "redaction run {run_id}/{total}: hidden_fields={hidden_fields}, disclosed_fields={}, repetition={repetition}/{}",
                args.redaction_disclosed_fields,
                args.runs
            );
            rows.push(run_redaction_one(
                run_id,
                *hidden_fields,
                args.redaction_disclosed_fields,
            )?);
            run_id += 1;
        }
    }
    write_redaction_outputs(&rows, &args.output_dir)?;
    println!(
        "wrote {} redaction rows to {}",
        rows.len(),
        args.output_dir.join("latest-redaction.json").display()
    );
    Ok(())
}

fn run_race_cli(args: &Args) -> Result<()> {
    let jobs = materialize_race_jobs(args);
    let total = jobs.len();
    let rows = run_race_jobs(args, &jobs, |job, _row| {
        println!(
            "race run {}/{total}: concurrency={}, repetition={}/{} complete",
            job.run_id, job.concurrency, job.repetition, args.runs
        );
    })?;
    write_race_outputs(&rows, args)?;
    println!(
        "wrote {} race rows to {}",
        rows.len(),
        args.output_dir.join("latest-race.json").display()
    );
    Ok(())
}

pub fn run_cli() -> Result<()> {
    require_bmi2_adx_runtime()?;
    initialize_offline_child_process()?;
    if std::env::args().nth(1).as_deref() == Some("generate-issuer-policy") {
        let output = policy_io::run_generate_cli(std::env::args().skip(2))?;
        println!("{}", output.display());
        return Ok(());
    }
    let args = parse_args()?;
    if args.native_client_validator {
        if args.issuer_policy.is_some() {
            return Err("--issuer-policy is not valid with --native-client-validator".to_string());
        }
        return run_native_client_validator();
    }
    if args.jsonl_server {
        let path = args
            .issuer_policy
            .as_deref()
            .ok_or("--jsonl-server requires --issuer-policy")?;
        let policy = policy_io::load(path)?;
        return run_jsonl_server(&policy);
    }
    if args.issuer_policy.is_some() {
        return Err("--issuer-policy is only valid with --jsonl-server".to_string());
    }
    if let Some(path) = &args.planner_trace_file {
        let trace = read_planner_trace(path)?;
        let rows = run_planner_trace(&trace)?;
        write_planner_trace_outputs(&trace, &rows, &args.output_dir)?;
        println!(
            "wrote {} planner trace rows to {}",
            rows.len(),
            args.output_dir.join("latest-planner-trace.json").display()
        );
        return Ok(());
    }
    if args.workflow_trace {
        let rows = run_workflow_trace()?;
        write_workflow_trace_outputs(&rows, &args.output_dir)?;
        println!(
            "wrote {} workflow trace rows to {}",
            rows.len(),
            args.output_dir.join("latest-workflow.json").display()
        );
        return Ok(());
    }
    if args.issuer_bench {
        return run_issuer_auth_cli(&args);
    }
    if args.redaction_bench {
        return run_redaction_cli(&args);
    }
    if args.race_bench {
        return run_race_cli(&args);
    }
    let configs = experiment_configs(&args);
    let total = configs.len() * args.runs;
    let mut rows = Vec::new();
    let mut run_id = 1;
    for (slots, spend_slots) in configs {
        for repetition in 1..=args.runs {
            println!(
                "run {run_id}/{total}: slots={slots}, spend_slots={spend_slots}, repetition={repetition}/{}",
                args.runs
            );
            rows.push(run_one(run_id, &args, slots, spend_slots)?);
            run_id += 1;
        }
    }
    write_outputs(&rows, &args.output_dir)?;
    println!(
        "wrote {} rows to {}",
        rows.len(),
        args.output_dir.join("latest-rust.json").display()
    );
    Ok(())
}

#[cfg(all(feature = "bmi2-adx", target_arch = "x86_64"))]
fn require_bmi2_adx_runtime() -> Result<()> {
    if std::is_x86_feature_detected!("bmi2") && std::is_x86_feature_detected!("adx") {
        Ok(())
    } else {
        Err("bmi2-adx build requires CPU features BMI2 and ADX".to_string())
    }
}

#[cfg(not(all(feature = "bmi2-adx", target_arch = "x86_64")))]
fn require_bmi2_adx_runtime() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        HolderState,
        WalletRuntime,
        TaxonomyAuthority,
        ServicePresentation,
        SlotPresentation,
        RedeemRequest,
    ) {
        let classes = vec!["business".to_string()];
        let slot_merchants = vec!["merchant-a".to_string()];
        let (user, wallet, taxonomy) = build_system(1, &classes);
        let (holder, _) = issue_task_credential(
            &user,
            &wallet,
            &classes,
            &[5],
            &classes,
            &slot_merchants,
            100,
            5,
        )
        .unwrap();
        let merchant = Merchant {
            merchant_id: slot_merchants[0].clone(),
            key: SchnorrKey::new(),
        };
        let input_digest =
            service_input_digest(&default_service_input("company-profile", "business"));
        let (q, preq, challenge, cert) = merchant_request(
            &merchant,
            &taxonomy,
            "company-profile",
            "business",
            &input_digest,
            5,
            1,
            false,
        );
        let (service, slot) = derive_presentations(
            &holder,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &merchant,
            &q,
            &preq,
            &challenge,
            &cert,
            &[0],
            1,
        )
        .unwrap();
        let request = make_redeem_request(service.clone(), slot.clone());
        (holder, wallet, taxonomy, service, slot, request)
    }

    #[test]
    fn accepts_valid_request() {
        let (_, wallet, taxonomy, _, _, request) = fixture();
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        let (ok, receipt) = redemption.redeem(&request, 1);
        assert!(ok, "{receipt}");
    }

    #[test]
    fn workflow_trace_accepts_all_calls_and_removes_reusable_handles() {
        let rows = run_workflow_trace().unwrap();
        assert_eq!(rows.len(), 4);
        assert!(rows.iter().all(|row| row.valid_redemption));
        assert!(rows.iter().all(|row| row.baseline_reusable_handles == 6));
        assert!(rows.iter().all(|row| row.minmandate_reusable_handles == 0));
        assert!(rows.iter().all(|row| !row.service_input_digest.is_empty()));
        assert!(rows.iter().all(|row| row.baseline_payload_bytes > 0));
        assert!(rows
            .iter()
            .all(|row| row.policy_atoms_checked == service_policy_atoms().len()));
        assert!(rows.iter().all(|row| !row.redemption_sees_service_input));
    }

    #[test]
    fn recorded_planner_trace_replays_through_redemption() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("planner_traces/company_diligence_llm_recorded.json");
        let trace = read_planner_trace(&path).unwrap();
        let rows = run_planner_trace(&trace).unwrap();
        assert_eq!(rows.len(), trace.calls.len());
        assert!(rows.iter().all(|row| row.valid_redemption));
        assert!(rows.iter().all(|row| row.baseline_reusable_handles == 6));
        assert!(rows.iter().all(|row| row.minmandate_reusable_handles == 0));
        assert!(rows.iter().all(|row| !row.service_input_digest.is_empty()));
        assert!(rows.iter().all(|row| !row.redemption_sees_service_input));
    }

    #[test]
    fn identical_retry_is_idempotent() {
        let (_, wallet, taxonomy, _, _, request) = fixture();
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        let (first_ok, first_receipt) = redemption.redeem(&request, 1);
        let (retry_ok, retry_receipt) = redemption.redeem(&request, 1);
        assert!(first_ok);
        assert!(!retry_ok);
        assert_eq!(first_receipt["receipt_id"], retry_receipt["receipt_id"]);
        assert_eq!(first_receipt["outcome"], "fresh_accept");
        assert_eq!(retry_receipt["outcome"], "idempotent_receipt");
        assert_eq!(first_receipt["fresh_execution_authorized"], true);
        assert_eq!(retry_receipt["fresh_execution_authorized"], false);
        assert_eq!(retry_receipt["settlement_authorization_issued"], false);
        assert_eq!(first_receipt["idempotent_replay"], false);
        assert_eq!(retry_receipt["idempotent_replay"], true);
        assert_eq!(
            first_receipt["settlement_authorization"],
            retry_receipt["settlement_authorization"]
        );
    }

    #[test]
    fn exact_ihbbs1_adapt_preserves_bbs_validity() {
        let (holder, wallet, _, _, _, _) = fixture();
        let alpha = random_scalar();
        let (randomized_pk, adapted) = ihbbs1::adapt(
            &wallet.issuance.issuer_pk,
            &holder.credential.signature,
            alpha,
        )
        .unwrap();
        assert_eq!(
            randomized_pk.x_tilde,
            wallet.issuance.issuer_pk.x_tilde * alpha
        );
        assert_eq!(adapted.e, holder.credential.signature.e * alpha);
        let representative = bbs::commitment(
            &wallet.issuance.issuer_pk.params,
            &holder.credential.messages,
        )
        .unwrap();
        assert_eq!(
            adapted.a * (wallet.issuance.sk.x * alpha + adapted.e),
            representative
        );
        assert_eq!(wire::encode_g1(&adapted.a).len(), wire::G1_COMPRESSED_BYTES);
        assert_eq!(
            wire::encode_g2(&randomized_pk.x_tilde).len(),
            wire::G2_COMPRESSED_BYTES
        );
        assert!(bbs::verify(
            &randomized_pk,
            &adapted,
            &holder.credential.messages
        ));
        assert!(!bbs::verify(
            &randomized_pk,
            &holder.credential.signature,
            &holder.credential.messages
        ));
        assert!(ihbbs1::adapt(
            &wallet.issuance.issuer_pk,
            &holder.credential.signature,
            Scalar::ZERO,
        )
        .is_err());
    }

    #[test]
    fn capability_coordinates_match_the_manuscript_boundary() {
        let (holder, wallet, _, service, slot, _) = fixture();
        let message_names = &wallet.issuance.issuer_pk.params.message_names;
        let expected = [
            CREDENTIAL_ID_NAME.to_string(),
            serial_seed_name("business"),
            fund_seed_name("business"),
            BUDGET_NAME.to_string(),
            EXPIRY_NAME.to_string(),
            FUND_NAME.to_string(),
            auth_name("business"),
            scope_name("business"),
        ];
        for name in expected {
            assert!(message_names.contains(&name), "missing coordinate {name}");
            assert!(holder.messages.contains_key(&name), "missing value {name}");
        }
        for legacy in ["hsk", "mu", "iota", "sid"] {
            assert!(!message_names.iter().any(|name| name == legacy));
            assert!(!holder.messages.contains_key(legacy));
        }
        assert_eq!(holder.messages[BUDGET_NAME], Scalar::from(5u64));
        assert_eq!(holder.messages[EXPIRY_NAME], Scalar::from(100u64));
        assert_eq!(
            holder.messages[FUND_NAME],
            scalar_from_value(&json!(FINAL_V2_FUNDING_BUCKET))
        );
        assert_eq!(FINAL_V2_FUNDING_BUCKET, wallet.funding_epoch);
        assert_eq!(
            holder.messages[&slot_name(0, "merchant")],
            scalar_from_value(&json!("merchant-a"))
        );
        assert_eq!(
            holder.messages[&scope_name("business")],
            scalar_from_value(&json!({
                "service_class": "business",
                "authorized": true,
            }))
        );
        for hidden in [CREDENTIAL_ID_NAME.to_string(), FUND_NAME.to_string()] {
            assert!(!service
                .presentation
                .disclosed_messages
                .contains_key(&hidden));
            assert!(!slot.presentation.disclosed_messages.contains_key(&hidden));
        }
        assert_eq!(
            service.presentation.disclosed_messages[&scope_name("business")],
            holder.messages[&scope_name("business")]
        );
        assert_eq!(
            service.presentation.disclosed_messages[EXPIRY_NAME],
            holder.messages[EXPIRY_NAME]
        );
        for hidden in [EXPIRY_NAME.to_string(), scope_name("business")] {
            assert!(!slot.presentation.disclosed_messages.contains_key(&hidden));
        }
        assert!(!service
            .presentation
            .disclosed_messages
            .contains_key(BUDGET_NAME));
        assert_eq!(
            slot.presentation.disclosed_messages[BUDGET_NAME],
            Scalar::from(5u64)
        );
        let merchant_view = service.to_value();
        assert!(service.context.get("selected_slots").is_none());
        assert!(merchant_view.get("selected_slots").is_none());
        assert!(merchant_view.get("preq").is_none());
        assert!(merchant_view["context"].get("selected_slots").is_none());
        assert!(merchant_view["context"].get("preq").is_none());
        let wallet_view = slot.to_value();
        let projection = wallet_view["payment_projection"]
            .as_object()
            .expect("wallet-facing payment projection is an object");
        let expected_projection_fields = BTreeSet::from([
            "amount",
            "payee",
            "asset",
            "class",
            "merchant",
            "quote_nonce",
            "time",
        ]);
        assert_eq!(
            projection.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            expected_projection_fields
        );
    }

    #[test]
    fn user_approval_and_capability_bind_exact_slot_merchants() {
        let classes = vec!["business".to_string()];
        let slot_merchants = vec!["merchant-approved".to_string()];
        let (user, wallet, taxonomy) = build_system(1, &classes);
        let (holder, issue_meta) = issue_task_credential(
            &user,
            &wallet,
            &classes,
            &[5],
            &classes,
            &slot_merchants,
            100,
            5,
        )
        .unwrap();
        assert_eq!(
            issue_meta["mandate"]["policy"]["allowed_merchants"],
            json!(["merchant-approved"])
        );
        assert_eq!(
            issue_meta["mandate"]["policy"]["slots"][0],
            json!({
                "slot_index": 0,
                "service_class": "business",
                "merchant_id": "merchant-approved",
                "capacity": 5,
                "expiry": 100,
                "funding_eligible": true,
            })
        );

        let unapproved = Merchant {
            merchant_id: "merchant-unapproved".to_string(),
            key: SchnorrKey::new(),
        };
        let input = service_input_digest(&default_service_input("company-profile", "business"));
        let (q, preq, challenge, cert) = merchant_request(
            &unapproved,
            &taxonomy,
            "company-profile",
            "business",
            &input,
            5,
            1,
            false,
        );
        let (service, slot) = derive_presentations(
            &holder,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &unapproved,
            &q,
            &preq,
            &challenge,
            &cert,
            &[0],
            1,
        )
        .unwrap();
        // The merchant-facing service view intentionally discloses the admitted
        // service class, not the wallet-facing slot merchant. Exact-merchant
        // binding is therefore enforced when the redemption wallet verifies the
        // spend view, where the slot coordinate is disclosed.
        let request = make_redeem_request(service, slot);
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        let (ok, receipt) = redemption.redeem(&request, 1);
        assert!(!ok, "{receipt}");
        assert_eq!(receipt["outcome"], "rejected");
        assert_eq!(receipt["reason"], "merchant");
    }

    #[test]
    fn admitted_class_policy_scope_allows_runtime_merchant_selection() {
        let classes = vec!["business".to_string()];
        let policy_scopes = vec!["policy:admitted:business".to_string()];
        let (user, wallet, taxonomy) = build_system(1, &classes);
        let (holder, issue_meta) = issue_task_credential(
            &user,
            &wallet,
            &classes,
            &[5],
            &classes,
            &policy_scopes,
            100,
            5,
        )
        .unwrap();
        assert_eq!(
            issue_meta["mandate"]["policy"]["allowed_merchants"],
            json!(["policy:admitted:business"])
        );

        let runtime_merchant = Merchant {
            merchant_id: "merchant-selected-after-approval".to_string(),
            key: SchnorrKey::new(),
        };
        let input = service_input_digest(&default_service_input("company-profile", "business"));
        let (q, preq, challenge, cert) = merchant_request(
            &runtime_merchant,
            &taxonomy,
            "company-profile",
            "business",
            &input,
            5,
            1,
            false,
        );
        let result = derive_presentations(
            &holder,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &runtime_merchant,
            &q,
            &preq,
            &challenge,
            &cert,
            &[0],
            1,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn forged_disclosed_merchant_does_not_repair_the_slot_proof() {
        let classes = vec!["business".to_string()];
        let approved = vec!["merchant-approved".to_string()];
        let (user, wallet, taxonomy) = build_system(1, &classes);
        let (holder, _) =
            issue_task_credential(&user, &wallet, &classes, &[5], &classes, &approved, 100, 5)
                .unwrap();
        let merchant = Merchant {
            merchant_id: "merchant-approved".to_string(),
            key: SchnorrKey::new(),
        };
        let input = service_input_digest(&default_service_input("company-profile", "business"));
        let (q, preq, challenge, cert) = merchant_request(
            &merchant,
            &taxonomy,
            "company-profile",
            "business",
            &input,
            5,
            1,
            false,
        );
        let (service, mut slot) = derive_presentations(
            &holder,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &merchant,
            &q,
            &preq,
            &challenge,
            &cert,
            &[0],
            1,
        )
        .unwrap();
        slot.presentation.disclosed_messages.insert(
            slot_name(0, "merchant"),
            scalar_from_value(&json!("merchant-unapproved")),
        );
        let mut request = make_redeem_request(service, slot);
        request.redemption_digest = redemption_view_digest(&request.slot);
        request.bind = one_call_bind(
            &request.service,
            &request.slot,
            &request.merchant_digest,
            &request.redemption_digest,
        )
        .unwrap();
        request.ack = merchant_acknowledge_service(
            &merchant,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &request.service,
            &request.redemption_digest,
            &request.bind,
            1,
        )
        .unwrap();
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        let (ok, reason) = redemption.redeem(&request, 1);
        assert!(!ok);
        assert_eq!(reason["reason"], "merchant");
    }

    #[test]
    fn scope_relation_rejects_cross_class_splicing() {
        let classes = vec!["business".to_string(), "patent".to_string()];
        let allowed_classes = vec!["business".to_string()];
        let slot_classes = vec!["business".to_string()];
        let slot_merchants = vec!["merchant-scope-test".to_string()];
        let (user, wallet, taxonomy) = build_system(1, &classes);
        let (holder, _) = issue_task_credential(
            &user,
            &wallet,
            &allowed_classes,
            &[5],
            &slot_classes,
            &slot_merchants,
            100,
            5,
        )
        .unwrap();
        for class_name in &classes {
            assert!(holder.messages.contains_key(&serial_seed_name(class_name)));
            assert!(holder.messages.contains_key(&fund_seed_name(class_name)));
        }
        assert_ne!(
            holder.messages[&serial_seed_name("business")],
            holder.messages[&serial_seed_name("patent")]
        );
        assert_ne!(
            holder.messages[&fund_seed_name("business")],
            holder.messages[&fund_seed_name("patent")]
        );
        let merchant = Merchant {
            merchant_id: "merchant-scope-test".to_string(),
            key: SchnorrKey::new(),
        };
        let input_digest =
            service_input_digest(&default_service_input("company-profile", "business"));
        let (q, preq, challenge, cert) = merchant_request(
            &merchant,
            &taxonomy,
            "company-profile",
            "business",
            &input_digest,
            5,
            1,
            false,
        );
        let (service, _) = derive_presentations(
            &holder,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &merchant,
            &q,
            &preq,
            &challenge,
            &cert,
            &[0],
            1,
        )
        .unwrap();
        for class_name in &classes {
            assert!(!service
                .presentation
                .disclosed_messages
                .contains_key(&serial_seed_name(class_name)));
            assert!(!service
                .presentation
                .disclosed_messages
                .contains_key(&fund_seed_name(class_name)));
        }
        let invocation_id = service.context["I"].as_str().unwrap();
        assert!(ihbbs1::verify(
            &wallet.issuance.verifier.public_params,
            &wallet.issuance.verifier.policy,
            &service.issuer_hiding_authorization,
            &service.presentation,
            &[(link_bases("business"), service.l)],
            &service.context,
            "mm-service-presentation",
            invocation_id,
            1,
        ));
        assert!(!ihbbs1::verify(
            &wallet.issuance.verifier.public_params,
            &wallet.issuance.verifier.policy,
            &service.issuer_hiding_authorization,
            &service.presentation,
            &[(link_bases("patent"), service.l)],
            &service.context,
            "mm-service-presentation",
            invocation_id,
            1,
        ));
    }

    #[test]
    fn funding_relation_rejects_projection_substitution() {
        let (_, wallet, taxonomy, _, slot, _) = fixture();
        let redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        let invocation_id = slot.context["I"].as_str().unwrap();
        let relations = redemption.slot_relations(&slot).unwrap();
        assert!(ihbbs1::verify(
            &redemption.verifier.public_params,
            &redemption.verifier.policy,
            &slot.issuer_hiding_authorization,
            &slot.presentation,
            &relations,
            &slot.context,
            "mm-slot-presentation",
            invocation_id,
            1,
        ));
        let mut substituted = relations;
        substituted[1] = funding_relation("different-funding-bucket");
        assert!(!ihbbs1::verify(
            &redemption.verifier.public_params,
            &redemption.verifier.policy,
            &slot.issuer_hiding_authorization,
            &slot.presentation,
            &substituted,
            &slot.context,
            "mm-slot-presentation",
            invocation_id,
            1,
        ));
    }

    #[test]
    fn policy_rejects_singletons_and_duplicates() {
        let params = ihbbs1::setup(&["scope".to_string()]);
        let (_, issuer_a) = ihbbs1::issuer_keygen(&params);
        let (_, issuer_b) = ihbbs1::issuer_keygen(&params);
        assert!(ihbbs1::set_policy(
            "epoch-test",
            0,
            100,
            "registry".to_string(),
            vec![issuer_a.clone()],
        )
        .is_err());
        assert!(ihbbs1::set_policy(
            "epoch-test",
            0,
            100,
            "registry".to_string(),
            vec![issuer_a.clone(), issuer_a],
        )
        .is_err());
        assert!(ihbbs1::set_policy(
            "epoch-test",
            0,
            100,
            "registry".to_string(),
            vec![issuer_b, ihbbs1::issuer_keygen(&params).1],
        )
        .is_ok());
    }

    fn jsonl_test_policy(label: &str) -> (policy_io::LoadedIssuerPolicy, PathBuf) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "target/canonical-test-output/jsonl-{label}-policy-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        policy_io::run_generate_cli(vec!["--output".to_string(), path.display().to_string()])
            .unwrap();
        (policy_io::load(&path).unwrap(), path)
    }

    fn jsonl_contract(mut request: Value, policy: &policy_io::LoadedIssuerPolicy) -> Value {
        request["protocol_version"] = json!(PROTOCOL_VERSION);
        request["wire_schema_version"] = json!(WIRE_SCHEMA_VERSION);
        request["issuer_policy"] = policy.metadata.clone();
        request["no_live_cost_boundary"] = no_live_cost_boundary_value();
        request
    }

    fn signed_test_approval(
        approval_workflow_id: &str,
        slots: &[Value],
        base_budget: u64,
        reserve_budget: u64,
        approved_budget: u64,
        funding_coverage: u64,
        amendment_limit: u64,
        approval_kind: &str,
        approval_sequence: u64,
        parent_approval_sha256: Option<&str>,
    ) -> Value {
        let ordered_slots = slots
            .iter()
            .map(|slot| {
                json!({
                    "service_class": slot["service_class"],
                    "merchant_id": slot["merchant_id"],
                    "capacity": slot["capacity"],
                    "expiry": slot["expiry"],
                })
            })
            .collect::<Vec<_>>();
        let mut classes = slots
            .iter()
            .map(|slot| slot["service_class"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        classes.sort();
        classes.dedup();
        let mut merchants = slots
            .iter()
            .map(|slot| slot["merchant_id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        merchants.sort();
        merchants.dedup();
        let eligible_indices = slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                slot["funding_eligible"].as_bool().unwrap().then_some(index)
            })
            .collect::<Vec<_>>();
        let seed = [0x42u8; 32];
        let (public_key, _) = sign_ed25519_for_test(&seed, b"derive-public-key").unwrap();
        let evidence_locator = "test-fixture://ed25519/user-approval-v1";
        let canonical_input = json!({
            "schema_version": "minmandate-user-approval-v1",
            "workflow_id": approval_workflow_id,
            "approval_kind": approval_kind,
            "approval_sequence": approval_sequence,
            "parent_approval_sha256": parent_approval_sha256,
            "decision": "approve",
            "ordered_slots": ordered_slots,
            "budget": {
                "base": base_budget,
                "reserve": reserve_budget,
                "approved_total": approved_budget,
            },
            "allowed_service_classes": classes,
            "allowed_merchants": merchants,
            "funding_eligibility": {
                "eligible_slot_indices": eligible_indices,
                "coverage": funding_coverage,
            },
            "amendment_limit": amendment_limit,
            "settlement_authorization": {
                "authorized": false,
                "mode": "none_local_experiment",
            },
            "approval_evidence": {
                "evidence_class": "human",
                "signer_id": "jsonl-test-user",
                "evidence_locator": evidence_locator,
                "frozen_evidence_sha256": sha256_plain_hex(evidence_locator.as_bytes()),
                "signature_scheme": "ed25519-v1",
                "signer_public_key_b64": wire::base64_encode(&public_key),
            },
        });
        let canonical_bytes = canonical_ascii_bytes(&canonical_input);
        let (_, signature) = sign_ed25519_for_test(&seed, &canonical_bytes).unwrap();
        let mut artifact = canonical_input.as_object().unwrap().clone();
        artifact.insert(
            "canonical_input_sha256".to_string(),
            json!(sha256_plain_hex(&canonical_bytes)),
        );
        artifact.insert(
            "signature".to_string(),
            json!(wire::base64_encode(&signature)),
        );
        let artifact_digest =
            sha256_plain_hex(&canonical_ascii_bytes(&Value::Object(artifact.clone())));
        artifact.insert("artifact_sha256".to_string(), json!(artifact_digest));
        Value::Object(artifact)
    }

    fn approved_begin_request(
        policy: &policy_io::LoadedIssuerPolicy,
        session_workflow_id: &str,
        approval_workflow_id: &str,
        slots: Vec<Value>,
        base_budget: u64,
        reserve_budget: u64,
        approved_budget: u64,
        funding_coverage: u64,
        amendment_limit: u64,
        approval_kind: &str,
        approval_sequence: u64,
        parent_approval_sha256: Option<&str>,
    ) -> (Value, String) {
        let artifact = signed_test_approval(
            approval_workflow_id,
            &slots,
            base_budget,
            reserve_budget,
            approved_budget,
            funding_coverage,
            amendment_limit,
            approval_kind,
            approval_sequence,
            parent_approval_sha256,
        );
        let artifact_digest = artifact["artifact_sha256"].as_str().unwrap().to_string();
        let request = jsonl_contract(
            json!({
                "operation": "begin_workflow",
                "workflow_id": session_workflow_id,
                "task": "exercise the exact approved JSONL mandate",
                "slots": slots,
                "experiment_variant": "full",
                "user_approval_artifact": artifact.clone(),
                "user_approval_artifact_sha256": artifact_digest,
                "budget": artifact["budget"].clone(),
                "approved_budget": approved_budget,
                "funding_reserve": reserve_budget,
                "funding": artifact["funding_eligibility"].clone(),
                "allowed_service_classes": artifact["allowed_service_classes"].clone(),
                "allowed_merchants": artifact["allowed_merchants"].clone(),
                "amendment_limit": amendment_limit,
                "settlement_authorization": artifact["settlement_authorization"].clone(),
            }),
            policy,
        );
        (request, artifact_digest)
    }

    fn approved_invoke_request(
        policy: &policy_io::LoadedIssuerPolicy,
        workflow_id: &str,
        call_id: &str,
        credential_id: &str,
        slot_index: usize,
        amount: u64,
    ) -> Value {
        jsonl_contract(
            json!({
                "operation": "invoke",
                "workflow_id": workflow_id,
                "call_id": call_id,
                "credential_id": credential_id,
                "service_id": "approved-service",
                "service_class": "communication",
                "merchant_id": "mail-service",
                "request_fields": {"query": "Company X"},
                "amount": amount,
                "trusted_now": 2,
                "slot_index": slot_index,
                "slot_indices": [slot_index],
                "attack": "none",
                "settlement_authorization": {
                    "authorized": false,
                    "mode": "none_local_experiment",
                },
            }),
            policy,
        )
    }

    fn one_jsonl_slot(capacity: u64, expiry: u64, funding_eligible: bool) -> Value {
        json!({
            "service_class": "communication",
            "merchant_id": "mail-service",
            "capacity": capacity,
            "expiry": expiry,
            "funding_eligible": funding_eligible,
        })
    }

    #[test]
    fn jsonl_requires_exact_ed25519_approval_and_independent_funding() {
        let (policy, policy_path) = jsonl_test_policy("approval");
        let (valid, credential_id) = approved_begin_request(
            &policy,
            "approval-workflow",
            "approval-workflow",
            vec![one_jsonl_slot(10, 100, true)],
            4,
            1,
            5,
            7,
            1,
            "initial",
            0,
            None,
        );
        let mut invalid_requests = Vec::new();

        let mut omitted = valid.clone();
        omitted
            .as_object_mut()
            .unwrap()
            .remove("user_approval_artifact");
        invalid_requests.push(omitted);
        for missing in [
            "approved_budget",
            "funding_reserve",
            "funding",
            "allowed_service_classes",
            "allowed_merchants",
            "amendment_limit",
            "settlement_authorization",
        ] {
            let mut request = valid.clone();
            request.as_object_mut().unwrap().remove(missing);
            invalid_requests.push(request);
        }
        let mut missing_expiry = valid.clone();
        missing_expiry["slots"][0]
            .as_object_mut()
            .unwrap()
            .remove("expiry");
        invalid_requests.push(missing_expiry);
        let mut zero_expiry = valid.clone();
        zero_expiry["slots"][0]["expiry"] = json!(0);
        invalid_requests.push(zero_expiry);
        let mut changed_class = valid.clone();
        changed_class["slots"][0]["service_class"] = json!("security");
        invalid_requests.push(changed_class);
        let mut changed_merchant = valid.clone();
        changed_merchant["slots"][0]["merchant_id"] = json!("other-merchant");
        invalid_requests.push(changed_merchant);
        let mut changed_capacity = valid.clone();
        changed_capacity["slots"][0]["capacity"] = json!(11);
        invalid_requests.push(changed_capacity);
        let mut changed_funding = valid.clone();
        changed_funding["slots"][0]["funding_eligible"] = json!(false);
        invalid_requests.push(changed_funding);
        let mut changed_budget = valid.clone();
        changed_budget["approved_budget"] = json!(6);
        invalid_requests.push(changed_budget);
        let mut changed_coverage = valid.clone();
        changed_coverage["funding"]["coverage"] = json!(8);
        invalid_requests.push(changed_coverage);
        let mut changed_classes = valid.clone();
        changed_classes["allowed_service_classes"] = json!(["communication", "security"]);
        invalid_requests.push(changed_classes);
        let mut changed_merchants = valid.clone();
        changed_merchants["allowed_merchants"] = json!(["mail-service", "other"]);
        invalid_requests.push(changed_merchants);
        let mut changed_limit = valid.clone();
        changed_limit["amendment_limit"] = json!(0);
        invalid_requests.push(changed_limit);
        let mut changed_settlement = valid.clone();
        changed_settlement["settlement_authorization"]["mode"] = json!("other");
        invalid_requests.push(changed_settlement);
        let mut tampered_signature = valid.clone();
        tampered_signature["user_approval_artifact"]["signature"] =
            json!(wire::base64_encode(&[0u8; 64]));
        invalid_requests.push(tampered_signature);
        let mut tampered_digest = valid.clone();
        tampered_digest["user_approval_artifact_sha256"] = json!("0".repeat(64));
        invalid_requests.push(tampered_digest);

        let (insufficient, _) = approved_begin_request(
            &policy,
            "insufficient-workflow",
            "insufficient-workflow",
            vec![one_jsonl_slot(10, 100, true)],
            5,
            0,
            5,
            4,
            0,
            "initial",
            0,
            None,
        );
        invalid_requests.push(insufficient);

        let mut state = JsonlState::new(json!({"test_attestation": true}));
        for request in invalid_requests {
            assert!(handle_jsonl_request(&request, &mut state, &policy).is_err());
        }
        let response = handle_jsonl_request(&valid, &mut state, &policy).unwrap();
        assert_eq!(response["credential_id"], credential_id);
        assert_eq!(response["session_id"], credential_id);
        assert_eq!(response["approved_budget"], 5);
        assert_eq!(response["funding_coverage"], 7);
        assert_eq!(response["issuance_mode"], ORDINARY_ISSUANCE_MODE);
        let session = state.sessions.get("approval-workflow").unwrap();
        let issuer_visible_names = response["issuer_visible_message_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        let signed_names = session
            .holder
            .credential
            .messages
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(issuer_visible_names, signed_names);
        assert!(issuer_visible_names.contains(serial_seed_name("communication").as_str()));
        assert!(issuer_visible_names.contains(fund_seed_name("communication").as_str()));
        assert!(issuer_visible_names.contains(bbs::PROVER_BLIND_MESSAGE));
        assert_eq!(session.holder.messages[BUDGET_NAME], Scalar::from(5u64));
        assert_eq!(
            session.holder.messages[&slot_name(0, "capacity")],
            Scalar::from(10u64)
        );
        assert_eq!(
            session.holder.messages[&slot_name(0, "funding_eligible")],
            Scalar::ONE
        );
        let _ = fs::remove_file(policy_path);
    }

    #[test]
    fn jsonl_exact_idempotency_returns_original_signed_records() {
        let (policy, policy_path) = jsonl_test_policy("idempotency");
        let (begin, credential_id) = approved_begin_request(
            &policy,
            "idempotency-workflow",
            "idempotency-workflow",
            vec![one_jsonl_slot(5, 100, true)],
            5,
            0,
            5,
            5,
            0,
            "initial",
            0,
            None,
        );
        let mut state = JsonlState::new(json!({"test_attestation": true}));
        handle_jsonl_request(&begin, &mut state, &policy).unwrap();
        let invoke = approved_invoke_request(
            &policy,
            "idempotency-workflow",
            "call-1",
            &credential_id,
            0,
            5,
        );
        let first = handle_jsonl_request(&invoke, &mut state, &policy).unwrap();
        assert_eq!(first["accepted"], true);
        assert_eq!(first["status"], "fresh_accept");
        assert_eq!(first["fresh_execution_authorized"], true);
        assert_eq!(first["settlement_authorization_issued"], true);
        assert!(first["merchant_view_serialized"]["issuer_hiding_evidence"].is_object());
        assert!(first["redemption_view_serialized"]["issuer_hiding_evidence"].is_object());
        for transmitted in [&first["settlement_authorization"], &first["signed_receipt"]] {
            let text = String::from_utf8(canonical_bytes(transmitted)).unwrap();
            assert!(text.contains(&credential_id));
            assert!(text.contains("session_id"));
        }
        for view in [
            &first["merchant_view_serialized"],
            &first["redemption_view_serialized"],
        ] {
            assert!(view["context"]["credential_id"].is_null());
            assert!(view["context"]["session_id"].is_null());
            let evidence =
                String::from_utf8(canonical_bytes(&view["issuer_hiding_evidence"])).unwrap();
            assert!(!evidence.contains("selected_issuer"));
            assert!(!evidence.contains("issuer_identity"));
        }
        assert_eq!(
            first["settlement_verification"]["key_attestation"]["statement"]["body"]
                ["credential_id"],
            credential_id
        );
        assert_eq!(
            first["settlement_verification"]["key_attestation"]["statement"]["body"]["session_id"],
            credential_id
        );
        for field in ["dM", "dR", "Bind"] {
            assert!(first[field].as_str().is_some_and(|value| !value.is_empty()));
        }
        let settlement_key = wire::decode_g1(
            &hex_decode(
                first["settlement_verification"]["verification_key"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(verify_local_signed_record(
            &first["settlement_authorization"],
            &settlement_key
        ));
        assert!(verify_local_signed_record(
            &first["signed_receipt"],
            &settlement_key
        ));
        assert!(verify_local_signed_record(
            &first["settlement_verification"]["key_attestation"],
            &state.settlement_trust_key.pk,
        ));
        assert_eq!(
            first["settlement_verification"]["verification_key_sha256"],
            sha256_plain_hex(&wire::encode_g1(&settlement_key))
        );

        let replay = handle_jsonl_request(&invoke, &mut state, &policy).unwrap();
        assert_eq!(replay["accepted"], false);
        assert_eq!(replay["status"], "idempotent_receipt");
        assert_eq!(replay["fresh_execution_authorized"], false);
        assert_eq!(replay["settlement_authorization_issued"], false);
        assert_eq!(replay["signed_receipt"], first["signed_receipt"]);
        assert_eq!(
            replay["settlement_authorization"],
            first["settlement_authorization"]
        );

        let mut conflicting = invoke.clone();
        conflicting["amount"] = json!(4);
        assert!(handle_jsonl_request(&conflicting, &mut state, &policy)
            .unwrap_err()
            .contains("different canonical request"));
        let _ = fs::remove_file(policy_path);
    }

    #[test]
    fn jsonl_replace_is_atomic_and_tombstones_parent_credential() {
        let (policy, policy_path) = jsonl_test_policy("replace");
        let (parent_begin, parent_credential) = approved_begin_request(
            &policy,
            "replace-parent",
            "replace-parent",
            vec![one_jsonl_slot(5, 100, true)],
            5,
            0,
            5,
            5,
            1,
            "initial",
            0,
            None,
        );
        let mut state = JsonlState::new(json!({"test_attestation": true}));
        handle_jsonl_request(&parent_begin, &mut state, &policy).unwrap();

        let (mut failed_replace, _) = approved_begin_request(
            &policy,
            "replace-child-failed",
            "replace-parent",
            vec![one_jsonl_slot(5, 100, true)],
            5,
            0,
            5,
            4,
            0,
            "amendment",
            1,
            Some(&parent_credential),
        );
        failed_replace["operation"] = json!("replace_workflow");
        failed_replace["workflow_id"] = json!("replace-parent");
        failed_replace["replacement_workflow_id"] = json!("replace-child-failed");
        failed_replace["parent_credential_id"] = json!(parent_credential);
        assert!(handle_jsonl_request(&failed_replace, &mut state, &policy).is_err());
        assert!(state.sessions.contains_key("replace-parent"));
        assert!(!state.credential_tombstones.contains(&parent_credential));

        let (mut replacement, replacement_credential) = approved_begin_request(
            &policy,
            "replace-child",
            "replace-parent",
            vec![one_jsonl_slot(5, 100, true)],
            5,
            0,
            5,
            5,
            0,
            "amendment",
            1,
            Some(&parent_credential),
        );
        replacement["operation"] = json!("replace_workflow");
        replacement["workflow_id"] = json!("replace-parent");
        replacement["replacement_workflow_id"] = json!("replace-child");
        replacement["parent_credential_id"] = json!(parent_credential);
        let replaced = handle_jsonl_request(&replacement, &mut state, &policy).unwrap();
        assert_eq!(replaced["status"], "replacement_committed");
        assert_eq!(replaced["parent_tombstoned"], true);
        assert!(!state.sessions.contains_key("replace-parent"));
        assert!(state.sessions.contains_key("replace-child"));
        assert!(state.credential_tombstones.contains(&parent_credential));
        assert!(state.session_tombstones.contains("replace-parent"));

        let parent_invoke = approved_invoke_request(
            &policy,
            "replace-parent",
            "old-call",
            &parent_credential,
            0,
            1,
        );
        assert!(handle_jsonl_request(&parent_invoke, &mut state, &policy)
            .unwrap_err()
            .contains("tombstoned"));
        let replacement_invoke = approved_invoke_request(
            &policy,
            "replace-child",
            "new-call",
            &replacement_credential,
            0,
            1,
        );
        assert_eq!(
            handle_jsonl_request(&replacement_invoke, &mut state, &policy).unwrap()["accepted"],
            true
        );
        let _ = fs::remove_file(policy_path);
    }

    #[test]
    fn jsonl_startup_attestation_fails_closed_without_deny_inet_preload() {
        if std::env::var("LD_PRELOAD").unwrap_or_default().is_empty() {
            assert!(startup_network_boundary_attestation()
                .unwrap_err()
                .contains("LD_PRELOAD"));
        } else if let Ok(attestation) = startup_network_boundary_attestation() {
            assert_eq!(attestation["loader_mapping_verified"], true);
            assert_eq!(attestation["af_inet_socket_creation_allowed"], true);
            assert_eq!(attestation["loopback_udp_connect_allowed"], true);
            assert_eq!(attestation["nonloopback_udp_connect_denied"], true);
            assert_eq!(attestation["network_payload_transmitted"], false);
            assert_eq!(attestation["live_service_contact_attempted"], false);
        }
    }

    #[test]
    fn jsonl_guard_rejects_live_or_chargeable_execution() {
        let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "target/canonical-test-output/jsonl-guard-policy-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&policy_path);
        policy_io::run_generate_cli(vec![
            "--output".to_string(),
            policy_path.display().to_string(),
        ])
        .unwrap();
        let policy = policy_io::load(&policy_path).unwrap();
        let contract = |mut request: Value| {
            request["protocol_version"] = json!(PROTOCOL_VERSION);
            request["wire_schema_version"] = json!(WIRE_SCHEMA_VERSION);
            request["issuer_policy"] = policy.metadata.clone();
            request["no_live_cost_boundary"] = no_live_cost_boundary_value();
            request
        };
        let mut state = JsonlState::new(json!({"test_attestation": true}));
        for forbidden in [
            "live_execution",
            "paid_saas",
            "real_payment_rail",
            "broadcast_transaction",
            "allow_charge",
            "allow_network",
            "allow_live_services",
            "allow_sandbox_services",
            "allow_real_payment",
            "allow_production_writes",
        ] {
            let mut request = contract(json!({"operation": "ping"}));
            request[forbidden] = json!(true);
            assert!(handle_jsonl_request(&request, &mut state, &policy).is_err());
        }
        let response = handle_jsonl_request(
            &contract(json!({
                "operation": "ping",
                "execution_mode": EXECUTION_MODE,
            })),
            &mut state,
            &policy,
        )
        .unwrap();
        assert_eq!(response["execution_mode"], EXECUTION_MODE);
        assert_eq!(response["allow_network"], false);
        assert_eq!(response["allow_live_services"], false);
        assert_eq!(response["allow_sandbox_services"], false);
        assert_eq!(response["allow_real_payment"], false);
        assert_eq!(response["allow_production_writes"], false);
        assert_eq!(response["quote_mode"], "virtual-deterministic");
        assert_eq!(response["settlement_mode"], "local-ledger-no-funds");
        assert_eq!(response["live_external_calls"], false);
        assert_eq!(response["real_charges"], false);
        assert_eq!(response["transaction_broadcast"], false);

        for request in [
            json!({"operation": "ping", "endpoint": "https://api.stripe.com"}),
            json!({"operation": "ping", "clay_api_key": "forbidden"}),
            json!({"operation": "ping", "payment_intent": "pi_forbidden"}),
        ] {
            assert!(handle_jsonl_request(&contract(request), &mut state, &policy).is_err());
        }
        assert!(handle_jsonl_request(
            &contract(json!({"operation": "ping", "endpoint": "http://127.0.0.1:11434"})),
            &mut state,
            &policy,
        )
        .is_ok());
        let _ = fs::remove_file(policy_path);
    }

    #[test]
    fn rejects_bad_binding() {
        let (_, wallet, taxonomy, _, _, mut request) = fixture();
        request.bind = "tampered".to_string();
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        let (ok, reason) = redemption.redeem(&request, 1);
        assert!(!ok);
        assert_eq!(reason["reason"], "bind");
    }

    #[test]
    fn rejects_uncertified_merchant_key_substitution() {
        let (_, wallet, taxonomy, _, _, mut request) = fixture();
        let attacker = SchnorrKey::new();
        request.slot.projection.merchant_pk = attacker.pk;
        request.redemption_digest = redemption_view_digest(&request.slot);
        request.bind = one_call_bind(
            &request.service,
            &request.slot,
            &request.merchant_digest,
            &request.redemption_digest,
        )
        .unwrap();
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        let (ok, reason) = redemption.redeem(&request, 1);
        assert!(!ok);
        assert_eq!(reason["reason"], "cross-view");
    }

    #[test]
    fn service_and_slot_share_one_randomized_issuer_key() {
        let (_, _, _, service, slot, _) = fixture();
        assert_eq!(
            service
                .issuer_hiding_authorization
                .randomized_issuer_pk
                .x_tilde,
            slot.issuer_hiding_authorization
                .randomized_issuer_pk
                .x_tilde
        );
        assert_ne!(
            service.presentation.proof.a_bar,
            slot.presentation.proof.a_bar
        );
    }

    #[test]
    fn production_fixture_policy_has_eight_admitted_issuers() {
        let classes = vec!["business".to_string()];
        let (_, wallet, _) = build_system(1, &classes);
        assert_eq!(
            wallet.issuance.verifier.policy.issuers.len(),
            ihbbs1::DETERMINISTIC_TEST_FIXTURE_ISSUERS
        );
        assert!(ihbbs1::verify_policy(
            &wallet.issuance.verifier.policy,
            &wallet.issuance.verifier.public_params,
        )
        .is_ok());
        assert!(wallet
            .issuance
            .verifier
            .policy
            .member_tag(&wallet.issuance.issuer_pk)
            .is_some());
    }

    #[test]
    fn cached_admission_material_preserves_the_frozen_registry_digest() {
        assert_eq!(
            canonical_registry_digest(),
            "2ee542dfa4189bc3d3eadc0c602aead8810ccb4734275e119b8d9ec4b6e917ed"
        );
    }

    #[test]
    fn admitted_issuers_complete_the_same_paid_call_path() {
        let classes = vec!["business".to_string()];
        let mut completed = BTreeSet::new();
        for index in 0..64 {
            let (user, wallet, taxonomy) = build_system_with_wallet_entity_id(
                1,
                &classes,
                Some(format!("wallet-fixture-{index}")),
            );
            let issuer = g2_hex(&wallet.issuance.issuer_pk.x_tilde);
            if !completed.insert(issuer) {
                continue;
            }
            let (holder, _) = issue_task_credential(
                &user,
                &wallet,
                &classes,
                &[5],
                &classes,
                &[format!("merchant-{index}")],
                100,
                5,
            )
            .unwrap();
            let merchant = Merchant {
                merchant_id: format!("merchant-{index}"),
                key: SchnorrKey::new(),
            };
            let input = service_input_digest(&default_service_input("company-profile", "business"));
            let (q, preq, challenge, cert) = merchant_request(
                &merchant,
                &taxonomy,
                "company-profile",
                "business",
                &input,
                5,
                1,
                false,
            );
            let (service, slot) = derive_presentations(
                &holder,
                &wallet.issuance.verifier,
                &taxonomy.key.pk,
                &merchant,
                &q,
                &preq,
                &challenge,
                &cert,
                &[0],
                1,
            )
            .unwrap();
            let mut redemption =
                RedemptionService::new_ephemeral(wallet.issuance.verifier.clone(), taxonomy.key.pk);
            assert!(redemption.redeem(&make_redeem_request(service, slot), 1).0);
            if completed.len() == 3 {
                break;
            }
        }
        assert_eq!(
            completed.len(),
            3,
            "fixture selection did not cover three issuers"
        );
    }

    #[test]
    fn rejects_nonmember_issuer_before_presentation() {
        let (mut holder, wallet, taxonomy, _, _, _) = fixture();
        let (_, outsider) = bbs::keygen(&wallet.issuance.issuer_pk.params);
        holder.issuer_hiding.issuer_pk = outsider;
        let merchant = Merchant {
            merchant_id: "merchant-outsider".to_string(),
            key: SchnorrKey::new(),
        };
        let input = service_input_digest(&default_service_input("company-profile", "business"));
        let (q, preq, challenge, cert) = merchant_request(
            &merchant,
            &taxonomy,
            "company-profile",
            "business",
            &input,
            5,
            1,
            false,
        );
        assert!(derive_presentations(
            &holder,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &merchant,
            &q,
            &preq,
            &challenge,
            &cert,
            &[0],
            1,
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_tag_policy_epoch_and_different_alpha() {
        let (_, wallet, taxonomy, _, _, request) = fixture();
        let invocation_id = request.slot.context["I"].as_str().unwrap().to_string();

        let mut wrong_tag = request.slot.issuer_hiding_authorization.clone();
        wrong_tag.randomized_policy_tag.0 += G2::generator();
        assert!(!verify_issuer_hidden_authorization(
            &wallet.issuance.verifier,
            &wrong_tag,
            &invocation_id,
            1,
        ));

        let mut wrong_epoch = request.slot.issuer_hiding_authorization.clone();
        wrong_epoch.epoch = "wrong-epoch".to_string();
        assert!(!verify_issuer_hidden_authorization(
            &wallet.issuance.verifier,
            &wrong_epoch,
            &invocation_id,
            1,
        ));

        let mut wrong_policy = wallet.issuance.verifier.clone();
        wrong_policy.policy.policy_digest = "wrong-policy".to_string();
        assert!(!verify_issuer_hidden_authorization(
            &wrong_policy,
            &request.slot.issuer_hiding_authorization,
            &invocation_id,
            1,
        ));

        let mut different_alpha = request.slot.issuer_hiding_authorization.clone();
        different_alpha.randomized_policy_tag.0 *= Scalar::from(2u64);
        assert!(!verify_issuer_hidden_authorization(
            &wallet.issuance.verifier,
            &different_alpha,
            &invocation_id,
            1,
        ));

        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        assert!(redemption.redeem(&request, 1).0);
    }

    #[test]
    fn rejects_cross_policy_splice() {
        let (_, _, _, _, _, request) = fixture();
        let classes = vec!["business".to_string()];
        let (_, mut other_wallet, _) = build_system(1, &classes);
        other_wallet.issuance.verifier.policy.epoch = "epoch-cross-policy".to_string();
        let invocation_id = request.slot.context["I"].as_str().unwrap();
        assert!(!verify_issuer_hidden_authorization(
            &other_wallet.issuance.verifier,
            &request.slot.issuer_hiding_authorization,
            invocation_id,
            1,
        ));
    }

    #[test]
    fn fresh_presentations_hide_stable_issuer_handle_and_preserve_joined_wallet_boundary() {
        let (holder, wallet, taxonomy, service_one, _, _) = fixture();
        let merchant = Merchant {
            merchant_id: "merchant-a".to_string(),
            key: SchnorrKey::new(),
        };
        let input = service_input_digest(&default_service_input("company-profile", "business"));
        let (q, preq, challenge, cert) = merchant_request(
            &merchant,
            &taxonomy,
            "company-profile",
            "business",
            &input,
            5,
            2,
            false,
        );
        let (service_two, slot_two) = derive_presentations(
            &holder,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &merchant,
            &q,
            &preq,
            &challenge,
            &cert,
            &[0],
            2,
        )
        .unwrap();
        assert_ne!(
            service_one
                .issuer_hiding_authorization
                .randomized_issuer_pk
                .x_tilde,
            service_two
                .issuer_hiding_authorization
                .randomized_issuer_pk
                .x_tilde
        );
        let original_issuer = g2_hex(&wallet.issuance.issuer_pk.x_tilde);
        let credential_id = holder.credential_id.clone();
        let session_id = holder.session_id.clone();
        for routine_view in [service_two.to_value(), slot_two.to_value()] {
            let encoded = canonical_bytes(&routine_view);
            let text = String::from_utf8(encoded).unwrap();
            assert!(!text.contains(&original_issuer));
            assert!(!text.contains(&credential_id));
            assert!(!text.contains(&session_id));
            assert!(!text.contains("session_id"));
            assert!(!text.contains("issuer_index"));
            assert!(!text.contains("common_alpha"));
            assert!(!json_has_key(&routine_view, "wallet_entity_id"));
        }
        let joined_wallet_audit = json!({
            "wallet_entity_id": wallet.wallet_entity_id,
            "selected_original_issuer_pk": original_issuer,
            "interfaces": ["W_iss", "W_red"],
        });
        assert!(json_has_key(&joined_wallet_audit, "wallet_entity_id"));
        assert!(json_has_key(
            &joined_wallet_audit,
            "selected_original_issuer_pk"
        ));
    }

    #[test]
    fn prf_serial_is_not_disclosed_and_is_checked() {
        let (holder, wallet, taxonomy, service, mut slot, _) = fixture();
        assert!(!slot
            .presentation
            .disclosed_messages
            .contains_key(&slot_name(0, "serial")));
        assert_eq!(
            slot.serials[&0],
            derive_slot_serial(holder.messages[&serial_seed_name("business")], 0)
        );
        slot.serials
            .insert(0, derive_slot_serial(random_scalar(), 0));
        let request = make_redeem_request(service, slot);
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        let (ok, reason) = redemption.redeem(&request, 1);
        assert!(!ok);
        assert_eq!(reason["reason"], "ack");
    }

    #[test]
    fn slot_serials_resist_the_legacy_public_normalization_linker() {
        let seed = random_scalar();
        let h0 = hash_to_scalar("mm-g1-generator", &[b"mm-slot-serial:0".to_vec()]);
        let h1 = hash_to_scalar("mm-g1-generator", &[b"mm-slot-serial:1".to_vec()]);
        let normalized0 = derive_slot_serial(seed, 0) * h0.invert().unwrap();
        let normalized1 = derive_slot_serial(seed, 1) * h1.invert().unwrap();

        assert_ne!(normalized0, normalized1);
    }

    #[test]
    fn request_bases_resist_the_legacy_known_dlog_equivocation() {
        let label0 = "mm-request-projection:hidden:service_input_digest";
        let label1 = "mm-request-projection:hidden:typed_request_digest";
        let h0 = hash_to_scalar("mm-g1-generator", &[label0.as_bytes().to_vec()]);
        let h1 = hash_to_scalar("mm-g1-generator", &[label1.as_bytes().to_vec()]);
        let value0 = random_scalar();
        let value1 = random_scalar();
        let delta = Scalar::from(7u64);
        let original = hash_g1(label0) * value0 + hash_g1(label1) * value1;
        let forged =
            hash_g1(label0) * (value0 + delta * h1) + hash_g1(label1) * (value1 - delta * h0);

        assert_ne!(original, forged);
    }

    #[test]
    fn rejects_tampered_prf_serial_even_if_context_matches() {
        let (_, wallet, taxonomy, service, mut slot, _) = fixture();
        slot.serials
            .insert(0, derive_slot_serial(random_scalar(), 0));
        if let Some(Value::Object(map)) = slot.context.get_mut("serials") {
            map.insert("0".to_string(), json!(g1_hex(&slot.serials[&0])));
        }
        let request = make_redeem_request(service, slot);
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        let (ok, reason) = redemption.redeem(&request, 1);
        assert!(!ok);
        assert_eq!(reason["reason"], "ack");
    }

    #[test]
    fn rejects_corrupted_proof_response() {
        let (_, wallet, taxonomy, service, mut slot, _) = fixture();
        let first = slot
            .presentation
            .proof
            .responses
            .keys()
            .next()
            .unwrap()
            .clone();
        let old = slot.presentation.proof.responses[&first];
        slot.presentation
            .proof
            .responses
            .insert(first, old + Scalar::ONE);
        let request = make_redeem_request(service, slot);
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        let (ok, reason) = redemption.redeem(&request, 1);
        assert!(!ok);
        assert!(
            reason["reason"] == "slot-proof"
                || reason["reason"] == "bind"
                || reason["reason"] == "ack"
        );
    }

    #[test]
    fn two_view_bind_rejects_splice_and_other_slot_under_same_ack() {
        let classes = vec!["business".to_string()];
        let merchants = vec!["merchant-bind".to_string(); 2];
        let (user, wallet, taxonomy) = build_system(2, &classes);
        let (holder, _) = issue_task_credential_with_expiries(
            &user,
            &wallet,
            &classes,
            &[5, 5],
            &["business".to_string(), "business".to_string()],
            &merchants,
            &[100, 100],
            10,
        )
        .unwrap();
        let merchant = Merchant {
            merchant_id: merchants[0].clone(),
            key: SchnorrKey::new(),
        };
        let make_views = |service_id: &str, slot_index: usize| {
            let input = service_input_digest(&default_service_input(service_id, "business"));
            let (q, preq, challenge, cert) = merchant_request(
                &merchant, &taxonomy, service_id, "business", &input, 5, 1, false,
            );
            derive_presentations(
                &holder,
                &wallet.issuance.verifier,
                &taxonomy.key.pk,
                &merchant,
                &q,
                &preq,
                &challenge,
                &cert,
                &[slot_index],
                1,
            )
            .unwrap()
        };
        let (service_zero, slot_zero) = make_views("service-zero", 0);
        let (service_one, slot_one) = make_views("service-one", 1);
        let request_zero = make_redeem_request(service_zero.clone(), slot_zero);
        assert_eq!(request_zero.ack.body["dM"], request_zero.merchant_digest);
        assert_eq!(request_zero.ack.body["dR"], request_zero.redemption_digest);
        assert_eq!(request_zero.ack.body["Bind"], request_zero.bind);

        let mut splice = make_redeem_request(service_one.clone(), slot_one.clone());
        splice.service = service_zero;
        splice.merchant_digest = merchant_view_digest(&splice.service);
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier.clone(), taxonomy.key.pk);
        let (fresh, rejection) = redemption.redeem(&splice, 1);
        assert!(!fresh);
        assert!(rejection["reason"] == "ack" || rejection["reason"] == "cross-view");

        let mut other_slot = make_redeem_request(service_one, slot_one);
        other_slot.ack = request_zero.ack;
        let (fresh, rejection) = redemption.redeem(&other_slot, 1);
        assert!(!fresh);
        assert_eq!(rejection["reason"], "ack");
    }

    #[test]
    fn slot_expiry_is_disclosed_only_to_the_wallet_facing_proof() {
        let classes = vec!["business".to_string()];
        let merchants = vec!["merchant-expiry".to_string(); 2];
        let (user, wallet, taxonomy) = build_system(2, &classes);
        let (holder, _) = issue_task_credential_with_expiries(
            &user,
            &wallet,
            &classes,
            &[5, 5],
            &["business".to_string(), "business".to_string()],
            &merchants,
            &[2, 100],
            10,
        )
        .unwrap();
        let merchant = Merchant {
            merchant_id: merchants[0].clone(),
            key: SchnorrKey::new(),
        };
        let input = service_input_digest(&default_service_input("expiry-service", "business"));
        let (q, preq, challenge, cert) = merchant_request(
            &merchant,
            &taxonomy,
            "expiry-service",
            "business",
            &input,
            5,
            1,
            false,
        );
        let (service, slot) = derive_presentations(
            &holder,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &merchant,
            &q,
            &preq,
            &challenge,
            &cert,
            &[0],
            1,
        )
        .unwrap();
        assert_eq!(
            service.presentation.disclosed_messages[EXPIRY_NAME],
            Scalar::from(100u64)
        );
        assert!(!service
            .presentation
            .disclosed_messages
            .contains_key(&slot_name(0, "expiry")));
        assert_eq!(
            slot.presentation.disclosed_messages[&slot_name(0, "expiry")],
            Scalar::from(2u64)
        );
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier.clone(), taxonomy.key.pk);
        let (fresh, rejection) = redemption.redeem(&make_redeem_request(service, slot), 3);
        assert!(!fresh);
        assert_eq!(rejection["reason"], "expiry");

        let (service, slot) = derive_presentations(
            &holder,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &merchant,
            &q,
            &preq,
            &challenge,
            &cert,
            &[0],
            3,
        )
        .unwrap();
        assert!(!redemption.redeem(&make_redeem_request(service, slot), 3).0);

        let (service, slot) = derive_presentations(
            &holder,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &merchant,
            &q,
            &preq,
            &challenge,
            &cert,
            &[1],
            3,
        )
        .unwrap();
        assert!(redemption.redeem(&make_redeem_request(service, slot), 3).0);
    }

    #[test]
    fn funding_reserve_and_signed_budget_are_independent_of_slot_capacity() {
        let classes = vec!["business".to_string()];
        let merchants = vec!["merchant-budget".to_string()];
        let (user, wallet, taxonomy) = build_system(1, &classes);
        {
            let mut funding = wallet.funding.lock().unwrap();
            funding.configured = true;
            funding.eligible = true;
            funding.available = 4;
        }
        assert!(issue_task_credential_with_expiries(
            &user,
            &wallet,
            &classes,
            &[10],
            &classes,
            &merchants,
            &[100],
            5,
        )
        .is_err());
        wallet.funding.lock().unwrap().available = 100;
        let (holder, metadata) = issue_task_credential_with_expiries(
            &user,
            &wallet,
            &classes,
            &[10],
            &classes,
            &merchants,
            &[100],
            5,
        )
        .unwrap();
        assert_eq!(metadata["funding_reserve"]["reserved_budget"], 5);
        assert_eq!(holder.messages[BUDGET_NAME], Scalar::from(5u64));
        assert_eq!(
            holder.messages[&slot_name(0, "capacity")],
            Scalar::from(10u64)
        );
        assert_eq!(wallet.funding.lock().unwrap().reserved, 5);

        let merchant = Merchant {
            merchant_id: merchants[0].clone(),
            key: SchnorrKey::new(),
        };
        let input = service_input_digest(&default_service_input("budget-service", "business"));
        let (q, preq, challenge, cert) = merchant_request(
            &merchant,
            &taxonomy,
            "budget-service",
            "business",
            &input,
            6,
            1,
            false,
        );
        let (service, slot) = derive_presentations(
            &holder,
            &wallet.issuance.verifier,
            &taxonomy.key.pk,
            &merchant,
            &q,
            &preq,
            &challenge,
            &cert,
            &[0],
            1,
        )
        .unwrap();
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        let (fresh, rejection) = redemption.redeem(&make_redeem_request(service, slot), 1);
        assert!(!fresh);
        assert_eq!(rejection["reason"], "budget");
        assert_eq!(rejection["settlement_authorization_issued"], false);
    }

    #[test]
    fn cumulative_redemption_cannot_exceed_signed_budget() {
        let classes = vec!["business".to_string()];
        let merchants = vec!["merchant-cumulative".to_string(); 2];
        let (user, wallet, taxonomy) = build_system(2, &classes);
        let (holder, _) = issue_task_credential_with_expiries(
            &user,
            &wallet,
            &classes,
            &[10, 10],
            &["business".to_string(), "business".to_string()],
            &merchants,
            &[100, 100],
            10,
        )
        .unwrap();
        let merchant = Merchant {
            merchant_id: merchants[0].clone(),
            key: SchnorrKey::new(),
        };
        let mut requests = Vec::new();
        for slot_index in 0..2 {
            let service_id = format!("cumulative-{slot_index}");
            let input = service_input_digest(&default_service_input(&service_id, "business"));
            let (q, preq, challenge, cert) = merchant_request(
                &merchant,
                &taxonomy,
                &service_id,
                "business",
                &input,
                6,
                1,
                false,
            );
            let (service, slot) = derive_presentations(
                &holder,
                &wallet.issuance.verifier,
                &taxonomy.key.pk,
                &merchant,
                &q,
                &preq,
                &challenge,
                &cert,
                &[slot_index],
                1,
            )
            .unwrap();
            requests.push(make_redeem_request(service, slot));
        }
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        assert!(redemption.redeem(&requests[0], 1).0);
        let (fresh, rejection) = redemption.redeem(&requests[1], 1);
        assert!(!fresh);
        assert_eq!(rejection["reason"], "budget");
    }

    #[test]
    fn local_settlement_authorization_and_receipt_are_signed_once() {
        let (_, wallet, taxonomy, _, _, request) = fixture();
        let mut redemption =
            RedemptionService::new_ephemeral(wallet.issuance.verifier, taxonomy.key.pk);
        let settlement_pk = redemption.settlement_key.pk;
        assert_ne!(settlement_pk, taxonomy.key.pk);
        assert_ne!(settlement_pk, request.service.q.merchant_pk);
        let (fresh, receipt) = redemption.redeem(&request, 1);
        assert!(fresh);
        assert!(verify_local_signed_record(
            &receipt["settlement_authorization"],
            &settlement_pk,
        ));
        assert!(verify_local_signed_record(
            &receipt["signed_receipt"],
            &settlement_pk,
        ));
        assert_eq!(receipt["real_payment_rail"], false);
        assert_eq!(receipt["transaction_broadcast"], false);

        let mut tampered = receipt["signed_receipt"].clone();
        tampered["statement"]["body"]["amount"] = json!(999);
        assert!(!verify_local_signed_record(&tampered, &settlement_pk));

        let (fresh, replay) = redemption.redeem(&request, 1);
        assert!(!fresh);
        assert_eq!(replay["outcome"], "idempotent_receipt");
        assert_eq!(replay["settlement_authorization_issued"], false);
        assert_eq!(
            replay["settlement_authorization"],
            receipt["settlement_authorization"]
        );
    }

    fn issuer_auth_fixture() -> (
        GroupStatusPublicKey,
        GroupStatusPresentation,
        Scalar,
        Scalar,
    ) {
        let registry = build_issuer_auth_registry(128);
        let (auth_sk, auth_pk) = group_status_keygen();
        let epoch = scalar_from_value(&json!("epoch-2026-06"));
        let expiry = Scalar::from(1_000_000u64);
        let context = auth_context(128, &registry, epoch);
        let wallet_id = registry_wallet_id(nonrevoked_wallet_index(128));
        let issuer_pk = registry_issuer_pk(wallet_id);
        let credential = issue_auth_credential(
            &auth_sk, &registry, wallet_id, issuer_pk, epoch, expiry, &context,
        )
        .unwrap();
        let presentation = present_auth_credential(&credential, &context);
        assert!(verify_auth_presentation(
            &auth_pk,
            &presentation,
            epoch,
            expiry,
            &context
        ));
        (auth_pk, presentation, epoch, expiry)
    }

    #[test]
    fn issuer_auth_accepts_nonrevoked_wallet() {
        let (_auth_pk, presentation, _epoch, _expiry) = issuer_auth_fixture();
        assert_eq!(presentation.disclosed_messages[AUTH_MEMBER], Scalar::ONE);
        assert_eq!(
            presentation.disclosed_messages[AUTH_NOT_REVOKED],
            Scalar::ONE
        );
        assert!(!presentation.disclosed_messages.contains_key(AUTH_WALLET_ID));
        assert!(!presentation.disclosed_messages.contains_key(AUTH_ISSUER_PK));
    }

    #[test]
    fn issuer_auth_rejects_revoked_wallet() {
        let registry = build_issuer_auth_registry(128);
        let (auth_sk, _auth_pk) = group_status_keygen();
        let epoch = scalar_from_value(&json!("epoch-2026-06"));
        let expiry = Scalar::from(1_000_000u64);
        let context = auth_context(128, &registry, epoch);
        let wallet_id = registry_wallet_id(revoked_wallet_index(128));
        let issuer_pk = registry_issuer_pk(wallet_id);
        let result = issue_auth_credential(
            &auth_sk, &registry, wallet_id, issuer_pk, epoch, expiry, &context,
        );
        assert!(result.is_err());
    }

    #[test]
    fn issuer_auth_rejects_tampered_issuer_key_binding() {
        let registry = build_issuer_auth_registry(128);
        let (auth_sk, auth_pk) = group_status_keygen();
        let epoch = scalar_from_value(&json!("epoch-2026-06"));
        let expiry = Scalar::from(1_000_000u64);
        let context = auth_context(128, &registry, epoch);
        let wallet_id = registry_wallet_id(nonrevoked_wallet_index(128));
        let issuer_pk = registry_issuer_pk(wallet_id);
        let credential = issue_auth_credential(
            &auth_sk, &registry, wallet_id, issuer_pk, epoch, expiry, &context,
        )
        .unwrap();
        let mut presentation = present_auth_credential(&credential, &context);
        presentation.randomized_issuer_pk += G2::generator();
        assert!(!verify_auth_presentation(
            &auth_pk,
            &presentation,
            epoch,
            expiry,
            &context
        ));
    }

    fn race_logical_results(rows: &[RaceRow]) -> Vec<Value> {
        rows.iter()
            .map(|row| {
                json!({
                    "run": row.run,
                    "concurrency": row.concurrency,
                    "accepted": row.accepted,
                    "rejected": row.rejected,
                    "double_spend_rejected": row.double_spend_rejected,
                    "other_rejected": row.other_rejected,
                    "state_backend": row.state_backend,
                    "locking_mechanism": row.locking_mechanism,
                    "linearizable": row.linearizable,
                })
            })
            .collect()
    }

    #[test]
    fn race_outer_parallelism_matches_sequential_logical_results() {
        let mut sequential_args = Args::default();
        sequential_args.runs = 2;
        sequential_args.race_concurrency = vec![2];
        sequential_args.race_jobs = 1;
        let jobs = materialize_race_jobs(&sequential_args);
        let sequential = run_race_jobs(&sequential_args, &jobs, |_job, _row| {}).unwrap();

        let mut parallel_args = sequential_args.clone();
        parallel_args.race_jobs = 2;
        let parallel = run_race_jobs(&parallel_args, &jobs, |_job, _row| {}).unwrap();

        assert_eq!(
            race_logical_results(&parallel),
            race_logical_results(&sequential)
        );
    }

    #[test]
    fn race_outer_parallelism_emits_rows_in_canonical_job_order() {
        let mut args = Args::default();
        args.runs = 3;
        args.race_concurrency = vec![2, 4];
        args.race_jobs = 3;
        let jobs = materialize_race_jobs(&args);
        let mut emitted = Vec::new();

        let rows = run_race_jobs_with(
            args.race_jobs,
            &jobs,
            |job| {
                std::thread::sleep(std::time::Duration::from_millis(
                    (4 - job.repetition) as u64,
                ));
                Ok(job.run_id)
            },
            |job, row| emitted.push((job.run_id, job.concurrency, job.repetition, *row)),
        )
        .unwrap();

        assert_eq!(rows, vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(
            emitted,
            jobs.iter()
                .map(|job| (job.run_id, job.concurrency, job.repetition, job.run_id))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn native_client_validator_accepts_valid_schnorr_and_rejects_tampering() {
        let key = SchnorrKey::new();
        let statement = json!({"domain": "native-validator-test", "body": {"call": 1}});
        let signature = key.sign(&statement);
        let item = json!({
            "verification_key": g1_hex(&key.pk),
            "statement": statement,
            "signature": signature.to_value(),
        });
        assert!(verify_native_schnorr_item(&item));

        let mut tampered = item;
        tampered["statement"]["body"]["call"] = json!(2);
        assert!(!verify_native_schnorr_item(&tampered));
        tampered["unexpected"] = json!(true);
        assert!(!verify_native_schnorr_item(&tampered));
    }

    #[test]
    fn compact_jsonl_transport_round_trips_and_rejects_tampering() {
        let payload = json!({
            "operation": "invoke",
            "proof": "ab".repeat(4096),
            "shared_view": {"I": "call-1", "Bind": "binding"},
        });
        let envelope = encode_jsonl_transport(&payload).unwrap();
        let (decoded, compact) = decode_jsonl_transport(&envelope.to_string()).unwrap();
        assert!(compact);
        assert_eq!(decoded, payload);
        assert!(
            envelope.to_string().len() < canonical_bytes(&payload).len(),
            "repetitive test payload should compress"
        );

        let mut tampered = envelope;
        tampered["uncompressed_sha256"] = json!("00".repeat(32));
        assert!(decode_jsonl_transport(&tampered.to_string()).is_err());
    }
}
