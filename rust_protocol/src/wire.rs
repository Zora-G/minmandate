//! Canonical project-owned wire encodings for the MinMandate prototype.
//!
//! These encodings use halo2curves' compressed BLS12-381 representation and
//! canonical scalar representation.  They are intentionally not advertised as
//! CFRG BBS wire encodings.  Decoding additionally enforces subgroup membership
//! and rejects identity points at protocol boundaries.

use crate::{Result, Scalar, G1, G2};
use ff::{Field, PrimeField};
use group::{cofactor::CofactorGroup, Group, GroupEncoding};
use halo2curves::bls12381::{G1Affine, G2Affine};

pub(crate) const G1_COMPRESSED_BYTES: usize = 48;
pub(crate) const G2_COMPRESSED_BYTES: usize = 96;
pub(crate) const SCALAR_BYTES: usize = 32;

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0] as u32;
        let b = chunk.get(1).copied().unwrap_or(0) as u32;
        let c = chunk.get(2).copied().unwrap_or(0) as u32;
        let word = (a << 16) | (b << 8) | c;
        out.push(BASE64_ALPHABET[((word >> 18) & 0x3f) as usize] as char);
        out.push(BASE64_ALPHABET[((word >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            BASE64_ALPHABET[((word >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64_ALPHABET[(word & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub(crate) fn base64_decode(value: &str) -> Result<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return Err("invalid base64 length".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (chunk_index, chunk) in bytes.chunks_exact(4).enumerate() {
        let is_last = chunk_index + 1 == bytes.len() / 4;
        let padding = match (chunk[2], chunk[3]) {
            (b'=', b'=') => 2,
            (_, b'=') => 1,
            (b'=', _) => return Err("invalid base64 padding".to_string()),
            _ => 0,
        };
        if padding != 0 && !is_last {
            return Err("base64 padding is only allowed in the final quartet".to_string());
        }
        let a = base64_value(chunk[0]).ok_or_else(|| "invalid base64 digit".to_string())?;
        let b = base64_value(chunk[1]).ok_or_else(|| "invalid base64 digit".to_string())?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            base64_value(chunk[2]).ok_or_else(|| "invalid base64 digit".to_string())?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            base64_value(chunk[3]).ok_or_else(|| "invalid base64 digit".to_string())?
        };
        if (padding == 2 && (b & 0x0f) != 0) || (padding == 1 && (c & 0x03) != 0) {
            return Err("non-canonical base64 trailing bits".to_string());
        }
        let word = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | d as u32;
        out.push((word >> 16) as u8);
        if padding < 2 {
            out.push((word >> 8) as u8);
        }
        if padding == 0 {
            out.push(word as u8);
        }
    }
    if base64_encode(&out) != value {
        return Err("non-canonical base64 encoding".to_string());
    }
    Ok(out)
}

pub(crate) fn encode_g1(point: &G1) -> Vec<u8> {
    G1Affine::from(*point).to_bytes().as_ref().to_vec()
}

pub(crate) fn encode_g2(point: &G2) -> Vec<u8> {
    G2Affine::from(*point).to_bytes().as_ref().to_vec()
}

pub(crate) fn encode_scalar(value: &Scalar) -> Vec<u8> {
    value.to_repr().as_ref().to_vec()
}

pub(crate) fn decode_g1(bytes: &[u8]) -> Result<G1> {
    if bytes.len() != G1_COMPRESSED_BYTES {
        return Err("invalid G1 compressed length".to_string());
    }
    let mut repr = <G1Affine as GroupEncoding>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    let affine = Option::<G1Affine>::from(G1Affine::from_bytes(&repr))
        .ok_or_else(|| "malformed or non-canonical G1 encoding".to_string())?;
    let point = G1::from(affine);
    if point == G1::identity() {
        return Err("identity G1 point is forbidden".to_string());
    }
    if !bool::from(point.is_torsion_free()) {
        return Err("G1 point is outside the prime-order subgroup".to_string());
    }
    if encode_g1(&point) != bytes {
        return Err("non-canonical G1 encoding".to_string());
    }
    Ok(point)
}

pub(crate) fn decode_g2(bytes: &[u8]) -> Result<G2> {
    if bytes.len() != G2_COMPRESSED_BYTES {
        return Err("invalid G2 compressed length".to_string());
    }
    let mut repr = <G2Affine as GroupEncoding>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    let affine = Option::<G2Affine>::from(G2Affine::from_bytes(&repr))
        .ok_or_else(|| "malformed or non-canonical G2 encoding".to_string())?;
    let point = G2::from(affine);
    if point == G2::identity() {
        return Err("identity G2 point is forbidden".to_string());
    }
    if !bool::from(point.is_torsion_free()) {
        return Err("G2 point is outside the prime-order subgroup".to_string());
    }
    if encode_g2(&point) != bytes {
        return Err("non-canonical G2 encoding".to_string());
    }
    Ok(point)
}

pub(crate) fn decode_scalar(bytes: &[u8]) -> Result<Scalar> {
    if bytes.len() != SCALAR_BYTES {
        return Err("invalid scalar length".to_string());
    }
    let mut repr = <Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    let value = Option::<Scalar>::from(Scalar::from_repr(repr))
        .ok_or_else(|| "non-canonical scalar encoding".to_string())?;
    if encode_scalar(&value) != bytes {
        return Err("non-canonical scalar encoding".to_string());
    }
    Ok(value)
}

pub(crate) fn decode_nonzero_scalar(bytes: &[u8]) -> Result<Scalar> {
    let value = decode_scalar(bytes)?;
    if value == Scalar::ZERO {
        return Err("zero scalar is forbidden at this protocol boundary".to_string());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    fn first_non_subgroup_g1_encoding() -> Vec<u8> {
        for counter in 1u64..100_000 {
            let mut bytes = vec![0u8; G1_COMPRESSED_BYTES];
            bytes[0] = 0x80;
            bytes[G1_COMPRESSED_BYTES - 8..].copy_from_slice(&counter.to_be_bytes());
            let mut repr = <G1Affine as GroupEncoding>::Repr::default();
            repr.as_mut().copy_from_slice(&bytes);
            if let Some(affine) = Option::<G1Affine>::from(G1Affine::from_bytes(&repr)) {
                let point = G1::from(affine);
                if point != G1::identity() && !bool::from(point.is_torsion_free()) {
                    return bytes;
                }
            }
        }
        panic!("could not construct a deterministic non-subgroup G1 test vector");
    }

    fn first_non_subgroup_g2_encoding() -> Vec<u8> {
        for counter in 1u64..100_000 {
            let mut bytes = vec![0u8; G2_COMPRESSED_BYTES];
            bytes[0] = 0x80;
            bytes[G2_COMPRESSED_BYTES - 8..].copy_from_slice(&counter.to_be_bytes());
            let mut repr = <G2Affine as GroupEncoding>::Repr::default();
            repr.as_mut().copy_from_slice(&bytes);
            if let Some(affine) = Option::<G2Affine>::from(G2Affine::from_bytes(&repr)) {
                let point = G2::from(affine);
                if point != G2::identity() && !bool::from(point.is_torsion_free()) {
                    return bytes;
                }
            }
        }
        panic!("could not construct a deterministic non-subgroup G2 test vector");
    }

    #[test]
    fn standard_bls12381_encoding_goldens_round_trip() {
        let g1 = decode_hex(
            "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac5\
             86c55e83ff97a1aeffb3af00adb22c6bb"
                .split_whitespace()
                .collect::<String>()
                .as_str(),
        );
        let g2 = decode_hex(
            "824aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d177\
             0bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65\
             596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
                .split_whitespace()
                .collect::<String>()
                .as_str(),
        );
        let one = decode_hex("0100000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(decode_g1(&g1).unwrap(), G1::generator());
        assert_eq!(decode_g2(&g2).unwrap(), G2::generator());
        assert_eq!(decode_nonzero_scalar(&one).unwrap(), Scalar::ONE);
        assert_eq!(encode_g1(&G1::generator()), g1);
        assert_eq!(encode_g2(&G2::generator()), g2);
        assert_eq!(encode_scalar(&Scalar::ONE), one);
    }

    #[test]
    fn canonical_base64_round_trip_and_rejections() {
        for input in [b"a".as_slice(), b"ab", b"abc", b"issuer-policy"] {
            let encoded = base64_encode(input);
            assert_eq!(base64_decode(&encoded).unwrap(), input);
        }
        assert!(base64_decode("").is_err());
        assert!(base64_decode("YQ=").is_err());
        assert!(base64_decode("YR==").is_err());
        assert!(base64_decode("YQ==AAAA").is_err());
    }

    #[test]
    fn rejects_identity_malformed_noncanonical_and_wrong_subgroup_encodings() {
        assert!(decode_g1(&encode_g1(&G1::identity())).is_err());
        assert!(decode_g2(&encode_g2(&G2::identity())).is_err());
        assert!(decode_nonzero_scalar(&encode_scalar(&Scalar::ZERO)).is_err());

        let mut malformed_g1 = encode_g1(&G1::generator());
        malformed_g1[0] &= 0x7f;
        assert!(decode_g1(&malformed_g1).is_err());
        let mut malformed_g2 = encode_g2(&G2::generator());
        malformed_g2[0] &= 0x7f;
        assert!(decode_g2(&malformed_g2).is_err());
        assert!(decode_scalar(&[0xff; SCALAR_BYTES]).is_err());

        assert!(decode_g1(&first_non_subgroup_g1_encoding()).is_err());
        assert!(decode_g2(&first_non_subgroup_g2_encoding()).is_err());
    }
}
