use hex;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use starknet::core::crypto::ecdsa_sign;
use starknet_crypto::Felt;
use std::str::FromStr;
pub mod starknet_messages;

pub struct StarkSignature {
    pub r: Felt,
    pub s: Felt,
    pub v: Felt,
}

fn grind_key(key_seed: BigUint) -> BigUint {
    let two_256 = BigUint::from_str(
        "115792089237316195423570985008687907853269984665640564039457584007913129639936",
    )
    .unwrap();
    let key_value_limit = BigUint::from_str(
        "3618502788666131213697322783095070105526743751716087489154079457884512865583",
    )
    .unwrap();

    let max_allowed_value = two_256.clone() - (two_256.clone() % (&key_value_limit));
    let mut index = BigUint::ZERO;
    loop {
        let hash_input = {
            let mut input = Vec::new();
            input.extend_from_slice(&key_seed.to_bytes_be());
            input.extend_from_slice(&index.to_bytes_be());
            input
        };
        let hash_result = Sha256::digest(&hash_input);
        let hash = hash_result.as_slice();
        let key = BigUint::from_bytes_be(&hash);

        if key < max_allowed_value {
            return key % (&key_value_limit);
        }

        index += BigUint::from_str("1").unwrap();
    }
}

pub fn get_private_key_from_eth_signature(signature: &str) -> Result<Felt, String> {
    let eth_sig_truncated = signature.trim_start_matches("0x");
    if eth_sig_truncated.len() < 64 {
        return Err("Invalid signature length".to_string());
    }
    let r = &eth_sig_truncated[..64];
    let r_bytes = hex::decode(r).map_err(|e| format!("Failed to decode r as hex: {:?}", e))?;
    let r_int = BigUint::from_bytes_be(&r_bytes);

    let ground_key = grind_key(r_int);
    return Ok(Felt::from_hex(&ground_key.to_str_radix(16)).unwrap());
}

pub fn sign_message(message: &Felt, private_key: &Felt) -> Result<StarkSignature, String> {
    return ecdsa_sign(private_key, &message)
        .map(|extended_signature| StarkSignature {
            r: extended_signature.r,
            s: extended_signature.s,
            v: extended_signature.v,
        })
        .map_err(|e| format!("Failed to sign message: {:?}", e));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_private_key_from_eth_signature() {
        let signature = "0x9ef64d5936681edf44b4a7ad713f3bc24065d4039562af03fccf6a08d6996eab367df11439169b417b6a6d8ce81d409edb022597ce193916757c7d5d9cbf97301c";
        let result = get_private_key_from_eth_signature(signature);

        match result {
            Ok(private_key) => {
                assert_eq!(private_key, Felt::from_dec_str("3554363360756768076148116215296798451844584215587910826843139626172125285444").unwrap());
            }
            Err(err) => {
                panic!("Expected Ok, got Err: {}", err);
            }
        }
    }
}
