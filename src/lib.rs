use hex;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use starknet::core::crypto::ecdsa_sign;
use starknet::core::types::Felt;
use std::str::FromStr;

use crate::starknet_messages::{
    AssetId, OffChainMessage, Order, PositionId, StarknetDomain, Timestamp, TransferArgs,
};
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

// these functions are designed to be called from other languages, such as Python or JavaScript,
// so they take string arguments.
pub fn get_order_hash(
    position_id: String,
    base_asset_id_hex: String,
    base_amount: String,
    quote_asset_id_hex: String,
    quote_amount: String,
    fee_asset_id_hex: String,
    fee_amount: String,
    expiration: String,
    salt: String,
    user_public_key_hex: String,
    domain_name: String,
    domain_version: String,
    domain_chain_id: String,
    domain_revision: String,
) -> Result<Felt, String> {
    let base_asset_id = Felt::from_hex(&base_asset_id_hex)
        .map_err(|e| format!("Invalid base_asset_id_hex: {:?}", e))?;
    let quote_asset_id = Felt::from_hex(&quote_asset_id_hex)
        .map_err(|e| format!("Invalid quote_asset_id_hex: {:?}", e))?;
    let fee_asset_id = Felt::from_hex(&fee_asset_id_hex)
        .map_err(|e| format!("Invalid fee_asset_id_hex: {:?}", e))?;
    let user_key = Felt::from_hex(&user_public_key_hex)
        .map_err(|e| format!("Invalid user_public_key_hex: {:?}", e))?;

    let position_id = u32::from_str_radix(&position_id, 10)
        .map_err(|e| format!("Invalid position_id: {:?}", e))?;
    let base_amount = i64::from_str_radix(&base_amount, 10)
        .map_err(|e| format!("Invalid base_amount: {:?}", e))?;
    let quote_amount = i64::from_str_radix(&quote_amount, 10)
        .map_err(|e| format!("Invalid quote_amount: {:?}", e))?;
    let fee_amount =
        u64::from_str_radix(&fee_amount, 10).map_err(|e| format!("Invalid fee_amount: {:?}", e))?;
    let expiration =
        u64::from_str_radix(&expiration, 10).map_err(|e| format!("Invalid expiration: {:?}", e))?;
    let salt = u64::from_str_radix(&salt, 10).map_err(|e| format!("Invalid salt: {:?}", e))?;
    let revision = u32::from_str_radix(&domain_revision, 10)
        .map_err(|e| format!("Invalid domain_revision: {:?}", e))?;

    let order = Order {
        position_id: PositionId { value: position_id },
        base_asset_id: AssetId {
            value: base_asset_id,
        },
        base_amount,
        quote_asset_id: AssetId {
            value: quote_asset_id,
        },
        quote_amount,
        fee_asset_id: AssetId {
            value: fee_asset_id,
        },
        fee_amount,
        expiration: Timestamp {
            seconds: expiration,
        },
        salt: salt
            .try_into()
            .map_err(|e| format!("Invalid salt vault: {:?}", e))?,
    };
    let domain = StarknetDomain {
        name: domain_name,
        version: domain_version,
        chain_id: domain_chain_id,
        revision,
    };
    order
        .message_hash(&domain, user_key)
        .map_err(|e| format!("Failed to compute message hash: {:?}", e))
}

pub fn get_transfer_hash(
    recipient_position_id: String,
    sender_position_id: String,
    collateral_id_hex: String,
    amount: String,
    expiration: String,
    salt: String,
    user_public_key_hex: String,
    domain_name: String,
    domain_version: String,
    domain_chain_id: String,
    domain_revision: String,
) -> Result<Felt, String> {
    let collateral_id = Felt::from_hex(&collateral_id_hex)
        .map_err(|e| format!("Invalid collateral_id_hex: {:?}", e))?;
    let user_key = Felt::from_hex(&user_public_key_hex)
        .map_err(|e| format!("Invalid user_public_key_hex: {:?}", e))?;

    let recipient = u32::from_str_radix(&recipient_position_id, 10)
        .map_err(|e| format!("Invalid recipient_position_id: {:?}", e))?;
    let position_id = u32::from_str_radix(&sender_position_id, 10)
        .map_err(|e| format!("Invalid sender_position_id: {:?}", e))?;
    let amount =
        u64::from_str_radix(&amount, 10).map_err(|e| format!("Invalid amount: {:?}", e))?;
    let expiration =
        u64::from_str_radix(&expiration, 10).map_err(|e| format!("Invalid expiration: {:?}", e))?;
    let salt = Felt::from_dec_str(&salt).map_err(|e| format!("Invalid salt: {:?}", e))?;
    let revision = u32::from_str_radix(&domain_revision, 10)
        .map_err(|e| format!("Invalid domain_revision: {:?}", e))?;

    let transfer_args = TransferArgs {
        recipient: PositionId { value: recipient },
        position_id: PositionId { value: position_id },
        collateral_id: AssetId {
            value: collateral_id,
        },
        amount,
        expiration: Timestamp {
            seconds: expiration,
        },
        salt,
    };
    let domain = StarknetDomain {
        name: domain_name,
        version: domain_version,
        chain_id: domain_chain_id,
        revision,
    };
    transfer_args
        .message_hash(&domain, user_key)
        .map_err(|e| format!("Failed to compute message hash: {:?}", e))
}

pub fn get_withdrawal_hash(
    recipient_hex: String,
    position_id: String,
    collateral_id_hex: String,
    amount: String,
    expiration: String,
    salt: String,
    user_public_key_hex: String,
    domain_name: String,
    domain_version: String,
    domain_chain_id: String,
    domain_revision: String,
) -> Result<Felt, String> {
    let collateral_id = Felt::from_hex(&collateral_id_hex)
        .map_err(|e| format!("Invalid collateral_id_hex: {:?}", e))?;
    let user_key = Felt::from_hex(&user_public_key_hex)
        .map_err(|e| format!("Invalid user_public_key_hex: {:?}", e))?;

    let recipient =
        Felt::from_hex(&recipient_hex).map_err(|e| format!("Invalid recipient_hex: {:?}", e))?;
    let position_id = u32::from_str_radix(&position_id, 10)
        .map_err(|e| format!("Invalid position_id: {:?}", e))?;
    let amount =
        u64::from_str_radix(&amount, 10).map_err(|e| format!("Invalid amount: {:?}", e))?;
    let expiration =
        u64::from_str_radix(&expiration, 10).map_err(|e| format!("Invalid expiration: {:?}", e))?;
    let salt = Felt::from_dec_str(&salt).map_err(|e| format!("Invalid salt: {:?}", e))?;
    let revision = u32::from_str_radix(&domain_revision, 10)
        .map_err(|e| format!("Invalid domain_revision: {:?}", e))?;

    let withdrawal_args = starknet_messages::WithdrawalArgs {
        recipient,
        position_id: PositionId { value: position_id },
        collateral_id: AssetId {
            value: collateral_id,
        },
        amount,
        expiration: Timestamp {
            seconds: expiration,
        },
        salt,
    };
    let domain = StarknetDomain {
        name: domain_name,
        version: domain_version,
        chain_id: domain_chain_id,
        revision,
    };
    withdrawal_args
        .message_hash(&domain, user_key)
        .map_err(|e| {
            format!(
                "Failed to compute message hash for withdrawal args: {:?}",
                e
            )
        })
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

    #[test]
    fn test_get_transfer_msg() {
        let recipient_position_id = "1".to_string();
        let sender_position_id = "2".to_string();
        let collateral_id_hex = "0x3".to_string();
        let amount = "4".to_string();
        let expiration = "5".to_string();
        let salt = "6".to_string();
        let user_public_key_hex =
            "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string();
        let domain_name = "Perpetuals".to_string();
        let domain_version = "v0".to_string();
        let domain_chain_id = "SN_SEPOLIA".to_string();
        let domain_revision = "1".to_string();

        let result = get_transfer_hash(
            recipient_position_id,
            sender_position_id,
            collateral_id_hex,
            amount,
            expiration,
            salt,
            user_public_key_hex,
            domain_name,
            domain_version,
            domain_chain_id,
            domain_revision,
        );

        match result {
            Ok(hash) => {
                assert_eq!(
                    hash,
                    Felt::from_hex(
                        "0x56c7b21d13b79a33d7700dda20e22246c25e89818249504148174f527fc3f8f"
                    )
                    .unwrap()
                );
            }
            Err(err) => {
                panic!("Expected Ok, got Err: {}", err);
            }
        }
    }

    #[test]
    fn test_get_order_hash() {
        let position_id = "100".to_string();
        let base_asset_id_hex = "0x2".to_string();
        let base_amount = "100".to_string();
        let quote_asset_id_hex = "0x1".to_string();
        let quote_amount = "-156".to_string();
        let fee_asset_id_hex = "0x1".to_string();
        let fee_amount = "74".to_string();
        let expiration = "100".to_string();
        let salt = "123".to_string();
        let user_public_key_hex =
            "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string();
        let domain_name = "Perpetuals".to_string();
        let domain_version = "v0".to_string();
        let domain_chain_id = "SN_SEPOLIA".to_string();
        let domain_revision = "1".to_string();

        let result = get_order_hash(
            position_id,
            base_asset_id_hex,
            base_amount,
            quote_asset_id_hex,
            quote_amount,
            fee_asset_id_hex,
            fee_amount,
            expiration,
            salt,
            user_public_key_hex,
            domain_name,
            domain_version,
            domain_chain_id,
            domain_revision,
        );

        match result {
            Ok(hash) => {
                assert_eq!(
                    hash,
                    Felt::from_hex(
                        "0x4de4c009e0d0c5a70a7da0e2039fb2b99f376d53496f89d9f437e736add6b48"
                    )
                    .unwrap()
                );
            }
            Err(err) => {
                panic!("Expected Ok, got Err: {}", err);
            }
        }
    }

    #[test]
    fn test_get_withdrawal_hash() {
        let recipient_hex = Felt::from_dec_str(
            "206642948138484946401984817000601902748248360221625950604253680558965863254",
        )
        .unwrap()
        .to_hex_string();
        let position_id = "2".to_string();
        let collateral_id_hex = Felt::from_dec_str(
            "1386727789535574059419576650469753513512158569780862144831829362722992755422",
        )
        .unwrap()
        .to_hex_string();
        let amount = "1000".to_string();
        let expiration = "0".to_string();
        let salt = "0".to_string();
        let user_public_key_hex =
            "0x5D05989E9302DCEBC74E241001E3E3AC3F4402CCF2F8E6F74B034B07AD6A904".to_string();
        let domain_name = "Perpetuals".to_string();
        let domain_version = "v0".to_string();
        let domain_chain_id = "SN_SEPOLIA".to_string();
        let domain_revision = "1".to_string();
        let result = get_withdrawal_hash(
            recipient_hex,
            position_id,
            collateral_id_hex,
            amount,
            expiration,
            salt,
            user_public_key_hex,
            domain_name,
            domain_version,
            domain_chain_id,
            domain_revision,
        );
        match result {
            Ok(hash) => {
                assert_eq!(
                    hash,
                    Felt::from_dec_str(
                        "2182119571682827544073774098906745929330860211691330979324731407862023927178"
                    )
                    .unwrap()
                );
            }
            Err(err) => {
                panic!("Expected Ok, got Err: {}", err);
            }
        }
    }
}
