use core::hash;

use serde_json;
use starknet::{
    core::{
        types::{TypedData, U256},
        utils::cairo_short_string_to_felt,
    },
    macros::{felt, selector},
};
use starknet_crypto::Felt;
use starknet_crypto::PoseidonHasher;

use lazy_static::lazy_static;

lazy_static! {
    static ref MESSAGE_FELT: Felt = cairo_short_string_to_felt("StarkNet Message").unwrap();
}

trait Hashable {
    const SELECTOR: Felt;
    fn hash(&self) -> Felt;
}

trait OffChainMessage: Hashable {
    fn message_hash(&self, stark_domain: &StarknetDomain, public_key: Felt) -> Option<Felt> {
        // let mut state = PoseidonTrait::new();
        // state = state.update_with('StarkNet Message');
        // state = state.update_with(domain.hash_struct());
        // state = state.update_with(public_key);
        // state = state.update_with(self.hash_struct());
        // state.finalize()

        let mut hasher = PoseidonHasher::new();
        hasher.update(*MESSAGE_FELT);
        hasher.update(stark_domain.hash());
        hasher.update(public_key);
        hasher.update(self.hash());
        Some(hasher.finalize())
    }
}

pub struct Timestamp {
    pub seconds: u64,
}

pub struct Order {
    pub position_id: PositionId,
    pub base_asset_id: AssetId,
    pub base_amount: i64,
    pub quote_asset_id: AssetId,
    pub quote_amount: i64,
    pub fee_asset_id: AssetId,
    pub fee_amount: u64,
    pub expiration: Timestamp,
    pub salt: Felt,
}

pub struct StarknetDomain {
    pub name: String,
    pub version: String,
    pub chain_id: String,
    pub revision: String,
}

pub struct AssetId {
    pub value: Felt,
}
pub struct PositionId {
    pub value: Felt,
}

pub struct AssetAmount {
    pub asset_id: AssetId,
    pub amount: i64,
}

pub struct TransferArgs {
    pub position_id: u32,
    pub recipient: u32,
    pub salt: Felt,
    pub expiration: u64,
    pub collateral: AssetAmount,
}

impl Hashable for StarknetDomain {
    const SELECTOR: Felt = selector!("\"StarknetDomain\"(\"name\":\"shortstring\",\"version\":\"shortstring\",\"chainId\":\"shortstring\",\"revision\":\"shortstring\")");

    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(cairo_short_string_to_felt(&self.name).unwrap());
        hasher.update(cairo_short_string_to_felt(&self.version).unwrap());
        hasher.update(cairo_short_string_to_felt(&self.chain_id).unwrap());
        hasher.update(cairo_short_string_to_felt(&self.revision).unwrap());
        hasher.finalize()
    }
}

impl Hashable for Order {
    const SELECTOR: Felt = selector!("\"Order\"(\"position_id\":\"felt\",\"base_asset_id\":\"AssetId\",\"base_amount\":\"i64\",\"quote_asset_id\":\"AssetId\",\"quote_amount\":\"i64\",\"fee_asset_id\":\"AssetId\",\"fee_amount\":\"u64\",\"expiration\":\"Timestamp\",\"salt\":\"felt\")\"PositionId\"(\"value\":\"felt\")\"AssetId\"(\"value\":\"felt\")\"Timestamp\"(\"seconds\":\"u64\")");
    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(self.position_id.value.into());
        hasher.update(self.base_asset_id.value.into());
        hasher.update(self.base_amount.into());
        hasher.update(self.quote_asset_id.value.into());
        hasher.update(self.quote_amount.into());
        hasher.update(self.fee_asset_id.value.into());
        hasher.update(self.fee_amount.into());
        hasher.update(self.expiration.seconds.into());
        hasher.update(self.salt.into());
        hasher.finalize()
    }
}

impl OffChainMessage for Order {}

impl Hashable for TransferArgs {
    const SELECTOR: Felt = selector!(
        "\"TransferArgs\"(
        \"position_id\":\"PositionId\",
        \"recipient\":\"PositionId\",
        \"salt\":\"felt\",
        \"expiration\":\"Timestamp\",
        \"collateral\":\"AssetAmount\"
      )\"PositionId\"(\"value\":\"felt\")\"Timestamp\"(\"seconds\":\"u64\")\"AssetAmount\"(\"asset_id\":\"AssetId\",\"amount\":\"i64\")\"AssetId\"(\"value\":\"felt\")"
    );

    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(self.position_id.into());
        hasher.update(self.recipient.into());
        hasher.update(self.salt.into());
        hasher.update(self.expiration.into());
        hasher.update(self.collateral.asset_id.value.into());
        hasher.update(self.collateral.amount.into());
        hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use starknet::{
        core::types::Felt,
        macros::{felt_dec, selector},
    };
    use starknet_crypto::PoseidonHasher;

    use super::*;

    #[test]
    fn go_for_it() {
        let args = TransferArgs {
            position_id: 1,
            recipient: 2,
            salt: 3.into(),
            expiration: 4,
            collateral: AssetAmount {
                asset_id: AssetId { value: 5.into() },
                amount: 6,
            },
        };

        let mut hasher = PoseidonHasher::new();
        hasher.update(
            Felt::from_hex(
                &selector!(
                "\"TransferArgs\"(\"position_id\":\"PositionId\",\"recipient\":\"PositionId\",\"salt\":\"felt\",\"expiration\":\"Timestamp\",\"collateral\":\"AssetAmount\")\"PositionId\"(\"value\":\"felt\")\"Timestamp\"(\"seconds\":\"u64\")\"AssetAmount\"(\"asset_id\":\"AssetId\",\"amount\":\"i64\")\"AssetId\"(\"value\":\"felt\")"
            ).to_hex_string()).unwrap(),
        );
        hasher.update(args.position_id.into());
        hasher.update(args.recipient.into());
        hasher.update(args.salt.into());
        hasher.update(args.expiration.into());
        hasher.update(args.collateral.asset_id.value.into());
        hasher.update(args.collateral.amount.into());

        let hash_value = hasher.finalize().to_hex_string();
        assert_eq!(
            hash_value,
            "0x4bad2287e5c6e12d33c63ed020e0e9c4b30bbdcb1bc4967fc6ff372180266e5"
        );
    }

    #[test]
    fn test_starknet_domain_selector() {
        let expected = Felt::from_hex_unchecked(
            "0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210",
        );
        let actual = StarknetDomain::SELECTOR;
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_starknet_domain_hashing() {
        let domain = StarknetDomain {
            name: "DAPP_NAME".to_string(),
            version: "v1".to_string(),
            chain_id: "TEST".to_string(),
            revision: "1".to_string(),
        };

        let actual = domain.hash();
        let expected = felt_dec!(
            "3433281071040767640814709368600706933598428900379824095511832833121789562575"
        );
        assert_eq!(actual, expected, "Hashes do not match for StarknetDomain");
    }

    #[test]
    fn test_order_selector() {
        let expected = Felt::from_hex_unchecked(
            "0x26e3f2492aae9866d09bd1635084175acbb80a33730cd0f2314b21c7f9d47eb",
        );
        let actual = Order::SELECTOR;
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_order_hashing() {
        let order = Order {
            position_id: PositionId {
                value: Felt::from_dec_str("1").unwrap(),
            },
            base_asset_id: AssetId {
                value: Felt::from_dec_str("2").unwrap(),
            },
            base_amount: 3,
            quote_asset_id: AssetId {
                value: Felt::from_dec_str("4").unwrap(),
            },
            quote_amount: 5,
            fee_asset_id: AssetId {
                value: Felt::from_dec_str("6").unwrap(),
            },
            fee_amount: 7,
            expiration: Timestamp { seconds: 8 },
            salt: Felt::from_dec_str("9").unwrap(),
        };

        let actual = order.hash();
        let expected = Felt::from_dec_str(
            "946920802435170097603289101599594900042939783390096257589678239726650388230",
        )
        .unwrap();
        assert_eq!(actual, expected, "Hashes do not match for Order");
    }

    #[test]
    fn test_message_hash() {
        let domain = StarknetDomain {
            name: "Perpetuals".to_string(),
            version: "v0".to_string(),
            chain_id: "SN_SEPOLIA".to_string(),
            revision: "1".to_string(),
        };

        let user_key = Felt::from_dec_str(
            "2629686405885377265612250192330550814166101744721025672593857097107510831364",
        )
        .unwrap();

        let order = Order {
            position_id: PositionId {
                value: Felt::from_dec_str("1").unwrap(),
            },
            base_asset_id: AssetId {
                value: Felt::from_dec_str("2").unwrap(),
            },
            base_amount: 3,
            quote_asset_id: AssetId {
                value: Felt::from_dec_str("4").unwrap(),
            },
            quote_amount: 5,
            fee_asset_id: AssetId {
                value: Felt::from_dec_str("6").unwrap(),
            },
            fee_amount: 7,
            expiration: Timestamp { seconds: 8 },
            salt: Felt::from_dec_str("9").unwrap(),
        };

        let actual = order.message_hash(&domain, user_key);
        let expected = Felt::from_dec_str(
            "2065028989800275619145929126273137957172733560534383417997414892126195744726",
        )
        .unwrap();

        assert_eq!(actual, Some(expected), "Hashes do not match for Order");
    }
}
