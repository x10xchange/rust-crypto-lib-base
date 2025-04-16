use starknet::core::utils::cairo_short_string_to_felt;

use starknet::macros::selector;
use starknet_crypto::Felt;
use starknet_crypto::PoseidonHasher;

use std::sync::LazyLock;

static MESSAGE_FELT: LazyLock<Felt> =
    LazyLock::new(|| cairo_short_string_to_felt("StarkNet Message").unwrap());

pub trait Hashable {
    const SELECTOR: Felt;
    fn hash(&self) -> Felt;
}

pub trait OffChainMessage: Hashable {
    fn message_hash(&self, stark_domain: &StarknetDomain, public_key: Felt) -> Option<Felt> {
        let mut hasher = PoseidonHasher::new();
        hasher.update(*MESSAGE_FELT);
        hasher.update(stark_domain.hash());
        hasher.update(public_key);
        hasher.update(self.hash());
        Some(hasher.finalize())
    }
}

pub struct StarknetDomain {
    pub name: String,
    pub version: String,
    pub chain_id: String,
    pub revision: String,
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
        let hash = hasher.finalize();
        return hash;
    }
}

pub struct AssetId {
    pub value: Felt,
}
pub struct PositionId {
    pub value: u32,
}

pub struct AssetAmount {
    pub asset_id: AssetId,
    pub amount: i64,
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

impl Hashable for Order {
    const SELECTOR: Felt = selector!("\"Order\"(\"position_id\":\"felt\",\"base_asset_id\":\"AssetId\",\"base_amount\":\"i64\",\"quote_asset_id\":\"AssetId\",\"quote_amount\":\"i64\",\"fee_asset_id\":\"AssetId\",\"fee_amount\":\"u64\",\"expiration\":\"Timestamp\",\"salt\":\"felt\")\"PositionId\"(\"value\":\"u32\")\"AssetId\"(\"value\":\"felt\")\"Timestamp\"(\"seconds\":\"u64\")");
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
        hasher.update(self.salt);
        hasher.finalize()
    }
}
impl OffChainMessage for Order {}

pub struct TransferArgs {
    pub recipient: PositionId,
    pub position_id: PositionId,
    pub collateral_id: AssetId,
    pub amount: u64,
    pub expiration: Timestamp,
    pub salt: Felt,
}

impl Hashable for TransferArgs {
    const SELECTOR: Felt = selector!("\"TransferArgs\"(\"recipient\":\"PositionId\",\"position_id\":\"PositionId\",\"collateral_id\":\"AssetId\",\"amount\":\"u64\",\"expiration\":\"Timestamp\",\"salt\":\"felt\")\"PositionId\"(\"value\":\"u32\")\"AssetId\"(\"value\":\"felt\")\"Timestamp\"(\"seconds\":\"u64\")");
    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(self.recipient.value.into());
        hasher.update(self.position_id.value.into());
        hasher.update(self.collateral_id.value.into());
        hasher.update(self.amount.into());
        hasher.update(self.expiration.seconds.into());
        hasher.update(self.salt);
        hasher.finalize()
    }
}

impl OffChainMessage for TransferArgs {}

pub static SEPOLIA_DOMAIN: LazyLock<StarknetDomain> = LazyLock::new(|| StarknetDomain {
    name: "Perpetuals".to_string(),
    version: "v0".to_string(),
    chain_id: "SN_SEPOLIA".to_string(),
    revision: "1".to_string(),
});

#[cfg(test)]
mod tests {
    use starknet::macros::felt_dec;

    use super::*;

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
            "0x36da8d51815527cabfaa9c982f564c80fa7429616739306036f1f9b608dd112",
        );
        let actual = Order::SELECTOR;
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_transfer_args_selector() {
        let expected = Felt::from_hex_unchecked(
            "0x1db88e2709fdf2c59e651d141c3296a42b209ce770871b40413ea109846a3b4",
        );
        let actual = TransferArgs::SELECTOR;
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_transfer_args_hashing() {
        let transfer_args = TransferArgs {
            recipient: PositionId { value: 1 },
            position_id: PositionId { value: 2 },
            collateral_id: AssetId {
                value: Felt::from_dec_str("3").unwrap(),
            },
            amount: 4,
            expiration: Timestamp { seconds: 5 },
            salt: Felt::from_dec_str("6").unwrap(),
        };

        let actual = transfer_args.hash();
        let expected = Felt::from_dec_str(
            "2223969487713427665389808888239017784545324676732964616876966103908214316949",
        )
        .unwrap();
        assert_eq!(actual, expected, "Hashes do not match for TransferArgs");
    }

    #[test]
    fn test_message_hash_transfer() {
        let transfer_args = TransferArgs {
            recipient: PositionId { value: 1 },
            position_id: PositionId { value: 2 },
            collateral_id: AssetId {
                value: Felt::from_dec_str("3").unwrap(),
            },
            amount: 4,
            expiration: Timestamp { seconds: 5 },
            salt: Felt::from_dec_str("6").unwrap(),
        };

        let user_key = Felt::from_dec_str(
            "2629686405885377265612250192330550814166101744721025672593857097107510831364",
        )
        .unwrap();

        let actual = transfer_args
            .message_hash(&SEPOLIA_DOMAIN, user_key)
            .unwrap();

        let expected = Felt::from_dec_str(
            "3466709383481810859947861276094399756712395853968834582933311835633294184917",
        )
        .unwrap();

        assert_eq!(actual, expected, "Hashes do not match for TransferArgs");
    }

    #[test]
    fn test_order_hashing() {
        let order = Order {
            position_id: PositionId { value: 1 },
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
            "1329353150252109345267997901008558234696410103652961347079636617692652241760",
        )
        .unwrap();
        assert_eq!(actual, expected, "Hashes do not match for Order");
    }

    #[test]
    fn test_message_hash_order() {
        let order = Order {
            position_id: PositionId { value: 100 },
            base_asset_id: AssetId {
                value: Felt::from(2),
            },
            base_amount: 100,
            quote_asset_id: AssetId {
                value: Felt::from(1),
            },
            quote_amount: -156,
            fee_asset_id: AssetId {
                value: Felt::from(1),
            },
            fee_amount: 74,
            expiration: Timestamp { seconds: 100 },
            salt: Felt::from(123),
        };
        let struct_hash = order.hash();
        assert_eq!(
            struct_hash,
            Felt::from_dec_str(
                "1665831471058010006487271218593798151006210932872528562786901713678061931056"
            )
            .unwrap(),
        );

        let user_key = Felt::from_dec_str(
            "2629686405885377265612250192330550814166101744721025672593857097107510831364",
        )
        .unwrap();

        let hash = order.message_hash(&SEPOLIA_DOMAIN, user_key).unwrap();
        let expected_hash = Felt::from_dec_str(
            "2777763653990294626488311476018476273780272220813327677173452477333361411339",
        )
        .unwrap();
        println!("{}", expected_hash.to_hex_string());
        assert_eq!(hash, expected_hash);
    }
}
