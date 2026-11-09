//! EIP-712 typed data for messages an EVM wallet signs, encoded by alloy.
//!
//! Every message is signed under the zk engine's domain (`perp-core/src/crypto/evm.rs`):
//! `Perpetuals` / `1` over the EVM chain id and the settlement contract.
//!
//! To add a message: declare it in the `sol!` block below (deriving `serde::Serialize`), build it
//! from the crate's own types, and hand it to [`signing_hash`] and [`typed_data`]. alloy derives
//! the type string, `hashStruct` and the `eth_signTypedData_v4` document from the declaration.

use alloy_dyn_abi::TypedData;
use alloy_primitives::{Address, B256};
use alloy_sol_types::{eip712_domain, sol, Eip712Domain, SolStruct};
use serde::Serialize;
use serde_json::Value;
use starknet::core::types::Felt;

use crate::starknet_messages::WithdrawAndStakeArgs;

pub const DOMAIN_NAME: &str = "Perpetuals";
pub const DOMAIN_VERSION: &str = "1";

sol! {
    /// The beneficiary's consent to a withdraw-and-stake: the fields the position owner signs
    /// (SNIP-12), in the same order. The engine and starkex-client's
    /// `WithdrawAndStake.EIP712_TYPE` declare the same type.
    #[derive(serde::Serialize)]
    struct WithdrawAndStake {
        uint32 positionId;
        bytes32 assetId;
        uint64 amount;
        address vault;
        address beneficiary;
        uint64 expiration;
        bytes32 salt;
    }
}

/// The engine's domain. Both values must be set: the engine refuses EVM signatures while either
/// is zero, since a signature made under an unconfigured domain would be valid on every
/// unconfigured deployment.
pub fn domain(chain_id: u64, verifying_contract: Address) -> Result<Eip712Domain, String> {
    if chain_id == 0 {
        return Err("chain_id must be set".to_string());
    }
    if verifying_contract.is_zero() {
        return Err("verifying_contract must be set".to_string());
    }
    Ok(eip712_domain! {
        name: DOMAIN_NAME,
        version: DOMAIN_VERSION,
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    })
}

/// The address a felt holds, refusing felts wider than 160 bits, as Cairo's `EthAddress` does.
pub fn address_from_felt(value: &Felt) -> Result<Address, String> {
    let bytes = value.to_bytes_be();
    if bytes[..12].iter().any(|b| *b != 0) {
        return Err(format!(
            "{} is not a 20-byte EVM address",
            value.to_hex_string()
        ));
    }
    Ok(Address::from_slice(&bytes[12..]))
}

/// A felt as a `bytes32`: its 32-byte big-endian encoding.
pub fn bytes32_from_felt(value: &Felt) -> B256 {
    B256::from(value.to_bytes_be())
}

/// `keccak256("\x19\x01" || domainSeparator || hashStruct(message))`: the digest the wallet signs.
pub fn signing_hash<S: SolStruct>(message: &S, domain: &Eip712Domain) -> B256 {
    message.eip712_signing_hash(domain)
}

/// The `eth_signTypedData_v4` document to ask the wallet to sign.
pub fn typed_data<S: SolStruct + Serialize>(
    message: &S,
    domain: &Eip712Domain,
) -> Result<Value, String> {
    let mut document = serde_json::to_value(TypedData::from_struct(message, Some(domain.clone())))
        .map_err(|e| format!("Failed to serialize typed data: {}", e))?;
    // alloy writes `chainId` as a hex string. Wallets check it against the connected chain, so
    // write the plain number starkex-client's document uses rather than rely on each wallet
    // parsing hex. It hashes the same either way.
    if let Some(chain_id) = domain.chain_id {
        let chain_id = u64::try_from(chain_id).map_err(|e| format!("Invalid chain_id: {}", e))?;
        document["domain"]["chainId"] = Value::from(chain_id);
    }
    Ok(document)
}

impl WithdrawAndStakeArgs {
    /// The beneficiary's EIP-712 message, refusing what the engine would refuse: addresses wider
    /// than 160 bits and a zero beneficiary.
    pub fn eip712_message(&self) -> Result<WithdrawAndStake, String> {
        let vault = address_from_felt(&self.vault).map_err(|e| format!("Invalid vault: {}", e))?;
        let beneficiary = address_from_felt(&self.beneficiary)
            .map_err(|e| format!("Invalid beneficiary: {}", e))?;
        if beneficiary.is_zero() {
            return Err("Invalid beneficiary: must be set".to_string());
        }
        Ok(WithdrawAndStake {
            positionId: self.position_id.value,
            assetId: bytes32_from_felt(&self.collateral_id.value),
            amount: self.amount,
            vault,
            beneficiary,
            expiration: self.expiration.seconds,
            salt: bytes32_from_felt(&self.salt),
        })
    }

    /// The digest the beneficiary's wallet signs under `domain`.
    pub fn eip712_hash(&self, domain: &Eip712Domain) -> Result<B256, String> {
        Ok(signing_hash(&self.eip712_message()?, domain))
    }

    /// The `eth_signTypedData_v4` document to ask the beneficiary's wallet to sign.
    pub fn eip712_typed_data(&self, domain: &Eip712Domain) -> Result<Value, String> {
        typed_data(&self.eip712_message()?, domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::starknet_messages::{AssetId, PositionId, Timestamp};
    use alloy_primitives::{hex, keccak256};
    use starknet::macros::{felt, felt_hex};

    /// starkex-client's `WithdrawAndStakeTest` payload and domain, which zkp's perp-core pins too:
    /// the beneficiary is Hardhat's account #1, the domain chain 31337 with contract 0x11..11. The
    /// struct hash and digest come from Foundry's `cast` (`cast wallet sign --data`).
    fn args() -> WithdrawAndStakeArgs {
        WithdrawAndStakeArgs {
            position_id: PositionId { value: 1 },
            collateral_id: AssetId { value: felt!("2") },
            amount: 3,
            vault: felt_hex!("0x5fbdb2315678afecb367f032d93f642f64180aa3"),
            beneficiary: felt_hex!("0x70997970c51812dc3a010c7d01b50e0d17dc79c8"),
            expiration: Timestamp { seconds: 6 },
            salt: felt!("7"),
        }
    }

    fn test_domain() -> Eip712Domain {
        domain(31_337, Address::repeat_byte(0x11)).unwrap()
    }

    /// The document starkex-client's test hands web3j's wallet encoder, which hashes it to
    /// [`DIGEST`]. Its addresses are EIP-55 checksummed; alloy writes them lowercase.
    const STARKEX_CLIENT_DOCUMENT: &str = r#"{
      "types": {
        "EIP712Domain": [
          {"name": "name", "type": "string"},
          {"name": "version", "type": "string"},
          {"name": "chainId", "type": "uint256"},
          {"name": "verifyingContract", "type": "address"}
        ],
        "WithdrawAndStake": [
          {"name": "positionId", "type": "uint32"},
          {"name": "assetId", "type": "bytes32"},
          {"name": "amount", "type": "uint64"},
          {"name": "vault", "type": "address"},
          {"name": "beneficiary", "type": "address"},
          {"name": "expiration", "type": "uint64"},
          {"name": "salt", "type": "bytes32"}
        ]
      },
      "primaryType": "WithdrawAndStake",
      "domain": {
        "name": "Perpetuals",
        "version": "1",
        "chainId": 31337,
        "verifyingContract": "0x1111111111111111111111111111111111111111"
      },
      "message": {
        "positionId": 1,
        "assetId": "0x0000000000000000000000000000000000000000000000000000000000000002",
        "amount": 3,
        "vault": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
        "beneficiary": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "expiration": 6,
        "salt": "0x0000000000000000000000000000000000000000000000000000000000000007"
      }
    }"#;

    const DIGEST: [u8; 32] =
        hex!("8a90600e06caea19adf9b0c3217116d00026fea0b525e368fc1533243e83c658");

    #[test]
    fn type_matches_the_engine_and_starkex_client() {
        let encode_type = WithdrawAndStake::eip712_encode_type();
        assert_eq!(
            encode_type,
            "WithdrawAndStake(uint32 positionId,bytes32 assetId,uint64 amount,address vault,address beneficiary,uint64 expiration,bytes32 salt)"
        );
        assert_eq!(
            keccak256(encode_type.as_bytes()),
            hex!("329750d0244af6ac8ca89bf9e4db7be418af5ef7fa0515fb815dac0227344228")
        );
    }

    #[test]
    fn domain_separator() {
        assert_eq!(
            test_domain().separator(),
            hex!("c9d781c055757ae11be264b8f8f56bb3dec743e6424ad0c1552083f0e0d5c6a2")
        );
    }

    #[test]
    fn struct_hash_matches_cast() {
        assert_eq!(
            args().eip712_message().unwrap().eip712_hash_struct(),
            hex!("b90a0db961bafe3d9ade9e49be5ada801b2f989082a780a56b35ff88ce3af9c5")
        );
    }

    #[test]
    fn digest_matches_cast() {
        assert_eq!(args().eip712_hash(&test_domain()).unwrap(), DIGEST);
    }

    #[test]
    fn typed_data_is_starkex_clients_document_with_lowercase_addresses() {
        let mut expected: Value = serde_json::from_str(STARKEX_CLIENT_DOCUMENT).unwrap();
        for field in ["vault", "beneficiary"] {
            let lower = expected["message"][field].as_str().unwrap().to_lowercase();
            expected["message"][field] = Value::from(lower);
        }
        assert_eq!(args().eip712_typed_data(&test_domain()).unwrap(), expected);
    }

    /// Read back as a wallet would, both documents hash to the signed digest.
    #[test]
    fn typed_data_hashes_to_the_digest_as_a_wallet_reads_it() {
        let ours: TypedData =
            serde_json::from_value(args().eip712_typed_data(&test_domain()).unwrap()).unwrap();
        let starkex_client: TypedData = serde_json::from_str(STARKEX_CLIENT_DOCUMENT).unwrap();
        assert_eq!(ours.eip712_signing_hash().unwrap(), DIGEST);
        assert_eq!(starkex_client.eip712_signing_hash().unwrap(), DIGEST);
    }

    #[test]
    fn every_field_and_the_domain_change_the_digest() {
        let base = args().eip712_hash(&test_domain()).unwrap();
        let changed: [fn(&mut WithdrawAndStakeArgs); 7] = [
            |a| a.position_id.value += 1,
            |a| a.collateral_id.value += Felt::ONE,
            |a| a.amount += 1,
            |a| a.vault += Felt::ONE,
            |a| a.beneficiary += Felt::ONE,
            |a| a.expiration.seconds += 1,
            |a| a.salt += Felt::ONE,
        ];
        for change in changed {
            let mut a = args();
            change(&mut a);
            assert_ne!(a.eip712_hash(&test_domain()).unwrap(), base);
        }
        let other_chain = domain(1, Address::repeat_byte(0x11)).unwrap();
        assert_ne!(args().eip712_hash(&other_chain).unwrap(), base);
        let other_contract = domain(31_337, Address::repeat_byte(0x22)).unwrap();
        assert_ne!(args().eip712_hash(&other_contract).unwrap(), base);
    }

    #[test]
    fn refuses_an_unset_domain() {
        assert!(domain(0, Address::repeat_byte(0x11)).is_err());
        assert!(domain(31_337, Address::ZERO).is_err());
    }

    #[test]
    fn refuses_a_zero_beneficiary_and_addresses_wider_than_160_bits() {
        let too_wide = Felt::TWO.pow(160u32);

        let mut zero = args();
        zero.beneficiary = Felt::ZERO;
        let mut wide_vault = args();
        wide_vault.vault = too_wide;
        let mut wide_beneficiary = args();
        wide_beneficiary.beneficiary = too_wide;

        for a in [zero, wide_vault, wide_beneficiary] {
            assert!(a.eip712_hash(&test_domain()).is_err());
            assert!(a.eip712_typed_data(&test_domain()).is_err());
        }
    }
}
