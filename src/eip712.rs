//! EIP-712 typed data for messages an EVM wallet signs.
//!
//! The beneficiary of a `WithdrawAndStake` consents with an EIP-712 signature from their EVM wallet,
//! alongside the position owner's SNIP-12 Stark signature over the same fields. The domain and type
//! here match the zk engine (`perp-core/src/crypto/evm.rs`) and starkex-client's `Eip712Domain` and
//! `WithdrawAndStake.EIP712_TYPE`.

use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use starknet::core::types::Felt;

use crate::starknet_messages::WithdrawAndStakeArgs;

pub const DOMAIN_NAME: &str = "Perpetuals";
pub const DOMAIN_VERSION: &str = "1";
const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// The beneficiary's EIP-712 type: the fields the owner signs (SNIP-12), in the same order.
pub const WITHDRAW_AND_STAKE_TYPE: &str = "WithdrawAndStake(uint32 positionId,bytes32 assetId,uint64 amount,address vault,address beneficiary,uint64 expiration,bytes32 salt)";
pub const WITHDRAW_AND_STAKE_PRIMARY_TYPE: &str = "WithdrawAndStake";

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn uint_word(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// A 20-byte EVM address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthAddress(pub [u8; 20]);

impl EthAddress {
    /// The address a felt holds, refusing felts wider than 160 bits, as Cairo's `EthAddress` does.
    pub fn from_felt(value: &Felt) -> Result<Self, String> {
        let bytes = value.to_bytes_be();
        if bytes[..12].iter().any(|b| *b != 0) {
            return Err(format!(
                "{} is not a 20-byte EVM address",
                value.to_hex_string()
            ));
        }
        Ok(EthAddress(bytes[12..].try_into().unwrap()))
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 20]
    }

    /// The EIP-712 `address` word: 12 zero bytes then the address.
    fn word(&self) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&self.0);
        word
    }

    /// The EIP-55 mixed-case checksum form, as wallets display it.
    pub fn to_checksum_string(&self) -> String {
        let lower = hex::encode(self.0);
        let hash = keccak256(lower.as_bytes());
        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for (i, c) in lower.chars().enumerate() {
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            out.push(if c.is_ascii_alphabetic() && nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            });
        }
        out
    }
}

/// The zk engine's EIP-712 domain: `Perpetuals` / `1` over the EVM chain id and the settlement
/// contract, so a signature cannot be replayed on another chain or deployment.
pub struct Eip712Domain {
    pub chain_id: u64,
    pub verifying_contract: EthAddress,
}

impl Eip712Domain {
    /// Both values must be set: the engine refuses EVM signatures while either is zero, since a
    /// signature made under an unconfigured domain would be valid on every unconfigured deployment.
    pub fn new(chain_id: u64, verifying_contract: EthAddress) -> Result<Self, String> {
        if chain_id == 0 {
            return Err("chain_id must be set".to_string());
        }
        if verifying_contract.is_zero() {
            return Err("verifying_contract must be set".to_string());
        }
        Ok(Eip712Domain {
            chain_id,
            verifying_contract,
        })
    }

    pub fn separator(&self) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(5 * 32);
        encoded.extend_from_slice(&keccak256(DOMAIN_TYPE.as_bytes()));
        encoded.extend_from_slice(&keccak256(DOMAIN_NAME.as_bytes()));
        encoded.extend_from_slice(&keccak256(DOMAIN_VERSION.as_bytes()));
        encoded.extend_from_slice(&uint_word(self.chain_id));
        encoded.extend_from_slice(&self.verifying_contract.word());
        keccak256(&encoded)
    }

    /// `keccak256("\x19\x01" || domainSeparator || structHash)`: the digest the wallet signs.
    pub fn typed_data_hash(&self, struct_hash: &[u8; 32]) -> [u8; 32] {
        let mut envelope = [0u8; 66];
        envelope[..2].copy_from_slice(b"\x19\x01");
        envelope[2..34].copy_from_slice(&self.separator());
        envelope[34..].copy_from_slice(struct_hash);
        keccak256(&envelope)
    }

    fn to_json(&self) -> Value {
        json!({
            "name": DOMAIN_NAME,
            "version": DOMAIN_VERSION,
            "chainId": self.chain_id,
            "verifyingContract": self.verifying_contract.to_checksum_string(),
        })
    }
}

fn bytes32_hex(value: &Felt) -> String {
    format!("0x{}", hex::encode(value.to_bytes_be()))
}

/// The addresses the beneficiary signs over, refusing what the engine would refuse.
fn addresses(args: &WithdrawAndStakeArgs) -> Result<(EthAddress, EthAddress), String> {
    let vault = EthAddress::from_felt(&args.vault).map_err(|e| format!("Invalid vault: {}", e))?;
    let beneficiary = EthAddress::from_felt(&args.beneficiary)
        .map_err(|e| format!("Invalid beneficiary: {}", e))?;
    if beneficiary.is_zero() {
        return Err("Invalid beneficiary: must be set".to_string());
    }
    Ok((vault, beneficiary))
}

impl WithdrawAndStakeArgs {
    /// EIP-712 `hashStruct`: `keccak256(typeHash || encodeData)`.
    pub fn eip712_struct_hash(&self) -> Result<[u8; 32], String> {
        let (vault, beneficiary) = addresses(self)?;
        let mut encoded = Vec::with_capacity(8 * 32);
        encoded.extend_from_slice(&keccak256(WITHDRAW_AND_STAKE_TYPE.as_bytes()));
        encoded.extend_from_slice(&uint_word(self.position_id.value.into()));
        encoded.extend_from_slice(&self.collateral_id.value.to_bytes_be());
        encoded.extend_from_slice(&uint_word(self.amount));
        encoded.extend_from_slice(&vault.word());
        encoded.extend_from_slice(&beneficiary.word());
        encoded.extend_from_slice(&uint_word(self.expiration.seconds));
        encoded.extend_from_slice(&self.salt.to_bytes_be());
        Ok(keccak256(&encoded))
    }

    /// The digest the beneficiary's wallet signs under `domain`.
    pub fn eip712_hash(&self, domain: &Eip712Domain) -> Result<[u8; 32], String> {
        Ok(domain.typed_data_hash(&self.eip712_struct_hash()?))
    }

    /// The `eth_signTypedData_v4` document to ask the beneficiary's wallet to sign.
    pub fn eip712_typed_data(&self, domain: &Eip712Domain) -> Result<Value, String> {
        let (vault, beneficiary) = addresses(self)?;
        Ok(json!({
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
            "primaryType": WITHDRAW_AND_STAKE_PRIMARY_TYPE,
            "domain": domain.to_json(),
            "message": {
                "positionId": self.position_id.value,
                "assetId": bytes32_hex(&self.collateral_id.value),
                "amount": self.amount,
                "vault": vault.to_checksum_string(),
                "beneficiary": beneficiary.to_checksum_string(),
                "expiration": self.expiration.seconds,
                "salt": bytes32_hex(&self.salt),
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::starknet_messages::{AssetId, PositionId, Timestamp};
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

    fn domain() -> Eip712Domain {
        Eip712Domain::new(31_337, EthAddress([0x11; 20])).unwrap()
    }

    #[test]
    fn type_hash_matches_cast() {
        assert_eq!(
            hex::encode(keccak256(WITHDRAW_AND_STAKE_TYPE.as_bytes())),
            "329750d0244af6ac8ca89bf9e4db7be418af5ef7fa0515fb815dac0227344228"
        );
    }

    #[test]
    fn domain_separator() {
        assert_eq!(
            hex::encode(domain().separator()),
            "c9d781c055757ae11be264b8f8f56bb3dec743e6424ad0c1552083f0e0d5c6a2"
        );
    }

    #[test]
    fn struct_hash_matches_cast() {
        assert_eq!(
            hex::encode(args().eip712_struct_hash().unwrap()),
            "b90a0db961bafe3d9ade9e49be5ada801b2f989082a780a56b35ff88ce3af9c5"
        );
    }

    #[test]
    fn digest_matches_cast() {
        assert_eq!(
            hex::encode(args().eip712_hash(&domain()).unwrap()),
            "8a90600e06caea19adf9b0c3217116d00026fea0b525e368fc1533243e83c658"
        );
    }

    /// The document starkex-client's test hands web3j's wallet encoder, which hashes it to the digest.
    #[test]
    fn typed_data_matches_the_document_starkex_client_verifies() {
        let expected: Value = serde_json::from_str(
            r#"{
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
            }"#,
        )
        .unwrap();
        assert_eq!(args().eip712_typed_data(&domain()).unwrap(), expected);
    }

    #[test]
    fn checksums_addresses_per_eip55() {
        // The EIP-55 spec's own examples.
        for address in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let felt = Felt::from_hex(address).unwrap();
            assert_eq!(
                EthAddress::from_felt(&felt).unwrap().to_checksum_string(),
                address
            );
        }
    }

    #[test]
    fn every_field_changes_the_digest() {
        let base = args().eip712_hash(&domain()).unwrap();
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
            assert_ne!(a.eip712_hash(&domain()).unwrap(), base);
        }
        let other_chain = Eip712Domain::new(1, EthAddress([0x11; 20])).unwrap();
        assert_ne!(args().eip712_hash(&other_chain).unwrap(), base);
        let other_contract = Eip712Domain::new(31_337, EthAddress([0x22; 20])).unwrap();
        assert_ne!(args().eip712_hash(&other_contract).unwrap(), base);
    }

    #[test]
    fn refuses_an_unset_domain() {
        assert!(Eip712Domain::new(0, EthAddress([0x11; 20])).is_err());
        assert!(Eip712Domain::new(31_337, EthAddress([0; 20])).is_err());
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
            assert!(a.eip712_hash(&domain()).is_err());
            assert!(a.eip712_typed_data(&domain()).is_err());
        }
    }
}
