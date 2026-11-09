# rust-crypto-lib-base

This crate provides core cryptographic primitives and message hashing utilities for StarkNet-based applications, with a focus on interoperability and off-chain message construction. The code is designed to be called from other languages (such as Python or JavaScript) and provides a set of Rust functions and types for working with StarkNet signatures, domain separation, and message hashing.

---

## File Overview

### `src/lib.rs`

This is the main entry point of the library. It provides:

- **Key Derivation and Signing**

  - `grind_key`: Deterministically derives a StarkNet-compatible private key from a seed using SHA-256 and modular reduction.
  - `get_private_key_from_eth_signature`: Extracts a private key from an Ethereum signature, using the `grind_key` function.
  - `sign_message`: Signs a message using StarkNet ECDSA and returns a `StarkSignature` struct.

- **Message Hashing Functions**

  - `get_order_hash`: Computes the hash for an order message, given all order parameters as strings.
  - `get_transfer_hash`: Computes the hash for a transfer message, given all transfer parameters as strings.
  - `get_withdrawal_hash`: Computes the hash for a withdrawal message, given all withdrawal parameters as strings.
  - `get_withdraw_and_stake_hash`: Computes the hash for a withdraw-and-stake message, given all its parameters as strings. `vault` and `beneficiary` are EVM addresses and must fit in 160 bits.
  - `get_withdraw_and_stake_eip712_typed_data`: Returns the `eth_signTypedData_v4` JSON document the withdraw-and-stake beneficiary's EVM wallet signs. Takes the same withdraw-and-stake inputs as `get_withdraw_and_stake_hash`, plus the EVM chain id and the settlement contract (`verifying_contract_hex`) of the EIP-712 domain.
  - `get_withdraw_and_stake_eip712_hash`: Returns the 32-byte EIP-712 digest (hex) of that same document, for checking a wallet's signature.

- **Types**

  - `StarkSignature`: Holds the `r`, `s`, and `v` components of a StarkNet ECDSA signature.

- **Testing**
  - Comprehensive unit tests for key derivation, signing, and message hash computation.

---

### `src/eip712.rs`

EIP-712 typed data for messages an EVM wallet signs. A withdraw-and-stake must also be signed by its beneficiary's EVM wallet:

- `Eip712Domain`: the zk engine's domain (`Perpetuals` / `1`, EVM chain id, settlement contract). Both the chain id and the contract must be set.
- `EthAddress`: a 20-byte EVM address, with its EIP-55 checksum form.
- `WithdrawAndStakeArgs::eip712_struct_hash`, `eip712_hash` and `eip712_typed_data`: the beneficiary's `WithdrawAndStake` EIP-712 message over the same fields the position owner signs.

---

### `src/starknet_messages.rs`

This module defines the core data structures and hashing logic for StarkNet off-chain messages:

- **Traits**

  - `Hashable`: For types that can be hashed with a Poseidon hash and a selector.
  - `OffChainMessage`: For types that represent off-chain messages and can be hashed with domain separation and a public key.

- **Domain and Message Types**

  - `StarknetDomain`: Represents the domain for message separation (name, version, chain_id, revision).
  - `AssetId`, `PositionId`, `AssetAmount`, `Timestamp`: Basic types for message construction.
  - `Order`, `TransferArgs`, `WithdrawalArgs`, `WithdrawAndStakeArgs`: Main message types for orders, transfers, withdrawals, and withdraw-and-stake.

- **Hash Implementations**

  - Each message type implements `Hashable` and provides a unique selector and hashing logic using the Poseidon hash function.

- **Constants**

  - `SEPOLIA_DOMAIN`: A pre-defined domain for the Sepolia testnet.

- **Testing**
  - Unit tests for selectors, hashing, and message hash computation for all message types.

---

## Usage

- **Hashing and Signing:**  
  Use the functions in `lib.rs` to derive keys, sign messages, and compute message hashes for StarkNet off-chain protocols.
- **Extending Message Types:**  
  Implement the `Hashable` and `OffChainMessage` traits for new message types as needed.
- **Interoperability:**  
  All public functions are designed to accept string arguments for easy FFI or WASM integration.

---

## Example

```rust
use rust_crypto_lib_base::{get_order_hash, sign_message, get_private_key_from_eth_signature};

// Compute an order hash
let hash = get_order_hash(
    "1".to_string(), "0x2".to_string(), "100".to_string(), "0x1".to_string(),
    "-156".to_string(), "0x1".to_string(), "74".to_string(), "100".to_string(),
    "123".to_string(), "0x...".to_string(), "Perpetuals".to_string(), "v0".to_string(),
    "SN_SEPOLIA".to_string(), "1".to_string()
)?;

// Sign a message
let private_key = get_private_key_from_eth_signature("0x...")?;
let signature = sign_message(&hash, &private_key)?;
```
