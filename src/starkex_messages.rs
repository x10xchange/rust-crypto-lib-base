use malachite::integer::Integer;
use malachite::num::basic::traits::Zero;
use malachite::num::conversion::traits::FromStringBase;
use malachite::num::conversion::traits::ToStringBase;

use starknet_crypto::pedersen_hash;
use starknet_crypto::Felt;

const OP_LIMIT_ORDER_WITH_FEES: u64 = 3;
const OP_TRANSFER: u64 = 4;
const OP_WITHDRAWAL_TO_ADDRESS: u64 = 7;

fn hash_function(a: &Integer, b: &Integer) -> Integer {
    let a_str = a.to_string_base(16);
    let b_str = b.to_string_base(16);
    let hash = pedersen_hash(
        &Felt::from_hex(&a_str).unwrap(),
        &Felt::from_hex(&b_str).unwrap(),
    );
    return Integer::from_string_base(16, &hash.to_hex_string()).unwrap();
}

pub(crate) fn hash_withdrawal_to_address_hex_to_hex(
    asset_id_collateral_hex: &str,
    position_id: u64,
    eth_address_hex: &str,
    nonce: u64,
    expiration_timestamp: u64,
    amount_hex: &str,
) -> String {
    let asset_id_collateral = Integer::from_string_base(16, asset_id_collateral_hex).unwrap();
    let amount = Integer::from_string_base(16, amount_hex).unwrap();

    let result = hash_withdrawal_to_address(
        &asset_id_collateral,
        position_id,
        eth_address_hex,
        nonce,
        expiration_timestamp,
        &amount,
    );

    result.to_string_base(16)
}

pub(crate) fn hash_order_hex_to_hex(
    asset_id_synthetic_hex: &str,
    asset_id_collateral_hex: &str,
    is_buying_synthetic: bool,
    asset_id_fee_hex: &str,
    amount_synthetic_hex: &str,
    amount_collateral_hex: &str,
    max_amount_fee_hex: &str,
    nonce: u64,
    position_id: u64,
    expiration_timestamp: u64,
) -> String {
    let synthetic_id_as_int = Integer::from_string_base(16, asset_id_synthetic_hex).unwrap();
    let collateral_id_as_int = Integer::from_string_base(16, asset_id_collateral_hex).unwrap();
    let fee_id_as_int = Integer::from_string_base(16, asset_id_fee_hex).unwrap();
    let amount_synthetic_as_int = Integer::from_string_base(16, amount_synthetic_hex).unwrap();
    let amount_collateral_as_int = Integer::from_string_base(16, amount_collateral_hex).unwrap();
    let max_amount_fee_as_int = Integer::from_string_base(16, max_amount_fee_hex).unwrap();

    let result = hash_order(
        &synthetic_id_as_int,
        &collateral_id_as_int,
        is_buying_synthetic,
        &fee_id_as_int,
        &amount_synthetic_as_int,
        &amount_collateral_as_int,
        &max_amount_fee_as_int,
        nonce,
        position_id,
        expiration_timestamp,
    );

    return result.to_string_base(16);
}

pub(crate) fn hash_withdrawal_to_address(
    asset_id_collateral: &Integer,
    position_id: u64,
    eth_address_hex: &str,
    nonce: u64,
    expiration_timestamp: u64,
    amount: &Integer,
) -> Integer {
    let eth_address_int = Integer::from_string_base(16, eth_address_hex).unwrap();
    let mut packed_message = Integer::from(OP_WITHDRAWAL_TO_ADDRESS);
    packed_message = (packed_message << 64) + Integer::from(position_id);
    packed_message = (packed_message << 32) + Integer::from(nonce);
    packed_message = (packed_message << 64) + amount.clone();
    packed_message = (packed_message << 32) + Integer::from(expiration_timestamp);
    packed_message = packed_message << 49;

    hash_function(
        &hash_function(asset_id_collateral, &eth_address_int),
        &packed_message,
    )
}

pub(crate) fn hash_order(
    asset_id_synthetic: &Integer,
    asset_id_collateral: &Integer,
    is_buying_synthetic: bool,
    asset_id_fee: &Integer,
    amount_synthetic: &Integer,
    amount_collateral: &Integer,
    max_amount_fee: &Integer,
    nonce: u64,
    position_id: u64,
    expiration_timestamp: u64,
) -> Integer {
    let (asset_id_sell, asset_id_buy, amount_sell, amount_buy, nonce) = if is_buying_synthetic {
        (
            asset_id_collateral,
            asset_id_synthetic,
            amount_collateral,
            amount_synthetic,
            Integer::from(nonce),
        )
    } else {
        (
            asset_id_synthetic,
            asset_id_collateral,
            amount_synthetic,
            amount_collateral,
            Integer::from(nonce),
        )
    };

    let a = hash_function(asset_id_sell, asset_id_buy);
    let b = hash_function(&a, asset_id_fee);

    let mut w4_packed = amount_sell.clone();
    w4_packed = (w4_packed << (64)) + amount_buy;
    w4_packed = (w4_packed << (64)) + max_amount_fee;
    w4_packed = (w4_packed << (32)) + &nonce;

    let c = hash_function(&b, &w4_packed);

    let mut w5_packed: Integer = (Integer::ZERO << (10)) + Integer::from(OP_LIMIT_ORDER_WITH_FEES);

    w5_packed = (w5_packed << (64)) + Integer::from(position_id);
    w5_packed = (w5_packed << (64)) + Integer::from(position_id);
    w5_packed = (w5_packed << (64)) + Integer::from(position_id);
    w5_packed = (w5_packed << (32)) + Integer::from(expiration_timestamp);
    w5_packed = w5_packed << (17);

    hash_function(&c, &w5_packed)
}

pub(crate) fn get_transfer_msg_without_bounds(
    asset_id: &Integer,
    asset_id_fee: &Integer,
    receiver_public_key: &Integer,
    sender_position_id: u64,
    receiver_position_id: u64,
    src_fee_position_id: u64,
    nonce: u64,
    amount: &Integer,
    max_amount_fee: &Integer,
    expiration_timestamp: u64,
) -> Integer {
    // Perform the initial hash operations
    let mut msg = hash_function(asset_id, asset_id_fee);
    msg = hash_function(&msg, receiver_public_key);

    // Construct the first packed message segment
    let mut packed_message0 = Integer::from(sender_position_id);
    packed_message0 = (packed_message0 << 64) + Integer::from(receiver_position_id);
    packed_message0 = (packed_message0 << 64) + Integer::from(src_fee_position_id);
    packed_message0 = (packed_message0 << 32) + Integer::from(nonce);

    // Hash with the first packed message
    msg = hash_function(&msg, &packed_message0);

    // Construct the second packed message segment with padding
    let mut packed_message1 = Integer::from(OP_TRANSFER);
    packed_message1 = (packed_message1 << 64) + amount.clone();
    packed_message1 = (packed_message1 << 64) + max_amount_fee.clone();
    packed_message1 = (packed_message1 << 32) + Integer::from(expiration_timestamp);
    packed_message1 = packed_message1 << 81; // Padding

    // Final hash with the second packed message
    hash_function(&msg, &packed_message1)
}