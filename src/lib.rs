mod starkex_messages;

pub fn get_limit_order_msg_from_hex_to_hex(
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
    hash_function: fn(&str, &str) -> str,
) -> String {
    return starkex_messages::hash_order_hex_to_hex(
        asset_id_synthetic_hex,
        asset_id_collateral_hex,
        is_buying_synthetic,
        asset_id_fee_hex,
        amount_synthetic_hex,
        amount_collateral_hex,
        max_amount_fee_hex,
        nonce,
        position_id,
        expiration_timestamp,
        hash_function,
    );
}
