//! Minimal ERC20 ABI bindings and calldata helpers.
//!
//! We only need the read methods used to display balances/metadata and the `transfer`
//! method used to send tokens. Everything is verified through the provider (Helios when
//! enabled), so we never trust a third party for these values.

use alloy::primitives::{Address, U256};
use alloy::sol;
use alloy::sol_types::{SolCall, SolEvent};

sol! {
    #[allow(missing_docs)]
    interface IERC20 {
        function balanceOf(address owner) external view returns (uint256);
        function decimals() external view returns (uint8);
        function symbol() external view returns (string);
        function name() external view returns (string);
        function transfer(address to, uint256 amount) external returns (bool);
        event Transfer(address indexed from, address indexed to, uint256 value);
    }
}

/// Keccak256 topic for the ERC20 `Transfer(address,address,uint256)` event.
/// Used to filter `eth_getLogs` when reconstructing token history.
pub fn transfer_topic() -> alloy::primitives::B256 {
    IERC20::Transfer::SIGNATURE_HASH
}

/// ABI-encoded calldata for `balanceOf(owner)`.
pub fn encode_balance_of(owner: Address) -> Vec<u8> {
    IERC20::balanceOfCall { owner }.abi_encode()
}

/// ABI-encoded calldata for `decimals()`.
pub fn encode_decimals() -> Vec<u8> {
    IERC20::decimalsCall {}.abi_encode()
}

/// ABI-encoded calldata for `symbol()`.
pub fn encode_symbol() -> Vec<u8> {
    IERC20::symbolCall {}.abi_encode()
}

/// ABI-encoded calldata for `transfer(to, amount)`.
pub fn encode_transfer(to: Address, amount: U256) -> Vec<u8> {
    IERC20::transferCall { to, amount }.abi_encode()
}

/// Decode a `uint256` return value (e.g. from `balanceOf`).
pub fn decode_u256(ret: &[u8]) -> Option<U256> {
    IERC20::balanceOfCall::abi_decode_returns(ret).ok()
}

/// Decode a `uint8` return value (e.g. from `decimals`).
pub fn decode_u8(ret: &[u8]) -> Option<u8> {
    IERC20::decimalsCall::abi_decode_returns(ret).ok()
}

/// Decode a `string` return value (e.g. from `symbol`/`name`).
pub fn decode_string(ret: &[u8]) -> Option<String> {
    IERC20::symbolCall::abi_decode_returns(ret).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn balance_of_selector() {
        let owner = Address::from_str("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
        let data = encode_balance_of(owner);
        // balanceOf(address) selector = 0x70a08231
        assert_eq!(&data[..4], &[0x70, 0xa0, 0x82, 0x31]);
        assert_eq!(data.len(), 4 + 32);
    }

    #[test]
    fn transfer_selector() {
        let to = Address::from_str("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
        let data = encode_transfer(to, U256::from(1000u64));
        // transfer(address,uint256) selector = 0xa9059cbb
        assert_eq!(&data[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
    }
}
