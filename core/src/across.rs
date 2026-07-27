// SPDX-License-Identifier: BSD-3-Clause
//! Across Protocol cross-chain bridge support.
//!
//! Bridging works by calling `depositV3` on the origin chain's SpokePool (the wallet is only ever
//! connected to the origin chain), using a fee quote from the Across `suggested-fees` API. This
//! module holds the supported-chain set and a canonical token-address registry keyed by
//! (symbol, chain_id) so the origin/destination token addresses can be resolved for the quote and
//! the deposit calldata (built in `wallet.rs`).

/// Chains where Across is available AND we have a token-address registry entry.
pub fn supported(chain_id: u64) -> bool {
    matches!(chain_id, 1 | 10 | 137 | 8453 | 42161)
}

/// User-facing bridgeable asset symbols (per-chain availability resolved via `token_address`).
pub const SYMBOLS: &[&str] = &["ETH", "USDC", "USDT", "DAI", "WBTC"];

/// Token decimals for a bridgeable symbol.
pub fn decimals(symbol: &str) -> u8 {
    match symbol.to_ascii_uppercase().as_str() {
        "USDC" | "USDT" => 6,
        "WBTC" => 8,
        _ => 18, // ETH / WETH / DAI
    }
}

/// Canonical ERC-20 (or wrapped-native) address for `symbol` on `chain_id`, if bridgeable there.
/// "ETH"/"WETH" resolve to the chain's canonical WETH; native ETH is deposited as a WETH-wrapped
/// value transfer (see `is_native`).
pub fn token_address(symbol: &str, chain_id: u64) -> Option<&'static str> {
    let s = symbol.to_ascii_uppercase();
    Some(match (s.as_str(), chain_id) {
        ("ETH" | "WETH", 1) => "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        ("ETH" | "WETH", 10) => "0x4200000000000000000000000000000000000006",
        ("ETH" | "WETH", 8453) => "0x4200000000000000000000000000000000000006",
        ("ETH" | "WETH", 42161) => "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
        ("ETH" | "WETH", 137) => "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619",

        ("USDC", 1) => "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        ("USDC", 10) => "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
        ("USDC", 8453) => "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        ("USDC", 42161) => "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
        ("USDC", 137) => "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",

        ("USDT", 1) => "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        ("USDT", 10) => "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58",
        ("USDT", 8453) => "0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2",
        ("USDT", 42161) => "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
        ("USDT", 137) => "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",

        ("DAI", 1) => "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        ("DAI", 10) => "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1",
        ("DAI", 8453) => "0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb",
        ("DAI", 42161) => "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1",
        ("DAI", 137) => "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063",

        ("WBTC", 1) => "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
        ("WBTC", 10) => "0x68f180fcCe6836688e9084f035309E29Bf0A2095",
        ("WBTC", 42161) => "0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f",
        ("WBTC", 137) => "0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6",
        // WBTC has no canonical Across route on Base.
        _ => return None,
    })
}

/// True if `symbol` is the origin chain's native gas coin, meaning the deposit is a native value
/// transfer (inputToken is the chain's WETH). Only the ETH-native chains are treated as native;
/// e.g. "ETH" on Polygon is the WETH ERC-20, not the native coin.
pub fn is_native(symbol: &str, chain_id: u64) -> bool {
    symbol.eq_ignore_ascii_case("ETH") && matches!(chain_id, 1 | 10 | 8453 | 42161)
}

/// Symbols bridgeable FROM `chain_id` (those with a registered token address there).
pub fn symbols_for(chain_id: u64) -> Vec<&'static str> {
    SYMBOLS.iter().copied().filter(|s| token_address(s, chain_id).is_some()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_only_on_eth_chains() {
        assert!(is_native("ETH", 1));
        assert!(is_native("eth", 8453));
        assert!(!is_native("ETH", 137)); // Polygon ETH is WETH ERC-20
        assert!(!is_native("USDC", 1));
    }

    #[test]
    fn token_registry_resolves() {
        assert_eq!(token_address("USDC", 8453), Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"));
        assert_eq!(token_address("ETH", 42161), Some("0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"));
        assert_eq!(token_address("WBTC", 8453), None); // not routed on Base
        assert_eq!(token_address("USDC", 999), None);  // unsupported chain
    }

    #[test]
    fn symbols_for_base_excludes_wbtc() {
        let s = symbols_for(8453);
        assert!(s.contains(&"ETH") && s.contains(&"USDC"));
        assert!(!s.contains(&"WBTC"));
    }
}
