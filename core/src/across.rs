// SPDX-License-Identifier: BSD-3-Clause
//! Across Protocol cross-chain bridge support.
//!
//! Bridging works by calling `depositV3` on the origin chain's SpokePool (the wallet is only ever
//! connected to the origin chain), using a fee quote from the Across `suggested-fees` API.
//!
//! Which assets and chain pairs are bridgeable is **not** knowledge this module can hold. Across
//! enables and retires routes on its own schedule - DAI, which earlier versions of this file
//! advertised on every chain, has since been withdrawn entirely, so every DAI bridge the wallet
//! offered failed with "Route is not enabled". So the route table is fetched from Across's own
//! `available-routes` endpoint and cached, and the hard-coded table below survives only as a
//! fallback for when that endpoint cannot be reached.
//!
//! Two rules keep the live data safe to act on:
//!
//!   * a route is only offered if both of its chains are ones the wallet itself supports, so
//!     bridged funds always land somewhere the user can see and spend them;
//!   * a route is only offered for an asset whose decimals the wallet can establish, since a wrong
//!     decimals figure silently misplaces the decimal point in the amount being sent.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::provider::RpcProvider;

/// One direction of one asset, exactly as Across reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub origin_chain: u64,
    pub origin_token: String,
    pub dest_chain: u64,
    pub dest_token: String,
    /// Across's own symbol for the asset, e.g. `ETH`, `WETH`, `USDC`, `USDC-BNB`.
    pub symbol: String,
    /// True when the deposit is made in the chain's native coin rather than the ERC-20 at
    /// `origin_token` (which is then the wrapped-native contract).
    pub is_native: bool,
}

/// Assets the wallet is willing to bridge. Across routes many more (`WLD`, `USDG`, `USDzC`, …);
/// they are dropped rather than shown, because each one needs its decimals and its behaviour
/// understood before the wallet can safely turn a typed amount into a transfer.
const ALLOWED: &[&str] = &["ETH", "WETH", "USDC", "USDT", "WBTC"];

/// How long a fetched route table is trusted. Across changes routes rarely; the cost of being a few
/// minutes stale is one clear "Route is not enabled" from the quote, which is handled.
const TTL: Duration = Duration::from_secs(15 * 60);

static CACHE: Mutex<Option<(Instant, Vec<Route>)>> = Mutex::new(None);

/// Across's canonical symbol reduced to the ticker the user recognises. Chain-suffixed variants
/// (`USDC-BNB` on BNB Smart Chain) are the same asset under a name only Across uses.
pub fn display_symbol(symbol: &str) -> &str {
    symbol.split('-').next().unwrap_or(symbol)
}

/// Chains the wallet can operate on, so a bridge never delivers to a chain it cannot then show.
fn wallet_supports(chain_id: u64) -> bool {
    !crate::chains::is_testnet(chain_id) && crate::chains::is_known(chain_id)
}

/// The route table, fetched if the cached one is missing or stale.
///
/// A fetch that fails falls back to whatever is cached, however old, and to the static table if
/// nothing is cached - bridging with a slightly stale route list is far better than a bridge dialog
/// that cannot be opened at all.
pub async fn routes(provider: &RpcProvider) -> Vec<Route> {
    if let Some((at, cached)) = CACHE.lock().unwrap().as_ref() {
        if at.elapsed() < TTL {
            return cached.clone();
        }
    }

    match fetch(provider).await {
        Ok(fresh) if !fresh.is_empty() => {
            *CACHE.lock().unwrap() = Some((Instant::now(), fresh.clone()));
            fresh
        }
        _ => {
            let stale = CACHE.lock().unwrap().as_ref().map(|(_, r)| r.clone());
            stale.unwrap_or_else(fallback_routes)
        }
    }
}

async fn fetch(provider: &RpcProvider) -> Result<Vec<Route>, crate::error::CoreError> {
    let v = provider.http_get_json("https://app.across.to/api/available-routes").await?;
    let arr = v.as_array().cloned().unwrap_or_default();
    let mut out = Vec::with_capacity(arr.len());
    for r in arr {
        let get_u64 = |k: &str| r.get(k).and_then(|x| x.as_u64());
        let get_str = |k: &str| r.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
        let (Some(origin_chain), Some(dest_chain)) =
            (get_u64("originChainId"), get_u64("destinationChainId"))
        else {
            continue;
        };
        let symbol = get_str("originTokenSymbol");
        // Only same-asset routes: Across pairs a symbol with itself, and anything else would mean
        // the user receives a different token than the one they chose to send.
        if symbol != get_str("destinationTokenSymbol") {
            continue;
        }
        if !ALLOWED.contains(&display_symbol(&symbol)) {
            continue;
        }
        if !wallet_supports(origin_chain) || !wallet_supports(dest_chain) {
            continue;
        }
        let origin_token = get_str("originToken");
        let dest_token = get_str("destinationToken");
        if origin_token.is_empty() || dest_token.is_empty() {
            continue;
        }
        out.push(Route {
            origin_chain,
            origin_token,
            dest_chain,
            dest_token,
            is_native: r.get("isNative").and_then(|x| x.as_bool()).unwrap_or(false),
            symbol,
        });
    }
    Ok(out)
}

/// Resolve the exact tokens for one bridge, or explain why it is not on offer.
pub fn resolve<'a>(routes: &'a [Route], origin: u64, dest: u64, symbol: &str) -> Option<&'a Route> {
    routes.iter().find(|r| {
        r.origin_chain == origin && r.dest_chain == dest && r.symbol.eq_ignore_ascii_case(symbol)
    })
}

/// Symbols bridgeable out of `origin`, in the order they should be offered.
pub fn symbols_from(routes: &[Route], origin: u64) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for r in routes.iter().filter(|r| r.origin_chain == origin) {
        if !out.iter().any(|s| s == &r.symbol) {
            out.push(r.symbol.clone());
        }
    }
    // Native first, then the order of ALLOWED, so the list reads the same on every chain.
    out.sort_by_key(|s| {
        let rank = ALLOWED.iter().position(|a| *a == display_symbol(s)).unwrap_or(ALLOWED.len());
        (rank, s.clone())
    });
    out
}

/// Destination chains reachable from `origin` with `symbol`.
pub fn destinations(routes: &[Route], origin: u64, symbol: &str) -> Vec<u64> {
    let mut out: Vec<u64> = routes
        .iter()
        .filter(|r| r.origin_chain == origin && r.symbol.eq_ignore_ascii_case(symbol))
        .map(|r| r.dest_chain)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Decimals for a bridgeable asset when they cannot be read from the chain.
///
/// Only a fallback: the caller asks the token contract itself first. USDC and USDT are six-decimal
/// on every chain here except BNB Smart Chain, where both are eighteen - the case that makes
/// guessing from the ticker alone unsafe.
pub fn fallback_decimals(symbol: &str, chain_id: u64) -> u8 {
    match display_symbol(symbol).to_ascii_uppercase().as_str() {
        "USDC" | "USDT" => {
            if chain_id == 56 {
                18
            } else {
                6
            }
        }
        "WBTC" => 8,
        _ => 18, // ETH / WETH
    }
}

// -------------------------------------------------------------------------------------------------
// Static fallback
// -------------------------------------------------------------------------------------------------

/// The routes to offer when Across's endpoint cannot be reached at all.
///
/// Deliberately conservative: the five chains and four assets that have been continuously routed for
/// years, in every direction. Anything newer is worth waiting for a live answer about.
fn fallback_routes() -> Vec<Route> {
    const CHAINS: [u64; 5] = [1, 10, 137, 8453, 42161];
    let mut out = Vec::new();
    for &origin in &CHAINS {
        for &dest in &CHAINS {
            if origin == dest {
                continue;
            }
            for symbol in ["ETH", "USDC", "USDT", "WBTC"] {
                let (Some(origin_token), Some(dest_token)) =
                    (fallback_token(symbol, origin), fallback_token(symbol, dest))
                else {
                    continue;
                };
                // Polygon's "ETH" is the WETH ERC-20, not the gas coin.
                let native = symbol == "ETH" && matches!(origin, 1 | 10 | 8453 | 42161);
                out.push(Route {
                    origin_chain: origin,
                    origin_token: origin_token.to_string(),
                    dest_chain: dest,
                    dest_token: dest_token.to_string(),
                    symbol: if symbol == "ETH" && !native { "WETH".into() } else { symbol.into() },
                    is_native: native,
                });
            }
        }
    }
    out
}

fn fallback_token(symbol: &str, chain_id: u64) -> Option<&'static str> {
    Some(match (symbol, chain_id) {
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

        ("WBTC", 1) => "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
        ("WBTC", 10) => "0x68f180fcCe6836688e9084f035309E29Bf0A2095",
        ("WBTC", 42161) => "0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f",
        ("WBTC", 137) => "0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6",
        // WBTC has never been routed on Base.
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(origin: u64, dest: u64, symbol: &str, native: bool) -> Route {
        Route {
            origin_chain: origin,
            origin_token: "0xaa".into(),
            dest_chain: dest,
            dest_token: "0xbb".into(),
            symbol: symbol.into(),
            is_native: native,
        }
    }

    #[test]
    fn chain_suffixed_symbols_display_as_the_plain_ticker() {
        assert_eq!(display_symbol("USDC-BNB"), "USDC");
        assert_eq!(display_symbol("USDC"), "USDC");
        assert_eq!(display_symbol("ETH"), "ETH");
    }

    #[test]
    fn bnb_stablecoins_are_eighteen_decimal() {
        // The reason decimals are read from the chain rather than guessed from the ticker.
        assert_eq!(fallback_decimals("USDC-BNB", 56), 18);
        assert_eq!(fallback_decimals("USDC", 1), 6);
        assert_eq!(fallback_decimals("WBTC", 1), 8);
        assert_eq!(fallback_decimals("ETH", 1), 18);
    }

    #[test]
    fn symbols_and_destinations_come_from_the_route_table() {
        let table = vec![r(1, 8453, "ETH", true), r(1, 10, "USDC", false), r(8453, 1, "USDC", false)];
        assert_eq!(symbols_from(&table, 1), vec!["ETH", "USDC"]);
        assert_eq!(destinations(&table, 1, "USDC"), vec![10]);
        assert!(destinations(&table, 1, "DAI").is_empty(), "a retired asset must not be offered");
        assert!(resolve(&table, 1, 8453, "ETH").unwrap().is_native);
        assert!(resolve(&table, 1, 999, "ETH").is_none());
    }

    #[test]
    fn the_fallback_offers_only_long_lived_routes() {
        let table = fallback_routes();
        assert!(resolve(&table, 1, 8453, "ETH").is_some());
        assert!(resolve(&table, 1, 8453, "WBTC").is_none(), "WBTC is not routed on Base");
        assert!(resolve(&table, 137, 1, "WETH").is_some(), "Polygon ETH is the WETH ERC-20");
        assert!(!resolve(&table, 137, 1, "WETH").unwrap().is_native);
        assert!(table.iter().all(|r| r.symbol != "DAI"), "DAI is no longer routed by Across");
    }
}
