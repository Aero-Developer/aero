//! Per-chain metadata registry.
//!
//! Every EVM chain shares the same addresses/keys; only the native coin, data endpoints and gas
//! model differ. This table lets the wallet operate across chains from a single lookup keyed by the
//! chain id, so the rest of the code stays chain-agnostic.

/// CoW Protocol's production EthFlow contract, which sells native coin by wrapping it and placing
/// the order on the seller's behalf. CoW deploys it at the same address on every chain they support.
///
/// Aero previously pointed mainnet at `0x40A50cf069e992AA4536211B23F286eF88752187`, an earlier
/// mainnet-only deployment. `createOrder` still exists there, so a sell would be accepted on chain
/// and then never filled: CoW's order book and its refunder both watch the current contract, so the
/// ETH would sit in the old one with nothing in Aero able to get it back.
pub const ETH_FLOW_PROD: &str = "0xbA3cB449bD2B4ADddBc894D8697F5170800EAdeC";

/// Static metadata for a supported EVM chain.
#[derive(Clone, Copy)]
pub struct ChainInfo {
    pub chain_id: u64,
    pub name: &'static str,
    /// Native coin ticker (ETH / POL / BNB / …).
    pub native_symbol: &'static str,
    /// CoinGecko coin id for pricing the native coin in USD.
    pub coingecko_id: &'static str,
    /// Keyless Etherscan-compatible API bases for history and NFTs, tried in order. Empty means no
    /// keyless explorer for this chain, so history is unavailable unless the user configures one.
    ///
    /// More than one because a single hardcoded explorer is a single point of failure that can only
    /// be repaired by shipping a new build: base.blockscout.com started answering 500 to every
    /// request, and every Aero pointed at it lost its Base history with no way back. The fetcher
    /// parks a base that stops answering and moves to the next.
    pub explorers: &'static [&'static str],
    /// DexScreener chain slug (token liquidity lookups). `None` => skip liquidity checks.
    pub dexscreener_slug: Option<&'static str>,
    /// Build legacy (type-0, `gasPrice`) transactions instead of EIP-1559 (e.g. BNB Smart Chain).
    pub legacy_gas: bool,
    /// CoW Protocol order-book API network slug (e.g. "mainnet"). `None` => swaps unavailable here.
    pub cow_network: Option<&'static str>,
    /// CoW eth-flow contract for native-ETH sells. `None` => native swaps disabled.
    ///
    /// CoW deploys this at [`ETH_FLOW_PROD`], the same address on every chain it supports. Before
    /// any native sell the wallet checks there is actually code there (see `eth_flow_for`), because
    /// the failure mode if there is not is that `createOrder` degrades into a plain transfer of the
    /// user's ETH to an address nobody controls.
    pub eth_flow: Option<&'static str>,
    /// Wrapped-native ERC-20 (WETH/WMATIC/…), used as the CoW sellToken for native swaps.
    pub wrapped_native: &'static str,
}

const CHAINS: &[ChainInfo] = &[
    ChainInfo {
        chain_id: 1,
        name: "Ethereum",
        native_symbol: "ETH",
        coingecko_id: "ethereum",
        explorers: &[
            "https://eth.blockscout.com",
            "https://blockscout.com/eth/mainnet",
            "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan",
        ],
        dexscreener_slug: Some("ethereum"),
        legacy_gas: false,
        cow_network: Some("mainnet"),
        eth_flow: Some(ETH_FLOW_PROD),
        wrapped_native: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    },
    ChainInfo {
        chain_id: 42161,
        name: "Arbitrum One",
        native_symbol: "ETH",
        coingecko_id: "ethereum",
        explorers: &["https://arbitrum.blockscout.com"],
        dexscreener_slug: Some("arbitrum"),
        legacy_gas: false,
        cow_network: Some("arbitrum_one"),
        eth_flow: Some(ETH_FLOW_PROD),
        wrapped_native: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
    },
    ChainInfo {
        chain_id: 8453,
        name: "Base",
        native_symbol: "ETH",
        coingecko_id: "ethereum",
        explorers: &["https://base.blockscout.com"],
        dexscreener_slug: Some("base"),
        legacy_gas: false,
        cow_network: Some("base"),
        eth_flow: Some(ETH_FLOW_PROD),
        wrapped_native: "0x4200000000000000000000000000000000000006",
    },
    ChainInfo {
        chain_id: 10,
        name: "Optimism",
        native_symbol: "ETH",
        coingecko_id: "ethereum",
        explorers: &["https://optimism.blockscout.com", "https://explorer.optimism.io"],
        dexscreener_slug: Some("optimism"),
        legacy_gas: false,
        cow_network: None, // CoW not deployed on Optimism
        eth_flow: None,
        wrapped_native: "0x4200000000000000000000000000000000000006",
    },
    ChainInfo {
        chain_id: 137,
        name: "Polygon",
        native_symbol: "POL",
        coingecko_id: "matic-network",
        explorers: &["https://polygon.blockscout.com"],
        dexscreener_slug: Some("polygon"),
        legacy_gas: false,
        cow_network: Some("polygon"),
        eth_flow: Some(ETH_FLOW_PROD),
        wrapped_native: "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
    },
    ChainInfo {
        chain_id: 56,
        name: "BNB Smart Chain",
        native_symbol: "BNB",
        coingecko_id: "binancecoin",
        // No keyless explorer publishes BNB Smart Chain history. Set one under Settings > Node - an
        // Etherscan V2 key covers this chain and every other one.
        explorers: &[],
        dexscreener_slug: Some("bsc"),
        legacy_gas: true, // BSC uses legacy gasPrice transactions
        // CoW does run on BNB - `https://api.cow.fi/bnb/api/v1` answers - so the old comment here
        // saying it was not deployed simply cost BNB users the gasless, MEV-protected route.
        cow_network: Some("bnb"),
        eth_flow: Some(ETH_FLOW_PROD),
        wrapped_native: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
    },
    ChainInfo {
        chain_id: 100,
        name: "Gnosis",
        native_symbol: "XDAI",
        coingecko_id: "xdai",
        explorers: &["https://gnosis.blockscout.com", "https://blockscout.com/xdai/mainnet"],
        dexscreener_slug: Some("gnosischain"),
        legacy_gas: false,
        cow_network: Some("xdai"),
        eth_flow: Some(ETH_FLOW_PROD),
        wrapped_native: "0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d",
    },
    ChainInfo {
        chain_id: 43114,
        name: "Avalanche",
        native_symbol: "AVAX",
        coingecko_id: "avalanche-2",
        // Routescan exposes a keyless Etherscan-compatible API for the Avalanche C-Chain (no
        // official keyless Blockscout). History works; NFT collections (Blockscout v2 only) don't.
        explorers: &["https://api.routescan.io/v2/network/mainnet/evm/43114/etherscan"],
        dexscreener_slug: Some("avalanche"),
        legacy_gas: false,
        cow_network: Some("avalanche"),
        eth_flow: Some(ETH_FLOW_PROD),
        wrapped_native: "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7",
    },
    // ---- Testnets (for safe testing). coingecko_id is "" so no misleading USD price is shown for
    // worthless testnet ETH; no swaps (CoW/routers not offered). ----
    ChainInfo {
        chain_id: 11155111,
        name: "Sepolia (testnet)",
        native_symbol: "SepoliaETH",
        coingecko_id: "",
        explorers: &["https://eth-sepolia.blockscout.com"],
        dexscreener_slug: None,
        legacy_gas: false,
        cow_network: None,
        eth_flow: None,
        wrapped_native: "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14",
    },
    ChainInfo {
        chain_id: 17000,
        name: "Holesky (testnet)",
        native_symbol: "HoleskyETH",
        coingecko_id: "",
        explorers: &["https://eth-holesky.blockscout.com"],
        dexscreener_slug: None,
        legacy_gas: false,
        cow_network: None,
        eth_flow: None,
        wrapped_native: "",
    },
];

/// True for chains that are test networks (worthless coins) - the UI marks them and can hide them.
pub fn is_testnet(chain_id: u64) -> bool {
    matches!(chain_id, 11155111 | 17000)
}

/// Whether this chain is in the table above, i.e. the wallet knows its coin, explorer and gas model.
/// Used to refuse bridging to a chain the wallet could not afterwards display the funds on.
pub fn is_known(chain_id: u64) -> bool {
    CHAINS.iter().any(|c| c.chain_id == chain_id)
}

// ---- Keyless swap-router support (multi-router aggregator) --------------------------------
// Each router uses a different chain identifier in its API path; a `None` means the router is not
// offered on that chain, so it's simply dropped from the comparison.

/// KyberSwap Aggregator API chain slug (path segment) for `chain_id`.
pub fn kyber_slug(chain_id: u64) -> Option<&'static str> {
    Some(match chain_id {
        1 => "ethereum",
        42161 => "arbitrum",
        8453 => "base",
        10 => "optimism",
        137 => "polygon",
        56 => "bsc",
        43114 => "avalanche",
        _ => return None,
    })
}

/// OpenOcean v3 chain code (path segment) for `chain_id`.
pub fn openocean_slug(chain_id: u64) -> Option<&'static str> {
    Some(match chain_id {
        1 => "eth",
        42161 => "arbitrum",
        8453 => "base",
        10 => "optimism",
        137 => "polygon",
        56 => "bsc",
        43114 => "avax",
        _ => return None,
    })
}

/// Whether Odos SOR supports `chain_id`.
///
/// Nothing does any more. Odos wound down its company and shut off `api.odos.xyz` on 30 July 2026;
/// the host now answers 530 to everything. Left as a function returning false, rather than deleting
/// the router outright, so the shape of the code still shows where a fourth aggregator plugs in.
///
/// This is not cosmetic. Every quote refresh asked Odos in parallel with the others, and over Tor a
/// request to a dead host does not fail fast - it waits out the full timeout on every refresh, on
/// every chain, for a route that can never come back.
pub fn odos_supported(_chain_id: u64) -> bool {
    false
}

/// Whether Paraswap supports `chain_id` (Paraswap uses `network=<chain_id>`).
pub fn paraswap_supported(chain_id: u64) -> bool {
    matches!(chain_id, 1 | 10 | 56 | 137 | 8453 | 42161 | 43114)
}

/// Metadata for `chain_id`, or a sane generic default (native "ETH", no explorer) for unknown ids.
pub fn chain_info(chain_id: u64) -> ChainInfo {
    CHAINS
        .iter()
        .copied()
        .find(|c| c.chain_id == chain_id)
        .unwrap_or(ChainInfo {
            chain_id,
            name: "Unknown",
            native_symbol: "ETH",
            coingecko_id: "ethereum",
            explorers: &[],
            dexscreener_slug: None,
            legacy_gas: false,
            cow_network: None,
            eth_flow: None,
            wrapped_native: "",
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every chain Aero offers CoW on must also carry the eth-flow address, or selling the chain's
    /// own coin through CoW is quietly impossible there. That is how Gnosis ended up with no way to
    /// sell XDAI at all: CoW was its only venue, and CoW refuses native sells without eth-flow.
    #[test]
    fn a_cow_chain_can_always_sell_its_own_coin() {
        for c in CHAINS {
            if c.cow_network.is_some() {
                assert_eq!(
                    c.eth_flow,
                    Some(ETH_FLOW_PROD),
                    "{} offers CoW but cannot sell native {}",
                    c.name,
                    c.native_symbol
                );
            }
        }
    }

    /// A chain that can swap at all needs a wrapped-native token, since that is what a native sell
    /// is actually routed as.
    #[test]
    fn every_swappable_chain_knows_its_wrapped_coin() {
        for c in CHAINS {
            if c.cow_network.is_some() || openocean_slug(c.chain_id).is_some() {
                assert!(
                    c.wrapped_native.starts_with("0x") && c.wrapped_native.len() == 42,
                    "{} has no wrapped-native address",
                    c.name
                );
            }
        }
    }

    /// Odos shut down on 30 July 2026 and `api.odos.xyz` answers 530. Asking it anyway costs a full
    /// timeout on every quote refresh, which over Tor is the slowest thing in the swap tab.
    #[test]
    fn the_dead_router_is_never_asked() {
        for c in CHAINS {
            assert!(!odos_supported(c.chain_id), "{} still queries Odos", c.name);
        }
    }
}
