//! Per-chain metadata registry.
//!
//! Every EVM chain shares the same addresses/keys; only the native coin, data endpoints and gas
//! model differ. This table lets the wallet operate across chains from a single lookup keyed by the
//! chain id, so the rest of the code stays chain-agnostic.

/// Static metadata for a supported EVM chain.
#[derive(Clone, Copy)]
pub struct ChainInfo {
    pub chain_id: u64,
    pub name: &'static str,
    /// Native coin ticker (ETH / POL / BNB / …).
    pub native_symbol: &'static str,
    /// CoinGecko coin id for pricing the native coin in USD.
    pub coingecko_id: &'static str,
    /// Keyless Blockscout API base (history + NFTs). `None` => no keyless explorer for this chain.
    pub blockscout_base: Option<&'static str>,
    /// DexScreener chain slug (token liquidity lookups). `None` => skip liquidity checks.
    pub dexscreener_slug: Option<&'static str>,
    /// Build legacy (type-0, `gasPrice`) transactions instead of EIP-1559 (e.g. BNB Smart Chain).
    pub legacy_gas: bool,
}

const CHAINS: &[ChainInfo] = &[
    ChainInfo {
        chain_id: 1,
        name: "Ethereum",
        native_symbol: "ETH",
        coingecko_id: "ethereum",
        blockscout_base: Some("https://eth.blockscout.com"),
        dexscreener_slug: Some("ethereum"),
        legacy_gas: false,
    },
    ChainInfo {
        chain_id: 42161,
        name: "Arbitrum One",
        native_symbol: "ETH",
        coingecko_id: "ethereum",
        blockscout_base: Some("https://arbitrum.blockscout.com"),
        dexscreener_slug: Some("arbitrum"),
        legacy_gas: false,
    },
    ChainInfo {
        chain_id: 8453,
        name: "Base",
        native_symbol: "ETH",
        coingecko_id: "ethereum",
        blockscout_base: Some("https://base.blockscout.com"),
        dexscreener_slug: Some("base"),
        legacy_gas: false,
    },
    ChainInfo {
        chain_id: 10,
        name: "Optimism",
        native_symbol: "ETH",
        coingecko_id: "ethereum",
        blockscout_base: Some("https://optimism.blockscout.com"),
        dexscreener_slug: Some("optimism"),
        legacy_gas: false,
    },
    ChainInfo {
        chain_id: 137,
        name: "Polygon",
        native_symbol: "POL",
        coingecko_id: "matic-network",
        blockscout_base: Some("https://polygon.blockscout.com"),
        dexscreener_slug: Some("polygon"),
        legacy_gas: false,
    },
    ChainInfo {
        chain_id: 56,
        name: "BNB Smart Chain",
        native_symbol: "BNB",
        coingecko_id: "binancecoin",
        blockscout_base: None, // no keyless Blockscout instance; history unavailable
        dexscreener_slug: Some("bsc"),
        legacy_gas: true, // BSC uses legacy gasPrice transactions
    },
    ChainInfo {
        chain_id: 100,
        name: "Gnosis",
        native_symbol: "XDAI",
        coingecko_id: "xdai",
        blockscout_base: Some("https://gnosis.blockscout.com"),
        dexscreener_slug: Some("gnosischain"),
        legacy_gas: false,
    },
    ChainInfo {
        chain_id: 43114,
        name: "Avalanche",
        native_symbol: "AVAX",
        coingecko_id: "avalanche-2",
        blockscout_base: None,
        dexscreener_slug: Some("avalanche"),
        legacy_gas: false,
    },
];

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
            blockscout_base: None,
            dexscreener_slug: None,
            legacy_gas: false,
        })
}
