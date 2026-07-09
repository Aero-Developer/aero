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
    /// CoW Protocol order-book API network slug (e.g. "mainnet"). `None` => swaps unavailable here.
    pub cow_network: Option<&'static str>,
    /// CoW eth-flow contract for native-ETH sells. `None` => native swaps disabled (only verified
    /// addresses are hardcoded, to never risk sending ETH to a wrong contract).
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
        blockscout_base: Some("https://eth.blockscout.com"),
        dexscreener_slug: Some("ethereum"),
        legacy_gas: false,
        cow_network: Some("mainnet"),
        eth_flow: Some("0x40A50cf069e992AA4536211B23F286eF88752187"),
        wrapped_native: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    },
    ChainInfo {
        chain_id: 42161,
        name: "Arbitrum One",
        native_symbol: "ETH",
        coingecko_id: "ethereum",
        blockscout_base: Some("https://arbitrum.blockscout.com"),
        dexscreener_slug: Some("arbitrum"),
        legacy_gas: false,
        cow_network: Some("arbitrum_one"),
        eth_flow: None,
        wrapped_native: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
    },
    ChainInfo {
        chain_id: 8453,
        name: "Base",
        native_symbol: "ETH",
        coingecko_id: "ethereum",
        blockscout_base: Some("https://base.blockscout.com"),
        dexscreener_slug: Some("base"),
        legacy_gas: false,
        cow_network: Some("base"),
        eth_flow: None,
        wrapped_native: "0x4200000000000000000000000000000000000006",
    },
    ChainInfo {
        chain_id: 10,
        name: "Optimism",
        native_symbol: "ETH",
        coingecko_id: "ethereum",
        blockscout_base: Some("https://optimism.blockscout.com"),
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
        blockscout_base: Some("https://polygon.blockscout.com"),
        dexscreener_slug: Some("polygon"),
        legacy_gas: false,
        cow_network: Some("polygon"),
        eth_flow: None,
        wrapped_native: "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
    },
    ChainInfo {
        chain_id: 56,
        name: "BNB Smart Chain",
        native_symbol: "BNB",
        coingecko_id: "binancecoin",
        blockscout_base: None, // no keyless Blockscout instance; history unavailable
        dexscreener_slug: Some("bsc"),
        legacy_gas: true, // BSC uses legacy gasPrice transactions
        cow_network: None, // CoW not deployed on BNB Smart Chain
        eth_flow: None,
        wrapped_native: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
    },
    ChainInfo {
        chain_id: 100,
        name: "Gnosis",
        native_symbol: "XDAI",
        coingecko_id: "xdai",
        blockscout_base: Some("https://gnosis.blockscout.com"),
        dexscreener_slug: Some("gnosischain"),
        legacy_gas: false,
        cow_network: Some("xdai"),
        eth_flow: None,
        wrapped_native: "0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d",
    },
    ChainInfo {
        chain_id: 43114,
        name: "Avalanche",
        native_symbol: "AVAX",
        coingecko_id: "avalanche-2",
        // Routescan exposes a keyless Etherscan-compatible API for the Avalanche C-Chain (no
        // official keyless Blockscout). History works; NFT collections (Blockscout v2 only) don't.
        blockscout_base: Some("https://api.routescan.io/v2/network/mainnet/evm/43114/etherscan"),
        dexscreener_slug: Some("avalanche"),
        legacy_gas: false,
        cow_network: Some("avalanche"),
        eth_flow: None,
        wrapped_native: "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7",
    },
    // ---- Testnets (for safe testing). coingecko_id is "" so no misleading USD price is shown for
    // worthless testnet ETH; no swaps (CoW/routers not offered). ----
    ChainInfo {
        chain_id: 11155111,
        name: "Sepolia (testnet)",
        native_symbol: "SepoliaETH",
        coingecko_id: "",
        blockscout_base: Some("https://eth-sepolia.blockscout.com"),
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
        blockscout_base: Some("https://eth-holesky.blockscout.com"),
        dexscreener_slug: None,
        legacy_gas: false,
        cow_network: None,
        eth_flow: None,
        wrapped_native: "",
    },
];

/// True for chains that are test networks (worthless coins) — the UI marks them and can hide them.
pub fn is_testnet(chain_id: u64) -> bool {
    matches!(chain_id, 11155111 | 17000)
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

/// Whether Odos SOR supports `chain_id` (Odos uses the numeric chain id, no slug).
pub fn odos_supported(chain_id: u64) -> bool {
    matches!(chain_id, 1 | 10 | 56 | 137 | 8453 | 42161 | 43114)
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
            blockscout_base: None,
            dexscreener_slug: None,
            legacy_gas: false,
            cow_network: None,
            eth_flow: None,
            wrapped_native: "",
        })
}
