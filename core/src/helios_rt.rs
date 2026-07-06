//! Optional trustless light-client backing via Helios (a16z).
//!
//! Enabled with `--features helios`. Helios syncs Ethereum's consensus light-client protocol
//! and exposes a **local** JSON-RPC endpoint that cryptographically verifies data fetched from
//! an untrusted upstream execution RPC. We then point [`crate::provider::RpcProvider`] at that
//! local endpoint, so every balance / `eth_call` the wallet performs is verified rather than
//! trusted.
//!
//! Note: the exact Helios builder surface tracks the upstream git crate; if a future Helios
//! release renames items, adjust the imports here. This module is compiled only when the
//! feature is on, so it never affects the default build or tests.

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Configuration for starting an embedded Helios light client.
pub struct HeliosConfig {
    /// Untrusted execution-layer RPC (must support `eth_getProof`), e.g. Alchemy/Infura.
    pub execution_rpc: String,
    /// Consensus-layer light-client RPC. Defaults to a public one if empty.
    pub consensus_rpc: Option<String>,
    /// Local port to expose the verified RPC on.
    pub local_port: u16,
}

impl Default for HeliosConfig {
    fn default() -> Self {
        Self {
            execution_rpc: String::new(),
            consensus_rpc: None,
            local_port: 8545,
        }
    }
}

/// Start Helios and return the local verified RPC URL (`http://127.0.0.1:<port>`).
///
/// The returned URL is what you pass to [`crate::provider::ProviderConfig::endpoints`]. Because
/// it is localhost, the provider is allowed to talk to it without the Tor proxy; Helios itself
/// should be configured to reach the untrusted upstream over Tor (via `ALL_PROXY`/system proxy).
#[cfg(feature = "helios")]
pub async fn start(cfg: &HeliosConfig) -> Result<String, BoxError> {
    use helios::ethereum::{config::networks::Network, EthereumClientBuilder};

    let consensus = cfg
        .consensus_rpc
        .clone()
        .unwrap_or_else(|| "https://www.lightclientdata.org".to_string());

    let mut client = EthereumClientBuilder::new()
        .network(Network::MAINNET)
        .execution_rpc(&cfg.execution_rpc)?
        .consensus_rpc(&consensus)?
        .load_external_fallback()
        .rpc_port(cfg.local_port)
        .build()?;

    client.start().await?;
    client.wait_synced().await;

    Ok(format!("http://127.0.0.1:{}", cfg.local_port))
}
