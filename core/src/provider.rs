//! Ethereum JSON-RPC provider that routes every request through Tor.
//!
//! We speak JSON-RPC directly with `reqwest` (rather than alloy's provider) so we have full
//! control over:
//!   * the SOCKS5 proxy (Tor) used for transport, with `socks5h://` so DNS is resolved through Tor,
//!   * rotation across multiple untrusted endpoints (no single server sees all traffic),
//!   * pointing at a local Helios endpoint when the `helios` feature verifies results.
//!
//! When the `helios` feature is enabled, [`ProviderConfig::exec_rpc`] should point at the local
//! Helios RPC (`http://127.0.0.1:8545`), which cryptographically verifies upstream data.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

use crate::error::{CoreError, Result};

/// Networking configuration for the wallet.
#[derive(Clone, Debug)]
pub struct ProviderConfig {
    /// EVM chain id (1 = mainnet).
    pub chain_id: u64,
    /// One or more execution-layer JSON-RPC endpoints. Requests are rotated across them.
    pub endpoints: Vec<String>,
    /// SOCKS5 proxy address for Tor, e.g. `socks5h://127.0.0.1:9050`. `None` disables Tor
    /// (only allowed for localhost endpoints such as your own node / Helios).
    pub socks_proxy: Option<String>,
    /// Explicit opt-in to talk to remote endpoints WITHOUT Tor (exposes the user's IP). Defaults
    /// to false so a missing proxy never silently leaks; the UI sets this only as a fallback when
    /// Tor is unavailable, and warns the user.
    pub allow_clearnet: bool,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            endpoints: Vec::new(),
            socks_proxy: Some("socks5h://127.0.0.1:9050".to_string()),
            allow_clearnet: false,
            timeout_secs: 60,
        }
    }
}

/// A Tor-routed JSON-RPC client with endpoint rotation.
pub struct RpcProvider {
    http: reqwest::Client,
    endpoints: Vec<String>,
    cursor: AtomicUsize,
    chain_id: u64,
}

impl RpcProvider {
    pub fn new(cfg: &ProviderConfig) -> Result<Self> {
        if cfg.endpoints.is_empty() {
            return Err(CoreError::NoProvider);
        }
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .user_agent("aero/0.1"); // deliberately generic; no identifying telemetry

        if let Some(proxy) = &cfg.socks_proxy {
            let p = reqwest::Proxy::all(proxy)
                .map_err(|e| CoreError::rpc(format!("bad socks proxy: {e}")))?;
            builder = builder.proxy(p);
        } else {
            // No proxy: refuse non-local endpoints to avoid leaking the user's IP, unless the
            // caller has explicitly opted into a direct (clearnet) connection.
            if !cfg.allow_clearnet {
                for ep in &cfg.endpoints {
                    if !is_local(ep) {
                        return Err(CoreError::rpc(format!(
                            "refusing to use remote endpoint {ep} without a Tor proxy"
                        )));
                    }
                }
            }
            builder = builder.no_proxy();
        }

        let http = builder
            .build()
            .map_err(|e| CoreError::rpc(format!("http client: {e}")))?;

        Ok(Self {
            http,
            endpoints: cfg.endpoints.clone(),
            cursor: AtomicUsize::new(0),
            chain_id: cfg.chain_id,
        })
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn next_endpoint(&self) -> &str {
        let i = self.cursor.fetch_add(1, Ordering::Relaxed) % self.endpoints.len();
        &self.endpoints[i]
    }

    /// GET a URL and parse it as JSON, reusing the same (Tor-proxied) HTTP client. Used for the
    /// market price API — routed through Tor so the price lookup can't be tied to the user's IP.
    /// GET raw bytes (e.g. an NFT thumbnail) over the same Tor-proxied client, so fetching remote
    /// images can't be tied to the user's IP.
    pub async fn http_get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| CoreError::rpc(format!("image get failed: {e}")))?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| CoreError::rpc(format!("image read failed ({status}): {e}")))?;
        Ok(bytes.to_vec())
    }

    pub async fn http_get_json(&self, url: &str) -> Result<Value> {
        let resp = self
            .http
            .get(url)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| CoreError::rpc(format!("http get failed: {e}")))?;
        let status = resp.status();
        resp.json()
            .await
            .map_err(|e| CoreError::rpc(format!("bad json ({status}): {e}")))
    }

    /// Perform a single JSON-RPC call. Tries each endpoint once on transport failure.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let mut last_err = CoreError::rpc("no endpoints");
        for _ in 0..self.endpoints.len() {
            let url = self.next_endpoint().to_string();
            match self.try_call(&url, &body).await {
                Ok(v) => return Ok(v),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn try_call(&self, url: &str, body: &Value) -> Result<Value> {
        let resp = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| CoreError::rpc(format!("request failed: {e}")))?;
        let status = resp.status();
        let val: Value = resp
            .json()
            .await
            .map_err(|e| CoreError::rpc(format!("bad response ({status}): {e}")))?;
        if let Some(err) = val.get("error") {
            return Err(CoreError::rpc(format!("rpc error: {err}")));
        }
        val.get("result")
            .cloned()
            .ok_or_else(|| CoreError::rpc("response missing result"))
    }

    /// Perform many JSON-RPC calls in a single HTTP request. Returns one result `Value` per input
    /// in the same order (a per-call error becomes `Value::Null`). Used for fast balance scanning
    /// over Tor: one round-trip instead of N.
    pub async fn call_batch(&self, calls: &[(String, Value)]) -> Result<Vec<Value>> {
        if calls.is_empty() {
            return Ok(Vec::new());
        }
        let body = Value::Array(
            calls
                .iter()
                .enumerate()
                .map(|(i, (method, params))| {
                    json!({ "jsonrpc": "2.0", "id": i, "method": method, "params": params })
                })
                .collect(),
        );

        let mut last_err = CoreError::rpc("no endpoints");
        for _ in 0..self.endpoints.len() {
            let url = self.next_endpoint().to_string();
            match self.try_call_batch(&url, &body, calls.len()).await {
                Ok(v) => return Ok(v),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn try_call_batch(&self, url: &str, body: &Value, n: usize) -> Result<Vec<Value>> {
        let resp = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| CoreError::rpc(format!("batch request failed: {e}")))?;
        let status = resp.status();
        let val: Value = resp
            .json()
            .await
            .map_err(|e| CoreError::rpc(format!("bad batch response ({status}): {e}")))?;
        let arr = val
            .as_array()
            .ok_or_else(|| CoreError::rpc("batch response was not an array"))?;
        // Responses may arrive out of order; place each by its `id` (the request index).
        let mut out = vec![Value::Null; n];
        for item in arr {
            if let Some(id) = item.get("id").and_then(|v| v.as_u64()) {
                let idx = id as usize;
                if idx < n {
                    out[idx] = item.get("result").cloned().unwrap_or(Value::Null);
                }
            }
        }
        Ok(out)
    }

    // ---- typed convenience wrappers over the raw JSON-RPC surface ----

    pub async fn get_balance(&self, address: &str) -> Result<Value> {
        self.call("eth_getBalance", json!([address, "latest"])).await
    }

    pub async fn get_transaction_count(&self, address: &str) -> Result<Value> {
        self.call("eth_getTransactionCount", json!([address, "latest"]))
            .await
    }

    pub async fn eth_call(&self, to: &str, data_hex: &str) -> Result<Value> {
        self.call("eth_call", json!([{ "to": to, "data": data_hex }, "latest"]))
            .await
    }

    pub async fn estimate_gas(&self, tx: Value) -> Result<Value> {
        self.call("eth_estimateGas", json!([tx])).await
    }

    pub async fn fee_history(&self) -> Result<Value> {
        // Last block, 25th/50th/75th percentiles for tip suggestion.
        self.call("eth_feeHistory", json!(["0x5", "latest", [25, 50, 75]]))
            .await
    }

    pub async fn gas_price(&self) -> Result<Value> {
        self.call("eth_gasPrice", json!([])).await
    }

    pub async fn send_raw_transaction(&self, raw_hex: &str) -> Result<Value> {
        self.call("eth_sendRawTransaction", json!([raw_hex])).await
    }

    pub async fn block_number(&self) -> Result<Value> {
        self.call("eth_blockNumber", json!([])).await
    }

    pub async fn get_logs(&self, filter: Value) -> Result<Value> {
        self.call("eth_getLogs", json!([filter])).await
    }
}

/// Whether `endpoint`'s host is a loopback/localhost address. Parses the URL host rather than doing
/// a substring match, so a hostile host like `http://127.0.0.1.evil.com/` (which *contains*
/// "127.0.0.1") is correctly treated as remote and refused without Tor.
fn is_local(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    match url.host_str() {
        Some(h) => {
            // Strip IPv6 brackets, then check literal loopback IPs (covers 127.0.0.0/8 and ::1)
            // and the "localhost" name exactly.
            let host = h.trim_start_matches('[').trim_end_matches(']');
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_local;

    #[test]
    fn is_local_only_matches_real_loopback() {
        // Genuine loopback / localhost endpoints.
        assert!(is_local("http://127.0.0.1:8545"));
        assert!(is_local("http://localhost:8545/"));
        assert!(is_local("http://[::1]:8545"));
        assert!(is_local("http://127.0.0.5:8545")); // 127.0.0.0/8 is all loopback

        // Hostile hosts that merely CONTAIN a loopback substring must be treated as remote.
        assert!(!is_local("http://127.0.0.1.evil.com/"));
        assert!(!is_local("http://localhost.evil.com/"));
        assert!(!is_local("http://evil.com/?x=127.0.0.1"));
        assert!(!is_local("https://eth.llamarpc.com"));
    }
}
