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

use std::fs::OpenOptions;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use serde_json::{json, Value};
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::error::{CoreError, Result};

/// Request priority. Foreground work the user is waiting on (balances of the open account, the fee
/// estimate when they open Send, the block poll) is `Interactive`; bulk background work that fans
/// out over many accounts/chains (the funded scan, the all-account history load, NFT/image fetches)
/// is `Background`. The gate below keeps Background from starving Interactive on the one Tor circuit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Priority {
    Interactive,
    Background,
}

tokio::task_local! {
    static PRIORITY: Priority;
}

/// Run `f` with every Tor request it makes (including everything it fans out to via join!/buffered,
/// which polls inline on the same task and so inherits this) marked `Background`. Wrap the bulk
/// operations (scan / all-account history / NFTs / images) at the FFI boundary with this.
pub async fn background<F: std::future::Future>(f: F) -> F::Output {
    PRIORITY.scope(Priority::Background, f).await
}

fn current_priority() -> Priority {
    PRIORITY.try_with(|p| *p).unwrap_or(Priority::Interactive)
}

/// Set once when the app is closing. Long-running background loops (the funded scan, the per-account
/// history fetch) poll this and bail out promptly so they release the core lock — otherwise the
/// blocking flush/save in the GUI's closeEvent would wait on an in-flight multi-minute scan/history
/// (made longer by rate-limit backoff), freezing the window so the X button appears to hang.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Request cooperative shutdown of all background network loops.
pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

/// Whether shutdown has been requested (background loops should stop and return what they have).
pub fn shutting_down() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

/// Sleep for `d`, but wake early (in <=200 ms) if shutdown is requested, so a backoff wait can't
/// keep the core lock held while the app is trying to close.
pub async fn interruptible_sleep(d: Duration) {
    let step = Duration::from_millis(200);
    let mut left = d;
    while left > Duration::ZERO {
        if shutting_down() {
            return;
        }
        let chunk = if left < step { left } else { step };
        tokio::time::sleep(chunk).await;
        left = left.saturating_sub(chunk);
    }
}

/// Hard cap on how many Tor requests may be in flight at once across the WHOLE app. A single Tor
/// circuit degrades if flooded, so every outbound request (JSON-RPC calls/batches, explorer/price/
/// image HTTP) takes a permit here first.
static TOTAL: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(12));
/// Sub-cap on `Background` requests. Background work must first take a slot here, THEN a TOTAL slot,
/// so at most this many bulk requests ever compete for TOTAL at once — leaving `TOTAL - BG` slots
/// that only Interactive work contends for. That's what stops a burst of dozens of scan/history
/// requests from queuing ahead of the fee/balance refresh the user is actually waiting on.
static BG: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(4));
/// Set the `AERO_NOPRIO` env var to fall back to the old flat single-queue behaviour (used by the
/// bench to measure the before/after of the priority gate). Off in normal builds.
static NOPRIO: Lazy<bool> = Lazy::new(|| std::env::var_os("AERO_NOPRIO").is_some());

/// A held gate: keeps the TOTAL (and, for background, BG) permit alive for the request's lifetime.
struct Gate {
    _total: SemaphorePermit<'static>,
    _bg: Option<SemaphorePermit<'static>>,
}

/// Acquire the concurrency gate for the current task's priority. Background: BG then TOTAL;
/// Interactive: TOTAL only (never blocked behind more than the few in-flight background requests).
async fn gate() -> Gate {
    let background = !*NOPRIO && current_priority() == Priority::Background;
    let bg = if background {
        Some(BG.acquire().await.expect("bg semaphore closed"))
    } else {
        None
    };
    let total = TOTAL.acquire().await.expect("total semaphore closed");
    Gate {
        _total: total,
        _bg: bg,
    }
}

// ---- lightweight request instrumentation (opt-in via AERO_NETLOG) ----
// AERO_NETLOG unset  => disabled (zero overhead beyond a cheap atomic check).
// AERO_NETLOG=1      => log lines to stderr.
// AERO_NETLOG=<path> => append log lines to that file.
static NETLOG_ON: Lazy<bool> = Lazy::new(|| std::env::var_os("AERO_NETLOG").is_some());
static NET_T0: Lazy<Instant> = Lazy::new(Instant::now);
static NET_INFLIGHT: AtomicUsize = AtomicUsize::new(0);
static NET_PEAK: AtomicUsize = AtomicUsize::new(0);
static NET_TOTAL: AtomicUsize = AtomicUsize::new(0);
static NET_WAIT_US: AtomicUsize = AtomicUsize::new(0); // summed gate-wait across all requests
static NET_FILE: Lazy<Option<Mutex<std::fs::File>>> = Lazy::new(|| {
    match std::env::var("AERO_NETLOG") {
        Ok(v) if v != "1" && !v.is_empty() => OpenOptions::new()
            .create(true)
            .append(true)
            .open(&v)
            .ok()
            .map(Mutex::new),
        _ => None,
    }
});

fn net_log_line(line: &str) {
    if let Some(m) = NET_FILE.as_ref() {
        if let Ok(mut f) = m.lock() {
            let _ = writeln!(f, "{line}");
        }
    } else {
        eprintln!("{line}");
    }
}

/// Snapshot of the process-wide request counters: (total requests, peak concurrent, summed gate-wait ms).
pub fn net_stats() -> (usize, usize, u64) {
    (
        NET_TOTAL.load(Ordering::Relaxed),
        NET_PEAK.load(Ordering::Relaxed),
        (NET_WAIT_US.load(Ordering::Relaxed) as u64) / 1000,
    )
}

/// Reset the request counters (used to isolate a bench phase). Does not touch the log file.
pub fn reset_net_stats() {
    NET_TOTAL.store(0, Ordering::Relaxed);
    NET_PEAK.store(0, Ordering::Relaxed);
    NET_WAIT_US.store(0, Ordering::Relaxed);
}

/// RAII probe around one in-flight request: records gate-wait, bumps the in-flight/peak gauges on
/// entry, logs a START line, and on drop decrements in-flight and logs an END line with the elapsed
/// on-wire time. Only does work when AERO_NETLOG is set.
struct ReqProbe {
    label: String,
    t_start: Instant,
    enabled: bool,
}

impl ReqProbe {
    fn begin(label: impl Into<String>, waited: Duration) -> Self {
        let enabled = *NETLOG_ON;
        NET_TOTAL.fetch_add(1, Ordering::Relaxed);
        NET_WAIT_US.fetch_add(waited.as_micros() as usize, Ordering::Relaxed);
        let inflight = NET_INFLIGHT.fetch_add(1, Ordering::Relaxed) + 1;
        NET_PEAK.fetch_max(inflight, Ordering::Relaxed);
        let label = label.into();
        if enabled {
            net_log_line(&format!(
                "{:>8.3}s START inflight={:<2} wait={:>4}ms pri={:<11} {}",
                NET_T0.elapsed().as_secs_f64(),
                inflight,
                waited.as_millis(),
                format!("{:?}", current_priority()),
                label,
            ));
        }
        ReqProbe {
            label,
            t_start: Instant::now(),
            enabled,
        }
    }
}

impl Drop for ReqProbe {
    fn drop(&mut self) {
        let inflight = NET_INFLIGHT.fetch_sub(1, Ordering::Relaxed) - 1;
        if self.enabled {
            net_log_line(&format!(
                "{:>8.3}s END   inflight={:<2} dur={:>5}ms {}",
                NET_T0.elapsed().as_secs_f64(),
                inflight,
                self.t_start.elapsed().as_millis(),
                self.label,
            ));
        }
    }
}

/// Short host label for logs, e.g. "eth.blockscout.com".
fn host_of(url: &str) -> &str {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
}

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
            .user_agent("aero/0.1") // deliberately generic; no identifying telemetry
            // Ignore any system/env proxy (HTTP(S)_PROXY / ALL_PROXY): a Tor-only wallet must never
            // route through an ambient proxy. We attach ONLY our explicit Tor proxy below.
            .no_proxy();

        if let Some(proxy) = &cfg.socks_proxy {
            // Force socks5h:// so hostnames are resolved THROUGH Tor (socks5:// would resolve DNS
            // locally, leaking the RPC/API hostnames to the user's resolver even over Tor).
            let norm = normalize_socks(proxy);
            let p = reqwest::Proxy::all(&norm)
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
            // (no_proxy already set above)
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

    // Sticky endpoint: keep using the SAME endpoint across calls (like Feather/Electrum use one node
    // per session) so the Tor stream + TLS connection are reused via keep-alive, instead of opening a
    // fresh circuit-hop to a different host on every request. We only move off it on failure
    // (advance_endpoint), so a flaky endpoint is abandoned but a healthy one is stuck to.
    fn current_endpoint(&self) -> &str {
        let i = self.cursor.load(Ordering::Relaxed) % self.endpoints.len();
        &self.endpoints[i]
    }

    fn advance_endpoint(&self) {
        self.cursor.fetch_add(1, Ordering::Relaxed);
    }

    /// GET a URL and parse it as JSON, reusing the same (Tor-proxied) HTTP client. Used for the
    /// market price API — routed through Tor so the price lookup can't be tied to the user's IP.
    /// GET raw bytes (e.g. an NFT thumbnail) over the same Tor-proxied client, so fetching remote
    /// images can't be tied to the user's IP.
    pub async fn http_get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let w0 = Instant::now();
        let _gate = gate().await; // priority-aware Tor concurrency gate
        let _probe = ReqProbe::begin(format!("GET  bytes {}", host_of(url)), w0.elapsed());
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
        let w0 = Instant::now();
        let _gate = gate().await; // priority-aware Tor concurrency gate
        let _probe = ReqProbe::begin(format!("GET  {}", host_of(url)), w0.elapsed());
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

    /// POST a JSON body (over the same Tor client) and return the parsed JSON response. The body is
    /// returned even for non-2xx statuses so callers (e.g. the CoW order-book API) can read the
    /// structured error object.
    pub async fn http_post_json(&self, url: &str, body: &Value) -> Result<Value> {
        let w0 = Instant::now();
        let _gate = gate().await; // priority-aware Tor concurrency gate
        let _probe = ReqProbe::begin(format!("POST {}", host_of(url)), w0.elapsed());
        let resp = self
            .http
            .post(url)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| CoreError::rpc(format!("http post failed: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| CoreError::rpc(format!("http post read failed ({status}): {e}")))?;
        serde_json::from_str(&text)
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
        for attempt in 0..self.endpoints.len() {
            if attempt > 0 {
                self.advance_endpoint(); // previous endpoint failed — try the next one
            }
            let url = self.current_endpoint().to_string();
            match self.try_call(&url, &body).await {
                Ok(Ok(v)) => return Ok(v),
                // A valid JSON-RPC error (revert, bad params, etc.) is a definitive answer, NOT a
                // transport failure — return it immediately instead of replaying the query to every
                // other endpoint (fewer requests, fewer servers see the query).
                Ok(Err(app_err)) => return Err(app_err),
                Err(transport) => last_err = transport, // try the next endpoint
            }
        }
        Err(last_err)
    }

    // Ok(Ok(result)) = success; Ok(Err(e)) = valid JSON-RPC error response (don't retry);
    // Err(e) = transport/parse failure (retry the next endpoint).
    async fn try_call(&self, url: &str, body: &Value) -> Result<std::result::Result<Value, CoreError>> {
        let w0 = Instant::now();
        let _gate = gate().await; // priority-aware Tor concurrency gate
        let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("rpc");
        let _probe = ReqProbe::begin(format!("RPC  {method} @{}", host_of(url)), w0.elapsed());
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
            return Ok(Err(CoreError::rpc(format!("rpc error: {err}"))));
        }
        match val.get("result").cloned() {
            Some(v) => Ok(Ok(v)),
            None => Err(CoreError::rpc("response missing result")), // treat as transport-ish, retry
        }
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
        for attempt in 0..self.endpoints.len() {
            if attempt > 0 {
                self.advance_endpoint(); // previous endpoint failed — try the next one
            }
            let url = self.current_endpoint().to_string();
            match self.try_call_batch(&url, &body, calls.len()).await {
                Ok(v) => return Ok(v),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn try_call_batch(&self, url: &str, body: &Value, n: usize) -> Result<Vec<Value>> {
        let w0 = Instant::now();
        let _gate = gate().await; // priority-aware Tor concurrency gate
        let _probe = ReqProbe::begin(format!("RPC  batch({n}) @{}", host_of(url)), w0.elapsed());
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
        // "pending" (not "latest") so back-to-back sends — an approve immediately followed by a swap,
        // send-to-many, or speed-up — each get the NEXT nonce and don't collide on the same one.
        self.call("eth_getTransactionCount", json!([address, "pending"]))
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
/// Force a SOCKS proxy URL to `socks5h://` so DNS is resolved through Tor. `socks5://` (which resolves
/// hostnames locally, leaking them) and a bare `host:port` are both rewritten. Anything else is
/// returned unchanged.
fn normalize_socks(proxy: &str) -> String {
    let p = proxy.trim();
    if let Some(rest) = p.strip_prefix("socks5://") {
        return format!("socks5h://{rest}");
    }
    if !p.contains("://") {
        return format!("socks5h://{p}");
    }
    p.to_string()
}

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
