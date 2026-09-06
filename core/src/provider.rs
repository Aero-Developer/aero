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

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
/// history fetch) poll this and bail out promptly so they release the core lock - otherwise the
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
static TOTAL: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(20));
/// Sub-cap on `Background` requests. Background work must first take a slot here, THEN a TOTAL slot,
/// so at most this many bulk requests ever compete for TOTAL at once - leaving `TOTAL - BG` slots
/// that only Interactive work contends for. That's what stops a burst of dozens of scan/history
/// requests from queuing ahead of the fee/balance refresh the user is actually waiting on.
static BG: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(ISO_CIRCUITS));
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

/// How long a lane keeps one circuit before Aero asks Tor for another.
///
/// Tor gives new streams a fresh circuit every ten minutes, but that only applies to streams it is
/// asked to open. A wallet polls without pause - blocks, balances, fees - so its connection never
/// goes idle, is never closed, and the stream stays on the circuit it was born on for as long as the
/// app is open. The rotation everyone assumes is happening does not happen. Retiring the connection
/// on a timer is what makes it real: the client is rebuilt under a new SOCKS username, the old
/// pooled connections go with it, and Tor has no choice but to build somewhere new.
const RPC_CIRCUIT_MS: u64 = 10 * 60 * 1000;
/// The market and exchange lane rotates more slowly on purpose. These hosts sit behind Cloudflare,
/// which treats an unfamiliar Tor exit as something to challenge, and the wallet learned the hard
/// way that changing exits often enough makes them fail outright.
const API_CIRCUIT_MS: u64 = 30 * 60 * 1000;
/// The isolated pool retires its circuits too. They were built once and kept for the life of the
/// connection, which is the same trap the wallet lane was in: these carry the block-explorer read of
/// every address the wallet owns, so an exit that is never replaced ends up holding the longest list
/// of them. Longer than the wallet lane because a full history load can run for minutes and there is
/// no reason to change exits underneath one.
const ISO_CIRCUIT_MS: u64 = 15 * 60 * 1000;

/// One lane's current circuit, and when it was built.
struct Lane {
    client: reqwest::Client,
    born_ms: u64,
    epoch: u64,
}

/// Serial number for single-use broadcast circuits, so two sends in the same millisecond still get
/// their own.
static BROADCAST_SEQ: AtomicUsize = AtomicUsize::new(0);
/// Serial number behind each provider's circuit nonce.
static PROVIDER_SEQ: AtomicUsize = AtomicUsize::new(0);

/// A tag that makes this provider's SOCKS usernames unlike any other provider's, including the ones
/// this same process used a minute ago.
///
/// Without it the names are fixed strings, and a fixed name is a fixed circuit: reconnecting, or
/// switching chain and coming back, would hand the wallet the exact exit it had just left. That is
/// the opposite of what "New Tor circuit" promises, and it is why the button restarting Tor was
/// doing more work than it should have needed to.
fn circuit_nonce() -> String {
    let seq = PROVIDER_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{:x}{:x}", now_ms(), seq)
}

/// A Tor-routed JSON-RPC client with endpoint rotation.
pub struct RpcProvider {
    http: reqwest::Client,
    /// `host:port` of the Tor SOCKS proxy, kept so a lane can be rebuilt under a new username.
    /// `None` in clearnet mode, where there are no circuits to separate.
    socks_hostport: Option<String>,
    /// Makes every circuit this provider asks for unlike the last provider's. See [`circuit_nonce`].
    nonce: String,
    timeout: Duration,
    /// Traffic separated by what it reveals: "rpc" carries the addresses and the transactions, "api"
    /// carries prices and trading. Kept apart so the exit that watches the wallet is not also the one
    /// watching the trades.
    lanes: Mutex<HashMap<&'static str, Lane>>,
    /// Cursor for handing out isolated circuits round-robin. The circuits themselves live in `lanes`
    /// under [`ISO_NAMES`], so they are retired on a timer like every other circuit.
    iso_cursor: AtomicUsize,
    endpoints: Vec<Endpoint>,
    cursor: AtomicUsize,
    chain_id: u64,
}

/// One JSON-RPC endpoint and what is known about its willingness to answer.
///
/// Public endpoints do not fail cleanly. They stay up and start refusing: a rate limit, a daily
/// quota, a sudden demand for an API key. Remembering that means the next request goes somewhere
/// else instead of walking back into the same wall, which is the difference between a wallet that
/// stops working when one provider changes its policy and one that quietly carries on.
struct Endpoint {
    url: String,
    /// Unix milliseconds until which this endpoint is passed over. Zero when healthy.
    parked_until: AtomicU64,
    /// Consecutive refusals, so a persistently unhappy endpoint is parked for longer each time.
    strikes: AtomicUsize,
}

/// How long an endpoint is passed over after refusing, doubling per consecutive refusal.
const PARK_BASE: u64 = 30_000;
const PARK_MAX: u64 = 600_000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What an endpoint said, once it is clear whose fault it was.
enum Outcome {
    Ok(Value),
    /// The endpoint answered about the request itself - a revert, a bad parameter, a transaction the
    /// chain will not take. Every other endpoint would say the same thing, so asking them is a waste
    /// of round trips and shows the query to more servers than necessary.
    Rejected(CoreError),
    /// The endpoint declined to serve this caller at all: a rate limit, a quota, a demand for an API
    /// key, a gateway error, a dead host. Says nothing about the request, so somewhere else is worth
    /// asking.
    Unavailable(CoreError),
}

/// Whether an HTTP status is the server declining to serve this caller rather than answering them.
///
/// 429 is the plain rate limit; 403 is the same thing dressed as a permission problem, which is how
/// Cloudflare turns Tor exits away; 408 and 5xx are the server or the hop in front of it failing.
/// Everything else, including a 400 or a 404, is an answer about the request and belongs to the
/// caller to interpret.
fn is_refusal_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || matches!(status.as_u16(), 403 | 408 | 429)
}

/// Whether an error came from a host declining to serve us, and so is worth another go elsewhere.
fn is_refusal(e: &CoreError) -> bool {
    let m = e.to_string();
    m.contains("refused: ") || m.contains("http get failed") || m.contains("http post failed")
}

/// Whether a JSON-RPC error describes the request rather than the server's willingness to answer it.
///
/// Deliberately a list of things known to be about the request, with everything else treated as the
/// endpoint's problem. The alternative - listing the ways a server can say "no" - has to be extended
/// every time a provider invents new wording, and being wrong that way is what leaves a wallet
/// showing "rate limit reached" with three working endpoints it never tried.
fn is_about_the_request(message: &str) -> bool {
    const REQUEST_FAULTS: &[&str] = &[
        "execution reverted",
        "revert",
        "insufficient funds",
        "insufficient balance",
        "nonce too low",
        "nonce too high",
        "invalid nonce",
        "already known",
        "already imported",
        "transaction underpriced",
        "replacement transaction",
        "fee cap",
        "max fee per gas",
        "tip higher than fee cap",
        "intrinsic gas",
        "exceeds block gas limit",
        "gas required exceeds",
        "out of gas",
        "invalid params",
        "invalid argument",
        "invalid sender",
        "invalid signature",
        "invalid opcode",
        "transaction type not supported",
        "oversized data",
        "future transaction",
        "known transaction",
    ];
    let m = message.to_lowercase();
    REQUEST_FAULTS.iter().any(|f| m.contains(f))
}

/// What Aero calls itself to every server it talks to.
///
/// It used to say `aero/0.1`, described in a comment as generic. It is the opposite of generic: it
/// names the wallet and its version to every RPC provider, explorer, price feed and exchange, and
/// the number of people running this program is small enough that saying so is most of the way to
/// being identified. It also undoes the work of separating traffic into circuits - two services
/// comparing notes, or one service behind two names, can rejoin the lanes on sight, because every
/// lane introduced itself with the same unusual string.
///
/// This is Tor Browser's user agent, which is the largest crowd available to stand in over this
/// network. It is deliberately identical on every platform - Tor Browser reports Windows from macOS
/// and Linux too, and a wallet that reported the truth would be handing over the one detail the
/// string is there to withhold.
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0";

/// How many isolated Tor circuits to spread bulk GETs over.
const ISO_CIRCUITS: usize = 8;

/// Lane names for the isolated pool. Fixed strings so a lane lookup costs no allocation, and one per
/// circuit so each can be retired on its own schedule.
const ISO_NAMES: [&str; ISO_CIRCUITS] =
    ["iso0", "iso1", "iso2", "iso3", "iso4", "iso5", "iso6", "iso7"];

/// FNV-1a. Used only to put a key on a circuit, so it needs to be stable and cheap, not strong -
/// and it must not be the standard hasher, whose seed changes every run and would scatter the same
/// address across a different exit each time the wallet opened.
fn stable_hash(key: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

impl RpcProvider {
    pub fn new(cfg: &ProviderConfig) -> Result<Self> {
        if cfg.endpoints.is_empty() {
            return Err(CoreError::NoProvider);
        }
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .user_agent(USER_AGENT) // see USER_AGENT: blend in, don't announce the wallet
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

        // Build the isolated-circuit pool (only when going through Tor). Each client uses a distinct
        // SOCKS username, and Tor's IsolateSOCKSAuth (on by default) gives each its own circuit/exit,
        // so concurrent bulk GETs leave through different IPs and don't share a per-IP rate limit.
        let timeout = Duration::from_secs(cfg.timeout_secs);
        let socks_hostport = cfg.socks_proxy.as_deref().map(socks_hostport);

        Ok(Self {
            http,
            socks_hostport,
            nonce: circuit_nonce(),
            timeout,
            // Circuits are built when first asked for, isolated pool included, and rebuilt whenever
            // one has been in use long enough. Nothing here is built once and kept forever.
            lanes: Mutex::new(HashMap::new()),
            iso_cursor: AtomicUsize::new(0),
            endpoints: cfg
                .endpoints
                .iter()
                .map(|url| Endpoint {
                    url: url.clone(),
                    parked_until: AtomicU64::new(0),
                    strikes: AtomicUsize::new(0),
                })
                .collect(),
            cursor: AtomicUsize::new(0),
            chain_id: cfg.chain_id,
        })
    }

    /// The SOCKS username for one lane at one point in its life. Tor keys a circuit on this string,
    /// so two names that differ by a character are two different exits.
    fn username(&self, name: &str, epoch: u64) -> String {
        format!("aero{}{name}{epoch}", self.nonce)
    }

    /// The client for a named lane, rebuilt under a fresh SOCKS username once its circuit has been
    /// carrying traffic for `max_age_ms`.
    ///
    /// Rebuilding is the point. A reqwest client pools its connections, and a pooled connection is
    /// one Tor stream on one circuit; keeping the client is keeping the exit. Dropping it is the only
    /// way to make Tor choose again.
    fn lane(&self, name: &'static str, max_age_ms: u64) -> reqwest::Client {
        let Some(hostport) = &self.socks_hostport else {
            return self.http.clone(); // clearnet: no circuits to keep apart
        };
        let now = now_ms();
        let mut lanes = match self.lanes.lock() {
            Ok(l) => l,
            Err(poisoned) => poisoned.into_inner(),
        };
        let epoch = match lanes.get(name) {
            Some(l) if now.saturating_sub(l.born_ms) < max_age_ms => return l.client.clone(),
            Some(l) => l.epoch + 1,
            None => 0,
        };
        match socks_client(hostport, &self.username(name, epoch), self.timeout) {
            Some(client) => {
                lanes.insert(name, Lane { client: client.clone(), born_ms: now, epoch });
                client
            }
            None => self.http.clone(),
        }
    }

    /// A circuit used for exactly one request and then abandoned.
    ///
    /// For broadcasting a signed transaction. Everything else the wallet asks a node is a question;
    /// this is the one message that hands over something permanent and public with the sender's name
    /// on it. Sending it down the same circuit that just asked after a dozen balances tells the node
    /// which wallet those balances belong to - so it goes out through an exit that has never been
    /// used for anything else and is never used again.
    fn one_shot_circuit(&self) -> reqwest::Client {
        let Some(hostport) = &self.socks_hostport else {
            return self.http.clone();
        };
        let n = BROADCAST_SEQ.fetch_add(1, Ordering::Relaxed);
        let username = format!("aero{}t{}x{n}", self.nonce, now_ms());
        socks_client(hostport, &username, self.timeout).unwrap_or_else(|| self.http.clone())
    }

    /// Round-robin one of the isolated circuits. For work where throughput is the point and there is
    /// nothing to keep together - retrying a refused API call, pulling token artwork off a CDN.
    fn iso_client(&self) -> reqwest::Client {
        let i = self.iso_cursor.fetch_add(1, Ordering::Relaxed) % ISO_CIRCUITS;
        self.lane(ISO_NAMES[i], ISO_CIRCUIT_MS)
    }

    /// The isolated circuit belonging to `key` - always the same one for the same key.
    ///
    /// Round-robin was the wrong instinct here, and backwards. Paging through one address's history
    /// handed page one to the first exit, page two to the second, and so on, so across a full load
    /// every exit ended up seeing a slice of every address - which is the clustering the isolated
    /// pool exists to prevent, performed eight times over. Keyed by address instead, an exit only
    /// ever learns about the addresses that hash to it, and the explorer sees one address being read
    /// by one client rather than eight clients taking turns on it.
    fn iso_client_for(&self, key: &str) -> reqwest::Client {
        let i = (stable_hash(key) % ISO_CIRCUITS as u64) as usize;
        self.lane(ISO_NAMES[i], ISO_CIRCUIT_MS)
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The order to try endpoints in for one request: the sticky one first, then the rest, with
    /// anything currently parked pushed to the back rather than dropped. Parked endpoints are still
    /// tried as a last resort, because a stale park must never be the reason a wallet has no network
    /// at all.
    ///
    /// The order starts at the same endpoint across calls (as Feather and Electrum use one node per
    /// session) so the Tor stream and TLS connection are reused via keep-alive, rather than opening a
    /// fresh circuit-hop to a different host every time. The pointer only moves off an endpoint that
    /// failed, so a flaky one is abandoned and a healthy one is stuck to.
    fn attempt_order(&self) -> Vec<usize> {
        let n = self.endpoints.len();
        let start = self.cursor.load(Ordering::Relaxed) % n;
        let now = now_ms();
        let mut ready = Vec::with_capacity(n);
        let mut parked = Vec::new();
        for k in 0..n {
            let i = (start + k) % n;
            if self.endpoints[i].parked_until.load(Ordering::Relaxed) > now {
                parked.push(i);
            } else {
                ready.push(i);
            }
        }
        ready.extend(parked);
        ready
    }

    /// Remember that this endpoint answered, and stick to it.
    fn mark_healthy(&self, i: usize) {
        self.endpoints[i].strikes.store(0, Ordering::Relaxed);
        self.endpoints[i].parked_until.store(0, Ordering::Relaxed);
        self.cursor.store(i, Ordering::Relaxed);
    }

    /// Remember that this endpoint would not serve us, and for how long to leave it alone.
    fn park(&self, i: usize) {
        let strikes = self.endpoints[i].strikes.fetch_add(1, Ordering::Relaxed) + 1;
        let backoff = PARK_BASE
            .saturating_mul(1u64 << strikes.min(5) as u64)
            .min(PARK_MAX);
        self.endpoints[i].parked_until.store(now_ms() + backoff, Ordering::Relaxed);
        // Move the sticky pointer along so the next request starts somewhere else even if this one
        // ends up succeeding on a later endpoint.
        self.cursor.store((i + 1) % self.endpoints.len(), Ordering::Relaxed);
    }

    /// GET raw bytes - an NFT thumbnail - over an isolated circuit.
    ///
    /// The URL here comes from a token's own metadata, which means an attacker chooses it. Anyone can
    /// airdrop a token whose artwork lives on their server and watch who fetches it. On the wallet's
    /// circuit that fetch would arrive from the same exit as the JSON-RPC that names the holder's
    /// addresses; on an isolated one it arrives from an exit doing nothing else of interest.
    pub async fn http_get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let w0 = Instant::now();
        let _gate = gate().await; // priority-aware Tor concurrency gate
        let _probe = ReqProbe::begin(format!("GET  bytes {}", host_of(url)), w0.elapsed());
        let client = self.iso_client();
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| CoreError::rpc(format!("image get failed: {e}")))?;
        let status = resp.status();
        // Without this, a rate limit's HTML apology is handed back as though it were a picture, and
        // whatever the decoder makes of that gets cached as the token's artwork.
        if !status.is_success() {
            return Err(CoreError::rpc(format!("image get failed: {status}")));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| CoreError::rpc(format!("image read failed ({status}): {e}")))?;
        Ok(bytes.to_vec())
    }

    /// GET+parse JSON over the STABLE (sticky) Tor circuit. Used for APIs that are Tor-hostile and/or
    /// stateful - DEX router quotes (CoW/Kyber/Odos/ParaSwap/OpenOcean), the CoW order book, and price
    /// feeds. Those often block or rate-limit random Tor exits behind Cloudflare, so rotating circuits
    /// (see http_get_json_isolated) made them fail intermittently; a single consistent circuit is far
    /// more reliable, and these are only a handful of requests (not the per-address history fan-out).
    pub async fn http_get_json(&self, url: &str) -> Result<Value> {
        // These are single-host APIs - a price feed, a router, an exchange - with nowhere to fail
        // over to, so a refusal gets a second and third chance instead. The retry goes over an
        // isolated circuit, which means a different Tor exit and usually a different rate-limit
        // bucket: the reason these get refused at all is that thousands of people share the handful
        // of exits in front of them.
        let market = self.lane("api", API_CIRCUIT_MS);
        let mut last = CoreError::rpc("no attempt made");
        for attempt in 0..3u32 {
            let client = if attempt == 0 { market.clone() } else { self.iso_client() };
            match self.get_json_with(&client, url, &[]).await {
                Ok(v) => return Ok(v),
                Err(e) if !is_refusal(&e) => return Err(e),
                Err(e) => last = e,
            }
            if shutting_down() {
                break;
            }
            interruptible_sleep(Duration::from_millis(400 << attempt)).await;
        }
        Err(last)
    }

    /// GET and parse JSON with `client`, treating a refusal as a failure rather than as data.
    ///
    /// The distinction matters more than it looks. A rate limit usually arrives as a perfectly valid
    /// JSON body with an HTTP 429 on it, and callers up the stack read a missing field as "nothing
    /// here" - so a refused balance lookup became a balance of zero, and a refused price became a
    /// price of nothing. Failing here means those read as errors, which is what they are.
    async fn get_json_with(
        &self,
        client: &reqwest::Client,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<Value> {
        let w0 = Instant::now();
        let _gate = gate().await; // priority-aware Tor concurrency gate
        let _probe = ReqProbe::begin(format!("GET  {}", host_of(url)), w0.elapsed());
        let mut req = client.get(url).header("accept", "application/json");
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| CoreError::rpc(format!("http get failed: {e}")))?;
        let status = resp.status();
        if is_refusal_status(status) {
            return Err(CoreError::rpc(format!("{} refused: {status}", host_of(url))));
        }
        resp.json()
            .await
            .map_err(|e| CoreError::rpc(format!("bad json ({status}): {e}")))
    }

    /// GET+parse JSON over the ISOLATED circuit belonging to `iso_key`. ONLY for the bulk,
    /// per-address block-explorer history fan-out, where hundreds of requests to one endpoint would
    /// otherwise share and rate-limit against a single exit IP. Do NOT use for router/price APIs.
    ///
    /// Pass the address being read as `iso_key`. Everything asked about one address then goes out
    /// through one exit, and different addresses go out through different ones - which is the
    /// separation this pool was built for.
    pub async fn http_get_json_isolated(&self, url: &str, iso_key: &str) -> Result<Value> {
        // No retry here: the caller (the explorer paging loop) already backs off and, now, moves to
        // a different explorer entirely, which is a better answer than asking the same one again.
        let client = self.iso_client_for(iso_key);
        self.get_json_with(&client, url, &[]).await
    }

    /// POST a JSON body (over the same Tor client) and return the parsed JSON response.
    ///
    /// A 4xx body is still returned, because for these APIs it carries the answer: CoW explains a
    /// rejected order in the body of a 400, and Hyperliquid explains a rejected order in the body of
    /// a 422. A refusal is different - there is no answer in it, only "not you, not now" - so it
    /// fails, and is retried on a fresh circuit rather than handed upwards as though the exchange had
    /// said something.
    pub async fn http_post_json(&self, url: &str, body: &Value) -> Result<Value> {
        let market = self.lane("api", API_CIRCUIT_MS);
        let mut last = CoreError::rpc("no attempt made");
        for attempt in 0..3u32 {
            let client = if attempt == 0 { market.clone() } else { self.iso_client() };
            match self.post_json_with(&client, url, body).await {
                Ok(v) => return Ok(v),
                Err(e) if !is_refusal(&e) => return Err(e),
                Err(e) => last = e,
            }
            if shutting_down() {
                break;
            }
            interruptible_sleep(Duration::from_millis(400 << attempt)).await;
        }
        Err(last)
    }

    async fn post_json_with(
        &self,
        client: &reqwest::Client,
        url: &str,
        body: &Value,
    ) -> Result<Value> {
        let w0 = Instant::now();
        let _gate = gate().await; // priority-aware Tor concurrency gate
        let _probe = ReqProbe::begin(format!("POST {}", host_of(url)), w0.elapsed());
        let resp = client
            .post(url)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| CoreError::rpc(format!("http post failed: {e}")))?;
        let status = resp.status();
        if is_refusal_status(status) {
            return Err(CoreError::rpc(format!("{} refused: {status}", host_of(url))));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| CoreError::rpc(format!("http post read failed ({status}): {e}")))?;
        serde_json::from_str(&text)
            .map_err(|e| CoreError::rpc(format!("bad json ({status}): {e}")))
    }

    /// GET+parse JSON with extra request headers, over the stable Tor circuit.
    ///
    /// Exists for APIs that carry a per-request credential in a header rather than the URL - Wagyu's
    /// bridge puts an order's session token in `x-session-id` precisely so it never lands in a query
    /// string, where it would end up in logs and history.
    pub async fn http_get_json_with_headers(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<Value> {
        // Retried like the other single-host GETs. This one tracks the progress of a redemption
        // whose funds are already on their way, so "the server was busy" must not be allowed to look
        // like "your order is gone".
        let market = self.lane("api", API_CIRCUIT_MS);
        let mut last = CoreError::rpc("no attempt made");
        for attempt in 0..3u32 {
            let client = if attempt == 0 { market.clone() } else { self.iso_client() };
            match self.get_json_with(&client, url, headers).await {
                Ok(v) => return Ok(v),
                Err(e) if !is_refusal(&e) => return Err(e),
                Err(e) => last = e,
            }
            if shutting_down() {
                break;
            }
            interruptible_sleep(Duration::from_millis(400 << attempt)).await;
        }
        Err(last)
    }

    /// Perform a single JSON-RPC call. Tries each endpoint once on transport failure.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        self.call_on(&self.lane("rpc", RPC_CIRCUIT_MS), body).await
    }

    /// Broadcast a signed transaction over a circuit built for this one request.
    pub async fn send_raw_transaction(&self, raw_hex: &str) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendRawTransaction",
            "params": [raw_hex],
        });
        self.call_on(&self.one_shot_circuit(), body).await
    }

    async fn call_on(&self, client: &reqwest::Client, body: Value) -> Result<Value> {
        let mut refusals = 0usize;
        let mut last_err = CoreError::rpc("no endpoints");
        for i in self.attempt_order() {
            let url = self.endpoints[i].url.clone();
            match self.try_call(client, &url, &body).await {
                Outcome::Ok(v) => {
                    self.mark_healthy(i);
                    return Ok(v);
                }
                // The endpoint answered about the request, not about us. Every other endpoint would
                // say the same, so return it rather than replaying the query across the internet.
                Outcome::Rejected(e) => return Err(e),
                // The endpoint would not serve us. Park it and ask the next one - this is the whole
                // point of configuring several, and returning here is what used to leave the wallet
                // reporting a rate limit while three working endpoints sat unused.
                Outcome::Unavailable(e) => {
                    self.park(i);
                    refusals += 1;
                    last_err = e;
                }
            }
        }
        Err(if refusals > 1 {
            CoreError::rpc(format!(
                "every network endpoint refused or failed to answer ({refusals} tried). \
                 They may be rate-limiting this connection; it usually clears on its own, or set \
                 your own node under Settings > Node. Last reply: {last_err}"
            ))
        } else {
            last_err
        })
    }

    async fn try_call(&self, client: &reqwest::Client, url: &str, body: &Value) -> Outcome {
        let w0 = Instant::now();
        let _gate = gate().await; // priority-aware Tor concurrency gate
        let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("rpc");
        let _probe = ReqProbe::begin(format!("RPC  {method} @{}", host_of(url)), w0.elapsed());
        let resp = match client.post(url).json(body).send().await {
            Ok(r) => r,
            Err(e) => return Outcome::Unavailable(CoreError::rpc(format!("request failed: {e}"))),
        };
        let status = resp.status();
        // A refusal is often an HTTP status rather than a JSON-RPC error - 429 for a rate limit, 403
        // for a key demand, 5xx for a gateway having a bad day - and the body is then frequently HTML
        // that would only produce a parse error.
        if status.is_server_error() || status.as_u16() == 429 || status.as_u16() == 403 {
            return Outcome::Unavailable(CoreError::rpc(format!("endpoint returned {status}")));
        }
        let val: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                return Outcome::Unavailable(CoreError::rpc(format!("bad response ({status}): {e}")))
            }
        };
        if let Some(err) = val.get("error") {
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            let text = CoreError::rpc(format!("rpc error: {err}"));
            return if is_about_the_request(&message) {
                Outcome::Rejected(text)
            } else {
                Outcome::Unavailable(text)
            };
        }
        match val.get("result").cloned() {
            Some(v) => Outcome::Ok(v),
            None => Outcome::Unavailable(CoreError::rpc("response missing result")),
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

        let client = self.lane("rpc", RPC_CIRCUIT_MS);
        let mut last_err = CoreError::rpc("no endpoints");
        for i in self.attempt_order() {
            let url = self.endpoints[i].url.clone();
            match self.try_call_batch(&client, &url, &body, calls.len()).await {
                Ok(v) => {
                    self.mark_healthy(i);
                    return Ok(v);
                }
                Err(e) => {
                    self.park(i);
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    async fn try_call_batch(
        &self,
        client: &reqwest::Client,
        url: &str,
        body: &Value,
        n: usize,
    ) -> Result<Vec<Value>> {
        let w0 = Instant::now();
        let _gate = gate().await; // priority-aware Tor concurrency gate
        let _probe = ReqProbe::begin(format!("RPC  batch({n}) @{}", host_of(url)), w0.elapsed());
        let resp = client
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| CoreError::rpc(format!("batch request failed: {e}")))?;
        let status = resp.status();
        if status.is_server_error() || status.as_u16() == 429 || status.as_u16() == 403 {
            return Err(CoreError::rpc(format!("endpoint returned {status}")));
        }
        let val: Value = resp
            .json()
            .await
            .map_err(|e| CoreError::rpc(format!("bad batch response ({status}): {e}")))?;
        let arr = val
            .as_array()
            .ok_or_else(|| CoreError::rpc("batch response was not an array"))?;
        // Responses may arrive out of order; place each by its `id` (the request index).
        let mut out = vec![Value::Null; n];
        let mut errors = 0usize;
        let mut first_error = String::new();
        for item in arr {
            if item.get("error").is_some() {
                errors += 1;
                if first_error.is_empty() {
                    first_error = item["error"].to_string();
                }
            }
            if let Some(id) = item.get("id").and_then(|v| v.as_u64()) {
                let idx = id as usize;
                if idx < n {
                    out[idx] = item.get("result").cloned().unwrap_or(Value::Null);
                }
            }
        }
        // A batch where every call came back an error is the endpoint refusing the batch, not N
        // separate answers. Returning it as N nulls is how a rate-limited balance refresh used to
        // read as "this account holds nothing" instead of as a failure worth retrying elsewhere.
        if errors > 0 && errors == arr.len() {
            return Err(CoreError::rpc(format!("batch refused: {first_error}")));
        }
        Ok(out)
    }

    // ---- typed convenience wrappers over the raw JSON-RPC surface ----

    pub async fn get_balance(&self, address: &str) -> Result<Value> {
        self.call("eth_getBalance", json!([address, "latest"])).await
    }

    pub async fn get_transaction_count(&self, address: &str) -> Result<Value> {
        // "pending" (not "latest") so back-to-back sends - an approve immediately followed by a swap,
        // send-to-many, or speed-up - each get the NEXT nonce and don't collide on the same one.
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
/// The `host:port` of a SOCKS proxy URL, with any credentials stripped.
fn socks_hostport(proxy: &str) -> String {
    let norm = normalize_socks(proxy);
    norm.strip_prefix("socks5h://")
        .unwrap_or(&norm)
        .rsplit('@')
        .next()
        .unwrap_or("127.0.0.1:9050")
        .to_string()
}

/// An HTTP client whose traffic goes to Tor under `username`.
///
/// The username is the whole mechanism: with IsolateSOCKSAuth, Tor gives each distinct SOCKS
/// username its own circuit and its own exit. The password is not checked and is not a secret.
fn socks_client(hostport: &str, username: &str, timeout: Duration) -> Option<reqwest::Client> {
    let proxy = reqwest::Proxy::all(&format!("socks5h://{username}:x@{hostport}")).ok()?;
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(USER_AGENT)
        .no_proxy()
        .proxy(proxy)
        .build()
        .ok()
}

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
    use super::*;

    #[test]
    fn a_refusal_is_told_apart_from_a_rejected_request() {
        // Real wordings from public endpoints. Every one of these must send the wallet to the next
        // endpoint rather than out to the user as an error: this is what "rate limit reached" with
        // three untouched endpoints behind it looked like.
        for refusal in [
            "rate limit exceeded",
            "Max rate limit reached",
            "daily request count exceeded, upgrade your account",
            "Too Many Requests",
            "Unauthorized: You must authenticate your request with an API key",
            "Cannot fulfill request",
            "capacity exceeded",
            "your app has exceeded its compute units per second capacity",
            "the method eth_feeHistory does not exist/is not available",
            "internal error",
            "service temporarily unavailable, please try again later",
            "project ID does not have access to archive state",
        ] {
            assert!(!is_about_the_request(refusal), "should have failed over: {refusal}");
        }

        // These describe the call, and every endpoint would say the same. Replaying them just shows
        // the query to more servers and slows down the answer the user is waiting for.
        for rejection in [
            "execution reverted: ERC20: transfer amount exceeds balance",
            "insufficient funds for gas * price + value",
            "nonce too low",
            "already known",
            "replacement transaction underpriced",
            "intrinsic gas too low",
            "invalid params: invalid argument 0",
            "gas required exceeds allowance",
        ] {
            assert!(is_about_the_request(rejection), "should not have failed over: {rejection}");
        }
    }

    #[test]
    fn a_parked_endpoint_goes_to_the_back_of_the_queue() {
        let p = RpcProvider::new(&ProviderConfig {
            chain_id: 1,
            endpoints: vec![
                "http://127.0.0.1:1".into(),
                "http://127.0.0.1:2".into(),
                "http://127.0.0.1:3".into(),
            ],
            socks_proxy: None,
            allow_clearnet: true,
            timeout_secs: 5,
        })
        .expect("provider");

        assert_eq!(p.attempt_order(), vec![0, 1, 2]);

        // The first endpoint refuses: it drops to last, and the next request starts on the second.
        p.park(0);
        assert_eq!(p.attempt_order(), vec![1, 2, 0]);

        // It is still tried as a last resort - a stale park must never mean "no network at all".
        p.park(1);
        p.park(2);
        assert_eq!(p.attempt_order().len(), 3);

        // Answering clears the record and makes it sticky again.
        p.mark_healthy(2);
        assert_eq!(p.attempt_order()[0], 2);
        assert_eq!(p.endpoints[2].strikes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn parking_backs_off_but_stays_bounded() {
        let p = RpcProvider::new(&ProviderConfig {
            chain_id: 1,
            endpoints: vec!["http://127.0.0.1:1".into()],
            socks_proxy: None,
            allow_clearnet: true,
            timeout_secs: 5,
        })
        .expect("provider");

        let mut previous = 0u64;
        for _ in 0..10 {
            p.park(0);
            let wait = p.endpoints[0].parked_until.load(Ordering::Relaxed) - now_ms();
            assert!(wait <= PARK_MAX + 1000, "park must stay bounded, got {wait}ms");
            previous = wait;
        }
        assert!(previous > PARK_BASE, "repeated refusals should back off");
    }

    fn tor_provider() -> RpcProvider {
        RpcProvider::new(&ProviderConfig {
            chain_id: 1,
            endpoints: vec!["http://127.0.0.1:1".into()],
            socks_proxy: Some("socks5h://127.0.0.1:9999".into()),
            allow_clearnet: false,
            timeout_secs: 5,
        })
        .expect("provider")
    }

    #[test]
    fn a_lane_retires_its_circuit_and_lanes_do_not_share_one() {
        // A wallet polls without pause, so its connection never idles out and the stream stays on the
        // circuit it was born on. Left alone, one exit sees the entire session.
        let p = tor_provider();

        // Within its lifetime a lane keeps one circuit: rotating per request is what made the
        // Cloudflare-fronted APIs fail.
        let _ = p.lane("rpc", RPC_CIRCUIT_MS);
        let epoch_now = p.lanes.lock().expect("lanes")["rpc"].epoch;
        let _ = p.lane("rpc", RPC_CIRCUIT_MS);
        assert_eq!(p.lanes.lock().expect("lanes")["rpc"].epoch, epoch_now);

        // Past its lifetime it must be rebuilt - a new username, which is a new circuit and a new
        // exit. Zero max age stands in for "the ten minutes are up".
        let _ = p.lane("rpc", 0);
        let rotated = p.lanes.lock().expect("lanes")["rpc"].epoch;
        assert_eq!(rotated, epoch_now + 1, "an expired lane must build a new circuit");

        // The wallet lane and the market lane must never be the same circuit, or the exit carrying
        // the trades is also the one carrying the addresses.
        let _ = p.lane("api", API_CIRCUIT_MS);
        assert_ne!(p.username("rpc", rotated), p.username("api", 0));
        assert_eq!(p.lanes.lock().expect("lanes").len(), 2);
    }

    #[test]
    fn an_address_always_reads_over_the_same_isolated_circuit() {
        let p = tor_provider();
        let a = "0x1111111111111111111111111111111111111111";
        let b = "0x2222222222222222222222222222222222222222";

        // Page two of an address's history must not go out through a different exit than page one.
        // Round-robin did exactly that, and the result was every exit seeing a piece of every
        // address - the clustering the pool is supposed to prevent.
        let first = stable_hash(a) % ISO_CIRCUITS as u64;
        for _ in 0..25 {
            assert_eq!(stable_hash(a) % ISO_CIRCUITS as u64, first);
        }

        // And the assignment has to survive a restart, or the same address would be read from a
        // different exit each session until every exit had seen it.
        assert_eq!(stable_hash(a), stable_hash(&a.to_string()));

        // Separate addresses should generally land on separate circuits. With eight of them a
        // collision is ordinary, so this checks the keys spread rather than that any two differ.
        let spread = (0..64)
            .map(|i| stable_hash(&format!("0x{i:040x}")) % ISO_CIRCUITS as u64)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(spread.len(), ISO_CIRCUITS, "keys should reach every circuit");

        let _ = (p.iso_client_for(a), p.iso_client_for(b));
        let lanes = p.lanes.lock().expect("lanes");
        assert!(lanes.keys().all(|k| ISO_NAMES.contains(k)), "iso work belongs on iso lanes");
    }

    #[test]
    fn the_isolated_pool_retires_its_circuits_too() {
        // These were built once in the constructor and kept for the life of the connection, which is
        // the same trap the wallet lane was in - and worse, because they carry the explorer read of
        // every address the wallet owns.
        let p = tor_provider();
        let key = "0xabc";
        let _ = p.iso_client_for(key);
        let name = ISO_NAMES[(stable_hash(key) % ISO_CIRCUITS as u64) as usize];
        let born = p.lanes.lock().expect("lanes")[name].epoch;

        let _ = p.lane(name, 0); // stand in for "its fifteen minutes are up"
        assert_eq!(
            p.lanes.lock().expect("lanes")[name].epoch,
            born + 1,
            "an isolated circuit must be replaced once it has been used long enough"
        );
    }

    #[test]
    fn reconnecting_does_not_land_back_on_the_circuit_it_left() {
        // Reconnecting, or leaving a chain and coming back, builds a new provider whose lanes start
        // over at epoch zero. With fixed usernames that meant asking Tor for the same isolation group
        // and being handed the same exit - so "New Tor circuit" changed nothing.
        let first = tor_provider();
        let second = tor_provider();
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.username("rpc", 0), second.username("rpc", 0));
    }

    #[test]
    fn every_broadcast_gets_a_circuit_of_its_own() {
        let p = tor_provider();

        // The counter behind the one-shot username has to move, or two sends in the same millisecond
        // would share an exit with each other.
        let before = BROADCAST_SEQ.load(Ordering::Relaxed);
        let _ = p.one_shot_circuit();
        let _ = p.one_shot_circuit();
        assert_eq!(BROADCAST_SEQ.load(Ordering::Relaxed), before + 2);

        // And a broadcast must not be handed the lane the balance queries are already using.
        assert!(p.lanes.lock().expect("lanes").is_empty());
    }

    /// A one-shot HTTP server on loopback that answers every request with `body`, so the failover
    /// can be exercised against a rate limit without depending on a real provider being in a bad
    /// mood.
    fn serve(body: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(8) {
                let Ok(mut s) = stream else { continue };
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    #[test]
    fn a_rate_limited_endpoint_is_stepped_over_not_reported() {
        // What the user saw: the first endpoint answers with a limit, and the wallet gave up there
        // and put that message on screen while the other endpoints sat untouched.
        let limited = serve(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32029,"message":"rate limit exceeded"}}"#);
        let working = serve(r#"{"jsonrpc":"2.0","id":1,"result":"0x1234"}"#);

        let p = RpcProvider::new(&ProviderConfig {
            chain_id: 1,
            endpoints: vec![limited.clone(), working.clone()],
            socks_proxy: None,
            allow_clearnet: true,
            timeout_secs: 10,
        })
        .expect("provider");

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let got = rt.block_on(p.call("eth_blockNumber", json!([]))).expect("should have failed over");
        assert_eq!(got, json!("0x1234"));

        // And the endpoint that refused is now parked, so the next call starts on the good one
        // instead of paying for the same refusal again.
        assert_eq!(p.attempt_order()[0], 1);

        // A revert is the request's own fault and must come straight back, not be replayed around
        // the internet in the hope that some other node likes it better.
        let reverting =
            serve(r#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted"}}"#);
        let p2 = RpcProvider::new(&ProviderConfig {
            chain_id: 1,
            endpoints: vec![reverting, working],
            socks_proxy: None,
            allow_clearnet: true,
            timeout_secs: 10,
        })
        .expect("provider");
        let err = rt
            .block_on(p2.call("eth_call", json!([])))
            .expect_err("a revert is an answer");
        assert!(err.to_string().contains("execution reverted"), "{err}");
    }

    /// As `serve`, but with a status line of the caller's choosing.
    fn serve_status(status: &'static str, body: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(8) {
                let Ok(mut s) = stream else { continue };
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let _ = write!(
                    s,
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    #[test]
    fn a_refused_http_get_is_an_error_not_an_empty_answer() {
        let p = RpcProvider::new(&ProviderConfig {
            chain_id: 1,
            endpoints: vec!["http://127.0.0.1:1".into()],
            socks_proxy: None,
            allow_clearnet: true,
            timeout_secs: 5,
        })
        .expect("provider");
        let rt = tokio::runtime::Runtime::new().expect("runtime");

        // A rate limit arrives as a perfectly valid JSON body with a 429 on it. Handed upwards, its
        // missing fields read as "no balances", "no orders", "no price" - the failure mode that
        // makes a wallet lie quietly rather than complain loudly.
        let limited = serve_status("429 Too Many Requests", r#"{"message":"rate limited"}"#);
        let err = rt
            .block_on(p.http_get_json(&format!("{limited}/anything")))
            .expect_err("a refusal is not data");
        assert!(err.to_string().contains("429"), "{err}");

        // A 400 still comes back, because for these APIs the body of a 400 is the answer: it is how
        // CoW explains a rejected order and how Hyperliquid explains a rejected size.
        let rejected = serve_status("400 Bad Request", r#"{"errorType":"InsufficientBalance"}"#);
        let v = rt
            .block_on(p.http_get_json(&format!("{rejected}/anything")))
            .expect("a 400 carries the explanation");
        assert_eq!(v["errorType"], "InsufficientBalance");

        // And an error page is never mistaken for a picture.
        let broken = serve_status("503 Service Unavailable", "<html>go away</html>");
        assert!(rt.block_on(p.http_get_bytes(&format!("{broken}/img.png"))).is_err());
    }

    #[test]
    fn a_batch_refused_outright_is_a_failure_not_a_row_of_empty_balances() {
        // Every sub-call rejected is the endpoint turning the batch away. Read as N nulls, that is a
        // wallet quietly showing zero balances for a whole page of accounts.
        let refusing = serve(
            r#"[{"jsonrpc":"2.0","id":0,"error":{"code":-32005,"message":"limit exceeded"}},
                {"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"limit exceeded"}}]"#,
        );
        let working = serve(r#"[{"jsonrpc":"2.0","id":0,"result":"0x1"},{"jsonrpc":"2.0","id":1,"result":"0x2"}]"#);
        let p = RpcProvider::new(&ProviderConfig {
            chain_id: 1,
            endpoints: vec![refusing, working],
            socks_proxy: None,
            allow_clearnet: true,
            timeout_secs: 10,
        })
        .expect("provider");

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let calls = vec![
            ("eth_getBalance".to_string(), json!([])),
            ("eth_getBalance".to_string(), json!([])),
        ];
        let got = rt.block_on(p.call_batch(&calls)).expect("should have failed over");
        assert_eq!(got, vec![json!("0x1"), json!("0x2")]);
    }

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
