//! Where transaction history comes from, and what to do when it stops coming.
//!
//! History is the one thing a wallet cannot derive from a node: reconstructing an address's past
//! from JSON-RPC alone means scanning every block, so it comes from an Etherscan-compatible explorer
//! API instead. That makes the explorer a dependency, and a keyless public explorer is a dependency
//! that will eventually rate-limit, break or disappear.
//!
//! Two things follow, and both are here:
//!
//!   * Several bases per chain, with the one that stopped answering parked for a while so the next
//!     account does not walk into the same wall. Aero fetches history for every account in the
//!     wallet, so a base that is 500ing must be discovered once, not a hundred and sixty times.
//!   * Whatever the user configured comes first. Anything Etherscan-compatible works, including an
//!     `api.etherscan.io/v2` URL carrying their own key, which covers every chain Aero supports. That
//!     is the escape hatch that means a provider going away is a setting to change rather than a new
//!     build to install.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;

/// How long a base that stopped answering is passed over, doubling per consecutive failure.
const PARK_BASE_MS: u64 = 60_000;
const PARK_MAX_MS: u64 = 900_000;

#[derive(Default)]
struct Health {
    parked_until: u64,
    strikes: u32,
}

static HEALTH: Lazy<Mutex<HashMap<String, Health>>> = Lazy::new(|| Mutex::new(HashMap::new()));
/// Bases configured by the user, per chain id. Tried before the built-in ones.
static CUSTOM: Lazy<Mutex<HashMap<u64, Vec<String>>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Replace the user's explorer bases for `chain_id`. Empty clears them.
///
/// Each entry is either a plain host (`https://eth.blockscout.com`), to which `/api` is appended, or
/// a URL that already carries a query string (`https://api.etherscan.io/v2/api?chainid=1&apikey=…`),
/// which is used as given. See [`query_base`].
pub fn set_custom(chain_id: u64, bases: Vec<String>) {
    let cleaned: Vec<String> = bases
        .into_iter()
        .map(|b| b.trim().trim_end_matches('/').to_string())
        .filter(|b| b.starts_with("http://") || b.starts_with("https://"))
        .collect();
    let mut map = CUSTOM.lock().unwrap_or_else(|e| e.into_inner());
    if cleaned.is_empty() {
        map.remove(&chain_id);
    } else {
        map.insert(chain_id, cleaned);
    }
}

/// Every explorer base to try for `chain_id`, best first: the user's, then the built-in ones, with
/// anything currently parked moved to the back rather than dropped - a stale park must never be the
/// reason history is missing when the base has since recovered.
pub fn bases(chain_id: u64) -> Vec<String> {
    let mut all: Vec<String> = CUSTOM
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&chain_id)
        .cloned()
        .unwrap_or_default();
    for b in crate::chains::chain_info(chain_id).explorers {
        if !all.iter().any(|x| x == b) {
            all.push((*b).to_string());
        }
    }

    let now = now_ms();
    let health = HEALTH.lock().unwrap_or_else(|e| e.into_inner());
    let (ready, parked): (Vec<String>, Vec<String>) = all
        .into_iter()
        .partition(|b| health.get(b).map(|h| h.parked_until <= now).unwrap_or(true));
    drop(health);

    let mut out = ready;
    out.extend(parked);
    out
}

/// Note that `base` would not answer, so the rest of this run goes elsewhere.
pub fn park(base: &str) {
    let mut health = HEALTH.lock().unwrap_or_else(|e| e.into_inner());
    let entry = health.entry(base.to_string()).or_default();
    entry.strikes = entry.strikes.saturating_add(1);
    let backoff = PARK_BASE_MS
        .saturating_mul(1u64 << entry.strikes.min(4))
        .min(PARK_MAX_MS);
    entry.parked_until = now_ms() + backoff;
}

/// Note that `base` answered, clearing any record against it.
pub fn mark_healthy(base: &str) {
    let mut health = HEALTH.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = health.get_mut(base) {
        entry.strikes = 0;
        entry.parked_until = 0;
    }
}

/// Turn an explorer base into the start of a query, ready for `&action=…` to be appended.
///
/// A base that already has a query string is left alone apart from the module parameter, which is
/// what lets a user paste an Etherscan V2 URL with their own key on it and have it work exactly like
/// a keyless Blockscout host.
pub fn query_base(base: &str) -> String {
    if base.contains('?') {
        format!("{base}&module=account")
    } else {
        format!("{base}/api?module=account")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_custom_base_is_tried_before_the_built_in_ones() {
        set_custom(1, vec!["https://my.explorer.example/".into()]);
        let list = bases(1);
        assert_eq!(list[0], "https://my.explorer.example");
        assert!(list.iter().any(|b| b == "https://eth.blockscout.com"));
        set_custom(1, Vec::new());
        assert_eq!(bases(1)[0], "https://eth.blockscout.com");
    }

    #[test]
    fn junk_is_not_accepted_as_a_base() {
        set_custom(10, vec!["not a url".into(), "ftp://nope".into(), "".into()]);
        assert!(!bases(10).iter().any(|b| b.contains("nope")));
        set_custom(10, Vec::new());
    }

    #[test]
    fn a_parked_base_moves_to_the_back_but_is_still_offered() {
        let first = bases(100)[0].clone();
        park(&first);
        let after = bases(100);
        assert_ne!(after[0], first, "a parked base should not lead");
        assert!(after.contains(&first), "a parked base must still be a last resort");
        mark_healthy(&first);
        assert_eq!(bases(100)[0], first);
    }

    #[test]
    fn a_key_carrying_url_keeps_its_query_string() {
        assert_eq!(
            query_base("https://api.etherscan.io/v2/api?chainid=8453&apikey=ABC"),
            "https://api.etherscan.io/v2/api?chainid=8453&apikey=ABC&module=account"
        );
        assert_eq!(
            query_base("https://eth.blockscout.com"),
            "https://eth.blockscout.com/api?module=account"
        );
    }
}
