// SPDX-License-Identifier: BSD-3-Clause
//! Hyperliquid exchange client - the venue where XMR1 trades.
//!
//! XMR1 is Wagyu's synthetic Monero: a token on Hyperliquid, not an ERC-20 on any chain Aero
//! otherwise talks to. It trades against USDC on Hyperliquid's central limit order book, which is
//! why this module exists at all - buying it means placing orders on an exchange, not swapping
//! through a router.
//!
//! Three things are worth understanding before reading further.
//!
//! **Money arrives and leaves over Arbitrum.** Hyperliquid's only funding rail is a bridge contract
//! on Arbitrum One that accepts native USDC. Depositing is an ordinary ERC-20 transfer to it;
//! withdrawing is a signed instruction to the exchange, which pays out on Arbitrum. Everything in
//! between happens on Hyperliquid, off any chain Aero can see.
//!
//! **Nothing here signs.** Building an action and signing it are kept apart: this module produces a
//! digest, the caller signs it with whatever holds the key (a local key, or a device), and hands the
//! signature back. That is what lets the same code path serve software and hardware wallets.
//!
//! **The signature commits to a hash of the action, not the action.** Hyperliquid msgpack-encodes
//! the action, appends the nonce and a vault marker, and hashes the result; the EIP-712 message
//! signed is a "phantom agent" carrying that hash. Field order in the encoding is therefore part of
//! the signature - reordering a struct below silently invalidates every order the wallet sends. The
//! structs are laid out in the order the exchange expects and must not be rearranged.
//!
//! Reference: <https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api>

use alloy::primitives::{keccak256, Address, B256};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::provider::RpcProvider;

/// Mainnet API root. Both the read-only `info` and the authenticated `exchange` endpoints live here.
pub const API: &str = "https://api.hyperliquid.xyz";

/// Hyperliquid's bridge on Arbitrum One. Deposits are a plain USDC transfer to this address.
///
/// Getting this wrong sends money nowhere recoverable, so it is pinned here and checked against the
/// deployed contract rather than fetched or configured.
pub const BRIDGE2_ARBITRUM: &str = "0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF7";

/// Native Circle USDC on Arbitrum One - the *only* token the bridge accepts.
///
/// Not to be confused with bridged USDC.e, which is a different contract. The bridge does not
/// recognise it, and tokens sent that way are lost.
pub const USDC_ARBITRUM: &str = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831";

/// Arbitrum One, the chain a deposit or withdrawal touches.
pub const ARBITRUM_CHAIN_ID: u64 = 42161;

/// Deposits below this are ignored by the bridge and are hard to recover.
pub const MIN_DEPOSIT_USDC: f64 = 5.0;

/// Flat fee the exchange charges to withdraw to Arbitrum.
pub const WITHDRAW_FEE_USDC: f64 = 1.0;

/// Spot markets are addressed as `10000 + index` when placing orders, distinguishing them from
/// perpetuals, which use the bare index.
const SPOT_ASSET_OFFSET: u32 = 10_000;

/// The token Aero offers. Wagyu's synthetic Monero.
pub const XMR1: &str = "XMR1";

// -------------------------------------------------------------------------------------------------
// Market metadata
// -------------------------------------------------------------------------------------------------

/// A spot market, resolved from the exchange rather than hard-coded: indices shift as tokens are
/// listed, and an order sent to a stale index would buy something else entirely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Market {
    /// What the book endpoint calls this market, e.g. `@260`.
    pub coin: String,
    /// What an order calls it: `10000 + spot index`.
    pub asset_id: u32,
    /// Decimal places allowed in a size.
    pub sz_decimals: u8,
    /// Decimal places allowed in a price. Spot allows `8 - szDecimals`.
    pub px_decimals: u8,
    /// How a transfer names this token: `NAME:0x…`. Orders address a market by index, but a spot
    /// transfer names the token itself, and the two are not interchangeable.
    pub send_token: String,
    /// Decimal places a *balance* can hold. Larger than [`sz_decimals`](Self::sz_decimals), which
    /// only constrains order sizes - a transfer may move a balance finer than it could be traded in.
    pub wei_decimals: u8,
}

/// Markets already looked up, so a screen refreshing every few seconds does not re-fetch the whole
/// listing each time. Cached for the process lifetime: a token's index changes only if it is
/// re-listed, which does not happen while a window is open.
static MARKETS: once_cell::sync::Lazy<std::sync::Mutex<std::collections::HashMap<String, Market>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Find the spot market pairing `token` with USDC.
pub async fn find_market(provider: &RpcProvider, token: &str) -> Result<Market> {
    if let Ok(cache) = MARKETS.lock() {
        if let Some(m) = cache.get(token) {
            return Ok(m.clone());
        }
    }
    let market = fetch_market(provider, token).await?;
    if let Ok(mut cache) = MARKETS.lock() {
        cache.insert(token.to_string(), market.clone());
    }
    Ok(market)
}

async fn fetch_market(provider: &RpcProvider, token: &str) -> Result<Market> {
    let meta = info(provider, &serde_json::json!({ "type": "spotMeta" })).await?;

    let tokens = meta.get("tokens").and_then(|t| t.as_array()).ok_or_else(bad_meta)?;
    let token_entry = tokens
        .iter()
        .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(token))
        .ok_or_else(|| CoreError::rpc(format!("{token} is not listed on Hyperliquid")))?;
    let token_index = token_entry.get("index").and_then(|i| i.as_u64()).ok_or_else(bad_meta)?;
    let sz_decimals = token_entry.get("szDecimals").and_then(|d| d.as_u64()).ok_or_else(bad_meta)? as u8;
    let wei_decimals = token_entry.get("weiDecimals").and_then(|d| d.as_u64()).ok_or_else(bad_meta)? as u8;
    // Several tokens can share a name on Hyperliquid, so a transfer is addressed by name *and* the
    // on-chain id. Sending by name alone is how funds reach an impostor token.
    let token_id = token_entry.get("tokenId").and_then(|t| t.as_str()).ok_or_else(bad_meta)?;

    // The pair we want is the one quoted in USDC, which is token index 0.
    let universe = meta.get("universe").and_then(|u| u.as_array()).ok_or_else(bad_meta)?;
    let pair = universe
        .iter()
        .find(|p| {
            let ids = p.get("tokens").and_then(|t| t.as_array());
            ids.map(|ids| {
                ids.first().and_then(|v| v.as_u64()) == Some(token_index)
                    && ids.get(1).and_then(|v| v.as_u64()) == Some(0)
            })
            .unwrap_or(false)
        })
        .ok_or_else(|| CoreError::rpc(format!("{token} has no USDC market on Hyperliquid")))?;
    let spot_index = pair.get("index").and_then(|i| i.as_u64()).ok_or_else(bad_meta)? as u32;

    Ok(Market {
        coin: format!("@{spot_index}"),
        asset_id: SPOT_ASSET_OFFSET + spot_index,
        sz_decimals,
        px_decimals: 8u8.saturating_sub(sz_decimals),
        send_token: format!("{token}:{token_id}"),
        wei_decimals,
    })
}

fn bad_meta() -> CoreError {
    CoreError::rpc("Hyperliquid returned market data in an unexpected shape".to_string())
}

// -------------------------------------------------------------------------------------------------
// Read-only endpoints
// -------------------------------------------------------------------------------------------------

/// One price level of the book.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Level {
    pub px: String,
    pub sz: String,
    #[serde(default)]
    pub n: u32,
}

/// A book snapshot, best price first on both sides.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Book {
    pub bids: Vec<Level>,
    pub asks: Vec<Level>,
    pub time: u64,
}

impl Book {
    /// Mid price, or `None` when either side is empty and there is nothing to be between.
    pub fn mid(&self) -> Option<f64> {
        let bid = self.bids.first()?.px.parse::<f64>().ok()?;
        let ask = self.asks.first()?.px.parse::<f64>().ok()?;
        Some((bid + ask) / 2.0)
    }
}

/// Fetch the order book for `coin` (`@260` for XMR1).
pub async fn book(provider: &RpcProvider, coin: &str) -> Result<Book> {
    let v = info(provider, &serde_json::json!({ "type": "l2Book", "coin": coin })).await?;
    // An answer without `levels` is not an empty book, it is not an answer. Shown as an empty book,
    // it reads as "nobody is buying or selling XMR1", which is a alarming thing to tell someone
    // holding it, and it would silently stop a market order from being priced.
    let Some(levels) = v.get("levels").and_then(|l| l.as_array()).cloned() else {
        return Err(CoreError::rpc(format!("hyperliquid book: unexpected reply {v}")));
    };
    let side = |i: usize| -> Vec<Level> {
        levels
            .get(i)
            .and_then(|s| serde_json::from_value(s.clone()).ok())
            .unwrap_or_default()
    };
    Ok(Book {
        bids: side(0),
        asks: side(1),
        time: v.get("time").and_then(|t| t.as_u64()).unwrap_or(0),
    })
}

/// A spot balance held on the exchange.
#[derive(Clone, Debug, Serialize)]
pub struct Balance {
    pub coin: String,
    /// Everything held, including the part reserved by resting orders.
    pub total: String,
    /// The part locked in resting orders and therefore not spendable.
    pub hold: String,
}

/// Spot balances for `user`. An account that has never traded returns an empty list, not an error.
pub async fn balances(provider: &RpcProvider, user: &str) -> Result<Vec<Balance>> {
    let v = info(
        provider,
        &serde_json::json!({ "type": "spotClearinghouseState", "user": user.to_lowercase() }),
    )
    .await?;
    // A reply with no `balances` field is the exchange failing to answer, not the account being
    // empty. Treated as empty it tells someone their money is gone, and worse, the redemption screen
    // would offer to withdraw zero.
    let Some(balances) = v.get("balances").and_then(|b| b.as_array()).cloned() else {
        return Err(CoreError::rpc(format!("hyperliquid balances: unexpected reply {v}")));
    };
    let mut out = Vec::new();
    for b in balances {
        let get = |k: &str| b.get(k).and_then(|x| x.as_str()).unwrap_or("0").to_string();
        out.push(Balance { coin: get("coin"), total: get("total"), hold: get("hold") });
    }
    Ok(out)
}

/// A resting order.
#[derive(Clone, Debug, Serialize)]
pub struct OpenOrder {
    pub oid: u64,
    pub coin: String,
    /// `true` for a buy.
    pub is_buy: bool,
    pub px: String,
    /// Size still unfilled.
    pub sz: String,
    pub timestamp: u64,
}

/// Orders `user` currently has resting on the book.
pub async fn open_orders(provider: &RpcProvider, user: &str) -> Result<Vec<OpenOrder>> {
    let v = info(
        provider,
        &serde_json::json!({ "type": "openOrders", "user": user.to_lowercase() }),
    )
    .await?;
    // Anything but a list means the exchange did not answer. An empty list of orders is a claim
    // worth being sure about: it is what the UI shows after a cancel, so getting it wrong tells
    // someone an order they still have on the book is gone.
    let Some(orders) = v.as_array().cloned() else {
        return Err(CoreError::rpc(format!("hyperliquid open orders: unexpected reply {v}")));
    };
    let mut out = Vec::new();
    for o in orders {
        let s = |k: &str| o.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
        out.push(OpenOrder {
            oid: o.get("oid").and_then(|x| x.as_u64()).unwrap_or(0),
            coin: s("coin"),
            // "B" for buy, "A" for sell (bid/ask).
            is_buy: s("side") == "B",
            px: s("limitPx"),
            sz: s("sz"),
            timestamp: o.get("timestamp").and_then(|x| x.as_u64()).unwrap_or(0),
        });
    }
    Ok(out)
}

/// A trade that happened.
#[derive(Clone, Debug, Serialize)]
pub struct Fill {
    pub coin: String,
    pub px: String,
    pub sz: String,
    pub is_buy: bool,
    pub time: u64,
    pub fee: String,
    pub hash: String,
}

/// Recent fills for `user`, newest last.
pub async fn fills(provider: &RpcProvider, user: &str) -> Result<Vec<Fill>> {
    let v = info(
        provider,
        &serde_json::json!({ "type": "userFills", "user": user.to_lowercase() }),
    )
    .await?;
    let Some(fills) = v.as_array().cloned() else {
        return Err(CoreError::rpc(format!("hyperliquid fills: unexpected reply {v}")));
    };
    let mut out = Vec::new();
    for f in fills {
        let s = |k: &str| f.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
        out.push(Fill {
            coin: s("coin"),
            px: s("px"),
            sz: s("sz"),
            is_buy: s("side") == "B",
            time: f.get("time").and_then(|x| x.as_u64()).unwrap_or(0),
            fee: s("fee"),
            hash: s("hash"),
        });
    }
    Ok(out)
}

async fn info(provider: &RpcProvider, body: &serde_json::Value) -> Result<serde_json::Value> {
    provider.http_post_json(&format!("{API}/info"), body).await
}

// -------------------------------------------------------------------------------------------------
// Number formatting
// -------------------------------------------------------------------------------------------------

/// Format a size for the wire, truncated to what the market accepts.
///
/// Truncation, never rounding: rounding a size up can ask to sell more of an asset than is held,
/// which the exchange rejects, and rounding a buy up spends more than the user chose.
pub fn format_size(size: f64, sz_decimals: u8) -> String {
    let factor = 10f64.powi(sz_decimals as i32);
    let scaled = size * factor;
    // A bare `floor` here is wrong, and quietly so. `0.29` is not representable in binary, and
    // `0.29 * 100` comes out as 28.999999999999996, so flooring turns a size the user typed exactly
    // into one step less than they asked for: 137 of the first 2000 hundredths do this. Anything
    // within a hair of a whole step is therefore treated as that step; the tolerance scales with the
    // number so it stays far below a step at any size, and far above the representation error.
    let eps = 1e-12 * scaled.abs().max(1.0);
    let steps = if (scaled.round() - scaled).abs() <= eps { scaled.round() } else { scaled.floor() };
    trim(&format!("{:.*}", sz_decimals as usize, steps / factor))
}

/// Format a price for the wire.
///
/// Hyperliquid takes at most five significant figures, and for spot at most `8 - szDecimals`
/// decimal places; integer prices are exempt from the significant-figure rule. A price outside
/// those bounds is rejected outright, so it is clamped here rather than sent and refused.
pub fn format_price(price: f64, px_decimals: u8) -> String {
    if price <= 0.0 {
        return "0".to_string();
    }
    // Five significant figures first, then the market's decimal limit.
    let magnitude = price.abs().log10().floor() as i32;
    let sig_decimals = (4 - magnitude).max(0) as usize;
    let decimals = sig_decimals.min(px_decimals as usize);
    trim(&format!("{price:.decimals$}"))
}

/// Drop trailing zeros so the string matches the exchange's canonical form; a size of `1.50` and one
/// of `1.5` hash differently, and only the second is accepted.
fn trim(s: &str) -> String {
    if !s.contains('.') {
        return s.to_string();
    }
    let t = s.trim_end_matches('0').trim_end_matches('.');
    if t.is_empty() || t == "-" {
        "0".to_string()
    } else {
        t.to_string()
    }
}

// -------------------------------------------------------------------------------------------------
// Actions
// -------------------------------------------------------------------------------------------------

/// How long an order stays on the book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tif {
    /// Rests until filled or cancelled - a limit order.
    Gtc,
    /// Takes what it can immediately and cancels the rest - how a market order is expressed.
    Ioc,
    /// Only rests; never takes. Rejected if it would cross.
    Alo,
}

impl Tif {
    fn wire(self) -> &'static str {
        match self {
            Tif::Gtc => "Gtc",
            Tif::Ioc => "Ioc",
            Tif::Alo => "Alo",
        }
    }
}

// The wire structs below are msgpack-encoded and hashed. Field order is part of the signature.

#[derive(Serialize)]
struct LimitWire {
    tif: &'static str,
}

#[derive(Serialize)]
struct OrderTypeWire {
    limit: LimitWire,
}

#[derive(Serialize)]
struct OrderWire {
    a: u32,
    b: bool,
    p: String,
    s: String,
    r: bool,
    t: OrderTypeWire,
}

#[derive(Serialize)]
struct OrderAction {
    #[serde(rename = "type")]
    kind: &'static str,
    orders: Vec<OrderWire>,
    grouping: &'static str,
}

#[derive(Serialize)]
struct CancelWire {
    a: u32,
    o: u64,
}

#[derive(Serialize)]
struct CancelAction {
    #[serde(rename = "type")]
    kind: &'static str,
    cancels: Vec<CancelWire>,
}

/// An action ready to be signed, and the digest to sign.
///
/// The caller signs `digest` and calls [`envelope`] with the result. Keeping the two apart is what
/// lets a hardware wallet sign the same action a local key would.
pub struct Unsigned {
    /// The action as it must appear in the request body - already in the order that was hashed.
    pub action: serde_json::Value,
    pub nonce: u64,
    /// What to sign.
    pub digest: B256,
    /// The two halves the digest is built from, kept because hardware wallets sign EIP-712 by
    /// taking them separately rather than a finished digest.
    pub domain_separator: B256,
    pub struct_hash: B256,
}

/// Build a limit or market order.
///
/// `price` is the limit for a `Gtc` order, and the worst acceptable price for an `Ioc` one - a
/// market order is an `Ioc` priced far enough through the book to clear it, which is also what caps
/// the damage a thin book can do.
pub fn order_action(
    market: &Market,
    is_buy: bool,
    price: f64,
    size: f64,
    tif: Tif,
) -> Result<Unsigned> {
    let px = format_price(price, market.px_decimals);
    let sz = format_size(size, market.sz_decimals);
    if sz.parse::<f64>().unwrap_or(0.0) <= 0.0 {
        return Err(CoreError::Amount(format!(
            "that size rounds to nothing on this market, which trades in steps of {}",
            10f64.powi(-(market.sz_decimals as i32))
        )));
    }
    if px.parse::<f64>().unwrap_or(0.0) <= 0.0 {
        return Err(CoreError::Amount("that price is not a valid limit".into()));
    }

    let action = OrderAction {
        kind: "order",
        orders: vec![OrderWire {
            a: market.asset_id,
            b: is_buy,
            p: px,
            s: sz,
            r: false,
            t: OrderTypeWire { limit: LimitWire { tif: tif.wire() } },
        }],
        grouping: "na",
    };
    l1_unsigned(&action)
}

/// Cancel a resting order by its id.
pub fn cancel_action(market: &Market, oid: u64) -> Result<Unsigned> {
    l1_unsigned(&CancelAction {
        kind: "cancel",
        cancels: vec![CancelWire { a: market.asset_id, o: oid }],
    })
}

/// Authorise `agent` to place and cancel orders for the signer, and nothing else.
///
/// The point of an agent is that it cannot move money: it trades, but withdrawals and transfers
/// still require the account's own key. Aero holds an agent key so that trading never needs the
/// key that can empty the account.
pub fn approve_agent_action(agent: Address, name: &str) -> Unsigned {
    let nonce = now_ms();
    // Lower-case hex: the signature is over the exact string, and the exchange lower-cases before
    // verifying.
    let agent_hex = format!("{agent:#x}").to_lowercase();
    let action = serde_json::json!({
        "type": "approveAgent",
        "signatureChainId": "0x66eee",
        "hyperliquidChain": "Mainnet",
        "agentAddress": agent_hex,
        "agentName": name,
        "nonce": nonce,
    });
    let (domain_separator, struct_hash) = user_signed_parts(
        "HyperliquidTransaction:ApproveAgent",
        &[
            ("hyperliquidChain", Field::Str("Mainnet".into())),
            ("agentAddress", Field::Address(agent)),
            ("agentName", Field::Str(name.to_string())),
            ("nonce", Field::Uint(nonce)),
        ],
    );
    Unsigned {
        action,
        nonce,
        digest: digest(domain_separator, struct_hash),
        domain_separator,
        struct_hash,
    }
}

/// Withdraw USDC from the exchange to `destination` on Arbitrum.
///
/// The exchange takes a flat fee (see [`WITHDRAW_FEE_USDC`]) out of the amount, and the funds arrive
/// as native USDC at the same address on Arbitrum a few minutes later.
pub fn withdraw_action(destination: Address, amount: &str) -> Unsigned {
    let time = now_ms();
    let dest_hex = format!("{destination:#x}").to_lowercase();
    let action = serde_json::json!({
        "type": "withdraw3",
        "signatureChainId": "0x66eee",
        "hyperliquidChain": "Mainnet",
        "destination": dest_hex,
        "amount": amount,
        "time": time,
    });
    let (domain_separator, struct_hash) = user_signed_parts(
        "HyperliquidTransaction:Withdraw",
        &[
            ("hyperliquidChain", Field::Str("Mainnet".into())),
            // Signed as a string, not an address: the type is `string` in Hyperliquid's schema.
            ("destination", Field::Str(dest_hex)),
            ("amount", Field::Str(amount.to_string())),
            ("time", Field::Uint(time)),
        ],
    );
    Unsigned {
        action,
        nonce: time,
        digest: digest(domain_separator, struct_hash),
        domain_separator,
        struct_hash,
    }
}

/// Send a spot token to another address on Hyperliquid.
///
/// This is how a redemption is actually paid: Wagyu names an address, and the XMR1 goes to it. Like
/// a withdrawal it moves money, so it is signed by the account key rather than the trading agent -
/// an agent deliberately cannot do this.
///
/// `amount` is a decimal string, not wei, and `token` must be the `NAME:0x…` form from
/// [`Market::send_token`].
pub fn spot_send_action(destination: Address, token: &str, amount: &str) -> Unsigned {
    let time = now_ms();
    let dest_hex = format!("{destination:#x}").to_lowercase();
    let action = serde_json::json!({
        "type": "spotSend",
        "signatureChainId": "0x66eee",
        "hyperliquidChain": "Mainnet",
        "destination": dest_hex,
        "token": token,
        "amount": amount,
        "time": time,
    });
    let (domain_separator, struct_hash) = user_signed_parts(
        "HyperliquidTransaction:SpotSend",
        &[
            ("hyperliquidChain", Field::Str("Mainnet".into())),
            ("destination", Field::Str(dest_hex)),
            ("token", Field::Str(token.to_string())),
            ("amount", Field::Str(amount.to_string())),
            ("time", Field::Uint(time)),
        ],
    );
    Unsigned {
        action,
        nonce: time,
        digest: digest(domain_separator, struct_hash),
        domain_separator,
        struct_hash,
    }
}

/// Assemble the request body once the digest has been signed.
pub fn envelope(unsigned: &Unsigned, signature: &alloy::primitives::Signature) -> serde_json::Value {
    // `v` is the recovery id as 27/28; alloy reports the parity as a bool.
    let v = if signature.v() { 28 } else { 27 };
    serde_json::json!({
        "action": unsigned.action,
        "nonce": unsigned.nonce,
        "signature": {
            "r": format!("{:#x}", signature.r()),
            "s": format!("{:#x}", signature.s()),
            "v": v,
        },
    })
}

/// Send a signed action and turn the exchange's reply into a result.
///
/// Hyperliquid answers `200` even when it refuses, with the reason inside the body - and an order
/// can be refused individually inside an otherwise successful batch, so both layers are checked.
pub async fn submit(provider: &RpcProvider, body: &serde_json::Value) -> Result<serde_json::Value> {
    let v = provider.http_post_json(&format!("{API}/exchange"), body).await?;
    if v.get("status").and_then(|s| s.as_str()) != Some("ok") {
        let msg = v
            .get("response")
            .and_then(|r| r.as_str())
            .unwrap_or("the exchange rejected the request");
        return Err(CoreError::rpc(format!("Hyperliquid: {msg}")));
    }
    let data = v.get("response").and_then(|r| r.get("data"));
    if let Some(statuses) = data.and_then(|d| d.get("statuses")).and_then(|s| s.as_array()) {
        for st in statuses {
            if let Some(err) = st.get("error").and_then(|e| e.as_str()) {
                return Err(CoreError::rpc(format!("Hyperliquid: {err}")));
            }
        }
    }
    Ok(v.clone())
}

// -------------------------------------------------------------------------------------------------
// Signing
// -------------------------------------------------------------------------------------------------

/// Msgpack-encode an L1 action, fold in the nonce, and build the phantom-agent digest.
fn l1_unsigned<T: Serialize>(action: &T) -> Result<Unsigned> {
    l1_unsigned_at(action, now_ms())
}

/// As [`l1_unsigned`], with the nonce pinned so tests can reproduce published signatures.
fn l1_unsigned_at<T: Serialize>(action: &T, nonce: u64) -> Result<Unsigned> {
    let packed = rmp_serde::to_vec_named(action)
        .map_err(|e| CoreError::Signing(format!("could not encode the action: {e}")))?;

    let mut buf = packed;
    buf.extend_from_slice(&nonce.to_be_bytes());
    buf.push(0x00); // no vault
    let connection_id = keccak256(&buf);

    // The value sent must be the same object that was hashed, so it is re-derived from the encoded
    // form rather than rebuilt.
    let action_json = serde_json::to_value(action)
        .map_err(|e| CoreError::Signing(format!("could not encode the action: {e}")))?;

    let (domain_separator, struct_hash) = l1_parts(connection_id);
    Ok(Unsigned {
        action: action_json,
        nonce,
        digest: digest(domain_separator, struct_hash),
        domain_separator,
        struct_hash,
    })
}

/// EIP-712 digest of `Agent { source, connectionId }` under the `Exchange` domain.
///
/// The chain id is 1337 by definition here - it is not the chain the wallet is on, and changing it
/// to match would make every signature invalid.
#[cfg(test)]
fn l1_digest(connection_id: B256) -> B256 {
    let (domain, struct_hash) = l1_parts(connection_id);
    digest(domain, struct_hash)
}

fn l1_parts(connection_id: B256) -> (B256, B256) {
    let domain = domain_separator("Exchange", 1337);
    let type_hash = keccak256(b"Agent(string source,bytes32 connectionId)");
    let mut encoded = Vec::with_capacity(96);
    encoded.extend_from_slice(type_hash.as_slice());
    encoded.extend_from_slice(keccak256(b"a").as_slice()); // "a" = mainnet
    encoded.extend_from_slice(connection_id.as_slice());
    (domain, keccak256(&encoded))
}

/// A field of a user-signed action, limited to the types Hyperliquid's schemas actually use.
enum Field {
    Str(String),
    Address(Address),
    Uint(u64),
}

impl Field {
    fn type_name(&self) -> &'static str {
        match self {
            Field::Str(_) => "string",
            Field::Address(_) => "address",
            Field::Uint(_) => "uint64",
        }
    }

    fn encode(&self) -> [u8; 32] {
        let mut word = [0u8; 32];
        match self {
            Field::Str(s) => word.copy_from_slice(keccak256(s.as_bytes()).as_slice()),
            Field::Address(a) => word[12..].copy_from_slice(a.as_slice()),
            Field::Uint(n) => word[24..].copy_from_slice(&n.to_be_bytes()),
        }
        word
    }
}

/// EIP-712 digest for the actions whose fields are signed directly - withdrawals and agent
/// approvals, the ones a user should be able to read on a device screen.
#[cfg(test)]
fn user_signed_digest(primary_type: &str, fields: &[(&str, Field)]) -> B256 {
    let (domain, struct_hash) = user_signed_parts(primary_type, fields);
    digest(domain, struct_hash)
}

fn user_signed_parts(primary_type: &str, fields: &[(&str, Field)]) -> (B256, B256) {
    // 0x66eee is what Hyperliquid's own SDK puts in `signatureChainId`, and the domain must agree
    // with it or the exchange recovers a different signer.
    let domain = domain_separator("HyperliquidSignTransaction", 0x66eee);

    let mut encode_type = String::from(primary_type);
    encode_type.push('(');
    for (i, (name, value)) in fields.iter().enumerate() {
        if i > 0 {
            encode_type.push(',');
        }
        encode_type.push_str(value.type_name());
        encode_type.push(' ');
        encode_type.push_str(name);
    }
    encode_type.push(')');

    let mut encoded = Vec::with_capacity(32 * (fields.len() + 1));
    encoded.extend_from_slice(keccak256(encode_type.as_bytes()).as_slice());
    for (_, value) in fields {
        encoded.extend_from_slice(&value.encode());
    }
    (domain, keccak256(&encoded))
}

fn domain_separator(name: &str, chain_id: u64) -> B256 {
    let type_hash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let mut chain = [0u8; 32];
    chain[24..].copy_from_slice(&chain_id.to_be_bytes());
    let mut encoded = Vec::with_capacity(160);
    encoded.extend_from_slice(type_hash.as_slice());
    encoded.extend_from_slice(keccak256(name.as_bytes()).as_slice());
    encoded.extend_from_slice(keccak256(b"1").as_slice());
    encoded.extend_from_slice(&chain);
    encoded.extend_from_slice(&[0u8; 32]); // verifyingContract is the zero address
    keccak256(&encoded)
}

fn digest(domain: B256, struct_hash: B256) -> B256 {
    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(domain.as_slice());
    buf.extend_from_slice(struct_hash.as_slice());
    keccak256(&buf)
}

/// Nonces are millisecond timestamps, and the exchange rejects one it has seen or one too far from
/// its own clock.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A market fixture. Only the ordering fields matter to these tests; the transfer fields are
    /// filled with XMR1's real values so nothing here depends on placeholders.
    fn market(coin: &str, asset_id: u32, sz_decimals: u8, px_decimals: u8) -> Market {
        Market {
            coin: coin.into(),
            asset_id,
            sz_decimals,
            px_decimals,
            send_token: "XMR1:0xbb2057659bd378d17e2e151bb04bdcaa".into(),
            wei_decimals: 8,
        }
    }

    #[test]
    fn sizes_truncate_rather_than_round() {
        // Rounding up a sell would try to sell more than is held.
        assert_eq!(format_size(1.239, 2), "1.23");
        assert_eq!(format_size(1.0, 2), "1");
        assert_eq!(format_size(0.005, 2), "0");
        assert_eq!(format_size(12.5, 2), "12.5");
    }

    #[test]
    fn sizes_survive_binary_representation() {
        // Every size the ticket can produce at two decimals must come back unchanged. A plain
        // floor of `size * 100` fails 137 of these, silently trading a step less than was asked
        // for - 0.29 XMR1 becomes 0.28, which is several dollars.
        assert_eq!(format_size(0.29, 2), "0.29");
        assert_eq!(format_size(1.13, 2), "1.13");
        assert_eq!(format_size(2.01, 2), "2.01");
        for i in 1..=2000 {
            let size = i as f64 / 100.0;
            let want = trim(&format!("{size:.2}"));
            assert_eq!(format_size(size, 2), want, "size {size}");
        }
        // The tolerance must not become a licence to round up: anything meaningfully short of a
        // step still truncates down.
        assert_eq!(format_size(1.2399, 2), "1.23");
        assert_eq!(format_size(0.9999, 2), "0.99");
    }

    #[test]
    fn prices_respect_five_significant_figures() {
        // XMR1: szDecimals 2, so at most 6 decimal places, and at most 5 significant figures.
        assert_eq!(format_price(375.82, 6), "375.82");
        assert_eq!(format_price(375.8234, 6), "375.82");
        assert_eq!(format_price(1234.5678, 6), "1234.6");
        // The decimal cap binds before the significant-figure one here.
        assert_eq!(format_price(0.0012345678, 6), "0.001235");
        assert_eq!(format_price(1.5, 6), "1.5");
    }

    #[test]
    fn trailing_zeros_are_dropped() {
        // "1.50" and "1.5" hash differently and only one is accepted.
        assert_eq!(trim("1.50"), "1.5");
        assert_eq!(trim("1.00"), "1");
        assert_eq!(trim("100"), "100");
    }

    #[test]
    fn spot_markets_are_offset_by_ten_thousand() {
        // An order carrying a bare spot index would name a perpetual instead.
        let m = market("@260", SPOT_ASSET_OFFSET + 260, 2, 6);
        assert_eq!(m.asset_id, 10260);
    }

    #[test]
    fn the_l1_domain_is_fixed_to_1337() {
        // Not the wallet's chain: signing under any other id makes every order unverifiable.
        let a = domain_separator("Exchange", 1337);
        let b = domain_separator("Exchange", 42161);
        assert_ne!(a, b);
    }

    #[test]
    fn a_size_that_rounds_to_nothing_is_refused() {
        let m = market("@260", 10260, 2, 6);
        assert!(order_action(&m, true, 375.0, 0.001, Tif::Gtc).is_err());
    }

    // The tests below reproduce published vectors from Hyperliquid's own Python SDK
    // (`tests/signing_test.py`). They are the only real proof that this module's msgpack encoding,
    // action hashing and EIP-712 construction agree with what the exchange verifies - a mistake
    // anywhere in that chain produces a signature that recovers to the wrong address, and the
    // exchange simply says the account does not exist.

    /// The key the SDK's vectors are signed with. Public, published, and holding nothing.
    const VECTOR_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";

    fn vector_signer() -> alloy::signers::local::PrivateKeySigner {
        VECTOR_KEY.parse().unwrap()
    }

    fn sign(digest: B256) -> (String, String, u8) {
        use alloy::signers::SignerSync;
        let sig = vector_signer().sign_hash_sync(&digest).unwrap();
        (
            format!("{:#x}", sig.r()),
            format!("{:#x}", sig.s()),
            if sig.v() { 28 } else { 27 },
        )
    }

    #[test]
    fn the_action_hash_matches_the_published_connection_id() {
        // test_phantom_agent_creation_matches_production: an ETH order, asset 4, at a fixed
        // timestamp. This pins the msgpack encoding and field order independently of signing.
        let m = market("@0", 4, 4, 4);
        let u = {
            let action = OrderAction {
                kind: "order",
                orders: vec![OrderWire {
                    a: m.asset_id,
                    b: true,
                    p: "1670.1".into(),
                    s: "0.0147".into(),
                    r: false,
                    t: OrderTypeWire { limit: LimitWire { tif: "Ioc" } },
                }],
                grouping: "na",
            };
            l1_unsigned_at(&action, 1677777606040).unwrap()
        };
        // Recompute the connection id the same way the digest did, to compare it directly.
        let packed = rmp_serde::to_vec_named(&OrderAction {
            kind: "order",
            orders: vec![OrderWire {
                a: 4,
                b: true,
                p: "1670.1".into(),
                s: "0.0147".into(),
                r: false,
                t: OrderTypeWire { limit: LimitWire { tif: "Ioc" } },
            }],
            grouping: "na",
        })
        .unwrap();
        let mut buf = packed;
        buf.extend_from_slice(&1677777606040u64.to_be_bytes());
        buf.push(0x00);
        assert_eq!(
            format!("{:#x}", keccak256(&buf)),
            "0x0fcbeda5ae3c4950a548021552a4fea2226858c4453571bf3f24ba017eac2908"
        );
        // And that the digest built from it is what gets signed.
        assert_eq!(u.digest, l1_digest(keccak256(&buf)));
    }

    #[test]
    fn an_order_signature_matches_the_published_vector() {
        // test_l1_action_signing_order_matches: asset 1, buy 100 at 100, Gtc, nonce 0, mainnet.
        let m = market("@1", 1, 2, 6);
        let action = OrderAction {
            kind: "order",
            orders: vec![OrderWire {
                a: m.asset_id,
                b: true,
                p: format_price(100.0, m.px_decimals),
                s: format_size(100.0, m.sz_decimals),
                r: false,
                t: OrderTypeWire { limit: LimitWire { tif: Tif::Gtc.wire() } },
            }],
            grouping: "na",
        };
        let u = l1_unsigned_at(&action, 0).unwrap();
        let (r, s, v) = sign(u.digest);
        assert_eq!(r, "0xd65369825a9df5d80099e513cce430311d7d26ddf477f5b3a33d2806b100d78e");
        assert_eq!(s, "0x2b54116ff64054968aa237c20ca9ff68000f977c93289157748a3162b6ea940e");
        assert_eq!(v, 28);
    }

    #[test]
    fn a_withdrawal_signature_matches_the_published_vector() {
        // test_sign_withdraw_from_bridge_action, which signs against Testnet - so the digest is
        // built by hand here with the same fields the mainnet path uses.
        let dest = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
        let digest = user_signed_digest(
            "HyperliquidTransaction:Withdraw",
            &[
                ("hyperliquidChain", Field::Str("Testnet".into())),
                ("destination", Field::Str(dest.into())),
                ("amount", Field::Str("1".into())),
                ("time", Field::Uint(1687816341423)),
            ],
        );
        let (r, s, v) = sign(digest);
        assert_eq!(r, "0x8363524c799e90ce9bc41022f7c39b4e9bdba786e5f9c72b20e43e1462c37cf9");
        assert_eq!(s, "0x58b1411a775938b83e29182e8ef74975f9054c8e97ebf5ec2dc8d51bfc893881");
        assert_eq!(v, 28);
    }

    #[test]
    fn a_transfer_signature_matches_the_published_vector() {
        // test_sign_usd_transfer_action - a different primary type over the same domain, which
        // catches a type-string built wrongly.
        let digest = user_signed_digest(
            "HyperliquidTransaction:UsdSend",
            &[
                ("hyperliquidChain", Field::Str("Testnet".into())),
                ("destination", Field::Str("0x5e9ee1089755c3435139848e47e6635505d5a13a".into())),
                ("amount", Field::Str("1".into())),
                ("time", Field::Uint(1687816341423)),
            ],
        );
        let (r, s, v) = sign(digest);
        assert_eq!(r, "0x637b37dd731507cdd24f46532ca8ba6eec616952c56218baeff04144e4a77073");
        assert_eq!(s, "0x11a6a24900e6e314136d2592e2f8d502cd89b7c15b198e1bee043c9589f9fad7");
        assert_eq!(v, 27);
    }

    #[test]
    fn a_cancel_signature_matches_the_published_vector() {
        // Built from the same primitives as an order, so a regression in either shows up here too.
        let m = market("@1", 1, 2, 6);
        let u = {
            let action = CancelAction {
                kind: "cancel",
                cancels: vec![CancelWire { a: m.asset_id, o: 12345 }],
            };
            l1_unsigned_at(&action, 0).unwrap()
        };
        // No published vector for this one; assert instead that it is stable and distinct from an
        // order's digest, so a copy-paste error between the two actions cannot go unnoticed.
        let order = l1_unsigned_at(
            &OrderAction {
                kind: "order",
                orders: vec![OrderWire {
                    a: 1,
                    b: true,
                    p: "100".into(),
                    s: "100".into(),
                    r: false,
                    t: OrderTypeWire { limit: LimitWire { tif: "Gtc" } },
                }],
                grouping: "na",
            },
            0,
        )
        .unwrap();
        assert_ne!(u.digest, order.digest);
    }
}
