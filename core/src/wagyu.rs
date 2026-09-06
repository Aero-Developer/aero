// SPDX-License-Identifier: BSD-3-Clause
//! Wagyu's bridge - the only way XMR1 turns back into actual Monero.
//!
//! Buying XMR1 on Hyperliquid gets a claim; this is where the claim is presented. Wagyu holds the
//! Monero, takes a percentage, and pays out to a Monero address. That makes it the one part of the
//! whole flow with counterparty risk, and the part worth being pedantic about.
//!
//! The shape of a redemption is a durable order rather than a fixed deposit address:
//!
//! 1. Ask Wagyu for an order, naming the Monero address to be paid.
//! 2. It replies with a **freshly generated** Hyperliquid address, an order id, and a session token.
//! 3. Send XMR1 to that address on Hyperliquid. The amount is whatever arrives - the order does not
//!    fix one.
//! 4. Wagyu pays out the Monero, minus its fee.
//!
//! Two properties of that flow drive the code below. The deposit address is **per order** and must
//! never be cached or reused - two orders created seconds apart return different addresses, and
//! sending to a stale one is sending to an order that is no longer expecting it. And the order
//! **expires**, so a redemption left half-finished is not merely slow, it is a transfer into an
//! address whose order has lapsed.
//!
//! Amounts here are Monero atomic units (piconero, 1e12 per XMR), not decimals.
//!
//! Reference: <https://docs.wagyu.xyz/native-bridge>

use serde::Serialize;

use crate::error::{CoreError, Result};
use crate::provider::RpcProvider;

/// The documented v2 origin. The older `api.wagyu.xyz/v1` still answers but is not the current
/// contract.
const API: &str = "https://api-beta.wagyu.xyz/v2";

/// Piconero per XMR.
pub const ATOMIC_PER_XMR: u64 = 1_000_000_000_000;

/// What Wagyu will charge and accept right now.
///
/// Read per redemption rather than baked in as a constant: the fee is runtime configuration on
/// Wagyu's side, and it applies per-sender overrides, so a figure hardcoded today can quietly become
/// a lie about how much a user is about to lose.
#[derive(Clone, Debug)]
pub struct Terms {
    /// Fraction taken on redeeming XMR1 for XMR, e.g. `0.02` for 2%.
    pub withdrawal_fee_rate: f64,
    /// Smallest redemption Wagyu accepts, in atomic units.
    pub minimum_atomic: u64,
}

impl Terms {
    /// Atomic units actually paid out for `gross`, after the fee.
    pub fn net_atomic(&self, gross: u64) -> u64 {
        let fee = (gross as f64 * self.withdrawal_fee_rate).ceil() as u64;
        gross.saturating_sub(fee)
    }
}

/// Current fees and minimums.
pub async fn terms(provider: &RpcProvider) -> Result<Terms> {
    let v = provider.http_get_json(&format!("{API}/bridges/terms")).await?;
    let rate = v
        .get("fees")
        .and_then(|f| f.get("withdrawalFeeRate"))
        .and_then(|r| r.as_f64())
        .ok_or_else(|| CoreError::rpc("Wagyu did not report its withdrawal fee".to_string()))?;
    let minimum = v
        .get("minimums")
        .and_then(|m| m.get("xmr"))
        .and_then(|x| x.as_f64())
        .ok_or_else(|| CoreError::rpc("Wagyu did not report its minimum".to_string()))?;
    // A fee far outside the published schedule means something changed that a user should be told
    // about rather than charged silently.
    if !(0.0..=0.10).contains(&rate) {
        return Err(CoreError::rpc(format!(
            "Wagyu is quoting an unexpected redemption fee of {:.1}% - not proceeding",
            rate * 100.0
        )));
    }
    Ok(Terms {
        withdrawal_fee_rate: rate,
        minimum_atomic: (minimum * ATOMIC_PER_XMR as f64).round() as u64,
    })
}

/// A redemption in progress.
#[derive(Clone, Debug, Serialize)]
pub struct Order {
    /// Wagyu's id, e.g. `wd_N3UXHR`.
    pub order_id: String,
    /// The credential that authorises reading this order. Sent in a header, never a URL.
    pub session_id: String,
    /// Where to send XMR1 on Hyperliquid. Generated for this order alone.
    pub deposit_address: String,
    /// When the order lapses, ISO-8601.
    pub expires_at: String,
    /// The Monero address that gets paid.
    pub destination: String,
}

#[derive(Serialize)]
struct CreateWithdraw<'a> {
    asset: &'a str,
    direction: &'a str,
    #[serde(rename = "toAddress")]
    to_address: &'a str,
}

/// Open a redemption paying out to `monero_address`.
///
/// Nothing is committed by this call - no XMR1 moves until the caller sends it to the address in the
/// reply. Note that Wagyu has no idempotency key on this endpoint, so a call that times out may
/// still have created an order; retrying blindly creates a second one.
pub async fn create_withdrawal(provider: &RpcProvider, monero_address: &str) -> Result<Order> {
    let address = monero_address.trim();
    validate_monero_address(address)?;

    let body = serde_json::to_value(CreateWithdraw {
        asset: "xmr",
        direction: "withdraw",
        to_address: address,
    })
    .map_err(|e| CoreError::rpc(format!("could not build the request: {e}")))?;

    let v = provider.http_post_json(&format!("{API}/bridges"), &body).await?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        return Err(CoreError::rpc(format!("Wagyu: {err}")));
    }
    let field = |k: &str| -> Result<String> {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::rpc(format!("Wagyu's reply had no {k}")))
    };

    let order = Order {
        order_id: field("orderId")?,
        session_id: field("sessionId")?,
        deposit_address: field("xmr1DepositAddress")?,
        expires_at: v
            .get("expiresAt")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
        destination: address.to_string(),
    };

    // Wagyu offers an opt-in gamble on the payout, where a *completed* order can pay nothing at all.
    // It defaults off; if a reply ever comes back with it on, stop rather than send funds into it.
    if v.get("coinflipRequested").and_then(|x| x.as_bool()).unwrap_or(false) {
        return Err(CoreError::rpc(
            "Wagyu opened this order with its coinflip option enabled, which can pay out nothing - \
             refusing to continue"
                .to_string(),
        ));
    }
    // Paying out to the wrong address is the one unrecoverable mistake here, so confirm Wagyu
    // recorded the destination we asked for instead of assuming.
    //
    // The request field is `toAddress` and the reply has been seen to echo it under either name, so
    // check whichever one came back. Looking for a single spelling meant a reply that used the other
    // skipped the check entirely and the XMR1 went out unchecked.
    let echoed = ["destination", "toAddress", "to_address", "destinationAddress"]
        .iter()
        .find_map(|k| v.get(*k).and_then(|x| x.as_str()));
    if let Some(dest) = echoed {
        if dest.trim() != address {
            return Err(CoreError::rpc(
                "Wagyu recorded a different payout address than the one given - not proceeding"
                    .to_string(),
            ));
        }
    }
    Ok(order)
}

/// Where a redemption has got to.
pub async fn order_status(
    provider: &RpcProvider,
    order_id: &str,
    session_id: &str,
) -> Result<serde_json::Value> {
    provider
        .http_get_json_with_headers(
            &format!("{API}/bridges/{order_id}"),
            &[("x-session-id", session_id)],
        )
        .await
}

/// Monero's Base58 alphabet. Not Bitcoin's: same 58 characters, but Monero encodes in fixed-size
/// blocks rather than as one big number.
const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// How many characters a block of 0..=8 bytes encodes to. A full 8-byte block is 11 characters; the
/// trailing partial block uses the shorter entries, and any other length is not valid Monero Base58.
const BLOCK_CHARS: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

/// Decode one Monero Base58 block onto `out`.
fn decode_block(chunk: &[u8], out: &mut Vec<u8>) -> Option<()> {
    let bytes = BLOCK_CHARS.iter().position(|&n| n == chunk.len())?;
    let mut num: u64 = 0;
    for c in chunk {
        let digit = B58.iter().position(|a| a == c)? as u64;
        num = num.checked_mul(58)?.checked_add(digit)?;
    }
    // A block that overflows the byte count it claims is not a block this encoder could produce.
    if bytes < 8 && num >= 1u64 << (8 * bytes) {
        return None;
    }
    out.extend_from_slice(&num.to_be_bytes()[8 - bytes..]);
    Some(())
}

/// Decode a whole Monero Base58 string, or `None` if it is not one.
fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() * 8 / 11 + 1);
    let full = b.len() / 11;
    for i in 0..full {
        decode_block(&b[i * 11..(i + 1) * 11], &mut out)?;
    }
    if b.len() % 11 != 0 {
        decode_block(&b[full * 11..], &mut out)?;
    }
    Some(out)
}

/// Reject anything that is not a valid Monero mainnet address before it reaches Wagyu.
///
/// This is the last check standing between a mistyped address and an irreversible payout, so it
/// verifies the address rather than merely eyeballing it: decode the Base58, check the network byte
/// says mainnet, and check the four-byte checksum Monero appends for exactly this purpose. The
/// checksum is what catches the realistic mistake, a character or two wrong in the middle of an
/// otherwise well-formed address, which every structural test in the world will happily wave
/// through.
///
/// Monero's checksum is the first four bytes of Keccak-256 over everything preceding it. That is the
/// original Keccak, the same one Ethereum uses, so `keccak256` here is the right function and not a
/// near-miss for SHA-3.
fn validate_monero_address(address: &str) -> Result<()> {
    // Standard addresses start with 4, subaddresses with 8; integrated addresses are longer.
    let plausible_prefix = address.starts_with('4') || address.starts_with('8');
    let plausible_length = matches!(address.len(), 95 | 106);
    if !plausible_prefix || !plausible_length {
        return Err(CoreError::Amount(
            "that does not look like a Monero address - they begin with 4 or 8 and are 95 \
             characters long (106 for an integrated address)"
                .to_string(),
        ));
    }
    if let Some(bad) = address.bytes().find(|c| !B58.contains(c)) {
        return Err(CoreError::Amount(format!(
            "that Monero address contains '{}', which cannot appear in one",
            bad as char
        )));
    }
    let raw = base58_decode(address).ok_or_else(|| {
        CoreError::Amount("that Monero address is not valid - check it and paste it again".to_string())
    })?;
    // network byte + spend key + view key + checksum, plus a payment id when integrated.
    if raw.len() < 5 {
        return Err(CoreError::Amount(
            "that Monero address is too short to be one".to_string(),
        ));
    }
    let (body, checksum) = raw.split_at(raw.len() - 4);
    if alloy::primitives::keccak256(body)[..4] != *checksum {
        return Err(CoreError::Amount(
            "that Monero address fails its own checksum, so at least one character is wrong. \
             Paste it again rather than retyping it - Monero payouts cannot be reversed."
                .to_string(),
        ));
    }
    // 18 standard, 19 integrated, 42 subaddress - all mainnet. Testnet and stagenet addresses look
    // identical to a human and would send the payout somewhere it can never be spent.
    match body.first() {
        Some(18) | Some(19) | Some(42) => Ok(()),
        _ => Err(CoreError::Amount(
            "that is not a Monero mainnet address - it looks like a testnet or stagenet one, and \
             a payout to it would be unspendable"
                .to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fee_is_taken_out_of_the_amount() {
        let t = Terms { withdrawal_fee_rate: 0.02, minimum_atomic: 10_000_000_000 };
        // Matches Wagyu's own quote: 1 XMR gross redeems to 0.98.
        assert_eq!(t.net_atomic(ATOMIC_PER_XMR), 980_000_000_000);
        assert_eq!(t.net_atomic(10_000_000_000), 9_800_000_000);
    }

    #[test]
    fn real_monero_addresses_are_accepted() {
        // Monero's published donation address (standard, 95 characters).
        assert!(validate_monero_address(
            "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H"
        )
        .is_ok());
    }

    #[test]
    fn addresses_that_cannot_be_monero_are_refused() {
        // An Ethereum address, which is the mistake a wallet user is most likely to make.
        assert!(validate_monero_address("0x5dFdC0fbF4e462e47B09adDa550D5b25cC2d8147").is_err());
        // Right shape, but contains characters Monero's Base58 alphabet excludes.
        let mut bad = "8".repeat(95);
        bad.replace_range(10..11, "0");
        assert!(validate_monero_address(&bad).is_err());
        // Truncated by a bad copy-paste.
        assert!(validate_monero_address("888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANs").is_err());
    }

    /// The mistake that actually costs someone their Monero: an address of exactly the right shape,
    /// in the right alphabet, with one character wrong. Nothing but the checksum catches this.
    #[test]
    fn a_single_wrong_character_is_caught() {
        const GOOD: &str =
            "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H";
        assert!(validate_monero_address(GOOD).is_ok());

        // Change one character at a time, right through the address, and require every single one
        // to be refused.
        for i in 1..GOOD.len() {
            let mut typo = GOOD.to_string();
            let orig = GOOD.as_bytes()[i];
            let swap = if orig == b'A' { b'B' } else { b'A' };
            typo.replace_range(i..i + 1, &(swap as char).to_string());
            assert!(
                validate_monero_address(&typo).is_err(),
                "a typo at position {i} was accepted: {typo}"
            );
        }
    }

    /// Two characters transposed - the other classic transcription error.
    #[test]
    fn transposed_characters_are_caught() {
        const GOOD: &str =
            "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H";
        let b = GOOD.as_bytes();
        let mut swapped = b.to_vec();
        swapped.swap(40, 41);
        assert_ne!(swapped, b.to_vec(), "pick a pair that actually differs");
        assert!(validate_monero_address(std::str::from_utf8(&swapped).unwrap()).is_err());
    }
}
