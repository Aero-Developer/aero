//! Live check that a signed order is accepted as *authentic* by Hyperliquid.
//!
//! Unit tests prove the signing matches published vectors offline. This proves the exchange agrees:
//! it signs a real order with a throwaway key that holds nothing, and reads the refusal. An account
//! with no balance is refused for lack of funds — but only *after* the signature has been checked
//! and the signer recovered, so a funds-related refusal means the signature verified. A malformed
//! signature is refused differently, before that point.
//!
//! Run with: cargo run --example hlcheck

use aero_core::hyperliquid;
use aero_core::provider::{ProviderConfig, RpcProvider};

#[tokio::main]
async fn main() {
    // Only the HTTP client is used here; the RPC endpoint is required to build a provider but is
    // never called, since Hyperliquid is not an EVM chain.
    let cfg = ProviderConfig {
        allow_clearnet: true,
        socks_proxy: None,
        chain_id: hyperliquid::ARBITRUM_CHAIN_ID,
        endpoints: vec!["https://arb1.arbitrum.io/rpc".to_string()],
        ..Default::default()
    };
    let provider = match RpcProvider::new(&cfg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("provider: {e}");
            return;
        }
    };

    let market = match hyperliquid::find_market(&provider, hyperliquid::XMR1).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("market lookup failed: {e}");
            return;
        }
    };
    println!(
        "market {} -> asset id {}, sizes to {} dp, prices to {} dp",
        market.coin, market.asset_id, market.sz_decimals, market.px_decimals
    );

    let book = hyperliquid::book(&provider, &market.coin).await.unwrap();
    println!(
        "best bid {} / best ask {}",
        book.bids.first().map(|l| l.px.as_str()).unwrap_or("-"),
        book.asks.first().map(|l| l.px.as_str()).unwrap_or("-")
    );

    // A throwaway key: published, empty, and only ever used to see how the exchange answers.
    let signer: alloy::signers::local::PrivateKeySigner =
        "0x0123456789012345678901234567890123456789012345678901234567890123".parse().unwrap();
    println!("signing as {}", signer.address());

    // Priced far below the market so it could never trade even if the account were funded.
    let unsigned = hyperliquid::order_action(&market, true, 1.0, 1.0, hyperliquid::Tif::Gtc).unwrap();
    println!("action: {}", serde_json::to_string(&unsigned.action).unwrap());

    use alloy::signers::SignerSync;
    let sig = signer.sign_hash_sync(&unsigned.digest).unwrap();
    let body = hyperliquid::envelope(&unsigned, &sig);

    match hyperliquid::submit(&provider, &body).await {
        Ok(v) => println!("accepted: {v}"),
        Err(e) => println!("refused: {e}"),
    }

    // The read paths, against an address that actually trades this market, so the shapes are
    // exercised with real data rather than empty lists.
    let active = "0x207700bd207df757825f9193ef9c648c1c65e06a";
    println!("\n--- read paths for {active} ---");
    match hyperliquid::balances(&provider, active).await {
        Ok(b) => println!("balances: {} entries, e.g. {:?}", b.len(), b.first()),
        Err(e) => println!("balances failed: {e}"),
    }
    match hyperliquid::open_orders(&provider, active).await {
        Ok(o) => println!("open orders: {}", o.len()),
        Err(e) => println!("open orders failed: {e}"),
    }
    match hyperliquid::fills(&provider, active).await {
        Ok(f) => println!("fills: {}", f.len()),
        Err(e) => println!("fills failed: {e}"),
    }

    // The agent lookup the wallet uses to decide whether trading is set up.
    let agents = provider
        .http_post_json(
            &format!("{}/info", hyperliquid::API),
            &serde_json::json!({ "type": "extraAgents", "user": active }),
        )
        .await;
    match agents {
        Ok(v) => println!("extraAgents: {v}"),
        Err(e) => println!("extraAgents failed: {e}"),
    }

    // The redemption path: Wagyu's side, then the transfer that pays it.
    println!("\n--- redemption ---");
    println!("transfers name the token as {}", market.send_token);

    match aero_core::wagyu::terms(&provider).await {
        Ok(t) => println!(
            "Wagyu takes {:.2}%, minimum {} XMR; 1 XMR redeems to {}",
            t.withdrawal_fee_rate * 100.0,
            t.minimum_atomic as f64 / aero_core::wagyu::ATOMIC_PER_XMR as f64,
            t.net_atomic(aero_core::wagyu::ATOMIC_PER_XMR) as f64
                / aero_core::wagyu::ATOMIC_PER_XMR as f64
        ),
        Err(e) => println!("Wagyu terms failed: {e}"),
    }

    // Two orders in a row, to confirm the deposit address really is per-order and must never be
    // cached. Monero's published donation address stands in for a payout address; both orders are
    // left to expire.
    let donation = "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H";
    let mut deposit_address = None;
    for n in 1..=2 {
        match aero_core::wagyu::create_withdrawal(&provider, donation).await {
            Ok(o) => {
                println!("order {n}: {} -> deposit to {}", o.order_id, o.deposit_address);
                if n == 1 {
                    deposit_address = Some(o.deposit_address);
                } else if Some(&o.deposit_address) == deposit_address.as_ref() {
                    println!("  !! same address as the previous order — the per-order assumption is wrong");
                }
            }
            Err(e) => println!("order {n} failed: {e}"),
        }
    }

    // Whether the exchange computes the same spotSend digest we do. An empty account cannot transfer,
    // but the refusal names the account it recovered — if that is the throwaway key's own address,
    // the exchange derived the digest exactly as we did.
    if let Some(dest) = deposit_address {
        let unsigned = hyperliquid::spot_send_action(
            dest.parse().unwrap(),
            &market.send_token,
            "0.01",
        );
        println!("action: {}", serde_json::to_string(&unsigned.action).unwrap());
        let sig = signer.sign_hash_sync(&unsigned.digest).unwrap();
        let body = hyperliquid::envelope(&unsigned, &sig);
        match hyperliquid::submit(&provider, &body).await {
            Ok(v) => println!("accepted: {v}"),
            Err(e) => println!("refused: {e}\n(expect this to name {})", signer.address()),
        }
    }
}
