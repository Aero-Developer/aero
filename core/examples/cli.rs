//! Standalone CLI harness for `aero_core`, useful for verifying the backend without the GUI.
//!
//! Examples:
//!   cargo run --example cli -- new 12
//!   cargo run --example cli -- address "test test ... junk" 0
//!   cargo run --example cli -- balance <mnemonic> <index> <chain_id> <rpc_url> [socks5h://127.0.0.1:9050]
//!   cargo run --example cli -- fees <chain_id> <rpc_url> [socks_proxy]

use aero_core::keys::WordCount;
use aero_core::provider::ProviderConfig;
use aero_core::wallet::Wallet;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: cli <new|address|balance|fees> ...");
        std::process::exit(2);
    }

    let rt = tokio::runtime::Runtime::new().unwrap();

    match args[0].as_str() {
        "new" => {
            let words = WordCount::from_count(args.get(1).map(|s| s.parse().unwrap_or(12)).unwrap_or(12))
                .unwrap();
            let w = Wallet::create_new(words).unwrap();
            println!("mnemonic: {}", w.mnemonic());
            println!("address0: {}", w.address(0).unwrap());
        }
        "address" => {
            let mnemonic = &args[1];
            let index: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            let w = Wallet::restore(mnemonic).unwrap();
            println!("{}", w.address(index).unwrap());
        }
        "balance" => {
            let mnemonic = &args[1];
            let index: u32 = args[2].parse().unwrap();
            let chain_id: u64 = args[3].parse().unwrap();
            let rpc = args[4].clone();
            let socks = args.get(5).cloned();
            let mut w = Wallet::restore(mnemonic).unwrap();
            w.set_provider(ProviderConfig {
                chain_id,
                endpoints: vec![rpc],
                socks_proxy: socks,
                allow_clearnet: false,
                timeout_secs: 60,
            })
            .unwrap();
            let bal = rt.block_on(w.eth_balance(index)).unwrap();
            println!("{} {}", bal.formatted, bal.symbol);
        }
        "allbalances" => {
            let mnemonic = &args[1];
            let num: u32 = args[2].parse().unwrap();
            let chain_id: u64 = args[3].parse().unwrap();
            let rpc = args[4].clone();
            let socks = args.get(5).cloned();
            let mut w = Wallet::restore(mnemonic).unwrap();
            for _ in 1..num {
                let _ = w.add_account();
            }
            w.set_provider(ProviderConfig {
                chain_id,
                endpoints: vec![rpc],
                socks_proxy: socks,
                allow_clearnet: false,
                timeout_secs: 60,
            })
            .unwrap();
            let v = rt.block_on(w.all_balances(num)).unwrap();
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        "fees" => {
            let chain_id: u64 = args[1].parse().unwrap();
            let rpc = args[2].clone();
            let socks = args.get(3).cloned();
            let mut w = Wallet::create_new(WordCount::Words12).unwrap();
            w.set_provider(ProviderConfig {
                chain_id,
                endpoints: vec![rpc],
                socks_proxy: socks,
                allow_clearnet: false,
                timeout_secs: 60,
            })
            .unwrap();
            let fees = rt.block_on(w.suggest_fees()).unwrap();
            println!(
                "base={} tip={} max={}",
                fees.base_fee, fees.max_priority_fee, fees.max_fee
            );
        }
        "scan" => {
            let mnemonic = &args[1];
            let rpc = args[2].clone();
            let socks = args.get(3).cloned();
            let mut w = Wallet::restore(mnemonic).unwrap();
            w.set_provider(ProviderConfig {
                chain_id: 1,
                endpoints: vec![rpc],
                socks_proxy: socks,
                allow_clearnet: false,
                timeout_secs: 60,
            })
            .unwrap();
            let funded = rt.block_on(w.scan_funded(20)).unwrap();
            println!("funded indices: {funded:?}");
        }
        "liquidity" => {
            let token = args[1].clone();
            let rpc = args[2].clone();
            let socks = args.get(3).cloned();
            let mut w = Wallet::create_new(WordCount::Words12).unwrap();
            w.set_provider(ProviderConfig {
                chain_id: 1,
                endpoints: vec![rpc],
                socks_proxy: socks,
                allow_clearnet: false,
                timeout_secs: 60,
            })
            .unwrap();
            let usd = rt.block_on(w.token_liquidity_usd(&token)).unwrap();
            println!("liquidity: ${usd}");
        }
        "nfts" => {
            let mnemonic = &args[1];
            let index: u32 = args[2].parse().unwrap();
            let rpc = args[3].clone();
            let socks = args.get(4).cloned();
            let mut w = Wallet::restore(mnemonic).unwrap();
            w.set_provider(ProviderConfig {
                chain_id: 1,
                endpoints: vec![rpc],
                socks_proxy: socks,
                allow_clearnet: false,
                timeout_secs: 60,
            })
            .unwrap();
            let nfts = rt.block_on(w.account_nfts(index)).unwrap();
            println!("nfts: {}", nfts.len());
            for n in nfts.iter().take(5) {
                println!("  {} {} x{} rep={}", n.token_type, n.name, n.count, n.reputation);
            }
        }
        "prices" => {
            let rpc = args[1].clone();
            let socks = args.get(2).cloned();
            let mut w = Wallet::create_new(WordCount::Words12).unwrap();
            w.set_provider(ProviderConfig {
                chain_id: 1,
                endpoints: vec![rpc],
                socks_proxy: socks,
                allow_clearnet: false,
                timeout_secs: 60,
            })
            .unwrap();
            let (xu, xc, eu, ec) = rt.block_on(w.market_prices()).unwrap();
            println!("XMR ${xu} ({xc:.2}%)  ETH ${eu} ({ec:.2}%)");
        }
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(2);
        }
    }
}
