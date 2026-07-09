//! Portable interactive console for the Aero wallet core.
//!
//! This is a runnable front-end for `aero_core` you can play with without the Qt GUI: it drives
//! the exact same backend (keys, encrypted keystore, Tor-routed RPC, EIP-1559 signing, ERC20).
//!
//! Run it and follow the menu. Network actions require an RPC endpoint (menu item 8); use your own
//! node / Helios for full privacy, or a public endpoint over Tor.

use std::io::{self, Write};

use aero_core::keys::WordCount;
use aero_core::provider::ProviderConfig;
use aero_core::wallet::{parse_units, Wallet};

fn main() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    // Headless bench mode: `aero bench` reproduces the connect-time Tor storm (all-account history
    // as background load) while timing foreground fee estimates, and prints request/concurrency
    // stats. Set AERO_NETLOG=<file> to also dump a per-request timeline, AERO_NOPRIO=1 to disable
    // the priority gate for an apples-to-apples before/after comparison.
    if std::env::args().nth(1).as_deref() == Some("bench") {
        run_bench(&rt);
        return;
    }

    let mut wallet: Option<Wallet> = None;
    let mut account: u32 = 0;
    let mut chain_id: u64 = 1;

    banner();
    loop {
        print_menu(wallet.is_some(), account);
        let choice = prompt("> ");
        match choice.trim() {
            "1" => wallet = Some(create_wallet()),
            "2" => wallet = Some(restore_wallet()),
            "3" => match open_wallet() {
                Some(w) => wallet = Some(w),
                None => {}
            },
            "4" => with_wallet(&wallet, |w| save_wallet(w)),
            "5" => with_wallet(&wallet, |w| show_address(w, account)),
            "6" => with_wallet_mut(&mut wallet, |w| {
                let idx = w.add_account();
                println!("  added account #{idx}");
            }),
            "7" => match prompt("  switch to account index: ").trim().parse::<u32>() {
                Ok(i) => {
                    account = i;
                    println!("  active account = #{account}");
                }
                Err(_) => println!("  invalid index"),
            },
            "8" => with_wallet_mut(&mut wallet, |w| configure_rpc(w, &mut chain_id)),
            "9" => with_wallet(&wallet, |w| eth_balance(&rt, w, account)),
            "10" => with_wallet(&wallet, |w| erc20_balance(&rt, w, account)),
            "11" => with_wallet(&wallet, |w| suggest_fees(&rt, w)),
            "12" => with_wallet(&wallet, |w| send_eth(&rt, w, account)),
            "13" => with_wallet(&wallet, |w| send_erc20(&rt, w, account)),
            "14" => with_wallet(&wallet, |w| history(&rt, w, account)),
            "15" => with_wallet_mut(&mut wallet, |w| manage_tokens(w)),
            "16" => with_wallet(&wallet, |w| show_seed(w)),
            "0" | "q" | "quit" | "exit" => {
                println!("bye.");
                break;
            }
            "" => {}
            other => println!("  unknown option: {other}"),
        }
        println!();
    }
}

// ---------- Tor bench (headless) ----------

fn run_bench(rt: &tokio::runtime::Runtime) {
    use std::time::{Duration, Instant};

    let mnemonic = std::env::var("AERO_BENCH_MNEMONIC")
        .unwrap_or_else(|_| "test test test test test test test test test test test junk".to_string());
    let naccts: u32 = std::env::var("AERO_BENCH_ACCOUNTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let socks = std::env::var("AERO_BENCH_SOCKS")
        .unwrap_or_else(|_| "socks5h://127.0.0.1:9055".to_string());
    let endpoints: Vec<String> = std::env::var("AERO_BENCH_RPC")
        .ok()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
        .unwrap_or_else(|| {
            vec![
                "https://ethereum-rpc.publicnode.com".into(),
                "https://eth.drpc.org".into(),
                "https://eth.merkle.io".into(),
                "https://1rpc.io/eth".into(),
            ]
        });

    println!("=== Aero Tor bench ===");
    println!(
        "accounts={naccts}  socks={socks}  priority_gate={}",
        if std::env::var_os("AERO_NOPRIO").is_some() {
            "OFF (flat single queue)"
        } else {
            "ON"
        }
    );

    let mut w = match Wallet::restore(mnemonic.trim()) {
        Ok(w) => w,
        Err(e) => {
            println!("restore failed: {e}");
            return;
        }
    };
    for _ in 1..naccts {
        w.add_account();
    }
    let cfg = ProviderConfig {
        chain_id: 1,
        endpoints,
        socks_proxy: Some(socks),
        allow_clearnet: false,
        timeout_secs: 30,
    };
    if let Err(e) = w.set_provider(cfg) {
        println!("set_provider failed: {e}");
        return;
    }

    print!("warming Tor circuit… ");
    io::stdout().flush().ok();
    match rt.block_on(w.block_number()) {
        Ok(b) => println!("chain head #{b}"),
        Err(e) => {
            println!("cannot reach chain over Tor: {e}\n(is the bundled Tor running on {})",
                     "127.0.0.1:9055");
            return;
        }
    }

    aero_core::provider::reset_net_stats();
    let t0 = Instant::now();
    let lats: Vec<u128> = rt.block_on(async {
        // Background load: every account's full history (marked Background, like the real app).
        let bg = async {
            let futs = (0..naccts).map(|i| aero_core::provider::background(w.account_history(i)));
            futures::future::join_all(futs).await
        };
        // The rest of the interactive connect set (balances + prices), foreground priority.
        let extras = String::new();
        let side = async {
            let _ = tokio::join!(w.all_balances(naccts, &extras), w.native_usd_price(), w.market_prices());
        };
        // Foreground probe: repeatedly time an interactive fee estimate while the storm runs. This is
        // the number that matters — how long a thing the user is waiting on takes under background load.
        let probe = async {
            let mut lats: Vec<u128> = Vec::new();
            for _ in 0..15u32 {
                tokio::time::sleep(Duration::from_millis(250)).await;
                let t = Instant::now();
                let _ = w.suggest_fees().await; // Interactive
                lats.push(t.elapsed().as_millis());
            }
            lats
        };
        let (_, _, lats) = tokio::join!(bg, side, probe);
        lats
    });
    let elapsed = t0.elapsed();
    let (total, peak, wait_ms) = aero_core::provider::net_stats();

    let mut sorted = lats.clone();
    sorted.sort_unstable();
    let n = sorted.len().max(1);
    let avg = lats.iter().sum::<u128>() / n as u128;
    let pick = |q: usize| sorted.get((sorted.len() * q / 100).min(sorted.len().saturating_sub(1))).copied().unwrap_or(0);

    println!("\n--- results ---");
    println!("wall time         : {:.1}s", elapsed.as_secs_f64());
    println!("requests total    : {total}");
    println!("peak concurrent   : {peak}");
    println!("summed gate-wait  : {wait_ms} ms");
    println!(
        "foreground fee latency (ms): avg={avg} p50={} p95={} max={}  (n={})",
        pick(50),
        pick(95),
        sorted.last().copied().unwrap_or(0),
        lats.len()
    );
    println!("(lower foreground latency + reasonable peak = healthier Tor usage)");
}

fn banner() {
    println!("========================================================");
    println!("  Aero — portable Ethereum wallet console (aero_core)");
    println!("  version {}", env!("CARGO_PKG_VERSION"));
    println!("========================================================");
    println!("  Keys stay local. Network calls go over Tor when a SOCKS");
    println!("  proxy is set. Nothing is logged anywhere.\n");
}

fn print_menu(loaded: bool, account: u32) {
    let state = if loaded {
        format!("[wallet loaded, active account #{account}]")
    } else {
        "[no wallet]".to_string()
    };
    println!("{state}");
    println!("  1) create new wallet          9)  check ETH balance");
    println!("  2) restore from mnemonic      10) check ERC20 balance");
    println!("  3) open wallet file           11) suggest fees");
    println!("  4) save wallet file           12) send ETH");
    println!("  5) show address               13) send ERC20");
    println!("  6) add account                14) ERC20 history");
    println!("  7) switch account             15) manage tokens");
    println!("  8) configure RPC / Tor        16) show seed phrase");
    println!("  0) quit");
}

// ---------- actions ----------

fn create_wallet() -> Wallet {
    let wc = match prompt("  word count (12/24) [12]: ").trim() {
        "24" => WordCount::Words24,
        _ => WordCount::Words12,
    };
    let w = Wallet::create_new(wc).expect("create");
    println!("\n  *** WRITE DOWN YOUR SEED PHRASE ***");
    println!("  {}\n", w.mnemonic());
    println!("  address #0: {}", w.address(0).unwrap());
    w
}

fn restore_wallet() -> Wallet {
    loop {
        let phrase = prompt("  enter BIP39 mnemonic: ");
        match Wallet::restore(phrase.trim()) {
            Ok(w) => {
                println!("  restored. address #0: {}", w.address(0).unwrap());
                return w;
            }
            Err(e) => println!("  {e} — try again"),
        }
    }
}

fn open_wallet() -> Option<Wallet> {
    let path = prompt("  wallet file path: ");
    let pw = prompt("  password: ");
    match Wallet::open(path.trim(), pw.trim()) {
        Ok(w) => {
            println!("  opened. address #0: {}", w.address(0).unwrap());
            Some(w)
        }
        Err(e) => {
            println!("  {e}");
            None
        }
    }
}

fn save_wallet(w: &Wallet) {
    let path = prompt("  save to path (e.g. mywallet.aero): ");
    let pw = prompt("  password: ");
    match w.save(path.trim(), pw.trim()) {
        Ok(()) => println!("  saved (encrypted with Argon2id + AES-256-GCM)."),
        Err(e) => println!("  {e}"),
    }
}

fn show_address(w: &Wallet, account: u32) {
    match w.address(account) {
        Ok(a) => println!("  account #{account}: {a}"),
        Err(e) => println!("  {e}"),
    }
}

fn configure_rpc(w: &mut Wallet, chain_id: &mut u64) {
    let cid = prompt("  chain id [1]: ");
    *chain_id = cid.trim().parse().unwrap_or(1);
    let eps = prompt("  RPC endpoint(s), comma-separated: ");
    let endpoints: Vec<String> = eps
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let proxy = prompt("  SOCKS proxy [socks5h://127.0.0.1:9050, blank=none]: ");
    let socks = {
        let p = proxy.trim();
        if p.is_empty() {
            Some("socks5h://127.0.0.1:9050".to_string())
        } else if p.eq_ignore_ascii_case("none") {
            None
        } else {
            Some(p.to_string())
        }
    };
    let cfg = ProviderConfig {
        chain_id: *chain_id,
        endpoints,
        socks_proxy: socks,
        allow_clearnet: false,
        timeout_secs: 60,
    };
    match w.set_provider(cfg) {
        Ok(()) => println!("  provider configured (chain {}).", *chain_id),
        Err(e) => println!("  {e}"),
    }
}

fn eth_balance(rt: &tokio::runtime::Runtime, w: &Wallet, account: u32) {
    match rt.block_on(w.eth_balance(account)) {
        Ok(b) => println!("  {} {}", b.formatted, b.symbol),
        Err(e) => println!("  {e}"),
    }
}

fn erc20_balance(rt: &tokio::runtime::Runtime, w: &Wallet, account: u32) {
    let token = prompt("  token contract address: ");
    match rt.block_on(w.erc20_balance(token.trim(), account)) {
        Ok(b) => println!("  {} {}", b.formatted, b.symbol),
        Err(e) => println!("  {e}"),
    }
}

fn suggest_fees(rt: &tokio::runtime::Runtime, w: &Wallet) {
    match rt.block_on(w.suggest_fees()) {
        Ok(f) => {
            println!("  base fee : {} wei", f.base_fee);
            println!("  tip      : {} wei", f.max_priority_fee);
            println!("  max fee  : {} wei", f.max_fee);
        }
        Err(e) => println!("  {e}"),
    }
}

fn send_eth(rt: &tokio::runtime::Runtime, w: &Wallet, account: u32) {
    let to = prompt("  to address: ");
    let amount = prompt("  amount (ETH): ");
    let wei = match parse_units(amount.trim(), 18) {
        Ok(v) => v.to_string(),
        Err(e) => {
            println!("  {e}");
            return;
        }
    };
    if !confirm(&format!("  send {} ETH to {}?", amount.trim(), to.trim())) {
        return;
    }
    match rt.block_on(w.send_eth(account, to.trim(), &wei, None, None)) {
        Ok(r) => println!("  broadcast! tx: {}", r.tx_hash),
        Err(e) => println!("  {e}"),
    }
}

fn send_erc20(rt: &tokio::runtime::Runtime, w: &Wallet, account: u32) {
    let token = prompt("  token contract address: ");
    let dec: u8 = prompt("  token decimals [18]: ").trim().parse().unwrap_or(18);
    let to = prompt("  to address: ");
    let amount = prompt("  amount: ");
    let units = match parse_units(amount.trim(), dec) {
        Ok(v) => v.to_string(),
        Err(e) => {
            println!("  {e}");
            return;
        }
    };
    if !confirm(&format!("  send {} tokens to {}?", amount.trim(), to.trim())) {
        return;
    }
    match rt.block_on(w.send_erc20(account, token.trim(), to.trim(), &units, None, None)) {
        Ok(r) => println!("  broadcast! tx: {}", r.tx_hash),
        Err(e) => println!("  {e}"),
    }
}

fn history(rt: &tokio::runtime::Runtime, w: &Wallet, account: u32) {
    let token = prompt("  token contract address: ");
    let from = prompt("  from block [earliest]: ");
    let from = if from.trim().is_empty() { "earliest" } else { from.trim() };
    match rt.block_on(w.erc20_history(token.trim(), account, from)) {
        Ok(items) => {
            if items.is_empty() {
                println!("  (no transfers found)");
            }
            for h in items {
                let arrow = if h.direction == "in" { "<-" } else { "->" };
                println!(
                    "  #{:>8}  {} {} {}  {} (tx {}…)",
                    h.block,
                    arrow,
                    h.formatted,
                    h.symbol,
                    h.counterparty,
                    &h.tx_hash.chars().take(10).collect::<String>()
                );
            }
        }
        Err(e) => println!("  {e}"),
    }
}

fn manage_tokens(w: &mut Wallet) {
    loop {
        println!("  tracked tokens:");
        for t in w.tokens() {
            println!("    {} ({}, {} decimals)", t.symbol, t.address, t.decimals);
        }
        match prompt("  (a)dd, (r)emove, (b)ack: ").trim() {
            "a" => {
                let address = prompt("    contract address: ").trim().to_string();
                let symbol = prompt("    symbol: ").trim().to_string();
                let decimals: u8 = prompt("    decimals [18]: ").trim().parse().unwrap_or(18);
                w.add_token(aero_core::keystore::TokenRef {
                    address,
                    symbol,
                    decimals,
                });
            }
            "r" => {
                let address = prompt("    address to remove: ");
                w.remove_token(address.trim());
            }
            _ => break,
        }
    }
}

fn show_seed(w: &Wallet) {
    if confirm("  reveal seed phrase on screen?") {
        println!("  {}", w.mnemonic());
    }
}

// ---------- helpers ----------

fn with_wallet(w: &Option<Wallet>, f: impl FnOnce(&Wallet)) {
    match w {
        Some(w) => f(w),
        None => println!("  no wallet loaded (create/restore/open first)."),
    }
}

fn with_wallet_mut(w: &mut Option<Wallet>, f: impl FnOnce(&mut Wallet)) {
    match w {
        Some(w) => f(w),
        None => println!("  no wallet loaded (create/restore/open first)."),
    }
}

fn prompt(msg: &str) -> String {
    print!("{msg}");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line).ok();
    line
}

fn confirm(msg: &str) -> bool {
    matches!(prompt(&format!("{msg} [y/N]: ")).trim(), "y" | "Y" | "yes")
}
