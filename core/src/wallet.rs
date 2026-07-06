//! High-level wallet: aggregates HD keys, the encrypted keystore, the Tor-routed provider,
//! and EIP-1559 transaction building/signing. This is the surface the C ABI (and the Qt
//! frontend) is built on, mirroring the role of Feather's `libwalletqt` `Wallet` class.

use std::str::FromStr;

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address, Bytes, TxKind, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use serde::Serialize;

use crate::chains::chain_info;
use crate::erc20;
use crate::error::{CoreError, Result};
use crate::hardware::{self, HwKind};
use crate::keys::{SeedPhrase, WordCount};
use crate::keystore::{self, AccountEntry, HwDescriptor, TokenRef, WalletSecrets};
use crate::provider::{ProviderConfig, RpcProvider};

/// A balance reported for display.
#[derive(Serialize)]
pub struct BalanceInfo {
    /// Raw integer value in the smallest unit (wei or token base units), decimal string.
    pub raw: String,
    /// Human-readable value, e.g. "1.2345".
    pub formatted: String,
    pub decimals: u8,
    pub symbol: String,
}

/// Suggested EIP-1559 fee parameters (all in wei, decimal strings).
#[derive(Serialize)]
pub struct FeeSuggestion {
    pub base_fee: String,
    pub max_priority_fee: String,
    pub max_fee: String,
}

/// Result of broadcasting a transaction.
#[derive(Serialize)]
pub struct SendResult {
    pub tx_hash: String,
}

/// A single transfer in the account history (native ETH or ERC20).
#[derive(Serialize, Default)]
pub struct HistoryItem {
    pub direction: String, // "in" | "out"
    pub counterparty: String,
    pub amount: String,     // base units, decimal string
    pub formatted: String,  // human readable
    pub tx_hash: String,
    pub block: u64,
    pub token: String,
    pub symbol: String,
    pub timestamp: u64,     // unix seconds (0 if unknown)
    pub fee: String,        // gas fee in wei, decimal string ("" if unknown)
    pub failed: bool,       // reverted / errored transaction
}

/// An owned NFT collection (ERC-721 / ERC-1155), as reported by the block explorer.
#[derive(Serialize, Default)]
pub struct NftCollection {
    pub name: String,
    pub symbol: String,
    pub address: String,
    pub token_type: String, // "ERC-721" | "ERC-1155"
    pub reputation: String, // "ok" | "neutral" | "scam" ...
    pub count: u64,         // number of items the account holds in this collection
    pub image_url: String,  // a representative item image (may be a data: URI, https, or ipfs://)
}

/// Where an account's signing key comes from: a local BIP39 seed, or a connected hardware device.
enum KeySource {
    /// Software wallet: the mnemonic (+ optional passphrase) is held in memory and on disk.
    Software(SeedPhrase),
    /// Hardware wallet: keys stay on the Ledger/Trezor; we only hold the device kind and (for
    /// Trezor) the host-entered passphrase. Every signature requires the device.
    Hardware(HwContext),
}

struct HwContext {
    kind: HwKind,
    passphrase: String, // host-entered (Trezor); empty/ignored for Ledger
}

pub struct Wallet {
    secrets: WalletSecrets,
    keys: KeySource,
    provider: Option<RpcProvider>,
    provider_cfg: ProviderConfig,
}

impl Wallet {
    // ---------- lifecycle ----------

    pub fn create_new(words: WordCount) -> Result<Self> {
        Self::create_new_with_passphrase(words, "")
    }

    /// Create a new wallet, optionally attaching a BIP39 passphrase (empty = none).
    pub fn create_new_with_passphrase(words: WordCount, passphrase: &str) -> Result<Self> {
        let seed = SeedPhrase::generate(words)?.with_passphrase(passphrase);
        Self::from_seed(seed, 1, Vec::new())
    }

    pub fn restore(mnemonic: &str) -> Result<Self> {
        Self::restore_with_passphrase(mnemonic, "")
    }

    /// Restore from a mnemonic, optionally attaching a BIP39 passphrase (empty = none). A different
    /// passphrase yields a completely different set of addresses.
    pub fn restore_with_passphrase(mnemonic: &str, passphrase: &str) -> Result<Self> {
        let seed = SeedPhrase::parse(mnemonic)?.with_passphrase(passphrase);
        Self::from_seed(seed, 1, Vec::new())
    }

    fn from_seed(seed: SeedPhrase, account_count: u32, tokens: Vec<TokenRef>) -> Result<Self> {
        let account_count = account_count.max(1);
        let mut secrets = WalletSecrets {
            mnemonic: seed.as_str().to_string(),
            passphrase: seed.passphrase().to_string(),
            account_count,
            account_order: Vec::new(),
            tokens,
            imported_keys: Vec::new(),
            hardware: None,
        };
        normalize_account_order(&mut secrets);
        Ok(Self {
            secrets,
            keys: KeySource::Software(seed),
            provider: None,
            provider_cfg: ProviderConfig::default(),
        })
    }

    /// Create a watch-only hardware wallet: connect the device, derive `num_accounts` addresses at
    /// `m/44'/60'/0'/0/x`, and build a wallet whose keys stay on the device. `passphrase` is the
    /// host-entered BIP39 passphrase (Trezor); ignored by Ledger (device-side only).
    pub async fn create_hardware(kind: HwKind, passphrase: &str, num_accounts: u32) -> Result<Self> {
        let n = num_accounts.max(1);
        let addresses = hardware::get_addresses(kind, passphrase, 0, n).await?;
        let account_order = (0..n).map(AccountEntry::Hd).collect();
        let secrets = WalletSecrets {
            mnemonic: String::new(),
            passphrase: String::new(),
            account_count: n,
            account_order,
            tokens: Vec::new(),
            imported_keys: Vec::new(),
            hardware: Some(HwDescriptor { kind: kind.as_str().to_string(), addresses }),
        };
        Ok(Self {
            secrets,
            keys: KeySource::Hardware(HwContext { kind, passphrase: passphrase.to_string() }),
            provider: None,
            provider_cfg: ProviderConfig::default(),
        })
    }

    pub fn open(path: &str, password: &str) -> Result<Self> {
        Self::open_with_passphrase(path, password, "")
    }

    /// Open an encrypted wallet file. For hardware wallets the device must be connected (and the
    /// Trezor passphrase supplied); we re-derive the first address and refuse to load if it doesn't
    /// match the stored one (so an unplugged device, or a wrong passphrase, won't open the wallet).
    pub fn open_with_passphrase(path: &str, password: &str, passphrase: &str) -> Result<Self> {
        let data = std::fs::read(path)?;
        let mut secrets = keystore::decrypt(&data, password)?;
        normalize_account_order(&mut secrets); // reconstruct order for older files

        if let Some(hw) = secrets.hardware.clone() {
            let kind = HwKind::parse(&hw.kind)?;
            // Require the device now and verify it derives the same first address.
            let derived = crate::ffi::block_on(hardware::get_address(kind, passphrase, 0))?;
            let expected = hw.addresses.first().cloned().unwrap_or_default();
            if !expected.is_empty() && !derived.eq_ignore_ascii_case(&expected) {
                return Err(CoreError::rpc(
                    "hardware device/passphrase does not match this wallet".to_string(),
                ));
            }
            return Ok(Self {
                secrets,
                keys: KeySource::Hardware(HwContext { kind, passphrase: passphrase.to_string() }),
                provider: None,
                provider_cfg: ProviderConfig::default(),
            });
        }

        // Software: re-attach the stored passphrase so HD addresses derive identically.
        let seed = SeedPhrase::parse(&secrets.mnemonic)?.with_passphrase(&secrets.passphrase);
        Ok(Self {
            keys: KeySource::Software(seed),
            provider: None,
            provider_cfg: ProviderConfig::default(),
            secrets,
        })
    }

    /// Whether this is a hardware wallet.
    pub fn is_hardware(&self) -> bool {
        matches!(self.keys, KeySource::Hardware(_))
    }

    /// Hardware device kind ("ledger"/"trezor"), or "" for software wallets.
    pub fn hw_kind(&self) -> &str {
        match &self.keys {
            KeySource::Hardware(ctx) => ctx.kind.as_str(),
            KeySource::Software(_) => "",
        }
    }

    pub fn save(&self, path: &str, password: &str) -> Result<()> {
        let blob = keystore::encrypt(&self.secrets, password)?;
        std::fs::write(path, blob)?;
        Ok(())
    }

    // ---------- accounts / keys ----------

    /// Seed phrase for software wallets; "" for hardware wallets (no seed on this machine).
    pub fn mnemonic(&self) -> &str {
        match &self.keys {
            KeySource::Software(seed) => seed.as_str(),
            KeySource::Hardware(_) => "",
        }
    }

    /// Whether this wallet is protected by a BIP39 passphrase.
    pub fn has_passphrase(&self) -> bool {
        match &self.keys {
            KeySource::Software(seed) => seed.has_passphrase(),
            KeySource::Hardware(ctx) => !ctx.passphrase.is_empty(),
        }
    }

    /// Total accounts shown to the user (HD + imported), in stable order.
    pub fn account_count(&self) -> u32 {
        self.secrets.account_order.len() as u32
    }

    /// Append a new HD account and return its (stable) unified index.
    pub fn add_account(&mut self) -> u32 {
        let hd_index = self.secrets.account_count;
        self.secrets.account_count += 1;
        self.secrets.account_order.push(AccountEntry::Hd(hd_index));
        self.account_count() - 1
    }

    /// Import a raw hex private key as a new account; returns its (stable) unified index.
    pub fn import_private_key(&mut self, hex_key: &str) -> Result<u32> {
        SeedPhrase::signer_from_hex(hex_key)?; // validate before storing
        let clean = hex_key.trim().trim_start_matches("0x").to_lowercase();
        let j = self.secrets.imported_keys.len();
        self.secrets.imported_keys.push(clean);
        self.secrets.account_order.push(AccountEntry::Imported(j));
        Ok(self.account_count() - 1)
    }

    /// Route a unified account index to a local signing key (software wallets only). Uses the stable
    /// per-account order so an index always resolves to the same key. Errors for hardware wallets.
    fn local_signer(&self, index: u32) -> Result<PrivateKeySigner> {
        let seed = match &self.keys {
            KeySource::Software(seed) => seed,
            KeySource::Hardware(_) => {
                return Err(CoreError::Signing(
                    "hardware wallet: keys stay on the device".into(),
                ))
            }
        };
        match self.secrets.account_order.get(index as usize) {
            Some(AccountEntry::Hd(i)) => seed.signer(*i),
            Some(AccountEntry::HdPath(path)) => seed.signer_at_path(path),
            Some(AccountEntry::Imported(j)) => {
                let key = self
                    .secrets
                    .imported_keys
                    .get(*j)
                    .ok_or_else(|| CoreError::Derivation(format!("no account at index {index}")))?;
                SeedPhrase::signer_from_hex(key)
            }
            None => Err(CoreError::Derivation(format!("no account at index {index}"))),
        }
    }

    /// HD derivation index behind unified account `index` (for hardware device paths). Hardware
    /// wallets are all-HD, so this is the entry's derivation index.
    fn hd_index(&self, index: u32) -> Result<u32> {
        match self.secrets.account_order.get(index as usize) {
            Some(AccountEntry::Hd(i)) => Ok(*i),
            _ => Err(CoreError::Derivation(format!("no HD account at index {index}"))),
        }
    }

    pub fn address(&self, index: u32) -> Result<String> {
        match &self.keys {
            KeySource::Software(_) => Ok(self.local_signer(index)?.address().to_checksum(None)),
            KeySource::Hardware(_) => {
                // Served from the addresses cached at create/open time (no device round-trip).
                self.secrets
                    .hardware
                    .as_ref()
                    .and_then(|hw| hw.addresses.get(index as usize))
                    .cloned()
                    .ok_or_else(|| CoreError::Derivation(format!("no account at index {index}")))
            }
        }
    }

    /// Export the raw private key (0x-prefixed hex) for an account index. Handle with care.
    /// Unavailable for hardware wallets (the key never leaves the device).
    pub fn export_private_key(&self, index: u32) -> Result<String> {
        let signer = self.local_signer(index)?;
        Ok(format!("0x{}", hex::encode(signer.to_bytes())))
    }

    /// Derive and append one more hardware account from the device; returns its unified index.
    pub async fn add_hardware_account(&mut self) -> Result<u32> {
        let ctx = match &self.keys {
            KeySource::Hardware(ctx) => ctx,
            KeySource::Software(_) => return Err(CoreError::rpc("not a hardware wallet")),
        };
        let next_hd = self.secrets.account_count;
        let addr = hardware::get_address(ctx.kind, &ctx.passphrase, next_hd).await?;
        self.secrets.account_count += 1;
        self.secrets.account_order.push(AccountEntry::Hd(next_hd));
        if let Some(hw) = self.secrets.hardware.as_mut() {
            hw.addresses.push(addr);
        }
        Ok(self.account_count() - 1)
    }

    // ---------- tokens ----------

    pub fn tokens(&self) -> &[TokenRef] {
        &self.secrets.tokens
    }

    pub fn add_token(&mut self, token: TokenRef) {
        if !self
            .secrets
            .tokens
            .iter()
            .any(|t| t.address.eq_ignore_ascii_case(&token.address))
        {
            self.secrets.tokens.push(token);
        }
    }

    pub fn remove_token(&mut self, address: &str) {
        self.secrets
            .tokens
            .retain(|t| !t.address.eq_ignore_ascii_case(address));
    }

    // ---------- networking ----------

    pub fn set_provider(&mut self, cfg: ProviderConfig) -> Result<()> {
        self.provider = Some(RpcProvider::new(&cfg)?);
        self.provider_cfg = cfg;
        Ok(())
    }

    fn provider(&self) -> Result<&RpcProvider> {
        self.provider.as_ref().ok_or(CoreError::NoProvider)
    }

    pub async fn eth_balance(&self, index: u32) -> Result<BalanceInfo> {
        let provider = self.provider()?;
        let addr = self.address(index)?;
        let raw_hex = provider.get_balance(&addr).await?;
        let wei = parse_hex_u256(&raw_hex)?;
        Ok(BalanceInfo {
            raw: wei.to_string(),
            formatted: format_units(wei, 18),
            decimals: 18,
            symbol: chain_info(provider.chain_id()).native_symbol.to_string(),
        })
    }

    pub async fn erc20_balance(&self, token: &str, index: u32) -> Result<BalanceInfo> {
        let provider = self.provider()?;
        let owner = parse_address(&self.address(index)?)?;
        let token_addr = parse_address(token)?;

        let bal_data = format!("0x{}", hex::encode(erc20::encode_balance_of(owner)));
        let bal_ret = provider.eth_call(&token_addr.to_string(), &bal_data).await?;
        let bal = erc20::decode_u256(&hex_bytes(&bal_ret)?)
            .ok_or_else(|| CoreError::rpc("could not decode balanceOf"))?;

        let (symbol, decimals) = self.erc20_metadata(token).await?;
        Ok(BalanceInfo {
            raw: bal.to_string(),
            formatted: format_units(bal, decimals),
            decimals,
            symbol,
        })
    }

    pub async fn erc20_metadata(&self, token: &str) -> Result<(String, u8)> {
        // Prefer cached metadata if we already track this token.
        if let Some(t) = self
            .secrets
            .tokens
            .iter()
            .find(|t| t.address.eq_ignore_ascii_case(token))
        {
            return Ok((t.symbol.clone(), t.decimals));
        }
        let provider = self.provider()?;
        let token_addr = parse_address(token)?.to_string();

        let dec_ret = provider
            .eth_call(&token_addr, &format!("0x{}", hex::encode(erc20::encode_decimals())))
            .await?;
        let decimals = erc20::decode_u8(&hex_bytes(&dec_ret)?).unwrap_or(18);

        let sym_ret = provider
            .eth_call(&token_addr, &format!("0x{}", hex::encode(erc20::encode_symbol())))
            .await?;
        let symbol = erc20::decode_string(&hex_bytes(&sym_ret)?).unwrap_or_else(|| "TOKEN".into());
        Ok((symbol, decimals))
    }

    /// Scan HD-derived addresses (`m/44'/60'/0'/0/x`) and return the indices that hold a balance
    /// (native ETH OR any tracked token). Uses a BIP44-style gap limit: scanning stops after
    /// `gap_limit` consecutive empty addresses. Balances are fetched in batched JSON-RPC requests
    /// so a deep scan is a handful of round-trips rather than one per address.
    pub async fn scan_funded(&mut self, gap_limit: u32) -> Result<Vec<u32>> {
        // Hardware wallets derive addresses via slow device round-trips, so we don't run an
        // automatic gap scan; the user adds accounts explicitly instead.
        if matches!(self.keys, KeySource::Hardware(_)) {
            return Ok(Vec::new());
        }

        // Ethereum seeds are used by different wallets under different derivation schemes, so — like
        // Electrum's Bitcoin recovery — we scan every common scheme (not just the standard BIP44
        // path) so funds created by any of them are found. `{i}` is the per-scheme index.
        // Scheme 0 is the standard path (stored as `Hd(index)`); the rest as `HdPath(path)`.
        const SCHEMES: [&str; 4] = [
            "m/44'/60'/0'/0/{i}", // BIP44: MetaMask, Trezor, Trust, imToken, Coinbase Wallet, ...
            "m/44'/60'/{i}'/0/0", // Ledger Live
            "m/44'/60'/0'/{i}",   // Ledger legacy / MyEtherWallet / MyCrypto
            "m/44'/60'/0'/0'/{i}",// some older/hardened variants
        ];

        let tokens: Vec<Address> = self
            .secrets
            .tokens
            .iter()
            .filter_map(|t| parse_address(&t.address).ok())
            .collect();
        let per_addr = 1 + tokens.len(); // 1 eth_getBalance + one balanceOf per token
        let chunk: u32 = 20;
        let hard_cap: u32 = 100_000; // safety bound
        let gap = gap_limit.max(1);

        // (scheme index, per-scheme index, full path) of every funded address found.
        let mut found: Vec<(usize, u32, String)> = Vec::new();

        {
            let seed = match &self.keys {
                KeySource::Software(seed) => seed,
                KeySource::Hardware(_) => unreachable!(),
            };
            let provider = self.provider()?;

            for (scheme_idx, template) in SCHEMES.iter().enumerate() {
                let mut consecutive_empty = 0u32;
                let mut index: u32 = 0;

                'scheme: while index < hard_cap {
                    let start = index;
                    let end = (start + chunk).min(hard_cap);

                    let mut addrs = Vec::with_capacity((end - start) as usize);
                    let mut paths = Vec::with_capacity((end - start) as usize);
                    for i in start..end {
                        let path = template.replace("{i}", &i.to_string());
                        addrs.push(seed.signer_at_path(&path)?.address());
                        paths.push((i, path));
                    }

                    // One batch: [eth_getBalance, balanceOf(token0), ...] per address.
                    let mut calls: Vec<(String, serde_json::Value)> =
                        Vec::with_capacity(addrs.len() * per_addr);
                    for a in &addrs {
                        calls.push((
                            "eth_getBalance".to_string(),
                            serde_json::json!([a.to_string(), "latest"]),
                        ));
                        for t in &tokens {
                            let data = format!("0x{}", hex::encode(erc20::encode_balance_of(*a)));
                            calls.push((
                                "eth_call".to_string(),
                                serde_json::json!([{ "to": t.to_string(), "data": data }, "latest"]),
                            ));
                        }
                    }
                    let results = provider.call_batch(&calls).await?;

                    for (p, _) in addrs.iter().enumerate() {
                        let base = p * per_addr;
                        let mut has_balance = results
                            .get(base)
                            .and_then(|v| parse_hex_u256(v).ok())
                            .map(|wei| wei > U256::ZERO)
                            .unwrap_or(false);
                        if !has_balance {
                            for j in 0..tokens.len() {
                                let bal = results
                                    .get(base + 1 + j)
                                    .and_then(|v| hex_bytes(v).ok())
                                    .and_then(|b| erc20::decode_u256(&b));
                                if matches!(bal, Some(b) if b > U256::ZERO) {
                                    has_balance = true;
                                    break;
                                }
                            }
                        }

                        let (i, path) = paths[p].clone();
                        if has_balance {
                            found.push((scheme_idx, i, path));
                            consecutive_empty = 0;
                        } else {
                            consecutive_empty += 1;
                            if consecutive_empty >= gap {
                                break 'scheme;
                            }
                        }
                    }
                    index = end;
                }
            }
        }

        // Register every funded address as an account (deduped), returning their unified indices so
        // the UI can show them. Scheme 0 keeps the compact `Hd(index)` form.
        let mut out = Vec::with_capacity(found.len());
        for (scheme_idx, i, path) in found {
            let entry = if scheme_idx == 0 {
                AccountEntry::Hd(i)
            } else {
                AccountEntry::HdPath(path)
            };
            let uni = match self.secrets.account_order.iter().position(|e| *e == entry) {
                Some(pos) => pos as u32,
                None => {
                    if let AccountEntry::Hd(idx) = &entry {
                        self.secrets.account_count = self.secrets.account_count.max(idx + 1);
                    }
                    self.secrets.account_order.push(entry);
                    (self.secrets.account_order.len() - 1) as u32
                }
            };
            out.push(uni);
        }
        Ok(out)
    }

    /// ETH/USD price read on-chain from the Chainlink mainnet aggregator via `eth_call`
    /// (over the same Tor RPC) — no third-party price API. Returns USD per 1 ETH.
    /// USD price of the connected chain's native coin. On Ethereum mainnet this uses the trustless
    /// on-chain Chainlink feed; on other chains (where that feed's RPC isn't reachable) it falls
    /// back to CoinGecko over Tor, keyed by the chain's native coin id.
    pub async fn native_usd_price(&self) -> Result<f64> {
        let info = chain_info(self.provider()?.chain_id());
        if info.chain_id == 1 {
            return self.eth_usd_price().await; // on-chain, trustless
        }
        let url = format!(
            "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd",
            info.coingecko_id
        );
        let v = self.provider()?.http_get_json(&url).await?;
        let price = v[info.coingecko_id]["usd"].as_f64().unwrap_or(0.0);
        if price <= 0.0 {
            return Err(CoreError::rpc("no native price"));
        }
        Ok(price)
    }

    pub async fn eth_usd_price(&self) -> Result<f64> {
        let provider = self.provider()?;
        // Chainlink ETH/USD feed (mainnet), 8 decimals.
        const FEED: &str = "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419";

        // Prefer latestRoundData() (0xfeaf968c); the `answer` is the 2nd 32-byte word. If that
        // call fails or returns a short/zero payload, fall back to latestAnswer() (0x50d25bcd),
        // which returns a single int256 word directly.
        let mut answer = match provider.eth_call(FEED, "0xfeaf968c").await {
            Ok(ret) => {
                let bytes = hex_bytes(&ret)?;
                if bytes.len() >= 64 {
                    U256::from_be_slice(&bytes[32..64])
                } else {
                    U256::ZERO
                }
            }
            Err(_) => U256::ZERO,
        };

        if answer == U256::ZERO {
            let ret = provider.eth_call(FEED, "0x50d25bcd").await?;
            let bytes = hex_bytes(&ret)?;
            if bytes.len() < 32 {
                return Err(CoreError::rpc("bad price feed response"));
            }
            answer = U256::from_be_slice(&bytes[0..32]);
        }

        let scaled = answer / U256::from(1_000_000u64); // keep 2 decimals (1e8 -> 1e2)
        let price = scaled.to::<u128>() as f64 / 100.0;
        Ok(price)
    }

    /// Market prices for the Home tickers: (xmr_usd, xmr_24h_change_pct, eth_usd, eth_24h_change_pct).
    /// XMR has no usable on-chain feed, so this uses a public price API fetched over the same Tor
    /// transport (no IP linkage). ETH balance valuation still uses the trustless on-chain feed.
    pub async fn market_prices(&self) -> Result<(f64, f64, f64, f64)> {
        let provider = self.provider()?;

        // Primary: CoinGecko (gives a true rolling-24h change). Over Tor this often hits a
        // shared-exit-IP rate limit (HTTP 429), so treat any failure/empty result as "try the
        // fallback" rather than surfacing an error.
        let cg = "https://api.coingecko.com/api/v3/simple/price\
                  ?ids=monero,ethereum&vs_currencies=usd&include_24hr_change=true";
        if let Ok(v) = provider.http_get_json(cg).await {
            let f = |k1: &str, k2: &str| v[k1][k2].as_f64();
            if let (Some(xu), Some(eu)) = (f("monero", "usd"), f("ethereum", "usd")) {
                if xu > 0.0 && eu > 0.0 {
                    return Ok((
                        xu,
                        f("monero", "usd_24h_change").unwrap_or(0.0),
                        eu,
                        f("ethereum", "usd_24h_change").unwrap_or(0.0),
                    ));
                }
            }
        }

        // Fallback: Kraken's public ticker is Tor-friendly and rarely rate-limited. It has no
        // rolling-24h field, so we approximate the change against today's opening price.
        let kr = "https://api.kraken.com/0/public/Ticker?pair=XMRUSD,ETHUSD";
        let v = provider.http_get_json(kr).await?;
        let pair = |name: &str| -> (f64, f64) {
            let node = &v["result"][name];
            let parse =
                |x: &serde_json::Value| x.as_str().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0);
            let last = parse(&node["c"][0]); // last trade price
            let open = parse(&node["o"]); // today's opening price
            let chg = if open > 0.0 { (last - open) / open * 100.0 } else { 0.0 };
            (last, chg)
        };
        let (xu, xc) = pair("XXMRZUSD");
        let (eu, ec) = pair("XETHZUSD");
        if xu <= 0.0 && eu <= 0.0 {
            return Err(CoreError::rpc("no market price data"));
        }
        Ok((xu, xc, eu, ec))
    }

    /// Total USD liquidity of the deepest DEX pool for `token` on Ethereum, via DexScreener (over
    /// Tor). Used to auto-trust otherwise-unknown tokens that have real market depth. Returns 0.0 if
    /// the token has no pools / on any error.
    pub async fn token_liquidity_usd(&self, token: &str) -> Result<f64> {
        let provider = self.provider()?;
        let Some(slug) = chain_info(provider.chain_id()).dexscreener_slug else {
            return Ok(0.0); // chain not indexed by DexScreener
        };
        let url = format!("https://api.dexscreener.com/latest/dex/tokens/{token}");
        let v = provider.http_get_json(&url).await?;
        let mut max = 0.0f64;
        if let Some(pairs) = v.get("pairs").and_then(|p| p.as_array()) {
            for p in pairs {
                if p.get("chainId").and_then(|c| c.as_str()) != Some(slug) {
                    continue;
                }
                let usd = p
                    .get("liquidity")
                    .and_then(|l| l.get("usd"))
                    .and_then(|u| u.as_f64())
                    .unwrap_or(0.0);
                if usd > max {
                    max = usd;
                }
            }
        }
        Ok(max)
    }

    /// USD -> `currency` conversion rate via CoinGecko (over Tor), using USDT as a ~1 USD proxy.
    /// Returns 1.0 for "usd". Used for the optional fiat-currency display setting.
    pub async fn fiat_per_usd(&self, currency: &str) -> Result<f64> {
        let cur = currency.trim().to_lowercase();
        if cur == "usd" {
            return Ok(1.0);
        }
        let provider = self.provider()?;
        let url = format!(
            "https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies={cur}"
        );
        let v = provider.http_get_json(&url).await?;
        let rate = v["tether"][cur.as_str()].as_f64().unwrap_or(0.0);
        if rate <= 0.0 {
            return Err(CoreError::rpc("no fiat rate"));
        }
        Ok(rate)
    }

    /// Current chain head block number (for cheap new-block polling).
    pub async fn block_number(&self) -> Result<u64> {
        let v = self.provider()?.block_number().await?;
        let s = v.as_str().unwrap_or("0x0");
        u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| CoreError::rpc(format!("bad block number: {e}")))
    }

    pub async fn suggest_fees(&self) -> Result<FeeSuggestion> {
        let provider = self.provider()?;

        // Legacy-gas chains (BSC) have no EIP-1559 base fee: quote a flat `gasPrice`. We map it into
        // the same fields the frontend/override path uses: max_fee = gasPrice, priority = 0.
        if chain_info(provider.chain_id()).legacy_gas {
            let gp = parse_hex_u256(&provider.gas_price().await?)?;
            return Ok(FeeSuggestion {
                base_fee: gp.to_string(),
                max_priority_fee: "0".to_string(),
                max_fee: gp.to_string(),
            });
        }

        // Base fee from the latest block via fee history; fall back to gasPrice.
        let (base_fee, tip) = match provider.fee_history().await {
            Ok(hist) => {
                let base = hist
                    .get("baseFeePerGas")
                    .and_then(|a| a.as_array())
                    .and_then(|a| a.last())
                    .and_then(|v| v.as_str())
                    .and_then(|s| parse_hex_u256(&serde_json::Value::String(s.to_string())).ok())
                    .unwrap_or(U256::ZERO);
                // priority fee: median of the returned rewards, fallback 1 gwei
                let tip = hist
                    .get("reward")
                    .and_then(|a| a.as_array())
                    .and_then(|rows| rows.last())
                    .and_then(|row| row.as_array())
                    .and_then(|cols| cols.get(1))
                    .and_then(|v| v.as_str())
                    .and_then(|s| parse_hex_u256(&serde_json::Value::String(s.to_string())).ok())
                    .unwrap_or(U256::from(1_000_000_000u64));
                (base, tip)
            }
            Err(_) => {
                let gp = parse_hex_u256(&provider.gas_price().await?)?;
                (gp, U256::from(1_000_000_000u64))
            }
        };
        // maxFee = 2*baseFee + tip (standard headroom for one base-fee bump)
        let max_fee = base_fee * U256::from(2u64) + tip;
        Ok(FeeSuggestion {
            base_fee: base_fee.to_string(),
            max_priority_fee: tip.to_string(),
            max_fee: max_fee.to_string(),
        })
    }

    /// Build, sign and broadcast a native ETH transfer. `fee` = optional (max_fee, max_priority)
    /// per gas in wei; `None` uses the node's automatic suggestion.
    pub async fn send_eth(
        &self,
        from_index: u32,
        to: &str,
        amount_wei: &str,
        fee: Option<(u128, u128)>,
    ) -> Result<SendResult> {
        let value = U256::from_str(amount_wei)
            .map_err(|_| CoreError::Amount(format!("invalid wei amount: {amount_wei}")))?;
        let to_addr = parse_address(to)?;
        self.build_sign_send(from_index, to_addr, value, Bytes::new(), None, fee)
            .await
    }

    /// Build, sign and broadcast an ERC20 `transfer`. `fee` as in [`send_eth`].
    pub async fn send_erc20(
        &self,
        from_index: u32,
        token: &str,
        to: &str,
        amount_units: &str,
        fee: Option<(u128, u128)>,
    ) -> Result<SendResult> {
        let amount = U256::from_str(amount_units)
            .map_err(|_| CoreError::Amount(format!("invalid token amount: {amount_units}")))?;
        let to_addr = parse_address(to)?;
        let token_addr = parse_address(token)?;
        let data = Bytes::from(erc20::encode_transfer(to_addr, amount));
        // Value is 0 for token transfers; the recipient of the tx is the token contract.
        self.build_sign_send(from_index, token_addr, U256::ZERO, data, None, fee)
            .await
    }

    /// Reconstruct ERC20 transfer history for `token`/`index` from event logs.
    ///
    /// Ethereum has no lightweight source for *native ETH* history (that needs an indexer);
    /// ERC20 history, however, is derivable trustlessly from `Transfer` logs. We query both
    /// outgoing (`from == owner`) and incoming (`to == owner`) and merge.
    pub async fn erc20_history(
        &self,
        token: &str,
        index: u32,
        from_block: &str,
    ) -> Result<Vec<HistoryItem>> {
        let provider = self.provider()?;
        let owner = parse_address(&self.address(index)?)?;
        let token_addr = parse_address(token)?.to_string();
        let (symbol, decimals) = self.erc20_metadata(token).await?;

        let topic0 = format!("0x{}", hex::encode(erc20::transfer_topic()));
        // address as a 32-byte topic (left-padded).
        let owner_topic = format!("0x{:0>64}", hex::encode(owner.as_slice()));

        let mut items = Vec::new();

        // Outgoing: topics = [Transfer, owner, *]
        let out_logs = provider
            .get_logs(serde_json::json!({
                "address": token_addr,
                "fromBlock": from_block,
                "toBlock": "latest",
                "topics": [topic0, owner_topic],
            }))
            .await?;
        self.collect_logs(&out_logs, "out", &symbol, decimals, &token_addr, &mut items)?;

        // Incoming: topics = [Transfer, *, owner]
        let in_logs = provider
            .get_logs(serde_json::json!({
                "address": token_addr,
                "fromBlock": from_block,
                "toBlock": "latest",
                "topics": [topic0, serde_json::Value::Null, owner_topic],
            }))
            .await?;
        self.collect_logs(&in_logs, "in", &symbol, decimals, &token_addr, &mut items)?;

        items.sort_by(|a, b| b.block.cmp(&a.block));
        Ok(items)
    }

    fn collect_logs(
        &self,
        logs: &serde_json::Value,
        direction: &str,
        symbol: &str,
        decimals: u8,
        token: &str,
        out: &mut Vec<HistoryItem>,
    ) -> Result<()> {
        let arr = logs.as_array().cloned().unwrap_or_default();
        for log in arr {
            let topics = log.get("topics").and_then(|t| t.as_array());
            let (Some(topics), Some(data)) = (topics, log.get("data").and_then(|d| d.as_str()))
            else {
                continue;
            };
            if topics.len() < 3 {
                continue;
            }
            let from = topic_to_address(topics[1].as_str().unwrap_or_default());
            let to = topic_to_address(topics[2].as_str().unwrap_or_default());
            let counterparty = if direction == "out" { to } else { from };
            let amount =
                U256::from_str(data.trim()).or_else(|_| parse_hex_u256_str(data)).unwrap_or(U256::ZERO);
            let block = log
                .get("blockNumber")
                .and_then(|b| b.as_str())
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            let tx_hash = log
                .get("transactionHash")
                .and_then(|h| h.as_str())
                .unwrap_or_default()
                .to_string();
            out.push(HistoryItem {
                direction: direction.to_string(),
                counterparty,
                amount: amount.to_string(),
                formatted: format_units(amount, decimals),
                tx_hash,
                block,
                token: token.to_string(),
                symbol: symbol.to_string(),
                ..Default::default()
            });
        }
        Ok(())
    }

    /// Full account history (native + all ERC20 transfers) fetched from the chain's Blockscout
    /// (Etherscan-compatible, keyless) API over the same Tor transport. Chains without a keyless
    /// explorer (see `chains::chain_info`) return an empty history.
    pub async fn account_history(&self, index: u32) -> Result<Vec<HistoryItem>> {
        let provider = self.provider()?;
        let info = chain_info(provider.chain_id());
        let owner = self.address(index)?.to_lowercase();

        let Some(bs) = info.blockscout_base else {
            return Ok(Vec::new()); // no keyless explorer for this chain
        };
        let base = format!("{bs}/api?module=account");
        let base = base.as_str();

        let mut items: Vec<HistoryItem> = Vec::new();

        // Native ETH transactions — ALL pages, so an old wallet's early history (e.g. 2021) isn't
        // truncated to the most recent 100.
        for r in fetch_all_pages(provider, base, "txlist", &owner).await {
            let s = |k: &str| r.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            let to = s("to").to_lowercase();
            let dir = if to == owner { "in" } else { "out" };
            let value = U256::from_str(&s("value")).unwrap_or(U256::ZERO);
            let gas_price = u128::from_str(&s("gasPrice")).unwrap_or(0);
            let gas_used = u128::from_str(&s("gasUsed")).unwrap_or(0);
            items.push(HistoryItem {
                direction: dir.to_string(),
                counterparty: if dir == "in" { s("from") } else { s("to") },
                amount: value.to_string(),
                formatted: format_units(value, 18),
                tx_hash: s("hash"),
                block: s("blockNumber").parse().unwrap_or(0),
                token: String::new(),
                symbol: info.native_symbol.to_string(),
                timestamp: s("timeStamp").parse().unwrap_or(0),
                fee: (gas_price.saturating_mul(gas_used)).to_string(),
                failed: s("isError") == "1" || s("txreceipt_status") == "0",
            });
        }

        // ERC20 token transfers — ALL pages.
        for r in fetch_all_pages(provider, base, "tokentx", &owner).await {
            let s = |k: &str| r.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            let to = s("to").to_lowercase();
            let dir = if to == owner { "in" } else { "out" };
            let decimals: u8 = s("tokenDecimal").parse().unwrap_or(18);
            let value = U256::from_str(&s("value")).unwrap_or(U256::ZERO);
            items.push(HistoryItem {
                direction: dir.to_string(),
                counterparty: if dir == "in" { s("from") } else { s("to") },
                amount: value.to_string(),
                formatted: format_units(value, decimals),
                tx_hash: s("hash"),
                block: s("blockNumber").parse().unwrap_or(0),
                token: s("contractAddress"),
                symbol: s("tokenSymbol"),
                timestamp: s("timeStamp").parse().unwrap_or(0),
                fee: String::new(),
                failed: false,
            });
        }

        // Drop exact-duplicate rows (same tx + asset + direction + amount) in case the explorer
        // returns overlapping entries; legitimately-distinct transfers (different hash/token/amount,
        // e.g. a swap moving two assets in one tx) are preserved.
        let mut seen = std::collections::HashSet::new();
        items.retain(|h| {
            seen.insert(format!("{}|{}|{}|{}", h.tx_hash, h.token, h.direction, h.amount))
        });

        items.sort_by(|a, b| b.block.cmp(&a.block));
        Ok(items)
    }

    /// Owned NFT collections (ERC-721 + ERC-1155) for `index`, from Blockscout's v2 API over Tor.
    /// Includes each collection's `reputation` so the UI can hide spam. Mainnet only.
    pub async fn account_nfts(&self, index: u32) -> Result<Vec<NftCollection>> {
        let provider = self.provider()?;
        let Some(bs) = chain_info(provider.chain_id()).blockscout_base else {
            return Ok(Vec::new()); // no keyless explorer for this chain
        };
        let owner = self.address(index)?;
        let url = format!("{bs}/api/v2/addresses/{owner}/nft/collections?type=ERC-721,ERC-1155");
        let v = provider.http_get_json(&url).await?;
        let mut out = Vec::new();
        if let Some(items) = v.get("items").and_then(|i| i.as_array()) {
            for it in items {
                let token = it.get("token");
                let g = |k: &str| {
                    token
                        .and_then(|t| t.get(k))
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string()
                };
                let count = it
                    .get("amount")
                    .and_then(|a| a.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .or_else(|| {
                        it.get("token_instances")
                            .and_then(|ti| ti.as_array())
                            .map(|a| a.len() as u64)
                    })
                    .unwrap_or(0);
                let image_url = it
                    .get("token_instances")
                    .and_then(|ti| ti.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|inst| inst.get("image_url"))
                    .and_then(|u| u.as_str())
                    .unwrap_or("")
                    .to_string();
                out.push(NftCollection {
                    name: g("name"),
                    symbol: g("symbol"),
                    address: g("address_hash"),
                    token_type: g("type"),
                    reputation: g("reputation"),
                    count,
                    image_url,
                });
            }
        }
        Ok(out)
    }

    /// Fetch an image URL over Tor and return it hex-encoded (empty on error / oversized). Used for
    /// NFT thumbnails so remote fetches never leak the user's IP.
    pub async fn fetch_image_hex(&self, url: &str) -> Result<String> {
        let bytes = self.provider()?.http_get_bytes(url).await?;
        if bytes.len() > 3_000_000 {
            return Err(CoreError::rpc("image too large"));
        }
        Ok(hex::encode(bytes))
    }

    /// Produce the signature for an already-built transaction: locally for software wallets, or via
    /// the device for hardware wallets (Ledger reuses alloy's tx encoding; Trezor gets decomposed
    /// fields). `max_fee_per_gas` doubles as the legacy `gasPrice`.
    #[allow(clippy::too_many_arguments)]
    async fn sign_built_tx(
        &self,
        index: u32,
        chain_id: u64,
        legacy: bool,
        tx: &mut dyn SignableTransaction<alloy::primitives::Signature>,
        nonce: u64,
        gas_limit: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        to: Address,
        value: U256,
        data: &[u8],
    ) -> Result<alloy::primitives::Signature> {
        match &self.keys {
            KeySource::Software(_) => {
                let signer = self.local_signer(index)?;
                let sighash = tx.signature_hash();
                signer
                    .sign_hash_sync(&sighash)
                    .map_err(|e| CoreError::Signing(e.to_string()))
            }
            KeySource::Hardware(ctx) => {
                let hd = self.hd_index(index)?;
                match ctx.kind {
                    HwKind::Ledger => hardware::ledger_sign_tx(hd, chain_id, &*tx).await,
                    HwKind::Trezor => {
                        hardware::trezor_sign_tx(
                            &ctx.passphrase, hd, legacy, nonce, gas_limit,
                            max_fee_per_gas, /* gas_price (legacy) */
                            max_fee_per_gas, /* max_fee (eip1559) */
                            max_priority_fee_per_gas, to, value, data, chain_id,
                        )
                        .await
                    }
                }
            }
        }
    }

    async fn build_sign_send(
        &self,
        from_index: u32,
        to: Address,
        value: U256,
        data: Bytes,
        gas_limit_override: Option<u64>,
        fee_override: Option<(u128, u128)>, // (max_fee_per_gas, max_priority_fee_per_gas)
    ) -> Result<SendResult> {
        let provider = self.provider()?;
        // The sending address comes from the account's derivation (software) or the device's cached
        // address (hardware) — no local key material is required to build the tx.
        let from: Address = parse_address(&self.address(from_index)?)?;

        let nonce_hex = provider.get_transaction_count(&from.to_string()).await?;
        let nonce = parse_hex_u64(&nonce_hex)?;

        // Use the caller's chosen fee (custom / tier) if given, else the node suggestion.
        let (max_fee_per_gas, max_priority_fee_per_gas) = match fee_override {
            Some((mf, mp)) => (mf, mp),
            None => {
                let fees = self.suggest_fees().await?;
                let mp = u128::from_str(&fees.max_priority_fee)
                    .map_err(|_| CoreError::Amount("bad tip".into()))?;
                let mf = u128::from_str(&fees.max_fee)
                    .map_err(|_| CoreError::Amount("bad maxfee".into()))?;
                (mf, mp)
            }
        };

        let gas_limit = match gas_limit_override {
            Some(g) => g,
            None => {
                let est = provider
                    .estimate_gas(serde_json::json!({
                        "from": from.to_string(),
                        "to": to.to_string(),
                        "value": format!("0x{:x}", value),
                        "data": format!("0x{}", hex::encode(&data)),
                    }))
                    .await?;
                // add ~25% headroom
                let g = parse_hex_u64(&est)?;
                g + g / 4
            }
        };

        let chain_id = provider.chain_id();
        // Legacy-gas chains (e.g. BNB Smart Chain) don't support EIP-1559; use a type-0 tx whose
        // `gasPrice` is the caller's max-fee (fee override plumbing maps tier/custom -> max_fee).
        let raw = if chain_info(chain_id).legacy_gas {
            let mut tx = TxLegacy {
                chain_id: Some(chain_id),
                nonce,
                gas_price: max_fee_per_gas,
                gas_limit,
                to: TxKind::Call(to),
                value,
                input: data.clone(),
            };
            let signature = self
                .sign_built_tx(
                    from_index, chain_id, true, &mut tx, nonce, gas_limit, max_fee_per_gas,
                    max_priority_fee_per_gas, to, value, &data,
                )
                .await?;
            let envelope: TxEnvelope = tx.into_signed(signature).into();
            envelope.encoded_2718()
        } else {
            let mut tx = TxEip1559 {
                chain_id,
                nonce,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                to: TxKind::Call(to),
                value,
                access_list: Default::default(),
                input: data.clone(),
            };
            let signature = self
                .sign_built_tx(
                    from_index, chain_id, false, &mut tx, nonce, gas_limit, max_fee_per_gas,
                    max_priority_fee_per_gas, to, value, &data,
                )
                .await?;
            let envelope: TxEnvelope = tx.into_signed(signature).into();
            envelope.encoded_2718()
        };
        let raw_hex = format!("0x{}", hex::encode(raw));

        let result = provider.send_raw_transaction(&raw_hex).await?;
        let tx_hash = result
            .as_str()
            .ok_or_else(|| CoreError::rpc("broadcast returned no hash"))?
            .to_string();
        Ok(SendResult { tx_hash })
    }
}

// ---------- helpers ----------

/// Ensure `secrets.account_order` is populated. Older wallet files (and freshly-built secrets) have
/// no order; reconstruct the historical layout — HD accounts `0..account_count` followed by the
/// imported keys — which preserves every account's existing index while making future
/// `add_account`/`import_private_key` calls append without shifting anything.
fn normalize_account_order(secrets: &mut WalletSecrets) {
    if !secrets.account_order.is_empty() {
        return;
    }
    let hd = secrets.account_count.max(1);
    secrets.account_count = hd;
    let mut order = Vec::with_capacity(hd as usize + secrets.imported_keys.len());
    for i in 0..hd {
        order.push(AccountEntry::Hd(i));
    }
    for j in 0..secrets.imported_keys.len() {
        order.push(AccountEntry::Imported(j));
    }
    secrets.account_order = order;
}

/// Fetch every page of an Etherscan-compatible list endpoint (txlist / tokentx), so history isn't
/// truncated to the most recent page. Stops at the first short/empty page or on error, with a hard
/// cap so a pathological account can't loop forever.
async fn fetch_all_pages(
    provider: &RpcProvider,
    base: &str,
    action: &str,
    owner: &str,
) -> Vec<serde_json::Value> {
    const PER_PAGE: usize = 1000;
    const MAX_PAGES: u32 = 25; // up to 25k txs per list — plenty, and bounds Tor round-trips
    let mut out = Vec::new();
    for page in 1..=MAX_PAGES {
        let url = format!(
            "{base}&action={action}&address={owner}&sort=desc&page={page}&offset={PER_PAGE}"
        );
        match provider.http_get_json(&url).await {
            Ok(v) => match v.get("result").and_then(|r| r.as_array()) {
                Some(rows) => {
                    let n = rows.len();
                    out.extend(rows.iter().cloned());
                    if n < PER_PAGE {
                        break; // last page reached
                    }
                }
                None => break, // "No transactions found" / error message => done
            },
            Err(_) => break,
        }
    }
    out
}

fn parse_address(s: &str) -> Result<Address> {
    Address::from_str(s.trim()).map_err(|_| CoreError::Address(s.to_string()))
}

fn parse_hex_u256(v: &serde_json::Value) -> Result<U256> {
    let s = v
        .as_str()
        .ok_or_else(|| CoreError::rpc("expected hex string"))?;
    U256::from_str(s).map_err(|e| CoreError::rpc(format!("bad hex u256 {s}: {e}")))
}

fn parse_hex_u64(v: &serde_json::Value) -> Result<u64> {
    let s = v
        .as_str()
        .ok_or_else(|| CoreError::rpc("expected hex string"))?;
    let s = s.trim_start_matches("0x");
    u64::from_str_radix(s, 16).map_err(|e| CoreError::rpc(format!("bad hex u64: {e}")))
}

fn parse_hex_u256_str(s: &str) -> Result<U256> {
    U256::from_str(s.trim()).map_err(|e| CoreError::rpc(format!("bad hex u256 {s}: {e}")))
}

/// Convert a 32-byte log topic (0x-prefixed) into a checksummed 0x address (last 20 bytes).
fn topic_to_address(topic: &str) -> String {
    let clean = topic.trim_start_matches("0x");
    if clean.len() < 40 {
        return String::from("0x");
    }
    let addr_hex = &clean[clean.len() - 40..];
    match Address::from_str(&format!("0x{addr_hex}")) {
        Ok(a) => a.to_checksum(None),
        Err(_) => format!("0x{addr_hex}"),
    }
}

fn hex_bytes(v: &serde_json::Value) -> Result<Vec<u8>> {
    let s = v
        .as_str()
        .ok_or_else(|| CoreError::rpc("expected hex string"))?;
    hex::decode(s.trim_start_matches("0x")).map_err(|e| CoreError::rpc(format!("bad hex: {e}")))
}

/// Format an integer amount with `decimals` into a human-readable decimal string.
pub fn format_units(value: U256, decimals: u8) -> String {
    let base = U256::from(10u64).pow(U256::from(decimals as u64));
    let whole = value / base;
    let frac = value % base;
    if frac.is_zero() {
        return whole.to_string();
    }
    let frac_str = format!("{:0width$}", frac, width = decimals as usize);
    let frac_trimmed = frac_str.trim_end_matches('0');
    format!("{whole}.{frac_trimmed}")
}

/// Parse a decimal string (e.g. "1.25") into an integer amount with `decimals`.
pub fn parse_units(amount: &str, decimals: u8) -> Result<U256> {
    let amount = amount.trim();
    let (whole, frac) = match amount.split_once('.') {
        Some((w, f)) => (w, f),
        None => (amount, ""),
    };
    if frac.len() > decimals as usize {
        return Err(CoreError::Amount(format!(
            "too many decimal places (max {decimals})"
        )));
    }
    let mut combined = String::from(whole);
    combined.push_str(frac);
    for _ in 0..(decimals as usize - frac.len()) {
        combined.push('0');
    }
    let combined = combined.trim_start_matches('0');
    let combined = if combined.is_empty() { "0" } else { combined };
    U256::from_str(combined).map_err(|e| CoreError::Amount(format!("invalid amount {amount}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_deterministic() {
        let mut w = Wallet::restore("test test test test test test test test test test test junk").unwrap();
        w.add_account(); // create account #1 so it is part of the HD range
        assert_eq!(
            w.address(0).unwrap().to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
        assert_eq!(
            w.address(1).unwrap().to_lowercase(),
            "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
        );
    }

    #[test]
    fn passphrase_persists_across_save_open() {
        let phrase = "test test test test test test test test test test test junk";
        let plain_addr = Wallet::restore(phrase).unwrap().address(0).unwrap();

        let w = Wallet::restore_with_passphrase(phrase, "s3cret").unwrap();
        assert!(w.has_passphrase());
        let pass_addr = w.address(0).unwrap();
        assert_ne!(plain_addr, pass_addr, "passphrase must change the address");

        // Save and reopen: the stored passphrase must re-derive the identical address.
        let mut path = std::env::temp_dir();
        path.push(format!("aero_pass_{}.aero", std::process::id()));
        let p = path.to_str().unwrap();
        w.save(p, "filepw").unwrap();

        let reopened = Wallet::open(p, "filepw").unwrap();
        assert!(reopened.has_passphrase());
        assert_eq!(reopened.address(0).unwrap(), pass_addr);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn add_account_after_import_keeps_indices_stable() {
        // Importing a key then adding an HD account must NOT change the imported account's index
        // or address (regression: the old HD/imported boundary shifted imported keys).
        let mut w = Wallet::restore("test test test test test test test test test test test junk").unwrap();
        let imported_idx = w
            .import_private_key("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
            .unwrap();
        let imported_addr = w.address(imported_idx).unwrap();

        let hd_idx = w.add_account(); // add an HD account AFTER the import
        assert_ne!(hd_idx, imported_idx);
        // The imported account is untouched: same index -> same address, still its own key.
        assert_eq!(w.address(imported_idx).unwrap(), imported_addr);
        assert_eq!(
            imported_addr.to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[test]
    fn import_private_key_adds_account() {
        let mut w = Wallet::create_new(WordCount::Words12).unwrap();
        let before = w.account_count();
        // Anvil account #0 private key -> 0xf39F...2266
        let idx = w
            .import_private_key("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
            .unwrap();
        assert_eq!(w.account_count(), before + 1);
        assert_eq!(
            w.address(idx).unwrap().to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[test]
    fn units_round_trip() {
        let wei = parse_units("1.5", 18).unwrap();
        assert_eq!(wei.to_string(), "1500000000000000000");
        assert_eq!(format_units(wei, 18), "1.5");
        assert_eq!(format_units(U256::from(1_000_000u64), 6), "1");
    }

    #[test]
    fn create_new_has_one_account() {
        let w = Wallet::create_new(WordCount::Words12).unwrap();
        assert_eq!(w.account_count(), 1);
        assert!(w.address(0).unwrap().starts_with("0x"));
    }
}
