//! High-level wallet: aggregates HD keys, the encrypted keystore, the Tor-routed provider,
//! and EIP-1559 transaction building/signing. This is the surface the C ABI (and the Qt
//! frontend) is built on, mirroring the role of Feather's `libwalletqt` `Wallet` class.

use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol;
use alloy::sol_types::{eip712_domain, SolCall, SolStruct};
use serde::Serialize;

use crate::chains;
use crate::chains::chain_info;
use crate::erc20;
use crate::error::{CoreError, Result};
use crate::hardware::{self, HwKind};
use crate::keys::{SeedPhrase, WordCount};
use crate::keystore::{self, AccountEntry, HwDescriptor, TokenRef, WalletSecrets};
use crate::provider::{ProviderConfig, RpcProvider};

// ---- Funded-scan live progress -------------------------------------------------------------
// Bumped by scan_funded so the UI can poll "N addresses checked, M funded" while the (long) scan
// runs on the runtime thread. Plain atomics (NOT thread-local) because the scan and the UI poll
// are on different threads. Reset by the FFI entry points before a scan starts.
pub static SCAN_CHECKED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static SCAN_FOUND: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// ---- CoW Protocol swap constants + types ---------------------------------------------------
// Same addresses on every chain CoW is deployed to.
const COW_SETTLEMENT: &str = "0x9008D19f58AAbD9eD0D60971565AA8510560ab41"; // EIP-712 verifyingContract
const COW_VAULT_RELAYER: &str = "0xC92E8bdf79f0507f65a392b0ab4667716BFE0110"; // approval target
/// Sentinel used in `buyToken` to receive native ETH (CoW unwraps WETH for you).
pub const COW_BUY_ETH: &str = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";

// ---- Multi-router (keyless) swap aggregator ------------------------------------------------
const KYBER_API: &str = "https://aggregator-api.kyberswap.com";
const ODOS_API: &str = "https://api.odos.xyz";
const PARASWAP_API: &str = "https://apiv5.paraswap.io";
const OPENOCEAN_API: &str = "https://open-api.openocean.finance";
/// Native-token sentinel used by KyberSwap / Paraswap / OpenOcean.
const EVM_NATIVE_SENTINEL: &str = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
/// Odos represents the native coin with the zero address.
const ODOS_NATIVE: &str = "0x0000000000000000000000000000000000000000";

/// Multicall3 — deployed at the same canonical address on every major EVM chain (incl. testnets).
/// We use `aggregate3Value` to send native coin to many recipients atomically in ONE transaction.
const MULTICALL3: &str = "0xcA11bde05977b3631167028862bE2a173976CA11";

alloy::sol! {
    struct Call3Value {
        address target;
        bool allowFailure;
        uint256 value;
        bytes callData;
    }
    function aggregate3Value(Call3Value[] calls) payable returns (bytes[] returnData);
}

/// A router quote/route normalized so the UI is router-agnostic.
#[derive(serde::Serialize, Clone, Default)]
pub struct RouterQuote {
    pub router_id: String,   // "cow" | "kyberswap" | "odos" | "paraswap" | "openocean"
    pub label: String,       // display name
    pub buy_amount: String,  // expected out, in buy-token base units (wei)
    pub gas_usd: f64,        // router-reported gas cost (USD), 0 if unknown/gasless
    pub gas_estimate: String, // gas units (best-effort), "0" if unknown/gasless
    pub spender: String,     // approval target ("" if unknown until build)
    pub to: String,          // tx target ("" for CoW signed order / unknown until build)
    pub kind: String,        // "signed-order" | "onchain"
}

/// Read a JSON value that may be a numeric string or a number as a plain decimal string.
fn json_num_str(v: &serde_json::Value) -> String {
    if let Some(s) = v.as_str() {
        s.to_string()
    } else if v.is_number() {
        v.to_string()
    } else {
        String::new()
    }
}

sol! {
    // GPv2Order.Data as the EIP-712 typed struct CoW signs. The struct MUST be named `Order` so the
    // EIP-712 type hash matches CoW's. `kind`/`sellTokenBalance`/`buyTokenBalance` hash as strings.
    #[allow(missing_docs)]
    struct Order {
        address sellToken;
        address buyToken;
        address receiver;
        uint256 sellAmount;
        uint256 buyAmount;
        uint32 validTo;
        bytes32 appData;
        uint256 feeAmount;
        string kind;
        bool partiallyFillable;
        string sellTokenBalance;
        string buyTokenBalance;
    }

    // CoW eth-flow: sell native ETH by depositing it into the eth-flow contract, which wraps +
    // places the order on your behalf.
    #[allow(missing_docs)]
    struct EthFlowData {
        address buyToken;
        address receiver;
        uint256 sellAmount;
        uint256 buyAmount;
        bytes32 appData;
        uint256 feeAmount;
        uint32 validTo;
        bool partiallyFillable;
        int64 quoteId;
    }
    #[allow(missing_docs)]
    interface IEthFlow {
        function createOrder(EthFlowData order) external payable returns (bytes32);
    }
}

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
#[derive(Serialize, Clone)]
pub struct FeeSuggestion {
    pub base_fee: String,
    pub max_priority_fee: String,
    pub max_fee: String,
}

/// Result of broadcasting a transaction.
#[derive(Serialize)]
pub struct SendResult {
    pub tx_hash: String,
    /// Nonce the transaction was broadcast at — needed to later speed-up or cancel it (a replacement
    /// reuses the same nonce with higher gas).
    pub nonce: u64,
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
    // ---- Swap rows (kind == "swap") ----
    #[serde(default)]
    pub kind: String, // "" for a normal transfer, "swap" for a swap row
    #[serde(default)]
    pub buy_symbol: String, // swap: symbol received (sell side reuses `symbol`/`formatted`/`token`)
    #[serde(default)]
    pub buy_formatted: String, // swap: human amount received
    #[serde(default)]
    pub status: String, // swap: "pending" | "done" | "failed"
    // Per-tx log index of a token transfer (Etherscan `logIndex`); used only to disambiguate two
    // legitimate identical transfers in the SAME tx during dedup. Internal to the core.
    #[serde(skip)]
    pub log_index: u64,
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
    /// Watch-only: no keys at all. Addresses come from `secrets.watch_addresses`; balances and
    /// history work but any signing/sending is refused.
    WatchOnly,
}

struct HwContext {
    kind: HwKind,
    passphrase: String, // host-entered (Trezor); empty/ignored for Ledger
}

/// Short-TTL caches for pure, read-only network lookups that several UI triggers hit repeatedly
/// (connect, tab switches, per-block refresh). Serving a recent value avoids re-opening a Tor
/// stream for data that barely changes over a few seconds — fewer requests = a healthier circuit.
/// Keyed by chain id so a network switch never returns another chain's value. Locks are only ever
/// held to copy the cached value in/out, NEVER across a network await.
#[derive(Default)]
struct NetCaches {
    native_price: Mutex<Option<(Instant, u64, f64)>>, // (fetched_at, chain_id, usd)
    fees: Mutex<Option<(Instant, u64, FeeSuggestion)>>, // (fetched_at, chain_id, fee)
}

pub struct Wallet {
    secrets: WalletSecrets,
    keys: KeySource,
    provider: Option<RpcProvider>,
    provider_cfg: ProviderConfig,
    caches: NetCaches,
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
            watch_addresses: Vec::new(),
            metadata: String::new(),
        };
        normalize_account_order(&mut secrets);
        Ok(Self {
            secrets,
            keys: KeySource::Software(seed),
            provider: None,
            provider_cfg: ProviderConfig::default(),
            caches: NetCaches::default(),
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
            watch_addresses: Vec::new(),
            metadata: String::new(),
        };
        Ok(Self {
            secrets,
            keys: KeySource::Hardware(HwContext { kind, passphrase: passphrase.to_string() }),
            provider: None,
            provider_cfg: ProviderConfig::default(),
            caches: NetCaches::default(),
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
            // An empty stored address list must NOT skip verification (that would open the wallet
            // against any connected device/passphrase) — treat it as a mismatch.
            let expected = hw.addresses.first().cloned().unwrap_or_default();
            if expected.is_empty() || !derived.eq_ignore_ascii_case(&expected) {
                return Err(CoreError::rpc(
                    "hardware device/passphrase does not match this wallet".to_string(),
                ));
            }
            return Ok(Self {
                secrets,
                keys: KeySource::Hardware(HwContext { kind, passphrase: passphrase.to_string() }),
                provider: None,
                provider_cfg: ProviderConfig::default(),
                caches: NetCaches::default(),
            });
        }

        // Watch-only: no keys, just the tracked addresses.
        if !secrets.watch_addresses.is_empty() {
            return Ok(Self {
                keys: KeySource::WatchOnly,
                provider: None,
                provider_cfg: ProviderConfig::default(),
                secrets,
                caches: NetCaches::default(),
            });
        }

        // Software: re-attach the stored passphrase so HD addresses derive identically.
        let seed = SeedPhrase::parse(&secrets.mnemonic)?.with_passphrase(&secrets.passphrase);
        Ok(Self {
            keys: KeySource::Software(seed),
            provider: None,
            provider_cfg: ProviderConfig::default(),
            secrets,
            caches: NetCaches::default(),
        })
    }

    /// Create an address-only watch wallet from one or more 0x addresses. No keys are stored, so
    /// balances/history work but signing/sending is refused. Addresses are validated + checksummed.
    pub fn watch_only(addresses: &[String]) -> Result<Self> {
        let mut addrs: Vec<String> = Vec::new();
        for a in addresses {
            let a = a.trim();
            if a.is_empty() {
                continue;
            }
            addrs.push(parse_address(a)?.to_checksum(None));
        }
        if addrs.is_empty() {
            return Err(CoreError::rpc("no valid addresses to watch".to_string()));
        }
        let n = addrs.len() as u32;
        let account_order = (0..n).map(AccountEntry::Hd).collect();
        let secrets = WalletSecrets {
            mnemonic: String::new(),
            passphrase: String::new(),
            account_count: n,
            account_order,
            tokens: Vec::new(),
            imported_keys: Vec::new(),
            hardware: None,
            watch_addresses: addrs,
            metadata: String::new(),
        };
        Ok(Self {
            secrets,
            keys: KeySource::WatchOnly,
            provider: None,
            provider_cfg: ProviderConfig::default(),
            caches: NetCaches::default(),
        })
    }

    /// Whether this is an address-only watch wallet (no keys; can't sign/send).
    pub fn is_watch_only(&self) -> bool {
        matches!(self.keys, KeySource::WatchOnly)
    }

    /// Whether this is a hardware wallet.
    pub fn is_hardware(&self) -> bool {
        matches!(self.keys, KeySource::Hardware(_))
    }

    /// Hardware device kind ("ledger"/"trezor"), or "" for software wallets.
    pub fn hw_kind(&self) -> &str {
        match &self.keys {
            KeySource::Hardware(ctx) => ctx.kind.as_str(),
            KeySource::Software(_) | KeySource::WatchOnly => "",
        }
    }

    pub fn save(&self, path: &str, password: &str) -> Result<()> {
        let blob = keystore::encrypt(&self.secrets, password)?;
        atomic_write(path, &blob)?;
        Ok(())
    }

    // ---------- accounts / keys ----------

    /// Seed phrase for software wallets; "" for hardware wallets (no seed on this machine).
    pub fn mnemonic(&self) -> &str {
        match &self.keys {
            KeySource::Software(seed) => seed.as_str(),
            KeySource::Hardware(_) | KeySource::WatchOnly => "",
        }
    }

    /// Whether this wallet is protected by a BIP39 passphrase.
    pub fn has_passphrase(&self) -> bool {
        match &self.keys {
            KeySource::Software(seed) => seed.has_passphrase(),
            KeySource::Hardware(ctx) => !ctx.passphrase.is_empty(),
            KeySource::WatchOnly => false,
        }
    }

    /// Total accounts shown to the user (HD + imported), in stable order.
    pub fn account_count(&self) -> u32 {
        self.secrets.account_order.len() as u32
    }

    /// Append a new HD account and return its (stable) unified index.
    pub fn add_account(&mut self) -> u32 {
        if matches!(self.keys, KeySource::WatchOnly) {
            return self.account_count().saturating_sub(1); // no keys to derive from — no-op
        }
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
            KeySource::WatchOnly => {
                return Err(CoreError::Signing(
                    "watch-only wallet: no private keys (cannot sign or send)".into(),
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
            KeySource::WatchOnly => self
                .secrets
                .watch_addresses
                .get(index as usize)
                .cloned()
                .ok_or_else(|| CoreError::Derivation(format!("no account at index {index}"))),
        }
    }

    /// Export the raw private key (0x-prefixed hex) for an account index. Handle with care.
    /// Unavailable for hardware wallets (the key never leaves the device).
    pub fn export_private_key(&self, index: u32) -> Result<String> {
        let signer = self.local_signer(index)?;
        Ok(format!("0x{}", hex::encode(signer.to_bytes())))
    }

    /// Sign a UTF-8 message with EIP-191 (`personal_sign`) using account `index`.
    /// Returns a 0x-prefixed 65-byte signature. Unavailable for hardware wallets here.
    pub fn sign_message(&self, index: u32, message: &str) -> Result<String> {
        // Hardware wallets: on-device personal_sign isn't wired yet (the Ledger signer's message API
        // sits behind a conflicting alloy_signer version in the dependency graph). Transaction signing
        // on-device works; message signing needs a software account for now.
        if matches!(&self.keys, KeySource::Hardware(_)) {
            return Err(CoreError::Signing(
                "message signing on a hardware wallet isn't supported yet — use a software account"
                    .into(),
            ));
        }
        let signer = self.local_signer(index)?; // errors for watch-only
        let sig = signer
            .sign_message_sync(message.as_bytes())
            .map_err(|e| CoreError::Signing(format!("sign message: {e}")))?;
        Ok(format!("0x{}", hex::encode(sig.as_bytes())))
    }

    /// Recover the address that produced an EIP-191 (`personal_sign`) signature over `message`.
    /// Returns the recovered, checksummed address so the caller can compare it to who they expected.
    /// This is a pure function (no keys involved) — hence `&self` isn't required.
    pub fn verify_message(message: &str, signature: &str) -> Result<String> {
        let hexs = signature.trim().trim_start_matches("0x").trim_start_matches("0X");
        let bytes = hex::decode(hexs)
            .map_err(|e| CoreError::Signing(format!("bad signature hex: {e}")))?;
        let sig = alloy::primitives::Signature::try_from(bytes.as_slice())
            .map_err(|e| CoreError::Signing(format!("bad signature: {e}")))?;
        let addr = sig
            .recover_address_from_msg(message.as_bytes())
            .map_err(|e| CoreError::Signing(format!("could not recover signer: {e}")))?;
        Ok(addr.to_checksum(None))
    }

    /// Derive and append one more hardware account from the device; returns its unified index.
    pub async fn add_hardware_account(&mut self) -> Result<u32> {
        let ctx = match &self.keys {
            KeySource::Hardware(ctx) => ctx,
            KeySource::Software(_) | KeySource::WatchOnly => {
                return Err(CoreError::rpc("not a hardware wallet"))
            }
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

    /// Frontend-owned per-wallet metadata JSON (labels/contacts/notes/funded), encrypted at rest.
    pub fn metadata(&self) -> &str {
        &self.secrets.metadata
    }

    /// Replace the per-wallet metadata blob. Persisted (encrypted) on the next `save`.
    pub fn set_metadata(&mut self, json: &str) {
        self.secrets.metadata = json.to_string();
    }

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

    /// Fetch native + tracked-token balances for accounts `0..num_accounts` in ONE batched
    /// JSON-RPC request (chunked to stay under public-RPC batch caps). This replaces the old
    /// per-account × per-token fan-out (which opened dozens of independent Tor circuits and made
    /// balances trickle in), so everything lands together in a couple of round-trips.
    ///
    /// Returns `{ "native_symbol": "...", "accounts": [ { index, native_raw, native_formatted,
    /// native_symbol, tokens: [ { address, symbol, decimals, raw, formatted } ] } ] }`.
    /// `extra_tokens_json` (may be empty) is a JSON array `[{address,symbol,decimals}]` of additional
    /// tokens to include in the balance read — e.g. the current chain's curated tokens — so the
    /// Send/Swap pickers show balances immediately without the user having to permanently track each
    /// token. Extras are fetched, never persisted.
    pub async fn all_balances(&self, num_accounts: u32, extra_tokens_json: &str) -> Result<serde_json::Value> {
        let provider = self.provider()?;
        let native_symbol = chain_info(provider.chain_id()).native_symbol.to_string();
        let n = num_accounts.max(1);

        // Resolve every account address once (works for both software and hardware — the latter
        // reads its cached device addresses, no device round-trip here).
        // A single unresolvable account must not blank every balance — skip it rather than error.
        let mut addrs: Vec<(u32, Address)> = Vec::with_capacity(n as usize);
        for i in 0..n {
            if let Ok(a) = self.address(i).and_then(|s| parse_address(&s)) {
                addrs.push((i, a));
            }
        }

        // Tracked tokens PLUS caller-supplied extras (current chain's curated tokens), deduped by
        // address. Owned (address, symbol, decimals, parsed) so extras needn't be persisted.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut tokens: Vec<(String, String, u8, Address)> = Vec::new();
        for t in &self.secrets.tokens {
            if let Ok(a) = parse_address(&t.address) {
                if seen.insert(t.address.to_lowercase()) {
                    tokens.push((t.address.clone(), t.symbol.clone(), t.decimals, a));
                }
            }
        }
        if !extra_tokens_json.trim().is_empty() {
            if let Ok(serde_json::Value::Array(arr)) =
                serde_json::from_str::<serde_json::Value>(extra_tokens_json)
            {
                for e in arr {
                    let address =
                        e.get("address").and_then(|x| x.as_str()).unwrap_or_default().to_string();
                    let symbol =
                        e.get("symbol").and_then(|x| x.as_str()).unwrap_or_default().to_string();
                    let decimals = e.get("decimals").and_then(|x| x.as_u64()).unwrap_or(18) as u8;
                    if let Ok(a) = parse_address(&address) {
                        if seen.insert(address.to_lowercase()) {
                            tokens.push((address, symbol, decimals, a));
                        }
                    }
                }
            }
        }
        let per_addr = 1 + tokens.len();

        // Chunk accounts so each batch stays comfortably under public-RPC limits (~40 calls).
        let per_chunk = (40usize / per_addr).max(1);
        let mut accounts_json: Vec<serde_json::Value> = Vec::with_capacity(addrs.len());

        for group in addrs.chunks(per_chunk) {
            let mut calls: Vec<(String, serde_json::Value)> =
                Vec::with_capacity(group.len() * per_addr);
            for (_, a) in group {
                calls.push((
                    "eth_getBalance".to_string(),
                    serde_json::json!([a.to_string(), "latest"]),
                ));
                for (_, _, _, taddr) in &tokens {
                    let data = format!("0x{}", hex::encode(erc20::encode_balance_of(*a)));
                    calls.push((
                        "eth_call".to_string(),
                        serde_json::json!([{ "to": taddr.to_string(), "data": data }, "latest"]),
                    ));
                }
            }
            let results = provider.call_batch(&calls).await?;

            for (p, (idx, _)) in group.iter().enumerate() {
                let base = p * per_addr;
                // A failed/absent RPC read (Value::Null) must NOT be reported as a real 0 balance —
                // otherwise a transient Tor/RPC hiccup makes the balance flicker to 0 and the next
                // successful read looks like an incoming payment. Mark it not-ok so the UI keeps its
                // cached value instead of clobbering it (and spamming "received" notifications).
                let native_res = results.get(base).and_then(|v| parse_hex_u256(v).ok());
                let native_ok = native_res.is_some();
                let wei = native_res.unwrap_or(U256::ZERO);
                let mut toks_json: Vec<serde_json::Value> = Vec::with_capacity(tokens.len());
                for (j, (taddr_s, tsym, tdec, _)) in tokens.iter().enumerate() {
                    let tok_res = results
                        .get(base + 1 + j)
                        .and_then(|v| hex_bytes(v).ok())
                        .and_then(|b| erc20::decode_u256(&b));
                    let ok = tok_res.is_some();
                    let bal = tok_res.unwrap_or(U256::ZERO);
                    toks_json.push(serde_json::json!({
                        "address": taddr_s,
                        "symbol": tsym,
                        "decimals": tdec,
                        "raw": bal.to_string(),
                        "formatted": format_units(bal, *tdec),
                        "ok": ok,
                    }));
                }
                accounts_json.push(serde_json::json!({
                    "index": idx,
                    "native_raw": wei.to_string(),
                    "native_formatted": format_units(wei, 18),
                    "native_symbol": native_symbol,
                    "native_ok": native_ok,
                    "tokens": toks_json,
                }));
            }
        }

        Ok(serde_json::json!({
            "native_symbol": native_symbol,
            "accounts": accounts_json,
        }))
    }

    /// Scan HD-derived addresses (`m/44'/60'/0'/0/x`) and return the indices that hold a balance
    /// (native ETH OR any tracked token). Uses a BIP44-style gap limit: scanning stops after
    /// `gap_limit` consecutive empty addresses. Balances are fetched in batched JSON-RPC requests
    /// so a deep scan is a handful of round-trips rather than one per address.
    pub async fn scan_funded(&mut self, gap_limit: u32) -> Result<Vec<u32>> {
        // Hardware wallets derive addresses via slow device round-trips, and watch-only wallets have
        // no keys to derive from, so neither runs an automatic gap scan.
        if matches!(self.keys, KeySource::Hardware(_) | KeySource::WatchOnly) {
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
        // Size the address chunk so each JSON-RPC batch (per_addr calls per address) stays under the
        // ~40-call public-RPC cap. A flat 20 addresses overflowed the batch once tokens were tracked
        // (20 * (1+tokens) calls), and the over-cap calls came back null — which used to be counted
        // as empty addresses and tripped the gap limit early (the "stopped at ~18" bug).
        let chunk: u32 = (40 / per_addr).max(1) as u32;
        let hard_cap: u32 = 100_000; // safety bound
        let gap = gap_limit.max(1);
        // Minimum indices always scanned on the standard BIP44 scheme before the gap can stop us
        // (covers a deep MetaMask wallet of ~230 accounts with internal unfunded gaps).
        const SCAN_FLOOR: u32 = 256;

        // (scheme index, per-scheme index, full path) of every funded address found.
        let mut found: Vec<(usize, u32, String)> = Vec::new();

        {
            let seed = match &self.keys {
                KeySource::Software(seed) => seed,
                KeySource::Hardware(_) | KeySource::WatchOnly => unreachable!(),
            };
            let provider = self.provider()?;
            // The deep 256-index floor is only needed on Ethereum mainnet (where users accumulate
            // many MetaMask accounts). On L2s/side-chains a fresh wallet is almost always empty, so
            // there we rely on the plain gap limit instead of scanning 256 indices per scheme.
            let is_mainnet = provider.chain_id() == 1;
            // Tracks whether anything at all was found on THIS chain. On non-mainnet chains, if the
            // standard BIP44 scheme (scheme 0) turns up nothing we skip the rare alternate-derivation
            // schemes (Ledger Live / legacy) for that chain — they're seldom used on L2s, and any that
            // are would already be registered from the mainnet scan. This cuts a fresh/empty wallet's
            // cross-chain scan from thousands of probes to a few hundred.
            let mut chain_found_any = false;

            for (scheme_idx, template) in SCHEMES.iter().enumerate() {
                if scheme_idx > 0 && !is_mainnet && !chain_found_any {
                    break; // this non-mainnet chain looks empty on the standard path — stop early
                }
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
                    // Run the batch; if it comes back empty/failed (transient Tor/RPC hiccup, or the
                    // endpoint rejecting the batch) retry once. A failed read must never be mistaken
                    // for a real zero balance, or it would wrongly advance the gap counter.
                    let batch_failed =
                        |r: &[serde_json::Value]| r.is_empty() || r.first().map(|v| v.is_null()).unwrap_or(true);
                    let mut results = provider.call_batch(&calls).await?;
                    if batch_failed(&results) {
                        results = provider.call_batch(&calls).await?;
                    }
                    if batch_failed(&results) {
                        // Endpoint can't service this scheme's batches; stop scanning it rather than
                        // loop to the hard cap treating every address as unknown.
                        break 'scheme;
                    }

                    for (p, _) in addrs.iter().enumerate() {
                        let base = p * per_addr;
                        // Native balance: distinguish a *successful* read from a failed/absent one.
                        let native = results.get(base).and_then(|v| parse_hex_u256(v).ok());
                        let native_ok = native.is_some();
                        let mut has_balance = native.map(|wei| wei > U256::ZERO).unwrap_or(false);
                        // Token balances. A missing entry or an explicit JSON `null` means the CALL
                        // failed (transient/batch issue) -> unknown, must not advance the gap. But a
                        // concrete return — including an empty `0x` from a revert or from there being
                        // no such token contract on THIS chain (the tracked list is mainnet tokens, so
                        // their addresses aren't contracts on L2s) — is a definitive read worth zero.
                        // Treating that `0x` as "failed" was why non-mainnet scans never advanced the
                        // gap and ran toward the hard cap.
                        let mut tokens_ok = true;
                        if !has_balance {
                            for j in 0..tokens.len() {
                                match results.get(base + 1 + j) {
                                    None => tokens_ok = false,
                                    Some(v) if v.is_null() => tokens_ok = false,
                                    Some(v) => {
                                        let bal = hex_bytes(v)
                                            .ok()
                                            .and_then(|b| erc20::decode_u256(&b))
                                            .unwrap_or(U256::ZERO); // `0x`/no-contract => zero
                                        if bal > U256::ZERO {
                                            has_balance = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        let (i, path) = paths[p].clone();
                        if has_balance {
                            found.push((scheme_idx, i, path));
                            SCAN_FOUND.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            consecutive_empty = 0;
                            chain_found_any = true;
                        } else if native_ok && tokens_ok {
                            // Genuinely empty: every read succeeded and was zero.
                            consecutive_empty += 1;
                            // Depth floor for the standard BIP44 scheme (scheme 0, e.g. MetaMask):
                            // always scan at least SCAN_FLOOR indices before the gap can stop us, so a
                            // wallet with many accounts and internal empty runs (> gap) — e.g. ~230
                            // MetaMask accounts where some middle ones are unfunded — is fully found
                            // rather than truncated. Other schemes rarely go deep, so they keep the
                            // plain gap limit.
                            if consecutive_empty >= gap
                                && (scheme_idx != 0 || !is_mainnet || i + 1 >= SCAN_FLOOR)
                            {
                                break 'scheme;
                            }
                        }
                        // else: a read failed (null) -> unknown; do NOT advance the gap counter.
                    }
                    SCAN_CHECKED.fetch_add((end - start) as u64, std::sync::atomic::Ordering::Relaxed);
                    index = end;
                }
            }
        }

        Ok(self.register_found(&found))
    }

    /// Register scanned funded derivation paths as accounts (deduped) and return their unified
    /// positions in `account_order` so the UI can mark them. Scheme 0 keeps the compact `Hd(index)`
    /// form; other schemes store the explicit path. Shared by the single-chain and all-chains scans.
    fn register_found(&mut self, found: &[(usize, u32, String)]) -> Vec<u32> {
        for (scheme_idx, i, path) in found {
            let entry = if *scheme_idx == 0 {
                AccountEntry::Hd(*i)
            } else {
                AccountEntry::HdPath(path.clone())
            };
            if !self.secrets.account_order.iter().any(|e| *e == entry) {
                if let AccountEntry::Hd(idx) = &entry {
                    self.secrets.account_count = self.secrets.account_count.max(idx + 1);
                }
                self.secrets.account_order.push(entry);
            }
        }

        // Make the standard-scheme accounts contiguous (0..=max) and in order, so the Receive tab
        // lists every account — funded ones AND the unfunded gaps between them — as one continuous
        // 0,1,2,... run instead of only the funded indices. Done only when the wallet is purely HD
        // (no imported keys / alternate-scheme accounts, whose unified positions and user labels we
        // must not move); pre-existing Hd(0..n) keep their positions, so labels stay aligned. This
        // targets the fresh-seed-import case.
        let max_hd = self
            .secrets
            .account_order
            .iter()
            .filter_map(|e| if let AccountEntry::Hd(i) = e { Some(*i) } else { None })
            .max();
        let only_hd = self
            .secrets
            .account_order
            .iter()
            .all(|e| matches!(e, AccountEntry::Hd(_)));
        if let (Some(max_hd), true) = (max_hd, only_hd) {
            let mut order = Vec::with_capacity(max_hd as usize + 1);
            for i in 0..=max_hd {
                order.push(AccountEntry::Hd(i));
            }
            self.secrets.account_order = order;
            self.secrets.account_count = max_hd + 1;
        }

        // Return the unified positions (into the final account_order) of the funded addresses. With
        // the contiguous fill above, a scheme-0 funded index == its position.
        let mut out = Vec::with_capacity(found.len());
        for (scheme_idx, i, path) in found {
            let entry = if *scheme_idx == 0 {
                AccountEntry::Hd(*i)
            } else {
                AccountEntry::HdPath(path.clone())
            };
            if let Some(pos) = self.secrets.account_order.iter().position(|e| *e == entry) {
                out.push(pos as u32);
            }
        }
        out
    }

    /// Scan ONE chain (via the given provider) for funded derivation paths, WITHOUT mutating the
    /// wallet — so several chains can be scanned concurrently (see `scan_funded_all_chains`). Returns
    /// the funded `(scheme_idx, per-scheme index, path)` tuples; the caller registers them. Chunks
    /// within each scheme are fetched with a small concurrent look-ahead window (`buffered`) instead
    /// of one-at-a-time, and the global RPC semaphore keeps total Tor concurrency bounded.
    async fn scan_chain_paths(
        &self,
        provider: &RpcProvider,
        gap_limit: u32,
    ) -> Vec<(usize, u32, String)> {
        use futures::stream::StreamExt;
        const SCHEMES: [&str; 4] = [
            "m/44'/60'/0'/0/{i}", // BIP44: MetaMask, Trezor, Trust, imToken, Coinbase Wallet, ...
            "m/44'/60'/{i}'/0/0", // Ledger Live
            "m/44'/60'/0'/{i}",   // Ledger legacy / MyEtherWallet / MyCrypto
            "m/44'/60'/0'/0'/{i}",// some older/hardened variants
        ];
        const SCAN_FLOOR: u32 = 256; // min BIP44 indices scanned on mainnet before the gap can stop
        const WINDOW: usize = 4;     // chunks in flight per scheme (globally capped by RPC_SEM)

        let seed = match &self.keys {
            KeySource::Software(s) => s,
            KeySource::Hardware(_) | KeySource::WatchOnly => return Vec::new(),
        };
        let tokens: Vec<Address> = self
            .secrets
            .tokens
            .iter()
            .filter_map(|t| parse_address(&t.address).ok())
            .collect();
        let per_addr = 1 + tokens.len(); // 1 eth_getBalance + one balanceOf per token
        // Address chunk sized to the per-request call budget. With no tracked tokens the batch is
        // just eth_getBalance calls, which public RPCs happily serve in larger batches, so use a
        // bigger budget (fewer round-trips); with tokens tracked, stay under the conservative ~40
        // call cap (over-cap calls come back null and would trip the gap logic).
        let budget = if per_addr == 1 { 100 } else { 40 };
        let chunk: u32 = (budget / per_addr).max(1) as u32;
        let hard_cap: u32 = 100_000;
        let gap = gap_limit.max(1);
        let is_mainnet = provider.chain_id() == 1;

        let batch_failed =
            |r: &[serde_json::Value]| r.is_empty() || r.first().map(|v| v.is_null()).unwrap_or(true);

        let mut found: Vec<(usize, u32, String)> = Vec::new();
        let mut chain_found_any = false;

        for (scheme_idx, template) in SCHEMES.iter().enumerate() {
            if crate::provider::shutting_down() {
                break; // app closing — stop scanning and return what we have
            }
            // On non-mainnet chains, if the standard path found nothing, skip the rare alt schemes.
            if scheme_idx > 0 && !is_mainnet && !chain_found_any {
                break;
            }

            let ranges = (0..hard_cap)
                .step_by(chunk as usize)
                .map(move |start| (start, (start + chunk).min(hard_cap)));
            // Fetch balances for a window of chunks concurrently; `buffered` yields them IN ORDER so
            // the gap-limit logic below still applies sequentially by index.
            let fetches = futures::stream::iter(ranges)
                .map(|(start, end)| {
                    let tokens = &tokens;
                    async move {
                        let mut paths: Vec<(u32, String)> = Vec::with_capacity((end - start) as usize);
                        let mut calls: Vec<(String, serde_json::Value)> =
                            Vec::with_capacity(((end - start) as usize) * per_addr);
                        for i in start..end {
                            let path = template.replace("{i}", &i.to_string());
                            let addr = match seed.signer_at_path(&path) {
                                Ok(s) => s.address(),
                                Err(_) => return (start, end, paths, Vec::new(), true),
                            };
                            calls.push((
                                "eth_getBalance".to_string(),
                                serde_json::json!([addr.to_string(), "latest"]),
                            ));
                            for t in tokens {
                                let data = format!("0x{}", hex::encode(erc20::encode_balance_of(addr)));
                                calls.push((
                                    "eth_call".to_string(),
                                    serde_json::json!([{ "to": t.to_string(), "data": data }, "latest"]),
                                ));
                            }
                            paths.push((i, path));
                        }
                        // Retry a failed/empty batch with EXPONENTIAL BACKOFF. This is critical for
                        // scan completeness: the balance reads go over one shared Tor exit and the
                        // RPC endpoint rate-limits, so a batch mid-scan can transiently fail. The old
                        // code retried once immediately (both attempts hit the same rate window) and,
                        // on failure, `break 'scheme` ABANDONED the rest of the scheme — silently
                        // skipping every higher-index funded account (the "found 167 one run, 43 the
                        // next" bug). Backing off and retrying lets the rate window recover so the
                        // scan reaches the true end instead of stopping at the first hiccup.
                        let mut results = provider.call_batch(&calls).await.unwrap_or_default();
                        let mut tries = 0u32;
                        while batch_failed(&results) && tries < 6 && !crate::provider::shutting_down() {
                            tries += 1;
                            crate::provider::interruptible_sleep(backoff_delay(tries)).await;
                            results = provider.call_batch(&calls).await.unwrap_or_default();
                        }
                        let failed = batch_failed(&results);
                        (start, end, paths, results, failed)
                    }
                })
                .buffered(WINDOW);
            futures::pin_mut!(fetches);

            let mut consecutive_empty = 0u32;
            'scheme: while let Some((start, end, paths, results, failed)) = fetches.next().await {
                if failed || crate::provider::shutting_down() {
                    break 'scheme; // endpoint can't service this scheme's batches, or app is closing
                }
                SCAN_CHECKED.fetch_add((end - start) as u64, std::sync::atomic::Ordering::Relaxed);
                for (p, (i, path)) in paths.iter().enumerate() {
                    let base = p * per_addr;
                    let native = results.get(base).and_then(|v| parse_hex_u256(v).ok());
                    let native_ok = native.is_some();
                    let mut has_balance = native.map(|wei| wei > U256::ZERO).unwrap_or(false);
                    let mut tokens_ok = true;
                    if !has_balance {
                        for j in 0..tokens.len() {
                            match results.get(base + 1 + j) {
                                None => tokens_ok = false,
                                Some(v) if v.is_null() => tokens_ok = false,
                                Some(v) => {
                                    let bal = hex_bytes(v)
                                        .ok()
                                        .and_then(|b| erc20::decode_u256(&b))
                                        .unwrap_or(U256::ZERO); // `0x`/no-contract => zero
                                    if bal > U256::ZERO {
                                        has_balance = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if has_balance {
                        found.push((scheme_idx, *i, path.clone()));
                        SCAN_FOUND.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        consecutive_empty = 0;
                        chain_found_any = true;
                    } else if native_ok && tokens_ok {
                        consecutive_empty += 1;
                        if consecutive_empty >= gap
                            && (scheme_idx != 0 || !is_mainnet || i + 1 >= SCAN_FLOOR)
                        {
                            break 'scheme; // dropping `fetches` cancels the look-ahead chunks
                        }
                    }
                    // else: a read failed (null) -> unknown; do NOT advance the gap counter.
                }
            }
        }

        found
    }

    /// Scan for funded addresses across MULTIPLE chains. EVM chains share the same addresses, so an
    /// address funded on any chain should be discovered on restore. Runs the derivation-scheme gap
    /// scan against each provider config in turn (skipping unreachable ones), accumulating funded
    /// accounts, then restores the original (UI-selected) provider.
    pub async fn scan_funded_all_chains(
        &mut self,
        configs: Vec<ProviderConfig>,
        gap_limit: u32,
    ) -> Result<Vec<u32>> {
        if matches!(self.keys, KeySource::Hardware(_) | KeySource::WatchOnly) {
            return Ok(Vec::new());
        }
        // Build a dedicated provider per chain and scan them ALL CONCURRENTLY (join_all), rather than
        // swapping the wallet's provider and scanning chains one after another. `scan_chain_paths` is
        // &self (read-only), so concurrent borrows are fine; the global RPC semaphore keeps total Tor
        // requests bounded. The wallet's own provider is left untouched (no set_provider swaps), so
        // there's nothing to restore. Registration happens once, after all chains finish.
        let providers: Vec<RpcProvider> = configs
            .into_iter()
            .filter(|c| !c.endpoints.is_empty())
            .filter_map(|c| RpcProvider::new(&c).ok())
            .collect();

        let per_chain =
            futures::future::join_all(providers.iter().map(|p| self.scan_chain_paths(p, gap_limit)))
                .await;

        // Merge funded paths across chains, deduped by (scheme, path) — the same address is funded on
        // multiple chains, but should register as one account.
        let mut found: Vec<(usize, u32, String)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for chain in per_chain {
            for f in chain {
                if seen.insert((f.0, f.2.clone())) {
                    found.push(f);
                }
            }
        }

        let mut indices = self.register_found(&found);
        indices.sort_unstable();
        indices.dedup();
        Ok(indices)
    }

    /// ETH/USD price read on-chain from the Chainlink mainnet aggregator via `eth_call`
    /// (over the same Tor RPC) — no third-party price API. Returns USD per 1 ETH.
    /// USD price of the connected chain's native coin. On Ethereum mainnet this uses the trustless
    /// on-chain Chainlink feed; on other chains (where that feed's RPC isn't reachable) it falls
    /// back to CoinGecko over Tor, keyed by the chain's native coin id.
    pub async fn native_usd_price(&self) -> Result<f64> {
        let chain = self.provider()?.chain_id();
        // Serve a recent price (≤20s) instead of re-fetching on every connect / tab switch / block.
        if let Some((t, cid, p)) = *self.caches.native_price.lock().unwrap() {
            if cid == chain && t.elapsed() < Duration::from_secs(20) {
                return Ok(p);
            }
        }
        let p = self.native_usd_price_inner().await?;
        *self.caches.native_price.lock().unwrap() = Some((Instant::now(), chain, p));
        Ok(p)
    }

    async fn native_usd_price_inner(&self) -> Result<f64> {
        let info = chain_info(self.provider()?.chain_id());

        // Ethereum mainnet: prefer the trustless on-chain Chainlink feed.
        if info.chain_id == 1 {
            if let Ok(p) = self.eth_usd_price().await {
                if p > 0.0 {
                    return Ok(p);
                }
            }
            // else fall through to the market sources (feed RPC hiccup shouldn't blank the price)
        }

        // Gnosis' native coin (xDAI) is a DAI-pegged stablecoin with no spot market — it's ~$1.
        if info.native_symbol.eq_ignore_ascii_case("XDAI")
            || info.native_symbol.eq_ignore_ascii_case("DAI")
        {
            return Ok(1.0);
        }

        match self
            .market_native_price(info.native_symbol, info.coingecko_id)
            .await
        {
            Some(p) => Ok(p),
            None => Err(CoreError::rpc("no native price")),
        }
    }

    /// Historical USD spot price of `symbol` on `date` (YYYY-MM-DD, UTC) via Coinbase — used to show
    /// each transaction's fiat value at the time it happened. Returns 0.0 if unavailable.
    pub async fn price_on_date(&self, symbol: &str, date: &str) -> Result<f64> {
        let provider = self.provider()?;
        let sym = symbol.to_uppercase();
        let url = format!("https://api.coinbase.com/v2/prices/{sym}-USD/spot?date={date}");
        let v = provider.http_get_json(&url).await?;
        Ok(v["data"]["amount"]
            .as_str()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0))
    }

    /// Best-effort USD spot price for a native coin from keyless, Tor-friendly public APIs.
    /// CoinGecko is unreliable over shared Tor exit IPs (empty/429 responses), so we try Coinbase
    /// first (covers ETH/POL/BNB/AVAX and rarely rate-limits), then Kraken, then CoinGecko. Returns
    /// `None` only if every source fails.
    async fn market_native_price(&self, symbol: &str, coingecko_id: &str) -> Option<f64> {
        let provider = self.provider().ok()?;
        let sym = symbol.to_uppercase();

        // 1) Coinbase spot price.
        let cb = format!("https://api.coinbase.com/v2/prices/{sym}-USD/spot");
        if let Ok(v) = provider.http_get_json(&cb).await {
            if let Some(p) = v["data"]["amount"].as_str().and_then(|s| s.parse::<f64>().ok()) {
                if p > 0.0 {
                    return Some(p);
                }
            }
        }

        // 2) Kraken ticker. The result key can differ from the requested pair (e.g. ETHUSD ->
        // XETHZUSD), so just read the single entry's last-trade price.
        let kr = format!("https://api.kraken.com/0/public/Ticker?pair={sym}USD");
        if let Ok(v) = provider.http_get_json(&kr).await {
            if let Some(node) = v
                .get("result")
                .and_then(|r| r.as_object())
                .and_then(|m| m.values().next())
            {
                if let Some(p) = node["c"][0].as_str().and_then(|s| s.parse::<f64>().ok()) {
                    if p > 0.0 {
                        return Some(p);
                    }
                }
            }
        }

        // 3) CoinGecko — last resort (often empty over Tor, but free when it works).
        let cg = format!(
            "https://api.coingecko.com/api/v3/simple/price?ids={coingecko_id}&vs_currencies=usd"
        );
        if let Ok(v) = provider.http_get_json(&cg).await {
            if let Some(p) = v[coingecko_id]["usd"].as_f64() {
                if p > 0.0 {
                    return Some(p);
                }
            }
        }

        None
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

    /// Transaction receipt for `tx_hash`. `Value::Null` until the tx is mined; once mined, an object
    /// with `status` ("0x1" success / "0x0" reverted) and `blockNumber`. The UI polls this after a
    /// send so the balance/history confirm the instant the tx lands, not on a fixed timer.
    pub async fn tx_receipt(&self, tx_hash: &str) -> Result<serde_json::Value> {
        self.provider()?
            .call("eth_getTransactionReceipt", serde_json::json!([tx_hash]))
            .await
    }

    /// Resolve an ENS name (e.g. "vitalik.eth") to a checksummed address via the ENS registry +
    /// resolver on Ethereum mainnet. Errors on non-mainnet chains or unresolved names.
    pub async fn resolve_ens(&self, name: &str) -> Result<String> {
        let provider = self.provider()?;
        if provider.chain_id() != 1 {
            return Err(CoreError::rpc("ENS names resolve on Ethereum mainnet only"));
        }
        let node = ens_namehash(name.trim());
        // ENS registry.resolver(bytes32) -> address (selector 0x0178b8bf).
        const REGISTRY: &str = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";
        let mut d1 = vec![0x01u8, 0x78, 0xb8, 0xbf];
        d1.extend_from_slice(&node);
        let r1 = provider.eth_call(REGISTRY, &format!("0x{}", hex::encode(&d1))).await?;
        let resolver = word_to_address(r1.as_str().unwrap_or(""))?;
        if resolver == Address::ZERO {
            return Err(CoreError::rpc("ENS name has no resolver"));
        }
        // resolver.addr(bytes32) -> address (selector 0x3b3b57de).
        let mut d2 = vec![0x3bu8, 0x3b, 0x57, 0xde];
        d2.extend_from_slice(&node);
        let r2 = provider
            .eth_call(&resolver.to_checksum(None), &format!("0x{}", hex::encode(&d2)))
            .await?;
        let addr = word_to_address(r2.as_str().unwrap_or(""))?;
        if addr == Address::ZERO {
            return Err(CoreError::rpc("ENS name does not resolve to an address"));
        }
        Ok(addr.to_checksum(None))
    }

    pub async fn suggest_fees(&self) -> Result<FeeSuggestion> {
        let chain = self.provider()?.chain_id();
        // Fees change at most once per block (~12s on mainnet, faster on L2s); a 5s cache absorbs
        // the repeated fee refreshes fired by opening/toggling the Send and Swap tabs.
        {
            let guard = self.caches.fees.lock().unwrap();
            if let Some((t, cid, f)) = guard.as_ref() {
                if *cid == chain && t.elapsed() < Duration::from_secs(5) {
                    return Ok(f.clone());
                }
            }
        }
        let f = self.suggest_fees_inner().await?;
        *self.caches.fees.lock().unwrap() = Some((Instant::now(), chain, f.clone()));
        Ok(f)
    }

    async fn suggest_fees_inner(&self) -> Result<FeeSuggestion> {
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
        // maxFee = 3*baseFee + tip. Base fee can rise up to 12.5% per block; 3x gives ~9 blocks of
        // headroom so a tx sent into a rising-fee period doesn't get stuck (2x could underprice).
        let max_fee = base_fee * U256::from(3u64) + tip;
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
        nonce_override: Option<u64>,
    ) -> Result<SendResult> {
        let value = U256::from_str(amount_wei)
            .map_err(|_| CoreError::Amount(format!("invalid wei amount: {amount_wei}")))?;
        let to_addr = parse_address(to)?;
        self.build_sign_send(from_index, to_addr, value, Bytes::new(), None, fee, nonce_override)
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
        nonce_override: Option<u64>,
    ) -> Result<SendResult> {
        let amount = U256::from_str(amount_units)
            .map_err(|_| CoreError::Amount(format!("invalid token amount: {amount_units}")))?;
        let to_addr = parse_address(to)?;
        let token_addr = parse_address(token)?;
        let data = Bytes::from(erc20::encode_transfer(to_addr, amount));
        // Value is 0 for token transfers; the recipient of the tx is the token contract.
        self.build_sign_send(from_index, token_addr, U256::ZERO, data, None, fee, nonce_override)
            .await
    }

    /// "Pay to many": send to several recipients from one account. Ethereum is account-based, so
    /// this broadcasts one transaction per recipient with sequential nonces (no batching contract
    /// needed). `recipients` is (to, amount) where amount is base units (wei for native, token
    /// units for ERC-20). Stops at the first failure (a nonce gap would strand later txs) and
    /// returns a JSON array of `{to, tx_hash}` / `{to, error}` describing what happened.
    pub async fn send_many(
        &self,
        from_index: u32,
        recipients: &[(String, String)],
        token: &str,
        fee: Option<(u128, u128)>,
    ) -> Result<serde_json::Value> {
        let provider = self.provider()?;
        let from = parse_address(&self.address(from_index)?)?;
        // ERC-20 pre-flight: make sure the account holds enough of the token for EVERY recipient
        // before broadcasting anything, so we don't spend gas on the first transfers only to have
        // later ones revert (native multi-send is atomic via Multicall3 and doesn't need this).
        if !token.is_empty() {
            let mut total = U256::ZERO;
            for (_, amount) in recipients {
                let a = U256::from_str(amount.trim())
                    .map_err(|_| CoreError::Amount("invalid token amount".into()))?;
                total = total
                    .checked_add(a)
                    .ok_or_else(|| CoreError::Amount("total overflow".into()))?;
            }
            let bal = U256::from_str(&self.erc20_balance(token, from_index).await?.raw)
                .unwrap_or(U256::ZERO);
            if bal < total {
                return Err(CoreError::Amount(format!(
                    "not enough of this token to pay all recipients (need {total}, have {bal})"
                )));
            }
        }
        let start = parse_hex_u64(&provider.get_transaction_count(&from.to_string()).await?)?;
        let mut out: Vec<serde_json::Value> = Vec::with_capacity(recipients.len());
        for (i, (to, amount)) in recipients.iter().enumerate() {
            let nonce = start + i as u64;
            let r = if token.is_empty() {
                self.send_eth(from_index, to, amount, fee, Some(nonce)).await
            } else {
                self.send_erc20(from_index, token, to, amount, fee, Some(nonce)).await
            };
            match r {
                Ok(res) => out.push(serde_json::json!({ "to": to, "tx_hash": res.tx_hash })),
                Err(e) => {
                    out.push(serde_json::json!({ "to": to, "error": e.to_string() }));
                    break; // don't create a nonce gap that strands the remaining sends
                }
            }
        }
        Ok(serde_json::json!(out))
    }

    /// Atomic native-coin multi-send: pay many recipients in ONE transaction via Multicall3's
    /// `aggregate3Value` (all-or-nothing — if any transfer would fail, the whole tx reverts, so no
    /// partial sends / stranded nonces). `recipients` are (address, decimal-wei). Native only.
    pub async fn send_many_native(
        &self,
        from_index: u32,
        recipients: &[(String, String)],
        fee: Option<(u128, u128)>,
    ) -> Result<SendResult> {
        if recipients.is_empty() {
            return Err(CoreError::rpc("no recipients"));
        }
        let mut calls: Vec<Call3Value> = Vec::with_capacity(recipients.len());
        let mut total = U256::ZERO;
        for (to, amount) in recipients {
            let value = U256::from_str(amount.trim())
                .map_err(|_| CoreError::Amount("invalid wei amount".into()))?;
            total = total
                .checked_add(value)
                .ok_or_else(|| CoreError::Amount("total overflow".into()))?;
            calls.push(Call3Value {
                target: parse_address(to)?,
                allowFailure: false, // any failed transfer reverts the whole batch
                value,
                callData: Bytes::new(), // plain value transfer to an EOA
            });
        }
        let data = aggregate3ValueCall { calls }.abi_encode();
        // msg.value MUST equal the sum (Multicall3 forwards each call's value; any surplus would be
        // stuck in the contract) — we send exactly `total`.
        self.build_sign_send(from_index, parse_address(MULTICALL3)?, total, Bytes::from(data), None,
                             fee, None)
            .await
    }

    /// Broadcast an already-signed raw transaction (0x-prefixed RLP). Works for any wallet type
    /// (no keys needed) — this is the "transaction pusher" used to relay an offline-signed tx over
    /// Tor. Returns the resulting tx hash.
    pub async fn broadcast_raw(&self, raw_hex: &str) -> Result<SendResult> {
        let provider = self.provider()?;
        let t = raw_hex.trim();
        let raw = if t.starts_with("0x") || t.starts_with("0X") {
            t.to_string()
        } else {
            format!("0x{t}")
        };
        // Decode the nonce from the signed RLP BEFORE broadcasting so a later speed-up/cancel (which
        // reuses SendResult.nonce) targets the right nonce instead of 0.
        let nonce = {
            use alloy::consensus::{Transaction as _, TxEnvelope};
            use alloy::eips::eip2718::Decodable2718;
            hex::decode(raw.trim_start_matches("0x").trim_start_matches("0X"))
                .ok()
                .and_then(|bytes| TxEnvelope::decode_2718(&mut bytes.as_slice()).ok())
                .map(|env| env.nonce())
                .unwrap_or(0)
        };
        let result = provider.send_raw_transaction(&raw).await?;
        let tx_hash = result
            .as_str()
            .ok_or_else(|| CoreError::rpc("broadcast returned no hash"))?
            .to_string();
        Ok(SendResult { tx_hash, nonce })
    }

    /// Build the fields of an UNSIGNED transaction (resolving nonce + gas + fees over the network),
    /// for air-gapped signing. Returns JSON the offline signer consumes via [`sign_unsigned`].
    /// `token` empty = native send (`amount_wei`), else ERC-20 transfer (`amount_units`).
    pub async fn build_unsigned(
        &self,
        from_index: u32,
        to: &str,
        amount_wei: &str,
        token: &str,
        amount_units: &str,
        fee: Option<(u128, u128)>,
        nonce_override: Option<u64>,
    ) -> Result<serde_json::Value> {
        let provider = self.provider()?;
        let from = parse_address(&self.address(from_index)?)?;
        let (to_addr, value, data) = if token.is_empty() {
            let v = U256::from_str(amount_wei)
                .map_err(|_| CoreError::Amount("invalid wei amount".into()))?;
            (parse_address(to)?, v, Bytes::new())
        } else {
            let amt = U256::from_str(amount_units)
                .map_err(|_| CoreError::Amount("invalid token amount".into()))?;
            let d = Bytes::from(erc20::encode_transfer(parse_address(to)?, amt));
            (parse_address(token)?, U256::ZERO, d)
        };
        let nonce = match nonce_override {
            Some(n) => n,
            None => parse_hex_u64(&provider.get_transaction_count(&from.to_string()).await?)?,
        };
        let (max_fee, max_priority) = match fee {
            Some(f) => f,
            None => {
                let s = self.suggest_fees().await?;
                (
                    u128::from_str(&s.max_fee).unwrap_or(0),
                    u128::from_str(&s.max_priority_fee).unwrap_or(0),
                )
            }
        };
        let est = provider
            .estimate_gas(serde_json::json!({
                "from": from.to_string(), "to": to_addr.to_string(),
                "value": format!("0x{:x}", value), "data": format!("0x{}", hex::encode(&data)),
            }))
            .await?;
        let g = parse_hex_u64(&est)?;
        let gas_limit = g + g / 4;
        let chain_id = provider.chain_id();
        Ok(serde_json::json!({
            "chain_id": chain_id, "from_index": from_index, "nonce": nonce,
            "to": to_addr.to_string(), "value": value.to_string(),
            "data": format!("0x{}", hex::encode(&data)), "gas_limit": gas_limit,
            "max_fee": max_fee.to_string(), "max_priority": max_priority.to_string(),
            "legacy": chain_info(chain_id).legacy_gas,
        }))
    }

    /// Sign an unsigned-tx JSON (from [`build_unsigned`]) with the local key and return the 0x raw
    /// RLP. Pure signing — no network needed, so it runs on an offline machine.
    pub async fn sign_unsigned(&self, json_str: &str) -> Result<String> {
        let v: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| CoreError::Amount(format!("bad unsigned tx json: {e}")))?;
        let from_index = v["from_index"].as_u64().unwrap_or(0) as u32;
        let chain_id = v["chain_id"]
            .as_u64()
            .ok_or_else(|| CoreError::Amount("missing chain_id".into()))?;
        let nonce = v["nonce"]
            .as_u64()
            .ok_or_else(|| CoreError::Amount("missing nonce".into()))?;
        let to = parse_address(v["to"].as_str().unwrap_or_default())?;
        let value = U256::from_str(v["value"].as_str().unwrap_or("0"))
            .map_err(|_| CoreError::Amount("bad value".into()))?;
        let data_hex = v["data"].as_str().unwrap_or("0x");
        let data = Bytes::from(
            hex::decode(data_hex.trim_start_matches("0x"))
                .map_err(|_| CoreError::Amount("bad data hex".into()))?,
        );
        let gas_limit = v["gas_limit"]
            .as_u64()
            .ok_or_else(|| CoreError::Amount("missing gas_limit".into()))?;
        let max_fee = u128::from_str(v["max_fee"].as_str().unwrap_or("0")).unwrap_or(0);
        let max_priority = u128::from_str(v["max_priority"].as_str().unwrap_or("0")).unwrap_or(0);
        let legacy = v["legacy"].as_bool().unwrap_or(false);

        let raw = if legacy {
            let mut tx = TxLegacy {
                chain_id: Some(chain_id),
                nonce,
                gas_price: max_fee,
                gas_limit,
                to: TxKind::Call(to),
                value,
                input: data.clone(),
            };
            let sig = self
                .sign_built_tx(from_index, chain_id, true, &mut tx, nonce, gas_limit, max_fee,
                    max_priority, to, value, &data)
                .await?;
            let env: TxEnvelope = tx.into_signed(sig).into();
            env.encoded_2718()
        } else {
            let mut tx = TxEip1559 {
                chain_id,
                nonce,
                gas_limit,
                max_fee_per_gas: max_fee,
                max_priority_fee_per_gas: max_priority,
                to: TxKind::Call(to),
                value,
                access_list: Default::default(),
                input: data.clone(),
            };
            let sig = self
                .sign_built_tx(from_index, chain_id, false, &mut tx, nonce, gas_limit, max_fee,
                    max_priority, to, value, &data)
                .await?;
            let env: TxEnvelope = tx.into_signed(sig).into();
            env.encoded_2718()
        };
        Ok(format!("0x{}", hex::encode(raw)))
    }

    /// Cancel a pending transaction by replacing it with a 0-value self-send at the same `nonce`.
    /// The replacement must pay more gas than the stuck tx (the caller supplies a bumped `fee`), so
    /// the network prefers it; once it mines, the original is dropped. Returns the replacement hash.
    pub async fn cancel_transaction(
        &self,
        from_index: u32,
        nonce: u64,
        fee: Option<(u128, u128)>,
    ) -> Result<SendResult> {
        let self_addr = parse_address(&self.address(from_index)?)?;
        // 0 ETH to yourself, minimal gas, at the same nonce.
        self.build_sign_send(
            from_index, self_addr, U256::ZERO, Bytes::new(), Some(21000), fee, Some(nonce),
        )
        .await
    }

    /// Replace-by-fee an ARBITRARY still-pending transaction of `from_index`, found by hash. When
    /// `cancel` is true, replace it with a 0-value self-send (cancel); otherwise rebroadcast the SAME
    /// recipient/value/data at the given (higher) fee (speed-up). Fetches the tx to recover its exact
    /// nonce + fields, so this works on any unconfirmed tx from history, not just the last one.
    pub async fn replace_tx(
        &self,
        from_index: u32,
        tx_hash: &str,
        fee: Option<(u128, u128)>,
        cancel: bool,
    ) -> Result<SendResult> {
        let provider = self.provider()?;
        let v = provider
            .call("eth_getTransactionByHash", serde_json::json!([tx_hash]))
            .await?;
        if v.is_null() {
            return Err(CoreError::rpc("transaction not found (may have already confirmed/dropped)"));
        }
        if v.get("blockNumber").map(|b| !b.is_null()).unwrap_or(false) {
            return Err(CoreError::rpc("transaction already confirmed — nothing to replace"));
        }
        let self_addr = parse_address(&self.address(from_index)?)?;
        // Only the sender can replace their own tx (same from + nonce).
        let from = v.get("from").and_then(|x| x.as_str()).unwrap_or("");
        if !from.eq_ignore_ascii_case(&self_addr.to_string()) {
            return Err(CoreError::rpc("this transaction was not sent from the selected account"));
        }
        let nonce = parse_hex_u64(&v["nonce"])?;
        // A node rejects a replacement that isn't ~12.5% above the ORIGINAL fee. Floor the fee at
        // 115% of the pending tx's own fee (reading it from the fetched tx), so replacing any stuck
        // tx always succeeds regardless of what the caller passed.
        let orig_max = parse_hex_u256(&v["maxFeePerGas"])
            .or_else(|_| parse_hex_u256(&v["gasPrice"]))
            .unwrap_or(U256::ZERO);
        let orig_tip = parse_hex_u256(&v["maxPriorityFeePerGas"]).unwrap_or(orig_max);
        let bump = |x: U256| x * U256::from(115u64) / U256::from(100u64);
        let (base_max, base_tip) = match fee {
            Some((mf, mp)) => (U256::from(mf), U256::from(mp)),
            None => {
                let s = self.suggest_fees().await?;
                (
                    U256::from_str(&s.max_fee).unwrap_or(U256::ZERO),
                    U256::from_str(&s.max_priority_fee).unwrap_or(U256::ZERO),
                )
            }
        };
        let final_max = base_max.max(bump(orig_max));
        let mut final_tip = base_tip.max(bump(orig_tip));
        if final_tip > final_max {
            final_tip = final_max;
        }
        let fee = Some((final_max.saturating_to::<u128>(), final_tip.saturating_to::<u128>()));
        if cancel {
            return self
                .build_sign_send(from_index, self_addr, U256::ZERO, Bytes::new(), Some(21000), fee,
                                  Some(nonce))
                .await;
        }
        let to = v.get("to").and_then(|x| x.as_str()).unwrap_or("");
        let to_addr = if to.is_empty() { self_addr } else { parse_address(to)? };
        let value = parse_hex_u256(&v["value"]).unwrap_or(U256::ZERO);
        let input = v.get("input").and_then(|x| x.as_str()).unwrap_or("0x");
        let data = Bytes::from(
            hex::decode(input.trim_start_matches("0x").trim_start_matches("0X")).unwrap_or_default(),
        );
        self.build_sign_send(from_index, to_addr, value, data, None, fee, Some(nonce))
            .await
    }

    // ---------- CoW Protocol swaps ----------

    /// Fetch a CoW Protocol sell-order quote. `sell_is_native` uses the chain's wrapped-native token
    /// as the sellToken; pass `COW_BUY_ETH` as `buy_token` to receive native ETH. Returns the raw
    /// CoW quote response (the order fields live under `quote`).
    pub async fn swap_quote(
        &self,
        from_index: u32,
        sell_token: &str,
        buy_token: &str,
        sell_amount_wei: &str,
        sell_is_native: bool,
    ) -> Result<serde_json::Value> {
        let info = chain_info(self.provider()?.chain_id());
        let cow = info
            .cow_network
            .ok_or_else(|| CoreError::rpc("swaps are not available on this network".to_string()))?;
        let from = self.address(from_index)?;
        let sell = if sell_is_native {
            parse_address(info.wrapped_native)?.to_checksum(None)
        } else {
            parse_address(sell_token)?.to_checksum(None)
        };
        let buy = if buy_token.eq_ignore_ascii_case(COW_BUY_ETH) {
            COW_BUY_ETH.to_string()
        } else {
            parse_address(buy_token)?.to_checksum(None)
        };
        let body = serde_json::json!({
            "sellToken": sell,
            "buyToken": buy,
            "from": from,
            "receiver": from,
            "kind": "sell",
            "sellAmountBeforeFee": sell_amount_wei,
            "signingScheme": "eip712",
            "priceQuality": "optimal",
        });
        let url = format!("https://api.cow.fi/{cow}/api/v1/quote");
        let resp = self.provider()?.http_post_json(&url, &body).await?;
        if resp.get("quote").is_none() {
            let msg = resp
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("quote unavailable");
            return Err(CoreError::rpc(format!("CoW quote: {msg}")));
        }
        Ok(resp)
    }

    /// Current allowance of `token` from account `from_index` to the CoW Vault Relayer.
    pub async fn swap_allowance(&self, from_index: u32, token: &str) -> Result<U256> {
        self.router_allowance(from_index, token, COW_VAULT_RELAYER).await
    }

    /// Current allowance of `token` from account `from_index` to an arbitrary `spender`.
    pub async fn router_allowance(&self, from_index: u32, token: &str, spender: &str) -> Result<U256> {
        let owner = parse_address(&self.address(from_index)?)?;
        let spender = parse_address(spender)?;
        let token_addr = parse_address(token)?.to_string();
        let data = format!("0x{}", hex::encode(erc20::encode_allowance(owner, spender)));
        let ret = self.provider()?.eth_call(&token_addr, &data).await?;
        Ok(erc20::decode_u256(&hex_bytes(&ret)?).unwrap_or(U256::ZERO))
    }

    /// Approve the CoW Vault Relayer to spend `token` from account `from_index`. `amount` is the
    /// decimal-wei cap to approve; pass "max" (or empty) for an unlimited allowance. Prefer an exact
    /// per-swap amount so a compromised relayer/token can't drain more than the current order.
    pub async fn swap_approve(
        &self,
        from_index: u32,
        token: &str,
        amount: &str,
    ) -> Result<SendResult> {
        self.router_approve(from_index, token, COW_VAULT_RELAYER, amount)
            .await
    }

    /// Approve `spender` to spend `token` from account `from_index`. `amount` is the decimal-wei cap;
    /// "max" (or empty) approves an unlimited allowance. Used for both the CoW Vault Relayer and the
    /// on-chain aggregator routers/proxies.
    pub async fn router_approve(
        &self,
        from_index: u32,
        token: &str,
        spender: &str,
        amount: &str,
    ) -> Result<SendResult> {
        let spender_addr = parse_address(spender)?;
        let token_addr = parse_address(token)?;
        let cap = if amount.is_empty() || amount.eq_ignore_ascii_case("max") {
            U256::MAX
        } else {
            U256::from_str(amount).map_err(|_| CoreError::Amount("bad approval amount".into()))?
        };
        let data = Bytes::from(erc20::encode_approve(spender_addr, cap));
        self.build_sign_send(from_index, token_addr, U256::ZERO, data, None, None, None)
            .await
    }

    /// Send an arbitrary-calldata transaction (used to execute an aggregator router's swap). `data`
    /// is 0x-prefixed calldata from the router's build/assemble step — used verbatim.
    pub async fn router_swap(
        &self,
        from_index: u32,
        to: &str,
        value_wei: &str,
        data_hex: &str,
    ) -> Result<SendResult> {
        let to_addr = parse_address(to)?;
        let value = U256::from_str(value_wei).unwrap_or(U256::ZERO);
        let data = Bytes::from(
            hex::decode(data_hex.trim_start_matches("0x"))
                .map_err(|_| CoreError::rpc("bad router calldata".to_string()))?,
        );
        self.build_sign_send(from_index, to_addr, value, data, None, None, None)
            .await
    }

    /// Build the executable transaction for the chosen on-chain router right before sending (fresh
    /// calldata). Returns `{to, data, value, spender, buy_amount, min_buy_amount}`. Not used for CoW
    /// (which keeps its signed-order path). `sell`/`buy` empty => native coin.
    #[allow(clippy::too_many_arguments)]
    pub async fn router_build(
        &self,
        router_id: &str,
        from_index: u32,
        sell: &str,
        buy: &str,
        sell_amount_wei: &str,
        sell_is_native: bool,
        sell_decimals: u8,
        buy_decimals: u8,
        slippage_bps: u32,
    ) -> Result<serde_json::Value> {
        let chain = self.provider()?.chain_id();
        let buy_is_native = buy.is_empty();
        let from = self.address(from_index)?;
        match router_id {
            "kyberswap" => {
                let slug = chains::kyber_slug(chain)
                    .ok_or_else(|| CoreError::rpc("kyber unsupported".to_string()))?;
                let tin = if sell_is_native { EVM_NATIVE_SENTINEL } else { sell };
                let tout = if buy_is_native { EVM_NATIVE_SENTINEL } else { buy };
                let routes_url = format!(
                    "{KYBER_API}/{slug}/api/v1/routes?tokenIn={tin}&tokenOut={tout}&amountIn={sell_amount_wei}"
                );
                let routes = self.provider()?.http_get_json(&routes_url).await?;
                let route_summary = routes
                    .get("data")
                    .and_then(|d| d.get("routeSummary"))
                    .cloned()
                    .ok_or_else(|| CoreError::rpc("kyber: no route".to_string()))?;
                let body = serde_json::json!({
                    "routeSummary": route_summary,
                    "sender": from,
                    "recipient": from,
                    "slippageTolerance": slippage_bps,
                });
                let b = self
                    .provider()?
                    .http_post_json(&format!("{KYBER_API}/{slug}/api/v1/route/build"), &body)
                    .await?;
                let d = b
                    .get("data")
                    .ok_or_else(|| CoreError::rpc("kyber build: no data".to_string()))?;
                let data = d.get("data").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let router = d
                    .get("routerAddress")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let value = if sell_is_native {
                    d.get("transactionValue")
                        .map(json_num_str)
                        .unwrap_or_else(|| sell_amount_wei.to_string())
                } else {
                    "0".to_string()
                };
                let buy_amount = d.get("amountOut").map(json_num_str).unwrap_or_default();
                // On-chain slippage is enforced by Kyber's `slippageTolerance` (above); report the
                // matching displayed minimum so the confirm dialog doesn't overstate the guarantee.
                let min_buy_amount = apply_slippage_min(&buy_amount, slippage_bps);
                Ok(serde_json::json!({
                    "to": router, "data": data, "value": value, "spender": router,
                    "buy_amount": buy_amount, "min_buy_amount": min_buy_amount,
                }))
            }
            "odos" => {
                let tin = if sell_is_native { ODOS_NATIVE } else { sell };
                let tout = if buy_is_native { ODOS_NATIVE } else { buy };
                let qbody = serde_json::json!({
                    "chainId": chain,
                    "inputTokens": [{ "tokenAddress": tin, "amount": sell_amount_wei }],
                    "outputTokens": [{ "tokenAddress": tout, "proportion": 1 }],
                    "userAddr": from,
                    "slippageLimitPercent": (slippage_bps as f64) / 100.0,
                });
                let q = self
                    .provider()?
                    .http_post_json(&format!("{ODOS_API}/sor/quote/v3"), &qbody)
                    .await?;
                let path_id = q
                    .get("pathId")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| CoreError::rpc("odos: no pathId".to_string()))?;
                let buy_amount = q
                    .get("outAmounts")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .map(json_num_str)
                    .unwrap_or_default();
                let abody = serde_json::json!({ "userAddr": from, "pathId": path_id, "simulate": false });
                let a = self
                    .provider()?
                    .http_post_json(&format!("{ODOS_API}/sor/assemble"), &abody)
                    .await?;
                let tx = a
                    .get("transaction")
                    .ok_or_else(|| CoreError::rpc("odos: no tx".to_string()))?;
                let to = tx.get("to").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let data = tx.get("data").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let value = tx.get("value").map(json_num_str).unwrap_or_else(|| "0".into());
                // On-chain slippage is enforced by Odos's `slippageLimitPercent` (above); report the
                // matching displayed minimum rather than the un-slipped expected output.
                let min_buy_amount = apply_slippage_min(&buy_amount, slippage_bps);
                Ok(serde_json::json!({
                    "to": to.clone(), "data": data, "value": value, "spender": to,
                    "buy_amount": buy_amount, "min_buy_amount": min_buy_amount,
                }))
            }
            "paraswap" => {
                let src = if sell_is_native { EVM_NATIVE_SENTINEL } else { sell };
                let dst = if buy_is_native { EVM_NATIVE_SENTINEL } else { buy };
                let prices_url = format!(
                    "{PARASWAP_API}/prices?srcToken={src}&destToken={dst}&amount={sell_amount_wei}\
                     &srcDecimals={sell_decimals}&destDecimals={buy_decimals}&side=SELL&network={chain}&userAddress={from}"
                );
                let p = self.provider()?.http_get_json(&prices_url).await?;
                let price_route = p
                    .get("priceRoute")
                    .cloned()
                    .ok_or_else(|| CoreError::rpc("paraswap: no route".to_string()))?;
                let dest_amount = price_route.get("destAmount").map(json_num_str).unwrap_or_default();
                let spender = price_route
                    .get("tokenTransferProxy")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let min_dest = {
                    let d = U256::from_str(&dest_amount).unwrap_or(U256::ZERO);
                    let bps = U256::from(10_000u64.saturating_sub(slippage_bps as u64));
                    (d * bps / U256::from(10_000u64)).to_string()
                };
                let tbody = serde_json::json!({
                    "srcToken": src, "destToken": dst, "srcAmount": sell_amount_wei,
                    "destAmount": min_dest, "priceRoute": price_route, "userAddress": from,
                    "srcDecimals": sell_decimals, "destDecimals": buy_decimals,
                });
                let t = self
                    .provider()?
                    .http_post_json(
                        &format!("{PARASWAP_API}/transactions/{chain}?ignoreChecks=true"),
                        &tbody,
                    )
                    .await?;
                let to = t.get("to").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let data = t.get("data").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let value = t.get("value").map(json_num_str).unwrap_or_else(|| "0".into());
                Ok(serde_json::json!({
                    "to": to, "data": data, "value": value, "spender": spender,
                    "buy_amount": dest_amount, "min_buy_amount": min_dest,
                }))
            }
            "openocean" => {
                let slug = chains::openocean_slug(chain)
                    .ok_or_else(|| CoreError::rpc("openocean unsupported".to_string()))?;
                let tin = if sell_is_native { EVM_NATIVE_SENTINEL } else { sell };
                let tout = if buy_is_native { EVM_NATIVE_SENTINEL } else { buy };
                let human = format_units(
                    U256::from_str(sell_amount_wei)
                        .map_err(|_| CoreError::Amount("bad amount".into()))?,
                    sell_decimals,
                );
                let slippage_pct = (slippage_bps as f64) / 100.0;
                let url = format!(
                    "{OPENOCEAN_API}/v3/{slug}/swap_quote?inTokenAddress={tin}&outTokenAddress={tout}\
                     &amount={human}&gasPrice=5&slippage={slippage_pct}&account={from}"
                );
                let r = self.provider()?.http_get_json(&url).await?;
                let d = r
                    .get("data")
                    .ok_or_else(|| CoreError::rpc("openocean: no data".to_string()))?;
                let to = d.get("to").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let data = d.get("data").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let value = d.get("value").map(json_num_str).unwrap_or_else(|| "0".into());
                let buy_amount = d.get("outAmount").map(json_num_str).unwrap_or_default();
                let min_buy = d
                    .get("minOutAmount")
                    .map(json_num_str)
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| buy_amount.clone());
                Ok(serde_json::json!({
                    "to": to.clone(), "data": data, "value": value, "spender": to,
                    "buy_amount": buy_amount, "min_buy_amount": min_buy,
                }))
            }
            other => Err(CoreError::rpc(format!("unknown router {other}"))),
        }
    }

    /// Sign (EIP-712) and submit the order described by a CoW quote response JSON. Returns the CoW
    /// order UID. `slippage_bps` lowers the order's minimum `buyAmount` so it can actually fill (an
    /// order signed at the exact quoted price sits open until the market moves back and often never
    /// completes).
    pub async fn swap_submit(&self, from_index: u32, quote_json: &str, slippage_bps: u32) -> Result<String> {
        let resp: serde_json::Value = serde_json::from_str(quote_json)
            .map_err(|e| CoreError::rpc(format!("bad quote json: {e}")))?;
        let q = resp
            .get("quote")
            .ok_or_else(|| CoreError::rpc("quote missing".to_string()))?;
        let chain_id = self.provider()?.chain_id();
        let cow = chain_info(chain_id)
            .cow_network
            .ok_or_else(|| CoreError::rpc("swaps unavailable".to_string()))?;

        let s = |k: &str| q.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let sell_token_s = s("sellToken");
        let buy_token_s = s("buyToken");
        let receiver_s = {
            let r = s("receiver");
            if r.is_empty() { "0x0000000000000000000000000000000000000000".to_string() } else { r }
        };
        let app_data_s = s("appData");
        let kind = if s("kind").is_empty() { "sell".to_string() } else { s("kind") };
        let sell_bal = if s("sellTokenBalance").is_empty() { "erc20".to_string() } else { s("sellTokenBalance") };
        let buy_bal = if s("buyTokenBalance").is_empty() { "erc20".to_string() } else { s("buyTokenBalance") };
        let partially = q.get("partiallyFillable").and_then(|v| v.as_bool()).unwrap_or(false);
        // Guard validTo: the quote's expiry may be near-term (and the approve step can eat minutes),
        // so ensure at least ~20 minutes out.
        let quote_valid_to = q.get("validTo").and_then(|v| v.as_u64()).unwrap_or(0);
        let min_valid_to = now_unix().saturating_add(20 * 60);
        let valid_to = quote_valid_to.max(min_valid_to) as u32;
        // CoW's current protocol requires orders with feeAmount = 0; the network fee is taken from
        // the traded amount by solvers. So we sell the FULL amount (quote.sellAmount + quote.feeAmount)
        // and set feeAmount to zero. (Signing/submitting the quote's fee verbatim => "Fee must be
        // zero".)
        let quoted_sell = U256::from_str(&s("sellAmount")).unwrap_or(U256::ZERO);
        let quoted_fee = U256::from_str(&s("feeAmount")).unwrap_or(U256::ZERO);
        let sell_amount = quoted_sell.saturating_add(quoted_fee);
        // Apply slippage to the minimum buy — this is what makes the order fillable.
        let quoted_buy = U256::from_str(&s("buyAmount")).unwrap_or(U256::ZERO);
        let bps = U256::from(10_000u64.saturating_sub(slippage_bps.min(5_000) as u64));
        let buy_amount = quoted_buy * bps / U256::from(10_000u64);
        let fee_amount = U256::ZERO;

        let order = Order {
            sellToken: parse_address(&sell_token_s)?,
            buyToken: parse_address(&buy_token_s)?,
            receiver: parse_address(&receiver_s)?,
            sellAmount: sell_amount,
            buyAmount: buy_amount,
            validTo: valid_to,
            appData: B256::from_str(app_data_s.trim_start_matches("0x"))
                .map_err(|e| CoreError::rpc(format!("bad appData: {e}")))?,
            feeAmount: fee_amount,
            kind: kind.clone(),
            partiallyFillable: partially,
            sellTokenBalance: sell_bal.clone(),
            buyTokenBalance: buy_bal.clone(),
        };
        let domain = eip712_domain! {
            name: "Gnosis Protocol",
            version: "v2",
            chain_id: chain_id,
            verifying_contract: parse_address(COW_SETTLEMENT)?,
        };
        let digest = order.eip712_signing_hash(&domain);
        let signer = self.local_signer(from_index)?;
        let sig = signer
            .sign_hash_sync(&digest)
            .map_err(|e| CoreError::Signing(format!("sign order: {e}")))?;
        let signature = format!("0x{}", hex::encode(sig.as_bytes()));

        let from = self.address(from_index)?;
        let order_body = serde_json::json!({
            "sellToken": sell_token_s,
            "buyToken": buy_token_s,
            "receiver": receiver_s,
            "sellAmount": sell_amount.to_string(),
            "buyAmount": buy_amount.to_string(),
            "validTo": valid_to,
            "appData": app_data_s,
            "feeAmount": fee_amount.to_string(),
            "kind": kind,
            "partiallyFillable": partially,
            "sellTokenBalance": sell_bal,
            "buyTokenBalance": buy_bal,
            "signingScheme": "eip712",
            "signature": signature,
            "from": from,
        });
        let url = format!("https://api.cow.fi/{cow}/api/v1/orders");
        let resp2 = self.provider()?.http_post_json(&url, &order_body).await?;
        if let Some(uid) = resp2.as_str() {
            return Ok(uid.to_string());
        }
        let msg = resp2
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("order rejected");
        Err(CoreError::rpc(format!("CoW order: {msg}")))
    }

    /// Sell native ETH via CoW eth-flow: one on-chain tx to the eth-flow contract that wraps the ETH
    /// and places the order. Uses the fields from a CoW quote (obtained with the wrapped-native
    /// sellToken). `buy_token` is the ERC-20 to receive.
    pub async fn swap_eth_flow(
        &self,
        from_index: u32,
        quote_json: &str,
        buy_token: &str,
        slippage_bps: u32,
    ) -> Result<SendResult> {
        let info = chain_info(self.provider()?.chain_id());
        let eth_flow = info
            .eth_flow
            .ok_or_else(|| CoreError::rpc("native-ETH swaps unavailable on this network".to_string()))?;
        let resp: serde_json::Value = serde_json::from_str(quote_json)
            .map_err(|e| CoreError::rpc(format!("bad quote json: {e}")))?;
        let q = resp
            .get("quote")
            .ok_or_else(|| CoreError::rpc("quote missing".to_string()))?;
        let s = |k: &str| q.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
        // Same fee=0 rule as signed orders: sell the full amount, fee 0. The ETH sent (value) is the
        // full sell amount, unchanged from quote.sellAmount + quote.feeAmount.
        let quoted_sell = U256::from_str(&s("sellAmount")).unwrap_or(U256::ZERO);
        let quoted_fee = U256::from_str(&s("feeAmount")).unwrap_or(U256::ZERO);
        let sell_amount = quoted_sell.saturating_add(quoted_fee);
        // Apply slippage to the minimum buy so the order can fill.
        let quoted_buy = U256::from_str(&s("buyAmount")).unwrap_or(U256::ZERO);
        let bps = U256::from(10_000u64.saturating_sub(slippage_bps.min(5_000) as u64));
        let buy_amount = quoted_buy * bps / U256::from(10_000u64);
        let fee_amount = U256::ZERO;
        let quote_valid_to = q.get("validTo").and_then(|v| v.as_u64()).unwrap_or(0);
        let valid_to = quote_valid_to.max(now_unix().saturating_add(20 * 60)) as u32;
        let quote_id = resp.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
        let receiver = parse_address(&self.address(from_index)?)?; // must be non-zero for eth-flow

        let order = EthFlowData {
            buyToken: parse_address(buy_token)?,
            receiver,
            sellAmount: sell_amount,
            buyAmount: buy_amount,
            appData: B256::from_str(s("appData").trim_start_matches("0x"))
                .map_err(|e| CoreError::rpc(format!("bad appData: {e}")))?,
            feeAmount: fee_amount,
            validTo: valid_to,
            partiallyFillable: false,
            quoteId: quote_id,
        };
        let calldata = Bytes::from(IEthFlow::createOrderCall { order }.abi_encode());
        // msg.value = the full sell amount (fee is 0 in the order).
        let value = sell_amount;
        self.build_sign_send(from_index, parse_address(eth_flow)?, value, calldata, None, None, None)
            .await
    }

    // ---------- Token approvals ----------

    /// Batched `allowance(owner, spender)` reads for every (token, spender) pair. `tokens_json` and
    /// `spenders_json` are JSON arrays of addresses. Returns only the non-zero allowances so the UI
    /// can list revokable approvals.
    pub async fn token_allowances(
        &self,
        from_index: u32,
        tokens_json: &str,
        spenders_json: &str,
    ) -> Result<serde_json::Value> {
        let owner = parse_address(&self.address(from_index)?)?;
        let tokens: Vec<String> = serde_json::from_str(tokens_json)
            .map_err(|e| CoreError::rpc(format!("bad tokens list: {e}")))?;
        let spenders: Vec<String> = serde_json::from_str(spenders_json)
            .map_err(|e| CoreError::rpc(format!("bad spenders list: {e}")))?;
        let mut pairs: Vec<(Address, Address)> = Vec::new();
        for t in &tokens {
            if let Ok(ta) = parse_address(t) {
                for s in &spenders {
                    if let Ok(sa) = parse_address(s) {
                        pairs.push((ta, sa));
                    }
                }
            }
        }
        let provider = self.provider()?;
        let mut out: Vec<serde_json::Value> = Vec::new();
        for group in pairs.chunks(40) {
            let mut calls: Vec<(String, serde_json::Value)> = Vec::with_capacity(group.len());
            for (t, s) in group {
                let data = format!("0x{}", hex::encode(erc20::encode_allowance(owner, *s)));
                calls.push((
                    "eth_call".to_string(),
                    serde_json::json!([{ "to": t.to_string(), "data": data }, "latest"]),
                ));
            }
            let results = provider.call_batch(&calls).await?;
            for (p, (t, s)) in group.iter().enumerate() {
                let a = results
                    .get(p)
                    .and_then(|v| hex_bytes(v).ok())
                    .and_then(|b| erc20::decode_u256(&b))
                    .unwrap_or(U256::ZERO);
                if a > U256::ZERO {
                    out.push(serde_json::json!({
                        "token": t.to_checksum(None),
                        "spender": s.to_checksum(None),
                        "allowance": a.to_string(),
                    }));
                }
            }
        }
        Ok(serde_json::json!({ "allowances": out }))
    }

    /// Revoke an ERC-20 approval by setting the allowance to zero (`approve(spender, 0)`).
    pub async fn revoke_approval(
        &self,
        from_index: u32,
        token: &str,
        spender: &str,
    ) -> Result<SendResult> {
        let token_addr = parse_address(token)?;
        let spender_addr = parse_address(spender)?;
        let data = Bytes::from(erc20::encode_approve(spender_addr, U256::ZERO));
        self.build_sign_send(from_index, token_addr, U256::ZERO, data, None, None, None)
            .await
    }

    /// DefiLlama current prices for a comma-separated list of coin keys
    /// (e.g. `ethereum:0x…,coingecko:ethereum`). Used to cross-check CoW quote rates.
    pub async fn defillama_prices(&self, coins_csv: &str) -> Result<serde_json::Value> {
        let url = format!("https://coins.llama.fi/prices/current/{coins_csv}");
        self.provider()?.http_get_json(&url).await
    }

    // ---------- Multi-router swap aggregator (quotes) ----------

    /// Fetch quotes from every keyless router supported on the current chain, in parallel over Tor,
    /// and return them best-first (largest expected output). `sell`/`buy` are token addresses; an
    /// empty string means the native coin. Routers that error or don't support the chain are simply
    /// dropped. Returns `{ "quotes": [RouterQuote, ...] }`.
    pub async fn swap_quotes(
        &self,
        from_index: u32,
        sell: &str,
        buy: &str,
        sell_amount_wei: &str,
        sell_is_native: bool,
        sell_decimals: u8,
        buy_decimals: u8,
        slippage_bps: u32,
    ) -> Result<serde_json::Value> {
        let buy_is_native = buy.is_empty();
        let (cow, kyber, odos, para, oo) = tokio::join!(
            self.cow_quote_norm(from_index, sell, buy, sell_amount_wei, sell_is_native, buy_is_native),
            self.kyber_quote(sell, buy, sell_amount_wei, sell_is_native, buy_is_native),
            self.odos_quote(from_index, sell, buy, sell_amount_wei, sell_is_native, buy_is_native, slippage_bps),
            self.paraswap_quote(sell, buy, sell_amount_wei, sell_is_native, buy_is_native, sell_decimals, buy_decimals),
            self.openocean_quote(sell, buy, sell_amount_wei, sell_is_native, buy_is_native, sell_decimals),
        );
        let _ = buy_decimals;
        let mut quotes: Vec<RouterQuote> = Vec::new();
        for r in [cow, kyber, odos, para, oo] {
            if let Ok(q) = r {
                if !q.buy_amount.is_empty() && q.buy_amount != "0" {
                    quotes.push(q);
                }
            }
        }
        quotes.sort_by(|a, b| {
            let av = U256::from_str(&a.buy_amount).unwrap_or(U256::ZERO);
            let bv = U256::from_str(&b.buy_amount).unwrap_or(U256::ZERO);
            bv.cmp(&av)
        });
        Ok(serde_json::json!({ "quotes": quotes }))
    }

    async fn cow_quote_norm(
        &self,
        from_index: u32,
        sell: &str,
        buy: &str,
        amount: &str,
        sell_is_native: bool,
        buy_is_native: bool,
    ) -> Result<RouterQuote> {
        let info = chain_info(self.provider()?.chain_id());
        if info.cow_network.is_none() {
            return Err(CoreError::rpc("cow unsupported".to_string()));
        }
        // Selling the native coin via CoW needs eth-flow (only where a verified eth-flow contract is
        // configured, i.e. mainnet). On other CoW chains (e.g. Arbitrum) don't offer a CoW route for
        // native sells — it would quote but fail to execute. Other routers handle native there.
        if sell_is_native && info.eth_flow.is_none() {
            return Err(CoreError::rpc("cow native-sell unavailable on this chain".to_string()));
        }
        let buy_param = if buy_is_native { COW_BUY_ETH } else { buy };
        let resp = self.swap_quote(from_index, sell, buy_param, amount, sell_is_native).await?;
        let buy_amount = resp
            .get("quote")
            .and_then(|q| q.get("buyAmount"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if buy_amount.is_empty() {
            return Err(CoreError::rpc("cow: empty out".to_string()));
        }
        Ok(RouterQuote {
            router_id: "cow".into(),
            label: "CoW Protocol".into(),
            buy_amount,
            gas_usd: 0.0,
            gas_estimate: "0".into(),
            spender: COW_VAULT_RELAYER.into(),
            to: String::new(),
            kind: "signed-order".into(),
        })
    }

    async fn kyber_quote(
        &self,
        sell: &str,
        buy: &str,
        amount: &str,
        sell_is_native: bool,
        buy_is_native: bool,
    ) -> Result<RouterQuote> {
        let slug = chains::kyber_slug(self.provider()?.chain_id())
            .ok_or_else(|| CoreError::rpc("kyber unsupported".to_string()))?;
        let tin = if sell_is_native { EVM_NATIVE_SENTINEL } else { sell };
        let tout = if buy_is_native { EVM_NATIVE_SENTINEL } else { buy };
        let url = format!(
            "{KYBER_API}/{slug}/api/v1/routes?tokenIn={tin}&tokenOut={tout}&amountIn={amount}"
        );
        let resp = self.provider()?.http_get_json(&url).await?;
        parse_kyber_quote(&resp)
    }

    #[allow(clippy::too_many_arguments)]
    async fn odos_quote(
        &self,
        from_index: u32,
        sell: &str,
        buy: &str,
        amount: &str,
        sell_is_native: bool,
        buy_is_native: bool,
        slippage_bps: u32,
    ) -> Result<RouterQuote> {
        let chain = self.provider()?.chain_id();
        if !chains::odos_supported(chain) {
            return Err(CoreError::rpc("odos unsupported".to_string()));
        }
        let from = self.address(from_index)?;
        let tin = if sell_is_native { ODOS_NATIVE } else { sell };
        let tout = if buy_is_native { ODOS_NATIVE } else { buy };
        let body = serde_json::json!({
            "chainId": chain,
            "inputTokens": [{ "tokenAddress": tin, "amount": amount }],
            "outputTokens": [{ "tokenAddress": tout, "proportion": 1 }],
            "userAddr": from,
            "slippageLimitPercent": (slippage_bps as f64) / 100.0,
        });
        let resp = self
            .provider()?
            .http_post_json(&format!("{ODOS_API}/sor/quote/v3"), &body)
            .await?;
        parse_odos_quote(&resp)
    }

    #[allow(clippy::too_many_arguments)]
    async fn paraswap_quote(
        &self,
        sell: &str,
        buy: &str,
        amount: &str,
        sell_is_native: bool,
        buy_is_native: bool,
        sell_decimals: u8,
        buy_decimals: u8,
    ) -> Result<RouterQuote> {
        let chain = self.provider()?.chain_id();
        if !chains::paraswap_supported(chain) {
            return Err(CoreError::rpc("paraswap unsupported".to_string()));
        }
        let src = if sell_is_native { EVM_NATIVE_SENTINEL } else { sell };
        let dst = if buy_is_native { EVM_NATIVE_SENTINEL } else { buy };
        let url = format!(
            "{PARASWAP_API}/prices?srcToken={src}&destToken={dst}&amount={amount}\
             &srcDecimals={sell_decimals}&destDecimals={buy_decimals}&side=SELL&network={chain}"
        );
        let resp = self.provider()?.http_get_json(&url).await?;
        parse_paraswap_quote(&resp)
    }

    async fn openocean_quote(
        &self,
        sell: &str,
        buy: &str,
        amount_wei: &str,
        sell_is_native: bool,
        buy_is_native: bool,
        sell_decimals: u8,
    ) -> Result<RouterQuote> {
        let slug = chains::openocean_slug(self.provider()?.chain_id())
            .ok_or_else(|| CoreError::rpc("openocean unsupported".to_string()))?;
        let tin = if sell_is_native { EVM_NATIVE_SENTINEL } else { sell };
        let tout = if buy_is_native { EVM_NATIVE_SENTINEL } else { buy };
        // OpenOcean v3 takes a *human* amount and a gwei gas price.
        let human = format_units(
            U256::from_str(amount_wei).map_err(|_| CoreError::Amount("bad amount".into()))?,
            sell_decimals,
        );
        let url = format!(
            "{OPENOCEAN_API}/v3/{slug}/quote?inTokenAddress={tin}&outTokenAddress={tout}\
             &amount={human}&gasPrice=5"
        );
        let resp = self.provider()?.http_get_json(&url).await?;
        parse_openocean_quote(&resp)
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

        // Fetch the three explorer lists CONCURRENTLY (they're independent) instead of one after
        // another — cuts an account's history latency to roughly that of a single list. Bounded by
        // the global RPC semaphore so the fan-out never floods Tor.
        let (txlist, tokentx, internal) = tokio::join!(
            fetch_all_pages(provider, base, "txlist", &owner),
            fetch_all_pages(provider, base, "tokentx", &owner),
            fetch_all_pages(provider, base, "txlistinternal", &owner),
        );

        // Native ETH transactions — ALL pages, so an old wallet's early history (e.g. 2021) isn't
        // truncated to the most recent 100.
        for r in txlist {
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
                ..Default::default()
            });
        }

        // ERC20 token transfers — ALL pages.
        for r in tokentx {
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
                log_index: s("logIndex").parse().unwrap_or(0),
                ..Default::default()
            });
        }

        // Internal (contract-initiated) native transfers TO the owner — ALL pages. These are the
        // native leg an EOA receives via a contract: the output of a token->native swap, a WETH
        // unwrap, a refund, etc. Without them a token->native swap looks like a one-sided "Sent"
        // (the native the user got back arrives by an internal tx, not the external tx list). Only
        // inbound value is added; native the owner *sends* is already in the external tx list above.
        for r in internal {
            let s = |k: &str| r.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            if s("to").to_lowercase() != owner {
                continue; // only native received via a contract
            }
            let value = U256::from_str(&s("value")).unwrap_or(U256::ZERO);
            if value.is_zero() {
                continue; // ignore 0-value internal calls (delegatecall bookkeeping, etc.)
            }
            items.push(HistoryItem {
                direction: "in".to_string(),
                counterparty: s("from"),
                amount: value.to_string(),
                formatted: format_units(value, 18),
                tx_hash: s("hash"),
                block: s("blockNumber").parse().unwrap_or(0),
                token: String::new(),
                symbol: info.native_symbol.to_string(),
                timestamp: s("timeStamp").parse().unwrap_or(0),
                fee: String::new(), // gas is charged on the external tx, not the internal transfer
                failed: s("isError") == "1",
                ..Default::default()
            });
        }

        // Drop exact-duplicate rows (same tx + asset + direction + amount) in case the explorer
        // returns overlapping entries; legitimately-distinct transfers (different hash/token/amount,
        // e.g. a swap moving two assets in one tx) are preserved.
        let mut seen = std::collections::HashSet::new();
        items.retain(|h| {
            // Include the log index so two LEGITIMATE identical transfers of the same token+amount in
            // one tx (e.g. a batch/airdrop emitting two equal Transfer events) aren't collapsed into
            // one — while true duplicate rows (same log index) from overlapping pages still dedup.
            seen.insert(format!(
                "{}|{}|{}|{}|{}",
                h.tx_hash, h.token, h.direction, h.amount, h.log_index
            ))
        });

        // Collapse on-chain swaps into a single "Swap A -> B" row: any tx where the owner both sent
        // asset A and received asset B (a router swap). CoW settlements are skipped here — they are
        // surfaced (with richer status) via `cow_orders`.
        let items = group_swaps(items);

        Ok(items)
    }

    /// Symbol + decimals for a token address from the tracked list; falls back to a short address
    /// and 18 decimals for unknown tokens.
    fn token_meta_hint(&self, addr: &str) -> (String, u8) {
        for t in &self.secrets.tokens {
            if t.address.eq_ignore_ascii_case(addr) {
                return (t.symbol.clone(), t.decimals);
            }
        }
        (short_addr_str(addr), 18)
    }

    /// CoW Protocol swaps for `index` (pending + historical, including months-old) from CoW's
    /// order-book API over Tor. Returns swap `HistoryItem`s with status. Empty on non-CoW chains.
    pub async fn cow_orders(&self, index: u32) -> Result<Vec<HistoryItem>> {
        let provider = self.provider()?;
        let Some(cow) = chain_info(provider.chain_id()).cow_network else {
            return Ok(Vec::new());
        };
        let owner = self.address(index)?;
        let url = format!("https://api.cow.fi/{cow}/api/v1/account/{owner}/orders?limit=200");
        let v = provider.http_get_json(&url).await?;
        let arr = v.as_array().cloned().unwrap_or_default();
        let mut out = Vec::with_capacity(arr.len());
        for o in arr {
            let g = |k: &str| o.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
            let status = match g("status").as_str() {
                "fulfilled" => "done",
                "open" | "presignaturePending" | "scheduled" | "active" => "pending",
                _ => "failed", // expired / cancelled
            }
            .to_string();
            let done = status == "done";
            let take = |exec: &str, quoted: &str| -> String {
                if done {
                    let e = g(exec);
                    if !e.is_empty() && e != "0" {
                        return e;
                    }
                }
                g(quoted)
            };
            let sell_token = g("sellToken");
            let buy_token = g("buyToken");
            let sell_raw = take("executedSellAmount", "sellAmount");
            let buy_raw = take("executedBuyAmount", "buyAmount");
            let (sell_sym, sell_dec) = self.token_meta_hint(&sell_token);
            let (buy_sym, buy_dec) = self.token_meta_hint(&buy_token);
            let sell_amt = U256::from_str(&sell_raw).unwrap_or(U256::ZERO);
            let buy_amt = U256::from_str(&buy_raw).unwrap_or(U256::ZERO);
            out.push(HistoryItem {
                direction: "swap".into(),
                counterparty: "CoW Protocol".into(),
                amount: sell_raw,
                formatted: format_units(sell_amt, sell_dec),
                tx_hash: g("uid"),
                block: 0,
                token: sell_token,
                symbol: sell_sym,
                timestamp: parse_iso8601(&g("creationDate")),
                fee: String::new(),
                failed: status == "failed",
                kind: "swap".into(),
                buy_symbol: buy_sym,
                buy_formatted: format_units(buy_amt, buy_dec),
                status,
                log_index: 0,
            });
        }
        Ok(out)
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
        // Not every keyless explorer implements the Blockscout v2 NFT endpoint (e.g. the Routescan
        // Etherscan-compatible API used for Avalanche). Treat any failure/absence as "no NFTs" rather
        // than surfacing an error.
        let Ok(v) = provider.http_get_json(&url).await else {
            return Ok(Vec::new());
        };
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
        // NFT image URLs come from an untrusted explorer response. Only fetch https:// (over Tor this
        // is safe; but in direct/own-node mode an http://127.0.0.1/... URL would be an SSRF against
        // local services, and http:// leaks in cleartext). Reject everything else.
        if !is_safe_image_url(url) {
            return Err(CoreError::rpc("unsupported or unsafe image URL"));
        }
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
            KeySource::WatchOnly => Err(CoreError::Signing(
                "watch-only wallet: cannot sign transactions".into(),
            )),
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
        nonce_override: Option<u64>, // reuse a specific nonce to replace (speed-up/cancel) a pending tx
    ) -> Result<SendResult> {
        let provider = self.provider()?;
        // The sending address comes from the account's derivation (software) or the device's cached
        // address (hardware) — no local key material is required to build the tx.
        let from: Address = parse_address(&self.address(from_index)?)?;

        let nonce = match nonce_override {
            Some(n) => n,
            None => {
                let nonce_hex = provider.get_transaction_count(&from.to_string()).await?;
                parse_hex_u64(&nonce_hex)?
            }
        };

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
        Ok(SendResult { tx_hash, nonce })
    }
}

// ---------- helpers ----------

/// Write `bytes` to `path` durably and without ever leaving a truncated/half-written wallet: write
/// to a sibling temp file, fsync it, then atomically rename over the target. On Unix the file is
/// created with owner-only (0600) permissions so the encrypted wallet isn't world-readable.
fn atomic_write(path: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SAVE_SEQ: AtomicU64 = AtomicU64::new(0);

    let target = std::path::Path::new(path);
    let dir = target.parent().unwrap_or_else(|| std::path::Path::new("."));
    if !dir.as_os_str().is_empty() {
        std::fs::create_dir_all(dir)?;
    }

    // Unique temp name in the same directory. A per-process/per-call suffix means two concurrent
    // saves (which only hold a shared read lock) can't clobber each other's temp file, and a stale
    // temp left by a crash is never reused.
    let base = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("wallet");
    let tmp = dir.join(format!(
        "{base}.{}.{}.tmp",
        std::process::id(),
        SAVE_SEQ.fetch_add(1, Ordering::Relaxed)
    ));

    let mut opts = std::fs::OpenOptions::new();
    // Unique temp name (pid+seq) makes collisions between live writers impossible; truncate cleanly
    // reuses a stale temp left by a crashed prior run that happened to reuse this pid.
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()?; // durability: ensure bytes hit disk before the rename
    }

    // Atomically replace the target. std::fs::rename overwrites an existing file on BOTH Unix and
    // Windows (MoveFileExW | MOVEFILE_REPLACE_EXISTING), so there is no delete-then-rename window
    // that could lose the wallet on a crash/power loss. On Windows a transient lock (AV/indexer)
    // can make the replace fail, so retry briefly; on persistent failure the original is left
    // intact and the temp is cleaned up.
    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..5 {
        match std::fs::rename(&tmp, target) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                #[cfg(windows)]
                std::thread::sleep(std::time::Duration::from_millis(40 * (attempt + 1)));
                #[cfg(not(windows))]
                let _ = attempt;
            }
        }
    }
    let _ = std::fs::remove_file(&tmp); // don't leave the temp behind on failure
    Err(last_err
        .map(CoreError::from)
        .unwrap_or_else(|| CoreError::Keystore("atomic rename failed".into())))
}

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
/// truncated to the most recent page.
///
/// CRITICAL for correctness across a multi-account wallet: the keyless Blockscout explorer
/// rate-limits by IP, and every account in the wallet shares ONE Tor exit. A burst of per-account
/// history fetches therefore reliably trips the limit, and Blockscout answers with
/// `{"message":"NOTOK","result":"Max rate limit reached"}` (or a transport error). The old code
/// treated a non-array `result` as "no more transactions" and returned an EMPTY list — so a
/// rate-limited account silently contributed ZERO history. Across ~160 accounts that turned a full
/// history into a tiny, wrong subset (the "only 221 transactions" bug).
///
/// So: retry the SAME page with exponential backoff on a rate-limit / transient failure, and only
/// stop on a genuine terminal response (an array shorter than a full page, or an explicit
/// "no transactions found"). Bounded by MAX_PAGES and MAX_RETRIES so a pathological account can't
/// loop forever.
async fn fetch_all_pages(
    provider: &RpcProvider,
    base: &str,
    action: &str,
    owner: &str,
) -> Vec<serde_json::Value> {
    const PER_PAGE: usize = 1000;
    const MAX_PAGES: u32 = 25; // up to 25k txs per list — plenty, and bounds Tor round-trips
    const MAX_RETRIES: u32 = 6; // per page, on rate-limit / transient error
    let mut out = Vec::new();
    let mut page = 1u32;
    while page <= MAX_PAGES {
        if crate::provider::shutting_down() {
            return out; // app closing — stop paging and release the core lock promptly
        }
        let url = format!(
            "{base}&action={action}&address={owner}&sort=desc&page={page}&offset={PER_PAGE}"
        );
        let mut attempt = 0u32;
        loop {
            match provider.http_get_json(&url).await {
                Ok(v) => {
                    if let Some(rows) = v.get("result").and_then(|r| r.as_array()) {
                        let n = rows.len();
                        out.extend(rows.iter().cloned());
                        if n < PER_PAGE {
                            return out; // last page reached
                        }
                        break; // full page — go fetch the next one
                    }
                    // `result` is missing or not an array. Two very different cases:
                    //   • a genuine "No transactions found" (message == "No transactions found",
                    //     result is often an empty string) → this account/list is simply done.
                    //   • a rate-limit / server hiccup ("Max rate limit reached", "NOTOK", etc.)
                    //     → must NOT be treated as done; back off and retry the SAME page.
                    let msg = format!(
                        "{} {}",
                        v.get("message").and_then(|m| m.as_str()).unwrap_or(""),
                        v.get("result").and_then(|r| r.as_str()).unwrap_or("")
                    )
                    .to_lowercase();
                    let rate_limited = msg.contains("rate limit")
                        || msg.contains("max rate")
                        || msg.contains("too many")
                        || msg.contains("notok")
                        || msg.contains("try again");
                    if rate_limited && attempt < MAX_RETRIES && !crate::provider::shutting_down() {
                        attempt += 1;
                        crate::provider::interruptible_sleep(backoff_delay(attempt)).await;
                        continue; // retry same page
                    }
                    // Terminal: genuine empty result, or we've exhausted retries.
                    return out;
                }
                Err(_) => {
                    // Transport/parse error (often a 429 body that isn't JSON). Retry with backoff
                    // rather than silently dropping the rest of this account's history.
                    if attempt < MAX_RETRIES && !crate::provider::shutting_down() {
                        attempt += 1;
                        crate::provider::interruptible_sleep(backoff_delay(attempt)).await;
                        continue;
                    }
                    return out;
                }
            }
        }
        page += 1;
    }
    out
}

/// Exponential backoff (capped) for retrying a rate-limited explorer page: 0.5s, 1s, 2s, 4s, 8s, 8s.
/// Enough to let a shared-Tor-exit rate window recover without stalling forever.
fn backoff_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(4); // 0..=4
    Duration::from_millis((500u64 << shift).min(8000))
}

/// Current unix time in seconds (0 if the clock is before the epoch, which shouldn't happen).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Short "0x1234…abcd" form of an address for unknown-token display.
fn short_addr_str(a: &str) -> String {
    if a.len() >= 12 {
        format!("{}…{}", &a[..6], &a[a.len() - 4..])
    } else {
        a.to_string()
    }
}

/// Parse an ISO-8601 UTC timestamp (e.g. "2025-01-16T07:51:51.983474Z") into unix seconds. Returns
/// 0 if it can't be parsed. Uses Howard Hinnant's days-from-civil algorithm (no chrono dependency).
fn parse_iso8601(s: &str) -> u64 {
    if s.len() < 19 {
        return 0;
    }
    let num = |a: usize, z: usize| s.get(a..z).and_then(|p| p.parse::<i64>().ok()).unwrap_or(0);
    let (y, mo, d, h, mi, se) = (
        num(0, 4),
        num(5, 7),
        num(8, 10),
        num(11, 13),
        num(14, 16),
        num(17, 19),
    );
    if mo == 0 || d == 0 {
        return 0;
    }
    let y = if mo <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    (days * 86400 + h * 3600 + mi * 60 + se).max(0) as u64
}

/// Collapse on-chain swap transactions (owner sent asset A and received asset B in the same tx)
/// into a single `kind == "swap"` `HistoryItem`. CoW settlement/vault txs are left untouched here —
/// those are surfaced with richer status via `Wallet::cow_orders` (avoiding duplicate rows).
fn group_swaps(items: Vec<HistoryItem>) -> Vec<HistoryItem> {
    use std::collections::HashMap;
    const COW_SETTLE: &str = "0x9008d19f58aabd9ed0d60971565aa8510560ab41";
    const COW_VAULT: &str = "0xc92e8bdf79f0507f65a392b0ab4667716bfe0110";

    let mut by_tx: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, it) in items.iter().enumerate() {
        if !it.tx_hash.is_empty() {
            by_tx.entry(it.tx_hash.clone()).or_default().push(i);
        }
    }

    let mut remove = vec![false; items.len()];
    let mut swaps: Vec<HistoryItem> = Vec::new();
    for (_tx, idxs) in by_tx {
        if idxs.len() < 2 {
            continue;
        }
        // CoW settlements come from cow_orders; don't also synthesize a row here.
        let is_cow = idxs.iter().any(|&i| {
            let cp = items[i].counterparty.to_lowercase();
            cp == COW_SETTLE || cp == COW_VAULT
        });
        if is_cow {
            continue;
        }
        // Pick the meaningful sent/received leg: prefer a real token transfer, else a non-zero
        // native amount (skips the 0-value native "gas only" row of a token swap).
        let pick = |dir: &str| -> Option<usize> {
            idxs.iter()
                .cloned()
                .find(|&i| items[i].direction == dir && !items[i].token.is_empty() && items[i].amount != "0")
                .or_else(|| {
                    idxs.iter()
                        .cloned()
                        .find(|&i| items[i].direction == dir && items[i].amount != "0")
                })
        };
        let (Some(so), Some(bi)) = (pick("out"), pick("in")) else {
            continue;
        };
        // Same asset in and out isn't a swap.
        if items[so].token.eq_ignore_ascii_case(&items[bi].token) && items[so].symbol == items[bi].symbol {
            continue;
        }
        // Fee: the native "out" row of this tx carries the gas cost.
        let fee = idxs
            .iter()
            .cloned()
            .find(|&i| items[i].token.is_empty() && !items[i].fee.is_empty())
            .map(|i| items[i].fee.clone())
            .unwrap_or_else(|| items[so].fee.clone());
        let failed = items[so].failed || items[bi].failed;
        swaps.push(HistoryItem {
            direction: "swap".into(),
            counterparty: items[so].counterparty.clone(),
            amount: items[so].amount.clone(),
            formatted: items[so].formatted.clone(),
            tx_hash: items[so].tx_hash.clone(),
            block: items[so].block,
            token: items[so].token.clone(),
            symbol: items[so].symbol.clone(),
            timestamp: items[so].timestamp,
            fee,
            failed,
            kind: "swap".into(),
            buy_symbol: items[bi].symbol.clone(),
            buy_formatted: items[bi].formatted.clone(),
            status: if failed { "failed".into() } else { "done".into() },
            log_index: 0,
        });
        for &i in &idxs {
            remove[i] = true; // fold every transfer of this swap tx into the single row
        }
    }

    let mut result: Vec<HistoryItem> = items
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !remove[*i])
        .map(|(_, h)| h)
        .collect();
    result.append(&mut swaps);
    result.sort_by(|a, b| b.block.cmp(&a.block));
    result
}

fn parse_address(s: &str) -> Result<Address> {
    let t = s.trim();
    // If the input is MIXED-case it carries an EIP-55 checksum — enforce it so a mistyped/corrupted
    // paste (a wrong checksum) is rejected rather than silently accepted (funds-loss defence). All-
    // lower / all-upper input has no checksum to verify, so parse it leniently.
    let hex = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    let has_lower = hex.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = hex.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Address::parse_checksummed(t, None).map_err(|_| CoreError::Address(s.to_string()));
    }
    Address::from_str(t).map_err(|_| CoreError::Address(s.to_string()))
}

/// EIP-137 ENS namehash of a dotted name ("a.b.eth"): node = keccak256(parent_node ++ keccak256(label)),
/// folded right-to-left from the zero root.
fn ens_namehash(name: &str) -> [u8; 32] {
    use alloy::primitives::keccak256;
    let mut node = [0u8; 32];
    if !name.is_empty() {
        for label in name.split('.').rev() {
            let label_hash = keccak256(label.as_bytes());
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&node);
            buf[32..].copy_from_slice(label_hash.as_slice());
            node = keccak256(buf).0;
        }
    }
    node
}

/// Extract the 20-byte address from a 32-byte ABI word returned by an `eth_call` (0x + 64 hex).
fn word_to_address(hex_word: &str) -> Result<Address> {
    let s = hex_word.trim_start_matches("0x").trim_start_matches("0X");
    if s.len() < 64 {
        return Err(CoreError::rpc("bad eth_call result word"));
    }
    Address::from_str(&format!("0x{}", &s[24..64])).map_err(|_| CoreError::rpc("bad address word"))
}

/// Whether an (untrusted) NFT image URL is safe to fetch: https only, and NOT pointing at a
/// loopback/private host (SSRF defence for direct/own-node mode; over Tor these can't be reached
/// anyway, but we reject them regardless). data: URLs are handled by the caller before this.
fn is_safe_image_url(url: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(url) else {
        return false;
    };
    if u.scheme() != "https" {
        return false;
    }
    match u.host_str() {
        Some(h) => {
            let host = h.trim_start_matches('[').trim_end_matches(']');
            if host.eq_ignore_ascii_case("localhost") {
                return false;
            }
            // Reject loopback/private/link-local IP literals; allow hostnames (resolved via Tor).
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                let bad = ip.is_loopback()
                    || ip.is_unspecified()
                    || match ip {
                        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
                        std::net::IpAddr::V6(_) => false,
                    };
                return !bad;
            }
            true
        }
        None => false,
    }
}

/// Minimum output after `slippage_bps` slippage, as a decimal-wei string: `amount * (10000-bps)/10000`
/// (bps capped at 50%). Used to display an honest "minimum received" for routers whose calldata
/// enforces slippage internally.
fn apply_slippage_min(amount_wei: &str, slippage_bps: u32) -> String {
    let a = U256::from_str(amount_wei.trim()).unwrap_or(U256::ZERO);
    let bps = U256::from(10_000u64.saturating_sub(slippage_bps.min(5_000) as u64));
    (a * bps / U256::from(10_000u64)).to_string()
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
/// Parse a KyberSwap `routes` response into a normalized quote.
fn parse_kyber_quote(resp: &serde_json::Value) -> Result<RouterQuote> {
    let data = resp
        .get("data")
        .ok_or_else(|| CoreError::rpc("kyber: no data".to_string()))?;
    let rs = data
        .get("routeSummary")
        .ok_or_else(|| CoreError::rpc("kyber: no route".to_string()))?;
    let buy_amount = rs.get("amountOut").map(json_num_str).unwrap_or_default();
    if buy_amount.is_empty() {
        return Err(CoreError::rpc("kyber: empty out".to_string()));
    }
    let gas_usd = rs
        .get("gasUsd")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    let gas_estimate = rs.get("gas").map(json_num_str).unwrap_or_else(|| "0".into());
    let router = data
        .get("routerAddress")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    Ok(RouterQuote {
        router_id: "kyberswap".into(),
        label: "KyberSwap".into(),
        buy_amount,
        gas_usd,
        gas_estimate,
        spender: router.clone(),
        to: router,
        kind: "onchain".into(),
    })
}

/// Parse an Odos `/sor/quote` response into a normalized quote.
fn parse_odos_quote(resp: &serde_json::Value) -> Result<RouterQuote> {
    let buy_amount = resp
        .get("outAmounts")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .map(json_num_str)
        .unwrap_or_default();
    if buy_amount.is_empty() {
        return Err(CoreError::rpc("odos: no out".to_string()));
    }
    let gas_usd = resp
        .get("gasEstimateValue")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    Ok(RouterQuote {
        router_id: "odos".into(),
        label: "Odos".into(),
        buy_amount,
        gas_usd,
        gas_estimate: "0".into(),
        spender: String::new(), // resolved at build (transaction.to)
        to: String::new(),
        kind: "onchain".into(),
    })
}

/// Parse a Paraswap `/prices` response into a normalized quote.
fn parse_paraswap_quote(resp: &serde_json::Value) -> Result<RouterQuote> {
    let pr = resp
        .get("priceRoute")
        .ok_or_else(|| CoreError::rpc("paraswap: no route".to_string()))?;
    let buy_amount = pr.get("destAmount").map(json_num_str).unwrap_or_default();
    if buy_amount.is_empty() {
        return Err(CoreError::rpc("paraswap: empty out".to_string()));
    }
    let gas_usd = pr
        .get("gasCostUSD")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    let spender = pr
        .get("tokenTransferProxy")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let to = pr
        .get("contractAddress")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    Ok(RouterQuote {
        router_id: "paraswap".into(),
        label: "ParaSwap".into(),
        buy_amount,
        gas_usd,
        gas_estimate: "0".into(),
        spender,
        to,
        kind: "onchain".into(),
    })
}

/// Parse an OpenOcean `/quote` response into a normalized quote.
fn parse_openocean_quote(resp: &serde_json::Value) -> Result<RouterQuote> {
    let data = resp
        .get("data")
        .ok_or_else(|| CoreError::rpc("openocean: no data".to_string()))?;
    let buy_amount = data.get("outAmount").map(json_num_str).unwrap_or_default();
    if buy_amount.is_empty() {
        return Err(CoreError::rpc("openocean: empty out".to_string()));
    }
    let gas_estimate = data
        .get("estimatedGas")
        .map(json_num_str)
        .unwrap_or_else(|| "0".into());
    Ok(RouterQuote {
        router_id: "openocean".into(),
        label: "OpenOcean".into(),
        buy_amount,
        gas_usd: 0.0,
        gas_estimate,
        spender: String::new(), // resolved at build
        to: String::new(),
        kind: "onchain".into(),
    })
}

pub fn format_units(value: U256, decimals: u8) -> String {
    // A malicious token can report absurd decimals; 10^decimals overflows U256 past ~77. Clamp so a
    // crafted token can't panic the formatter (it just displays with fewer places).
    let decimals = decimals.min(36);
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
    let decimals = decimals.min(36); // guard against adversarial token decimals (10^d overflow)
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
    fn ens_namehash_matches_eip137_vectors() {
        // Canonical EIP-137 test vectors.
        assert_eq!(ens_namehash(""), [0u8; 32]);
        assert_eq!(
            hex::encode(ens_namehash("eth")),
            "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
        );
        assert_eq!(
            hex::encode(ens_namehash("foo.eth")),
            "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f"
        );
    }

    #[test]
    fn word_to_address_extracts_low_20_bytes() {
        let word = "0x000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045";
        assert_eq!(
            word_to_address(word).unwrap().to_checksum(None),
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        );
    }

    #[test]
    fn parse_router_quotes_from_samples() {
        // KyberSwap routes: data.routeSummary.amountOut + data.routerAddress.
        let kyber = serde_json::json!({
            "data": {
                "routeSummary": { "amountOut": "177656413", "gas": "210000", "gasUsd": "1.23" },
                "routerAddress": "0x6131B5fae19EA4f9D964eAc0408E4408b66337b5"
            }
        });
        let q = parse_kyber_quote(&kyber).unwrap();
        assert_eq!(q.router_id, "kyberswap");
        assert_eq!(q.buy_amount, "177656413");
        assert_eq!(q.spender, "0x6131B5fae19EA4f9D964eAc0408E4408b66337b5");
        assert_eq!(q.to, q.spender);
        assert!((q.gas_usd - 1.23).abs() < 1e-9);

        // Odos quote: outAmounts[0] (string) + gasEstimateValue.
        let odos = serde_json::json!({ "outAmounts": ["177700000"], "gasEstimateValue": 2.5 });
        let q = parse_odos_quote(&odos).unwrap();
        assert_eq!(q.router_id, "odos");
        assert_eq!(q.buy_amount, "177700000");
        assert!((q.gas_usd - 2.5).abs() < 1e-9);

        // Paraswap prices: priceRoute.destAmount + tokenTransferProxy (spender) + contractAddress (to).
        let para = serde_json::json!({
            "priceRoute": {
                "destAmount": "177731275",
                "gasCostUSD": "0.046660",
                "tokenTransferProxy": "0x216b4b4ba9f3e719726886d34a177484278bfcae",
                "contractAddress": "0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57"
            }
        });
        let q = parse_paraswap_quote(&para).unwrap();
        assert_eq!(q.router_id, "paraswap");
        assert_eq!(q.buy_amount, "177731275");
        assert_eq!(q.spender, "0x216b4b4ba9f3e719726886d34a177484278bfcae");
        assert_eq!(q.to, "0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57");

        // OpenOcean quote: data.outAmount + estimatedGas.
        let oo = serde_json::json!({ "data": { "outAmount": "177706794", "estimatedGas": 210487 } });
        let q = parse_openocean_quote(&oo).unwrap();
        assert_eq!(q.router_id, "openocean");
        assert_eq!(q.buy_amount, "177706794");
        assert_eq!(q.gas_estimate, "210487");

        // Missing output is an error (router gets dropped from the comparison).
        assert!(parse_kyber_quote(&serde_json::json!({ "data": { "routeSummary": {} } })).is_err());
    }

    #[test]
    fn cow_order_type_hash_matches() {
        // Must equal GPv2Order.TYPE_HASH from @cowprotocol/contracts. If our struct name, field
        // order, or types differ, the type hash changes and CoW rejects every signature.
        let th = alloy::primitives::keccak256(Order::eip712_encode_type().as_bytes());
        assert_eq!(
            format!("0x{}", hex::encode(th)),
            "0xd5a25ba2e97094ad7d83dc28a6572da797d6b3e7fc6663bd93efb789fc17e489"
        );
    }

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
    fn sign_and_verify_message_roundtrip() {
        let w = Wallet::restore("test test test test test test test test test test test junk").unwrap();
        let addr = w.address(0).unwrap();
        let sig = w.sign_message(0, "Hello Aero").unwrap();
        assert!(sig.starts_with("0x") && sig.len() == 132, "expect 65-byte hex sig");
        // The recovered signer must equal the signing account.
        assert_eq!(
            Wallet::verify_message("Hello Aero", &sig).unwrap().to_lowercase(),
            addr.to_lowercase()
        );
        // A different message must NOT recover the same address.
        assert_ne!(
            Wallet::verify_message("Tampered", &sig).unwrap().to_lowercase(),
            addr.to_lowercase()
        );
    }

    #[test]
    fn watch_only_tracks_address_but_cannot_sign() {
        let a = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let w = Wallet::watch_only(&[a.to_string()]).unwrap();
        assert!(w.is_watch_only());
        assert_eq!(w.account_count(), 1);
        assert_eq!(w.address(0).unwrap().to_lowercase(), a.to_lowercase());
        assert!(w.mnemonic().is_empty());
        assert!(w.export_private_key(0).is_err(), "watch-only must have no key to export");
        assert!(w.sign_message(0, "x").is_err(), "watch-only must not sign");

        // Save + reopen must preserve the watch-only nature and the address.
        let mut p = std::env::temp_dir();
        p.push(format!("aero_watch_{}.keys", std::process::id()));
        let ps = p.to_str().unwrap();
        w.save(ps, "pw").unwrap();
        let re = Wallet::open(ps, "pw").unwrap();
        assert!(re.is_watch_only());
        assert_eq!(re.address(0).unwrap().to_lowercase(), a.to_lowercase());
        std::fs::remove_file(ps).ok();
    }

    #[test]
    fn change_password_reencrypts_over_existing_file() {
        // Simulates the "change password" flow: save, then save AGAIN over the same file with a new
        // password. The overwrite must be atomic/clean — the old password must stop working and the
        // new one must open the identical wallet (no corruption, no key loss).
        let phrase = "test test test test test test test test test test test junk";
        let w = Wallet::restore(phrase).unwrap();
        let addr = w.address(0).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!("aero_chpw_{}.keys", std::process::id()));
        let p = path.to_str().unwrap();

        w.save(p, "oldpw").unwrap();
        assert!(Wallet::open(p, "oldpw").is_ok());

        // Re-encrypt over the existing file with a new password (this is what onChangePassword does).
        w.save(p, "newpw").unwrap();

        assert!(std::fs::metadata(p).is_ok(), "wallet file must still exist after re-encrypt");
        assert!(Wallet::open(p, "oldpw").is_err(), "old password must no longer decrypt");
        let reopened = Wallet::open(p, "newpw").unwrap();
        assert_eq!(reopened.address(0).unwrap(), addr, "wallet must be intact after re-encrypt");

        // No temp files should be left behind in the directory.
        let dir = path.parent().unwrap();
        let stem = path.file_name().unwrap().to_str().unwrap();
        let leftover = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.starts_with(stem) && n.ends_with(".tmp")
            });
        assert!(!leftover, "no .tmp file should remain after a successful save");
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
