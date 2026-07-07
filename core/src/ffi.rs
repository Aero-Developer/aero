//! C ABI for the wallet core, consumed by the Qt/C++ frontend.
//!
//! Conventions:
//!  * Opaque `Wallet*` handles are created by the constructors and released with
//!    [`aero_wallet_free`].
//!  * Functions returning `char*` allocate a NUL-terminated UTF-8 string that the caller must
//!    release with [`aero_string_free`]. A NULL return means failure; call
//!    [`aero_last_error`] for a human-readable message.
//!  * String results that carry data are JSON, matching the serde structs in `wallet.rs`.
//!  * Network operations block on an internal Tokio runtime; call them from a worker thread on
//!    the C++ side (as Feather already does for wallet operations).

use std::cell::RefCell;
use std::ffi::{c_char, c_int, CStr, CString};
use std::ptr;

use once_cell::sync::Lazy;
use tokio::runtime::Runtime;

use crate::keys::WordCount;
use crate::keystore::TokenRef;
use crate::provider::ProviderConfig;
use crate::wallet::Wallet;

static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    Runtime::new().expect("failed to create tokio runtime")
});

/// Block on a future using the shared runtime. Used by sync core paths (e.g. opening a hardware
/// wallet, which must reach the device). Never call from inside an async task on this runtime.
pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    RUNTIME.block_on(f)
}

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = RefCell::new(None);
}

fn set_error(msg: impl Into<String>) {
    let c = CString::new(msg.into()).unwrap_or_else(|_| CString::new("error").unwrap());
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(c));
}

fn clear_error() {
    LAST_ERROR.with(|e| *e.borrow_mut() = None);
}

/// Return the last error message for the current thread, or NULL if none.
/// Caller must free with [`aero_string_free`].
#[no_mangle]
pub extern "C" fn aero_last_error() -> *mut c_char {
    LAST_ERROR.with(|e| match e.borrow().as_ref() {
        Some(c) => c.clone().into_raw(),
        None => ptr::null_mut(),
    })
}

/// Semantic version of the core library.
#[no_mangle]
pub extern "C" fn aero_version() -> *mut c_char {
    to_cstr(env!("CARGO_PKG_VERSION"))
}

/// Free a string returned by this library.
#[no_mangle]
pub extern "C" fn aero_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)) };
    }
}

// ---------------- wallet lifecycle ----------------

/// Create a new wallet with a fresh random mnemonic (`word_count` = 12 or 24).
#[no_mangle]
pub extern "C" fn aero_wallet_create_new(word_count: u32) -> *mut Wallet {
    clear_error();
    let words = match WordCount::from_count(word_count as usize) {
        Ok(w) => w,
        Err(e) => {
            set_error(e.to_string());
            return ptr::null_mut();
        }
    };
    match Wallet::create_new(words) {
        Ok(w) => Box::into_raw(Box::new(w)),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Create a new wallet with a fresh mnemonic and an optional BIP39 passphrase (empty/NULL = none).
#[no_mangle]
pub extern "C" fn aero_wallet_create_new_with_passphrase(
    word_count: u32,
    passphrase: *const c_char,
) -> *mut Wallet {
    clear_error();
    let words = match WordCount::from_count(word_count as usize) {
        Ok(w) => w,
        Err(e) => {
            set_error(e.to_string());
            return ptr::null_mut();
        }
    };
    let pass = from_cstr(passphrase).unwrap_or_default();
    match Wallet::create_new_with_passphrase(words, &pass) {
        Ok(w) => Box::into_raw(Box::new(w)),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Restore a wallet from a BIP39 mnemonic.
#[no_mangle]
pub extern "C" fn aero_wallet_restore(mnemonic: *const c_char) -> *mut Wallet {
    clear_error();
    let m = match from_cstr(mnemonic) {
        Some(s) => s,
        None => {
            set_error("null mnemonic");
            return ptr::null_mut();
        }
    };
    match Wallet::restore(&m) {
        Ok(w) => Box::into_raw(Box::new(w)),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Restore a wallet from a BIP39 mnemonic with an optional passphrase (empty/NULL = none). A
/// different passphrase derives a completely different set of addresses.
#[no_mangle]
pub extern "C" fn aero_wallet_restore_with_passphrase(
    mnemonic: *const c_char,
    passphrase: *const c_char,
) -> *mut Wallet {
    clear_error();
    let Some(m) = from_cstr(mnemonic) else {
        set_error("null mnemonic");
        return ptr::null_mut();
    };
    let pass = from_cstr(passphrase).unwrap_or_default();
    match Wallet::restore_with_passphrase(&m, &pass) {
        Ok(w) => Box::into_raw(Box::new(w)),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Whether the wallet's HD tree is protected by a BIP39 passphrase (1 = yes, 0 = no).
#[no_mangle]
pub extern "C" fn aero_wallet_has_passphrase(w: *mut Wallet) -> c_int {
    match unsafe { w.as_ref() } {
        Some(w) if w.has_passphrase() => 1,
        _ => 0,
    }
}

// ---------------- hardware wallets (Ledger / Trezor) ----------------

/// List connected devices of `kind` ("ledger"/"trezor") as a JSON array of names. Caller frees.
#[no_mangle]
pub extern "C" fn aero_wallet_hw_list_devices(kind: *const c_char) -> *mut c_char {
    clear_error();
    let Some(kind_s) = from_cstr(kind) else {
        set_error("null kind");
        return ptr::null_mut();
    };
    let hwkind = match crate::hardware::HwKind::parse(&kind_s) {
        Ok(k) => k,
        Err(e) => {
            set_error(e.to_string());
            return ptr::null_mut();
        }
    };
    let list = RUNTIME.block_on(crate::hardware::list_devices(hwkind));
    to_cstr(&serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string()))
}

/// Create a watch-only hardware wallet by deriving `num_accounts` addresses from the connected
/// device. `passphrase` is the host-entered BIP39 passphrase (Trezor); NULL/"" = none.
#[no_mangle]
pub extern "C" fn aero_wallet_create_hardware(
    kind: *const c_char,
    passphrase: *const c_char,
    num_accounts: u32,
) -> *mut Wallet {
    clear_error();
    let Some(kind_s) = from_cstr(kind) else {
        set_error("null kind");
        return ptr::null_mut();
    };
    let pass = from_cstr(passphrase).unwrap_or_default();
    let hwkind = match crate::hardware::HwKind::parse(&kind_s) {
        Ok(k) => k,
        Err(e) => {
            set_error(e.to_string());
            return ptr::null_mut();
        }
    };
    match RUNTIME.block_on(Wallet::create_hardware(hwkind, &pass, num_accounts.max(1))) {
        Ok(w) => Box::into_raw(Box::new(w)),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Open a hardware wallet file. Requires the device (and its passphrase, if any); fails if the
/// device is absent or derives a different first address.
#[no_mangle]
pub extern "C" fn aero_wallet_open_hardware(
    path: *const c_char,
    password: *const c_char,
    passphrase: *const c_char,
) -> *mut Wallet {
    clear_error();
    let (Some(path), Some(pw)) = (from_cstr(path), from_cstr(password)) else {
        set_error("null path/password");
        return ptr::null_mut();
    };
    let pass = from_cstr(passphrase).unwrap_or_default();
    match Wallet::open_with_passphrase(&path, &pw, &pass) {
        Ok(w) => Box::into_raw(Box::new(w)),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Inspect a wallet file without a device: 1 = hardware wallet, 0 = software wallet, -1 = can't
/// decrypt (wrong password / unreadable). Lets the open flow decide whether to prompt for a device.
#[no_mangle]
pub extern "C" fn aero_wallet_file_is_hardware(
    path: *const c_char,
    password: *const c_char,
) -> c_int {
    clear_error();
    let (Some(path), Some(pw)) = (from_cstr(path), from_cstr(password)) else {
        set_error("null path/password");
        return -1;
    };
    match std::fs::read(&path)
        .ok()
        .and_then(|d| crate::keystore::decrypt(&d, &pw).ok())
    {
        Some(sec) => {
            if sec.hardware.is_some() {
                1
            } else {
                0
            }
        }
        None => -1,
    }
}

/// Whether the wallet's keys live on a hardware device (1 = yes, 0 = no).
#[no_mangle]
pub extern "C" fn aero_wallet_is_hardware(w: *mut Wallet) -> c_int {
    match unsafe { w.as_ref() } {
        Some(w) if w.is_hardware() => 1,
        _ => 0,
    }
}

/// Create an address-only watch wallet from a JSON array of 0x addresses (e.g. `["0x..","0x.."]`).
/// No keys are stored; balances/history work but signing/sending is refused.
#[no_mangle]
pub extern "C" fn aero_wallet_watch_only(addresses_json: *const c_char) -> *mut Wallet {
    clear_error();
    let Some(js) = from_cstr(addresses_json) else {
        set_error("null addresses");
        return ptr::null_mut();
    };
    let addrs: Vec<String> = serde_json::from_str(&js).unwrap_or_default();
    match Wallet::watch_only(&addrs) {
        Ok(w) => Box::into_raw(Box::new(w)),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Whether the wallet is an address-only watch wallet (1 = yes, 0 = no).
#[no_mangle]
pub extern "C" fn aero_wallet_is_watch_only(w: *mut Wallet) -> c_int {
    match unsafe { w.as_ref() } {
        Some(w) if w.is_watch_only() => 1,
        _ => 0,
    }
}

/// Hardware device kind ("ledger"/"trezor"), or "" for software wallets. Caller frees.
#[no_mangle]
pub extern "C" fn aero_wallet_hw_kind(w: *mut Wallet) -> *mut c_char {
    match unsafe { w.as_ref() } {
        Some(w) => to_cstr(w.hw_kind()),
        None => to_cstr(""),
    }
}

/// Derive and append one more hardware account from the device; returns its index (u32::MAX on error).
#[no_mangle]
pub extern "C" fn aero_wallet_hw_add_account(w: *mut Wallet) -> u32 {
    clear_error();
    let Some(w) = (unsafe { w.as_mut() }) else {
        set_error("null wallet");
        return u32::MAX;
    };
    match RUNTIME.block_on(w.add_hardware_account()) {
        Ok(i) => i,
        Err(e) => {
            set_error(e.to_string());
            u32::MAX
        }
    }
}

/// Open an encrypted wallet file with a password.
#[no_mangle]
pub extern "C" fn aero_wallet_open(path: *const c_char, password: *const c_char) -> *mut Wallet {
    clear_error();
    let (Some(path), Some(pw)) = (from_cstr(path), from_cstr(password)) else {
        set_error("null path/password");
        return ptr::null_mut();
    };
    match Wallet::open(&path, &pw) {
        Ok(w) => Box::into_raw(Box::new(w)),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Encrypt and save the wallet to `path`. Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn aero_wallet_save(
    w: *mut Wallet,
    path: *const c_char,
    password: *const c_char,
) -> c_int {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return -1;
    };
    let (Some(path), Some(pw)) = (from_cstr(path), from_cstr(password)) else {
        set_error("null path/password");
        return -1;
    };
    match w.save(&path, &pw) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e.to_string());
            -1
        }
    }
}

/// Release a wallet handle.
#[no_mangle]
pub extern "C" fn aero_wallet_free(w: *mut Wallet) {
    if !w.is_null() {
        unsafe { drop(Box::from_raw(w)) };
    }
}

// ---------------- accounts / keys ----------------

/// Return the wallet mnemonic (handle with care in the UI). Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_mnemonic(w: *mut Wallet) -> *mut c_char {
    let Some(w) = (unsafe { w.as_ref() }) else {
        return ptr::null_mut();
    };
    to_cstr(w.mnemonic())
}

#[no_mangle]
pub extern "C" fn aero_wallet_account_count(w: *mut Wallet) -> u32 {
    unsafe { w.as_ref() }.map(|w| w.account_count()).unwrap_or(0)
}

/// Derive/track a new account; returns its index (or u32::MAX on error).
#[no_mangle]
pub extern "C" fn aero_wallet_add_account(w: *mut Wallet) -> u32 {
    match unsafe { w.as_mut() } {
        Some(w) => w.add_account(),
        None => u32::MAX,
    }
}

/// Import a raw hex private key as a new account; returns its index (or u32::MAX on error).
#[no_mangle]
pub extern "C" fn aero_wallet_import_private_key(w: *mut Wallet, hex_key: *const c_char) -> u32 {
    clear_error();
    let Some(w) = (unsafe { w.as_mut() }) else {
        set_error("null wallet");
        return u32::MAX;
    };
    let Some(hex_key) = from_cstr(hex_key) else {
        set_error("null key");
        return u32::MAX;
    };
    match w.import_private_key(&hex_key) {
        Ok(idx) => idx,
        Err(e) => {
            set_error(e.to_string());
            u32::MAX
        }
    }
}

/// Return the checksummed 0x address for `index`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_address(w: *mut Wallet, index: u32) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    match w.address(index) {
        Ok(a) => to_cstr(&a),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Export the raw 0x-prefixed private key hex for `index`. Caller frees the string. Sensitive.
#[no_mangle]
pub extern "C" fn aero_wallet_export_private_key(w: *mut Wallet, index: u32) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    match w.export_private_key(index) {
        Ok(k) => to_cstr(&k),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// EIP-191 personal_sign of `message` (UTF-8) with account `index`. Returns 0x-prefixed 65-byte
/// signature hex; null on error. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_sign_message(
    w: *mut Wallet,
    index: u32,
    message: *const c_char,
) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    let Some(message) = from_cstr(message) else {
        set_error("null message");
        return ptr::null_mut();
    };
    match w.sign_message(index, &message) {
        Ok(sig) => to_cstr(&sig),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Recover the signer address of an EIP-191 personal_sign `signature` over `message`. Returns the
/// checksummed address hex; null on error (bad signature). Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_verify_message(
    message: *const c_char,
    signature: *const c_char,
) -> *mut c_char {
    clear_error();
    let (Some(message), Some(signature)) = (from_cstr(message), from_cstr(signature)) else {
        set_error("null message/signature");
        return ptr::null_mut();
    };
    match Wallet::verify_message(&message, &signature) {
        Ok(addr) => to_cstr(&addr),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

// ---------------- tokens ----------------

/// Track an ERC20 token in the wallet's Tokens/Assets panel.
#[no_mangle]
pub extern "C" fn aero_wallet_add_token(
    w: *mut Wallet,
    address: *const c_char,
    symbol: *const c_char,
    decimals: u8,
) -> c_int {
    clear_error();
    let Some(w) = (unsafe { w.as_mut() }) else {
        set_error("null wallet");
        return -1;
    };
    let (Some(address), Some(symbol)) = (from_cstr(address), from_cstr(symbol)) else {
        set_error("null token fields");
        return -1;
    };
    w.add_token(TokenRef {
        address,
        symbol,
        decimals,
    });
    0
}

#[no_mangle]
pub extern "C" fn aero_wallet_remove_token(w: *mut Wallet, address: *const c_char) -> c_int {
    let Some(w) = (unsafe { w.as_mut() }) else {
        return -1;
    };
    let Some(address) = from_cstr(address) else {
        return -1;
    };
    w.remove_token(&address);
    0
}

/// JSON array of tracked tokens. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_tokens(w: *mut Wallet) -> *mut c_char {
    let Some(w) = (unsafe { w.as_ref() }) else {
        return ptr::null_mut();
    };
    match serde_json::to_string(w.tokens()) {
        Ok(s) => to_cstr(&s),
        Err(_) => ptr::null_mut(),
    }
}

/// Per-wallet metadata JSON blob (labels/contacts/notes/funded). "" if none. Caller frees. This is
/// stored encrypted inside the wallet file, not in plaintext settings.
#[no_mangle]
pub extern "C" fn aero_wallet_metadata(w: *mut Wallet) -> *mut c_char {
    match unsafe { w.as_ref() } {
        Some(w) => to_cstr(w.metadata()),
        None => ptr::null_mut(),
    }
}

/// Replace the per-wallet metadata JSON blob. Persisted (encrypted) on the next `aero_wallet_save`.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn aero_wallet_set_metadata(w: *mut Wallet, json: *const c_char) -> c_int {
    clear_error();
    let Some(w) = (unsafe { w.as_mut() }) else {
        set_error("null wallet");
        return -1;
    };
    let Some(json) = from_cstr(json) else {
        set_error("null metadata");
        return -1;
    };
    w.set_metadata(&json);
    0
}

// ---------------- networking ----------------

/// Configure the Tor-routed RPC provider.
/// `endpoints_json` is a JSON array of RPC URLs; `socks_proxy` may be NULL to disable Tor.
/// With no proxy, remote endpoints are refused unless `allow_clearnet` is true (a deliberate,
/// IP-exposing opt-out of Tor); localhost endpoints (your own node / Helios) are always allowed.
#[no_mangle]
pub extern "C" fn aero_wallet_set_provider(
    w: *mut Wallet,
    chain_id: u64,
    endpoints_json: *const c_char,
    socks_proxy: *const c_char,
    allow_clearnet: bool,
    timeout_secs: u64,
) -> c_int {
    clear_error();
    let Some(w) = (unsafe { w.as_mut() }) else {
        set_error("null wallet");
        return -1;
    };
    let Some(endpoints_json) = from_cstr(endpoints_json) else {
        set_error("null endpoints");
        return -1;
    };
    let endpoints: Vec<String> = match serde_json::from_str(&endpoints_json) {
        Ok(v) => v,
        Err(e) => {
            set_error(format!("bad endpoints json: {e}"));
            return -1;
        }
    };
    let cfg = ProviderConfig {
        chain_id,
        endpoints,
        socks_proxy: from_cstr(socks_proxy),
        allow_clearnet,
        timeout_secs: if timeout_secs == 0 { 60 } else { timeout_secs },
    };
    match w.set_provider(cfg) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e.to_string());
            -1
        }
    }
}

/// ETH balance for `index` as JSON `BalanceInfo`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_eth_balance(w: *mut Wallet, index: u32) -> *mut c_char {
    block_json(w, |w| RUNTIME.block_on(w.eth_balance(index)))
}

/// Native + tracked-token balances for accounts `0..num_accounts` in one batched request.
/// Returns JSON `{ native_symbol, accounts: [ { index, native_raw, native_formatted,
/// native_symbol, tokens: [ { address, symbol, decimals, raw, formatted } ] } ] }`.
/// Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_all_balances(w: *mut Wallet, num_accounts: u32) -> *mut c_char {
    block_json(w, |w| RUNTIME.block_on(w.all_balances(num_accounts)))
}

/// ERC20 balance as JSON `BalanceInfo`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_erc20_balance(
    w: *mut Wallet,
    token: *const c_char,
    index: u32,
) -> *mut c_char {
    let Some(token) = from_cstr(token) else {
        set_error("null token");
        return ptr::null_mut();
    };
    block_json(w, |w| RUNTIME.block_on(w.erc20_balance(&token, index)))
}

/// Suggested EIP-1559 fees as JSON `FeeSuggestion`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_suggest_fees(w: *mut Wallet) -> *mut c_char {
    block_json(w, |w| RUNTIME.block_on(w.suggest_fees()))
}

/// ETH/USD price (from the on-chain Chainlink feed, over Tor) as a decimal string. Caller frees.
#[no_mangle]
pub extern "C" fn aero_wallet_eth_usd_price(w: *mut Wallet) -> *mut c_char {
    aero_wallet_native_usd_price(w)
}

/// USD price of the connected chain's native coin (Chainlink on mainnet, CoinGecko elsewhere).
/// Decimal string; caller frees.
#[no_mangle]
pub extern "C" fn aero_wallet_native_usd_price(w: *mut Wallet) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    match RUNTIME.block_on(w.native_usd_price()) {
        Ok(p) => to_cstr(&format!("{p}")),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Deepest DEX pool USD liquidity for a token (via DexScreener over Tor), as a decimal string
/// ("0" on error / no pools). Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_token_liquidity_usd(
    w: *mut Wallet,
    token: *const c_char,
) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    let Some(token) = from_cstr(token) else {
        set_error("null token");
        return ptr::null_mut();
    };
    match RUNTIME.block_on(w.token_liquidity_usd(&token)) {
        Ok(usd) => to_cstr(&format!("{usd}")),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Resolve an ERC-20's symbol + decimals (over Tor) as JSON `{"symbol","decimals"}`. Used by the
/// Send token picker when the user pastes an arbitrary contract address. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_erc20_metadata(
    w: *mut Wallet,
    token: *const c_char,
) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    let Some(token) = from_cstr(token) else {
        set_error("null token");
        return ptr::null_mut();
    };
    match RUNTIME.block_on(w.erc20_metadata(&token)) {
        Ok((symbol, decimals)) => {
            to_cstr(&serde_json::json!({ "symbol": symbol, "decimals": decimals }).to_string())
        }
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// USD -> fiat conversion rate for `currency` (e.g. "eur"), via CoinGecko over Tor. 1.0 for "usd"
/// or on error. Used for the Settings fiat-currency display option. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_fiat_per_usd(w: *mut Wallet, currency: *const c_char) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    let Some(currency) = from_cstr(currency) else {
        set_error("null currency");
        return ptr::null_mut();
    };
    match RUNTIME.block_on(w.fiat_per_usd(&currency)) {
        Ok(rate) => to_cstr(&format!("{rate}")),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Current chain head block number (0 on error). Used for cheap new-block polling.
#[no_mangle]
pub extern "C" fn aero_wallet_block_number(w: *mut Wallet) -> u64 {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return 0;
    };
    match RUNTIME.block_on(w.block_number()) {
        Ok(n) => n,
        Err(e) => {
            set_error(e.to_string());
            0
        }
    }
}

/// Market prices for the Home tickers as JSON `{"xmr_usd","xmr_chg","eth_usd","eth_chg"}` (fetched
/// over Tor). Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_market_prices(w: *mut Wallet) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    match RUNTIME.block_on(w.market_prices()) {
        Ok((xu, xc, eu, ec)) => to_cstr(&format!(
            "{{\"xmr_usd\":{xu},\"xmr_chg\":{xc},\"eth_usd\":{eu},\"eth_chg\":{ec}}}"
        )),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Parse an optional (max_fee, max_priority) fee override from two decimal-wei C strings.
/// Returns `None` (automatic) unless both parse to a positive value.
fn parse_fee_override(max_fee: *const c_char, max_priority: *const c_char) -> Option<(u128, u128)> {
    let mf = from_cstr(max_fee)?.parse::<u128>().ok()?;
    let mp = from_cstr(max_priority)?.parse::<u128>().ok()?;
    if mf == 0 {
        return None;
    }
    Some((mf, mp))
}

/// Send ETH; returns JSON `SendResult` with the tx hash. `max_fee_wei`/`max_priority_wei` may be
/// NULL/"0" for an automatic fee. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_send_eth(
    w: *mut Wallet,
    from_index: u32,
    to: *const c_char,
    amount_wei: *const c_char,
    max_fee_wei: *const c_char,
    max_priority_wei: *const c_char,
    nonce: u64, // u64::MAX = automatic; a specific value replaces a pending tx (speed-up)
) -> *mut c_char {
    let (Some(to), Some(amount)) = (from_cstr(to), from_cstr(amount_wei)) else {
        set_error("null to/amount");
        return ptr::null_mut();
    };
    let fee = parse_fee_override(max_fee_wei, max_priority_wei);
    let nonce_ov = (nonce != u64::MAX).then_some(nonce);
    block_json(w, |w| RUNTIME.block_on(w.send_eth(from_index, &to, &amount, fee, nonce_ov)))
}

/// Send an ERC20 token; returns JSON `SendResult`. Fee/nonce args as in `aero_wallet_send_eth`.
#[no_mangle]
pub extern "C" fn aero_wallet_send_erc20(
    w: *mut Wallet,
    from_index: u32,
    token: *const c_char,
    to: *const c_char,
    amount_units: *const c_char,
    max_fee_wei: *const c_char,
    max_priority_wei: *const c_char,
    nonce: u64, // u64::MAX = automatic; a specific value replaces a pending tx (speed-up)
) -> *mut c_char {
    let (Some(token), Some(to), Some(amount)) =
        (from_cstr(token), from_cstr(to), from_cstr(amount_units))
    else {
        set_error("null args");
        return ptr::null_mut();
    };
    let fee = parse_fee_override(max_fee_wei, max_priority_wei);
    let nonce_ov = (nonce != u64::MAX).then_some(nonce);
    block_json(w, |w| {
        RUNTIME.block_on(w.send_erc20(from_index, &token, &to, &amount, fee, nonce_ov))
    })
}

/// Historical USD spot price of `symbol` on `date` (YYYY-MM-DD) as a decimal string ("0" if
/// unavailable). Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_price_on_date(
    w: *mut Wallet,
    symbol: *const c_char,
    date: *const c_char,
) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    let (Some(symbol), Some(date)) = (from_cstr(symbol), from_cstr(date)) else {
        set_error("null symbol/date");
        return ptr::null_mut();
    };
    match RUNTIME.block_on(w.price_on_date(&symbol, &date)) {
        Ok(p) => to_cstr(&p.to_string()),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// "Pay to many": send to several recipients (one tx each, sequential nonces). `recipients_json` is
/// a JSON array of `["0xto","amountBaseUnits"]` pairs; `token` empty = native, else ERC-20 address.
/// Returns a JSON array of `{to, tx_hash}` / `{to, error}`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_send_many(
    w: *mut Wallet,
    from_index: u32,
    recipients_json: *const c_char,
    token: *const c_char,
    max_fee_wei: *const c_char,
    max_priority_wei: *const c_char,
) -> *mut c_char {
    let (Some(rj), Some(token)) = (from_cstr(recipients_json), from_cstr(token)) else {
        set_error("null args");
        return ptr::null_mut();
    };
    let recipients: Vec<(String, String)> = serde_json::from_str(&rj).unwrap_or_default();
    let fee = parse_fee_override(max_fee_wei, max_priority_wei);
    block_json(w, |w| RUNTIME.block_on(w.send_many(from_index, &recipients, &token, fee)))
}

/// Broadcast an already-signed raw transaction (0x RLP hex) over the wallet's RPC/Tor. Returns JSON
/// `SendResult`. Works for watch-only wallets too (no keys needed). Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_broadcast_raw(w: *mut Wallet, raw_hex: *const c_char) -> *mut c_char {
    let Some(raw) = from_cstr(raw_hex) else {
        set_error("null raw tx");
        return ptr::null_mut();
    };
    block_json(w, |w| RUNTIME.block_on(w.broadcast_raw(&raw)))
}

/// Build an UNSIGNED transaction (resolves nonce/gas/fees over the network) as JSON, for air-gapped
/// signing. `token` empty = native (uses `amount_wei`), else ERC-20 transfer (`amount_units`).
/// `nonce` = u64::MAX for automatic. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_build_unsigned(
    w: *mut Wallet,
    from_index: u32,
    to: *const c_char,
    amount_wei: *const c_char,
    token: *const c_char,
    amount_units: *const c_char,
    max_fee_wei: *const c_char,
    max_priority_wei: *const c_char,
    nonce: u64,
) -> *mut c_char {
    let (Some(to), Some(amount_wei), Some(token), Some(amount_units)) = (
        from_cstr(to),
        from_cstr(amount_wei),
        from_cstr(token),
        from_cstr(amount_units),
    ) else {
        set_error("null args");
        return ptr::null_mut();
    };
    let fee = parse_fee_override(max_fee_wei, max_priority_wei);
    let nonce_ov = (nonce != u64::MAX).then_some(nonce);
    block_json(w, |w| {
        RUNTIME.block_on(w.build_unsigned(from_index, &to, &amount_wei, &token, &amount_units, fee, nonce_ov))
    })
}

/// Sign an unsigned-tx JSON (from `aero_wallet_build_unsigned`) with the local key; returns the 0x
/// raw RLP hex (no network needed — runs offline). Null on error. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_sign_unsigned(w: *mut Wallet, json: *const c_char) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    let Some(json) = from_cstr(json) else {
        set_error("null json");
        return ptr::null_mut();
    };
    match RUNTIME.block_on(w.sign_unsigned(&json)) {
        Ok(s) => to_cstr(&s),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Cancel a pending tx by broadcasting a 0-value self-send at `nonce` with a (bumped) fee. Returns
/// JSON `SendResult`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_cancel_tx(
    w: *mut Wallet,
    from_index: u32,
    nonce: u64,
    max_fee_wei: *const c_char,
    max_priority_wei: *const c_char,
) -> *mut c_char {
    let fee = parse_fee_override(max_fee_wei, max_priority_wei);
    block_json(w, |w| RUNTIME.block_on(w.cancel_transaction(from_index, nonce, fee)))
}

/// ERC20 transfer history as a JSON array of `HistoryItem`. `from_block` is a hex block number
/// or "earliest"/"latest". Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_erc20_history(
    w: *mut Wallet,
    token: *const c_char,
    index: u32,
    from_block: *const c_char,
) -> *mut c_char {
    let (Some(token), Some(from_block)) = (from_cstr(token), from_cstr(from_block)) else {
        set_error("null token/from_block");
        return ptr::null_mut();
    };
    block_json(w, |w| {
        RUNTIME.block_on(w.erc20_history(&token, index, &from_block))
    })
}

/// Full account history (native ETH + all ERC20 transfers) for `index`, fetched from a block
/// explorer over Tor, as a JSON array of `HistoryItem`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_account_history(w: *mut Wallet, index: u32) -> *mut c_char {
    block_json(w, |w| RUNTIME.block_on(w.account_history(index)))
}

/// Scan every common Ethereum derivation scheme for balances (Electrum-style multi-path recovery),
/// registering funded addresses as accounts and returning their unified indices as a JSON array.
/// Mutates the wallet, so it takes `&mut`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_scan_funded(w: *mut Wallet, gap_limit: u32) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_mut() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    match RUNTIME.block_on(w.scan_funded(gap_limit)) {
        Ok(v) => match serde_json::to_string(&v) {
            Ok(s) => to_cstr(&s),
            Err(e) => {
                set_error(e.to_string());
                ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Owned NFT collections (ERC-721 + ERC-1155) for an account as a JSON array. Caller frees.
#[no_mangle]
pub extern "C" fn aero_wallet_account_nfts(w: *mut Wallet, index: u32) -> *mut c_char {
    block_json(w, |w| RUNTIME.block_on(w.account_nfts(index)))
}

/// Fetch an image URL over Tor, hex-encoded ("" on error). Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_fetch_image(w: *mut Wallet, url: *const c_char) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    let Some(url) = from_cstr(url) else {
        set_error("null url");
        return ptr::null_mut();
    };
    match RUNTIME.block_on(w.fetch_image_hex(&url)) {
        Ok(hexstr) => to_cstr(&hexstr),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

// ---------------- utilities ----------------

/// Convert a human decimal string to base units (returns decimal string). Caller frees.
#[no_mangle]
pub extern "C" fn aero_parse_units(amount: *const c_char, decimals: u8) -> *mut c_char {
    clear_error();
    let Some(amount) = from_cstr(amount) else {
        set_error("null amount");
        return ptr::null_mut();
    };
    match crate::wallet::parse_units(&amount, decimals) {
        Ok(v) => to_cstr(&v.to_string()),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

// ---------------- internal glue ----------------

fn block_json<T: serde::Serialize>(
    w: *mut Wallet,
    f: impl FnOnce(&Wallet) -> crate::error::Result<T>,
) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    match f(w) {
        Ok(val) => match serde_json::to_string(&val) {
            Ok(s) => to_cstr(&s),
            Err(e) => {
                set_error(e.to_string());
                ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

fn to_cstr(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

fn from_cstr(s: *const c_char) -> Option<String> {
    if s.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(s) }.to_str().ok().map(|s| s.to_string())
}
