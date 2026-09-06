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

// -------------------------------------------------------------------------------------------------
// Trezor-Host Protocol (2025+ Trezor models)
// -------------------------------------------------------------------------------------------------

/// Asks the user for the 6-digit code the Trezor is displaying during pairing.
///
/// Unlike every other call here, this one runs the other way round: the core invokes it partway
/// through a blocking operation, on whichever worker thread is driving the device. An
/// implementation that touches the UI must therefore marshal to the UI thread itself.
///
/// Write the code as NUL-terminated ASCII into `out` (at most `out_len` bytes including the
/// terminator) and return 0. Return non-zero if the user cancelled.
pub type PairingCodeFn =
    Option<extern "C" fn(ctx: *mut std::ffi::c_void, out: *mut c_char, out_len: c_int) -> c_int>;

/// The registered callback plus its context pointer.
///
/// The pointer is owned by the C++ side, which must keep it alive until the process exits or the
/// callback is replaced. `Send` is asserted because the callback is invoked from worker threads;
/// the C++ implementation is responsible for being thread-safe, which is exactly what marshalling
/// to the UI thread achieves.
struct PairingCallback {
    func: PairingCodeFn,
    ctx: *mut std::ffi::c_void,
}
unsafe impl Send for PairingCallback {}

impl PairingCallback {
    /// Invoke the C callback and read back the code.
    ///
    /// Taking `&self` matters: it makes the closure below capture the whole struct rather than its
    /// individual fields, which is what keeps the `Send` assertion above meaningful under Rust
    /// 2021's disjoint capture rules.
    fn ask(&self) -> std::result::Result<String, String> {
        let func = self.func.ok_or("no pairing callback is registered")?;
        let mut buf = [0u8; 32];
        let rc = func(self.ctx, buf.as_mut_ptr() as *mut c_char, buf.len() as c_int);
        if rc != 0 {
            return Err("pairing was cancelled".into());
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8(buf[..end].to_vec())
            .map_err(|_| "the pairing code was not valid text".to_string())
    }
}

/// Configure Trezor-Host Protocol support: where to keep the pairing credential, and how to ask
/// the user for the pairing code.
///
/// `credential_path` should be an app-level location so a device is paired once for all wallets.
/// Passing a NULL callback disables pairing: already-paired devices keep working, but a device
/// that needs pairing reports an error rather than hanging.
///
/// # Safety
/// `credential_path` must be a valid NUL-terminated string. `ctx` must remain valid for as long as
/// the callback is registered.
#[no_mangle]
pub unsafe extern "C" fn aero_thp_configure(
    credential_path: *const c_char,
    callback: PairingCodeFn,
    ctx: *mut std::ffi::c_void,
) {
    clear_error();
    let path = std::path::PathBuf::from(from_cstr(credential_path).unwrap_or_default());
    let prompt: Option<crate::thp_conn::CodePrompt> = callback.map(|_| {
        let cb = PairingCallback { func: callback, ctx };
        Box::new(move || cb.ask()) as crate::thp_conn::CodePrompt
    });
    crate::thp_conn::configure(path, prompt);
}

/// Whether a Trezor has already been paired, i.e. whether connecting will be silent. 1 = yes.
#[no_mangle]
pub extern "C" fn aero_thp_is_paired() -> c_int {
    c_int::from(crate::thp_conn::is_paired())
}

/// Forget the stored pairing, so the next connection pairs afresh. Returns 0 on success.
#[no_mangle]
pub extern "C" fn aero_thp_forget_pairing() -> c_int {
    clear_error();
    match crate::thp_conn::forget_pairing() {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Drop any cached device connection. Call when a wallet is closed so the device is released.
#[no_mangle]
pub extern "C" fn aero_thp_disconnect() {
    crate::thp_conn::disconnect();
}

/// Free a string returned by this library.
#[no_mangle]
pub extern "C" fn aero_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)) };
    }
}

/// Free a string that carried SECRET material (mnemonic / exported private key), zeroizing the
/// bytes first so the plaintext doesn't linger in freed heap. Callers use this instead of
/// `aero_string_free` for `aero_wallet_mnemonic` / `aero_wallet_export_private_key`.
#[no_mangle]
pub extern "C" fn aero_secret_string_free(s: *mut c_char) {
    if !s.is_null() {
        use zeroize::Zeroize;
        unsafe {
            let mut bytes = CString::from_raw(s).into_bytes();
            bytes.zeroize();
        }
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

/// The 0-based imported-key ordinal for the account at `index`, or -1 when it is seed-derived (or the
/// index is out of range). Lets the UI label imported accounts distinctly from HD accounts.
#[no_mangle]
pub extern "C" fn aero_wallet_account_imported_ordinal(w: *mut Wallet, index: u32) -> c_int {
    match unsafe { w.as_ref() } {
        Some(w) => w
            .account_imported_ordinal(index)
            .map(|j| j as c_int)
            .unwrap_or(-1),
        None => -1,
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

/// Point history for `chain_id` at explorer APIs of the caller's choosing, ahead of the built-in
/// ones. `csv` is a comma-separated list of bases; NULL or empty restores the built-ins.
///
/// Each entry is either a host, to which `/api` is appended, or a URL that already carries a query
/// string, which is used as given - so `https://api.etherscan.io/v2/api?chainid=1&apikey=…` works,
/// as does a private Blockscout. This exists so that an explorer going away or tightening its limits
/// is a setting somebody changes rather than a release everybody has to install.
#[no_mangle]
pub extern "C" fn aero_set_history_apis(chain_id: u64, csv: *const c_char) {
    let list = from_cstr(csv)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    crate::explorers::set_custom(chain_id, list);
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
pub extern "C" fn aero_wallet_all_balances(
    w: *mut Wallet,
    num_accounts: u32,
    extra_tokens_json: *const c_char,
) -> *mut c_char {
    // Empty/NULL extras is fine (tracked tokens only).
    let extras = from_cstr(extra_tokens_json).unwrap_or_default();
    block_json(w, |w| RUNTIME.block_on(w.all_balances(num_accounts, &extras)))
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

/// Atomic native multi-send via Multicall3 (one tx, all-or-nothing). `recipients_json` is a JSON
/// array of [address, decimal-wei]. Returns JSON `SendResult`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_send_many_native(
    w: *mut Wallet,
    from_index: u32,
    recipients_json: *const c_char,
    max_fee_wei: *const c_char,
    max_priority_wei: *const c_char,
) -> *mut c_char {
    let Some(rj) = from_cstr(recipients_json) else {
        set_error("null recipients");
        return ptr::null_mut();
    };
    let recipients: Vec<(String, String)> = serde_json::from_str(&rj).unwrap_or_default();
    let fee = parse_fee_override(max_fee_wei, max_priority_wei);
    block_json(w, |w| RUNTIME.block_on(w.send_many_native(from_index, &recipients, fee)))
}

/// Replace-by-fee an arbitrary still-pending tx (found by hash) of `from_index`: `cancel`=true does
/// a 0-value self-send at its nonce; otherwise rebroadcasts the same tx at a higher fee (speed-up).
/// Returns JSON `SendResult`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_replace_tx(
    w: *mut Wallet,
    from_index: u32,
    tx_hash: *const c_char,
    max_fee_wei: *const c_char,
    max_priority_wei: *const c_char,
    cancel: bool,
) -> *mut c_char {
    let Some(tx_hash) = from_cstr(tx_hash) else {
        set_error("null tx_hash");
        return ptr::null_mut();
    };
    let fee = parse_fee_override(max_fee_wei, max_priority_wei);
    block_json(w, |w| RUNTIME.block_on(w.replace_tx(from_index, &tx_hash, fee, cancel)))
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
/// raw RLP hex (no network needed - runs offline). Null on error. Caller frees the string.
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

// ---------- CoW Protocol swaps ----------

/// Fetch a CoW swap quote as JSON (the order fields live under `quote`). `sell_is_native` sells the
/// chain's wrapped-native token; pass the BUY_ETH sentinel as `buy_token` to receive native ETH.
/// Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_swap_quote(
    w: *mut Wallet,
    from_index: u32,
    sell_token: *const c_char,
    buy_token: *const c_char,
    sell_amount_wei: *const c_char,
    sell_is_native: bool,
) -> *mut c_char {
    let (Some(sell), Some(buy), Some(amount)) = (
        from_cstr(sell_token),
        from_cstr(buy_token),
        from_cstr(sell_amount_wei),
    ) else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| {
        RUNTIME.block_on(w.swap_quote(from_index, &sell, &buy, &amount, sell_is_native))
    })
}

/// Current allowance of `token` (account `from_index`) to the CoW Vault Relayer, as a decimal-wei
/// string ("0" on error). Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_swap_allowance(
    w: *mut Wallet,
    from_index: u32,
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
    match RUNTIME.block_on(w.swap_allowance(from_index, &token)) {
        Ok(a) => to_cstr(&a.to_string()),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Approve the CoW Vault Relayer to spend `token`. `amount` is the decimal-wei cap; "max" (or empty)
/// approves an unlimited allowance. Returns JSON `SendResult`.
#[no_mangle]
pub extern "C" fn aero_wallet_swap_approve(
    w: *mut Wallet,
    from_index: u32,
    token: *const c_char,
    amount: *const c_char,
) -> *mut c_char {
    let Some(token) = from_cstr(token) else {
        set_error("null token");
        return ptr::null_mut();
    };
    let amount = from_cstr(amount).unwrap_or_default();
    block_json(w, |w| RUNTIME.block_on(w.swap_approve(from_index, &token, &amount)))
}

/// Sign (EIP-712) and submit the order from a CoW quote JSON. Returns the order UID string. Null on
/// error. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_swap_submit(
    w: *mut Wallet,
    from_index: u32,
    quote_json: *const c_char,
    slippage_bps: u32,
) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    let Some(quote) = from_cstr(quote_json) else {
        set_error("null quote");
        return ptr::null_mut();
    };
    match RUNTIME.block_on(w.swap_submit(from_index, &quote, slippage_bps)) {
        Ok(uid) => to_cstr(&uid),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Sell native ETH via CoW eth-flow (on-chain tx). `quote_json` from a quote taken with
/// `sell_is_native = true`; `buy_token` is the ERC-20 to receive. Returns JSON `SendResult`.
#[no_mangle]
pub extern "C" fn aero_wallet_swap_eth_flow(
    w: *mut Wallet,
    from_index: u32,
    quote_json: *const c_char,
    buy_token: *const c_char,
    slippage_bps: u32,
) -> *mut c_char {
    let (Some(quote), Some(buy)) = (from_cstr(quote_json), from_cstr(buy_token)) else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| {
        RUNTIME.block_on(w.swap_eth_flow(from_index, &quote, &buy, slippage_bps))
    })
}

/// Batched allowance scan. `tokens_json`/`spenders_json` are JSON arrays of addresses. Returns JSON
/// `{ "allowances": [ {token, spender, allowance}, … ] }` (non-zero only). Caller frees.
#[no_mangle]
pub extern "C" fn aero_wallet_token_allowances(
    w: *mut Wallet,
    from_index: u32,
    tokens_json: *const c_char,
    spenders_json: *const c_char,
) -> *mut c_char {
    let (Some(tokens), Some(spenders)) = (from_cstr(tokens_json), from_cstr(spenders_json)) else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| {
        RUNTIME.block_on(w.token_allowances(from_index, &tokens, &spenders))
    })
}

/// Revoke an ERC-20 approval (`approve(spender, 0)`). Returns JSON `SendResult`. Caller frees.
#[no_mangle]
pub extern "C" fn aero_wallet_revoke_approval(
    w: *mut Wallet,
    from_index: u32,
    token: *const c_char,
    spender: *const c_char,
) -> *mut c_char {
    let (Some(token), Some(spender)) = (from_cstr(token), from_cstr(spender)) else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| {
        RUNTIME.block_on(w.revoke_approval(from_index, &token, &spender))
    })
}

/// DefiLlama current prices for a comma-separated coin-key list. Returns the raw JSON. Caller frees.
#[no_mangle]
pub extern "C" fn aero_wallet_defillama_prices(
    w: *mut Wallet,
    coins_csv: *const c_char,
) -> *mut c_char {
    let Some(coins) = from_cstr(coins_csv) else {
        set_error("null coins");
        return ptr::null_mut();
    };
    block_json(w, |w| RUNTIME.block_on(w.defillama_prices(&coins)))
}

// ---------- Multi-router swap aggregator ----------

/// Fetch quotes from every keyless router supported on the current chain (parallel, over Tor).
/// `sell`/`buy` are token addresses; empty = native coin. Returns JSON `{ "quotes": [...] }`,
/// best-first. Caller frees the string.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn aero_wallet_swap_quotes(
    w: *mut Wallet,
    from_index: u32,
    sell: *const c_char,
    buy: *const c_char,
    sell_amount_wei: *const c_char,
    sell_is_native: bool,
    sell_decimals: u8,
    buy_decimals: u8,
    slippage_bps: u32,
) -> *mut c_char {
    let (Some(sell), Some(buy), Some(amount)) =
        (from_cstr(sell), from_cstr(buy), from_cstr(sell_amount_wei))
    else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| {
        RUNTIME.block_on(w.swap_quotes(
            from_index, &sell, &buy, &amount, sell_is_native, sell_decimals, buy_decimals,
            slippage_bps,
        ))
    })
}

/// Build the executable transaction for a chosen on-chain router (fresh calldata). Returns JSON
/// `{to, data, value, spender, buy_amount, min_buy_amount}`. Caller frees the string.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn aero_wallet_router_build(
    w: *mut Wallet,
    router_id: *const c_char,
    from_index: u32,
    sell: *const c_char,
    buy: *const c_char,
    sell_amount_wei: *const c_char,
    sell_is_native: bool,
    sell_decimals: u8,
    buy_decimals: u8,
    slippage_bps: u32,
) -> *mut c_char {
    let (Some(router_id), Some(sell), Some(buy), Some(amount)) = (
        from_cstr(router_id),
        from_cstr(sell),
        from_cstr(buy),
        from_cstr(sell_amount_wei),
    ) else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| {
        RUNTIME.block_on(w.router_build(
            &router_id, from_index, &sell, &buy, &amount, sell_is_native, sell_decimals,
            buy_decimals, slippage_bps,
        ))
    })
}

/// Approve `spender` to spend `token`. `amount` is decimal-wei; "max"/empty = unlimited. Returns
/// JSON `SendResult`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_router_approve(
    w: *mut Wallet,
    from_index: u32,
    token: *const c_char,
    spender: *const c_char,
    amount: *const c_char,
) -> *mut c_char {
    let (Some(token), Some(spender)) = (from_cstr(token), from_cstr(spender)) else {
        set_error("null args");
        return ptr::null_mut();
    };
    let amount = from_cstr(amount).unwrap_or_default();
    block_json(w, |w| {
        RUNTIME.block_on(w.router_approve(from_index, &token, &spender, &amount))
    })
}

/// Current allowance of `token` (account `from_index`) to an arbitrary `spender`, as decimal-wei
/// ("0" on error). Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_router_allowance(
    w: *mut Wallet,
    from_index: u32,
    token: *const c_char,
    spender: *const c_char,
) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    let (Some(token), Some(spender)) = (from_cstr(token), from_cstr(spender)) else {
        set_error("null args");
        return ptr::null_mut();
    };
    match RUNTIME.block_on(w.router_allowance(from_index, &token, &spender)) {
        Ok(a) => to_cstr(&a.to_string()),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Send an arbitrary-calldata swap tx (`to`/`value`/`data` from `aero_wallet_router_build`). Returns
/// JSON `SendResult`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_router_swap(
    w: *mut Wallet,
    from_index: u32,
    to: *const c_char,
    value_wei: *const c_char,
    data_hex: *const c_char,
) -> *mut c_char {
    let (Some(to), Some(value), Some(data)) =
        (from_cstr(to), from_cstr(value_wei), from_cstr(data_hex))
    else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| RUNTIME.block_on(w.router_swap(from_index, &to, &value, &data)))
}

/// What Across can bridge out of the connected chain right now, as JSON
/// `{origin_chain, assets:[{symbol, display, decimals, native, destinations:[chain_id]}]}`.
/// Fetched from Across itself, so retired assets stop being offered. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_across_assets(w: *mut Wallet) -> *mut c_char {
    block_json(w, |w| RUNTIME.block_on(w.across_assets()))
}

// --- Hyperliquid (XMR1) ---------------------------------------------------------------------------

/// Everything the XMR1 trading screen shows, as JSON: the order book, the account's XMR1 and USDC
/// balances, its resting orders and its recent fills. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_hl_overview(w: *mut Wallet, index: u32) -> *mut c_char {
    block_json(w, |w| RUNTIME.block_on(w.hl_overview(index)))
}

/// Whether this account has already authorised Aero's trading key. Returns JSON `{"ready":bool}`.
/// Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_hl_agent_ready(w: *mut Wallet, index: u32) -> *mut c_char {
    block_json(w, |w| {
        RUNTIME
            .block_on(w.hl_agent_ready(index))
            .map(|ready| serde_json::json!({ "ready": ready }))
    })
}

/// Authorise Aero's trading key for this account - a one-time signature with the account key, after
/// which orders are signed by a key that cannot withdraw. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_hl_approve_agent(w: *mut Wallet, index: u32) -> *mut c_char {
    block_json(w, |w| RUNTIME.block_on(w.hl_approve_agent(index)))
}

/// Place an XMR1 order. `market_order` fills immediately at up to `price` and cancels any remainder;
/// otherwise the order rests at `price`. Returns JSON `{state, size, price, oid}` where `state` is
/// `filled`, `resting` or `none`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_hl_place_order(
    w: *mut Wallet,
    index: u32,
    is_buy: bool,
    price: f64,
    size: f64,
    market_order: bool,
) -> *mut c_char {
    block_json(w, |w| {
        RUNTIME.block_on(w.hl_place_order(index, is_buy, price, size, market_order))
    })
}

/// Cancel a resting XMR1 order by its exchange order id. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_hl_cancel_order(w: *mut Wallet, index: u32, oid: u64) -> *mut c_char {
    block_json(w, |w| RUNTIME.block_on(w.hl_cancel_order(index, oid)))
}

/// Move USDC from Arbitrum One onto the exchange by transferring it to Hyperliquid's bridge.
/// Requires the wallet to be connected to Arbitrum. Returns JSON `SendResult`. Caller frees.
#[no_mangle]
pub extern "C" fn aero_wallet_hl_deposit(
    w: *mut Wallet,
    index: u32,
    amount_usdc: *const c_char,
) -> *mut c_char {
    let Some(amount) = from_cstr(amount_usdc) else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| RUNTIME.block_on(w.hl_deposit(index, &amount)))
}

/// Withdraw USDC from the exchange back to this account's address on Arbitrum, minus the exchange's
/// flat fee. Signed by the account key, which an agent cannot do. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_hl_withdraw(
    w: *mut Wallet,
    index: u32,
    amount_usdc: *const c_char,
) -> *mut c_char {
    let Some(amount) = from_cstr(amount_usdc) else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| RUNTIME.block_on(w.hl_withdraw(index, &amount)))
}

/// Move USDC between the perp (margin) and spot wallets on the exchange. `to_perp` true is spot to
/// perp; false is perp to spot, which makes a fresh bridge deposit spendable on the XMR1 book.
/// Signed by the account key. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_hl_class_transfer(
    w: *mut Wallet,
    index: u32,
    amount_usdc: *const c_char,
    to_perp: bool,
) -> *mut c_char {
    let Some(amount) = from_cstr(amount_usdc) else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| RUNTIME.block_on(w.hl_class_transfer(index, &amount, to_perp)))
}

/// What redeeming `amount_xmr1` of XMR1 for real Monero would cost: fee, minimum, and net payout.
/// Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_xmr_redeem_quote(
    w: *mut Wallet,
    index: u32,
    amount_xmr1: *const c_char,
) -> *mut c_char {
    let Some(amount) = from_cstr(amount_xmr1) else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| RUNTIME.block_on(w.xmr_redeem_quote(index, &amount)))
}

/// Redeem XMR1 for Monero paid to `monero_address`. Opens a Wagyu order and sends the XMR1 to the
/// address that order names. Returns the order id and session id needed to track it.
/// Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_xmr_redeem(
    w: *mut Wallet,
    index: u32,
    monero_address: *const c_char,
    amount_xmr1: *const c_char,
) -> *mut c_char {
    let (Some(address), Some(amount)) = (from_cstr(monero_address), from_cstr(amount_xmr1)) else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| RUNTIME.block_on(w.xmr_redeem(index, &address, &amount)))
}

/// Progress of a redemption. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_xmr_redeem_status(
    w: *mut Wallet,
    order_id: *const c_char,
    session_id: *const c_char,
) -> *mut c_char {
    let (Some(order), Some(session)) = (from_cstr(order_id), from_cstr(session_id)) else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| RUNTIME.block_on(w.xmr_redeem_status(&order, &session)))
}

/// Across bridge fee quote for sending `amount_wei` of `symbol` from the connected chain to
/// `dest_chain_id`. Returns normalized JSON (output amount, fees, SpokePool, deposit params).
/// Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_across_quote(
    w: *mut Wallet,
    from_index: u32,
    symbol: *const c_char,
    dest_chain_id: u64,
    amount_wei: *const c_char,
) -> *mut c_char {
    let (Some(symbol), Some(amount)) = (from_cstr(symbol), from_cstr(amount_wei)) else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| RUNTIME.block_on(w.across_quote(from_index, &symbol, dest_chain_id, &amount)))
}

/// Build the Across SpokePool `depositV3` transaction (fresh quote). Returns JSON
/// `{to, spender, data, value, native, output_amount, ...}`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_across_build(
    w: *mut Wallet,
    from_index: u32,
    symbol: *const c_char,
    dest_chain_id: u64,
    amount_wei: *const c_char,
) -> *mut c_char {
    let (Some(symbol), Some(amount)) = (from_cstr(symbol), from_cstr(amount_wei)) else {
        set_error("null args");
        return ptr::null_mut();
    };
    block_json(w, |w| RUNTIME.block_on(w.across_build(from_index, &symbol, dest_chain_id, &amount)))
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
        RUNTIME.block_on(crate::provider::background(w.erc20_history(
            &token,
            index,
            &from_block,
        )))
    })
}

/// Full account history (native ETH + all ERC20 transfers) for `index`, fetched from a block
/// explorer over Tor, as a JSON array of `HistoryItem`. Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_account_history(w: *mut Wallet, index: u32) -> *mut c_char {
    block_json(w, |w| {
        RUNTIME.block_on(crate::provider::background(w.account_history(index)))
    })
}

/// Transaction receipt JSON for `tx_hash` ("null" until mined; then an object with `status` +
/// `blockNumber`). Interactive priority (the UI polls this to confirm a send fast). Caller frees.
#[no_mangle]
pub extern "C" fn aero_wallet_tx_receipt(w: *mut Wallet, tx_hash: *const c_char) -> *mut c_char {
    let Some(tx_hash) = from_cstr(tx_hash) else {
        set_error("null tx_hash");
        return ptr::null_mut();
    };
    block_json(w, |w| RUNTIME.block_on(w.tx_receipt(&tx_hash)))
}

/// Resolve an ENS name (e.g. "alice.eth") to a checksummed 0x address (Ethereum mainnet only).
/// Returns the address string, or NULL on error (see aero_last_error). Caller frees.
#[no_mangle]
pub extern "C" fn aero_wallet_resolve_ens(w: *mut Wallet, name: *const c_char) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    let Some(name) = from_cstr(name) else {
        set_error("null name");
        return ptr::null_mut();
    };
    match RUNTIME.block_on(w.resolve_ens(&name)) {
        Ok(addr) => to_cstr(&addr),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// CoW Protocol swap orders (pending + historical) for `index` from CoW's order-book API over Tor,
/// as a JSON array of swap `HistoryItem`s (with `status`). Caller frees the string.
#[no_mangle]
pub extern "C" fn aero_wallet_cow_orders(w: *mut Wallet, index: u32) -> *mut c_char {
    block_json(w, |w| {
        RUNTIME.block_on(crate::provider::background(w.cow_orders(index)))
    })
}

/// Request cooperative shutdown of all background network loops (funded scan, per-account history).
/// Called from the GUI's close handler so those loops stop and release the core lock promptly,
/// instead of the blocking close-time save waiting on an in-flight multi-minute scan/history.
#[no_mangle]
pub extern "C" fn aero_request_shutdown() {
    crate::provider::request_shutdown();
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
    crate::wallet::SCAN_CHECKED.store(0, std::sync::atomic::Ordering::Relaxed);
    crate::wallet::SCAN_FOUND.store(0, std::sync::atomic::Ordering::Relaxed);
    match RUNTIME.block_on(crate::provider::background(w.scan_funded(gap_limit))) {
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

/// Scan for funded addresses across MULTIPLE chains. `configs_json` is a JSON array of
/// `{"chain_id":<u64>,"endpoints":["..."],"socks":"socks5h://..."}` (blank socks = direct).
/// Registers funded addresses as accounts and returns their unified indices as a JSON array.
#[no_mangle]
pub extern "C" fn aero_wallet_scan_funded_multi(
    w: *mut Wallet,
    configs_json: *const c_char,
    gap_limit: u32,
) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_mut() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    let Some(js) = from_cstr(configs_json) else {
        set_error("null configs");
        return ptr::null_mut();
    };
    #[derive(serde::Deserialize)]
    struct ScanChain {
        chain_id: u64,
        endpoints: Vec<String>,
        #[serde(default)]
        socks: String,
    }
    crate::wallet::SCAN_CHECKED.store(0, std::sync::atomic::Ordering::Relaxed);
    crate::wallet::SCAN_FOUND.store(0, std::sync::atomic::Ordering::Relaxed);
    let chains: Vec<ScanChain> = serde_json::from_str(&js).unwrap_or_default();
    let configs: Vec<ProviderConfig> = chains
        .into_iter()
        .map(|c| {
            let socks = c.socks.trim().to_string();
            let direct = socks.is_empty();
            ProviderConfig {
                chain_id: c.chain_id,
                endpoints: c.endpoints,
                socks_proxy: if direct { None } else { Some(socks) },
                allow_clearnet: direct,
                timeout_secs: 30, // fail fast on an unreachable chain
            }
        })
        .collect();
    match RUNTIME.block_on(crate::provider::background(
        w.scan_funded_all_chains(configs, gap_limit),
    )) {
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

/// Live progress of an in-flight funded scan: number of addresses checked so far. Lock-free; safe to
/// call from any thread while a scan runs on another. Reset to 0 when a scan starts.
#[no_mangle]
pub extern "C" fn aero_wallet_scan_progress() -> u64 {
    crate::wallet::SCAN_CHECKED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Read-only funded-address discovery for ONE chain (see `Wallet::scan_one_chain_paths`).
/// `config_json` is a single `{chain_id, endpoints, socks}` object. Returns a JSON array of
/// `[scheme, index, path]` triples (the funded derivation paths), for `aero_wallet_register_scanned`
/// to commit. This half takes only a SHARED borrow, so the caller can hold a read lock (and release
/// it between chains), keeping account mutations like add-account responsive during the scan. Caller
/// frees.
#[no_mangle]
pub extern "C" fn aero_wallet_scan_chain_paths(
    w: *mut Wallet,
    config_json: *const c_char,
    gap_limit: u32,
) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_ref() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    let Some(js) = from_cstr(config_json) else {
        set_error("null config");
        return ptr::null_mut();
    };
    #[derive(serde::Deserialize)]
    struct ScanChain {
        chain_id: u64,
        endpoints: Vec<String>,
        #[serde(default)]
        socks: String,
    }
    let Ok(c) = serde_json::from_str::<ScanChain>(&js) else {
        set_error("bad config json");
        return ptr::null_mut();
    };
    let socks = c.socks.trim().to_string();
    let direct = socks.is_empty();
    let config = ProviderConfig {
        chain_id: c.chain_id,
        endpoints: c.endpoints,
        socks_proxy: if direct { None } else { Some(socks) },
        allow_clearnet: direct,
        timeout_secs: 30,
    };
    match RUNTIME.block_on(crate::provider::background(
        w.scan_one_chain_paths(config, gap_limit),
    )) {
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

/// Commit funded paths discovered by `aero_wallet_scan_chain_paths` (a JSON array of `[scheme, index,
/// path]` triples). Mutating half of the scan; takes an exclusive borrow but does no network I/O.
/// Returns a JSON array of the unified account indices registered. Caller frees.
#[no_mangle]
pub extern "C" fn aero_wallet_register_scanned(
    w: *mut Wallet,
    found_json: *const c_char,
) -> *mut c_char {
    clear_error();
    let Some(w) = (unsafe { w.as_mut() }) else {
        set_error("null wallet");
        return ptr::null_mut();
    };
    let Some(js) = from_cstr(found_json) else {
        set_error("null found");
        return ptr::null_mut();
    };
    let found: Vec<(usize, u32, String)> = serde_json::from_str(&js).unwrap_or_default();
    let indices = w.register_scanned(&found);
    match serde_json::to_string(&indices) {
        Ok(s) => to_cstr(&s),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Live progress of an in-flight funded scan: number of funded addresses found so far. Lock-free.
#[no_mangle]
pub extern "C" fn aero_wallet_scan_found() -> u64 {
    crate::wallet::SCAN_FOUND.load(std::sync::atomic::Ordering::Relaxed)
}

/// Owned NFT collections (ERC-721 + ERC-1155) for an account as a JSON array. Caller frees.
#[no_mangle]
pub extern "C" fn aero_wallet_account_nfts(w: *mut Wallet, index: u32) -> *mut c_char {
    block_json(w, |w| {
        RUNTIME.block_on(crate::provider::background(w.account_nfts(index)))
    })
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
    match RUNTIME.block_on(crate::provider::background(w.fetch_image_hex(&url))) {
        Ok(hexstr) => to_cstr(&hexstr),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Signed updates (see update.rs)
// -------------------------------------------------------------------------------------------------
//
// Four steps, kept separate so the UI can put a decision between any two of them. The one that
// matters is between check and download: nothing is fetched, written or installed until the user has
// seen what the signed manifest says and agreed to it.

/// The fingerprint of the key that must sign an update, for display. Caller frees.
#[no_mangle]
pub extern "C" fn aero_update_key_fingerprint() -> *mut c_char {
    to_cstr(&crate::pgp::release_fingerprint_display())
}

/// Look for a newer signed release. `current` is this build's version, `socks` the Tor proxy (may be
/// NULL to go direct). Returns the update status as JSON, or NULL with [`aero_last_error`] set.
///
/// An error here always means "could not establish that an update is genuine", never "no update".
/// A NULL return must not be shown to the user as "you are up to date".
#[no_mangle]
pub extern "C" fn aero_update_check(current: *const c_char, socks: *const c_char) -> *mut c_char {
    clear_error();
    let Some(current) = from_cstr(current) else {
        set_error("null version");
        return ptr::null_mut();
    };
    let socks = from_cstr(socks);
    match RUNTIME.block_on(crate::update::check(&current, socks.as_deref())) {
        Ok(status) => match serde_json::to_string(&status) {
            Ok(json) => to_cstr(&json),
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

/// Download the archive described by a status JSON from [`aero_update_check`] and check it against
/// the hash the signed manifest gave. Returns the archive path, or NULL on failure.
///
/// The status must be the one this core produced; it is re-parsed rather than trusted as a handle,
/// and the download is rejected unless its length and hash match what it says.
#[no_mangle]
pub extern "C" fn aero_update_download(
    status_json: *const c_char,
    app_dir: *const c_char,
    socks: *const c_char,
) -> *mut c_char {
    clear_error();
    let (Some(status_json), Some(app_dir)) = (from_cstr(status_json), from_cstr(app_dir)) else {
        set_error("null argument");
        return ptr::null_mut();
    };
    let status: crate::update::UpdateStatus = match serde_json::from_str(&status_json) {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("bad update status: {e}"));
            return ptr::null_mut();
        }
    };
    let socks = from_cstr(socks);
    match RUNTIME.block_on(crate::update::download(
        &status,
        std::path::Path::new(&app_dir),
        socks.as_deref(),
    )) {
        Ok(path) => to_cstr(&path.to_string_lossy()),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Bytes downloaded so far, and the total expected. Lock-free; poll from the UI thread.
#[no_mangle]
pub extern "C" fn aero_update_downloaded() -> u64 {
    crate::update::DOWNLOADED.load(std::sync::atomic::Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn aero_update_download_total() -> u64 {
    crate::update::DOWNLOAD_TOTAL.load(std::sync::atomic::Ordering::Relaxed)
}

/// Abandon a download in flight. Safe to call at any time, from any thread.
///
/// [`aero_update_download`] then fails with a message [`aero_update_was_cancelled`] recognises, so a
/// pressed Cancel button is not reported back to the user as a fault.
#[no_mangle]
pub extern "C" fn aero_update_cancel() {
    crate::update::cancel();
}

/// Whether a message from [`aero_last_error`] describes a cancelled download rather than a failure.
#[no_mangle]
pub extern "C" fn aero_update_was_cancelled(message: *const c_char) -> c_int {
    let Some(m) = from_cstr(message) else { return 0 };
    c_int::from(crate::update::was_cancelled(&m))
}

/// Unpack a downloaded archive into the staging folder. Returns 0 on success, -1 on failure.
///
/// Nothing in the application folder is changed by this: staging exists so that a bad archive is
/// discovered while it is still off to one side.
#[no_mangle]
pub extern "C" fn aero_update_stage(archive: *const c_char, app_dir: *const c_char) -> c_int {
    clear_error();
    let (Some(archive), Some(app_dir)) = (from_cstr(archive), from_cstr(app_dir)) else {
        set_error("null argument");
        return -1;
    };
    match crate::update::stage(
        std::path::Path::new(&archive),
        std::path::Path::new(&app_dir),
    ) {
        Ok(_) => 0,
        Err(e) => {
            set_error(e.to_string());
            -1
        }
    }
}

/// Install the staged update. Returns the number of files replaced, or -1 on failure.
///
/// On failure nothing has changed: the install undoes itself rather than leaving a folder that is
/// half one version and half another.
#[no_mangle]
pub extern "C" fn aero_update_apply(app_dir: *const c_char) -> c_int {
    clear_error();
    let Some(app_dir) = from_cstr(app_dir) else {
        set_error("null app dir");
        return -1;
    };
    match crate::update::apply(std::path::Path::new(&app_dir)) {
        Ok(n) => n as c_int,
        Err(e) => {
            set_error(e.to_string());
            -1
        }
    }
}

/// Delete what the previous update displaced. Call once at startup; does nothing if there is none.
#[no_mangle]
pub extern "C" fn aero_update_sweep(app_dir: *const c_char) {
    if let Some(app_dir) = from_cstr(app_dir) {
        crate::update::sweep(std::path::Path::new(&app_dir));
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
