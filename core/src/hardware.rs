//! Hardware-wallet device layer (Ledger + Trezor) over USB.
//!
//! Keys never leave the device. We connect on demand for each operation (enumerate / derive
//! address / sign) rather than holding a live handle, which keeps the wallet `Send` across the
//! FFI's worker threads and matches the stateless nature of the devices.
//!
//! * Ledger: driven through `alloy-signer-ledger` (native HID transport). Ledger's Ethereum app has
//!   no host-passphrase API, so any BIP39 passphrase is entered on the device itself.
//! * Trezor: driven through `trezor-client` directly (not `alloy-signer-trezor`) so we can inject a
//!   host-entered passphrase (Trezor Suite style) via the `PassphraseRequest` -> `ack_passphrase`
//!   flow. Talks to the device directly over USB - no vendor bridge or suite needs to be running.
//! * Trezor, 2025+ models (Safe 5/7, T3W1): those speak only the Trezor-Host Protocol and reject
//!   the client above with `Failure_InvalidProtocol`. They are handled by `thp_conn`, which this
//!   module falls back to. Unlike the rest of this layer, a THP connection is held open and reused,
//!   because establishing one costs a full Noise handshake.
//!
//! All accounts use the standard BIP44 path `m/44'/60'/0'/0/{index}` (matching Aero's software
//! wallets and MetaMask).

use alloy::consensus::SignableTransaction;
use alloy::primitives::{normalize_v, Address, Signature, U256};
use alloy_signer_ledger::{HDPath, LedgerSigner};
use trezor_client::{protos, Trezor, TrezorMessage, TrezorResponse};

use crate::error::{CoreError, Result};

/// Supported hardware wallet families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwKind {
    Ledger,
    Trezor,
}

impl HwKind {
    pub fn as_str(self) -> &'static str {
        match self {
            HwKind::Ledger => "ledger",
            HwKind::Trezor => "trezor",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ledger" => Ok(HwKind::Ledger),
            "trezor" => Ok(HwKind::Trezor),
            other => Err(CoreError::rpc(format!("unknown hardware kind: {other}"))),
        }
    }
}

/// Which protocol the attached Trezor speaks.
///
/// Worth remembering rather than re-deciding: finding out costs a rejected handshake, and for a THP
/// device the legacy client retries several times before giving up. Cleared whenever a device is
/// unplugged or an operation fails outright, so swapping devices re-probes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrezorProtocol {
    Legacy,
    Thp,
}

static TREZOR_PROTOCOL: std::sync::Mutex<Option<TrezorProtocol>> = std::sync::Mutex::new(None);

fn remembered_protocol() -> Option<TrezorProtocol> {
    *TREZOR_PROTOCOL.lock().unwrap()
}

fn remember_protocol(p: Option<TrezorProtocol>) {
    *TREZOR_PROTOCOL.lock().unwrap() = p;
}

/// Run a Trezor operation, over whichever protocol the device speaks.
///
/// On the first operation both are tried, legacy first so that existing devices behave exactly as
/// before. If both fail, both errors are reported: the legacy error alone is misleading on a THP
/// device, and the THP error alone is misleading on a legacy one.
fn trezor_op<T>(
    legacy: impl Fn() -> std::result::Result<T, String>,
    thp: impl Fn() -> std::result::Result<T, String>,
) -> Result<T> {
    match remembered_protocol() {
        Some(TrezorProtocol::Legacy) => legacy().map_err(|e| {
            remember_protocol(None);
            CoreError::rpc(e)
        }),
        Some(TrezorProtocol::Thp) => thp().map_err(|e| {
            remember_protocol(None);
            crate::thp_conn::disconnect();
            CoreError::rpc(e)
        }),
        None => match legacy() {
            Ok(v) => {
                remember_protocol(Some(TrezorProtocol::Legacy));
                Ok(v)
            }
            Err(legacy_err) => match thp() {
                Ok(v) => {
                    remember_protocol(Some(TrezorProtocol::Thp));
                    Ok(v)
                }
                Err(thp_err) => {
                    crate::thp_conn::disconnect();
                    Err(CoreError::rpc(format!(
                        "could not talk to the Trezor.\n\
                         As an older device (Model One/T, Safe 3): {legacy_err}\n\
                         As a 2025+ device (Safe 5/7): {thp_err}"
                    )))
                }
            },
        },
    }
}

/// Standard Ethereum BIP44 derivation path string for `index`.
fn path_str(index: u32) -> String {
    format!("m/44'/60'/0'/0/{index}")
}

/// Trezor path as hardened components: m/44'/60'/0'/0/{index}.
fn trezor_path(index: u32) -> Vec<u32> {
    const H: u32 = 0x8000_0000;
    vec![44 | H, 60 | H, H, 0, index]
}

/// Big-endian, leading-zeros-trimmed encoding (as Ethereum/Trezor expect for scalars).
fn u_be(n: u128) -> Vec<u8> {
    U256::from(n).to_be_bytes_trimmed_vec()
}

// -------------------------------------------------------------------------------------------------
// Discovery
// -------------------------------------------------------------------------------------------------

/// List connected devices of `kind` (human-readable names). Empty when none are present/reachable.
pub async fn list_devices(kind: HwKind) -> Vec<String> {
    match kind {
        HwKind::Ledger => match LedgerSigner::new(HDPath::Other(path_str(0)), None).await {
            Ok(s) => vec![format!("Ledger ({})", s.get_address().await
                .map(|a| a.to_checksum(None)).unwrap_or_default())],
            Err(_) => Vec::new(),
        },
        HwKind::Trezor => trezor_client::find_devices(false)
            .into_iter()
            .filter(|d| !d.debug)
            .map(|d| d.model.to_string())
            .collect(),
    }
}

// -------------------------------------------------------------------------------------------------
// Address derivation
// -------------------------------------------------------------------------------------------------

/// Derive `count` addresses starting at `start`, connecting to the device once. `on_device` asks a
/// THP Trezor (Safe 5/7) to take the BIP39 passphrase on its own screen instead of over the wire.
pub async fn get_addresses(
    kind: HwKind,
    passphrase: &str,
    on_device: bool,
    start: u32,
    count: u32,
) -> Result<Vec<String>> {
    match kind {
        HwKind::Ledger => {
            // One transport, reused across the derivations.
            let signer = LedgerSigner::new(HDPath::Other(path_str(start)), None)
                .await
                .map_err(|e| CoreError::rpc(format!("Ledger: {e}")))?;
            let mut out = Vec::with_capacity(count as usize);
            for i in start..start + count {
                let addr = signer
                    .get_address_with_path(&HDPath::Other(path_str(i)))
                    .await
                    .map_err(|e| CoreError::rpc(format!("Ledger get_address: {e}")))?;
                out.push(addr.to_checksum(None));
            }
            Ok(out)
        }
        HwKind::Trezor => {
            let raw = trezor_op(
                || {
                    let mut client = connect_trezor().map_err(|e| e.to_string())?;
                    let mut out = Vec::with_capacity(count as usize);
                    for i in start..start + count {
                        out.push(trezor_get_address(&mut client, trezor_path(i), passphrase)?);
                    }
                    Ok(out)
                },
                || crate::thp_conn::get_addresses(passphrase, on_device, start, count),
            )?;
            raw.into_iter()
                .map(|s| {
                    s.parse::<Address>()
                        .map(|a| a.to_checksum(None))
                        .map_err(|e| CoreError::rpc(format!("bad Trezor address {s}: {e}")))
                })
                .collect()
        }
    }
}

/// Derive a single address at `index`.
pub async fn get_address(
    kind: HwKind,
    passphrase: &str,
    on_device: bool,
    index: u32,
) -> Result<String> {
    let mut v = get_addresses(kind, passphrase, on_device, index, 1).await?;
    v.pop().ok_or_else(|| CoreError::rpc("no address returned"))
}

// -------------------------------------------------------------------------------------------------
// Signing
// -------------------------------------------------------------------------------------------------

/// Sign an already-built EIP-1559/legacy transaction with a Ledger, returning the signature to
/// attach. We pass the wallet's own signing-payload RLP bytes to the device (rather than the alloy
/// tx object) so we don't depend on the Ledger crate's alloy-consensus version. The device returns
/// a y-parity signature; the caller's `into_signed` re-derives the correct on-wire `v`.
pub async fn ledger_sign_tx(
    index: u32,
    chain_id: u64,
    tx: &dyn SignableTransaction<Signature>,
) -> Result<Signature> {
    let payload = tx.encoded_for_signing();
    let signer = LedgerSigner::new(HDPath::Other(path_str(index)), Some(chain_id))
        .await
        .map_err(|e| CoreError::rpc(format!("Ledger: {e}")))?;
    signer
        .sign_tx_rlp(&payload)
        .await
        .map_err(|e| CoreError::Signing(format!("Ledger sign: {e}")))
}


/// Sign a transaction with a Trezor (host-entered passphrase). Fields are the same ones the wallet
/// used to build the tx; Trezor re-encodes internally and returns r/s/v.
#[allow(clippy::too_many_arguments)]
pub async fn trezor_sign_tx(
    passphrase: &str,
    on_device: bool,
    index: u32,
    legacy: bool,
    nonce: u64,
    gas_limit: u64,
    gas_price: u128,
    max_fee: u128,
    max_priority: u128,
    to: Address,
    value: U256,
    data: &[u8],
    chain_id: u64,
) -> Result<Signature> {
    let to_str = to.to_checksum(None);
    // THP carries amounts as u128. Every real Ether amount fits (u128 wei is ~3.4e20 ETH), but
    // check rather than truncate: a silently wrong amount is the worst possible failure here.
    let value_u128: u128 = value
        .try_into()
        .map_err(|_| CoreError::rpc("transaction value is too large to sign on this device"))?;

    trezor_op(
        || {
            let mut client = connect_trezor().map_err(|e| e.to_string())?;
            let path = trezor_path(index);
            if legacy {
                trezor_sign_legacy(
                    &mut client, path, u_be(nonce as u128), u_be(gas_price), u_be(gas_limit as u128),
                    to_str.clone(), value.to_be_bytes_trimmed_vec(), data.to_vec(), chain_id,
                    passphrase,
                )
            } else {
                trezor_sign_eip1559(
                    &mut client, path, u_be(nonce as u128), u_be(gas_limit as u128), to_str.clone(),
                    value.to_be_bytes_trimmed_vec(), data.to_vec(), chain_id, u_be(max_fee),
                    u_be(max_priority), passphrase,
                )
            }
        },
        || {
            let (v, r, s) = if legacy {
                crate::thp_conn::sign_legacy(
                    passphrase, on_device, index, nonce, gas_limit, gas_price, &to_str, value_u128,
                    data, chain_id,
                )?
            } else {
                crate::thp_conn::sign_eip1559(
                    passphrase, on_device, index, nonce, gas_limit, max_fee, max_priority, &to_str,
                    value_u128, data, chain_id,
                )?
            };
            parity_signature(v, &r, &s)
        },
    )
}

// -------------------------------------------------------------------------------------------------
// Trezor protocol helpers (mirror trezor-client's ethereum flow, but inject a host passphrase)
// -------------------------------------------------------------------------------------------------

fn connect_trezor() -> Result<Trezor> {
    // A previous/interrupted session (or Trezor Suite/Bridge grabbing the device) can leave an
    // unacknowledged USB packet buffered on the device; the next `Initialize` then trips over that
    // stale message and the device replies `Failure_InvalidProtocol` (or a malformed-chunk error).
    // Dropping the handle and reconnecting drains the stale message, so retry a few times with a
    // fresh connection before giving up - this is what Trezor's own host tools do.
    let mut last = String::new();
    for attempt in 0..4 {
        match trezor_client::unique(false) {
            Ok(mut client) => match client.init_device(None) {
                Ok(()) => return Ok(client),
                Err(e) => last = e.to_string(), // client dropped here -> USB handle released
            },
            Err(e) => last = format!("Trezor not found (connect + unlock the device): {e}"),
        }
        if attempt + 1 < 4 {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
    let low = last.to_ascii_lowercase();
    let hint = if low.contains("invalidprotocol") || low.contains("invalid protocol") {
        // The device rejected Codec v1 outright - it speaks only the newer encrypted Trezor-Host
        // Protocol (THP), used by 2025+ models (Safe 5/7, T3W1). Our Trezor library is Codec v1 only,
        // so it can't pair with a THP device yet.
        "  (this is a newer Trezor that uses the encrypted Trezor-Host Protocol, which Aero does not \
         support yet - older Trezors: Model One/T, Safe 3 work. Use Trezor Suite/MetaMask with a THP \
         device for now.)"
    } else if low.contains("protocol") || low.contains("chunk") {
        "  (unplug and reconnect the Trezor, close Trezor Suite/Bridge if it's open, then retry)"
    } else {
        ""
    };
    Err(CoreError::rpc(format!("Trezor init: {last}{hint}")))
}

/// Drive a Trezor response to completion, auto-acking button requests and injecting the
/// host-entered passphrase on passphrase requests (Trezor Suite style).
fn handle_pp<T, R: TrezorMessage>(
    resp: TrezorResponse<'_, T, R>,
    pp: &str,
) -> std::result::Result<T, String> {
    match resp {
        TrezorResponse::Ok(t) => Ok(t),
        TrezorResponse::Failure(f) => Err(format!("device rejected: {}", f.message())),
        TrezorResponse::ButtonRequest(req) => {
            handle_pp(req.ack().map_err(|e| e.to_string())?, pp)
        }
        TrezorResponse::PinMatrixRequest(_) => {
            Err("Unlock your Trezor (enter the PIN on the device), then try again".to_string())
        }
        TrezorResponse::PassphraseRequest(req) => {
            handle_pp(req.ack_passphrase(pp.to_string()).map_err(|e| e.to_string())?, pp)
        }
    }
}

fn trezor_get_address(
    client: &mut Trezor,
    path: Vec<u32>,
    pp: &str,
) -> std::result::Result<String, String> {
    let mut req = protos::EthereumGetAddress::new();
    req.address_n = path;
    let resp = client
        .call(req, Box::new(|_, m: protos::EthereumAddress| Ok(m.address().into())))
        .map_err(|e| e.to_string())?;
    handle_pp(resp, pp)
}

fn parity_signature(v: u64, r: &[u8], s: &[u8]) -> std::result::Result<Signature, String> {
    let parity = normalize_v(v).ok_or_else(|| format!("invalid signature parity {v}"))?;
    if r.len() != 32 || s.len() != 32 {
        return Err("malformed r/s length".to_string());
    }
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(r);
    rs[32..].copy_from_slice(s);
    Ok(Signature::from_bytes_and_parity(&rs, parity))
}

#[allow(clippy::too_many_arguments)]
fn trezor_sign_eip1559(
    client: &mut Trezor,
    path: Vec<u32>,
    nonce: Vec<u8>,
    gas_limit: Vec<u8>,
    to: String,
    value: Vec<u8>,
    data: Vec<u8>,
    chain_id: u64,
    max_gas_fee: Vec<u8>,
    max_priority_fee: Vec<u8>,
    pp: &str,
) -> std::result::Result<Signature, String> {
    let mut req = protos::EthereumSignTxEIP1559::new();
    let mut data = data;
    req.address_n = path;
    req.set_nonce(nonce);
    req.set_max_gas_fee(max_gas_fee);
    req.set_max_priority_fee(max_priority_fee);
    req.set_gas_limit(gas_limit);
    req.set_value(value);
    req.set_chain_id(chain_id);
    req.set_to(to);
    req.set_data_length(data.len() as u32);
    let first: Vec<u8> = data.splice(..std::cmp::min(1024, data.len()), []).collect();
    req.set_data_initial_chunk(first);

    let resp = client
        .call(req, Box::new(|_, m: protos::EthereumTxRequest| Ok(m)))
        .map_err(|e| e.to_string())?;
    let mut resp = handle_pp(resp, pp)?;
    while resp.data_length() > 0 {
        let mut ack = protos::EthereumTxAck::new();
        let chunk: Vec<u8> = data.splice(..std::cmp::min(1024, data.len()), []).collect();
        ack.set_data_chunk(chunk);
        let r = client
            .call(ack, Box::new(|_, m: protos::EthereumTxRequest| Ok(m)))
            .map_err(|e| e.to_string())?;
        resp = handle_pp(r, pp)?;
    }
    // For typed (EIP-1559) txs the device returns the recovery id directly; normalize_v maps any
    // encoding (0/1, 27/28, EIP-155) to the y-parity alloy needs, and alloy re-derives the on-wire v.
    parity_signature(resp.signature_v() as u64, resp.signature_r(), resp.signature_s())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_parse_roundtrips() {
        assert_eq!(HwKind::parse("ledger").unwrap().as_str(), "ledger");
        assert_eq!(HwKind::parse("Trezor").unwrap().as_str(), "trezor");
        assert!(HwKind::parse("nano-x").is_err());
    }

    #[test]
    fn standard_bip44_paths() {
        assert_eq!(path_str(0), "m/44'/60'/0'/0/0");
        assert_eq!(path_str(3), "m/44'/60'/0'/0/3");
        // 44' , 60' , 0' , 0 , index
        assert_eq!(trezor_path(2), vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 2]);
    }

    // Note: device discovery/signing paths (list_devices/get_address/sign) require a physical
    // Ledger/Trezor and a working USB host, so they aren't unit-tested here. They return Result and
    // never unwrap, so a missing device surfaces as an error rather than a panic.
}

#[allow(clippy::too_many_arguments)]
fn trezor_sign_legacy(
    client: &mut Trezor,
    path: Vec<u32>,
    nonce: Vec<u8>,
    gas_price: Vec<u8>,
    gas_limit: Vec<u8>,
    to: String,
    value: Vec<u8>,
    data: Vec<u8>,
    chain_id: u64,
    pp: &str,
) -> std::result::Result<Signature, String> {
    let mut req = protos::EthereumSignTx::new();
    let mut data = data;
    req.address_n = path;
    req.set_nonce(nonce);
    req.set_gas_price(gas_price);
    req.set_gas_limit(gas_limit);
    req.set_value(value);
    req.set_chain_id(chain_id);
    req.set_to(to);
    req.set_data_length(data.len() as u32);
    let first: Vec<u8> = data.splice(..std::cmp::min(1024, data.len()), []).collect();
    req.set_data_initial_chunk(first);

    let resp = client
        .call(req, Box::new(|_, m: protos::EthereumTxRequest| Ok(m)))
        .map_err(|e| e.to_string())?;
    let mut resp = handle_pp(resp, pp)?;
    while resp.data_length() > 0 {
        let mut ack = protos::EthereumTxAck::new();
        let chunk: Vec<u8> = data.splice(..std::cmp::min(1024, data.len()), []).collect();
        ack.set_data_chunk(chunk);
        let r = client
            .call(ack, Box::new(|_, m: protos::EthereumTxRequest| Ok(m)))
            .map_err(|e| e.to_string())?;
        resp = handle_pp(r, pp)?;
    }
    parity_signature(resp.signature_v() as u64, resp.signature_r(), resp.signature_s())
}
