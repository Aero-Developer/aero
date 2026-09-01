// SPDX-License-Identifier: BSD-3-Clause
//! Wallet-facing layer over the Trezor-Host Protocol.
//!
//! `thp.rs` implements the protocol; this module makes it usable from the rest of the wallet. It
//! owns three things the protocol layer deliberately does not:
//!
//!   * **the pairing credential on disk** - so a device is paired once rather than once per launch,
//!   * **the live connection** - a THP connection costs a full Noise handshake, so it is opened once
//!     and reused rather than rebuilt for every address derivation,
//!   * **the 6-digit code prompt** - pairing needs user input in the middle of the protocol, which
//!     the caller supplies as a hook.
//!
//! Everything here is blocking. Callers run it on a worker thread, as they already do for the
//! legacy Trezor client.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use crate::thp::{self, Channel, EncryptedChannel, Eip1559Tx};

/// How the user is asked for the 6-digit code the device displays during pairing.
///
/// Returns the code, or an error if the user cancelled. Called on whichever thread drives the
/// connection, so an implementation that needs a UI thread must marshal the call itself.
pub type CodePrompt = Box<dyn Fn() -> Result<String, String> + Send + 'static>;

// Kept apart rather than in one struct so that pairing, which blocks on the user for as long as it
// takes them to read a code off the screen, only holds the prompt lock.
static CREDENTIAL_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
static PROMPT: Mutex<Option<CodePrompt>> = Mutex::new(None);
static CONNECTION: Mutex<Option<Connection>> = Mutex::new(None);

/// Lock without caring whether a previous holder panicked.
///
/// The alternative, `unwrap()`, turns one panic anywhere in the protocol code into a permanently
/// dead hardware-wallet feature for the rest of the run - and, because these are reached from an
/// `extern "C"` boundary, into an abort of the whole application. Nothing here is an invariant that
/// a panic could leave half-applied: the worst a poisoned lock hands back is a connection that has
/// gone stale, which the caller already handles by reconnecting.
fn lock<T>(m: &'static Mutex<T>) -> MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Point the THP layer at a credential file and a way to prompt for the pairing code. Called once
/// during start-up; the path comes from the caller so that portable installations keep their state
/// alongside the executable.
pub fn configure(credential_path: PathBuf, prompt: Option<CodePrompt>) {
    *lock(&CREDENTIAL_PATH) = Some(credential_path);
    *lock(&PROMPT) = prompt;
}

/// Whether a device has already been paired, i.e. whether connecting will be silent.
pub fn is_paired() -> bool {
    credential_path()
        .and_then(|p| Credentials::load(&p))
        .map(|c| c.credential.is_some())
        .unwrap_or(false)
}

/// Forget the stored pairing. The next connection pairs from scratch.
pub fn forget_pairing() -> Result<(), String> {
    disconnect();
    let path = credential_path()?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("could not remove the pairing: {e}"))?;
    }
    Ok(())
}

/// Drop the cached connection. The device is left alone; the next call reconnects.
pub fn disconnect() {
    *lock(&CONNECTION) = None;
}

/// Derive `count` Ethereum addresses starting at `start`, for the wallet selected by `passphrase`.
pub fn get_addresses(passphrase: &str, start: u32, count: u32) -> Result<Vec<String>, String> {
    with_connection(|conn| {
        let session = conn.session_for(passphrase)?;
        let mut out = Vec::with_capacity(count as usize);
        // saturating, so that a nonsensical range asks the device for nothing rather than wrapping
        // round to index 0 and handing back addresses the caller will file under the wrong account.
        for index in start..start.saturating_add(count) {
            out.push(conn.address(session, index)?);
        }
        Ok(out)
    })
}

/// Sign an EIP-1559 transaction, returning `(v, r, s)`. The user approves it on the device.
#[allow(clippy::too_many_arguments)]
pub fn sign_eip1559(
    passphrase: &str,
    index: u32,
    nonce: u64,
    gas_limit: u64,
    max_fee: u128,
    max_priority: u128,
    to: &str,
    value: u128,
    data: &[u8],
    chain_id: u64,
) -> Result<(u64, [u8; 32], [u8; 32]), String> {
    with_connection(|conn| {
        let session = conn.session_for(passphrase)?;
        let tx = Eip1559Tx {
            nonce,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: max_priority,
            gas_limit,
            to,
            value,
            data,
            chain_id,
        };
        conn.channel.ethereum_sign_eip1559(&mut conn.crypto, session, &path_for(index), &tx)
    })
}

/// Sign a legacy (pre-EIP-1559) transaction, returning `(v, r, s)`. `v` is EIP-155 encoded.
#[allow(clippy::too_many_arguments)]
pub fn sign_legacy(
    passphrase: &str,
    index: u32,
    nonce: u64,
    gas_limit: u64,
    gas_price: u128,
    to: &str,
    value: u128,
    data: &[u8],
    chain_id: u64,
) -> Result<(u64, [u8; 32], [u8; 32]), String> {
    with_connection(|conn| {
        let session = conn.session_for(passphrase)?;
        let tx = thp::LegacyTx { nonce, gas_price, gas_limit, to, value, data, chain_id };
        conn.channel.ethereum_sign_legacy(&mut conn.crypto, session, &path_for(index), &tx)
    })
}

/// Whether a Trezor that speaks THP is attached. Cheap: it only enumerates USB.
pub fn device_present() -> bool {
    thp::usb::UsbLink::open().is_ok()
}

// -------------------------------------------------------------------------------------------------
// Connection handling
// -------------------------------------------------------------------------------------------------

struct Connection {
    channel: Channel,
    crypto: EncryptedChannel,
    /// Sessions already opened on this connection, keyed by passphrase. A session is a passphrase
    /// wallet, so reusing them avoids re-deriving the seed on every call.
    sessions: HashMap<String, u8>,
}

impl Connection {
    fn session_for(&mut self, passphrase: &str) -> Result<u8, String> {
        if let Some(&id) = self.sessions.get(passphrase) {
            return Ok(id);
        }
        let arg = if passphrase.is_empty() { None } else { Some(passphrase) };
        let id = self.channel.create_session(&mut self.crypto, arg, false)?;
        self.sessions.insert(passphrase.to_string(), id);
        Ok(id)
    }

    fn address(&mut self, session: u8, index: u32) -> Result<String, String> {
        self.channel.ethereum_address(&mut self.crypto, session, &path_for(index))
    }
}

/// Whether an error is the device's own answer rather than a broken connection.
///
/// The distinction decides whether retrying is safe. A transport failure can be retried because the
/// device never saw the request; a refusal from the device must not be, because retrying replays the
/// request - and for signing that means putting a confirmation the user has just declined straight
/// back on their screen, where a reflexive tap approves it.
fn device_answered(err: &str) -> bool {
    err.starts_with("device reported") || err == "cancelled on the device"
}

/// Run `f` against a live connection, opening one if needed.
///
/// A cached connection can go stale without us noticing - the cable is pulled, the device locks,
/// another program takes it. Rather than trying to detect that, a transport failure drops the
/// connection and retries once from scratch. The second failure is reported.
fn with_connection<T, F>(mut f: F) -> Result<T, String>
where
    F: FnMut(&mut Connection) -> Result<T, String>,
{
    for attempt in 0..2 {
        let mut guard = lock(&CONNECTION);
        if guard.is_none() {
            // Pairing is only ever attempted on the first try. Retrying it would put the pairing
            // dialog back in the user's face for every failure - and since each retry also makes
            // the device display a fresh code, a loop of them is both alarming and useless.
            match connect(attempt == 0) {
                Ok(c) => *guard = Some(c),
                // Connecting can fail for a reason the attempt itself resolves - the credential
                // upgrade below records that it tried, so the retry takes a different path.
                Err(e) if attempt == 1 => return Err(e),
                Err(_) => continue,
            }
        }
        let conn = guard.as_mut().expect("just connected");
        match f(conn) {
            Ok(v) => return Ok(v),
            Err(e) => {
                *guard = None; // force a fresh handshake next time round
                if attempt == 1 || device_answered(&e) {
                    return Err(e);
                }
            }
        }
    }
    unreachable!("loop returns on both attempts")
}

/// Open a channel, handshake, and - if `allow_pairing` - pair when the device does not know us.
fn connect(allow_pairing: bool) -> Result<Connection, String> {
    let path = credential_path()?;
    let mut creds = Credentials::load(&path)?;

    let link = thp::usb::UsbLink::open()?;
    let (mut channel, _props) = Channel::allocate(link)?;
    let mut hs = channel.handshake(creds.host_static_priv, creds.credential.as_deref(), true)?;

    if hs.is_paired() {
        // The device knows us, but may still want a tap to let us connect. Upgrading the credential
        // to an autoconnect one removes that, and can only be done from here - an already-paired
        // connection - never during pairing itself.
        //
        // Attempted at most once. If the user declines, or the firmware refuses, we carry on with
        // the ordinary credential and simply keep confirming on connect; nagging every launch would
        // be worse than the tap. The attempt is recorded either way.
        if hs.trezor_state == thp::device_state::PAIRED && !creds.autoconnect_tried {
            let upgraded = creds.credential.as_deref().and_then(|prev| {
                channel
                    .request_autoconnect_credential(&mut hs.crypto, &hs.host_static_pub, prev)
                    .ok()
            });
            let upgraded_ok = upgraded.is_some();
            if let Some(cred) = upgraded {
                creds.credential = Some(cred);
            }
            creds.autoconnect_tried = true;
            creds.save(&path)?;

            // A refused credential request can leave the channel unusable, so give up on this one
            // and let the caller reconnect. The flag now saved means the retry will not ask again.
            if !upgraded_ok {
                return Err("could not upgrade the pairing for silent reconnects".into());
            }
        }
        channel.finish_without_pairing(&mut hs.crypto)?;
    } else {
        // Either this device has never seen us, or it forgot us - a wipe, or the user removing the
        // host from the device's list. Either way the stored credential is dead, so pair afresh.
        if !allow_pairing {
            return Err("this Trezor needs to be paired with Aero - reconnect it and try again".into());
        }
        let guard = lock(&PROMPT);
        let prompt = guard.as_ref().ok_or(
            "this Trezor needs to be paired, but Aero has no way to ask you for the code",
        )?;
        let outcome = channel.pair_code_entry(
            &hs.handshake_hash,
            &hs.host_static_pub,
            &mut hs.crypto,
            "Aero",
            "Aero Wallet",
            || prompt(),
        )?;
        drop(guard);

        creds.credential = Some(outcome.credential);
        creds.save(&path)?;
    }

    Ok(Connection { channel, crypto: hs.crypto, sessions: HashMap::new() })
}

fn credential_path() -> Result<PathBuf, String> {
    lock(&CREDENTIAL_PATH)
        .clone()
        .ok_or_else(|| "the Trezor THP layer has not been configured".to_string())
}

/// Standard Ethereum derivation path, matching the rest of the wallet.
fn path_for(index: u32) -> [u32; 5] {
    const H: u32 = 0x8000_0000;
    [44 | H, 60 | H, H, 0, index]
}

// -------------------------------------------------------------------------------------------------
// Credential storage
// -------------------------------------------------------------------------------------------------

/// The host's identity for this device, persisted between runs.
///
/// The static key is what the credential is bound to, so the two must be kept together - a
/// credential without its key is worthless, and a new key means pairing again. Neither is secret in
/// the sense that losing it risks funds: the worst case is being asked to pair once more.
struct Credentials {
    host_static_priv: [u8; 32],
    credential: Option<Vec<u8>>,
    /// Whether we have already tried to upgrade to a credential that connects without a tap.
    /// Recorded so a device or user that refuses is not asked again on every launch.
    autoconnect_tried: bool,
}

impl Credentials {
    fn load(path: &std::path::Path) -> Result<Self, String> {
        let fresh =
            || Self { host_static_priv: rand::random(), credential: None, autoconnect_tried: false };
        let Ok(text) = std::fs::read_to_string(path) else {
            return Ok(fresh());
        };
        let mut host_static_priv = None;
        let mut credential = None;
        let mut autoconnect_tried = false;
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else { continue };
            match key.trim() {
                "host_static_priv" => {
                    host_static_priv = hex::decode(value.trim())
                        .ok()
                        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
                }
                "credential" => credential = hex::decode(value.trim()).ok(),
                "autoconnect_tried" => autoconnect_tried = value.trim() == "1",
                _ => {}
            }
        }
        match host_static_priv {
            // A corrupt or truncated file is not worth failing over: start again and re-pair.
            None => Ok(fresh()),
            Some(key) => Ok(Self { host_static_priv: key, credential, autoconnect_tried }),
        }
    }

    fn save(&self, path: &std::path::Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
        }
        let mut text = format!("host_static_priv={}\n", hex::encode(self.host_static_priv));
        if let Some(c) = &self.credential {
            text.push_str(&format!("credential={}\n", hex::encode(c)));
        }
        if self.autoconnect_tried {
            text.push_str("autoconnect_tried=1\n");
        }
        std::fs::write(path, text).map_err(|e| format!("could not save the pairing: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_round_trip_through_disk() {
        let dir = std::env::temp_dir().join(format!("aero-thp-test-{}", std::process::id()));
        let path = dir.join("pairing.txt");
        let _ = std::fs::remove_file(&path);

        // Missing file yields a fresh key and no credential, rather than an error.
        let fresh = Credentials::load(&path).unwrap();
        assert!(fresh.credential.is_none());

        let saved = Credentials {
            host_static_priv: [7u8; 32],
            credential: Some(vec![1, 2, 3]),
            autoconnect_tried: true,
        };
        saved.save(&path).unwrap();
        let loaded = Credentials::load(&path).unwrap();
        assert_eq!(loaded.host_static_priv, [7u8; 32]);
        assert_eq!(loaded.credential, Some(vec![1, 2, 3]));
        assert!(loaded.autoconnect_tried, "an upgrade attempt must not be repeated every launch");

        // Garbage must not be fatal: we re-pair instead of refusing to start.
        std::fs::write(&path, "nonsense").unwrap();
        assert!(Credentials::load(&path).unwrap().credential.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_refusal_from_the_device_is_never_retried() {
        // Every phrasing describe_failure() can produce, since retrying any of them would replay a
        // confirmation the user has already answered.
        assert!(device_answered("cancelled on the device"));
        assert!(device_answered("device reported a failure: Invalid session"));
        assert!(device_answered("device reported failure code 4"));
        assert!(device_answered("device reported an unspecified failure"));

        // Transport failures, by contrast, mean the device never saw the request.
        assert!(!device_answered("no Trezor found on USB"));
        assert!(!device_answered("timed out waiting for the device"));
    }

    #[test]
    fn derivation_path_matches_the_wallet() {
        assert_eq!(path_for(0), [0x8000_002C, 0x8000_003C, 0x8000_0000, 0, 0]);
        assert_eq!(path_for(5)[4], 5);
    }
}
