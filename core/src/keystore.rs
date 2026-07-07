//! Password-encrypted wallet file.
//!
//! Layout (JSON envelope, `.aero` extension), replacing Monero's `.keys` file:
//! ```json
//! {
//!   "version": 1,
//!   "kdf": "argon2id",
//!   "salt": "<base64/hex>",
//!   "nonce": "<hex>",
//!   "ciphertext": "<hex>"   // AES-256-GCM of the plaintext JSON below
//! }
//! ```
//! The encrypted plaintext is a [`WalletSecrets`] JSON blob holding the mnemonic and metadata.
//! We never write the mnemonic or derived keys to disk in the clear.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    AeadCore, Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{CoreError, Result};

// File format versions:
//   v1 — no stored Argon2 params (used `Argon2::default()`).
//   v2 — stores Argon2 params in the (unauthenticated) header.
//   v3 — additionally binds the header (version/kdf/params/salt/nonce) as AES-GCM associated data,
//        so the KDF parameters can't be tampered with or downgraded. New wallets are written as v3.
// Older versions still decrypt for backward compatibility.
const VERSION: u32 = 3;

// Argon2id cost for NEW wallets. 64 MiB / 3 passes is comfortably above OWASP's minimum and much
// stronger than the crate default (19 MiB / 2), making offline password cracking far more costly.
const ARGON_M_COST_KIB: u32 = 65536; // 64 MiB
const ARGON_T_COST: u32 = 3;
const ARGON_P_COST: u32 = 1;

/// Metadata for a tracked ERC20 token.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenRef {
    pub address: String,
    pub symbol: String,
    pub decimals: u8,
}

/// Watch-only descriptor for a hardware-wallet file. Contains NO secrets — only the device kind
/// and the public addresses derived at create time (so the UI can show accounts). The private keys
/// never leave the Ledger/Trezor; every signature requires the device to be connected.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HwDescriptor {
    /// "ledger" | "trezor".
    pub kind: String,
    /// Cached public addresses, index-aligned with `account_order` (all `Hd` entries).
    pub addresses: Vec<String>,
}

/// One account slot, giving each unified account index a *stable* identity. Without this, deriving
/// "HD accounts first, then imported keys" meant adding an HD account shifted every imported key's
/// index — remapping which key an index signs with, and misaligning per-index labels/history.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccountEntry {
    /// HD account at the standard BIP44 derivation index `m/44'/60'/0'/0/{0}`.
    Hd(u32),
    /// Imported raw private key at `imported_keys[{0}]`.
    Imported(usize),
    /// HD account at an explicit derivation path (non-standard schemes discovered by scanning,
    /// e.g. Ledger Live `m/44'/60'/1'/0/0` or MEW/legacy `m/44'/60'/0'/1`).
    HdPath(String),
}

/// The decrypted contents of a wallet file.
#[derive(Clone, Serialize, Deserialize)]
pub struct WalletSecrets {
    pub mnemonic: String,
    /// Optional BIP39 passphrase ("extension word"). Empty = none. Stored so HD addresses
    /// re-derive identically when the wallet is reopened. Absent in older files (serde default).
    #[serde(default)]
    pub passphrase: String,
    /// Number of HD accounts derived (>=1); also the next free HD derivation index.
    pub account_count: u32,
    /// Stable unified account ordering. Empty in older files; reconstructed on load as
    /// `[Hd(0..account_count), Imported(0..imported_keys.len())]` to preserve their indices.
    #[serde(default)]
    pub account_order: Vec<AccountEntry>,
    /// Tracked ERC20 tokens (the "Tokens/Assets" panel).
    #[serde(default)]
    pub tokens: Vec<TokenRef>,
    /// Raw secp256k1 private keys (hex) imported outside the HD tree.
    #[serde(default)]
    pub imported_keys: Vec<String>,
    /// Present only for hardware wallets (watch-only; no secrets stored). When set, `mnemonic`,
    /// `passphrase` and `imported_keys` are empty and signing is delegated to the device.
    #[serde(default)]
    pub hardware: Option<HwDescriptor>,
    /// Address-only watch wallet: when non-empty (and no mnemonic/hardware), the wallet tracks these
    /// addresses with no keys — balances/history work, signing/sending is refused. Absent in older
    /// files (serde default).
    #[serde(default)]
    pub watch_addresses: Vec<String>,
    /// Opaque, frontend-owned JSON blob for per-wallet metadata (address labels, contacts, notes,
    /// funded-address list). Kept here so it is encrypted at rest instead of in plaintext settings.
    #[serde(default)]
    pub metadata: String,
}

impl Drop for WalletSecrets {
    fn drop(&mut self) {
        self.mnemonic.zeroize();
        self.passphrase.zeroize();
        // Imported keys are raw private keys; metadata can hold PII (labels/contacts/notes).
        for k in &mut self.imported_keys {
            k.zeroize();
        }
        self.metadata.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u32,
    kdf: String,
    // Argon2 cost parameters (present from version 2). Absent => version-1 defaults.
    #[serde(default)]
    m_cost: Option<u32>,
    #[serde(default)]
    t_cost: Option<u32>,
    #[serde(default)]
    p_cost: Option<u32>,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn argon2_with(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Argon2<'static>> {
    let params = Params::new(m_cost, t_cost, p_cost, None)
        .map_err(|e| CoreError::Keystore(format!("argon2 params: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn derive_key(argon: &Argon2, password: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| CoreError::Keystore(format!("argon2: {e}")))?;
    Ok(key)
}

/// Deterministic associated data (v3+) that binds the header to the ciphertext, so the KDF
/// parameters, salt and nonce can't be tampered with or downgraded without failing authentication.
fn header_aad(version: u32, kdf: &str, m: u32, t: u32, p: u32, salt_hex: &str, nonce_hex: &str) -> Vec<u8> {
    format!("aero-keystore|v={version}|kdf={kdf}|m={m}|t={t}|p={p}|salt={salt_hex}|nonce={nonce_hex}")
        .into_bytes()
}

/// Encrypt `secrets` under `password` and return the serialized envelope bytes (v3, AAD-bound).
pub fn encrypt(secrets: &WalletSecrets, password: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let argon = argon2_with(ARGON_M_COST_KIB, ARGON_T_COST, ARGON_P_COST)?;
    let mut key_bytes = derive_key(&argon, password.as_bytes(), &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let salt_hex = hex::encode(salt);
    let nonce_hex = hex::encode(nonce);
    let aad = header_aad(
        VERSION, "argon2id", ARGON_M_COST_KIB, ARGON_T_COST, ARGON_P_COST, &salt_hex, &nonce_hex,
    );

    let mut plaintext = serde_json::to_vec(secrets)?;
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext.as_ref(), aad: &aad })
        .map_err(|e| CoreError::Keystore(format!("aes-gcm encrypt: {e}")))?;
    plaintext.zeroize(); // don't leave the mnemonic JSON lingering in freed memory
    key_bytes.zeroize();

    let env = Envelope {
        version: VERSION,
        kdf: "argon2id".to_string(),
        m_cost: Some(ARGON_M_COST_KIB),
        t_cost: Some(ARGON_T_COST),
        p_cost: Some(ARGON_P_COST),
        salt: salt_hex,
        nonce: nonce_hex,
        ciphertext: hex::encode(ciphertext),
    };
    Ok(serde_json::to_vec_pretty(&env)?)
}

/// Decrypt an envelope produced by [`encrypt`].
pub fn decrypt(data: &[u8], password: &str) -> Result<WalletSecrets> {
    let env: Envelope = serde_json::from_slice(data)
        .map_err(|_| CoreError::Keystore("not a valid wallet file".into()))?;
    if env.version == 0 || env.version > VERSION {
        return Err(CoreError::Keystore(format!(
            "unsupported wallet version {}",
            env.version
        )));
    }
    let salt = hex::decode(&env.salt).map_err(|e| CoreError::Keystore(e.to_string()))?;
    let nonce_bytes = hex::decode(&env.nonce).map_err(|e| CoreError::Keystore(e.to_string()))?;
    let ciphertext =
        hex::decode(&env.ciphertext).map_err(|e| CoreError::Keystore(e.to_string()))?;

    // Only version-1 files predate stored params (crate default). v2/v3 MUST carry their params —
    // refusing the default fallback here stops an attacker from stripping params to force a weaker
    // KDF (a downgrade). For v3 the params are additionally authenticated via the AAD below.
    let (argon, params) = match (env.version, env.m_cost, env.t_cost, env.p_cost) {
        (1, _, _, _) => (Argon2::default(), None),
        (_, Some(m), Some(t), Some(p)) => (argon2_with(m, t, p)?, Some((m, t, p))),
        _ => return Err(CoreError::Keystore("wallet file missing KDF parameters".into())),
    };
    let mut key_bytes = derive_key(&argon, password.as_bytes(), &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // v3+ binds the header as associated data; v1/v2 have no AAD.
    let aad = if env.version >= 3 {
        let (m, t, p) = params.expect("v3 requires params (checked above)");
        Some(header_aad(env.version, &env.kdf, m, t, p, &env.salt, &env.nonce))
    } else {
        None
    };
    let mut plaintext = match &aad {
        Some(aad) => cipher.decrypt(nonce, Payload { msg: ciphertext.as_ref(), aad }),
        None => cipher.decrypt(nonce, ciphertext.as_ref()),
    }
    .map_err(|_| CoreError::BadPassword)?;
    key_bytes.zeroize();

    let secrets: WalletSecrets = serde_json::from_slice(&plaintext)?;
    plaintext.zeroize(); // scrub the decrypted mnemonic JSON from memory
    Ok(secrets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(metadata: &str) -> WalletSecrets {
        WalletSecrets {
            mnemonic: "test test test test test test test test test test test junk".into(),
            passphrase: String::new(),
            account_count: 1,
            account_order: vec![],
            tokens: vec![],
            imported_keys: vec![],
            hardware: None,
            watch_addresses: vec![],
            metadata: metadata.to_string(),
        }
    }

    #[test]
    fn metadata_roundtrips_encrypted() {
        let blob = encrypt(&sample(r#"{"labels":{"0":"Savings"}}"#), "pw").unwrap();
        // The metadata must NOT appear in plaintext in the file (it's inside the ciphertext).
        assert!(!String::from_utf8_lossy(&blob).contains("Savings"));
        let back = decrypt(&blob, "pw").unwrap();
        assert_eq!(back.metadata, r#"{"labels":{"0":"Savings"}}"#);
    }

    #[test]
    fn tampering_kdf_params_or_version_fails() {
        // v3 files bind version/params/salt/nonce as AAD; downgrading or lowering them must fail.
        let blob = encrypt(&sample(""), "pw").unwrap();
        let mut env: serde_json::Value = serde_json::from_slice(&blob).unwrap();

        // Lower the Argon2 memory cost -> AAD mismatch -> auth failure.
        let mut weak = env.clone();
        weak["m_cost"] = serde_json::json!(8);
        assert!(matches!(
            decrypt(&serde_json::to_vec(&weak).unwrap(), "pw"),
            Err(CoreError::BadPassword)
        ));

        // Downgrade the version to 1 (default-params, no AAD) -> wrong key -> auth failure.
        env["version"] = serde_json::json!(1);
        assert!(decrypt(&serde_json::to_vec(&env).unwrap(), "pw").is_err());
    }

    #[test]
    fn v2_without_params_is_refused() {
        // A v2/v3 file that is missing its KDF params must be rejected (anti-downgrade), not
        // silently opened with default params.
        let blob = encrypt(&sample(""), "pw").unwrap();
        let mut env: serde_json::Value = serde_json::from_slice(&blob).unwrap();
        env["version"] = serde_json::json!(2);
        env.as_object_mut().unwrap().remove("m_cost");
        assert!(decrypt(&serde_json::to_vec(&env).unwrap(), "pw").is_err());
    }

    #[test]
    fn round_trip() {
        let secrets = WalletSecrets {
            mnemonic: "test test test test test test test test test test test junk".into(),
            passphrase: "extra secret".into(),
            account_count: 3,
            account_order: vec![],
            tokens: vec![TokenRef {
                address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".into(),
                symbol: "USDT".into(),
                decimals: 6,
            }],
            imported_keys: vec![],
            hardware: None,
            watch_addresses: vec![],
            metadata: String::new(),
        };
        let blob = encrypt(&secrets, "hunter2").unwrap();
        let back = decrypt(&blob, "hunter2").unwrap();
        assert_eq!(back.mnemonic, secrets.mnemonic);
        assert_eq!(back.passphrase, "extra secret");
        assert_eq!(back.account_count, 3);
        assert_eq!(back.tokens, secrets.tokens);
    }

    #[test]
    fn decrypts_legacy_v1_file() {
        // A version-1 file has no stored Argon2 params and was written with the crate default;
        // decrypt() must fall back to that so pre-existing wallets keep opening.
        use aes_gcm::aead::{Aead, KeyInit};
        let secrets = WalletSecrets {
            mnemonic: "test test test test test test test test test test test junk".into(),
            passphrase: String::new(),
            account_count: 2,
            account_order: vec![],
            tokens: vec![],
            imported_keys: vec![],
            hardware: None,
            watch_addresses: vec![],
            metadata: String::new(),
        };
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(&Argon2::default(), b"pw", &salt).unwrap();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, serde_json::to_vec(&secrets).unwrap().as_ref())
            .unwrap();
        let env = serde_json::json!({
            "version": 1, "kdf": "argon2id",
            "salt": hex::encode(salt), "nonce": hex::encode(nonce), "ciphertext": hex::encode(ct),
        });
        let back = decrypt(&serde_json::to_vec(&env).unwrap(), "pw").unwrap();
        assert_eq!(back.account_count, 2);
    }

    #[test]
    fn wrong_password_fails() {
        let secrets = WalletSecrets {
            mnemonic: "test test test test test test test test test test test junk".into(),
            passphrase: String::new(),
            account_count: 1,
            account_order: vec![],
            tokens: vec![],
            imported_keys: vec![],
            hardware: None,
            watch_addresses: vec![],
            metadata: String::new(),
        };
        let blob = encrypt(&secrets, "correct").unwrap();
        assert!(matches!(
            decrypt(&blob, "wrong"),
            Err(CoreError::BadPassword)
        ));
    }
}
