//! BIP39 mnemonic + BIP44 HD key derivation for Ethereum.
//!
//! Derivation path: `m/44'/60'/0'/0/{index}` (the standard Ethereum path, index = account slot,
//! analogous to a Feather/Monero subaddress index).

use alloy::signers::local::{coins_bip39::English, MnemonicBuilder, PrivateKeySigner};
use bip39::{Language, Mnemonic};
use zeroize::Zeroize;

use crate::error::{CoreError, Result};

/// Number of words in a BIP39 mnemonic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordCount {
    Words12,
    Words24,
}

impl WordCount {
    pub fn count(self) -> usize {
        match self {
            WordCount::Words12 => 12,
            WordCount::Words24 => 24,
        }
    }

    pub fn from_count(n: usize) -> Result<Self> {
        match n {
            12 => Ok(WordCount::Words12),
            24 => Ok(WordCount::Words24),
            _ => Err(CoreError::Mnemonic(format!(
                "unsupported word count {n} (use 12 or 24)"
            ))),
        }
    }
}

/// A validated BIP39 seed phrase with an optional passphrase (the BIP39 "extension word" /
/// "25th word"). The phrase and passphrase are zeroized on drop.
///
/// The passphrase is mixed into PBKDF2 alongside the mnemonic, so a different passphrase derives a
/// completely different set of addresses. An empty passphrase is the standard no-passphrase case.
#[derive(Clone)]
pub struct SeedPhrase {
    phrase: String,
    passphrase: String,
}

impl Drop for SeedPhrase {
    fn drop(&mut self) {
        self.phrase.zeroize();
        self.passphrase.zeroize();
    }
}

impl SeedPhrase {
    /// Generate a fresh random mnemonic using the OS RNG (no passphrase).
    pub fn generate(words: WordCount) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, words.count())
            .map_err(|e| CoreError::Mnemonic(e.to_string()))?;
        Ok(Self {
            phrase: mnemonic.to_string(),
            passphrase: String::new(),
        })
    }

    /// Validate and wrap an existing phrase (used for wallet restore), with no passphrase.
    pub fn parse(phrase: &str) -> Result<Self> {
        let normalized = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
        Mnemonic::parse_in_normalized(Language::English, &normalized)
            .map_err(|e| CoreError::Mnemonic(e.to_string()))?;
        Ok(Self {
            phrase: normalized,
            passphrase: String::new(),
        })
    }

    /// Attach a BIP39 passphrase. An empty string means "no passphrase" (the default).
    pub fn with_passphrase(mut self, passphrase: &str) -> Self {
        self.passphrase = passphrase.to_string();
        self
    }

    pub fn as_str(&self) -> &str {
        &self.phrase
    }

    /// The attached BIP39 passphrase ("" if none).
    pub fn passphrase(&self) -> &str {
        &self.passphrase
    }

    /// Whether a non-empty passphrase is attached.
    pub fn has_passphrase(&self) -> bool {
        !self.passphrase.is_empty()
    }

    pub fn word_count(&self) -> usize {
        self.phrase.split_whitespace().count()
    }

    /// Build a signer from a raw hex private key (imported outside the HD tree).
    pub fn signer_from_hex(hex_key: &str) -> Result<PrivateKeySigner> {
        let clean = hex_key.trim().trim_start_matches("0x");
        let bytes = hex::decode(clean).map_err(|e| CoreError::Derivation(format!("bad key hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(CoreError::Derivation("private key must be 32 bytes".into()));
        }
        PrivateKeySigner::from_slice(&bytes).map_err(|e| CoreError::Derivation(e.to_string()))
    }

    /// Derive the signer (private key) for a given account index using the
    /// standard Ethereum derivation path `m/44'/60'/0'/0/{index}`. The BIP39 passphrase (if any)
    /// participates in the seed derivation; an empty passphrase is the standard no-passphrase case.
    pub fn signer(&self, index: u32) -> Result<PrivateKeySigner> {
        MnemonicBuilder::<English>::default()
            .phrase(self.phrase.clone())
            .index(index)
            .map_err(|e| CoreError::Derivation(e.to_string()))?
            .password(&self.passphrase)
            .build()
            .map_err(|e| CoreError::Derivation(e.to_string()))
    }

    /// Derive the signer for an explicit BIP32 derivation path (e.g. `m/44'/60'/1'/0/0`), used to
    /// scan the non-standard schemes other Ethereum wallets use (Ledger Live, MEW/legacy, ...).
    pub fn signer_at_path(&self, path: &str) -> Result<PrivateKeySigner> {
        MnemonicBuilder::<English>::default()
            .phrase(self.phrase.clone())
            .derivation_path(path)
            .map_err(|e| CoreError::Derivation(e.to_string()))?
            .password(&self.passphrase)
            .build()
            .map_err(|e| CoreError::Derivation(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_12_and_24_words() {
        assert_eq!(SeedPhrase::generate(WordCount::Words12).unwrap().word_count(), 12);
        assert_eq!(SeedPhrase::generate(WordCount::Words24).unwrap().word_count(), 24);
    }

    #[test]
    fn known_vector_address() {
        // Canonical test mnemonic; account 0 address is well-known across Ethereum tooling.
        let phrase = "test test test test test test test test test test test junk";
        let seed = SeedPhrase::parse(phrase).unwrap();
        let signer = seed.signer(0).unwrap();
        assert_eq!(
            signer.address().to_string().to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[test]
    fn rejects_bad_phrase() {
        assert!(SeedPhrase::parse("not a valid mnemonic phrase at all nope").is_err());
    }

    #[test]
    fn passphrase_changes_derived_address() {
        let phrase = "test test test test test test test test test test test junk";
        let plain = SeedPhrase::parse(phrase).unwrap();
        let withpass = SeedPhrase::parse(phrase).unwrap().with_passphrase("hunter2");

        // Empty passphrase must match the no-passphrase derivation exactly (BIP39 default).
        let empty = SeedPhrase::parse(phrase).unwrap().with_passphrase("");
        assert_eq!(plain.signer(0).unwrap().address(), empty.signer(0).unwrap().address());

        // A non-empty passphrase must derive an entirely different address.
        assert!(withpass.has_passphrase());
        assert_ne!(plain.signer(0).unwrap().address(), withpass.signer(0).unwrap().address());
    }
}
