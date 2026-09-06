//! aero_core - the Ethereum wallet backend for the Aero desktop wallet.
//!
//! This crate replaces Feather's Monero `libwalletqt`/`monero` backend. It provides:
//!   * BIP39/BIP44 HD key derivation for Ethereum ([`keys`]),
//!   * a password-encrypted wallet file ([`keystore`]),
//!   * ERC20 ABI helpers ([`erc20`]),
//!   * a Tor-routed JSON-RPC provider with endpoint rotation ([`provider`]),
//!   * EIP-1559 transaction building/signing and balances ([`wallet`]),
//!   * a C ABI ([`ffi`]) consumed by the Qt/C++ frontend.
//!
//! Networking is designed to avoid third-party trust: with the `helios` feature the provider
//! talks to a local Helios light client that cryptographically verifies an untrusted upstream RPC;
//! without it, requests still go over Tor to user-configured endpoints.

pub mod across;
pub mod chains;
pub mod erc20;
pub mod error;
pub mod explorers;
pub mod ffi;
pub mod hardware;
pub mod hyperliquid;
pub mod keys;
pub mod keystore;
pub mod pgp;
pub mod provider;
pub mod thp;
pub mod thp_conn;
pub mod update;
pub mod wagyu;
pub mod wallet;

#[cfg(feature = "helios")]
pub mod helios_rt;

pub use error::{CoreError, Result};
pub use wallet::Wallet;
