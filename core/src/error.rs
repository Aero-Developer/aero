//! Error types for the wallet core.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid mnemonic: {0}")]
    Mnemonic(String),

    #[error("key derivation failed: {0}")]
    Derivation(String),

    #[error("keystore error: {0}")]
    Keystore(String),

    #[error("wrong password or corrupted wallet file")]
    BadPassword,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("network/rpc error: {0}")]
    Rpc(String),

    #[error("provider not configured; call set_rpc first")]
    NoProvider,

    #[error("invalid address: {0}")]
    Address(String),

    #[error("invalid amount: {0}")]
    Amount(String),

    #[error("signing error: {0}")]
    Signing(String),

    #[error("{0}")]
    Other(String),
}

impl CoreError {
    pub fn other(msg: impl Into<String>) -> Self {
        CoreError::Other(msg.into())
    }
    pub fn rpc(msg: impl Into<String>) -> Self {
        CoreError::Rpc(msg.into())
    }
}
