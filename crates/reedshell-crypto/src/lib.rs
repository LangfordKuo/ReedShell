#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! ReedShell client-side cryptography.
//!
//! This crate is the only place in the workspace allowed to implement
//! decryption. The server crate must not depend on these primitives.

pub mod aead;
pub mod error;
pub mod kdf;
pub mod recovery;
pub mod secret;

pub use error::CryptoError;
pub use secret::SecretKey;
