#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Shared domain types for every ReedShell component.

pub mod consts;
pub mod error;
pub mod id;
pub mod kdf;
pub mod model;
