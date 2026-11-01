#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! ReedShell synchronization service.

pub mod config;
pub mod error;
pub mod repo;
pub mod routes;
pub mod security;
pub mod services;
pub mod state;

pub use config::{Config, Environment};
pub use error::AppError;
pub use state::AppState;
