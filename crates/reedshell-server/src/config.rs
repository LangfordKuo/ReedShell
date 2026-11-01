use std::{env, fmt, net::SocketAddr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use thiserror::Error;

/// Runtime environment of the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

impl Environment {
    #[must_use]
    pub fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

/// Process configuration read from the environment.
#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub environment: Environment,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    /// 32-byte Ed25519 seed used to sign access tokens and entitlements.
    pub token_signing_key: [u8; 32],
    /// Allows the in-memory repository. Only valid outside production.
    pub allow_memory_repository: bool,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid REEDSHELL_BIND value: {0}")]
    Bind(String),
    #[error("REEDSHELL_TOKEN_KEY must be base64 for exactly 32 bytes")]
    TokenKey,
    #[error("REEDSHELL_TOKEN_KEY is required when REEDSHELL_ENV=production")]
    MissingTokenKey,
    #[error("random source unavailable")]
    Random,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_raw = env::var("REEDSHELL_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
        let bind_addr = bind_raw
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::Bind(bind_raw))?;

        let environment = match env::var("REEDSHELL_ENV").as_deref() {
            Ok("production") => Environment::Production,
            _ => Environment::Development,
        };

        let database_url = non_empty_env("DATABASE_URL");
        let redis_url = non_empty_env("REDIS_URL");

        let token_signing_key = match env::var("REEDSHELL_TOKEN_KEY") {
            Ok(value) => {
                let bytes = STANDARD
                    .decode(value.trim())
                    .map_err(|_| ConfigError::TokenKey)?;
                bytes.try_into().map_err(|_| ConfigError::TokenKey)?
            }
            Err(_) if environment.is_production() => return Err(ConfigError::MissingTokenKey),
            Err(_) => {
                let mut key = [0u8; 32];
                getrandom::fill(&mut key).map_err(|_| ConfigError::Random)?;
                key
            }
        };

        let allow_memory_repository = match env::var("REEDSHELL_ALLOW_MEMORY").as_deref() {
            Ok("1" | "true" | "yes") => true,
            Ok("0" | "false" | "no") => false,
            _ => !environment.is_production(),
        };

        Ok(Self {
            bind_addr,
            environment,
            database_url,
            redis_url,
            token_signing_key,
            allow_memory_repository,
        })
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("environment", &self.environment)
            .field("database_url_configured", &self.database_url.is_some())
            .field("redis_url_configured", &self.redis_url.is_some())
            .field("token_signing_key", &"[REDACTED]")
            .field("allow_memory_repository", &self.allow_memory_repository)
            .finish()
    }
}

fn non_empty_env(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_signing_key() {
        let config = Config {
            bind_addr: "127.0.0.1:8080".parse().expect("valid addr"),
            environment: Environment::Development,
            database_url: None,
            redis_url: None,
            token_signing_key: [9u8; 32],
            allow_memory_repository: true,
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("9, 9"));
        assert!(rendered.contains("REDACTED"));
    }
}
