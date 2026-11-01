use std::sync::Arc;

use crate::{config::Config, repo::UserRepository, security::token::TokenSigner};

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub users: Arc<dyn UserRepository>,
    pub tokens: Arc<TokenSigner>,
}
