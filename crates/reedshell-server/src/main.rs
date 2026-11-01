use std::sync::Arc;

use anyhow::Context;
use reedshell_server::{
    AppState, Config, repo::memory::MemoryUserRepository, routes, security::token::TokenSigner,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = Config::from_env().context("invalid configuration")?;
    let config = Arc::new(config);

    if !config.allow_memory_repository {
        anyhow::bail!(
            "no persistent user repository is configured; set REEDSHELL_ALLOW_MEMORY=1 for development"
        );
    }
    tracing::warn!("using in-memory user repository; all data is lost on restart");

    let users = Arc::new(MemoryUserRepository::default());
    let tokens = Arc::new(TokenSigner::from_seed(config.token_signing_key));
    let state = AppState {
        config: Arc::clone(&config),
        users,
        tokens,
    };

    let app = routes::router(state);
    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.bind_addr))?;

    tracing::info!(
        address = %config.bind_addr,
        environment = ?config.environment,
        "ReedShell server listening"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,reedshell_server=debug"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
