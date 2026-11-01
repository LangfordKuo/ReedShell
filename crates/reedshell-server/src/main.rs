use std::sync::Arc;

use anyhow::Context;
use reedshell_server::{
    AppState, Config,
    repo::{UserRepository, memory::MemoryUserRepository, mysql::MySqlUserRepository},
    routes,
    security::{
        rate_limit::{MemoryRateLimiter, RateLimiter, RedisRateLimiter},
        token::TokenSigner,
    },
};
use sqlx::mysql::MySqlPoolOptions;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    init_tracing();

    let config = Config::from_env().context("invalid configuration")?;
    let config = Arc::new(config);

    let users: Arc<dyn UserRepository> = if let Some(database_url) = &config.database_url {
        let pool = MySqlPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .context("failed to connect to MySQL")?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("failed to run database migrations")?;
        tracing::info!("using MySQL user repository");
        Arc::new(MySqlUserRepository::new(pool))
    } else if config.allow_memory_repository {
        tracing::warn!("using in-memory user repository; all data is lost on restart");
        Arc::new(MemoryUserRepository::default())
    } else {
        anyhow::bail!("DATABASE_URL is required; set REEDSHELL_ALLOW_MEMORY=1 for development");
    };

    let limiter: Arc<dyn RateLimiter> = if let Some(redis_url) = &config.redis_url {
        match RedisRateLimiter::connect(redis_url).await {
            Ok(limiter) => {
                tracing::info!("using Redis rate limiter");
                Arc::new(limiter)
            }
            Err(error) if !config.environment.is_production() => {
                tracing::warn!(%error, "Redis unavailable; using in-memory rate limiter");
                Arc::new(MemoryRateLimiter::default())
            }
            Err(error) => return Err(error).context("failed to connect to Redis"),
        }
    } else if config.environment.is_production() {
        anyhow::bail!("REDIS_URL is required in production");
    } else {
        tracing::warn!("REDIS_URL is not set; using in-memory rate limiter");
        Arc::new(MemoryRateLimiter::default())
    };

    let tokens = Arc::new(TokenSigner::from_seed(config.token_signing_key));
    let state = AppState {
        config: Arc::clone(&config),
        users,
        tokens,
        limiter,
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
