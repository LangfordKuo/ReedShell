use std::collections::HashMap;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::sync::Mutex;

/// Result of consuming one unit from a rate-limit bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after_secs: u64,
}

/// Current state of a bucket without consuming a unit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateLimitState {
    pub count: u32,
    pub retry_after_secs: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("rate limiter backend unavailable")]
    Unavailable,
}

/// Fixed-window rate limiter.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn hit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> Result<RateLimitDecision, RateLimitError>;

    async fn peek(&self, key: &str) -> Result<RateLimitState, RateLimitError>;

    async fn reset(&self, key: &str) -> Result<(), RateLimitError>;
}

#[derive(Clone, Copy)]
struct Window {
    count: u32,
    expires_at: i64,
}

/// In-process limiter used in tests and when Redis is unavailable in development.
#[derive(Default)]
pub struct MemoryRateLimiter {
    buckets: Mutex<HashMap<String, Window>>,
}

impl MemoryRateLimiter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RateLimiter for MemoryRateLimiter {
    async fn hit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> Result<RateLimitDecision, RateLimitError> {
        let now = now_secs();
        let mut buckets = self.buckets.lock().await;
        let window = buckets.entry(key.to_owned()).or_insert(Window {
            count: 0,
            expires_at: saturating_add(now, window_secs),
        });

        if window.expires_at <= now {
            window.count = 0;
            window.expires_at = saturating_add(now, window_secs);
        }

        window.count = window.count.saturating_add(1);
        let retry_after = u64::try_from((window.expires_at - now).max(0)).unwrap_or(0);

        Ok(RateLimitDecision {
            allowed: window.count <= limit,
            remaining: limit.saturating_sub(window.count),
            retry_after_secs: retry_after,
        })
    }

    async fn peek(&self, key: &str) -> Result<RateLimitState, RateLimitError> {
        let now = now_secs();
        let buckets = self.buckets.lock().await;
        let Some(window) = buckets.get(key) else {
            return Ok(RateLimitState::default());
        };
        if window.expires_at <= now {
            return Ok(RateLimitState::default());
        }
        Ok(RateLimitState {
            count: window.count,
            retry_after_secs: u64::try_from((window.expires_at - now).max(0)).unwrap_or(0),
        })
    }

    async fn reset(&self, key: &str) -> Result<(), RateLimitError> {
        self.buckets.lock().await.remove(key);
        Ok(())
    }
}

/// Redis-backed limiter shared by every server instance.
pub struct RedisRateLimiter {
    connection: redis::aio::ConnectionManager,
}

impl RedisRateLimiter {
    pub async fn connect(url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        let connection = client.get_connection_manager().await?;
        Ok(Self { connection })
    }

    fn storage_key(key: &str) -> String {
        format!("reedshell:rl:{key}")
    }
}

const HIT_SCRIPT: &str = r"
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {current, ttl}
";

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn hit(
        &self,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> Result<RateLimitDecision, RateLimitError> {
        let mut connection = self.connection.clone();
        let (current, ttl): (i64, i64) = redis::Script::new(HIT_SCRIPT)
            .key(Self::storage_key(key))
            .arg(window_secs)
            .invoke_async(&mut connection)
            .await
            .map_err(|_| RateLimitError::Unavailable)?;

        let count = u32::try_from(current).unwrap_or(u32::MAX);
        Ok(RateLimitDecision {
            allowed: count <= limit,
            remaining: limit.saturating_sub(count),
            retry_after_secs: u64::try_from(ttl.max(0)).unwrap_or(0),
        })
    }

    async fn peek(&self, key: &str) -> Result<RateLimitState, RateLimitError> {
        let mut connection = self.connection.clone();
        let storage_key = Self::storage_key(key);
        let (value, ttl): (Option<u32>, i64) = redis::pipe()
            .cmd("GET")
            .arg(&storage_key)
            .cmd("TTL")
            .arg(&storage_key)
            .query_async(&mut connection)
            .await
            .map_err(|_| RateLimitError::Unavailable)?;

        Ok(RateLimitState {
            count: value.unwrap_or(0),
            retry_after_secs: u64::try_from(ttl.max(0)).unwrap_or(0),
        })
    }

    async fn reset(&self, key: &str) -> Result<(), RateLimitError> {
        let mut connection = self.connection.clone();
        redis::cmd("DEL")
            .arg(Self::storage_key(key))
            .query_async::<i64>(&mut connection)
            .await
            .map_err(|_| RateLimitError::Unavailable)?;
        Ok(())
    }
}

fn now_secs() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn saturating_add(value: i64, delta: u64) -> i64 {
    let delta = i64::try_from(delta).unwrap_or(i64::MAX);
    value.saturating_add(delta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_up_to_the_limit_then_denies() {
        let limiter = MemoryRateLimiter::new();
        for _ in 0..3 {
            let decision = limiter.hit("login:user", 3, 60).await.expect("hit");
            assert!(decision.allowed);
        }
        let decision = limiter.hit("login:user", 3, 60).await.expect("hit");
        assert!(!decision.allowed);
        assert_eq!(decision.remaining, 0);
        assert!(decision.retry_after_secs > 0);
    }

    #[tokio::test]
    async fn peek_does_not_consume() {
        let limiter = MemoryRateLimiter::new();
        limiter.hit("key", 5, 60).await.expect("hit");
        let state = limiter.peek("key").await.expect("peek");
        assert_eq!(state.count, 1);
        let state = limiter.peek("key").await.expect("peek");
        assert_eq!(state.count, 1);
    }

    #[tokio::test]
    async fn reset_clears_the_bucket() {
        let limiter = MemoryRateLimiter::new();
        limiter.hit("key", 1, 60).await.expect("hit");
        assert!(!limiter.hit("key", 1, 60).await.expect("hit").allowed);
        limiter.reset("key").await.expect("reset");
        assert!(limiter.hit("key", 1, 60).await.expect("hit").allowed);
    }

    #[tokio::test]
    async fn different_keys_are_isolated() {
        let limiter = MemoryRateLimiter::new();
        assert!(limiter.hit("a", 1, 60).await.expect("hit").allowed);
        assert!(!limiter.hit("a", 1, 60).await.expect("hit").allowed);
        assert!(limiter.hit("b", 1, 60).await.expect("hit").allowed);
    }

    #[tokio::test]
    async fn redis_limiter_enforces_and_resets() {
        let Ok(url) = std::env::var("REDIS_URL") else {
            eprintln!("skipping Redis integration test: REDIS_URL is not set");
            return;
        };
        let limiter = RedisRateLimiter::connect(&url).await.expect("connect");
        let key = format!("test:{}", ulid::Ulid::new());

        assert!(limiter.hit(&key, 2, 60).await.expect("hit").allowed);
        assert!(limiter.hit(&key, 2, 60).await.expect("hit").allowed);
        let denied = limiter.hit(&key, 2, 60).await.expect("hit");
        assert!(!denied.allowed);
        assert!(denied.retry_after_secs > 0);

        let state = limiter.peek(&key).await.expect("peek");
        assert_eq!(state.count, 3);
        assert!(state.retry_after_secs > 0);

        limiter.reset(&key).await.expect("reset");
        assert!(limiter.hit(&key, 2, 60).await.expect("hit").allowed);
    }
}
