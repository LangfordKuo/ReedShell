//! Protocol limits shared by client and server.

/// Length of the client-derived authentication key.
pub const AUTH_KEY_LEN: usize = 32;

/// Length of an Ed25519 or X25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of the symmetric master key.
pub const MASTER_KEY_LEN: usize = 32;

/// Length of an XChaCha20-Poly1305 nonce.
pub const AEAD_NONCE_LEN: usize = 24;

/// Length of a Poly1305 authentication tag.
pub const AEAD_TAG_LEN: usize = 16;

/// Length of a wrapped master key (key plus authentication tag).
pub const WRAPPED_MASTER_KEY_LEN: usize = MASTER_KEY_LEN + AEAD_TAG_LEN;

/// Maximum length of an email address.
pub const MAX_EMAIL_LEN: usize = 255;

/// Maximum length of a device display name.
pub const MAX_DEVICE_NAME_LEN: usize = 64;

/// Maximum length of an operating-system version string.
pub const MAX_OS_VERSION_LEN: usize = 64;

/// Maximum length of a client version string.
pub const MAX_APP_VERSION_LEN: usize = 32;

/// Maximum number of vault records per account.
pub const MAX_VAULT_ITEMS_PER_USER: u64 = 20_000;

/// Maximum total ciphertext bytes per account (50 MiB).
pub const MAX_VAULT_BYTES_PER_USER: u64 = 50 * 1024 * 1024;

/// Maximum ciphertext size of a single record (256 KiB).
pub const MAX_ITEM_BYTES: usize = 256 * 1024;

/// Maximum changes accepted in one push request.
pub const MAX_PUSH_BATCH_ITEMS: usize = 100;

/// Maximum total ciphertext accepted in one push request (1 MiB).
pub const MAX_PUSH_BATCH_BYTES: usize = 1024 * 1024;

/// Maximum page size for incremental pulls.
pub const MAX_PULL_LIMIT: u32 = 500;

/// Default page size for incremental pulls.
pub const DEFAULT_PULL_LIMIT: u32 = 200;

/// Number of days a tombstone is retained before physical deletion.
pub const TOMBSTONE_RETENTION_DAYS: i64 = 90;

/// Maximum number of active Pro devices.
pub const MAX_PRO_DEVICES: u32 = 10;

/// Access token lifetime in seconds.
pub const ACCESS_TOKEN_TTL_SECS: i64 = 15 * 60;

/// Refresh token lifetime in seconds (30 days).
pub const REFRESH_TOKEN_TTL_SECS: i64 = 30 * 24 * 60 * 60;
