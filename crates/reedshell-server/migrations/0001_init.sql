-- ReedShell initial schema (MySQL 8.4)
-- All timestamps are stored in UTC as DATETIME(3).

CREATE TABLE users (
    id                  CHAR(26) NOT NULL PRIMARY KEY,
    email               VARCHAR(255) NOT NULL,
    email_verified_at   DATETIME(3) NULL,
    auth_hash           VARBINARY(64) NOT NULL,
    kdf_salt            VARBINARY(16) NOT NULL,
    kdf_params          JSON NOT NULL,
    kdf_version         SMALLINT NOT NULL DEFAULT 1,
    wrapped_mk_by_pw    VARBINARY(128) NOT NULL,
    nonce_pw            VARBINARY(24) NOT NULL,
    wrapped_mk_by_rc    VARBINARY(128) NOT NULL,
    nonce_rc            VARBINARY(24) NOT NULL,
    plan                ENUM('free', 'pro') NOT NULL DEFAULT 'free',
    plan_expires_at     DATETIME(3) NULL,
    trial_used_at       DATETIME(3) NULL,
    status              ENUM('active', 'suspended', 'pending_delete') NOT NULL DEFAULT 'active',
    delete_after        DATETIME(3) NULL,
    created_at          DATETIME(3) NOT NULL,
    updated_at          DATETIME(3) NOT NULL,
    UNIQUE KEY uk_users_email (email)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE TABLE devices (
    id              CHAR(26) NOT NULL PRIMARY KEY,
    user_id         CHAR(26) NOT NULL,
    name            VARCHAR(64) NOT NULL,
    platform        ENUM('windows', 'macos', 'android', 'ios', 'web', 'unknown') NOT NULL,
    os_version      VARCHAR(64) NULL,
    app_version     VARCHAR(32) NULL,
    public_key      VARBINARY(32) NOT NULL,
    last_seen_at    DATETIME(3) NULL,
    last_ip         VARBINARY(16) NULL,
    created_at      DATETIME(3) NOT NULL,
    revoked_at      DATETIME(3) NULL,
    UNIQUE KEY uk_devices_user_pubkey (user_id, public_key),
    KEY idx_devices_user (user_id)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE TABLE refresh_tokens (
    id          CHAR(26) NOT NULL PRIMARY KEY,
    user_id     CHAR(26) NOT NULL,
    device_id   CHAR(26) NOT NULL,
    token_hash  VARBINARY(32) NOT NULL,
    expires_at  DATETIME(3) NOT NULL,
    created_at  DATETIME(3) NOT NULL,
    rotated_at  DATETIME(3) NULL,
    revoked_at  DATETIME(3) NULL,
    replaced_by CHAR(26) NULL,
    UNIQUE KEY uk_refresh_hash (token_hash),
    KEY idx_refresh_device (device_id)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE TABLE sync_counters (
    user_id  CHAR(26) NOT NULL PRIMARY KEY,
    last_seq BIGINT UNSIGNED NOT NULL DEFAULT 0
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE TABLE vault_items (
    user_id     CHAR(26) NOT NULL,
    item_id     CHAR(26) NOT NULL,
    version     INT UNSIGNED NOT NULL,
    change_seq  BIGINT UNSIGNED NOT NULL,
    deleted     TINYINT(1) NOT NULL DEFAULT 0,
    nonce       VARBINARY(24) NOT NULL,
    ciphertext  MEDIUMBLOB NOT NULL,
    size        INT UNSIGNED NOT NULL,
    updated_at  DATETIME(3) NOT NULL,
    PRIMARY KEY (user_id, item_id),
    KEY idx_vault_changes (user_id, change_seq)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE TABLE subscriptions (
    id                    CHAR(26) NOT NULL PRIMARY KEY,
    user_id               CHAR(26) NOT NULL,
    plan                  ENUM('pro') NOT NULL,
    status                ENUM('trialing', 'active', 'past_due', 'canceled', 'expired') NOT NULL,
    provider              ENUM('epay', 'redeem', 'manual') NOT NULL,
    provider_ref          VARCHAR(128) NULL,
    current_period_start  DATETIME(3) NULL,
    current_period_end    DATETIME(3) NULL,
    cancel_at_period_end  TINYINT(1) NOT NULL DEFAULT 0,
    created_at            DATETIME(3) NOT NULL,
    updated_at            DATETIME(3) NOT NULL,
    KEY idx_subscriptions_user (user_id)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE TABLE orders (
    id                CHAR(26) NOT NULL PRIMARY KEY,
    user_id           CHAR(26) NOT NULL,
    provider          ENUM('epay', 'redeem') NOT NULL,
    provider_order_id VARCHAR(128) NOT NULL,
    amount_cents      INT NOT NULL,
    currency          CHAR(3) NOT NULL,
    status            ENUM('pending', 'paid', 'refunded', 'failed') NOT NULL,
    raw               JSON NULL,
    created_at        DATETIME(3) NOT NULL,
    UNIQUE KEY uk_orders_provider (provider, provider_order_id),
    KEY idx_orders_user (user_id)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE TABLE redemption_codes (
    id            CHAR(26) NOT NULL PRIMARY KEY,
    code_hash     VARBINARY(32) NOT NULL,
    batch_id      CHAR(26) NOT NULL,
    plan          ENUM('pro') NOT NULL,
    duration_days INT NOT NULL,
    max_uses      INT NOT NULL DEFAULT 1,
    used_count    INT NOT NULL DEFAULT 0,
    expires_at    DATETIME(3) NULL,
    disabled_at   DATETIME(3) NULL,
    created_by    CHAR(26) NOT NULL,
    created_at    DATETIME(3) NOT NULL,
    UNIQUE KEY uk_codes_hash (code_hash)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE TABLE admin_users (
    id              CHAR(26) NOT NULL PRIMARY KEY,
    email           VARCHAR(255) NOT NULL,
    password_hash   VARBINARY(64) NOT NULL,
    totp_secret_enc VARBINARY(128) NOT NULL,
    role            ENUM('super', 'support') NOT NULL DEFAULT 'support',
    status          ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    last_login_at   DATETIME(3) NULL,
    created_at      DATETIME(3) NOT NULL,
    UNIQUE KEY uk_admin_email (email)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE TABLE audit_logs (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    actor_type  ENUM('admin', 'user', 'system') NOT NULL,
    actor_id    CHAR(26) NOT NULL,
    action      VARCHAR(64) NOT NULL,
    target_type VARCHAR(32) NULL,
    target_id   VARCHAR(64) NULL,
    metadata    JSON NULL,
    ip          VARBINARY(16) NULL,
    created_at  DATETIME(3) NOT NULL,
    KEY idx_audit_actor_time (actor_type, actor_id, created_at),
    KEY idx_audit_action_time (action, created_at)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE TABLE email_tokens (
    id         CHAR(26) NOT NULL PRIMARY KEY,
    user_id    CHAR(26) NOT NULL,
    kind       ENUM('verify', 'reset') NOT NULL,
    token_hash VARBINARY(32) NOT NULL,
    expires_at DATETIME(3) NOT NULL,
    used_at    DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL,
    UNIQUE KEY uk_email_tokens_hash (token_hash)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE TABLE web_sessions (
    id           CHAR(26) NOT NULL PRIMARY KEY,
    subject_type ENUM('user', 'admin') NOT NULL,
    subject_id   CHAR(26) NOT NULL,
    token_hash   VARBINARY(32) NOT NULL,
    csrf_hash    VARBINARY(32) NOT NULL,
    expires_at   DATETIME(3) NOT NULL,
    ip           VARBINARY(16) NULL,
    user_agent   VARCHAR(255) NULL,
    created_at   DATETIME(3) NOT NULL,
    UNIQUE KEY uk_web_sessions_hash (token_hash)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;
