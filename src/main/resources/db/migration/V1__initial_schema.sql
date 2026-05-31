-- ================================================================
-- V1: SACCOS Auth Service — Initial Schema
-- ================================================================

CREATE TABLE users (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sacco_code                  VARCHAR(50) NOT NULL,
    username                    VARCHAR(100) NOT NULL,
    phone                       VARCHAR(20) NOT NULL UNIQUE,
    email                       VARCHAR(200),
    full_name                   VARCHAR(200) NOT NULL,
    password_hash               VARCHAR(255) NOT NULL,
    member_id                   UUID,
    member_number               VARCHAR(50),
    status                      VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    failed_login_attempts       INT NOT NULL DEFAULT 0,
    locked_until                TIMESTAMP,
    last_login_at               TIMESTAMP,
    last_login_ip               VARCHAR(50),
    password_changed_at         TIMESTAMP,
    must_change_password        BOOLEAN NOT NULL DEFAULT TRUE,
    password_reset_otp          VARCHAR(255),
    password_reset_otp_expiry   TIMESTAMP,
    created_by                  VARCHAR(200),
    created_at                  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (username, sacco_code)
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    VARCHAR(30) NOT NULL,
    PRIMARY KEY (user_id, role)
);

CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token           VARCHAR(255) NOT NULL UNIQUE,
    expires_at      TIMESTAMP NOT NULL,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_reason  VARCHAR(50),
    device_info     TEXT,
    ip_address      VARCHAR(50),
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE auth_audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID,
    username        VARCHAR(100),
    sacco_code      VARCHAR(50),
    action          VARCHAR(50) NOT NULL,
    success         BOOLEAN NOT NULL,
    failure_reason  TEXT,
    details         TEXT,
    ip_address      VARCHAR(50),
    user_agent      TEXT,
    device_info     TEXT,
    performed_by    UUID,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_users_sacco         ON users(sacco_code);
CREATE INDEX idx_users_phone         ON users(phone);
CREATE INDEX idx_users_member_id     ON users(member_id);
CREATE INDEX idx_refresh_token       ON refresh_tokens(token);
CREATE INDEX idx_refresh_user        ON refresh_tokens(user_id, revoked);
CREATE INDEX idx_audit_user          ON auth_audit_logs(user_id);
CREATE INDEX idx_audit_sacco         ON auth_audit_logs(sacco_code, created_at DESC);

-- Seed: default SYSTEM service account (for service-to-service calls)
-- Password: ChangeThisServiceAccountPassword! (must be changed in production)
INSERT INTO users (sacco_code, username, phone, full_name, password_hash, status, must_change_password)
VALUES (
    'SYSTEM',
    'sacco-system',
    '+255000000000',
    'SACCO System Service Account',
    '$2a$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', -- placeholder
    'ACTIVE',
    FALSE
);

INSERT INTO user_roles (user_id, role)
SELECT id, 'SYSTEM' FROM users WHERE username = 'sacco-system';
