-- V1__create_secbret_user.sql
-- Part IV §secbret_user

CREATE TABLE secbret_user (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(50)  NOT NULL UNIQUE,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(20)  NOT NULL DEFAULT 'REPORTER',
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMP,
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP    NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_user_role CHECK (role IN ('REPORTER', 'ANALYST', 'ADMIN'))
);

CREATE INDEX idx_user_username ON secbret_user (username);
CREATE INDEX idx_user_email    ON secbret_user (email);
CREATE INDEX idx_user_role     ON secbret_user (role);
CREATE INDEX idx_user_locked_until ON secbret_user (locked_until) WHERE locked_until IS NOT NULL;
