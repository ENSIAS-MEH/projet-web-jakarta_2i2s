-- V12__create_webhook_subscription.sql
-- Part IV §webhook_subscription (V12)
-- v2 pre-positioning: no application code references this table in v1.
-- ON DELETE CASCADE on owner_id per Part II §F and Part IV §ON DELETE Cascade Policy.

CREATE TABLE webhook_subscription (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id              UUID NOT NULL REFERENCES secbret_user(id) ON DELETE CASCADE,
    callback_url          VARCHAR(2048) NOT NULL,
    signing_secret_enc    VARCHAR(512)  NOT NULL,
    event_types           VARCHAR(50)[] NOT NULL,
    is_active             BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMP     NOT NULL DEFAULT NOW(),
    last_delivery_at      TIMESTAMP,
    last_delivery_status  INTEGER,

    CONSTRAINT chk_event_types       CHECK (array_length(event_types, 1) >= 1),
    CONSTRAINT chk_delivery_status   CHECK (last_delivery_status IS NULL
        OR (last_delivery_status >= 100 AND last_delivery_status <= 599))
);

CREATE INDEX idx_webhook_subscription_owner  ON webhook_subscription (owner_id);
CREATE INDEX idx_webhook_subscription_active ON webhook_subscription (is_active) WHERE is_active = TRUE;
