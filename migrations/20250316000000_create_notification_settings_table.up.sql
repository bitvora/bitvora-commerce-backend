CREATE TABLE IF NOT EXISTS notification_settings (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    account_id UUID NOT NULL REFERENCES accounts(id),
    channel_type VARCHAR(50) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    events JSONB NOT NULL,
    email VARCHAR(255),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP
);

CREATE UNIQUE INDEX notification_settings_account_channel_idx ON notification_settings(account_id, channel_type) WHERE deleted_at IS NULL;
CREATE INDEX notification_settings_user_id_idx ON notification_settings(user_id);
CREATE INDEX notification_settings_account_id_idx ON notification_settings(account_id); 