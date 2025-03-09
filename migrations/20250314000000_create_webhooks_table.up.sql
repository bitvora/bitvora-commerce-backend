CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    account_id UUID NOT NULL REFERENCES accounts(id),
    url TEXT NOT NULL,
    description TEXT,
    secret TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    events JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP
);

CREATE INDEX webhooks_user_id_idx ON webhooks(user_id);
CREATE INDEX webhooks_account_id_idx ON webhooks(account_id); 