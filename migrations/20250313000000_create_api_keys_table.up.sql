CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    account_id UUID NOT NULL REFERENCES accounts(id),
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    permissions JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    deleted_at TIMESTAMP,
    locked_at TIMESTAMP
);

CREATE INDEX api_keys_user_id_idx ON api_keys(user_id);
CREATE INDEX api_keys_account_id_idx ON api_keys(account_id);
CREATE INDEX api_keys_token_hash_idx ON api_keys(token_hash); 