CREATE TABLE wallet_connections (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    account_id UUID NOT NULL REFERENCES accounts(id),
    nostr_pubkey VARCHAR(255) NOT NULL,
    nostr_secret VARCHAR(255) NOT NULL,
    nostr_relay VARCHAR(255) NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expired_at TIMESTAMP,
    deleted_at TIMESTAMP,
    methods JSONB DEFAULT '[]'
);

CREATE INDEX wallet_connections_user_id_idx ON wallet_connections(user_id);
CREATE INDEX wallet_connections_account_id_idx ON wallet_connections(account_id); 