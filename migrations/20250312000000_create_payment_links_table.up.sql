CREATE TABLE IF NOT EXISTS payment_links (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    account_id UUID NOT NULL REFERENCES accounts(id),
    product_id UUID REFERENCES products(id),
    amount FLOAT NOT NULL,
    currency VARCHAR(10) NOT NULL,
    metadata JSONB,
    items JSONB,
    expiry_minutes INT NOT NULL DEFAULT 1440,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP
);

CREATE INDEX payment_links_user_id_idx ON payment_links(user_id);
CREATE INDEX payment_links_account_id_idx ON payment_links(account_id); 