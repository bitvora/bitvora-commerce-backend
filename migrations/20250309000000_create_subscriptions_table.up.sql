CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE subscriptions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    account_id UUID NOT NULL REFERENCES accounts(id),
    customer_id UUID NOT NULL REFERENCES customers(id),
    product_id UUID NOT NULL REFERENCES products(id),
    billing_start_date TIMESTAMP NOT NULL,
    active_on_date TIMESTAMP NOT NULL,
    metadata JSONB,
    nostr_relay VARCHAR(255),
    nostr_pubkey VARCHAR(255),
    nostr_secret VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX subscriptions_user_id_idx ON subscriptions(user_id);
CREATE INDEX subscriptions_account_id_idx ON subscriptions(account_id);
CREATE INDEX subscriptions_customer_id_idx ON subscriptions(customer_id);
CREATE INDEX subscriptions_product_id_idx ON subscriptions(product_id); 