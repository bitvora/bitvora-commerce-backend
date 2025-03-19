CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE subscriptions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    account_id UUID NOT NULL REFERENCES accounts(id),
    customer_id UUID NOT NULL REFERENCES customers(id),
    product_id UUID NOT NULL REFERENCES products(id),
    billing_start_date TIMESTAMP NOT NULL,
    active_on_date TIMESTAMP NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    next_billing_date TIMESTAMP NOT NULL,
    last_payment_date TIMESTAMP,
    last_payment_status VARCHAR(50),
    failed_payment_attempts INT DEFAULT 0,
    billing_interval_hours INT,
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
CREATE INDEX subscriptions_next_billing_date_idx ON subscriptions(next_billing_date);
CREATE INDEX subscriptions_status_idx ON subscriptions(status); 