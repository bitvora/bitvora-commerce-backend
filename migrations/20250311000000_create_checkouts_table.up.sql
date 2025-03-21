CREATE TABLE checkouts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    account_id UUID NOT NULL REFERENCES accounts(id),
    customer_id UUID REFERENCES customers(id),
    subscription_id UUID REFERENCES subscriptions(id),
    product_id UUID REFERENCES products(id),
    type VARCHAR(50) NOT NULL DEFAULT 'single',
    state VARCHAR(50) NOT NULL DEFAULT 'open',
    amount BIGINT NOT NULL,
    received_amount BIGINT DEFAULT 0,
    lightning_invoice TEXT,
    bitcoin_address TEXT,
    redirect_url TEXT,
    metadata JSONB,
    items JSONB,
    rates JSONB,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX checkouts_user_id_idx ON checkouts(user_id);
CREATE INDEX checkouts_account_id_idx ON checkouts(account_id);
CREATE INDEX checkouts_customer_id_idx ON checkouts(customer_id);
CREATE INDEX checkouts_subscription_id_idx ON checkouts(subscription_id);
CREATE INDEX checkouts_product_id_idx ON checkouts(product_id);
CREATE INDEX checkouts_type_idx ON checkouts(type);
CREATE INDEX checkouts_state_idx ON checkouts(state);
CREATE INDEX checkouts_expires_at_idx ON checkouts(expires_at); 