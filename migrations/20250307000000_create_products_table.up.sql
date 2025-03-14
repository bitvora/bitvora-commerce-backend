CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE products (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    account_id UUID NOT NULL REFERENCES accounts(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    image VARCHAR(255),
    is_recurring BOOLEAN NOT NULL DEFAULT FALSE,
    amount DECIMAL(10, 2) NOT NULL, -- Price amount
    currency VARCHAR(10) NOT NULL,  -- Currency code (fiat or crypto)
    billing_period_hours INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX products_user_id_idx ON products(user_id);
CREATE INDEX products_account_id_idx ON products(account_id); 