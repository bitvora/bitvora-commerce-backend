CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY,
    webhook_id UUID NOT NULL REFERENCES webhooks(id),
    event_type TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('successful', 'pending', 'failed')),
    request_payload JSONB NOT NULL,
    response_body TEXT,
    response_status_code INTEGER,
    duration_ms INTEGER,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE INDEX webhook_deliveries_webhook_id_idx ON webhook_deliveries(webhook_id);
CREATE INDEX webhook_deliveries_status_idx ON webhook_deliveries(status);
CREATE INDEX webhook_deliveries_created_at_idx ON webhook_deliveries(created_at); 