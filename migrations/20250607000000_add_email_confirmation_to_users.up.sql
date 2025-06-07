ALTER TABLE users 
ADD COLUMN email_confirmation_token VARCHAR(255),
ADD COLUMN email_confirmed_at TIMESTAMP;

-- Add index for faster lookups on confirmation token
CREATE INDEX idx_users_email_confirmation_token ON users(email_confirmation_token); 