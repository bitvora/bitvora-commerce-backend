DROP INDEX IF EXISTS idx_users_email_confirmation_token;

ALTER TABLE users 
DROP COLUMN IF EXISTS email_confirmation_token,
DROP COLUMN IF EXISTS email_confirmed_at; 