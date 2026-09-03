-- Migration 003: Add password_hash column and support for INDIVIDUAL role

ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS api_key TEXT;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS plan TEXT;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS plan_status TEXT;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS billing_interval TEXT;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS devices_limit INTEGER;

-- Make api_key_hash nullable if it was NOT NULL in 001
ALTER TABLE admin_users ALTER COLUMN api_key_hash DROP NOT NULL;

-- Ensure role constraint allows INDIVIDUAL
ALTER TABLE admin_users DROP CONSTRAINT IF EXISTS admin_users_role_check;
ALTER TABLE admin_users ADD CONSTRAINT admin_users_role_check CHECK (role IN ('SUPER_ADMIN', 'ORG_ADMIN', 'READ_ONLY', 'INDIVIDUAL'));

