-- ==============================================================================
-- PhishGuard Production Schema Migration 004
-- Centralized Serverless Session Revocation Table
-- ==============================================================================

-- Minimal session revocation table:
-- Stores only the cryptographic SHA-256 hash of the token, expiration, and tenant metadata.
-- Raw session tokens are never persisted.
CREATE TABLE IF NOT EXISTS revoked_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT,
    organization_id TEXT,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Index on expires_at for efficient opportunistic cleanup and ignoring expired records
CREATE INDEX IF NOT EXISTS idx_revoked_sessions_expires_at ON revoked_sessions (expires_at);

-- Index on organization_id for multi-tenant isolation and security audit queries
CREATE INDEX IF NOT EXISTS idx_revoked_sessions_org ON revoked_sessions (organization_id);

-- Enable Row Level Security
ALTER TABLE revoked_sessions ENABLE ROW LEVEL SECURITY;

-- Deny all direct anonymous or client-authenticated access (API access only via backend)
REVOKE ALL ON TABLE revoked_sessions FROM anon, authenticated;

-- Grant operational permissions exclusively to the backend service_role
GRANT ALL ON TABLE revoked_sessions TO service_role;

CREATE POLICY "Backend service_role full access on revoked_sessions"
    ON revoked_sessions FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);
