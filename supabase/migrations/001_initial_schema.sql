-- ==============================================================================
-- PhishGuard Production Schema Migration 001
-- PostgreSQL / Supabase Schema for Multi-Tenant Browser Security Platform
-- ==============================================================================

-- Enable UUID extension if not enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==============================================================================
-- 1. ORGANIZATIONS (Multi-Tenant Isolation Root)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    domain TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'TRIAL', 'DECOMMISSIONED')),
    enforcement_mode TEXT NOT NULL DEFAULT 'BLOCK' CHECK (enforcement_mode IN ('BLOCK', 'WARN', 'MONITOR')),
    telemetry_enabled BOOLEAN NOT NULL DEFAULT true,
    min_extension_version TEXT NOT NULL DEFAULT '1.0.0',
    retention_days INTEGER NOT NULL DEFAULT 90,
    backend_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 2. ENROLLMENT TOKENS (Cryptographically Hashed Fleet Registration Secrets)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT 'Fleet Deployment Token',
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
    max_uses INTEGER,
    use_count INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 3. DEVICES (Enrolled Corporate Endpoints)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    installation_id TEXT NOT NULL,
    device_api_key_hash TEXT NOT NULL UNIQUE,
    device_name TEXT,
    extension_version TEXT NOT NULL DEFAULT '1.0.0',
    browser TEXT,
    os TEXT,
    platform TEXT,
    ip TEXT,
    status TEXT NOT NULL DEFAULT 'HEALTHY' CHECK (status IN ('HEALTHY', 'UPDATE_REQUIRED', 'OFFLINE', 'REVOKED')),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_org_installation UNIQUE (organization_id, installation_id)
);

-- ==============================================================================
-- 4. SECURITY EVENTS (Anonymized, Sanitized Telemetry Ingestion)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'NAVIGATION_BLOCKED',
        'WARNING_DISPLAYED',
        'WARNING_OVERRIDDEN',
        'SUSPICIOUS_OBSERVATION',
        'DOWNLOAD_BLOCKED',
        'FORM_THREAT_INTERCEPTED'
    )),
    url TEXT NOT NULL,
    hostname TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    action TEXT NOT NULL CHECK (action IN ('BLOCKED', 'WARNED', 'OVERRIDDEN', 'LOGGED')),
    threat_category TEXT NOT NULL CHECK (threat_category IN (
        'BRAND_IMPERSONATION',
        'CREDENTIAL_HARVESTING',
        'MALICIOUS_DOWNLOAD',
        'ZERO_DAY_SUSPICIOUS',
        'OTHER'
    )),
    detection_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    signals JSONB NOT NULL DEFAULT '[]'::jsonb,
    navigation_blocked BOOLEAN NOT NULL DEFAULT false,
    user_override BOOLEAN NOT NULL DEFAULT false,
    source TEXT NOT NULL DEFAULT 'CLIENT_EXTENSION',
    extension_version TEXT NOT NULL DEFAULT '1.0.0',
    tab_id INTEGER,
    timestamp BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 5. ADMIN USERS (Dashboard & Tenant Management Credentials)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS admin_users (
    id TEXT PRIMARY KEY,
    organization_id TEXT REFERENCES organizations(id) ON DELETE CASCADE,
    username TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'ORG_ADMIN' CHECK (role IN ('SUPER_ADMIN', 'ORG_ADMIN', 'READ_ONLY')),
    api_key_hash TEXT NOT NULL UNIQUE,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 6. AUDIT LOGS (Security Governance & Operations Trail)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    organization_id TEXT REFERENCES organizations(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    timestamp BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- PERFORMANCE INDEXES
-- ==============================================================================
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_org ON enrollment_tokens(organization_id);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_hash ON enrollment_tokens(token_hash);

CREATE INDEX IF NOT EXISTS idx_devices_org ON devices(organization_id);
CREATE INDEX IF NOT EXISTS idx_devices_key_hash ON devices(device_api_key_hash);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_devices_installation ON devices(installation_id);

CREATE INDEX IF NOT EXISTS idx_events_org ON security_events(organization_id);
CREATE INDEX IF NOT EXISTS idx_events_device ON security_events(device_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_risk_level ON security_events(organization_id, risk_level);
CREATE INDEX IF NOT EXISTS idx_events_threat_category ON security_events(organization_id, threat_category);

CREATE INDEX IF NOT EXISTS idx_admin_users_org ON admin_users(organization_id);
CREATE INDEX IF NOT EXISTS idx_admin_users_key_hash ON admin_users(api_key_hash);

CREATE INDEX IF NOT EXISTS idx_audit_logs_org ON audit_logs(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);

-- ==============================================================================
-- AUTOMATIC TIMESTAMP TRIGGER
-- ==============================================================================
CREATE OR REPLACE FUNCTION update_timestamp_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_organizations_updated_at ON organizations;
CREATE TRIGGER trg_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp_column();

DROP TRIGGER IF EXISTS trg_devices_updated_at ON devices;
CREATE TRIGGER trg_devices_updated_at
    BEFORE UPDATE ON devices
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp_column();

DROP TRIGGER IF EXISTS trg_admin_users_updated_at ON admin_users;
CREATE TRIGGER trg_admin_users_updated_at
    BEFORE UPDATE ON admin_users
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp_column();

-- ==============================================================================
-- SEED INITIAL PILOT ORGANIZATION
-- ==============================================================================
INSERT INTO organizations (
    id,
    name,
    domain,
    status,
    enforcement_mode,
    telemetry_enabled,
    min_extension_version,
    retention_days
) VALUES (
    'ORG-ACME-PILOT',
    'Acme Corporation',
    'acme.com',
    'ACTIVE',
    'BLOCK',
    true,
    '1.0.0',
    90
) ON CONFLICT (id) DO NOTHING;

-- SHA-256 for pilot token 'pg_enroll_acme_pilot_2026'
-- echo -n "pg_enroll_acme_pilot_2026" | sha256sum -> 245f78cbb454f762dd76d3a82414771c504a794cb178bf71bfce6218d6a6ef41
INSERT INTO enrollment_tokens (
    id,
    organization_id,
    token_hash,
    label,
    status,
    max_uses,
    use_count
) VALUES (
    'tok_acme_pilot_initial',
    'ORG-ACME-PILOT',
    '245f78cbb454f762dd76d3a82414771c504a794cb178bf71bfce6218d6a6ef41',
    'Acme Company Pilot Deployment Token',
    'ACTIVE',
    NULL,
    0
) ON CONFLICT (token_hash) DO NOTHING;
