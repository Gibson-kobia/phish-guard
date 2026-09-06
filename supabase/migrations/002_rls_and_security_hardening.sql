-- ==============================================================================
-- PhishGuard Production Schema Migration 002
-- Row Level Security (RLS) & Defense-in-Depth Hardening
-- ==============================================================================

-- 1. Enable Row Level Security on all core tables
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- 2. Revoke public/anonymous API direct access
-- All browser clients and extension endpoints communicate solely via the Vercel API layer.
-- Direct PostgREST access from unauthenticated anon/authenticated clients is explicitly denied.
REVOKE ALL ON TABLE organizations FROM anon, authenticated;
REVOKE ALL ON TABLE enrollment_tokens FROM anon, authenticated;
REVOKE ALL ON TABLE devices FROM anon, authenticated;
REVOKE ALL ON TABLE security_events FROM anon, authenticated;
REVOKE ALL ON TABLE admin_users FROM anon, authenticated;
REVOKE ALL ON TABLE audit_logs FROM anon, authenticated;

-- 3. Grant full operational permissions exclusively to the backend service_role
GRANT ALL ON TABLE organizations TO service_role;
GRANT ALL ON TABLE enrollment_tokens TO service_role;
GRANT ALL ON TABLE devices TO service_role;
GRANT ALL ON TABLE security_events TO service_role;
GRANT ALL ON TABLE admin_users TO service_role;
GRANT ALL ON TABLE audit_logs TO service_role;

-- 4. Service Role Policies (Allows backend queries while blocking public direct reads)
CREATE POLICY "Backend service_role full access on organizations"
    ON organizations FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Backend service_role full access on enrollment_tokens"
    ON enrollment_tokens FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Backend service_role full access on devices"
    ON devices FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Backend service_role full access on security_events"
    ON security_events FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Backend service_role full access on admin_users"
    ON admin_users FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Backend service_role full access on audit_logs"
    ON audit_logs FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);
