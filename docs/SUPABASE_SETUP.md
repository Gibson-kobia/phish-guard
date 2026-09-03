# PhishGuard Supabase Database Setup Guide

This guide walks you through provisioning, initializing, and connecting a production Supabase PostgreSQL instance for the PhishGuard Browser Security Platform.

---

## Architecture Overview

PhishGuard utilizes PostgreSQL on Supabase to provide:
- **Strict Multi-Tenant Isolation**: Organizations, devices, tokens, events, and audit trails partitioned cleanly by `organization_id`.
- **Cryptographically Hashed Credentials**: Enrollment tokens and device API keys are stored only as SHA-256 hashes (`token_hash`, `device_api_key_hash`).
- **Sanitized Telemetry Persistence**: High-throughput indexing on `(organization_id, timestamp DESC)` and `(organization_id, threat_category)`.

---

## Step 1: Create a Supabase Project

1. Navigate to [https://supabase.com](https://supabase.com) and sign in.
2. Click **"New Project"**.
3. Set your project settings:
   - **Name**: `phishguard-production` (or your company name)
   - **Database Password**: Generate and securely store a strong password.
   - **Region**: Select the region closest to your enterprise workforce (e.g. `us-east-1` or `eu-central-1`).
4. Click **"Create new project"** and wait ~2 minutes for provisioning to complete.

---

## Step 2: Execute Database Migration

1. In your Supabase dashboard, click the **SQL Editor** tab in the left sidebar (icon with `>_`).
2. Click **"New Query"**.
3. Copy the entire contents of `supabase/migrations/001_initial_schema.sql` from this repository.
4. Paste the SQL into the editor and click **"Run"** (or press `Ctrl+Enter` / `Cmd+Enter`).
5. Verify in the **Table Editor** that the following tables are created:
   - `organizations`
   - `enrollment_tokens`
   - `devices`
   - `security_events`
   - `admin_users`
   - `audit_logs`

---

## Step 3: Retrieve API Credentials

1. In your Supabase project, go to **Project Settings** (gear icon) -> **API**.
2. Note the following values:
   - **Project URL** (e.g. `https://abcdefghijklm.supabase.co`)
   - **Project API Keys**:
     - `anon` `public` key (client-safe)
     - `service_role` `secret` key (**CRITICAL**: Use this for the backend server, as it bypasses RLS for administrative operations).

---

## Step 4: Configure Backend Environment Variables

In your deployment environment (Vercel, Cloud Run, or `.env`), add:

```env
# Supabase PostgreSQL Configuration
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_SERVICE_ROLE_KEY=eyJh...your_service_role_key

# Admin & Fleet Configuration
PHISHGUARD_ADMIN_API_KEY=pg_admin_secops_prod_2026_change_me
PHISHGUARD_API_BASE_URL=https://your-phishguard-backend.vercel.app
```

---

## Step 5: Verification

Run the test suite or test health endpoint to confirm live connectivity:

```bash
npm test
```

When connected to Supabase, the server logs:
```
🔌 [PhishGuard Database] Initializing Supabase PostgreSQL Adapter...
✅ [Supabase Adapter] Connected to Supabase PostgreSQL successfully
```

---

## Schema Reference & Foreign Key Map

```
organizations (id)
  ├── enrollment_tokens (organization_id -> organizations.id)
  ├── devices (organization_id -> organizations.id)
  │     └── unique(organization_id, installation_id)
  ├── security_events (organization_id -> organizations.id)
  └── audit_logs (organization_id -> organizations.id)
```
