# PhishGuard Production Deployment Guide

This guide covers deploying the full-stack PhishGuard platform to **Vercel** (Cloud Backend & Admin Console), **Supabase** (PostgreSQL Database), and **Google Chrome** (MV3 Client Extension Fleet).

---

## Architecture Flow

```
┌─────────────────────────┐          ┌─────────────────────────┐
│ Chrome Fleet Endpoints  │          │ Security Admin Console  │
│ (MV3 Extension)         │          │ (Web Dashboard)         │
└────────────┬────────────┘          └────────────┬────────────┘
             │ (Device Auth & Batch Sync)         │ (Admin Auth)
             ▼                                    ▼
┌──────────────────────────────────────────────────────────────┐
│ Vercel Serverless Backend / Node Express Container           │
│ - POST /api/devices/enroll (Token exchange -> Device Key)    │
│ - POST /api/devices/heartbeat (Status & Policy pull)         │
│ - POST /api/events (Sanitized Telemetry Ingestion)           │
│ - GET  /api/overview, /api/devices, /api/events (Admin APIs) │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ Supabase PostgreSQL Database                                 │
│ (Multi-Tenant Isolated Schema + Indexes + Audit Trail)       │
└──────────────────────────────────────────────────────────────┘
```

---

## 1. Database Setup (Supabase)

Follow `docs/SUPABASE_SETUP.md`:
1. Create project on [Supabase](https://supabase.com).
2. Run `supabase/migrations/001_initial_schema.sql` in SQL Editor.
3. Obtain `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`.

---

## 2. Backend & Console Deployment (Vercel)

### Option A: Vercel CLI
```bash
# 1. Install Vercel CLI
npm i -g vercel

# 2. Deploy to production
vercel --prod
```

### Option B: Vercel Web Dashboard (GitHub Import)
1. Push this repository to GitHub.
2. Link the repository in the Vercel Dashboard.
3. Configure the **Environment Variables** in Vercel Project Settings:
   - `SUPABASE_URL`: `https://your-project.supabase.co`
   - `SUPABASE_SERVICE_ROLE_KEY`: `<your_service_role_key>`
   - `PHISHGUARD_ADMIN_API_KEY`: `<secure_random_admin_key>`
   - `PHISHGUARD_API_BASE_URL`: `https://your-app-name.vercel.app`
4. Click **Deploy**.

The Vercel configuration routes `/api/*` to `api/index.ts` and serves the compiled Vite dashboard at `/`.

---

## 3. Extension Fleet Deployment (Chrome MV3)

### Step 1: Build the Extension Package
```bash
npm run package:extension
```
This produces `dist-extension/` and a deployable zip in `dist-extension/phishguard-extension-v1.0.0.zip`.

### Step 2: Enterprise MDM / GPO Policy Configuration
Deploy the extension via Google Admin Console or Microsoft Intune using Chrome Enterprise Policy:

#### Chrome Managed Storage Schema (`extension/schema.json`):
```json
{
  "PhishGuardApiBaseUrl": "https://your-phishguard-backend.vercel.app",
  "EnrollmentToken": "pg_enroll_acme_pilot_2026",
  "EnforcementMode": "BLOCK",
  "TelemetryEnabled": true
}
```

### Step 3: Zero-Touch Client Enrollment
When the user opens Google Chrome:
1. The background service worker reads the managed policy.
2. The client checks local storage for an existing `deviceApiKey`.
3. If not enrolled, it calls `POST /api/devices/enroll` with the `EnrollmentToken` and a generated `installationId`.
4. The server validates the token, issues a unique `deviceId` (`DEV-XXXX`) and secret `deviceApiKey` (`pg_dev_...`), and records the device.
5. The extension stores the key securely in `chrome.storage.local` and starts background heartbeats and queue synchronization.

---

## 4. Verification Checklist

1. [ ] Backend Health: `curl -s https://your-app-name.vercel.app/api/health | jq`
2. [ ] Admin Login: Access `https://your-app-name.vercel.app/` with Admin Key.
3. [ ] Fleet Ingestion: Verify enrolled endpoints show `ONLINE` status in the Fleet table.
4. [ ] Incident Inception: Navigate to test simulation page, trigger a blocked event, verify real-time appearance in the Security Dashboard.
