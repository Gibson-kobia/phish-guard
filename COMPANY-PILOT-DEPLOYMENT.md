# PhishGuard Company Pilot Deployment Runbook

This runbook guides security teams through enrolling and verifying the first real company pilot on the PhishGuard platform.

## Pilot Target Milestone

```
[ Central Backend ] ──> [ 1 Organization (Acme Corp) ] ──> [ 1 Real Endpoint (Chrome) ]
                                                                       │
                                                         Navigates to phishing test URL
                                                                       │
                                                          [ Instant Local Block ]
                                                                       │
                                                       [ Anonymized Event Sync ]
                                                                       │
                                                          [ Visible on Console ]
```

---

## Step 1: Deploy & Start the Central Backend

1. **Configure Environment Variables**:
   Copy `.env.example` to `.env`:
   ```bash
   PHISHGUARD_API_BASE_URL="http://localhost:3000"
   PHISHGUARD_ADMIN_API_KEY="pg_adm_live_pilot_secret_key"
   PORT=3000
   ```

2. **Launch the Service**:
   ```bash
   npm run build
   npm start
   ```

3. **Verify Backend Health**:
   ```bash
   curl -s http://localhost:3000/api/health | jq .
   ```
   *Expected Response:*
   ```json
   {
     "status": "ok",
     "service": "PhishGuard Central Enterprise Security Platform",
     "version": "1.0.0",
     "environment": "production"
   }
   ```

---

## Step 2: Provision Tenant Organization & Token

1. **Create the Organization (if not pre-seeded)**:
   ```bash
   curl -X POST http://localhost:3000/api/organizations \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer pg_adm_live_pilot_secret_key" \
     -d '{
       "name": "Acme Corporation",
       "domain": "acmepilot.com",
       "enforcementMode": "BLOCK",
       "telemetryEnabled": true
     }'
   ```

2. **Generate an Enrollment Token**:
   ```bash
   curl -X POST http://localhost:3000/api/organizations/ORG-ACME-PILOT/tokens \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer pg_adm_live_pilot_secret_key" \
     -d '{
       "label": "Acme Pilot Fleet Wave 1",
       "expiresInDays": 30
     }'
   ```
   *Note the returned token (e.g., `pg_enroll_...`). The backend stores only the SHA-256 hash.*

---

## Step 3: Deploy Extension to Fleet Endpoints

### Option A: Google Workspace / Chrome Browser Cloud Management
In Google Admin Console under **Devices > Chrome > Apps & extensions**:
1. Add the PhishGuard extension ID.
2. Under **Policy for extensions**, upload or enter the JSON configuration:
   ```json
   {
     "PhishGuardApiBaseUrl": {
       "Value": "http://localhost:3000"
     },
     "EnrollmentToken": {
       "Value": "pg_enroll_acme_pilot_2026"
     },
     "EnforcementMode": {
       "Value": "BLOCK"
     },
     "TelemetryEnabled": {
       "Value": true
     }
   }
   ```

### Option B: Windows Active Directory Group Policy (GPO)
Add registry keys under `HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome\3rdparty\extensions\<EXTENSION_ID>\policy`:
- `PhishGuardApiBaseUrl` (String): `http://localhost:3000`
- `EnrollmentToken` (String): `pg_enroll_acme_pilot_2026`
- `EnforcementMode` (String): `BLOCK`

---

## Step 4: End-to-End Acceptance Verification

Execute this 5-point verification procedure:

### 1. Device Enrollment Verification
When Chrome launches, the extension registers automatically:
```bash
curl -s "http://localhost:3000/api/devices?organizationId=ORG-ACME-PILOT" \
  -H "Authorization: Bearer pg_adm_live_pilot_secret_key" | jq .
```
Verify the device appears with:
- `status`: `"ONLINE"`
- `organizationId`: `"ORG-ACME-PILOT"`
- `extensionVersion`: `"1.0.0"`

### 2. Device Heartbeat Verification
```bash
curl -X POST http://localhost:3000/api/devices/heartbeat \
  -H "Content-Type: application/json" \
  -H "X-PhishGuard-Org": "ORG-ACME-PILOT" \
  -d '{
    "deviceId": "DEV-PILOT-01",
    "installationId": "inst_pilot_01",
    "browser": "Chrome 128.0",
    "os": "macOS"
  }'
```
*Expected Result:* Returns `{ "success": true, "enforcementMode": "BLOCK" }`.

### 3. Real Navigation Blocking
1. On the enrolled endpoint, navigate in Chrome to a high-risk typosquatting or phishing destination (e.g. `http://paypa1-security-verification.com/login`).
2. **Behavior**: Navigation is terminated immediately before any form rendering. The PhishGuard Warning Screen is shown explaining the detected threat (`LOOKALIKE_DOMAIN` / `SUSPICIOUS_TOKEN`).

### 4. Canonical Event Ingestion & Scoping
Query the security events for the organization:
```bash
curl -s "http://localhost:3000/api/events?organizationId=ORG-ACME-PILOT" \
  -H "Authorization: Bearer pg_adm_live_pilot_secret_key" | jq .
```
Confirm the event contains:
- `action`: `"BLOCKED"`
- `navigationBlocked`: `true`
- `targetDomain`: `"paypa1-security-verification.com"`
- `organizationId`: `"ORG-ACME-PILOT"`
- Sensitive query parameters are sanitized.

### 5. Multi-Tenant Isolation Check
Query events for a different organization (e.g., `ORG-OTHER-TENANT`):
```bash
curl -s "http://localhost:3000/api/events?organizationId=ORG-OTHER-TENANT" \
  -H "Authorization: Bearer pg_adm_live_pilot_secret_key" | jq .
```
*Expected Result:* Returns `{ "events": [], "total": 0 }`. Zero cross-tenant leakage.

---

## Step 5: Pilot Monitoring & Reporting

1. **Open Security Console**:
   Navigate to `http://localhost:3000` to inspect:
   - **Overview Tab**: Live threat counter, active endpoints, top targeted brands.
   - **Security Events Tab**: Interactive timeline of blocked attacks with drill-down explanations.
   - **Fleet Devices Tab**: Endpoint version compliance and last-seen telemetry.
   - **Reports & CSV Tab**: One-click download of compliance audit data.
