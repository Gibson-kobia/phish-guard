# PhishGuard Multi-Tenant Deployment Architecture

## 1. Overview & Trust Model

PhishGuard provides enterprise-grade, privacy-first phishing and typosquatting protection across distributed employee endpoints. The architecture connects thousands of browser extension instances to a central management service while preserving complete organization-level data isolation.

```
+-----------------------------------------------------------------------------------+
|                            Central PhishGuard Backend                             |
|                                                                                   |
|  +--------------------+   +---------------------+   +--------------------------+  |
|  | Multi-Tenant DB    |   | Device Registry &   |   | Canonical Security Event |  |
|  | & Isolation Engine |   | Credentials Service |   | Ingestion Pipeline       |  |
|  +--------------------+   +---------------------+   +--------------------------+  |
|            ^                         ^                           ^                |
+------------|-------------------------|---------------------------|----------------+
             |                         |                           |
             | HTTPS (REST API)        | Device Auth (Bearer Key)  | Async Batch Sync
             v                         v                           v
+------------------------+   +------------------------+   +------------------------+
|   Organization A       |   |   Organization B       |   |   Organization C       |
|  +------------------+  |   |  +------------------+  |   |  +------------------+  |
|  | Device A1 (Chrome)|  |   |  | Device B1 (Chrome)|  |   |  | Device C1 (Chrome)|  |
|  | Local AI Engine  |  |   |  | Local AI Engine  |  |   |  | Local AI Engine  |  |
|  +------------------+  |   |  +------------------+  |   |  +------------------+  |
|  | Device A2 (Chrome)|  |   |  | Device B2 (Chrome)|  |   |  | Device C2 (Chrome)|  |
|  | Local AI Engine  |  |   |  | Local AI Engine  |  |   |  | Local AI Engine  |  |
|  +------------------+  |   |  +------------------+  |   |  +------------------+  |
+------------------------+   +------------------------+   +------------------------+
```

### Core Identities

| Identity | Type | Format | Scope & Purpose |
| :--- | :--- | :--- | :--- |
| **Organization** | `organizationId` | `ORG-XXXX-XXXX` | Primary tenant boundary. All devices, policies, audit logs, and security events belong strictly to one organization. |
| **Device** | `deviceId` | `DEV-XXXX-XXXX` | Stable physical/logical endpoint identity. Registered during enrollment. |
| **Installation** | `installationId` | `inst_<base36>_<random>` | Ephemeral extension instance identifier stored in `chrome.storage.local`. Generated once per installation. |

> **Crucial Rule**: Usernames, corporate email addresses, Active Directory computer names, or public IP addresses are **never** used as primary entity keys.

---

## 2. Secure Enrollment & Credentials Lifecycle

```
[Administrator]                       [PhishGuard Backend]                     [Chrome Extension]
       |                                       |                                        |
       |--- 1. POST /api/orgs/:id/tokens ----->|                                        |
       |    (Generate Enrollment Token)        |                                        |
       |<-- Returns pg_enroll_xxxx ------------|                                        |
       |                                       |                                        |
       |--- 2. Deploy via GPO / Managed Policy ---------------------------------------->|
       |    (PhishGuardApiBaseUrl + Token)     |                                        |
       |                                       |                                        |
       |                                       |<-- 3. POST /api/devices/enroll --------|
       |                                       |    (Token, installationId, OS, browser)|
       |                                       |                                        |
       |                                       |--- 4. Verify Token Hash & Org -------->|
       |                                       |    Issue Device Credentials           |
       |                                       |    (deviceId, orgId, deviceApiKey)     |
       |                                       |                                        |
       |                                       |    [Persist in chrome.storage.local]   |
       |                                       |                                        |
       |                                       |<-- 5. POST /api/devices/heartbeat -----|
       |                                       |    (Bearer <deviceApiKey>)             |
       |                                       |                                        |
       |                                       |<-- 6. POST /api/events ----------------|
       |                                       |    (Durable queue batch sync)          |
```

### 1. Enrollment Token Generation
- Admin creates a token with a designated label and 30-day expiration.
- The plaintext token (format: `pg_enroll_<32 hex chars>`) is returned once to the administrator.
- The backend computes and stores the **SHA-256 hash** of the token. The plaintext is never stored in the database.

### 2. Device Enrollment (`POST /api/devices/enroll`)
- Extension reads `EnrollmentToken` from `chrome.storage.managed` (or options).
- Extension contacts backend with `enrollmentToken`, `installationId`, `extensionVersion`, `browser`, and `os`.
- Backend validates token hash, verifies organization status (`ACTIVE`), and issues:
  - `deviceId`: Permanent unique device identifier.
  - `deviceApiKey`: High-entropy device secret (`pg_dev_<64 hex chars>`).
  - Active organizational enforcement policy.
- Extension stores `deviceApiKey` in `chrome.storage.local`.

### 3. Server-Side Authoritative Organization Binding
- Server-side authorization **never** trusts client-supplied `organizationId` headers or payload attributes.
- When an event or heartbeat is received, the server validates the `Authorization: Bearer <deviceApiKey>` against registered devices and derives the authoritative `organizationId` from the database.
- Attempts to spoof another organization result in immediate rejection.

---

## 3. Communication Endpoints & Protocols

### Endpoint Matrix

| Method | Path | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | None | Public health check, platform version, and high-level uptime stats. |
| `GET` | `/api/version` | None | Release versions, download links, and minimum supported extension version. |
| `GET` | `/api/config` | Device / None | Active organizational policy for connected endpoints. |
| `POST` | `/api/devices/enroll` | Enrollment Token | Exchanges enrollment token for device credentials. |
| `POST` | `/api/devices/heartbeat` | Device Key | Periodic presence notification (updates `lastSeen` and returns policy). |
| `POST` | `/api/events` | Device Key | Ingests canonical security events from local durable queue. |
| `GET` | `/api/admin/organizations` | Admin Key | Lists all tenant organizations. |
| `POST` | `/api/admin/organizations` | Admin Key | Provisions a new tenant organization. |
| `POST` | `/api/admin/organizations/:id/tokens` | Admin Key | Generates a new enrollment token for a tenant. |
| `POST` | `/api/admin/tokens/:id/revoke` | Admin Key | Immediately revokes an enrollment token. |
| `GET` | `/api/events?organizationId=...` | Admin Key | Scoped query of security events with pagination. |
| `GET` | `/api/devices?organizationId=...` | Admin Key | Scoped query of enrolled devices. |

---

## 4. Privacy & Anonymization Guarantees

PhishGuard is designed with zero-knowledge data minimization principles:

1. **Never Transmitted**:
   - Password fields, PINs, or credential values
   - Credit card numbers, CVVs, expiration dates
   - Keystrokes or form input buffers
   - Session cookies, bearer tokens, or authorization headers
   - Page DOM trees, raw HTML snapshots, or full page source
2. **URL Sanitization**:
   - Before any security event is queued or ingested, all sensitive query parameters (e.g. `token=`, `auth=`, `key=`, `secret=`, `code=`, `access_token=`, `password=`, `session=`, `jwt=`) are stripped and replaced with `[REDACTED]`.
3. **Local Evaluation**:
   - 100% of detection, heuristic evaluation, brand similarity matching, and navigation blocking occurs directly inside the client browser engine. No third-party or server roundtrip is required to decide whether a site is safe.

---

## 5. Offline & Resilience Guarantees

- **Local-First Protection**: Even if the corporate network is offline or the PhishGuard central server is unreachable, the extension continues to intercept malicious URLs and block phishing attacks with 0ms added latency.
- **Durable Local Queue**: Security events are recorded in a bounded local storage queue (maximum 500 events).
- **Exponential Backoff**: When the server is unreachable, the synchronization worker backs off exponentially without spamming the network or causing CPU spikes.
- **Safe Asynchronous Execution**: All telemetry synchronization runs in isolated asynchronous promises wrapped in safety boundaries so that service worker tasks never crash or unhandle exceptions.
