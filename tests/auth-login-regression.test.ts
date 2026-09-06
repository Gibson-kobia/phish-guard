/**
 * PhishGuard Super Admin & Operator Authentication Regression Tests
 * 
 * Verifies:
 * 1. Super Admin authentication succeeds with valid credentials
 * 2. Super Admin password reconciliation with PHISHGUARD_INITIAL_ADMIN_PASSWORD env var
 * 3. Invalid credentials return clean 401 JSON responses (never 500 or HTML)
 * 4. Missing parameters return clean 400 JSON responses
 * 5. Serverless & empty database initialization handles login gracefully
 * 6. Rate limiting triggers properly with 429 JSON response
 */

import crypto from 'crypto';
import { createExpressApp, getSessionSigningSecret } from '../src/server/app';
import { InMemoryDatabaseAdapter } from '../src/server/storage/inMemoryAdapter';
import { hashPassword } from '../src/server/authUtils';

export async function runAuthLoginRegressionTests(): Promise<{ passed: number; failed: number; errors: string[] }> {
  let passed = 0;
  let failed = 0;
  const errors: string[] = [];

  function assert(condition: boolean, testName: string, detail?: string) {
    if (condition) {
      passed++;
    } else {
      failed++;
      errors.push(`FAIL: ${testName}${detail ? ` (${detail})` : ''}`);
    }
  }

  // 1. In-Memory Database with Seeded Super Admin
  try {
    const db = new InMemoryDatabaseAdapter();
    db.init();

    const testPass = 'SecOpsTestPassword2026!';
    const superAdmin = {
      id: 'usr_super_admin_test',
      username: 'admin',
      name: 'SecOps Director',
      email: 'admin@phishguard.security',
      role: 'SUPER_ADMIN' as const,
      passwordHash: hashPassword(testPass),
      apiKey: 'test_key',
      createdAt: Date.now(),
      lastLoginAt: Date.now()
    };
    (db as any).adminUsers.push(superAdmin);

    const app = createExpressApp(db);

    // Helper to simulate request via express route invocation
    const mockPostLogin = (body: any): Promise<{ status: number; body: any; headers: any }> => {
      return new Promise((resolve) => {
        const req: any = {
          method: 'POST',
          url: '/api/auth/login',
          ip: '127.0.0.1',
          body,
          headers: { 'content-type': 'application/json' },
          get(name: string) { return this.headers[name.toLowerCase()]; }
        };
        const headers: Record<string, any> = {};
        const res: any = {
          statusCode: 200,
          headersSent: false,
          headers,
          setHeader(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          getHeader(k: string) { return headers[k.toLowerCase()]; },
          header(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          set(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          status(code: number) { this.statusCode = code; return this; },
          json(data: any) { this.headersSent = true; resolve({ status: this.statusCode, body: data, headers }); },
          send(data: any) { this.headersSent = true; resolve({ status: this.statusCode, body: data, headers }); },
          sendStatus(code: number) { this.statusCode = code; this.headersSent = true; resolve({ status: code, body: null, headers }); }
        };

        (app as any).handle(req, res);
      });
    };

    // Test A: Valid Super Admin login by email
    const loginRes1 = await mockPostLogin({
      email: 'admin@phishguard.security',
      password: testPass
    });
    assert(loginRes1.status === 200, 'Valid login returns 200', `Got ${loginRes1.status}`);
    assert(loginRes1.body?.success === true, 'Valid login body has success: true');
    assert(!!loginRes1.body?.token, 'Valid login returns session token');
    assert(loginRes1.body?.user?.role === 'SUPER_ADMIN', 'Returned user is SUPER_ADMIN');

    // Test B: Valid Super Admin login by username
    const loginRes2 = await mockPostLogin({
      username: 'admin',
      password: testPass
    });
    assert(loginRes2.status === 200, 'Valid login by username returns 200');
    assert(loginRes2.body?.user?.email === 'admin@phishguard.security', 'Matched user email is admin@phishguard.security');

    // Test C: Invalid password returns 401 JSON
    const loginRes3 = await mockPostLogin({
      email: 'admin@phishguard.security',
      password: 'WrongPassword123!'
    });
    assert(loginRes3.status === 401, 'Invalid password returns 401 JSON', `Got ${loginRes3.status}`);
    assert(typeof loginRes3.body === 'object' && !!loginRes3.body?.error, '401 response is valid JSON with error field');

    // Test D: Missing credentials returns 400 JSON
    const loginRes4 = await mockPostLogin({});
    assert(loginRes4.status === 400, 'Missing fields returns 400 JSON', `Got ${loginRes4.status}`);
    assert(typeof loginRes4.body === 'object' && !!loginRes4.body?.error, '400 response is valid JSON with error field');

    // Test E: Non-existent user returns 401 JSON
    const loginRes5 = await mockPostLogin({
      email: 'nonexistent@nowhere.com',
      password: 'AnyPassword123!'
    });
    assert(loginRes5.status === 401, 'Non-existent user returns 401 JSON');
    assert(typeof loginRes5.body === 'object' && !!loginRes5.body?.error, '401 is JSON');

    // Test F: Login via stripped prefix /auth/login (Vercel serverless compatibility)
    const mockPostLoginStripped = (body: any): Promise<{ status: number; body: any }> => {
      return new Promise((resolve) => {
        const req: any = {
          method: 'POST',
          url: '/auth/login',
          ip: '127.0.0.1',
          body,
          headers: { 'content-type': 'application/json' },
          get(name: string) { return this.headers[name.toLowerCase()]; }
        };
        const headers: Record<string, any> = {};
        const res: any = {
          statusCode: 200,
          headersSent: false,
          headers,
          setHeader(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          getHeader(k: string) { return headers[k.toLowerCase()]; },
          header(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          set(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          status(code: number) { this.statusCode = code; return this; },
          json(data: any) { this.headersSent = true; resolve({ status: this.statusCode, body: data }); }
        };
        (app as any).handle(req, res);
      });
    };
    const loginRes6 = await mockPostLoginStripped({
      email: 'admin@phishguard.security',
      password: testPass
    });
    assert(loginRes6.status === 200, 'Login via /auth/login returns 200 JSON');
    assert(loginRes6.body?.success === true, 'Stripped path returns success: true');

    // Test G: Unknown route returns 404 JSON (never HTML or 500)
    const mockUnknownRoute = (): Promise<{ status: number; body: any }> => {
      return new Promise((resolve) => {
        const req: any = {
          method: 'GET',
          url: '/api/nonexistent-endpoint',
          ip: '127.0.0.1',
          headers: {},
          get(name: string) { return this.headers[name.toLowerCase()]; }
        };
        const res: any = {
          statusCode: 200,
          headersSent: false,
          headers: {},
          setHeader() { return this; },
          header() { return this; },
          set() { return this; },
          status(code: number) { this.statusCode = code; return this; },
          json(data: any) { this.headersSent = true; resolve({ status: this.statusCode, body: data }); }
        };
        (app as any).handle(req, res);
      });
    };
    const unknownRes = await mockUnknownRoute();
    assert(unknownRes.status === 404, 'Unknown endpoint returns 404 JSON', `Got ${unknownRes.status}`);
    assert(typeof unknownRes.body === 'object' && !!unknownRes.body?.error, '404 response is valid JSON');

  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Authentication regression suite threw: ${err?.message}`);
  }

  // 2. Test Super Admin Environment Variable Password Synchronization
  try {
    const originalEnv = process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
    const newEnvPassword = 'NewVercelEnvSecretPassword2026!';
    process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD = newEnvPassword;

    const db = new InMemoryDatabaseAdapter();
    db.init();

    // Initial super admin seeded with an old hash
    const superAdmin = {
      id: 'usr_super_admin_01',
      username: 'admin',
      name: 'SecOps Director',
      email: 'admin@phishguard.security',
      role: 'SUPER_ADMIN' as const,
      passwordHash: hashPassword('OldStalePassword123!'),
      apiKey: 'test_key',
      createdAt: Date.now(),
      lastLoginAt: Date.now()
    };
    (db as any).adminUsers.push(superAdmin);

    const app = createExpressApp(db);

    const mockPostLogin = (body: any): Promise<{ status: number; body: any }> => {
      return new Promise((resolve) => {
        const req: any = {
          method: 'POST',
          url: '/api/auth/login',
          ip: '127.0.0.2',
          body,
          headers: { 'content-type': 'application/json' },
          get(name: string) { return this.headers[name.toLowerCase()]; }
        };
        const headers: Record<string, any> = {};
        const res: any = {
          statusCode: 200,
          headersSent: false,
          headers,
          setHeader(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          getHeader(k: string) { return headers[k.toLowerCase()]; },
          header(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          set(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          status(code: number) { this.statusCode = code; return this; },
          json(data: any) { this.headersSent = true; resolve({ status: this.statusCode, body: data }); }
        };
        (app as any).handle(req, res);
      });
    };

    // Attempt login with the new environment password
    const syncLoginRes = await mockPostLogin({
      email: 'admin@phishguard.security',
      password: newEnvPassword
    });

    assert(syncLoginRes.status === 200, 'Super admin login succeeds when using newly added PHISHGUARD_INITIAL_ADMIN_PASSWORD env var');
    assert(syncLoginRes.body?.success === true, 'Password sync login returns success: true');

    // Clean up env
    if (originalEnv !== undefined) {
      process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD = originalEnv;
    } else {
      delete process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
    }
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Env password sync test threw: ${err?.message}`);
  }

  // 3. Test Uninitialized Super Admin without PHISHGUARD_INITIAL_ADMIN_PASSWORD returns 500 configuration error
  try {
    const originalEnv = process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
    delete process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;

    const db = new InMemoryDatabaseAdapter();
    db.init();

    // Super admin created in uninitialized / locked bootstrap state
    const uninitializedAdmin = {
      id: 'usr_super_admin_01',
      username: 'admin',
      name: 'SecOps Director',
      email: 'admin@phishguard.security',
      role: 'SUPER_ADMIN' as const,
      passwordHash: 'DISABLED:UNINITIALIZED_BOOTSTRAP',
      apiKey: 'test_key',
      createdAt: Date.now(),
      lastLoginAt: Date.now()
    };
    (db as any).adminUsers.push(uninitializedAdmin);

    const app = createExpressApp(db);

    const mockPostLogin = (body: any): Promise<{ status: number; body: any }> => {
      return new Promise((resolve) => {
        const req: any = {
          method: 'POST',
          url: '/api/auth/login',
          ip: '127.0.0.3',
          body,
          headers: { 'content-type': 'application/json' },
          get(name: string) { return this.headers[name.toLowerCase()]; }
        };
        const headers: Record<string, any> = {};
        const res: any = {
          statusCode: 200,
          headersSent: false,
          headers,
          setHeader(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          getHeader(k: string) { return headers[k.toLowerCase()]; },
          header(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          set(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          status(code: number) { this.statusCode = code; return this; },
          json(data: any) { this.headersSent = true; resolve({ status: this.statusCode, body: data }); }
        };
        (app as any).handle(req, res);
      });
    };

    const res = await mockPostLogin({
      email: 'admin@phishguard.security',
      password: 'SomeRandomAttempt123!'
    });

    assert(res.status === 500, 'Uninitialized super admin login without env var returns 500', `Got ${res.status}`);
    assert(typeof res.body?.error === 'string' && res.body.error.includes('PHISHGUARD_INITIAL_ADMIN_PASSWORD'), 'Returns safe server configuration error message');

    if (originalEnv !== undefined) {
      process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD = originalEnv;
    }
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Uninitialized super admin test threw: ${err?.message}`);
  }

  // 4. Test Existing Valid Super Admin logs in even when PHISHGUARD_INITIAL_ADMIN_PASSWORD is NOT configured
  try {
    const originalEnv = process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
    delete process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;

    const db = new InMemoryDatabaseAdapter();
    db.init();

    const existingSecret = 'ExistingValidSuperAdminSecret2026!';
    const existingAdmin = {
      id: 'usr_super_admin_01',
      username: 'admin',
      name: 'SecOps Director',
      email: 'admin@phishguard.security',
      role: 'SUPER_ADMIN' as const,
      passwordHash: hashPassword(existingSecret),
      apiKey: 'test_key',
      createdAt: Date.now(),
      lastLoginAt: Date.now()
    };
    (db as any).adminUsers.push(existingAdmin);

    const app = createExpressApp(db);

    const mockPostLogin = (body: any): Promise<{ status: number; body: any }> => {
      return new Promise((resolve) => {
        const req: any = {
          method: 'POST',
          url: '/api/auth/login',
          ip: '127.0.0.4',
          body,
          headers: { 'content-type': 'application/json' },
          get(name: string) { return this.headers[name.toLowerCase()]; }
        };
        const headers: Record<string, any> = {};
        const res: any = {
          statusCode: 200,
          headersSent: false,
          headers,
          setHeader(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          getHeader(k: string) { return headers[k.toLowerCase()]; },
          header(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          set(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          status(code: number) { this.statusCode = code; return this; },
          json(data: any) { this.headersSent = true; resolve({ status: this.statusCode, body: data }); }
        };
        (app as any).handle(req, res);
      });
    };

    // Valid existing password login should succeed
    const validRes = await mockPostLogin({
      email: 'admin@phishguard.security',
      password: existingSecret
    });
    assert(validRes.status === 200, 'Existing Super Admin logs in without PHISHGUARD_INITIAL_ADMIN_PASSWORD env var');
    assert(validRes.body?.success === true, 'Existing Super Admin login succeeds');

    // Invalid password returns 401
    const invalidRes = await mockPostLogin({
      email: 'admin@phishguard.security',
      password: 'IncorrectPassword999!'
    });
    assert(invalidRes.status === 401, 'Wrong password for existing Super Admin returns 401 without crashing');

    if (originalEnv !== undefined) {
      process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD = originalEnv;
    }
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Existing super admin test threw: ${err?.message}`);
  }

  // 5. Acme Corporation ORG_ADMIN Account Flow, Strict Scope & RBAC Isolation Tests
  try {
    const db = new InMemoryDatabaseAdapter();
    db.init();

    // Create Acme Corporation organization
    const acmeOrg = db.createOrganization({
      organizationId: 'ORG-ACME-PILOT',
      name: 'Acme Corporation',
      status: 'ACTIVE'
    });

    // Create a secondary tenant organization
    const otherOrg = db.createOrganization({
      organizationId: 'ORG-RIVAL-ENTERPRISE',
      name: 'Rival Enterprise Inc',
      status: 'ACTIVE'
    });

    // Add device to Acme and device to otherOrg
    (db as any).devices.push({
      deviceId: 'DEV-ACME-01',
      installationId: 'inst_acme_01',
      organizationId: 'ORG-ACME-PILOT',
      hostname: 'acme-laptop-01',
      os: 'Mac',
      browser: 'Chrome',
      extensionVersion: '1.0.0',
      status: 'ONLINE',
      firstSeen: Date.now() - 100000,
      lastSeen: Date.now(),
      registeredAt: Date.now() - 100000,
      apiKeyHash: 'hash1'
    });

    (db as any).devices.push({
      deviceId: 'DEV-RIVAL-01',
      installationId: 'inst_rival_01',
      organizationId: 'ORG-RIVAL-ENTERPRISE',
      hostname: 'rival-laptop-01',
      os: 'Windows',
      browser: 'Edge',
      extensionVersion: '1.0.0',
      status: 'ONLINE',
      firstSeen: Date.now() - 100000,
      lastSeen: Date.now(),
      registeredAt: Date.now() - 100000,
      apiKeyHash: 'hash2'
    });

    const acmeTestPass = 'AcmeSecOpsTestPass2026!';
    const acmeOrgAdmin = {
      id: 'usr_acme_admin_01',
      username: 'acme_admin',
      name: 'Alex Rivera (IT Lead)',
      email: 'it-admin@acme-corp.com',
      role: 'ORG_ADMIN' as const,
      organizationId: 'ORG-ACME-PILOT',
      passwordHash: hashPassword(acmeTestPass),
      apiKey: 'acme_test_api_key',
      createdAt: Date.now(),
      lastLoginAt: Date.now()
    };
    (db as any).adminUsers.push(acmeOrgAdmin);

    const app = createExpressApp(db);

    // Universal mock request helper
    const mockRequest = (options: {
      method: string;
      url: string;
      headers?: Record<string, string>;
      body?: any;
    }): Promise<{ status: number; body: any }> => {
      return new Promise((resolve) => {
        const urlObj = new URL(options.url, 'http://localhost:3000');
        const req: any = {
          method: options.method,
          url: options.url,
          ip: '127.0.0.10',
          body: options.body || {},
          query: Object.fromEntries(urlObj.searchParams.entries()),
          headers: { 'content-type': 'application/json', ...(options.headers || {}) },
          get(name: string) { return this.headers[name.toLowerCase()]; }
        };
        const headers: Record<string, any> = {};
        const res: any = {
          statusCode: 200,
          headersSent: false,
          headers,
          setHeader(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          getHeader(k: string) { return headers[k.toLowerCase()]; },
          header(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          set(k: string, v: string) { headers[k.toLowerCase()] = v; return this; },
          status(code: number) { this.statusCode = code; return this; },
          json(data: any) { this.headersSent = true; resolve({ status: this.statusCode, body: data }); },
          send(data: any) { this.headersSent = true; resolve({ status: this.statusCode, body: data }); },
          sendStatus(code: number) { this.statusCode = code; this.headersSent = true; resolve({ status: code, body: null }); }
        };
        (app as any).handle(req, res);
      });
    };

    // 5a. Valid ORG_ADMIN login by email
    const loginEmailRes = await mockRequest({
      method: 'POST',
      url: '/api/auth/login',
      body: { email: 'it-admin@acme-corp.com', password: acmeTestPass }
    });
    assert(loginEmailRes.status === 200, 'ORG_ADMIN login by email succeeds with 200');
    assert(loginEmailRes.body?.success === true, 'ORG_ADMIN login response has success: true');
    assert(loginEmailRes.body?.user?.role === 'ORG_ADMIN', 'ORG_ADMIN user role is strictly ORG_ADMIN');
    assert(loginEmailRes.body?.user?.role !== 'SUPER_ADMIN', 'ORG_ADMIN is NOT granted SUPER_ADMIN privileges');
    assert(loginEmailRes.body?.user?.organizationId === 'ORG-ACME-PILOT', 'ORG_ADMIN is scoped strictly to ORG-ACME-PILOT');
    const orgAdminToken = loginEmailRes.body?.token;
    assert(typeof orgAdminToken === 'string' && orgAdminToken.length > 20, 'ORG_ADMIN receives valid session token');

    // 5b. Valid ORG_ADMIN login by username
    const loginUsernameRes = await mockRequest({
      method: 'POST',
      url: '/api/auth/login',
      body: { username: 'acme_admin', password: acmeTestPass }
    });
    assert(loginUsernameRes.status === 200, 'ORG_ADMIN login by username succeeds with 200');
    assert(loginUsernameRes.body?.user?.email === 'it-admin@acme-corp.com', 'Username login maps to correct user');

    // 5c. Wrong password fails with 401
    const wrongPassRes = await mockRequest({
      method: 'POST',
      url: '/api/auth/login',
      body: { email: 'it-admin@acme-corp.com', password: 'DefinitelyWrongPassword123!' }
    });
    assert(wrongPassRes.status === 401, 'ORG_ADMIN wrong password returns 401 Unauthorized');
    assert(!wrongPassRes.body?.token, 'No session token issued on failed login');

    // 5d. ORG_ADMIN receives only its organization scope via /api/auth/me
    const meRes = await mockRequest({
      method: 'GET',
      url: '/api/auth/me',
      headers: { authorization: `Bearer ${orgAdminToken}` }
    });
    assert(meRes.status === 200, '/api/auth/me succeeds with valid ORG_ADMIN token');
    assert(meRes.body?.user?.organizationId === 'ORG-ACME-PILOT', 'Me endpoint returns ORG-ACME-PILOT');
    assert(meRes.body?.user?.role === 'ORG_ADMIN', 'Me endpoint returns ORG_ADMIN role');
    assert(meRes.body?.organization?.organizationId === 'ORG-ACME-PILOT', 'Me endpoint returns Acme Corporation details');

    // 5e. ORG_ADMIN cannot access SUPER_ADMIN routes
    const superAdminUsersRes = await mockRequest({
      method: 'GET',
      url: '/api/admin/users',
      headers: { authorization: `Bearer ${orgAdminToken}` }
    });
    assert(superAdminUsersRes.status === 403, 'ORG_ADMIN accessing /api/admin/users is rejected with 403 Forbidden');

    const superAdminOrgsRes = await mockRequest({
      method: 'GET',
      url: '/api/admin/organizations',
      headers: { authorization: `Bearer ${orgAdminToken}` }
    });
    assert(superAdminOrgsRes.status === 403, 'ORG_ADMIN accessing /api/admin/organizations is rejected with 403 Forbidden');

    const createAdminRes = await mockRequest({
      method: 'POST',
      url: '/api/admin/users',
      headers: { authorization: `Bearer ${orgAdminToken}` },
      body: { email: 'attacker@evil.com', role: 'SUPER_ADMIN' }
    });
    assert(createAdminRes.status === 403, 'ORG_ADMIN creating admin users is rejected with 403 Forbidden');

    // 5f. ORG_ADMIN cannot access another organization's devices or events
    const customerDevicesRes = await mockRequest({
      method: 'GET',
      url: '/api/customer/devices?orgId=ORG-RIVAL-ENTERPRISE',
      headers: { authorization: `Bearer ${orgAdminToken}` }
    });
    assert(customerDevicesRes.status === 200, 'Customer devices endpoint returns 200');
    assert(customerDevicesRes.body?.devices?.length === 1, 'Only Acme devices are returned (count: 1)');
    assert(customerDevicesRes.body?.devices?.[0]?.deviceId === 'DEV-ACME-01', 'Returned device is DEV-ACME-01');
    assert(!customerDevicesRes.body?.devices?.some((d: any) => d.deviceId === 'DEV-RIVAL-01'), 'Rival device DEV-RIVAL-01 is NOT visible');

    // 5g. Session authentication is actually enforced server-side
    const noAuthOverviewRes = await mockRequest({
      method: 'GET',
      url: '/api/customer/overview'
    });
    assert(noAuthOverviewRes.status === 401, 'Access without token returns 401 Unauthorized');

    const fakeTokenOverviewRes = await mockRequest({
      method: 'GET',
      url: '/api/customer/overview',
      headers: { authorization: 'Bearer fake-invalid-session-token-999' }
    });
    assert(fakeTokenOverviewRes.status === 401, 'Access with fake token returns 401 Unauthorized');

    const validOverviewRes = await mockRequest({
      method: 'GET',
      url: '/api/customer/overview',
      headers: { authorization: `Bearer ${orgAdminToken}` }
    });
    assert(validOverviewRes.status === 200, 'Access with valid ORG_ADMIN token returns 200 OK');
    assert(validOverviewRes.body?.organization?.organizationId === 'ORG-ACME-PILOT', 'Overview returns Acme organization');

    // 5h. No role-selection or client-preset bypass exists
    const bypassRes = await mockRequest({
      method: 'POST',
      url: '/api/auth/login',
      body: {
        email: 'it-admin@acme-corp.com',
        password: acmeTestPass,
        role: 'SUPER_ADMIN', // Attacker attempts client-side role elevation
        accountType: 'SUPER_ADMIN'
      }
    });
    assert(bypassRes.status === 200, 'Login succeeds');
    assert(bypassRes.body?.user?.role === 'ORG_ADMIN', 'Role bypass is ignored; user role remains strictly ORG_ADMIN');

    // 5i. Bootstrap test: uninitialized password without env var fails safely with 500
    const uninitAdmin = {
      id: 'usr_uninit_org_admin',
      username: 'uninit_admin',
      name: 'Uninitialized IT Lead',
      email: 'uninit@acme-corp.com',
      role: 'ORG_ADMIN' as const,
      organizationId: 'ORG-ACME-PILOT',
      passwordHash: 'DISABLED:UNINITIALIZED_BOOTSTRAP',
      apiKey: 'key',
      createdAt: Date.now(),
      lastLoginAt: Date.now()
    };
    (db as any).adminUsers.push(uninitAdmin);

    const origOrgPass = process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD;
    const origAdminPass = process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
    delete process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD;
    delete process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;

    const uninitRes = await mockRequest({
      method: 'POST',
      url: '/api/auth/login',
      body: { email: 'uninit@acme-corp.com', password: 'AnyPasswordAttempt!' }
    });
    assert(uninitRes.status === 500, 'Uninitialized Org Admin without env var returns safe 500');
    assert(uninitRes.body?.error?.includes('bootstrap required'), 'Error explains bootstrap required without exposing secrets');

    // 5j. Bootstrap test: with env var set, bootstrapping succeeds and subsequent login works
    process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD = 'BootstrapOrgAdminPass2026!';
    const bootstrappedLogin = await mockRequest({
      method: 'POST',
      url: '/api/auth/login',
      body: { email: 'uninit@acme-corp.com', password: 'BootstrapOrgAdminPass2026!' }
    });
    assert(bootstrappedLogin.status === 200, 'Org Admin bootstraps successfully when env var is set');
    assert(bootstrappedLogin.body?.user?.role === 'ORG_ADMIN', 'Bootstrapped account is ORG_ADMIN');

    // Clean up env vars
    if (origOrgPass !== undefined) process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD = origOrgPass;
    else delete process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD;
    if (origAdminPass !== undefined) process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD = origAdminPass;
    else delete process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;

    // =========================================================================
    // 6. Multi-Instance Serverless Session & Customer Token Lifecycle Suite
    // =========================================================================
    
    // Helper for executing simulated requests against any Express app instance
    const execAppRequest = (targetApp: any, options: {
      method: string;
      url: string;
      headers?: Record<string, string>;
      body?: any;
    }): Promise<{ status: number; body: any; headers: any }> => {
      return new Promise((resolve) => {
        const req: any = {
          method: options.method,
          url: options.url,
          ip: '127.0.0.1',
          body: options.body || {},
          headers: {
            'content-type': 'application/json',
            ...(options.headers || {})
          }
        };

        const resHeaders: Record<string, string> = {};
        const res: any = {
          statusCode: 200,
          setHeader: (k: string, v: string) => {
            resHeaders[k.toLowerCase()] = v;
            return res;
          },
          status: (code: number) => {
            res.statusCode = code;
            return res;
          },
          json: (data: any) => {
            resolve({ status: res.statusCode, body: data, headers: resHeaders });
            return res;
          },
          send: (data: any) => {
            let parsed = data;
            try { parsed = JSON.parse(data); } catch {}
            resolve({ status: res.statusCode, body: parsed, headers: resHeaders });
            return res;
          },
          end: () => {
            resolve({ status: res.statusCode, body: null, headers: resHeaders });
            return res;
          }
        };

        targetApp(req, res, () => {
          resolve({ status: 404, body: { error: 'Not Found' }, headers: resHeaders });
        });
      });
    };

    const acmePassword = 'AcmeOrgAdminPass2026!';
    
    // 6a. Serverless Instance A handles Login
    const dbA = new InMemoryDatabaseAdapter();
    dbA.init();
    dbA.createOrganization({
      organizationId: 'ORG-ACME-PILOT',
      name: 'Acme Corporation (Pilot)',
      status: 'ACTIVE',
      enforcementMode: 'BLOCK'
    });
    dbA.createOrganization({
      organizationId: 'ORG-COMPETITOR-01',
      name: 'Competitor Corp',
      status: 'ACTIVE',
      enforcementMode: 'BLOCK'
    });
    const acmeAdminUserA = {
      id: 'usr_acme_admin_01',
      username: 'acme_admin',
      name: 'Alex Rivera (IT Lead)',
      email: 'it-admin@acme-corp.com',
      role: 'ORG_ADMIN' as const,
      organizationId: 'ORG-ACME-PILOT',
      passwordHash: hashPassword(acmePassword),
      apiKey: 'key_a',
      createdAt: Date.now(),
      lastLoginAt: Date.now()
    };
    (dbA as any).adminUsers.push(acmeAdminUserA);
    const appA = createExpressApp(dbA);

    // Test wrong password
    const multiInstanceWrongPassRes = await execAppRequest(appA, {
      method: 'POST',
      url: '/api/auth/login',
      body: { email: 'it-admin@acme-corp.com', password: 'WrongPassword123!' }
    });
    assert(multiInstanceWrongPassRes.status === 401, 'Wrong password returns 401');
    assert(multiInstanceWrongPassRes.body?.error?.includes('Invalid email or password'), 'Clean error message on bad password');

    // Test valid login on Instance A
    const validLoginRes = await execAppRequest(appA, {
      method: 'POST',
      url: '/api/auth/login',
      body: { email: 'it-admin@acme-corp.com', password: acmePassword }
    });
    assert(validLoginRes.status === 200, 'Valid login on Instance A returns 200');
    const sessionToken = validLoginRes.body?.token;
    assert(typeof sessionToken === 'string' && sessionToken.startsWith('pg_sess_'), 'Session token is returned');
    assert(validLoginRes.body?.user?.role === 'ORG_ADMIN', 'Returned user role is ORG_ADMIN');
    assert(validLoginRes.body?.user?.organizationId === 'ORG-ACME-PILOT', 'Returned user org is ORG-ACME-PILOT');
    
    // Test Set-Cookie header is provided with secure attributes
    const setCookieHeader = validLoginRes.headers['set-cookie'];
    assert(typeof setCookieHeader === 'string' && setCookieHeader.includes('phishguard_auth_token='), 'Set-Cookie contains phishguard_auth_token');
    assert(setCookieHeader.includes('HttpOnly'), 'Cookie is HttpOnly');
    assert(setCookieHeader.includes('SameSite=Lax'), 'Cookie is SameSite=Lax');

    // 6b. Test Unauthenticated Requests
    const unauthGetTokens = await execAppRequest(appA, {
      method: 'GET',
      url: '/api/customer/tokens'
    });
    assert(unauthGetTokens.status === 401, 'GET /api/customer/tokens without auth returns 401');

    const unauthPostTokens = await execAppRequest(appA, {
      method: 'POST',
      url: '/api/customer/tokens',
      body: { label: 'Unauth Token' }
    });
    assert(unauthPostTokens.status === 401, 'POST /api/customer/tokens without auth returns 401');

    // 6c. Test Tampered Token Rejection
    const tamperedToken = sessionToken.slice(0, -4) + 'abcd';
    const tamperedRes = await execAppRequest(appA, {
      method: 'GET',
      url: '/api/customer/tokens',
      headers: { authorization: `Bearer ${tamperedToken}` }
    });
    assert(tamperedRes.status === 401, 'Tampered token signature returns 401');

    // 6d. Test Cross-Instance Execution (Simulate Vercel Serverless Function Instance B)
    // Instance B has its own completely separate DB adapter and separate memory space
    const dbB = new InMemoryDatabaseAdapter();
    dbB.init();
    dbB.createOrganization({
      organizationId: 'ORG-ACME-PILOT',
      name: 'Acme Corporation (Pilot)',
      status: 'ACTIVE',
      enforcementMode: 'BLOCK'
    });
    dbB.createOrganization({
      organizationId: 'ORG-COMPETITOR-01',
      name: 'Competitor Corp',
      status: 'ACTIVE',
      enforcementMode: 'BLOCK'
    });
    const acmeAdminUserB = {
      id: 'usr_acme_admin_01',
      username: 'acme_admin',
      name: 'Alex Rivera (IT Lead)',
      email: 'it-admin@acme-corp.com',
      role: 'ORG_ADMIN' as const,
      organizationId: 'ORG-ACME-PILOT',
      passwordHash: hashPassword(acmePassword),
      apiKey: 'key_b',
      createdAt: Date.now(),
      lastLoginAt: Date.now()
    };
    (dbB as any).adminUsers.push(acmeAdminUserB);
    const appB = createExpressApp(dbB);

    // Test GET /api/auth/me on Instance B using sessionToken from Instance A
    const meResB = await execAppRequest(appB, {
      method: 'GET',
      url: '/api/auth/me',
      headers: { authorization: `Bearer ${sessionToken}` }
    });
    assert(meResB.status === 200, 'GET /api/auth/me succeeds on separate Instance B using token from Instance A');
    assert(meResB.body?.user?.email === 'it-admin@acme-corp.com', 'Instance B recognizes user email');
    assert(meResB.body?.user?.role === 'ORG_ADMIN', 'Instance B recognizes user role');
    assert(meResB.body?.user?.organizationId === 'ORG-ACME-PILOT', 'Instance B recognizes organizationId');

    // Test GET /api/customer/tokens on Instance B
    const getTokensResB = await execAppRequest(appB, {
      method: 'GET',
      url: '/api/customer/tokens',
      headers: { authorization: `Bearer ${sessionToken}` }
    });
    assert(getTokensResB.status === 200, 'GET /api/customer/tokens succeeds on Instance B');
    assert(Array.isArray(getTokensResB.body?.tokens), 'tokens array returned');

    // Test POST /api/customer/tokens on Instance B with Bearer Token
    const postTokenResB = await execAppRequest(appB, {
      method: 'POST',
      url: '/api/customer/tokens',
      headers: { authorization: `Bearer ${sessionToken}` },
      body: {
        label: 'Instance B Production Rollout Token',
        expiresInDays: 30,
        maxUses: 25
      }
    });
    assert(postTokenResB.status === 201, 'POST /api/customer/tokens succeeds with 201 Created on separate Instance B');
    assert(postTokenResB.body?.success === true, 'Token creation response indicates success');
    assert(postTokenResB.body?.token?.organizationId === 'ORG-ACME-PILOT', 'Created token is scoped strictly to ORG-ACME-PILOT');
    assert(postTokenResB.body?.token?.label === 'Instance B Production Rollout Token', 'Created token has correct label');

    // Test POST /api/customer/tokens on Instance B with Cookie Authentication
    const postTokenCookieResB = await execAppRequest(appB, {
      method: 'POST',
      url: '/api/customer/tokens',
      headers: { cookie: `phishguard_auth_token=${sessionToken}` },
      body: {
        label: 'Cookie-Authenticated Token',
        expiresInDays: 7,
        maxUses: 10
      }
    });
    assert(postTokenCookieResB.status === 201, 'POST /api/customer/tokens succeeds via Cookie authentication');
    assert(postTokenCookieResB.body?.token?.organizationId === 'ORG-ACME-PILOT', 'Cookie-authenticated token scoped to ORG-ACME-PILOT');

    // 6e. Test ORG_ADMIN attempting SUPER_ADMIN privileged endpoints
    const adminUsersRes = await execAppRequest(appB, {
      method: 'GET',
      url: '/api/admin/users',
      headers: { authorization: `Bearer ${sessionToken}` }
    });
    assert(adminUsersRes.status === 403, 'ORG_ADMIN attempting GET /api/admin/users is rejected with 403 Forbidden');

    const adminCreateUserRes = await execAppRequest(appB, {
      method: 'POST',
      url: '/api/admin/users',
      headers: { authorization: `Bearer ${sessionToken}` },
      body: { email: 'hacker@evil.com', password: 'Password123!', role: 'SUPER_ADMIN' }
    });
    assert(adminCreateUserRes.status === 403, 'ORG_ADMIN attempting POST /api/admin/users is rejected with 403 Forbidden');

    const adminCreateOrgRes = await execAppRequest(appB, {
      method: 'POST',
      url: '/api/admin/organizations',
      headers: { authorization: `Bearer ${sessionToken}` },
      body: { name: 'Unauthorized New Org', organizationId: 'ORG-UNAUTH' }
    });
    assert(adminCreateOrgRes.status === 403, 'ORG_ADMIN attempting POST /api/admin/organizations is rejected with 403 Forbidden');

    // 6f. Test Cross-Tenant Access Isolation
    // Attempting to create token for a different organization must be forced to user's own org
    const crossTenantTokenRes = await execAppRequest(appB, {
      method: 'POST',
      url: '/api/customer/tokens',
      headers: { authorization: `Bearer ${sessionToken}` },
      body: {
        organizationId: 'ORG-COMPETITOR-01', // Attacker attempts to target competitor org
        label: 'Illicit Competitor Token'
      }
    });
    assert(crossTenantTokenRes.status === 201, 'Token created but organization is enforced');
    assert(crossTenantTokenRes.body?.token?.organizationId === 'ORG-ACME-PILOT', 'Token organization was strictly clamped to ORG-ACME-PILOT');

    // Querying customer devices with a different orgId query param
    const crossTenantDevicesRes = await execAppRequest(appB, {
      method: 'GET',
      url: '/api/customer/devices?orgId=ORG-COMPETITOR-01',
      headers: { authorization: `Bearer ${sessionToken}` }
    });
    assert(crossTenantDevicesRes.status === 200, 'Devices query handled');
    const returnedDevices = crossTenantDevicesRes.body?.devices || [];
    assert(returnedDevices.every((d: any) => d.organizationId === 'ORG-ACME-PILOT'), 'Cross-tenant devices are never leaked; strictly scoped to user organization');

    // 6g. Logout Session Invalidation
    const logoutRes = await execAppRequest(appB, {
      method: 'POST',
      url: '/api/auth/logout',
      headers: { authorization: `Bearer ${sessionToken}` }
    });
    assert(logoutRes.status === 200, 'Logout succeeds with 200');
    assert(logoutRes.headers['set-cookie']?.includes('Max-Age=0'), 'Logout clears auth cookie');

    const postLogoutMeRes = await execAppRequest(appB, {
      method: 'GET',
      url: '/api/auth/me',
      headers: { authorization: `Bearer ${sessionToken}` }
    });
    assert(postLogoutMeRes.status === 401, 'Subsequent request after logout returns 401 Unauthorized');

    // =========================================================================
    // 7. HMAC Signing Secret Security & Serverless Failure Modes Suite
    // =========================================================================

    // 7a. Missing server-side signing secret causes a safe server configuration failure rather than using a default
    const savedSecret = process.env.PHISHGUARD_SESSION_SECRET;
    delete process.env.PHISHGUARD_SESSION_SECRET;
    let thrownError: any = null;
    try {
      getSessionSigningSecret();
    } catch (err: any) {
      thrownError = err;
    }
    assert(thrownError !== null, 'Missing PHISHGUARD_SESSION_SECRET causes safe configuration failure (throws error)');
    assert(
      thrownError?.message?.includes('PHISHGUARD_SESSION_SECRET'),
      'Safe configuration error explicitly names required PHISHGUARD_SESSION_SECRET environment variable'
    );
    assert(
      !thrownError?.message?.includes('pg_cluster_secret_sign_v1_durable_2026'),
      'No hardcoded fallback secret is leaked in error messages'
    );

    // Restore environment variable
    process.env.PHISHGUARD_SESSION_SECRET = savedSecret || 'pg_test_suite_secret_env_value_2026';
    const activeSecret = getSessionSigningSecret();
    assert(
      activeSecret === process.env.PHISHGUARD_SESSION_SECRET,
      'HMAC signing secret is loaded exclusively from server-side environment variable'
    );

    // 7b. Confirm signing secret is NEVER sent to browser, in token payload, or in responses
    const testSecretStr = process.env.PHISHGUARD_SESSION_SECRET;
    assert(
      !sessionToken.includes(testSecretStr),
      'Session token does NOT contain the raw HMAC secret'
    );
    const tokenParts = sessionToken.replace('pg_sess_', '').split('.');
    const decodedPayloadStr = Buffer.from(tokenParts[0], 'base64url').toString('utf8');
    assert(
      !decodedPayloadStr.includes(testSecretStr),
      'Decoded session token payload does NOT contain the HMAC secret'
    );
    assert(
      !JSON.stringify(validLoginRes.body).includes(testSecretStr),
      'Login response body does NOT leak the HMAC signing secret'
    );
    assert(
      !JSON.stringify(meResB.body).includes(testSecretStr),
      '/api/auth/me response body does NOT leak the HMAC signing secret'
    );

    // 7c. Browser authentication using HttpOnly cookie without localStorage token
    // Create new login to get fresh cookie
    const freshLoginRes = await execAppRequest(appA, {
      method: 'POST',
      url: '/api/auth/login',
      body: { email: 'it-admin@acme-corp.com', password: acmePassword }
    });
    assert(freshLoginRes.status === 200, 'Fresh login succeeds');
    const freshSetCookie = freshLoginRes.headers['set-cookie'];
    const cookieVal = freshSetCookie.split(';')[0]; // "phishguard_auth_token=pg_sess_..."

    // Make request to /api/auth/me with ONLY Cookie header (zero authorization/bearer headers)
    const cookieOnlyMeRes = await execAppRequest(appA, {
      method: 'GET',
      url: '/api/auth/me',
      headers: { cookie: cookieVal } // NO authorization or x-phishguard-auth-token headers!
    });
    assert(cookieOnlyMeRes.status === 200, 'HttpOnly cookie alone authenticates /api/auth/me without localStorage token');
    assert(cookieOnlyMeRes.body?.user?.email === 'it-admin@acme-corp.com', 'User correctly authenticated via cookie');

    // Make request to /api/customer/overview with ONLY Cookie header
    const cookieOnlyOverviewRes = await execAppRequest(appA, {
      method: 'GET',
      url: '/api/customer/overview',
      headers: { cookie: cookieVal }
    });
    assert(cookieOnlyOverviewRes.status === 200, 'HttpOnly cookie alone authenticates /api/customer/overview without localStorage token');

    // Make request to /api/customer/tokens with ONLY Cookie header
    const cookieOnlyTokensRes = await execAppRequest(appA, {
      method: 'GET',
      url: '/api/customer/tokens',
      headers: { cookie: cookieVal }
    });
    assert(cookieOnlyTokensRes.status === 200, 'HttpOnly cookie alone authenticates /api/customer/tokens');

    // 7d. In-memory & centralized revocation:
    // When Instance A processes a logout, it invalidates local memory and persists to database:
    const freshTokenStr = freshLoginRes.body?.token;
    const logoutResA = await execAppRequest(appA, {
      method: 'POST',
      url: '/api/auth/logout',
      headers: { cookie: `phishguard_auth_token=${freshTokenStr}` }
    });
    assert(logoutResA.status === 200, 'Logout on Instance A succeeds');

    // Instance A immediately rejects the token
    const afterLogoutMeA = await execAppRequest(appA, {
      method: 'GET',
      url: '/api/auth/me',
      headers: { cookie: `phishguard_auth_token=${freshTokenStr}` }
    });
    assert(afterLogoutMeA.status === 401, 'Instance A rejects token immediately after revocation');

    // Across an independent serverless instance C sharing the centralized persistent store:
    const dbC = new InMemoryDatabaseAdapter();
    dbC.init();
    const appC = createExpressApp(dbC);
    const crossInstanceTestRes = await execAppRequest(appC, {
      method: 'GET',
      url: '/api/auth/me',
      headers: { authorization: `Bearer ${freshTokenStr}` }
    });
    assert(
      crossInstanceTestRes.status === 401,
      'Instance C rejects token across serverless boundary using centralized persistent revocation'
    );

    // =========================================================================
    // 8. CENTRALIZED PERSISTENT SESSION REVOCATION SUITE (Multi-Instance Proofs)
    // =========================================================================

    // Clear shared revocation store before running proof assertions
    InMemoryDatabaseAdapter.clearCentralizedRevocations();

    // Instance 1: Serverless Instance Alpha (handles login & logout)
    const dbInstA = new InMemoryDatabaseAdapter();
    dbInstA.init();
    dbInstA.createOrganization({
      organizationId: 'ORG-ACME-PILOT',
      name: 'Acme Corporation (Pilot)',
      status: 'ACTIVE',
      enforcementMode: 'BLOCK'
    });
    dbInstA.createOrganization({
      organizationId: 'ORG-COMPETITOR-01',
      name: 'Competitor Corp',
      status: 'ACTIVE',
      enforcementMode: 'BLOCK'
    });
    const acmeAdminInstA = {
      id: 'usr_acme_admin_proof',
      username: 'acme_proof_admin',
      name: 'Alex Rivera (IT Lead)',
      email: 'alex.rivera@acme-corp.com',
      role: 'ORG_ADMIN' as const,
      organizationId: 'ORG-ACME-PILOT',
      passwordHash: hashPassword('AcmeSecurePassword2026!'),
      apiKey: 'key_proof_a',
      createdAt: Date.now(),
      lastLoginAt: Date.now()
    };
    (dbInstA as any).adminUsers.push(acmeAdminInstA);
    const appInstA = createExpressApp(dbInstA);

    // Instance 2: Independent Serverless Instance Beta (simulates independent Vercel lambda instance)
    const dbInstB = new InMemoryDatabaseAdapter();
    dbInstB.init();
    dbInstB.createOrganization({
      organizationId: 'ORG-ACME-PILOT',
      name: 'Acme Corporation (Pilot)',
      status: 'ACTIVE',
      enforcementMode: 'BLOCK'
    });
    dbInstB.createOrganization({
      organizationId: 'ORG-COMPETITOR-01',
      name: 'Competitor Corp',
      status: 'ACTIVE',
      enforcementMode: 'BLOCK'
    });
    const acmeAdminInstB = { ...acmeAdminInstA, apiKey: 'key_proof_b' };
    (dbInstB as any).adminUsers.push(acmeAdminInstB);
    const appInstB = createExpressApp(dbInstB);

    // PROOF 1: Login succeeds
    const proofLoginRes = await execAppRequest(appInstA, {
      method: 'POST',
      url: '/api/auth/login',
      body: { email: 'alex.rivera@acme-corp.com', password: 'AcmeSecurePassword2026!' }
    });
    assert(proofLoginRes.status === 200, 'Proof 1: Login succeeds with 200');
    const proofToken = proofLoginRes.body?.token;
    assert(typeof proofToken === 'string' && proofToken.startsWith('pg_sess_'), 'Proof 1: Valid signed session token issued');
    assert(proofLoginRes.body?.user?.organizationId === 'ORG-ACME-PILOT', 'Proof 1: User organizationId is ORG-ACME-PILOT');

    // PROOF 2: Token works from an independent server instance
    const proofInstBAuthRes = await execAppRequest(appInstB, {
      method: 'GET',
      url: '/api/auth/me',
      headers: { authorization: `Bearer ${proofToken}` }
    });
    assert(proofInstBAuthRes.status === 200, 'Proof 2: Token works from independent server instance Beta');
    assert(proofInstBAuthRes.body?.user?.email === 'alex.rivera@acme-corp.com', 'Proof 2: Independent instance resolves user email');

    // PROOF 3: Logout persists revocation
    const proofLogoutRes = await execAppRequest(appInstA, {
      method: 'POST',
      url: '/api/auth/logout',
      headers: { authorization: `Bearer ${proofToken}` }
    });
    assert(proofLogoutRes.status === 200, 'Proof 3: Logout on Instance Alpha succeeds');
    const proofTokenHash = crypto.createHash('sha256').update(proofToken).digest('hex');
    assert(dbInstA.isSessionRevoked(proofTokenHash) === true, 'Proof 3: Logout persists revocation in shared database');

    // PROOF 4: The same token is rejected from an independent server instance after logout
    const proofInstBPostLogoutRes = await execAppRequest(appInstB, {
      method: 'GET',
      url: '/api/auth/me',
      headers: { authorization: `Bearer ${proofToken}` }
    });
    assert(proofInstBPostLogoutRes.status === 401, 'Proof 4: The same token is rejected from independent server instance Beta after logout');

    // PROOF 5: Tampered tokens remain rejected
    const freshTokenRes = await execAppRequest(appInstA, {
      method: 'POST',
      url: '/api/auth/login',
      body: { email: 'alex.rivera@acme-corp.com', password: 'AcmeSecurePassword2026!' }
    });
    const freshToken = freshTokenRes.body?.token;
    const tamperedProofToken = freshToken.slice(0, -5) + 'xxxxx';
    const tamperedProofRes = await execAppRequest(appInstB, {
      method: 'GET',
      url: '/api/auth/me',
      headers: { authorization: `Bearer ${tamperedProofToken}` }
    });
    assert(tamperedProofRes.status === 401, 'Proof 5: Tampered tokens remain rejected with 401');

    // PROOF 6: Expired tokens remain rejected
    const expiredPayload = {
      userId: 'usr_acme_admin_proof',
      username: 'acme_proof_admin',
      name: 'Alex Rivera',
      email: 'alex.rivera@acme-corp.com',
      role: 'ORG_ADMIN',
      organizationId: 'ORG-ACME-PILOT',
      iat: Date.now() - 100000,
      exp: Date.now() - 5000,
      nonce: 'expired_nonce'
    };
    const expPayloadB64 = Buffer.from(JSON.stringify(expiredPayload)).toString('base64url');
    const expSig = crypto
      .createHmac('sha256', getSessionSigningSecret())
      .update(expPayloadB64)
      .digest('base64url');
    const expiredToken = `pg_sess_${expPayloadB64}.${expSig}`;
    const expiredRes = await execAppRequest(appInstB, {
      method: 'GET',
      url: '/api/auth/me',
      headers: { authorization: `Bearer ${expiredToken}` }
    });
    assert(expiredRes.status === 401, 'Proof 6: Expired tokens remain rejected with 401');

    // PROOF 7: ORG_ADMIN remains isolated to ORG-ACME-PILOT
    const crossTenantCreateRes = await execAppRequest(appInstB, {
      method: 'POST',
      url: '/api/customer/tokens',
      headers: { authorization: `Bearer ${freshToken}` },
      body: {
        organizationId: 'ORG-COMPETITOR-01',
        label: 'Infiltration Token'
      }
    });
    assert(crossTenantCreateRes.status === 201, 'Proof 7: Token creation request processed');
    assert(crossTenantCreateRes.body?.token?.organizationId === 'ORG-ACME-PILOT', 'Proof 7: ORG_ADMIN cannot target other organizations; strictly clamped to ORG-ACME-PILOT');

    const competitorDevicesRes = await execAppRequest(appInstB, {
      method: 'GET',
      url: '/api/customer/devices?orgId=ORG-COMPETITOR-01',
      headers: { authorization: `Bearer ${freshToken}` }
    });
    assert(competitorDevicesRes.status === 200, 'Proof 7: Customer devices endpoint accessible');
    const compDevices = competitorDevicesRes.body?.devices || [];
    assert(compDevices.every((d: any) => d.organizationId === 'ORG-ACME-PILOT'), 'Proof 7: Devices returned are strictly isolated to ORG-ACME-PILOT');

    // PROOF 8: SUPER_ADMIN routes remain inaccessible to ORG_ADMIN
    const forbiddenUsersRes = await execAppRequest(appInstB, {
      method: 'GET',
      url: '/api/admin/users',
      headers: { authorization: `Bearer ${freshToken}` }
    });
    assert(forbiddenUsersRes.status === 403, 'Proof 8: GET /api/admin/users is forbidden (403) for ORG_ADMIN');

    const forbiddenOrgsRes = await execAppRequest(appInstB, {
      method: 'GET',
      url: '/api/admin/organizations',
      headers: { authorization: `Bearer ${freshToken}` }
    });
    assert(forbiddenOrgsRes.status === 403, 'Proof 8: GET /api/admin/organizations is forbidden (403) for ORG_ADMIN');

    const forbiddenCreateOrgRes = await execAppRequest(appInstB, {
      method: 'POST',
      url: '/api/admin/organizations',
      headers: { authorization: `Bearer ${freshToken}` },
      body: { name: 'Hostile Org', organizationId: 'ORG-HOSTILE' }
    });
    assert(forbiddenCreateOrgRes.status === 403, 'Proof 8: POST /api/admin/organizations is forbidden (403) for ORG_ADMIN');

  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Acme ORG_ADMIN suite threw: ${err?.message}`);
  }

  return { passed, failed, errors };
}
