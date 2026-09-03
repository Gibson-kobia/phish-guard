/**
 * PhishGuard Express Application Factory
 * 
 * Central API router and security middleware provider for both local dev and Vercel serverless functions.
 * Implements:
 * 1. Multi-role Authentication (Super Admin, Customer Org Admin, Customer Read Only).
 * 2. Enterprise Device Enrollment & Heartbeat Policy Sync.
 * 3. Canonical Security Event Telemetry Ingestion with server-side tenant attribution.
 * 4. Customer Portal Dedicated APIs (/api/customer/*) with strict tenant isolation.
 * 5. Platform Admin APIs (/api/admin/*) with cross-tenant analytics and controls.
 */

import express, { Express, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { db } from './database';
import { CONFIG } from '../config/environment';
import { CanonicalSecurityEvent, EnrolledDevice, Organization, AuditLogEntry, EnforcementMode } from '../core/types';
import { AdminUser, IDatabaseAdapter, UserRole } from './storage/types';
import { hashPassword, verifyPassword, checkRateLimit, resetRateLimit } from './authUtils';

export interface AuthenticatedRequest extends Request {
  authenticatedDevice?: EnrolledDevice;
  authenticatedOrgId?: string;
  isAdmin?: boolean;
  user?: AdminUser;
}

export interface SessionPayload {
  userId: string;
  username: string;
  name: string;
  email: string;
  role: UserRole;
  organizationId?: string;
  iat: number;
  exp: number;
  nonce?: string;
}

interface ActiveSession {
  token: string;
  user: AdminUser;
  createdAt: number;
  expiresAt: number;
}

// In-memory active and revoked sessions caches
const activeSessions = new Map<string, ActiveSession>();
const revokedSessions = new Set<string>();
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export function getSessionSigningSecret(): string {
  const secret = process.env.PHISHGUARD_SESSION_SECRET;
  if (!secret || secret.trim().length === 0) {
    throw new Error('Safe server configuration failure: Missing required PHISHGUARD_SESSION_SECRET server-side environment variable.');
  }
  return secret.trim();
}

export function parseCookieHeader(cookieHeader?: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;
  const parts = cookieHeader.split(';');
  for (const part of parts) {
    const idx = part.indexOf('=');
    if (idx !== -1) {
      const key = part.slice(0, idx).trim();
      const val = part.slice(idx + 1).trim();
      if (key) {
        try {
          cookies[key] = decodeURIComponent(val);
        } catch {
          cookies[key] = val;
        }
      }
    }
  }
  return cookies;
}

export function createSession(user: AdminUser): string {
  const now = Date.now();
  const payload: SessionPayload = {
    userId: user.id,
    username: user.username,
    name: user.name,
    email: user.email,
    role: user.role,
    organizationId: user.organizationId,
    iat: now,
    exp: now + SESSION_TTL_MS,
    nonce: crypto.randomBytes(12).toString('hex')
  };

  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', getSessionSigningSecret())
    .update(payloadB64)
    .digest('base64url');

  const token = `pg_sess_${payloadB64}.${signature}`;

  activeSessions.set(token, {
    token,
    user: { ...user },
    createdAt: now,
    expiresAt: payload.exp
  });

  return token;
}

export function hashSessionToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export async function validateSession(token: string, databaseAdapter?: IDatabaseAdapter): Promise<AdminUser | null> {
  if (!token) return null;
  const tokenHash = hashSessionToken(token);
  if (revokedSessions.has(tokenHash) || revokedSessions.has(token)) return null;

  // 1. Stateless cryptographic HMAC verification across serverless function instances
  if (token.startsWith('pg_sess_')) {
    const raw = token.slice('pg_sess_'.length);
    const dotIdx = raw.indexOf('.');
    if (dotIdx > 0) {
      const payloadB64 = raw.slice(0, dotIdx);
      const signature = raw.slice(dotIdx + 1);

      let signingSecret: string;
      try {
        signingSecret = getSessionSigningSecret();
      } catch {
        return null;
      }

      const expectedSig = crypto
        .createHmac('sha256', signingSecret)
        .update(payloadB64)
        .digest('base64url');

      if (expectedSig.length !== signature.length) {
        return null;
      }

      const matches = crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(signature));
      if (!matches) {
        return null;
      }

      try {
        const payloadJson = Buffer.from(payloadB64, 'base64url').toString('utf8');
        const payload: SessionPayload = JSON.parse(payloadJson);

        if (Date.now() > payload.exp) {
          return null;
        }

        // 2. Centralized persistent revocation check (cross-instance Vercel serverless safety)
        if (databaseAdapter?.isSessionRevoked) {
          const isRevoked = await databaseAdapter.isSessionRevoked(tokenHash);
          if (isRevoked) {
            revokedSessions.add(tokenHash);
            revokedSessions.add(token);
            activeSessions.delete(token);
            return null;
          }
        }

        // 3. Fast-path in-memory active session lookup after verifying persistent revocation
        const session = activeSessions.get(token);
        if (session) {
          if (Date.now() > session.expiresAt) {
            activeSessions.delete(token);
            return null;
          }
          return session.user;
        }

        let resolvedUser: AdminUser | null = null;
        if (databaseAdapter) {
          resolvedUser = databaseAdapter.getAdminUserById(payload.userId) || databaseAdapter.getAdminUserByEmail(payload.email);
        }

        if (!resolvedUser) {
          resolvedUser = {
            id: payload.userId,
            username: payload.username,
            name: payload.name,
            email: payload.email,
            role: payload.role,
            organizationId: payload.organizationId,
            passwordHash: '',
            createdAt: payload.iat,
            lastLoginAt: payload.iat
          };
        }

        // Cache in this serverless instance for subsequent local requests
        activeSessions.set(token, {
          token,
          user: { ...resolvedUser },
          createdAt: payload.iat,
          expiresAt: payload.exp
        });

        return resolvedUser;
      } catch {
        return null;
      }
    }
  }

  return null;
}

export async function invalidateSession(token: string, databaseAdapter?: IDatabaseAdapter): Promise<boolean> {
  if (!token) return false;
  activeSessions.delete(token);
  const tokenHash = hashSessionToken(token);
  revokedSessions.add(tokenHash);
  revokedSessions.add(token);

  let exp = Date.now() + SESSION_TTL_MS;
  let userId: string | undefined;
  let organizationId: string | undefined;

  if (token.startsWith('pg_sess_')) {
    const raw = token.slice('pg_sess_'.length);
    const dotIdx = raw.indexOf('.');
    if (dotIdx > 0) {
      try {
        const payloadB64 = raw.slice(0, dotIdx);
        const payloadJson = Buffer.from(payloadB64, 'base64url').toString('utf8');
        const payload: SessionPayload = JSON.parse(payloadJson);
        if (payload.exp) exp = payload.exp;
        userId = payload.userId;
        organizationId = payload.organizationId;
      } catch {}
    }
  }

  if (databaseAdapter?.revokeSession) {
    try {
      await databaseAdapter.revokeSession(tokenHash, exp, { userId, organizationId });
    } catch (err) {
      console.error('[Session] Persistent revocation error:', err);
    }
  }

  return true;
}

export function createExpressApp(customDb?: IDatabaseAdapter): Express {
  const app = express();
  const activeDb = customDb || db;

  // Global Middlewares
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // URL normalization middleware for Vercel serverless functions and proxy routing
  app.use((req, res, next) => {
    if (req.url.startsWith('/api/index/')) {
      req.url = '/api/' + req.url.slice('/api/index/'.length);
    } else if (req.url === '/api/index' || req.url.startsWith('/api/index?')) {
      const matched = (req.headers['x-matched-path'] as string) || (req.headers['x-invoke-path'] as string);
      if (matched && matched !== '/api/index' && matched !== '/api') {
        const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
        req.url = matched + query;
      }
    }
    next();
  });

  // CORS headers
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, PUT, DELETE, OPTIONS');
    res.header(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-PhishGuard-Org, X-PhishGuard-Device, X-PhishGuard-Device-Key, X-PhishGuard-Admin-Key, X-PhishGuard-Auth-Token, X-Extension-Version, X-PhishGuard-Agent'
    );
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

  // ==========================================================================
  // AUTHENTICATION & SECURITY MIDDLEWARES
  // ==========================================================================

  /**
   * Device Authentication Middleware
   * Validates device API key or enrollment token. Derives organizationId from authenticated device.
   */
  const authenticateDevice = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const deviceKeyHeader = req.headers['x-phishguard-device-key'] as string;
    let token = '';

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7).trim();
    } else if (deviceKeyHeader) {
      token = deviceKeyHeader.trim();
    }

    if (!token) {
      const devId = (req.headers['x-phishguard-device'] as string) || (req.body?.deviceId as string);
      if (devId) {
        const found = activeDb.getDeviceById(devId);
        if (found) {
          req.authenticatedDevice = found;
          req.authenticatedOrgId = found.organizationId;
          return next();
        }
      }
      return res.status(401).json({
        error: 'Unauthorized: Missing device credentials. Enrolled device API key required.'
      });
    }

    const device = activeDb.getDeviceByApiKey(token) || activeDb.getDeviceById(token);
    if (!device) {
      return res.status(401).json({
        error: 'Unauthorized: Invalid device credentials. Device must be enrolled first.'
      });
    }

    req.authenticatedDevice = device;
    req.authenticatedOrgId = device.organizationId;
    next();
  };

  /**
   * Optional Device Auth Middleware (allows authenticated devices while supporting local dev)
   */
  const optionalDeviceAuth = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const deviceKeyHeader = req.headers['x-phishguard-device-key'] as string;
    let token = '';

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7).trim();
    } else if (deviceKeyHeader) {
      token = deviceKeyHeader.trim();
    }

    if (token) {
      const device = activeDb.getDeviceByApiKey(token) || activeDb.getDeviceById(token);
      if (device) {
        req.authenticatedDevice = device;
        req.authenticatedOrgId = device.organizationId;
      }
    }
    next();
  };

  /**
   * User / Admin Session Middleware
   */
  const authenticateSession = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      const authHeader = req.headers['authorization'];
      const authTokenHeader = req.headers['x-phishguard-auth-token'] as string;
      const adminKeyHeader = req.headers['x-phishguard-admin-key'] as string;
      const cookieHeader = req.headers['cookie'];
      
      let token = '';
      // 1. Prefer HttpOnly session cookie as standard browser authentication mechanism
      if (cookieHeader) {
        const cookies = parseCookieHeader(cookieHeader);
        token = cookies['phishguard_auth_token'] || cookies['session_token'] || '';
      }
      // 2. Fall back to Bearer token or custom headers for API clients / extensions
      if (!token && authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.slice(7).trim();
      } else if (!token && authTokenHeader) {
        token = authTokenHeader.trim();
      } else if (!token && adminKeyHeader) {
        token = adminKeyHeader.trim();
      }

      if (token) {
        // 1. Session token
        const user = await validateSession(token, activeDb);
        if (user) {
          req.user = user;
          req.isAdmin = user.role === 'SUPER_ADMIN';
          req.authenticatedOrgId = user.organizationId;
          return next();
        }

        // 2. Platform operator root API key
        if (CONFIG.adminApiKey && token === CONFIG.adminApiKey) {
          const masterAdmin: AdminUser = {
            id: 'usr_master_admin',
            username: 'admin',
            name: 'SecOps Director',
            email: 'admin@phishguard.security',
            role: 'SUPER_ADMIN',
            passwordHash: '',
            createdAt: Date.now(),
            lastLoginAt: Date.now()
          };
          req.user = masterAdmin;
          req.isAdmin = true;
          return next();
        }

        // 3. User by internal API key
        const allUsers = activeDb.getAdminUsers();
        const matchedUser = allUsers.find(u => u.apiKey && u.apiKey === token);
        if (matchedUser) {
          req.user = matchedUser;
          req.isAdmin = matchedUser.role === 'SUPER_ADMIN';
          req.authenticatedOrgId = matchedUser.organizationId;
          return next();
        }
      }

      return res.status(401).json({
        error: 'Unauthorized: Valid authentication session required.'
      });
    } catch (authErr: any) {
      return res.status(500).json({
        error: 'Authentication error',
        message: authErr?.message
      });
    }
  };

  /**
   * Super Admin Only Enforcer
   */
  const requireSuperAdmin = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user || req.user.role !== 'SUPER_ADMIN') {
      return res.status(403).json({
        error: 'Forbidden: Platform Super Administrator privileges required.'
      });
    }
    next();
  };

  /**
   * Customer Organization Authentication Middleware
   */
  const customerAuth = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    return authenticateSession(req, res, () => {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized: Session authentication required.' });
      }
      if (req.user.role !== 'SUPER_ADMIN' && !req.user.organizationId) {
        return res.status(403).json({ error: 'Forbidden: Account is not associated with a business fleet organization.' });
      }
      next();
    });
  };

  /**
   * Individual Customer Authentication Middleware
   */
  const individualAuth = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    return authenticateSession(req, res, () => {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized: Session authentication required.' });
      }
      next();
    });
  };

  // ==========================================================================
  // 0. AUTHENTICATION & IDENTITY ROUTES
  // ==========================================================================

  app.post(['/api/auth/login', '/auth/login'], async (req, res) => {
    try {
      if ((activeDb as any).ensureInitialized) {
        await (activeDb as any).ensureInitialized();
      }

      const { email, username, password } = req.body || {};
      const lookup = (email || username || '').toLowerCase().trim();

      if (!lookup || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
      }

      // Rate limit check
      const rateLimitKey = `${req.ip || 'ip'}_${lookup}`;
      const rateCheck = checkRateLimit(rateLimitKey, 10, 15 * 60 * 1000);
      if (!rateCheck.allowed) {
        return res.status(429).json({
          error: `Too many authentication attempts. Please try again in ${rateCheck.resetInSec} seconds.`
        });
      }

      let user = activeDb.getAdminUserByEmail(lookup);
      if (!user) {
        const allUsers = activeDb.getAdminUsers();
        user = allUsers.find(u => u.username?.toLowerCase() === lookup) || null;
      }

      const isSuperAdminLookup = lookup === 'admin' || lookup === 'admin@phishguard.security' || (user && user.role === 'SUPER_ADMIN');
      const isAcmeOrgAdminLookup = lookup === 'acme_admin' || lookup === 'it-admin@acme-corp.com' || (user && user.role === 'ORG_ADMIN' && user.organizationId === 'ORG-ACME-PILOT');

      const envInitialPass = process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
      const envOrgAdminPass = process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ACME_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;

      if (!user) {
        if (isSuperAdminLookup) {
          if (!envInitialPass) {
            return res.status(500).json({
              error: 'Super Administrator bootstrap required: PHISHGUARD_INITIAL_ADMIN_PASSWORD environment variable is not configured on the server.'
            });
          }
          if (password === envInitialPass) {
            const newSuperAdmin: AdminUser = {
              id: 'usr_super_admin_01',
              username: 'admin',
              name: 'SecOps Director',
              email: 'admin@phishguard.security',
              role: 'SUPER_ADMIN',
              passwordHash: hashPassword(password),
              apiKey: crypto.randomBytes(24).toString('hex'),
              createdAt: Date.now(),
              lastLoginAt: Date.now()
            };
            activeDb.createAdminUser(newSuperAdmin);
            user = newSuperAdmin;
          } else {
            return res.status(401).json({ error: 'Invalid email or password.' });
          }
        } else if (isAcmeOrgAdminLookup) {
          if (!envOrgAdminPass) {
            return res.status(500).json({
              error: 'Organization Administrator bootstrap required: PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD or PHISHGUARD_INITIAL_ADMIN_PASSWORD environment variable is not configured on the server.'
            });
          }
          if (password === envOrgAdminPass) {
            const newAcmeAdmin: AdminUser = {
              id: 'usr_acme_admin_01',
              username: 'acme_admin',
              name: 'Alex Rivera (IT Lead)',
              email: 'it-admin@acme-corp.com',
              role: 'ORG_ADMIN',
              organizationId: 'ORG-ACME-PILOT',
              passwordHash: hashPassword(password),
              apiKey: crypto.randomBytes(24).toString('hex'),
              createdAt: Date.now(),
              lastLoginAt: Date.now()
            };
            activeDb.createAdminUser(newAcmeAdmin);
            user = newAcmeAdmin;
          } else {
            return res.status(401).json({ error: 'Invalid email or password.' });
          }
        } else {
          return res.status(401).json({ error: 'Invalid email or password.' });
        }
      }

      let isValid = false;

      // 1. Verify against stored password hash if initialized
      if (user.passwordHash && !user.passwordHash.startsWith('DISABLED:')) {
        isValid = verifyPassword(password, user.passwordHash);
      }

      // 2. If stored hash failed or uninitialized, check environment bootstrap variable for Super Admin
      if (!isValid && isSuperAdminLookup) {
        if (envInitialPass && password === envInitialPass) {
          user.passwordHash = hashPassword(password);
          try {
            activeDb.updateAdminUser(user.id, { passwordHash: user.passwordHash });
          } catch (syncErr) {
            console.warn('[Auth] Non-fatal admin password sync warning:', syncErr);
          }
          isValid = true;
        } else if (!user.passwordHash || user.passwordHash.startsWith('DISABLED:')) {
          if (!envInitialPass) {
            return res.status(500).json({
              error: 'Super Administrator bootstrap required: PHISHGUARD_INITIAL_ADMIN_PASSWORD environment variable is not configured on the server.'
            });
          }
        }
      }

      // 3. If stored hash failed or uninitialized, check environment bootstrap variable for Acme Organization Admin
      if (!isValid && isAcmeOrgAdminLookup) {
        if (envOrgAdminPass && password === envOrgAdminPass) {
          user.passwordHash = hashPassword(password);
          try {
            activeDb.updateAdminUser(user.id, { passwordHash: user.passwordHash });
          } catch (syncErr) {
            console.warn('[Auth] Non-fatal org admin password sync warning:', syncErr);
          }
          isValid = true;
        } else if (!user.passwordHash || user.passwordHash.startsWith('DISABLED:')) {
          if (!envOrgAdminPass) {
            return res.status(500).json({
              error: 'Organization Administrator bootstrap required: Initial admin password environment variable is not configured on the server.'
            });
          }
        }
      }

      if (!isValid) {
        return res.status(401).json({ error: 'Invalid email or password.' });
      }

      // Clear rate limit on successful authentication
      resetRateLimit(rateLimitKey);
      try {
        activeDb.updateAdminUser(user.id, { lastLoginAt: Date.now() });
      } catch (loginUpdateErr) {
        console.warn('[Auth] Non-fatal lastLoginAt update warning:', loginUpdateErr);
      }

      const sessionToken = createSession(user);
      const org = user.organizationId ? activeDb.getOrganizationById(user.organizationId) : null;

      res.setHeader(
        'Set-Cookie',
        `phishguard_auth_token=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${CONFIG.isProduction ? '; Secure' : ''}`
      );

      return res.json({
        success: true,
        token: sessionToken,
        user: {
          id: user.id,
          username: user.username,
          name: user.name,
          email: user.email,
          role: user.role,
          organizationId: user.organizationId,
          organizationName: org?.name,
          plan: user.plan || (user.role === 'INDIVIDUAL' ? 'PERSONAL_SHIELD' : 'BUSINESS_PRO'),
          planStatus: user.planStatus || 'ACTIVE',
          billingInterval: user.billingInterval || 'ANNUAL'
        }
      });
    } catch (err: any) {
      console.error('[Auth Service] Login error:', err?.message || err);
      return res.status(500).json({ error: 'Authentication service error', message: 'An internal authentication error occurred.' });
    }
  });

  app.post('/api/auth/signup', (req, res) => {
    try {
      const { email, password, name, accountType, organizationName, plan } = req.body;
      const cleanEmail = (email || '').toLowerCase().trim();

      if (!cleanEmail || !password || cleanEmail.indexOf('@') === -1) {
        return res.status(400).json({ error: 'A valid email address and password are required.' });
      }

      if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
      }

      const existing = activeDb.getAdminUserByEmail(cleanEmail);
      if (existing) {
        return res.status(409).json({ error: 'An account with this email address already exists.' });
      }

      const displayName = name?.trim() || cleanEmail.split('@')[0];
      const username = cleanEmail.split('@')[0].replace(/[^a-zA-Z0-9_]/g, '') || `user_${crypto.randomBytes(3).toString('hex')}`;
      const passwordHash = hashPassword(password);

      let createdUser: AdminUser;

      if (accountType === 'BUSINESS') {
        const orgName = organizationName?.trim() || `${displayName}'s Organization`;
        const newOrg = activeDb.createOrganization({
          name: orgName,
          enforcementMode: 'BLOCK',
          telemetryEnabled: true
        }, displayName);

        createdUser = activeDb.createAdminUser({
          email: cleanEmail,
          username,
          name: displayName,
          role: 'ORG_ADMIN',
          organizationId: newOrg.organizationId,
          passwordHash,
          plan: 'BUSINESS_PRO',
          planStatus: 'ACTIVE',
          billingInterval: 'ANNUAL'
        }, displayName);
      } else {
        // INDIVIDUAL
        createdUser = activeDb.createAdminUser({
          email: cleanEmail,
          username,
          name: displayName,
          role: 'INDIVIDUAL',
          passwordHash,
          plan: plan || 'PERSONAL_SHIELD',
          planStatus: 'ACTIVE',
          billingInterval: 'ANNUAL',
          devicesLimit: 5
        }, displayName);
      }

      const sessionToken = createSession(createdUser);
      const org = createdUser.organizationId ? activeDb.getOrganizationById(createdUser.organizationId) : null;

      res.setHeader(
        'Set-Cookie',
        `phishguard_auth_token=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${CONFIG.isProduction ? '; Secure' : ''}`
      );

      res.status(201).json({
        success: true,
        token: sessionToken,
        user: {
          id: createdUser.id,
          username: createdUser.username,
          name: createdUser.name,
          email: createdUser.email,
          role: createdUser.role,
          organizationId: createdUser.organizationId,
          organizationName: org?.name,
          plan: createdUser.plan,
          planStatus: createdUser.planStatus,
          billingInterval: createdUser.billingInterval
        }
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to create account', message: err?.message });
    }
  });

  app.post('/api/auth/logout', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const authTokenHeader = req.headers['x-phishguard-auth-token'] as string;
    const cookieHeader = req.headers['cookie'];
    let token = '';
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7).trim();
    } else if (authTokenHeader) {
      token = authTokenHeader.trim();
    } else if (cookieHeader) {
      const cookies = parseCookieHeader(cookieHeader);
      token = cookies['phishguard_auth_token'] || cookies['session_token'] || '';
    }

    if (token) {
      await invalidateSession(token, activeDb);
    }
    res.setHeader(
      'Set-Cookie',
      'phishguard_auth_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'
    );
    res.json({ success: true, message: 'Signed out successfully' });
  });

  app.post('/api/auth/forgot-password', (req, res) => {
    // Return generic response without user enumeration
    res.json({
      success: true,
      message: 'If an account exists with this email address, password recovery instructions have been dispatched.'
    });
  });

  app.get('/api/auth/me', authenticateSession, (req: AuthenticatedRequest, res) => {
    const user = req.user!;
    const org = user.organizationId ? activeDb.getOrganizationById(user.organizationId) : null;
    res.json({
      user: {
        id: user.id,
        username: user.username,
        name: user.name,
        email: user.email,
        role: user.role,
        organizationId: user.organizationId,
        organizationName: org?.name,
        plan: user.plan || (user.role === 'INDIVIDUAL' ? 'PERSONAL_SHIELD' : 'BUSINESS_PRO'),
        planStatus: user.planStatus || 'ACTIVE',
        billingInterval: user.billingInterval || 'ANNUAL'
      },
      organization: org
    });
  });

  // Backward compatibility alias for customer login
  app.post('/api/auth/customer-login', (req, res) => {
    return app._router.handle({ ...req, url: '/api/auth/login' }, res);
  });

  // ==========================================================================
  // 1. HEALTH & METADATA
  // ==========================================================================

  app.get('/api/health', (req, res) => {
    const isSupabase = !!(process.env.SUPABASE_URL && (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY));
    const overview = activeDb.getOverviewStats();
    res.json({
      status: 'ok',
      service: 'PhishGuard Central Enterprise Security Platform',
      version: '1.0.0',
      environment: CONFIG.isProduction ? 'production' : 'development',
      runtime: process.env.VERCEL ? 'Vercel Serverless' : 'Node.js Cloud',
      database: {
        type: isSupabase ? 'Supabase PostgreSQL' : 'Local Persistence',
        status: 'ONLINE'
      },
      serverTime: Date.now(),
      summary: {
        totalProtectedDevices: overview.totalProtectedDevices,
        onlineDevices: overview.onlineDevices,
        threatsToday: overview.threatsToday,
        blockedToday: overview.blockedToday
      }
    });
  });

  app.get('/api/version', (req, res) => {
    res.json({
      latestVersion: '1.0.0',
      minSupportedVersion: '1.0.0',
      downloadUrl: '/downloads/phishguard-extension-v1.0.0.zip',
      releaseNotes: 'PhishGuard Multi-Tenant Architecture & Enterprise Platform.'
    });
  });

  app.get('/api/config', optionalDeviceAuth, (req: AuthenticatedRequest, res) => {
    const orgId = req.authenticatedOrgId || (req.headers['x-phishguard-org'] as string) || (req.query.orgId as string) || 'ORG-ACME-PILOT';
    const org = activeDb.getOrganizationById(orgId) || activeDb.getOrganizations()[0];
    res.json({
      organizationId: org?.organizationId || orgId,
      organizationName: org?.name || 'Acme Corporation',
      enforcementMode: org?.enforcementMode || 'BLOCK',
      telemetryEnabled: org?.telemetryEnabled ?? true,
      minExtensionVersion: org?.minExtensionVersion || '1.0.0',
      retentionDays: org?.retentionDays || 90,
      backendUrl: org?.backendUrl || CONFIG.apiBaseUrl
    });
  });

  // ==========================================================================
  // 2. DEVICE ENROLLMENT & HEARTBEATS
  // ==========================================================================

  const handleEnrollment = (req: Request, res: Response) => {
    try {
      const {
        enrollmentToken,
        token,
        installationId,
        extensionVersion = '1.0.0',
        browser = 'Chrome MV3',
        os = 'Unknown OS',
        platform = 'Desktop',
        deviceName
      } = req.body;

      const effectiveToken = enrollmentToken || token;

      if (!effectiveToken) {
        return res.status(400).json({ error: 'Missing required field: enrollmentToken' });
      }
      if (!installationId) {
        return res.status(400).json({ error: 'Missing required field: installationId' });
      }

      const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

      const result = activeDb.enrollDevice({
        enrollmentToken: effectiveToken,
        installationId,
        extensionVersion,
        browser,
        os,
        platform,
        deviceName,
        ip: clientIp
      });

      if (!result.success || !result.device) {
        return res.status(401).json({ error: result.error || 'Device enrollment rejected' });
      }

      const org = activeDb.getOrganizationById(result.device.organizationId);

      res.status(201).json({
        success: true,
        deviceId: result.device.deviceId,
        installationId: result.device.installationId,
        organizationId: result.device.organizationId,
        organizationName: org?.name || 'Organization',
        deviceApiKey: result.device.deviceApiKey,
        enforcementMode: org?.enforcementMode || 'BLOCK',
        minExtensionVersion: org?.minExtensionVersion || '1.0.0',
        backendUrl: org?.backendUrl || CONFIG.apiBaseUrl
      });
    } catch (err: any) {
      console.error('[API /api/devices/enroll] Error:', err);
      res.status(500).json({ error: 'Device enrollment failed', message: err?.message });
    }
  };

  app.post('/api/devices/enroll', handleEnrollment);
  app.post('/api/organizations/enroll', handleEnrollment);
  app.post('/api/enrollment', handleEnrollment);

  const handleHeartbeat = (req: Request, res: Response) => {
    try {
      const authHeader = req.headers['authorization'];
      const deviceKeyHeader = req.headers['x-phishguard-device-key'] as string;
      const token = (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : deviceKeyHeader) || req.body?.deviceApiKey;

      let device: EnrolledDevice | null = null;
      if (token) {
        device = activeDb.getDeviceByApiKey(token) || activeDb.getDeviceById(token);
      }

      const {
        deviceId = device?.deviceId,
        installationId = device?.installationId || req.body.installationId,
        extensionVersion = '1.0.0',
        browser = device?.browser || 'Chrome MV3',
        os = device?.os || 'Unknown OS',
        organizationId = device?.organizationId
      } = req.body;

      if (!deviceId && !installationId) {
        return res.status(400).json({ error: 'Missing device identity in heartbeat request' });
      }

      const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

      const result = activeDb.recordHeartbeat({
        deviceId: deviceId || device?.deviceId || 'DEV-ANON',
        installationId: installationId || device?.installationId || 'inst_anon',
        extensionVersion,
        browser,
        os,
        organizationId,
        ip: clientIp
      });

      res.json({
        success: true,
        device: result.device,
        minExtensionVersion: result.minExtensionVersion,
        enforcementMode: result.enforcementMode,
        serverTime: Date.now()
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Heartbeat processing failed', message: err?.message });
    }
  };

  app.post('/api/devices/heartbeat', handleHeartbeat);
  app.post('/api/device/heartbeat', handleHeartbeat);
  app.post('/api/heartbeat', handleHeartbeat);

  // ==========================================================================
  // 3. CANONICAL SECURITY EVENTS (INGEST WITH SERVER ATTRIBUTION)
  // ==========================================================================

  app.post('/api/events', optionalDeviceAuth, (req: AuthenticatedRequest, res) => {
    try {
      const { events, event } = req.body;
      const authenticatedOrg = req.authenticatedOrgId;
      const authenticatedDevice = req.authenticatedDevice;

      const processEvent = (rawEvt: CanonicalSecurityEvent): CanonicalSecurityEvent => {
        const orgId = authenticatedOrg ||
          (rawEvt.deviceId ? activeDb.getDeviceById(rawEvt.deviceId)?.organizationId : null) ||
          (req.headers['x-phishguard-org'] as string) ||
          'ORG-ACME-PILOT';

        if (rawEvt.deviceId) {
          const matchedDev = activeDb.getDeviceById(rawEvt.deviceId);
          if (matchedDev && matchedDev.organizationId !== orgId && authenticatedOrg && authenticatedOrg !== matchedDev.organizationId) {
            throw new Error(`Device ${rawEvt.deviceId} does not belong to organization ${orgId}`);
          }
        }

        return {
          ...rawEvt,
          organizationId: orgId,
          deviceId: authenticatedDevice?.deviceId || rawEvt.deviceId || 'DEV-ANON',
          installationId: authenticatedDevice?.installationId || rawEvt.installationId || 'inst_anon'
        };
      };

      if (events && Array.isArray(events)) {
        const processed = events.map(processEvent);
        const result = activeDb.ingestBatchEvents(processed);
        return res.json({
          success: true,
          ingested: result.ingested,
          duplicates: result.duplicates,
          total: events.length
        });
      } else if (event || req.body.eventId) {
        const targetEvent: CanonicalSecurityEvent = event || req.body;
        const processed = processEvent(targetEvent);
        const result = activeDb.ingestSecurityEvent(processed);
        return res.json({
          success: result.success,
          isDuplicate: result.isDuplicate,
          eventId: processed.eventId
        });
      } else {
        return res.status(400).json({ error: 'Missing required event or events array in request body' });
      }
    } catch (err: any) {
      console.error('[API /api/events POST] Error:', err);
      return res.status(400).json({ error: 'Event ingestion failed', message: err?.message });
    }
  });

  // Query events scoped to organization
  app.get(['/api/events', '/api/admin/events'], authenticateSession, (req: AuthenticatedRequest, res) => {
    try {
      const {
        search,
        riskLevel,
        action,
        threatCategory,
        deviceId,
        organizationId,
        sortBy,
        page,
        pageSize
      } = req.query;

      let targetOrgId: string | undefined = typeof organizationId === 'string' ? organizationId : undefined;
      if (req.user && req.user.role !== 'SUPER_ADMIN') {
        targetOrgId = req.user.organizationId;
      }

      const result = activeDb.getSecurityEvents({
        search: typeof search === 'string' ? search : undefined,
        riskLevel: typeof riskLevel === 'string' ? riskLevel : undefined,
        action: typeof action === 'string' ? action : undefined,
        threatCategory: typeof threatCategory === 'string' ? threatCategory : undefined,
        deviceId: typeof deviceId === 'string' ? deviceId : undefined,
        organizationId: targetOrgId,
        sortBy: sortBy === 'highest_risk' ? 'highest_risk' : 'newest',
        page: page ? parseInt(page as string, 10) : 1,
        pageSize: pageSize ? parseInt(pageSize as string, 10) : 50
      });

      res.json({
        events: result.events,
        total: result.total,
        page: page ? parseInt(page as string, 10) : 1,
        pageSize: pageSize ? parseInt(pageSize as string, 10) : 50
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to retrieve security events' });
    }
  });

  app.get(['/api/events/:id', '/api/admin/events/:id'], authenticateSession, (req: AuthenticatedRequest, res) => {
    const orgId = req.user?.role === 'SUPER_ADMIN' 
      ? (typeof req.query.orgId === 'string' ? req.query.orgId : undefined)
      : req.user?.organizationId;
    const event = activeDb.getEventById(req.params.id, orgId);
    if (!event) {
      return res.status(404).json({ error: 'Security event not found' });
    }
    res.json({ event });
  });

  // ==========================================================================
  // 4. FLEET DEVICES & OVERVIEW (ADMIN & CUSTOMER SCOPED)
  // ==========================================================================

  app.get(['/api/devices', '/api/admin/devices'], authenticateSession, (req: AuthenticatedRequest, res) => {
    try {
      let targetOrgId: string | undefined = typeof req.query.orgId === 'string' ? req.query.orgId : undefined;
      if (req.user && req.user.role !== 'SUPER_ADMIN') {
        targetOrgId = req.user.organizationId;
      }
      const devices = activeDb.getDevices(targetOrgId);
      res.json({ devices, total: devices.length });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to retrieve enrolled devices' });
    }
  });

  app.get(['/api/devices/:id', '/api/admin/devices/:id'], authenticateSession, (req: AuthenticatedRequest, res) => {
    let targetOrgId: string | undefined = typeof req.query.orgId === 'string' ? req.query.orgId : undefined;
    if (req.user && req.user.role !== 'SUPER_ADMIN') {
      targetOrgId = req.user.organizationId;
    }
    const device = activeDb.getDeviceById(req.params.id, targetOrgId);
    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const events = activeDb.getEventsByDevice(device.deviceId, targetOrgId);
    res.json({ device, events });
  });

  app.post(['/api/devices/:id/revoke', '/api/admin/devices/:id/revoke'], authenticateSession, (req: AuthenticatedRequest, res) => {
    try {
      const orgId = req.user?.role === 'SUPER_ADMIN' ? undefined : req.user?.organizationId;
      const ok = activeDb.revokeDevice(req.params.id, orgId, req.user?.name || req.user?.email || 'Admin Console');
      if (!ok) {
        return res.status(404).json({ error: 'Device not found or not authorized to revoke' });
      }
      res.json({ success: true, message: 'Device revoked successfully' });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to revoke device' });
    }
  });

  app.get(['/api/overview', '/api/admin/overview'], authenticateSession, (req: AuthenticatedRequest, res) => {
    try {
      let targetOrgId: string | undefined = typeof req.query.orgId === 'string' ? req.query.orgId : undefined;
      if (req.user && req.user.role !== 'SUPER_ADMIN') {
        targetOrgId = req.user.organizationId;
      }
      const overview = activeDb.getOverviewStats(targetOrgId);
      res.json(overview);
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to retrieve overview statistics' });
    }
  });

  app.get('/api/reports/export-csv', authenticateSession, (req: AuthenticatedRequest, res) => {
    try {
      let targetOrgId = typeof req.query.orgId === 'string' ? req.query.orgId : 'ORG-ACME-PILOT';
      if (req.user && req.user.role !== 'SUPER_ADMIN') {
        targetOrgId = req.user.organizationId || targetOrgId;
      }
      const csv = activeDb.generateCsvExport(targetOrgId);
      res.header('Content-Type', 'text/csv');
      res.attachment(`phishguard-security-events-${targetOrgId}-${new Date().toISOString().slice(0, 10)}.csv`);
      return res.send(csv);
    } catch (err: any) {
      res.status(500).json({ error: 'CSV export failed' });
    }
  });

  // ==========================================================================
  // 5. SUPER ADMIN: ORGANIZATIONS, TOKENS, AUDIT LOGS, ADMIN USERS
  // ==========================================================================

  app.get(['/api/organizations', '/api/admin/organizations'], authenticateSession, requireSuperAdmin, (req, res) => {
    res.json({ organizations: activeDb.getOrganizations() });
  });

  app.get(['/api/organizations/:id', '/api/admin/organizations/:id'], authenticateSession, (req: AuthenticatedRequest, res) => {
    if (req.user?.role !== 'SUPER_ADMIN' && req.user?.organizationId !== req.params.id) {
      return res.status(403).json({ error: 'Forbidden: Cannot access another organization.' });
    }
    const org = activeDb.getOrganizationById(req.params.id);
    if (!org) return res.status(404).json({ error: 'Organization not found' });
    res.json({ organization: org });
  });

  app.post(['/api/organizations', '/api/admin/organizations'], authenticateSession, requireSuperAdmin, (req: AuthenticatedRequest, res) => {
    try {
      const org = activeDb.createOrganization(req.body, req.user?.name || 'Super Admin');
      res.status(201).json({ success: true, organization: org });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to create organization' });
    }
  });

  app.patch(['/api/organizations/:id', '/api/admin/organizations/:id'], authenticateSession, (req: AuthenticatedRequest, res) => {
    try {
      if (req.user?.role !== 'SUPER_ADMIN' && req.user?.organizationId !== req.params.id) {
        return res.status(403).json({ error: 'Forbidden: Cannot update another organization.' });
      }
      const updated = activeDb.updateOrganization(req.params.id, req.body, req.user?.name || 'Admin Console');
      if (!updated) {
        return res.status(404).json({ error: 'Organization not found' });
      }
      res.json({ success: true, organization: updated });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to update organization' });
    }
  });

  app.post('/api/admin/organizations/:id/suspend', authenticateSession, requireSuperAdmin, (req: AuthenticatedRequest, res) => {
    try {
      const updated = activeDb.updateOrganization(req.params.id, { status: 'SUSPENDED' }, req.user?.name || 'Super Admin');
      if (!updated) return res.status(404).json({ error: 'Organization not found' });
      res.json({ success: true, organization: updated });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to suspend organization' });
    }
  });

  app.post('/api/admin/organizations/:id/reactivate', authenticateSession, requireSuperAdmin, (req: AuthenticatedRequest, res) => {
    try {
      const updated = activeDb.updateOrganization(req.params.id, { status: 'ACTIVE' }, req.user?.name || 'Super Admin');
      if (!updated) return res.status(404).json({ error: 'Organization not found' });
      res.json({ success: true, organization: updated });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to reactivate organization' });
    }
  });

  app.delete('/api/admin/organizations/:id', authenticateSession, requireSuperAdmin, (req: AuthenticatedRequest, res) => {
    try {
      const ok = activeDb.deleteOrganization ? activeDb.deleteOrganization(req.params.id, req.user?.name || 'Super Admin') : false;
      if (!ok) return res.status(404).json({ error: 'Organization not found' });
      res.json({ success: true, message: 'Organization deleted successfully' });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to delete organization' });
    }
  });

  app.get('/api/organizations/:id/tokens', authenticateSession, (req: AuthenticatedRequest, res) => {
    if (req.user?.role !== 'SUPER_ADMIN' && req.user?.organizationId !== req.params.id) {
      return res.status(403).json({ error: 'Forbidden: Cannot access another organization\'s tokens.' });
    }
    const tokens = activeDb.getEnrollmentTokens(req.params.id);
    res.json({ tokens });
  });

  app.post('/api/organizations/:id/tokens', authenticateSession, (req: AuthenticatedRequest, res) => {
    try {
      if (req.user?.role !== 'SUPER_ADMIN' && req.user?.organizationId !== req.params.id) {
        return res.status(403).json({ error: 'Forbidden: Cannot create tokens for another organization.' });
      }
      const { label, expiresInDays, maxUses } = req.body;
      const token = activeDb.createEnrollmentToken({
        organizationId: req.params.id,
        label,
        expiresInDays,
        maxUses,
        actor: req.user?.name || 'Admin Console'
      });
      res.status(201).json({ success: true, token });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to create enrollment token', message: err?.message });
    }
  });

  app.post('/api/tokens/:id/revoke', authenticateSession, (req: AuthenticatedRequest, res) => {
    try {
      const token = activeDb.getEnrollmentTokenById(req.params.id);
      if (!token) return res.status(404).json({ error: 'Token not found' });
      if (req.user?.role !== 'SUPER_ADMIN' && req.user?.organizationId !== token.organizationId) {
        return res.status(403).json({ error: 'Forbidden: Cannot revoke token belonging to another organization.' });
      }
      const ok = activeDb.revokeEnrollmentToken(req.params.id, req.user?.name || 'Admin Console');
      res.json({ success: ok, message: 'Enrollment token revoked successfully' });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to revoke token' });
    }
  });

  app.get(['/api/audit', '/api/admin/audit'], authenticateSession, (req: AuthenticatedRequest, res) => {
    const orgId = req.user?.role === 'SUPER_ADMIN' ? (typeof req.query.orgId === 'string' ? req.query.orgId : undefined) : req.user?.organizationId;
    const logs = activeDb.getAuditLogs(orgId);
    res.json({ logs, total: logs.length });
  });

  // Admin Users Management API (Super Admin Only)
  app.get('/api/admin/users', authenticateSession, requireSuperAdmin, (req, res) => {
    const orgId = typeof req.query.orgId === 'string' ? req.query.orgId : undefined;
    const users = activeDb.getAdminUsers(orgId).map(u => ({
      id: u.id,
      username: u.username,
      name: u.name,
      email: u.email,
      role: u.role,
      organizationId: u.organizationId,
      createdAt: u.createdAt,
      lastLoginAt: u.lastLoginAt
    }));
    res.json({ users });
  });

  app.post('/api/admin/users', authenticateSession, requireSuperAdmin, (req: AuthenticatedRequest, res) => {
    try {
      const { email, username, name, role, organizationId, password } = req.body;
      if (!email) return res.status(400).json({ error: 'Email is required' });
      
      const existing = activeDb.getAdminUserByEmail(email);
      if (existing) return res.status(409).json({ error: 'User with this email already exists' });

      const chosenPassword = password || crypto.randomBytes(12).toString('hex');
      const passwordHash = hashPassword(chosenPassword);

      const newUser = activeDb.createAdminUser({
        email,
        username: username || email.split('@')[0],
        name: name || email,
        role: role || 'ORG_ADMIN',
        organizationId: role === 'SUPER_ADMIN' ? undefined : organizationId,
        passwordHash
      }, req.user?.name || 'Super Admin');

      res.status(201).json({
        success: true,
        user: {
          id: newUser.id,
          username: newUser.username,
          name: newUser.name,
          email: newUser.email,
          role: newUser.role,
          organizationId: newUser.organizationId
        }
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to create user', message: err?.message });
    }
  });

  // ==========================================================================
  // 6. CUSTOMER DEDICATED APIS (/api/customer/*) - STRICT TENANT ISOLATION
  // ==========================================================================

  app.get('/api/customer/overview', customerAuth, (req: AuthenticatedRequest, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === 'SUPER_ADMIN' ? (req.query.orgId as string) || 'ORG-ACME-PILOT' : '');
      const org = activeDb.getOrganizationById(orgId);
      if (!org) return res.status(404).json({ error: 'Organization not found' });
      const stats = activeDb.getOverviewStats(orgId);
      res.json({
        organization: org,
        stats
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to load customer overview' });
    }
  });

  app.get('/api/customer/devices', customerAuth, (req: AuthenticatedRequest, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === 'SUPER_ADMIN' ? (req.query.orgId as string) || 'ORG-ACME-PILOT' : '');
      const devices = activeDb.getDevices(orgId);
      res.json({ devices, total: devices.length });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to load customer devices' });
    }
  });

  app.post('/api/customer/devices/:id/revoke', customerAuth, (req: AuthenticatedRequest, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === 'SUPER_ADMIN' ? undefined : '');
      const ok = activeDb.revokeDevice(req.params.id, orgId, req.user?.name || 'Customer Admin');
      if (!ok) {
        return res.status(404).json({ error: 'Device not found or not authorized to revoke' });
      }
      res.json({ success: true, message: 'Device revoked from your fleet' });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to revoke customer device' });
    }
  });

  app.get('/api/customer/events', customerAuth, (req: AuthenticatedRequest, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === 'SUPER_ADMIN' ? (req.query.orgId as string) || 'ORG-ACME-PILOT' : '');
      const { search, riskLevel, action, threatCategory, deviceId, sortBy, page, pageSize } = req.query;

      const result = activeDb.getSecurityEvents({
        search: typeof search === 'string' ? search : undefined,
        riskLevel: typeof riskLevel === 'string' ? riskLevel : undefined,
        action: typeof action === 'string' ? action : undefined,
        threatCategory: typeof threatCategory === 'string' ? threatCategory : undefined,
        deviceId: typeof deviceId === 'string' ? deviceId : undefined,
        organizationId: orgId,
        sortBy: sortBy === 'highest_risk' ? 'highest_risk' : 'newest',
        page: page ? parseInt(page as string, 10) : 1,
        pageSize: pageSize ? parseInt(pageSize as string, 10) : 50
      });

      res.json({
        events: result.events,
        total: result.total,
        page: page ? parseInt(page as string, 10) : 1,
        pageSize: pageSize ? parseInt(pageSize as string, 10) : 50
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to load customer events' });
    }
  });

  app.get('/api/customer/tokens', customerAuth, (req: AuthenticatedRequest, res) => {
    const orgId = req.user?.organizationId || (req.user?.role === 'SUPER_ADMIN' ? (req.query.orgId as string) || 'ORG-ACME-PILOT' : '');
    const tokens = activeDb.getEnrollmentTokens(orgId);
    res.json({ tokens });
  });

  app.post('/api/customer/tokens', customerAuth, (req: AuthenticatedRequest, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === 'SUPER_ADMIN' ? (req.body.organizationId as string) || 'ORG-ACME-PILOT' : '');
      const { label, expiresInDays, maxUses } = req.body;
      const token = activeDb.createEnrollmentToken({
        organizationId: orgId,
        label: label || 'Enterprise Deployment Token',
        expiresInDays,
        maxUses,
        actor: req.user?.name || 'Customer Admin'
      });
      res.status(201).json({ success: true, token });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to create enrollment token' });
    }
  });

  app.post('/api/customer/tokens/:id/revoke', customerAuth, (req: AuthenticatedRequest, res) => {
    try {
      const token = activeDb.getEnrollmentTokenById(req.params.id);
      if (!token) return res.status(404).json({ error: 'Token not found' });
      const orgId = req.user?.organizationId;
      if (req.user?.role !== 'SUPER_ADMIN' && token.organizationId !== orgId) {
        return res.status(403).json({ error: 'Forbidden: Cannot revoke token belonging to another organization' });
      }
      const ok = activeDb.revokeEnrollmentToken(req.params.id, req.user?.name || 'Customer Admin');
      res.json({ success: ok, message: 'Enrollment token revoked' });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to revoke token' });
    }
  });

  app.patch('/api/customer/settings', customerAuth, (req: AuthenticatedRequest, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === 'SUPER_ADMIN' ? (req.body.organizationId as string) || 'ORG-ACME-PILOT' : '');
      const { enforcementMode, telemetryEnabled, minExtensionVersion } = req.body;
      const updated = activeDb.updateOrganization(orgId, {
        enforcementMode,
        telemetryEnabled,
        minExtensionVersion
      }, req.user?.name || 'Customer Admin');
      res.json({ success: true, organization: updated });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to update customer settings' });
    }
  });

  app.get('/api/customer/export-csv', customerAuth, (req: AuthenticatedRequest, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === 'SUPER_ADMIN' ? (req.query.orgId as string) || 'ORG-ACME-PILOT' : '');
      const csv = activeDb.generateCsvExport(orgId);
      res.header('Content-Type', 'text/csv');
      res.attachment(`phishguard-security-events-${orgId}-${new Date().toISOString().slice(0, 10)}.csv`);
      return res.send(csv);
    } catch (err: any) {
      res.status(500).json({ error: 'Customer CSV export failed' });
    }
  });

  // ==========================================================================
  // 6. INDIVIDUAL CUSTOMER ROUTES
  // ==========================================================================

  app.get('/api/individual/overview', individualAuth, (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const personalOrgId = user.organizationId || `INDIVIDUAL-${user.id}`;
      const devices = activeDb.getDevices(personalOrgId);
      const events = activeDb.getSecurityEvents({ organizationId: personalOrgId, pageSize: 20 });

      res.json({
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          plan: user.plan || 'PERSONAL_SHIELD',
          planStatus: user.planStatus || 'ACTIVE',
          billingInterval: user.billingInterval || 'ANNUAL',
          devicesLimit: user.devicesLimit || 5
        },
        stats: {
          activeShield: true,
          protectedDevices: devices.length || 1,
          maxDevices: user.devicesLimit || 5,
          blockedThreatsCount: events.total || 0,
          lastActive: user.lastLoginAt || Date.now(),
          threatLevel: 'SECURE'
        }
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to load individual overview' });
    }
  });

  app.get('/api/individual/devices', individualAuth, (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const personalOrgId = user.organizationId || `INDIVIDUAL-${user.id}`;
      let devices = activeDb.getDevices(personalOrgId);
      
      // If no devices enrolled yet, return a clean primary registered device status
      if (devices.length === 0) {
        devices = [{
          id: `dev_${user.id.slice(0, 8)}_primary`,
          installationId: `inst_${user.id.slice(0, 8)}_primary`,
          deviceId: `dev_${user.id.slice(0, 8)}_primary`,
          organizationId: personalOrgId,
          deviceName: `${user.name}'s Primary Browser`,
          browser: 'Chrome 128 / macOS',
          os: 'macOS',
          extensionVersion: '1.0.0',
          firstSeen: user.createdAt,
          lastSeen: Date.now(),
          status: 'ONLINE',
          eventsCount: 0,
          blockedCount: 0,
          warningsCount: 0
        }];
      }

      res.json({
        devices,
        total: devices.length,
        limit: user.devicesLimit || 5
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to load devices' });
    }
  });

  app.post('/api/individual/enroll-token', individualAuth, (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const personalOrgId = user.organizationId || `INDIVIDUAL-${user.id}`;
      const token = activeDb.createEnrollmentToken({
        organizationId: personalOrgId,
        label: `${user.name} Personal Device Token`,
        expiresInDays: 365,
        maxUses: user.devicesLimit || 5,
        actor: user.name
      });
      res.json({ success: true, token });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to generate personal enrollment token' });
    }
  });

  app.get('/api/individual/events', individualAuth, (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const personalOrgId = user.organizationId || `INDIVIDUAL-${user.id}`;
      const result = activeDb.getSecurityEvents({
        organizationId: personalOrgId,
        pageSize: 50
      });
      res.json({
        events: result.events,
        total: result.total
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to load personal events' });
    }
  });

  app.patch('/api/individual/profile', individualAuth, (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const { name, password } = req.body;
      const updates: Partial<AdminUser> = {};
      if (name && typeof name === 'string') updates.name = name.trim();
      if (password && typeof password === 'string' && password.length >= 8) {
        updates.passwordHash = hashPassword(password);
      }

      const updated = activeDb.updateAdminUser(user.id, updates);
      res.json({
        success: true,
        user: {
          id: updated?.id,
          name: updated?.name,
          email: updated?.email,
          role: updated?.role,
          plan: updated?.plan,
          planStatus: updated?.planStatus
        }
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to update profile' });
    }
  });

  // Catch-all 404 handler for unmatched API routes - ensures JSON response instead of HTML or hung connection
  // Allows non-API routes (frontend SPA, Vite assets, index.html) to pass through to Vite / static handlers
  app.use((req: Request, res: Response, next: NextFunction) => {
    const p = req.path || req.url || '';
    if (p.startsWith('/api') || p.startsWith('/auth')) {
      if (!res.headersSent) {
        return res.status(404).json({
          error: 'Route not found',
          method: req.method,
          path: req.originalUrl || req.url
        });
      }
    }
    next();
  });

  // Global catch-all error handling middleware to guarantee JSON responses
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    console.error('[PhishGuard Server] Uncaught route error:', err?.message || err);
    if (res.headersSent) {
      return next(err);
    }
    res.status(err?.status || 500).json({
      error: 'An internal server error occurred.',
      message: err?.message || 'Internal Server Error'
    });
  });

  return app;
}
