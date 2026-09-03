// src/server/app.ts
import express from "express";
import crypto5 from "crypto";

// src/server/storage/jsonFileAdapter.ts
import fs from "fs";
import path from "path";
import crypto2 from "crypto";

// src/server/authUtils.ts
import crypto from "crypto";
var loginAttempts = /* @__PURE__ */ new Map();
function hashPassword(password) {
  if (!password || typeof password !== "string") {
    throw new Error("Password must be a non-empty string");
  }
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt:${salt}:${derivedKey.toString("hex")}`;
}
function verifyPassword(password, storedHash) {
  if (!password || !storedHash) return false;
  try {
    if (storedHash.startsWith("scrypt:")) {
      const parts = storedHash.split(":");
      if (parts.length !== 3) return false;
      const salt = parts[1];
      const originalHash = parts[2];
      const derivedKey = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
      const derivedKeyHex = derivedKey.toString("hex");
      if (derivedKeyHex.length !== originalHash.length) return false;
      return crypto.timingSafeEqual(Buffer.from(derivedKeyHex, "hex"), Buffer.from(originalHash, "hex"));
    }
    const sha256 = crypto.createHash("sha256").update(password).digest("hex");
    if (storedHash.length === sha256.length) {
      return crypto.timingSafeEqual(Buffer.from(sha256, "hex"), Buffer.from(storedHash, "hex"));
    }
  } catch (err) {
    return false;
  }
  return false;
}
function checkRateLimit(key, maxAttempts = 10, windowMs = 15 * 60 * 1e3) {
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (!entry || now > entry.resetAt) {
    loginAttempts.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: maxAttempts - 1, resetInSec: Math.ceil(windowMs / 1e3) };
  }
  entry.count += 1;
  const remaining = Math.max(0, maxAttempts - entry.count);
  const resetInSec = Math.ceil((entry.resetAt - now) / 1e3);
  if (entry.count > maxAttempts) {
    return { allowed: false, remaining: 0, resetInSec };
  }
  return { allowed: true, remaining, resetInSec };
}
function resetRateLimit(key) {
  loginAttempts.delete(key);
}

// src/server/storage/jsonFileAdapter.ts
var isServerless = !!process.env.VERCEL || !!process.env.AWS_LAMBDA_FUNCTION_NAME || !!process.env.NOW_REGION;
var FALLBACK_RO_FILE = path.resolve(process.cwd(), "data", "phishguard-db.json");
var DB_DIR = isServerless ? "/tmp" : path.resolve(process.cwd(), "data");
var DB_FILE = path.join(DB_DIR, "phishguard-db.json");
var MAX_EVENTS_RETENTION = 1e4;
var ONLINE_THRESHOLD_MS = 5 * 60 * 1e3;
var JsonFileDatabaseAdapter = class {
  constructor(customFilePath) {
    this.data = {
      organizations: [],
      enrollmentTokens: [],
      devices: [],
      adminUsers: [],
      securityEvents: [],
      auditLogs: []
    };
    // Fast In-Memory Lookup Indexes
    this.orgIndex = /* @__PURE__ */ new Map();
    this.tokenIndex = /* @__PURE__ */ new Map();
    // By token string
    this.tokenHashIndex = /* @__PURE__ */ new Map();
    // By tokenHash
    this.deviceApiKeyIndex = /* @__PURE__ */ new Map();
    // By deviceApiKey
    this.deviceIdIndex = /* @__PURE__ */ new Map();
    // By "orgId:deviceId"
    this.eventIdSet = /* @__PURE__ */ new Set();
    this.isLoaded = false;
    this.filePath = customFilePath || DB_FILE;
    this.init();
  }
  init() {
    try {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        try {
          fs.mkdirSync(dir, { recursive: true });
        } catch (mkErr) {
          console.warn("[PhishGuard DB] Directory creation non-fatal warning:", mkErr);
        }
      }
      let sourceFile = this.filePath;
      if (!fs.existsSync(sourceFile) && fs.existsSync(FALLBACK_RO_FILE)) {
        sourceFile = FALLBACK_RO_FILE;
      }
      if (fs.existsSync(sourceFile)) {
        const raw = fs.readFileSync(sourceFile, "utf-8");
        const parsed = JSON.parse(raw);
        this.data = {
          organizations: parsed.organizations || [],
          enrollmentTokens: parsed.enrollmentTokens || [],
          devices: parsed.devices || [],
          securityEvents: parsed.securityEvents || [],
          auditLogs: parsed.auditLogs || [],
          adminUsers: parsed.adminUsers || []
        };
        if (this.data.organizations.length === 0) {
          this.seedInitialPilotData();
        }
        if (!this.data.adminUsers || this.data.adminUsers.length === 0) {
          this.seedInitialAdminUsers();
        }
        if (process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD) {
          const superAdmin = this.data.adminUsers.find(
            (u) => u.role === "SUPER_ADMIN" || u.username === "admin" || u.email === "admin@phishguard.security"
          );
          if (superAdmin) {
            superAdmin.passwordHash = hashPassword(process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD);
          }
        }
        const orgAdminPass = process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ACME_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
        let acmeAdmin = this.data.adminUsers.find(
          (u) => u.organizationId === "ORG-ACME-PILOT" && u.role === "ORG_ADMIN" || u.username === "acme_admin" || u.email === "it-admin@acme-corp.com"
        );
        if (!acmeAdmin) {
          acmeAdmin = {
            id: "usr_acme_admin_01",
            username: "acme_admin",
            name: "Alex Rivera (IT Lead)",
            email: "it-admin@acme-corp.com",
            role: "ORG_ADMIN",
            organizationId: "ORG-ACME-PILOT",
            passwordHash: orgAdminPass ? hashPassword(orgAdminPass) : "DISABLED:UNINITIALIZED_BOOTSTRAP",
            apiKey: crypto2.randomBytes(24).toString("hex"),
            createdAt: Date.now() - 15 * 864e5,
            lastLoginAt: 0
          };
          this.data.adminUsers.push(acmeAdmin);
        } else if (orgAdminPass && (acmeAdmin.passwordHash.startsWith("DISABLED:") || acmeAdmin.passwordHash !== hashPassword(orgAdminPass))) {
          acmeAdmin.passwordHash = hashPassword(orgAdminPass);
        }
        this.rebuildIndexes();
        this.persist();
        this.isLoaded = true;
      } else {
        this.seedInitialPilotData();
        this.seedInitialAdminUsers();
        this.rebuildIndexes();
        this.persist();
      }
    } catch (err) {
      console.warn("[PhishGuard DB] Initializing fresh database state:", err);
      this.seedInitialPilotData();
      this.seedInitialAdminUsers();
      this.rebuildIndexes();
    }
  }
  seedInitialAdminUsers() {
    const now = Date.now();
    const initialPass = process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
    const scryptPasswordHash = initialPass ? hashPassword(initialPass) : "DISABLED:UNINITIALIZED_BOOTSTRAP";
    const orgAdminPass = process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ACME_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
    const orgAdminHash = orgAdminPass ? hashPassword(orgAdminPass) : "DISABLED:UNINITIALIZED_BOOTSTRAP";
    this.data.adminUsers = [
      {
        id: "usr_super_admin_01",
        username: "admin",
        name: "SecOps Director",
        email: "admin@phishguard.security",
        role: "SUPER_ADMIN",
        passwordHash: scryptPasswordHash,
        apiKey: crypto2.randomBytes(24).toString("hex"),
        createdAt: now - 30 * 864e5,
        lastLoginAt: now - 36e5
      },
      {
        id: "usr_acme_admin_01",
        username: "acme_admin",
        name: "Alex Rivera (IT Lead)",
        email: "it-admin@acme-corp.com",
        role: "ORG_ADMIN",
        organizationId: "ORG-ACME-PILOT",
        passwordHash: orgAdminHash,
        apiKey: crypto2.randomBytes(24).toString("hex"),
        createdAt: now - 15 * 864e5,
        lastLoginAt: now - 72e5
      },
      {
        id: "usr_individual_01",
        username: "janedoe",
        name: "Jane Doe",
        email: "jane.doe@example.com",
        role: "INDIVIDUAL",
        plan: "PERSONAL_SHIELD",
        planStatus: "ACTIVE",
        billingInterval: "ANNUAL",
        devicesLimit: 3,
        passwordHash: scryptPasswordHash,
        apiKey: crypto2.randomBytes(24).toString("hex"),
        createdAt: now - 10 * 864e5,
        lastLoginAt: now - 18e5
      }
    ];
  }
  rebuildIndexes() {
    this.orgIndex.clear();
    this.tokenIndex.clear();
    this.tokenHashIndex.clear();
    this.deviceApiKeyIndex.clear();
    this.deviceIdIndex.clear();
    this.eventIdSet.clear();
    const uniqueOrgs = [];
    const seenOrgIds = /* @__PURE__ */ new Set();
    for (const org of this.data.organizations) {
      if (!seenOrgIds.has(org.organizationId)) {
        seenOrgIds.add(org.organizationId);
        uniqueOrgs.push(org);
        this.orgIndex.set(org.organizationId, org);
      }
    }
    this.data.organizations = uniqueOrgs;
    const uniqueTokens = [];
    const seenTokenKeys = /* @__PURE__ */ new Set();
    for (const tok of this.data.enrollmentTokens) {
      const key = tok.tokenHash || tok.token || tok.id;
      if (!seenTokenKeys.has(key)) {
        seenTokenKeys.add(key);
        uniqueTokens.push(tok);
        if (tok.token) this.tokenIndex.set(tok.token, tok);
        if (tok.tokenHash) this.tokenHashIndex.set(tok.tokenHash, tok);
      }
    }
    this.data.enrollmentTokens = uniqueTokens;
    const uniqueDevices = [];
    const seenDevKeys = /* @__PURE__ */ new Set();
    for (const dev of this.data.devices) {
      const key = `${dev.organizationId}:${dev.deviceId}`;
      if (!seenDevKeys.has(key)) {
        seenDevKeys.add(key);
        uniqueDevices.push(dev);
        if (dev.deviceApiKey) this.deviceApiKeyIndex.set(dev.deviceApiKey, dev);
        this.deviceIdIndex.set(key, dev);
      }
    }
    this.data.devices = uniqueDevices;
    const uniqueUsers = [];
    const seenUserKeys = /* @__PURE__ */ new Set();
    for (const u of this.data.adminUsers || []) {
      const key = u.id || u.email.toLowerCase();
      if (!seenUserKeys.has(key)) {
        seenUserKeys.add(key);
        uniqueUsers.push(u);
      }
    }
    this.data.adminUsers = uniqueUsers;
    for (const evt of this.data.securityEvents) {
      this.eventIdSet.add(evt.eventId);
    }
  }
  persist() {
    try {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), "utf-8");
    } catch (err) {
      console.error("[PhishGuard DB] Persistence write failure:", err);
    }
  }
  hashToken(token) {
    return crypto2.createHash("sha256").update(token).digest("hex");
  }
  seedInitialPilotData() {
    const now = Date.now();
    const pilotOrgId = "ORG-ACME-PILOT";
    const pilotToken = "pg_enroll_acme_pilot_2026";
    const pilotTokenHash = this.hashToken(pilotToken);
    const defaultOrg = {
      organizationId: pilotOrgId,
      name: "Acme Corporation (Pilot)",
      status: "PILOT",
      enrollmentToken: pilotToken,
      enforcementMode: "BLOCK",
      telemetryEnabled: true,
      retentionDays: 90,
      minExtensionVersion: "1.0.0",
      backendUrl: "http://localhost:3000",
      createdAt: now - 1e3 * 60 * 60 * 24 * 7,
      updatedAt: now
    };
    const defaultToken = {
      id: "tok_acme_pilot_init",
      organizationId: pilotOrgId,
      token: pilotToken,
      tokenHash: pilotTokenHash,
      label: "Initial Pilot Enrollment Token",
      status: "ACTIVE",
      createdAt: now - 1e3 * 60 * 60 * 24 * 7,
      expiresAt: null,
      maxUses: null,
      useCount: 1,
      revokedAt: null,
      revokedBy: null
    };
    this.data.organizations = [defaultOrg];
    this.data.enrollmentTokens = [defaultToken];
    this.data.devices = [];
    this.data.securityEvents = [];
    this.data.auditLogs = [{
      id: "audit_init_001",
      organizationId: pilotOrgId,
      timestamp: now,
      actor: "System Bootstrap",
      action: "ORGANIZATION_INITIALIZED",
      target: pilotOrgId,
      details: "Initialized default organization Acme Corporation for deployment pilot."
    }];
  }
  // ==========================================================================
  // 1. ORGANIZATIONS
  // ==========================================================================
  getOrganizations() {
    return [...this.data.organizations];
  }
  getOrganizationById(organizationId) {
    return this.orgIndex.get(organizationId) || null;
  }
  createOrganization(data, actor = "Admin Console") {
    const orgId = data.organizationId || `ORG-${crypto2.randomBytes(4).toString("hex").toUpperCase()}`;
    const existing = this.getOrganizationById(orgId);
    if (existing) {
      if (data.name) existing.name = data.name;
      if (data.status) existing.status = data.status;
      if (data.enforcementMode) existing.enforcementMode = data.enforcementMode;
      if (data.telemetryEnabled !== void 0) existing.telemetryEnabled = data.telemetryEnabled;
      if (data.minExtensionVersion) existing.minExtensionVersion = data.minExtensionVersion;
      if (data.retentionDays) existing.retentionDays = data.retentionDays;
      if (data.backendUrl) existing.backendUrl = data.backendUrl;
      existing.updatedAt = Date.now();
      this.persist();
      return { ...existing };
    }
    const initialTokenStr = `pg_enroll_${crypto2.randomBytes(16).toString("hex")}`;
    const now = Date.now();
    const newOrg = {
      organizationId: orgId,
      name: data.name || "New Organization",
      status: data.status || "ACTIVE",
      enrollmentToken: initialTokenStr,
      enforcementMode: data.enforcementMode || "BLOCK",
      telemetryEnabled: data.telemetryEnabled ?? true,
      minExtensionVersion: data.minExtensionVersion || "1.0.0",
      retentionDays: data.retentionDays || 90,
      backendUrl: data.backendUrl || "",
      createdAt: now,
      updatedAt: now
    };
    const tokenObj = {
      id: `tok_${crypto2.randomBytes(6).toString("hex")}`,
      organizationId: orgId,
      token: initialTokenStr,
      tokenHash: this.hashToken(initialTokenStr),
      label: "Default Enrollment Token",
      status: "ACTIVE",
      createdAt: now,
      expiresAt: null,
      maxUses: null,
      useCount: 0,
      revokedAt: null,
      revokedBy: null
    };
    this.data.organizations.push(newOrg);
    this.data.enrollmentTokens.push(tokenObj);
    this.rebuildIndexes();
    this.addAuditLog({
      organizationId: orgId,
      actor,
      action: "ORGANIZATION_CREATED",
      target: orgId,
      details: `Created organization ${newOrg.name} (${orgId}) with initial enrollment token.`
    });
    this.persist();
    return newOrg;
  }
  updateOrganization(organizationId, updates, actor = "Admin Console") {
    const org = this.getOrganizationById(organizationId);
    if (!org) return null;
    if (updates.name !== void 0) org.name = updates.name;
    if (updates.status !== void 0) org.status = updates.status;
    if (updates.enforcementMode !== void 0) org.enforcementMode = updates.enforcementMode;
    if (updates.telemetryEnabled !== void 0) org.telemetryEnabled = updates.telemetryEnabled;
    if (updates.minExtensionVersion !== void 0) org.minExtensionVersion = updates.minExtensionVersion;
    if (updates.retentionDays !== void 0) org.retentionDays = updates.retentionDays;
    if (updates.backendUrl !== void 0) org.backendUrl = updates.backendUrl;
    org.updatedAt = Date.now();
    this.addAuditLog({
      organizationId,
      actor,
      action: "ORGANIZATION_POLICY_UPDATED",
      target: organizationId,
      details: `Updated policy: enforcement=${org.enforcementMode}, minVersion=${org.minExtensionVersion}, telemetry=${org.telemetryEnabled}`
    });
    this.persist();
    return { ...org };
  }
  // ==========================================================================
  // 2. ENROLLMENT TOKENS
  // ==========================================================================
  createEnrollmentToken(data) {
    const org = this.getOrganizationById(data.organizationId);
    if (!org) {
      throw new Error(`Organization ${data.organizationId} not found`);
    }
    const tokenStr = `pg_enroll_${crypto2.randomBytes(20).toString("hex")}`;
    const tokenHash = this.hashToken(tokenStr);
    const now = Date.now();
    const expiresAt = data.expiresInDays ? now + data.expiresInDays * 24 * 60 * 60 * 1e3 : null;
    const tokenObj = {
      id: `tok_${crypto2.randomBytes(6).toString("hex")}`,
      organizationId: data.organizationId,
      token: tokenStr,
      tokenHash,
      label: data.label || `Enrollment Token ${(/* @__PURE__ */ new Date()).toISOString().split("T")[0]}`,
      status: "ACTIVE",
      createdAt: now,
      expiresAt,
      maxUses: data.maxUses ?? null,
      useCount: 0,
      revokedAt: null,
      revokedBy: null
    };
    this.data.enrollmentTokens.push(tokenObj);
    this.rebuildIndexes();
    this.addAuditLog({
      organizationId: data.organizationId,
      actor: data.actor || "Admin Console",
      action: "ENROLLMENT_TOKEN_CREATED",
      target: tokenObj.id,
      details: `Generated enrollment token "${tokenObj.label}" (expires: ${expiresAt ? new Date(expiresAt).toISOString() : "Never"})`
    });
    this.persist();
    return tokenObj;
  }
  getEnrollmentTokens(organizationId) {
    return this.data.enrollmentTokens.filter((t) => t.organizationId === organizationId).map((t) => ({ ...t, token: "" }));
  }
  getEnrollmentTokenById(tokenId) {
    return this.data.enrollmentTokens.find((t) => t.id === tokenId) || null;
  }
  validateEnrollmentToken(tokenString) {
    if (!tokenString || typeof tokenString !== "string") {
      return { valid: false, error: "Missing enrollment token string" };
    }
    const tokenObj = this.tokenIndex.get(tokenString) || this.tokenHashIndex.get(this.hashToken(tokenString));
    if (!tokenObj) {
      return { valid: false, error: "Invalid enrollment token" };
    }
    if (tokenObj.status === "REVOKED" || tokenObj.revokedAt !== null) {
      return { valid: false, error: "Enrollment token has been revoked by organization administrator" };
    }
    if (tokenObj.expiresAt && Date.now() > tokenObj.expiresAt) {
      tokenObj.status = "EXPIRED";
      this.persist();
      return { valid: false, error: "Enrollment token has expired" };
    }
    if (tokenObj.maxUses && tokenObj.useCount >= tokenObj.maxUses) {
      return { valid: false, error: "Enrollment token maximum device registration limit reached" };
    }
    return { valid: true, token: tokenObj };
  }
  revokeEnrollmentToken(tokenId, actor = "Admin Console") {
    const token = this.getEnrollmentTokenById(tokenId);
    if (!token) return false;
    token.status = "REVOKED";
    token.revokedAt = Date.now();
    token.revokedBy = actor;
    this.addAuditLog({
      organizationId: token.organizationId,
      actor,
      action: "ENROLLMENT_TOKEN_REVOKED",
      target: token.id,
      details: `Revoked enrollment token "${token.label}" (${token.id})`
    });
    this.persist();
    return true;
  }
  // ==========================================================================
  // 3. DEVICE ENROLLMENT & AUTHENTICATION
  // ==========================================================================
  enrollDevice(data) {
    const validation = this.validateEnrollmentToken(data.enrollmentToken);
    if (!validation.valid || !validation.token) {
      return { success: false, error: validation.error || "Invalid enrollment token" };
    }
    const token = validation.token;
    const org = this.getOrganizationById(token.organizationId);
    if (!org) {
      return { success: false, error: "Organization associated with token does not exist" };
    }
    const existing = this.data.devices.find(
      (d) => d.organizationId === token.organizationId && d.installationId === data.installationId
    );
    const now = Date.now();
    if (existing) {
      existing.extensionVersion = data.extensionVersion;
      existing.browser = data.browser;
      existing.os = data.os;
      existing.platform = data.platform || existing.platform;
      existing.deviceName = data.deviceName || existing.deviceName;
      existing.lastSeen = now;
      existing.lastIp = data.ip || existing.lastIp;
      if (!existing.deviceApiKey) {
        existing.deviceApiKey = `pg_dev_${crypto2.randomBytes(24).toString("hex")}`;
      }
      this.rebuildIndexes();
      this.persist();
      return { success: true, device: { ...existing } };
    }
    const deviceId = `DEV-${crypto2.randomBytes(4).toString("hex").toUpperCase()}`;
    const deviceApiKey = `pg_dev_${crypto2.randomBytes(24).toString("hex")}`;
    const newDevice = {
      id: `dev_${crypto2.randomBytes(6).toString("hex")}`,
      installationId: data.installationId || `inst_${crypto2.randomBytes(8).toString("hex")}`,
      deviceId,
      organizationId: token.organizationId,
      deviceApiKey,
      deviceName: data.deviceName || `Endpoint ${deviceId}`,
      extensionVersion: data.extensionVersion || "1.0.0",
      browser: data.browser || "Chrome MV3",
      platform: data.platform || "Desktop",
      os: data.os || "Unknown OS",
      firstSeen: now,
      lastSeen: now,
      status: "ONLINE",
      eventsCount: 0,
      blockedCount: 0,
      warningsCount: 0,
      lastIp: data.ip
    };
    token.useCount += 1;
    this.data.devices.push(newDevice);
    this.rebuildIndexes();
    this.addAuditLog({
      organizationId: token.organizationId,
      actor: "Device Registration Service",
      action: "DEVICE_ENROLLED",
      target: deviceId,
      details: `Enrolled new endpoint ${deviceId} (${newDevice.os}, ${newDevice.browser}) via token ${token.label}`
    });
    this.persist();
    return { success: true, device: newDevice };
  }
  getDevices(organizationId) {
    const now = Date.now();
    return this.data.devices.filter((d) => !organizationId || d.organizationId === organizationId).map((device) => {
      const org = this.getOrganizationById(device.organizationId);
      const minVersion = org?.minExtensionVersion || "1.0.0";
      let status = "ONLINE";
      if (now - device.lastSeen > ONLINE_THRESHOLD_MS) {
        status = "OFFLINE";
      } else if (device.extensionVersion < minVersion) {
        status = "UPDATE_REQUIRED";
      }
      return {
        ...device,
        status
      };
    });
  }
  getDeviceById(deviceId, organizationId) {
    const devices = this.getDevices(organizationId);
    return devices.find((d) => d.deviceId === deviceId || d.id === deviceId) || null;
  }
  getDeviceByApiKey(apiKey) {
    if (!apiKey) return null;
    return this.deviceApiKeyIndex.get(apiKey) || null;
  }
  revokeDevice(deviceId, organizationId, actor = "Admin Console") {
    const devIndex = this.data.devices.findIndex(
      (d) => (d.deviceId === deviceId || d.id === deviceId) && (!organizationId || d.organizationId === organizationId)
    );
    if (devIndex === -1) return false;
    const dev = this.data.devices[devIndex];
    this.data.devices.splice(devIndex, 1);
    this.rebuildIndexes();
    this.persist();
    this.addAuditLog({
      organizationId: dev.organizationId,
      actor,
      action: "DEVICE_REVOKED",
      target: dev.deviceId,
      details: `Revoked endpoint ${dev.deviceName} (${dev.deviceId}). Device credentials disabled.`
    });
    return true;
  }
  deleteOrganization(organizationId, actor = "Admin Console") {
    const idx = this.data.organizations.findIndex((o) => o.organizationId === organizationId);
    if (idx === -1) return false;
    const org = this.data.organizations[idx];
    this.data.organizations.splice(idx, 1);
    this.data.enrollmentTokens = this.data.enrollmentTokens.filter((t) => t.organizationId !== organizationId);
    this.data.devices = this.data.devices.filter((d) => d.organizationId !== organizationId);
    this.rebuildIndexes();
    this.persist();
    this.addAuditLog({
      organizationId,
      actor,
      action: "ORGANIZATION_DELETED",
      target: organizationId,
      details: `Permanently deleted organization ${org.name} (${organizationId})`
    });
    return true;
  }
  // ==========================================================================
  // ADMIN USERS & RBAC
  // ==========================================================================
  getAdminUsers(organizationId) {
    if (!organizationId) return [...this.data.adminUsers];
    return this.data.adminUsers.filter((u) => u.organizationId === organizationId);
  }
  getAdminUserById(id) {
    return this.data.adminUsers.find((u) => u.id === id) || null;
  }
  getAdminUserByEmail(email) {
    if (!email) return null;
    return this.data.adminUsers.find((u) => u.email.toLowerCase() === email.toLowerCase()) || null;
  }
  createAdminUser(user, actor = "Admin Console") {
    const newUser = {
      ...user,
      id: `usr_${crypto2.randomBytes(6).toString("hex")}`,
      createdAt: Date.now(),
      lastLoginAt: 0
    };
    this.data.adminUsers.push(newUser);
    this.persist();
    this.addAuditLog({
      organizationId: user.organizationId || "GLOBAL",
      actor,
      action: "ADMIN_USER_CREATED",
      target: newUser.id,
      details: `Created administrative user ${newUser.email} with role ${newUser.role}`
    });
    return newUser;
  }
  updateAdminUser(id, updates, actor = "Admin Console") {
    const user = this.data.adminUsers.find((u) => u.id === id);
    if (!user) return null;
    if (updates.name !== void 0) user.name = updates.name;
    if (updates.email !== void 0) user.email = updates.email;
    if (updates.role !== void 0) user.role = updates.role;
    if (updates.passwordHash !== void 0) user.passwordHash = updates.passwordHash;
    if (updates.lastLoginAt !== void 0) user.lastLoginAt = updates.lastLoginAt;
    this.persist();
    this.addAuditLog({
      organizationId: user.organizationId || "GLOBAL",
      actor,
      action: "ADMIN_USER_UPDATED",
      target: user.id,
      details: `Updated administrative user ${user.email}`
    });
    return { ...user };
  }
  deleteAdminUser(id, actor = "Admin Console") {
    const idx = this.data.adminUsers.findIndex((u) => u.id === id);
    if (idx === -1) return false;
    const user = this.data.adminUsers[idx];
    this.data.adminUsers.splice(idx, 1);
    this.persist();
    this.addAuditLog({
      organizationId: user.organizationId || "GLOBAL",
      actor,
      action: "ADMIN_USER_DELETED",
      target: user.id,
      details: `Deleted administrative user ${user.email}`
    });
    return true;
  }
  recordHeartbeat(data) {
    const now = Date.now();
    let device = this.data.devices.find(
      (d) => d.deviceId === data.deviceId || d.installationId === data.installationId && (!data.organizationId || d.organizationId === data.organizationId)
    );
    const orgId = data.organizationId || device?.organizationId || "ORG-ACME-PILOT";
    const org = this.getOrganizationById(orgId) || this.data.organizations[0];
    if (!device) {
      const deviceId = data.deviceId || `DEV-${crypto2.randomBytes(4).toString("hex").toUpperCase()}`;
      device = {
        id: `dev_${crypto2.randomBytes(6).toString("hex")}`,
        installationId: data.installationId || `inst_${crypto2.randomBytes(8).toString("hex")}`,
        deviceId,
        organizationId: orgId,
        deviceApiKey: `pg_dev_${crypto2.randomBytes(24).toString("hex")}`,
        deviceName: `Endpoint ${deviceId}`,
        extensionVersion: data.extensionVersion || "1.0.0",
        browser: data.browser || "Chrome MV3",
        os: data.os || "Unknown OS",
        firstSeen: now,
        lastSeen: now,
        status: "ONLINE",
        eventsCount: 0,
        blockedCount: 0,
        warningsCount: 0,
        lastIp: data.ip
      };
      this.data.devices.push(device);
    } else {
      device.lastSeen = now;
      device.extensionVersion = data.extensionVersion || device.extensionVersion;
      if (data.browser) device.browser = data.browser;
      if (data.os) device.os = data.os;
      if (data.ip) device.lastIp = data.ip;
      device.status = device.extensionVersion < (org?.minExtensionVersion || "1.0.0") ? "UPDATE_REQUIRED" : "ONLINE";
    }
    this.rebuildIndexes();
    this.persist();
    return {
      success: true,
      device: { ...device },
      enforcementMode: org?.enforcementMode || "BLOCK",
      minExtensionVersion: org?.minExtensionVersion || "1.0.0"
    };
  }
  // ==========================================================================
  // 4. CANONICAL SECURITY EVENTS (INGEST, PRIVACY, DEDUPLICATION)
  // ==========================================================================
  sanitizeUrl(rawUrl) {
    try {
      const parsed = new URL(rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`);
      const sensitiveKeys = ["token", "password", "pass", "pwd", "auth", "access_token", "secret", "key", "id_token", "code", "session", "user", "email", "jwt", "api_key"];
      const params = new URLSearchParams(parsed.search);
      for (const k of Array.from(params.keys())) {
        if (sensitiveKeys.some((sk) => k.toLowerCase().includes(sk))) {
          params.set(k, "[REDACTED]");
        }
      }
      const searchStr = decodeURIComponent(params.toString());
      return `${parsed.origin}${parsed.pathname}${searchStr ? `?${searchStr}` : ""}`;
    } catch {
      return rawUrl.replace(/([?&](token|password|pass|key|code|auth|secret|jwt|session)=)[^&]*/gi, "$1[REDACTED]");
    }
  }
  ingestSecurityEvent(event) {
    if (!event.eventId) {
      event.eventId = `evt_${Date.now()}_${crypto2.randomBytes(4).toString("hex")}`;
    }
    if (this.eventIdSet.has(event.eventId)) {
      return { success: true, isDuplicate: true, eventId: event.eventId };
    }
    event.url = this.sanitizeUrl(event.url);
    event.timestamp = event.timestamp || Date.now();
    event.organizationId = event.organizationId || "ORG-ACME-PILOT";
    event.createdAt = event.createdAt || new Date(event.timestamp).toISOString();
    const device = this.data.devices.find(
      (d) => d.organizationId === event.organizationId && d.deviceId === event.deviceId
    );
    if (device) {
      device.eventsCount = (device.eventsCount || 0) + 1;
      if (event.action === "BLOCKED") {
        device.blockedCount = (device.blockedCount || 0) + 1;
      } else if (event.action === "WARNED") {
        device.warningsCount = (device.warningsCount || 0) + 1;
      }
    }
    this.data.securityEvents.unshift(event);
    this.eventIdSet.add(event.eventId);
    if (this.data.securityEvents.length > MAX_EVENTS_RETENTION) {
      const removed = this.data.securityEvents.pop();
      if (removed) this.eventIdSet.delete(removed.eventId);
    }
    this.persist();
    return { success: true, isDuplicate: false, eventId: event.eventId };
  }
  ingestBatchEvents(events) {
    let ingested = 0;
    let duplicates = 0;
    for (const evt of events) {
      const res = this.ingestSecurityEvent(evt);
      if (res.isDuplicate) {
        duplicates++;
      } else if (res.success) {
        ingested++;
      }
    }
    return { ingested, duplicates };
  }
  getSecurityEvents(filter) {
    let list = this.data.securityEvents.filter((e) => {
      if (filter.organizationId && e.organizationId !== filter.organizationId) return false;
      if (filter.deviceId && e.deviceId !== filter.deviceId) return false;
      if (filter.riskLevel && filter.riskLevel !== "ALL" && e.riskLevel !== filter.riskLevel) return false;
      if (filter.action && filter.action !== "ALL" && e.action !== filter.action) return false;
      if (filter.threatCategory && filter.threatCategory !== "ALL" && e.threatCategory !== filter.threatCategory) return false;
      if (filter.search) {
        const q = filter.search.toLowerCase();
        const matchUrl = e.url?.toLowerCase().includes(q);
        const matchHost = e.hostname?.toLowerCase().includes(q);
        const matchBrand = e.brand?.toLowerCase().includes(q);
        const matchDevice = e.deviceId?.toLowerCase().includes(q);
        const matchReasons = e.detectionReasons?.some((r) => r.toLowerCase().includes(q));
        if (!matchUrl && !matchHost && !matchBrand && !matchDevice && !matchReasons) {
          return false;
        }
      }
      return true;
    });
    if (filter.sortBy === "highest_risk") {
      list.sort((a, b) => b.riskScore - a.riskScore);
    } else {
      list.sort((a, b) => b.timestamp - a.timestamp);
    }
    const total = list.length;
    const page = filter.page || 1;
    const pageSize = filter.pageSize || 50;
    const startIndex = (page - 1) * pageSize;
    const paged = list.slice(startIndex, startIndex + pageSize);
    return { events: paged, total };
  }
  getEventById(eventId, organizationId) {
    const evt = this.data.securityEvents.find((e) => e.eventId === eventId);
    if (!evt) return null;
    if (organizationId && evt.organizationId !== organizationId) return null;
    return evt;
  }
  getEventsByDevice(deviceId, organizationId) {
    return this.data.securityEvents.filter(
      (e) => e.deviceId === deviceId && (!organizationId || e.organizationId === organizationId)
    );
  }
  // ==========================================================================
  // 5. METRICS, OVERVIEW & CSV EXPORT
  // ==========================================================================
  getOverviewStats(organizationId) {
    const orgDevices = this.getDevices(organizationId);
    const orgEvents = this.data.securityEvents.filter(
      (e) => !organizationId || e.organizationId === organizationId
    );
    const now = Date.now();
    const twentyFourHoursAgo = now - 24 * 60 * 60 * 1e3;
    const eventsToday = orgEvents.filter((e) => e.timestamp >= twentyFourHoursAgo);
    const blockedToday = eventsToday.filter((e) => e.action === "BLOCKED").length;
    const warningsToday = eventsToday.filter((e) => e.action === "WARNED").length;
    const threatsToday = eventsToday.filter((e) => e.riskScore >= 60).length;
    const onlineDevices = orgDevices.filter((d) => d.status === "ONLINE").length;
    const offlineDevices = orgDevices.filter((d) => d.status === "OFFLINE").length;
    const updateRequiredDevices = orgDevices.filter((d) => d.status === "UPDATE_REQUIRED").length;
    const devicesNeedingAttention = orgDevices.filter((d) => d.status === "NEEDS_ATTENTION" || d.status === "UPDATE_REQUIRED").length;
    const brandCounts = /* @__PURE__ */ new Map();
    for (const evt of orgEvents) {
      if (evt.brand) {
        const cur = brandCounts.get(evt.brand) || { count: 0, category: evt.threatCategory || "OTHER" };
        cur.count++;
        brandCounts.set(evt.brand, cur);
      }
    }
    const topTargetedBrands = Array.from(brandCounts.entries()).map(([brand, data]) => ({ brand, count: data.count, category: data.category })).sort((a, b) => b.count - a.count).slice(0, 5);
    const catCounts = /* @__PURE__ */ new Map();
    for (const evt of orgEvents) {
      const cat = evt.threatCategory || "OTHER";
      catCounts.set(cat, (catCounts.get(cat) || 0) + 1);
    }
    const totalEventsCount = orgEvents.length;
    const topThreatCategories = Array.from(catCounts.entries()).map(([category, count]) => ({
      category,
      count,
      percentage: totalEventsCount > 0 ? Math.round(count / totalEventsCount * 100) : 0
    })).sort((a, b) => b.count - a.count);
    return {
      totalProtectedDevices: orgDevices.length,
      onlineDevices,
      offlineDevices,
      updateRequiredDevices,
      devicesNeedingAttention,
      threatsToday,
      blockedToday,
      warningsToday,
      totalEventsCount,
      topTargetedBrands,
      topThreatCategories,
      recentEvents: orgEvents.slice(0, 10)
    };
  }
  generateCsvExport(organizationId) {
    const events = this.data.securityEvents.filter((e) => e.organizationId === organizationId);
    const headers = [
      "EventID",
      "TimestampISO",
      "OrganizationID",
      "DeviceID",
      "InstallationID",
      "Action",
      "RiskLevel",
      "RiskScore",
      "ThreatCategory",
      "TargetBrand",
      "Hostname",
      "SanitizedURL",
      "DetectionReasons"
    ];
    const rows = events.map((e) => [
      e.eventId,
      new Date(e.timestamp).toISOString(),
      e.organizationId,
      e.deviceId,
      e.installationId,
      e.action,
      e.riskLevel,
      String(e.riskScore),
      e.threatCategory || "OTHER",
      e.brand || "",
      e.hostname,
      `"${(e.url || "").replace(/"/g, '""')}"`,
      `"${(e.detectionReasons || []).join("; ").replace(/"/g, '""')}"`
    ]);
    return [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
  }
  // ==========================================================================
  // 6. AUDIT LOGS
  // ==========================================================================
  addAuditLog(entry) {
    const log = {
      id: `audit_${Date.now()}_${crypto2.randomBytes(3).toString("hex")}`,
      timestamp: Date.now(),
      organizationId: entry.organizationId,
      actor: entry.actor,
      action: entry.action,
      target: entry.target,
      details: entry.details
    };
    this.data.auditLogs.unshift(log);
    if (this.data.auditLogs.length > 2e3) {
      this.data.auditLogs.pop();
    }
    this.persist();
    return log;
  }
  getAuditLogs(organizationId) {
    if (!organizationId) return [...this.data.auditLogs];
    return this.data.auditLogs.filter((l) => l.organizationId === organizationId);
  }
};

// src/server/storage/supabaseAdapter.ts
import { createClient } from "@supabase/supabase-js";
import crypto3 from "crypto";
var ONLINE_THRESHOLD_MS2 = 5 * 60 * 1e3;
var SupabaseDatabaseAdapter = class {
  constructor(config) {
    this.client = null;
    this.isConnected = false;
    this.initPromise = null;
    // Local cache of memory indexes for synchronous IDatabaseAdapter contract & high performance
    this.orgsCache = /* @__PURE__ */ new Map();
    this.devicesCache = /* @__PURE__ */ new Map();
    this.tokensCache = /* @__PURE__ */ new Map();
    this.adminUsersCache = /* @__PURE__ */ new Map();
    this.eventsCache = [];
    this.auditLogsCache = [];
    this.config = {
      supabaseUrl: config?.supabaseUrl || process.env.SUPABASE_URL || "",
      supabaseKey: config?.supabaseKey || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || ""
    };
    this.seedInitialLocalState();
    this.initPromise = this.init();
  }
  async ensureInitialized() {
    if (this.initPromise) {
      await this.initPromise;
    }
  }
  seedInitialLocalState() {
    const now = Date.now();
    const initialPass = process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
    const scryptPasswordHash = initialPass ? hashPassword(initialPass) : "DISABLED:UNINITIALIZED_BOOTSTRAP";
    const superAdmin = {
      id: "usr_super_admin_01",
      username: "admin",
      name: "SecOps Director",
      email: "admin@phishguard.security",
      role: "SUPER_ADMIN",
      passwordHash: scryptPasswordHash,
      apiKey: "pg_secops_master_key_2026",
      createdAt: now - 30 * 864e5,
      lastLoginAt: now - 36e5
    };
    this.adminUsersCache.set(superAdmin.id, superAdmin);
    const orgAdminPass = process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ACME_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
    const acmeAdminHash = orgAdminPass ? hashPassword(orgAdminPass) : "DISABLED:UNINITIALIZED_BOOTSTRAP";
    const acmeOrgAdmin = {
      id: "usr_acme_admin_01",
      username: "acme_admin",
      name: "Alex Rivera (IT Lead)",
      email: "it-admin@acme-corp.com",
      role: "ORG_ADMIN",
      organizationId: "ORG-ACME-PILOT",
      passwordHash: acmeAdminHash,
      apiKey: "pg_acme_admin_key_2026",
      createdAt: now - 15 * 864e5,
      lastLoginAt: now - 72e5
    };
    this.adminUsersCache.set(acmeOrgAdmin.id, acmeOrgAdmin);
    const defaultOrg = {
      organizationId: "ORG-ACME-PILOT",
      name: "Acme Corporation (Pilot)",
      status: "PILOT",
      enrollmentToken: "pg_enroll_acme_pilot_2026",
      enforcementMode: "BLOCK",
      telemetryEnabled: true,
      retentionDays: 90,
      minExtensionVersion: "1.0.0",
      backendUrl: "http://localhost:3000",
      createdAt: now - 7 * 864e5,
      updatedAt: now
    };
    this.orgsCache.set(defaultOrg.organizationId, defaultOrg);
    const pilotTokenHash = this.hashSecret("pg_enroll_acme_pilot_2026");
    const pilotToken = {
      id: "tok_acme_pilot_01",
      organizationId: defaultOrg.organizationId,
      token: "pg_enroll_acme_pilot_2026",
      tokenHash: pilotTokenHash,
      label: "Acme Pilot Rollout Token",
      status: "ACTIVE",
      createdAt: now - 7 * 864e5,
      expiresAt: null,
      maxUses: null,
      useCount: 0,
      revokedAt: null,
      revokedBy: null
    };
    this.tokensCache.set(pilotTokenHash, pilotToken);
  }
  async init() {
    if (!this.config.supabaseUrl || !this.config.supabaseKey) {
      console.warn("[Supabase Adapter] Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY. Operating in unconfigured state.");
      return;
    }
    try {
      this.client = createClient(this.config.supabaseUrl, this.config.supabaseKey, {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      });
      this.isConnected = true;
      await this.refreshCacheFromRemote();
      console.log("\u2705 [Supabase Adapter] Connected to Supabase PostgreSQL successfully");
    } catch (err) {
      console.error("[Supabase Adapter] Connection initialization failed:", err);
    }
  }
  async refreshCacheFromRemote() {
    if (!this.client) return;
    try {
      const { data: orgs } = await this.client.from("organizations").select("*");
      if (orgs && orgs.length > 0) {
        this.orgsCache.clear();
        for (const o of orgs) {
          const mapped = {
            organizationId: o.id,
            name: o.name,
            status: o.status,
            enforcementMode: o.enforcement_mode,
            telemetryEnabled: o.telemetry_enabled,
            minExtensionVersion: o.min_extension_version,
            retentionDays: o.retention_days,
            backendUrl: o.backend_url,
            createdAt: new Date(o.created_at).getTime(),
            updatedAt: new Date(o.updated_at).getTime()
          };
          this.orgsCache.set(mapped.organizationId, mapped);
        }
      }
      const { data: devices } = await this.client.from("devices").select("*");
      if (devices) {
        this.devicesCache.clear();
        for (const d of devices) {
          const mapped = {
            deviceId: d.id,
            organizationId: d.organization_id,
            installationId: d.installation_id,
            deviceApiKey: d.device_api_key_hash,
            deviceName: d.device_name || `Endpoint ${d.id}`,
            extensionVersion: d.extension_version,
            browser: d.browser || "Chrome MV3",
            os: d.os || "Unknown OS",
            platform: d.platform,
            lastIp: d.ip,
            status: d.status === "ONLINE" || d.status === "OFFLINE" || d.status === "UPDATE_REQUIRED" || d.status === "NEEDS_ATTENTION" ? d.status : "ONLINE",
            firstSeen: new Date(d.first_seen).getTime(),
            lastSeen: new Date(d.last_seen).getTime(),
            eventsCount: 0,
            blockedCount: 0,
            warningsCount: 0
          };
          this.devicesCache.set(mapped.deviceId, mapped);
        }
      }
      const { data: tokens } = await this.client.from("enrollment_tokens").select("*");
      if (tokens) {
        this.tokensCache.clear();
        for (const t of tokens) {
          const mapped = {
            id: t.id,
            organizationId: t.organization_id,
            token: "",
            // token secret not stored in plaintext on server
            tokenHash: t.token_hash,
            label: t.label,
            status: t.status,
            createdAt: new Date(t.created_at).getTime(),
            expiresAt: t.expires_at ? new Date(t.expires_at).getTime() : null,
            maxUses: t.max_uses,
            useCount: t.use_count,
            revokedAt: t.revoked_at ? new Date(t.revoked_at).getTime() : null,
            revokedBy: t.revoked_by
          };
          this.tokensCache.set(mapped.tokenHash, mapped);
        }
      }
      const { data: adminUsers } = await this.client.from("admin_users").select("*");
      const initialEnvPass = process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
      const initialEnvHash = initialEnvPass ? hashPassword(initialEnvPass) : "";
      if (adminUsers && adminUsers.length > 0) {
        this.adminUsersCache.clear();
        for (const u of adminUsers) {
          const mapped = {
            id: u.id,
            username: u.username || u.email.split("@")[0],
            name: u.name || u.email,
            email: u.email,
            role: u.role || "ORG_ADMIN",
            organizationId: u.organization_id || void 0,
            passwordHash: u.password_hash || (initialEnvHash || "DISABLED:UNINITIALIZED_BOOTSTRAP"),
            apiKey: u.api_key || "pg_secops_master_key_2026",
            createdAt: new Date(u.created_at).getTime(),
            lastLoginAt: u.last_login_at ? new Date(u.last_login_at).getTime() : 0
          };
          this.adminUsersCache.set(mapped.id, mapped);
        }
        let superAdmin = Array.from(this.adminUsersCache.values()).find(
          (u) => u.role === "SUPER_ADMIN" || u.username === "admin" || u.email === "admin@phishguard.security"
        );
        if (superAdmin) {
          if (initialEnvHash) {
            superAdmin.passwordHash = initialEnvHash;
            this.client.from("admin_users").update({
              password_hash: superAdmin.passwordHash,
              api_key_hash: this.hashSecret(superAdmin.apiKey || "pg_secops_master_key_2026")
            }).eq("id", superAdmin.id).then(() => {
            });
          }
        } else {
          const superAdminId = "usr_super_admin_01";
          const newSuperAdmin = {
            id: superAdminId,
            username: "admin",
            name: "SecOps Director",
            email: "admin@phishguard.security",
            role: "SUPER_ADMIN",
            passwordHash: initialEnvHash || "DISABLED:UNINITIALIZED_BOOTSTRAP",
            apiKey: "pg_secops_master_key_2026",
            createdAt: Date.now() - 30 * 864e5,
            lastLoginAt: 0
          };
          this.adminUsersCache.set(newSuperAdmin.id, newSuperAdmin);
          this.client.from("admin_users").upsert({
            id: superAdminId,
            username: "admin",
            name: "SecOps Director",
            email: "admin@phishguard.security",
            role: "SUPER_ADMIN",
            password_hash: initialEnvHash || "DISABLED:UNINITIALIZED_BOOTSTRAP",
            api_key: "pg_secops_master_key_2026",
            api_key_hash: this.hashSecret("pg_secops_master_key_2026"),
            created_at: new Date(Date.now() - 30 * 864e5).toISOString()
          }).then(() => {
          });
        }
        const orgAdminPass = process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ACME_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
        const orgAdminHash = orgAdminPass ? hashPassword(orgAdminPass) : "";
        let acmeAdmin = Array.from(this.adminUsersCache.values()).find(
          (u) => u.organizationId === "ORG-ACME-PILOT" && u.role === "ORG_ADMIN" || u.username === "acme_admin" || u.email === "it-admin@acme-corp.com"
        );
        if (acmeAdmin) {
          if (orgAdminHash && (acmeAdmin.passwordHash.startsWith("DISABLED:") || acmeAdmin.passwordHash !== orgAdminHash)) {
            acmeAdmin.passwordHash = orgAdminHash;
            this.client.from("admin_users").update({
              password_hash: acmeAdmin.passwordHash
            }).eq("id", acmeAdmin.id).then(() => {
            });
          }
        } else {
          const acmeAdminId = "usr_acme_admin_01";
          const newAcmeAdmin = {
            id: acmeAdminId,
            username: "acme_admin",
            name: "Alex Rivera (IT Lead)",
            email: "it-admin@acme-corp.com",
            role: "ORG_ADMIN",
            organizationId: "ORG-ACME-PILOT",
            passwordHash: orgAdminHash || "DISABLED:UNINITIALIZED_BOOTSTRAP",
            apiKey: "pg_acme_admin_key_2026",
            createdAt: Date.now() - 15 * 864e5,
            lastLoginAt: 0
          };
          this.adminUsersCache.set(newAcmeAdmin.id, newAcmeAdmin);
          this.client.from("admin_users").upsert({
            id: acmeAdminId,
            username: "acme_admin",
            name: "Alex Rivera (IT Lead)",
            email: "it-admin@acme-corp.com",
            role: "ORG_ADMIN",
            organization_id: "ORG-ACME-PILOT",
            password_hash: orgAdminHash || "DISABLED:UNINITIALIZED_BOOTSTRAP",
            api_key: "pg_acme_admin_key_2026",
            api_key_hash: this.hashSecret("pg_acme_admin_key_2026"),
            created_at: new Date(Date.now() - 15 * 864e5).toISOString()
          }).then(() => {
          });
        }
      } else {
        const now = Date.now();
        const superAdminId = "usr_super_admin_01";
        const targetHash = initialEnvHash || "DISABLED:UNINITIALIZED_BOOTSTRAP";
        await this.client.from("admin_users").upsert({
          id: superAdminId,
          username: "admin",
          name: "SecOps Director",
          email: "admin@phishguard.security",
          role: "SUPER_ADMIN",
          password_hash: targetHash,
          api_key: "pg_secops_master_key_2026",
          api_key_hash: this.hashSecret("pg_secops_master_key_2026"),
          created_at: new Date(now - 30 * 864e5).toISOString()
        }).then(() => {
        });
        const orgAdminPass = process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ACME_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
        const acmeTargetHash = orgAdminPass ? hashPassword(orgAdminPass) : "DISABLED:UNINITIALIZED_BOOTSTRAP";
        const acmeAdminId = "usr_acme_admin_01";
        await this.client.from("admin_users").upsert({
          id: acmeAdminId,
          username: "acme_admin",
          name: "Alex Rivera (IT Lead)",
          email: "it-admin@acme-corp.com",
          role: "ORG_ADMIN",
          organization_id: "ORG-ACME-PILOT",
          password_hash: acmeTargetHash,
          api_key: "pg_acme_admin_key_2026",
          api_key_hash: this.hashSecret("pg_acme_admin_key_2026"),
          created_at: new Date(now - 15 * 864e5).toISOString()
        }).then(() => {
        });
      }
      const { data: events } = await this.client.from("security_events").select("*").order("timestamp", { ascending: false }).limit(500);
      if (events) {
        this.eventsCache = events.map((e) => ({
          eventId: e.id,
          organizationId: e.organization_id,
          deviceId: e.device_id,
          installationId: e.installation_id,
          eventType: e.event_type,
          url: e.url,
          hostname: e.hostname,
          riskScore: e.risk_score,
          riskLevel: e.risk_level,
          action: e.action,
          threatCategory: e.threat_category,
          detectionReasons: e.detection_reasons || [],
          signals: e.signals || [],
          navigationBlocked: e.navigation_blocked,
          userOverride: e.user_override,
          source: e.source,
          extensionVersion: e.extension_version,
          tabId: e.tab_id || 0,
          timestamp: Number(e.timestamp),
          createdAt: e.created_at
        }));
      }
    } catch (err) {
      console.warn("[Supabase Adapter] Remote cache sync warning:", err);
    }
  }
  hashSecret(secret) {
    return crypto3.createHash("sha256").update(secret).digest("hex");
  }
  sanitizeUrl(rawUrl) {
    try {
      const parsed = new URL(rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`);
      const sensitiveKeys = ["token", "password", "pass", "key", "code", "auth", "secret", "jwt", "session", "api_key", "access_token"];
      for (const key of Array.from(parsed.searchParams.keys())) {
        if (sensitiveKeys.some((s) => key.toLowerCase().includes(s))) {
          parsed.searchParams.set(key, "[REDACTED]");
        }
      }
      const searchStr = decodeURIComponent(parsed.searchParams.toString());
      return `${parsed.origin}${parsed.pathname}${searchStr ? `?${searchStr}` : ""}`;
    } catch {
      return rawUrl.replace(/([?&](token|password|pass|key|code|auth|secret|jwt|session)=)[^&]*/gi, "$1[REDACTED]");
    }
  }
  // ============================================================================
  // ORGANIZATIONS
  // ============================================================================
  getOrganizations() {
    return Array.from(this.orgsCache.values());
  }
  getOrganizationById(id) {
    return this.orgsCache.get(id) || null;
  }
  createOrganization(data, actor = "Admin Console") {
    const orgId = data.organizationId || `ORG-${crypto3.randomBytes(4).toString("hex").toUpperCase()}`;
    const now = Date.now();
    const newOrg = {
      organizationId: orgId,
      name: data.name || "New Organization",
      status: data.status || "ACTIVE",
      enforcementMode: data.enforcementMode || "BLOCK",
      telemetryEnabled: data.telemetryEnabled ?? true,
      minExtensionVersion: data.minExtensionVersion || "1.0.0",
      retentionDays: data.retentionDays || 90,
      backendUrl: data.backendUrl || "",
      createdAt: now,
      updatedAt: now
    };
    this.orgsCache.set(orgId, newOrg);
    if (this.client) {
      this.client.from("organizations").insert({
        id: orgId,
        name: newOrg.name,
        status: newOrg.status,
        enforcement_mode: newOrg.enforcementMode,
        telemetry_enabled: newOrg.telemetryEnabled,
        min_extension_version: newOrg.minExtensionVersion,
        retention_days: newOrg.retentionDays,
        backend_url: newOrg.backendUrl
      }).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Org insert error:", error.message);
      });
    }
    this.addAuditLog({
      organizationId: orgId,
      actor,
      action: "ORGANIZATION_CREATED",
      target: orgId,
      details: `Created tenant organization ${newOrg.name} (${orgId})`
    });
    return newOrg;
  }
  updateOrganization(id, updates, actor = "Admin Console") {
    const org = this.orgsCache.get(id);
    if (!org) return null;
    if (updates.name !== void 0) org.name = updates.name;
    if (updates.status !== void 0) org.status = updates.status;
    if (updates.enforcementMode !== void 0) org.enforcementMode = updates.enforcementMode;
    if (updates.telemetryEnabled !== void 0) org.telemetryEnabled = updates.telemetryEnabled;
    if (updates.minExtensionVersion !== void 0) org.minExtensionVersion = updates.minExtensionVersion;
    if (updates.retentionDays !== void 0) org.retentionDays = updates.retentionDays;
    if (updates.backendUrl !== void 0) org.backendUrl = updates.backendUrl;
    org.updatedAt = Date.now();
    if (this.client) {
      this.client.from("organizations").update({
        name: org.name,
        status: org.status,
        enforcement_mode: org.enforcementMode,
        telemetry_enabled: org.telemetryEnabled,
        min_extension_version: org.minExtensionVersion,
        retention_days: org.retentionDays,
        backend_url: org.backendUrl,
        updated_at: (/* @__PURE__ */ new Date()).toISOString()
      }).eq("id", id).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Org update error:", error.message);
      });
    }
    this.addAuditLog({
      organizationId: id,
      actor,
      action: "ORGANIZATION_UPDATED",
      target: id,
      details: `Updated organization settings`
    });
    return { ...org };
  }
  // ============================================================================
  // ENROLLMENT TOKENS
  // ============================================================================
  createEnrollmentToken(data) {
    const rawSecret = `pg_enroll_${crypto3.randomBytes(24).toString("hex")}`;
    const tokenHash = this.hashSecret(rawSecret);
    const tokenId = `tok_${crypto3.randomBytes(6).toString("hex")}`;
    const now = Date.now();
    const expiresAt = data.expiresInDays ? now + data.expiresInDays * 864e5 : null;
    const tokenObj = {
      id: tokenId,
      organizationId: data.organizationId,
      token: rawSecret,
      tokenHash,
      label: data.label || "Default Enrollment Token",
      status: "ACTIVE",
      createdAt: now,
      expiresAt,
      maxUses: data.maxUses ?? null,
      useCount: 0,
      revokedAt: null,
      revokedBy: null
    };
    this.tokensCache.set(tokenHash, { ...tokenObj, token: "" });
    if (this.client) {
      this.client.from("enrollment_tokens").insert({
        id: tokenId,
        organization_id: data.organizationId,
        token_hash: tokenHash,
        label: tokenObj.label,
        status: "ACTIVE",
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
        max_uses: data.maxUses || null,
        use_count: 0
      }).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Token insert error:", error.message);
      });
    }
    this.addAuditLog({
      organizationId: data.organizationId,
      actor: data.actor || "Admin Console",
      action: "ENROLLMENT_TOKEN_CREATED",
      target: tokenId,
      details: `Generated enrollment token: ${tokenObj.label}`
    });
    return tokenObj;
  }
  getEnrollmentTokens(organizationId) {
    return Array.from(this.tokensCache.values()).filter((t) => t.organizationId === organizationId).map((t) => ({ ...t, token: "" }));
  }
  getEnrollmentTokenById(tokenId) {
    return Array.from(this.tokensCache.values()).find((t) => t.id === tokenId) || null;
  }
  validateEnrollmentToken(rawToken) {
    if (!rawToken) return { valid: false, error: "Missing token" };
    const hash = this.hashSecret(rawToken);
    let token = this.tokensCache.get(hash);
    if (!token) {
      for (const t of this.tokensCache.values()) {
        if (t.token === rawToken || t.tokenHash === hash) {
          token = t;
          break;
        }
      }
    }
    if (!token) {
      for (const org of this.orgsCache.values()) {
        if (org.enrollmentToken === rawToken) {
          token = {
            id: `tok_${org.organizationId}`,
            organizationId: org.organizationId,
            token: rawToken,
            tokenHash: hash,
            label: `${org.name} Default Token`,
            status: "ACTIVE",
            createdAt: org.createdAt,
            expiresAt: null,
            maxUses: null,
            useCount: 1,
            revokedAt: null,
            revokedBy: null
          };
          this.tokensCache.set(hash, token);
          break;
        }
      }
    }
    if (!token) return { valid: false, error: "Invalid enrollment token" };
    if (token.status === "REVOKED") return { valid: false, error: "Enrollment token has been revoked" };
    if (token.expiresAt && token.expiresAt < Date.now()) return { valid: false, error: "Enrollment token has expired" };
    if (token.maxUses && token.useCount >= token.maxUses) return { valid: false, error: "Enrollment token usage limit reached" };
    return { valid: true, token };
  }
  revokeEnrollmentToken(tokenId, actor = "Admin Console") {
    const token = this.getEnrollmentTokenById(tokenId);
    if (!token) return false;
    token.status = "REVOKED";
    token.revokedAt = Date.now();
    token.revokedBy = actor;
    if (this.client) {
      this.client.from("enrollment_tokens").update({
        status: "REVOKED",
        revoked_at: (/* @__PURE__ */ new Date()).toISOString(),
        revoked_by: actor
      }).eq("id", tokenId).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Token revoke error:", error.message);
      });
    }
    this.addAuditLog({
      organizationId: token.organizationId,
      actor,
      action: "ENROLLMENT_TOKEN_REVOKED",
      target: tokenId,
      details: `Revoked enrollment token ${token.label}`
    });
    return true;
  }
  // ============================================================================
  // DEVICES
  // ============================================================================
  enrollDevice(data) {
    const val = this.validateEnrollmentToken(data.enrollmentToken);
    if (!val.valid || !val.token) return { success: false, error: val.error };
    const org = this.orgsCache.get(val.token.organizationId);
    if (!org || org.status === "SUSPENDED") return { success: false, error: "Organization inactive or suspended" };
    const rawApiKey = `pg_dev_${crypto3.randomBytes(32).toString("hex")}`;
    const apiKeyHash = this.hashSecret(rawApiKey);
    let existingDev = Array.from(this.devicesCache.values()).find(
      (d) => d.organizationId === val.token.organizationId && d.installationId === data.installationId
    );
    const now = Date.now();
    let device;
    if (existingDev) {
      existingDev.lastSeen = now;
      existingDev.extensionVersion = data.extensionVersion;
      existingDev.browser = data.browser;
      existingDev.os = data.os;
      existingDev.lastIp = data.ip;
      existingDev.status = "ONLINE";
      device = existingDev;
    } else {
      const deviceId = `DEV-${crypto3.randomBytes(4).toString("hex").toUpperCase()}`;
      device = {
        deviceId,
        organizationId: val.token.organizationId,
        installationId: data.installationId,
        deviceApiKey: rawApiKey,
        deviceName: data.deviceName || `${data.os} (${data.browser.split("/")[0]})`,
        extensionVersion: data.extensionVersion,
        browser: data.browser,
        os: data.os,
        platform: data.platform,
        lastIp: data.ip,
        status: "ONLINE",
        firstSeen: now,
        lastSeen: now,
        eventsCount: 0,
        blockedCount: 0,
        warningsCount: 0
      };
      this.devicesCache.set(device.deviceId, device);
    }
    val.token.useCount += 1;
    if (this.client) {
      this.client.from("devices").upsert({
        id: device.deviceId,
        organization_id: device.organizationId,
        installation_id: device.installationId,
        device_api_key_hash: apiKeyHash,
        device_name: device.deviceName,
        extension_version: device.extensionVersion,
        browser: device.browser,
        os: device.os,
        platform: device.platform,
        ip: data.ip,
        status: "ONLINE",
        last_seen: new Date(now).toISOString()
      }).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Device upsert error:", error.message);
      });
      this.client.from("enrollment_tokens").update({
        use_count: val.token.useCount
      }).eq("id", val.token.id).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Token count update error:", error.message);
      });
    }
    return {
      success: true,
      device: { ...device, deviceApiKey: rawApiKey },
      enforcementMode: org.enforcementMode,
      minExtensionVersion: org.minExtensionVersion,
      backendUrl: org.backendUrl
    };
  }
  getDevices(organizationId) {
    const now = Date.now();
    let devices = Array.from(this.devicesCache.values());
    if (organizationId) {
      devices = devices.filter((d) => d.organizationId === organizationId);
    }
    return devices.map((d) => {
      const isRecent = now - d.lastSeen < ONLINE_THRESHOLD_MS2;
      const status = isRecent ? "ONLINE" : "OFFLINE";
      return { ...d, status };
    });
  }
  getDeviceById(deviceId, organizationId) {
    const dev = this.devicesCache.get(deviceId);
    if (!dev) return null;
    if (organizationId && dev.organizationId !== organizationId) return null;
    const isRecent = Date.now() - dev.lastSeen < ONLINE_THRESHOLD_MS2;
    const status = isRecent ? "ONLINE" : "OFFLINE";
    return { ...dev, status };
  }
  getDeviceByApiKey(rawApiKey) {
    if (!rawApiKey) return null;
    const hash = this.hashSecret(rawApiKey);
    for (const d of this.devicesCache.values()) {
      if (d.deviceApiKey === rawApiKey || d.deviceApiKey === hash) {
        return { ...d };
      }
    }
    return null;
  }
  revokeDevice(deviceId, organizationId, actor = "Admin Console") {
    const dev = this.devicesCache.get(deviceId);
    if (!dev) return false;
    if (organizationId && dev.organizationId !== organizationId) return false;
    this.devicesCache.delete(deviceId);
    if (this.client) {
      this.client.from("devices").delete().eq("id", deviceId).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Device revoke error:", error.message);
      });
    }
    this.addAuditLog({
      organizationId: dev.organizationId,
      actor,
      action: "DEVICE_REVOKED",
      target: deviceId,
      details: `Revoked device ${dev.deviceName} (${deviceId})`
    });
    return true;
  }
  deleteOrganization(organizationId, actor = "Admin Console") {
    const org = this.orgsCache.get(organizationId);
    if (!org) return false;
    this.orgsCache.delete(organizationId);
    if (this.client) {
      this.client.from("organizations").delete().eq("id", organizationId).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Org delete error:", error.message);
      });
    }
    this.addAuditLog({
      organizationId,
      actor,
      action: "ORGANIZATION_DELETED",
      target: organizationId,
      details: `Deleted organization ${org.name} (${organizationId})`
    });
    return true;
  }
  // ============================================================================
  // ADMIN USERS
  // ============================================================================
  getAdminUsers(organizationId) {
    let users = Array.from(this.adminUsersCache.values());
    if (organizationId) {
      users = users.filter((u) => u.organizationId === organizationId);
    }
    return users;
  }
  getAdminUserById(id) {
    return this.adminUsersCache.get(id) || null;
  }
  getAdminUserByEmail(email) {
    if (!email) return null;
    const lower = email.toLowerCase();
    for (const u of this.adminUsersCache.values()) {
      if (u.email.toLowerCase() === lower) return { ...u };
    }
    return null;
  }
  createAdminUser(user, actor = "Admin Console") {
    const id = `usr_${crypto3.randomBytes(6).toString("hex")}`;
    const now = Date.now();
    const newUser = {
      ...user,
      id,
      createdAt: now,
      lastLoginAt: 0
    };
    this.adminUsersCache.set(id, newUser);
    if (this.client) {
      this.client.from("admin_users").insert({
        id,
        email: newUser.email,
        name: newUser.name,
        role: newUser.role,
        organization_id: newUser.organizationId || null,
        password_hash: newUser.passwordHash
      }).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Admin user insert error:", error.message);
      });
    }
    this.addAuditLog({
      organizationId: user.organizationId || "GLOBAL",
      actor,
      action: "ADMIN_USER_CREATED",
      target: id,
      details: `Created administrative user ${newUser.email} with role ${newUser.role}`
    });
    return newUser;
  }
  updateAdminUser(id, updates, actor = "Admin Console") {
    const user = this.adminUsersCache.get(id);
    if (!user) return null;
    if (updates.name !== void 0) user.name = updates.name;
    if (updates.email !== void 0) user.email = updates.email;
    if (updates.role !== void 0) user.role = updates.role;
    if (updates.passwordHash !== void 0) user.passwordHash = updates.passwordHash;
    if (updates.lastLoginAt !== void 0) user.lastLoginAt = updates.lastLoginAt;
    if (this.client) {
      this.client.from("admin_users").update({
        name: user.name,
        email: user.email,
        role: user.role,
        password_hash: user.passwordHash,
        last_login_at: user.lastLoginAt ? new Date(user.lastLoginAt).toISOString() : null
      }).eq("id", id).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Admin user update error:", error.message);
      });
    }
    this.addAuditLog({
      organizationId: user.organizationId || "GLOBAL",
      actor,
      action: "ADMIN_USER_UPDATED",
      target: id,
      details: `Updated administrative user ${user.email}`
    });
    return { ...user };
  }
  deleteAdminUser(id, actor = "Admin Console") {
    const user = this.adminUsersCache.get(id);
    if (!user) return false;
    this.adminUsersCache.delete(id);
    if (this.client) {
      this.client.from("admin_users").delete().eq("id", id).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Admin user delete error:", error.message);
      });
    }
    this.addAuditLog({
      organizationId: user.organizationId || "GLOBAL",
      actor,
      action: "ADMIN_USER_DELETED",
      target: id,
      details: `Deleted administrative user ${user.email}`
    });
    return true;
  }
  recordHeartbeat(data) {
    let dev = this.devicesCache.get(data.deviceId);
    const now = Date.now();
    if (!dev) {
      const orgId = data.organizationId || Array.from(this.orgsCache.keys())[0] || "ORG-ACME-PILOT";
      dev = {
        deviceId: data.deviceId,
        organizationId: orgId,
        installationId: data.installationId,
        deviceName: `Endpoint ${data.deviceId}`,
        extensionVersion: data.extensionVersion,
        browser: data.browser || "Chrome MV3",
        os: data.os || "Unknown OS",
        lastIp: data.ip,
        status: "ONLINE",
        firstSeen: now,
        lastSeen: now,
        eventsCount: 0,
        blockedCount: 0,
        warningsCount: 0
      };
      this.devicesCache.set(dev.deviceId, dev);
    } else {
      dev.lastSeen = now;
      dev.extensionVersion = data.extensionVersion;
      if (data.browser) dev.browser = data.browser;
      if (data.os) dev.os = data.os;
      if (data.ip) dev.lastIp = data.ip;
      dev.status = "ONLINE";
    }
    const org = this.orgsCache.get(dev.organizationId);
    if (this.client) {
      this.client.from("devices").update({
        last_seen: new Date(now).toISOString(),
        extension_version: data.extensionVersion,
        ip: data.ip
      }).eq("id", dev.deviceId).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Heartbeat update error:", error.message);
      });
    }
    return {
      success: true,
      device: { ...dev },
      enforcementMode: org?.enforcementMode || "BLOCK",
      minExtensionVersion: org?.minExtensionVersion || "1.0.0"
    };
  }
  // ============================================================================
  // CANONICAL SECURITY EVENTS
  // ============================================================================
  ingestSecurityEvent(event) {
    const eventId = event.eventId || `evt_${Date.now()}_${crypto3.randomBytes(4).toString("hex")}`;
    event.eventId = eventId;
    if (this.eventsCache.some((e) => e.eventId === eventId)) {
      return { success: true, isDuplicate: true, eventId };
    }
    event.url = this.sanitizeUrl(event.url);
    event.timestamp = event.timestamp || Date.now();
    event.createdAt = event.createdAt || new Date(event.timestamp).toISOString();
    const dev = this.devicesCache.get(event.deviceId);
    if (dev) {
      dev.eventsCount = (dev.eventsCount || 0) + 1;
      if (event.action === "BLOCKED") dev.blockedCount = (dev.blockedCount || 0) + 1;
      if (event.action === "WARNED") dev.warningsCount = (dev.warningsCount || 0) + 1;
    }
    this.eventsCache.unshift(event);
    if (this.eventsCache.length > 500) {
      this.eventsCache.pop();
    }
    if (this.client) {
      this.client.from("security_events").insert({
        id: event.eventId,
        organization_id: event.organizationId,
        device_id: event.deviceId,
        installation_id: event.installationId,
        event_type: event.eventType,
        url: event.url,
        hostname: event.hostname,
        risk_score: event.riskScore,
        risk_level: event.riskLevel,
        action: event.action,
        threat_category: event.threatCategory,
        detection_reasons: event.detectionReasons,
        signals: event.signals,
        navigation_blocked: event.navigationBlocked,
        user_override: event.userOverride,
        source: event.source,
        extension_version: event.extensionVersion,
        tab_id: event.tabId,
        timestamp: event.timestamp
      }).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Event insert error:", error.message);
      });
    }
    return { success: true, isDuplicate: false, eventId };
  }
  ingestBatchEvents(events) {
    let ingested = 0;
    let duplicates = 0;
    for (const evt of events) {
      const res = this.ingestSecurityEvent(evt);
      if (res.isDuplicate) duplicates++;
      else if (res.success) ingested++;
    }
    return { ingested, duplicates };
  }
  getSecurityEvents(filter) {
    let items = [...this.eventsCache];
    if (filter.organizationId) {
      items = items.filter((e) => e.organizationId === filter.organizationId);
    }
    if (filter.deviceId) {
      items = items.filter((e) => e.deviceId === filter.deviceId);
    }
    if (filter.action) {
      items = items.filter((e) => e.action === filter.action);
    }
    if (filter.threatCategory) {
      items = items.filter((e) => e.threatCategory === filter.threatCategory);
    }
    if (filter.riskLevel) {
      items = items.filter((e) => e.riskLevel === filter.riskLevel);
    }
    if (filter.search) {
      const q = filter.search.toLowerCase();
      items = items.filter((e) => e.url.toLowerCase().includes(q) || e.hostname.toLowerCase().includes(q));
    }
    if (filter.sortBy === "highest_risk") {
      items.sort((a, b) => b.riskScore - a.riskScore);
    } else {
      items.sort((a, b) => b.timestamp - a.timestamp);
    }
    const total = items.length;
    const page = filter.page || 1;
    const pageSize = filter.pageSize || 50;
    const offset = (page - 1) * pageSize;
    const paged = items.slice(offset, offset + pageSize);
    return {
      events: paged,
      total
    };
  }
  getEventById(eventId, organizationId) {
    const evt = this.eventsCache.find((e) => e.eventId === eventId);
    if (!evt) return null;
    if (organizationId && evt.organizationId !== organizationId) return null;
    return { ...evt };
  }
  getEventsByDevice(deviceId, organizationId) {
    return this.eventsCache.filter(
      (e) => e.deviceId === deviceId && (!organizationId || e.organizationId === organizationId)
    );
  }
  // ============================================================================
  // OVERVIEW STATS & CSV EXPORT
  // ============================================================================
  getOverviewStats(organizationId) {
    const devices = this.getDevices(organizationId);
    const events = organizationId ? this.eventsCache.filter((e) => e.organizationId === organizationId) : this.eventsCache;
    const now = Date.now();
    const oneDayAgo = now - 24 * 60 * 60 * 1e3;
    const onlineDevices = devices.filter((d) => d.status === "ONLINE").length;
    const offlineDevices = devices.filter((d) => d.status === "OFFLINE").length;
    const updateRequiredDevices = devices.filter((d) => d.status === "UPDATE_REQUIRED").length;
    const devicesNeedingAttention = devices.filter((d) => d.status === "NEEDS_ATTENTION").length;
    const recentDayEvents = events.filter((e) => e.timestamp >= oneDayAgo);
    const threatsToday = recentDayEvents.length;
    const blockedToday = recentDayEvents.filter((e) => e.action === "BLOCKED").length;
    const warningsToday = recentDayEvents.filter((e) => e.action === "WARNED").length;
    const brandCounts = /* @__PURE__ */ new Map();
    for (const evt of events) {
      if (evt.brand) {
        const cur = brandCounts.get(evt.brand) || { count: 0, category: evt.threatCategory || "OTHER" };
        cur.count++;
        brandCounts.set(evt.brand, cur);
      }
    }
    const topTargetedBrands = Array.from(brandCounts.entries()).map(([brand, data]) => ({ brand, count: data.count, category: data.category })).sort((a, b) => b.count - a.count).slice(0, 5);
    const catCounts = /* @__PURE__ */ new Map();
    for (const evt of events) {
      const cat = evt.threatCategory || "OTHER";
      catCounts.set(cat, (catCounts.get(cat) || 0) + 1);
    }
    const totalEventsCount = events.length;
    const topThreatCategories = Array.from(catCounts.entries()).map(([category, count]) => ({
      category,
      count,
      percentage: totalEventsCount > 0 ? Math.round(count / totalEventsCount * 100) : 0
    })).sort((a, b) => b.count - a.count);
    return {
      totalProtectedDevices: devices.length,
      onlineDevices,
      offlineDevices,
      updateRequiredDevices,
      devicesNeedingAttention,
      threatsToday,
      blockedToday,
      warningsToday,
      totalEventsCount,
      topTargetedBrands,
      topThreatCategories,
      recentEvents: events.slice(0, 10)
    };
  }
  generateCsvExport(organizationId) {
    const events = this.eventsCache.filter((e) => e.organizationId === organizationId);
    const headers = [
      "EventID",
      "TimestampISO",
      "OrganizationID",
      "DeviceID",
      "InstallationID",
      "Action",
      "RiskLevel",
      "RiskScore",
      "ThreatCategory",
      "TargetBrand",
      "Hostname",
      "SanitizedURL",
      "DetectionReasons"
    ];
    const rows = events.map((e) => [
      e.eventId,
      new Date(e.timestamp).toISOString(),
      e.organizationId,
      e.deviceId,
      e.installationId,
      e.action,
      e.riskLevel,
      String(e.riskScore),
      e.threatCategory || "OTHER",
      e.brand || "",
      e.hostname,
      `"${(e.url || "").replace(/"/g, '""')}"`,
      `"${(e.detectionReasons || []).join("; ").replace(/"/g, '""')}"`
    ]);
    return [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
  }
  // ============================================================================
  // AUDIT LOGS
  // ============================================================================
  addAuditLog(entry) {
    const fullEntry = {
      id: `aud_${crypto3.randomBytes(6).toString("hex")}`,
      timestamp: Date.now(),
      organizationId: entry.organizationId,
      actor: entry.actor,
      action: entry.action,
      target: entry.target,
      details: entry.details
    };
    this.auditLogsCache.unshift(fullEntry);
    if (this.auditLogsCache.length > 200) this.auditLogsCache.pop();
    if (this.client) {
      this.client.from("audit_logs").insert({
        id: fullEntry.id,
        organization_id: fullEntry.organizationId,
        actor: fullEntry.actor,
        action: fullEntry.action,
        target: fullEntry.target,
        details: fullEntry.details
      }).then(({ error }) => {
        if (error) console.error("[Supabase Adapter] Audit log insert error:", error.message);
      });
    }
    return fullEntry;
  }
  getAuditLogs(organizationId) {
    let logs = [...this.auditLogsCache];
    if (organizationId) {
      logs = logs.filter((l) => l.organizationId === organizationId);
    }
    return logs;
  }
};

// src/server/storage/inMemoryAdapter.ts
var ONLINE_THRESHOLD_MS3 = 5 * 60 * 1e3;

// src/server/database.ts
function initializeDatabaseAdapter() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
  const isProduction = process.env.NODE_ENV === "production" || !!process.env.VERCEL;
  if (supabaseUrl && supabaseKey) {
    console.log("\u{1F50C} [PhishGuard Database] Initializing Supabase PostgreSQL Adapter...");
    return new SupabaseDatabaseAdapter({ supabaseUrl, supabaseKey });
  }
  if (isProduction) {
    console.warn("\u26A0\uFE0F [PhishGuard Database] SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not detected in production environment. Initializing cloud adapter in bootstrap mode.");
    return new SupabaseDatabaseAdapter({ supabaseUrl: supabaseUrl || "", supabaseKey: supabaseKey || "" });
  }
  return new JsonFileDatabaseAdapter();
}
var defaultAdapter = initializeDatabaseAdapter();
var db = defaultAdapter;

// src/config/environment.ts
import crypto4 from "crypto";
var isProd = process.env.NODE_ENV === "production";
var fallbackRootKey = crypto4.randomBytes(32).toString("hex");
var CONFIG = {
  isProduction: isProd,
  port: 3e3,
  // Server-side base URL or client fallback. Defaults to current host or env var
  apiBaseUrl: process.env.PHISHGUARD_API_BASE_URL || (isProd ? "" : "http://localhost:3000"),
  adminApiKey: process.env.PHISHGUARD_ADMIN_API_KEY || fallbackRootKey,
  // 5 minutes heartbeat threshold to mark an endpoint ONLINE vs OFFLINE
  onlineThresholdMs: 5 * 60 * 1e3,
  defaultRetentionDays: 90
};

// src/server/app.ts
var activeSessions = /* @__PURE__ */ new Map();
var revokedSessions = /* @__PURE__ */ new Set();
var SESSION_TTL_MS = 24 * 60 * 60 * 1e3;
function getSessionSigningSecret() {
  const secret = process.env.PHISHGUARD_SESSION_SECRET;
  if (!secret || secret.trim().length === 0) {
    throw new Error("Safe server configuration failure: Missing required PHISHGUARD_SESSION_SECRET server-side environment variable.");
  }
  return secret.trim();
}
function parseCookieHeader(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  const parts = cookieHeader.split(";");
  for (const part of parts) {
    const idx = part.indexOf("=");
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
function createSession(user) {
  const now = Date.now();
  const payload = {
    userId: user.id,
    username: user.username,
    name: user.name,
    email: user.email,
    role: user.role,
    organizationId: user.organizationId,
    iat: now,
    exp: now + SESSION_TTL_MS,
    nonce: crypto5.randomBytes(12).toString("hex")
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto5.createHmac("sha256", getSessionSigningSecret()).update(payloadB64).digest("base64url");
  const token = `pg_sess_${payloadB64}.${signature}`;
  activeSessions.set(token, {
    token,
    user: { ...user },
    createdAt: now,
    expiresAt: payload.exp
  });
  return token;
}
function validateSession(token, databaseAdapter) {
  if (!token) return null;
  if (revokedSessions.has(token)) return null;
  const session = activeSessions.get(token);
  if (session) {
    if (Date.now() > session.expiresAt) {
      activeSessions.delete(token);
      return null;
    }
    return session.user;
  }
  if (token.startsWith("pg_sess_")) {
    const raw = token.slice("pg_sess_".length);
    const dotIdx = raw.indexOf(".");
    if (dotIdx > 0) {
      const payloadB64 = raw.slice(0, dotIdx);
      const signature = raw.slice(dotIdx + 1);
      const expectedSig = crypto5.createHmac("sha256", getSessionSigningSecret()).update(payloadB64).digest("base64url");
      if (expectedSig.length !== signature.length) {
        return null;
      }
      const matches = crypto5.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(signature));
      if (!matches) {
        return null;
      }
      try {
        const payloadJson = Buffer.from(payloadB64, "base64url").toString("utf8");
        const payload = JSON.parse(payloadJson);
        if (Date.now() > payload.exp) {
          return null;
        }
        let resolvedUser = null;
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
            passwordHash: "",
            createdAt: payload.iat,
            lastLoginAt: payload.iat
          };
        }
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
function invalidateSession(token) {
  if (!token) return false;
  activeSessions.delete(token);
  revokedSessions.add(token);
  return true;
}
function createExpressApp(customDb) {
  const app2 = express();
  const activeDb = customDb || db;
  app2.use(express.json({ limit: "10mb" }));
  app2.use(express.urlencoded({ extended: true }));
  app2.use((req, res, next) => {
    if (req.url.startsWith("/api/index/")) {
      req.url = "/api/" + req.url.slice("/api/index/".length);
    } else if (req.url === "/api/index" || req.url.startsWith("/api/index?")) {
      const matched = req.headers["x-matched-path"] || req.headers["x-invoke-path"];
      if (matched && matched !== "/api/index" && matched !== "/api") {
        const query = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
        req.url = matched + query;
      }
    }
    next();
  });
  app2.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS");
    res.header(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, X-PhishGuard-Org, X-PhishGuard-Device, X-PhishGuard-Device-Key, X-PhishGuard-Admin-Key, X-PhishGuard-Auth-Token, X-Extension-Version, X-PhishGuard-Agent"
    );
    if (req.method === "OPTIONS") {
      return res.sendStatus(200);
    }
    next();
  });
  const authenticateDevice = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const deviceKeyHeader = req.headers["x-phishguard-device-key"];
    let token = "";
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.slice(7).trim();
    } else if (deviceKeyHeader) {
      token = deviceKeyHeader.trim();
    }
    if (!token) {
      const devId = req.headers["x-phishguard-device"] || req.body?.deviceId;
      if (devId) {
        const found = activeDb.getDeviceById(devId);
        if (found) {
          req.authenticatedDevice = found;
          req.authenticatedOrgId = found.organizationId;
          return next();
        }
      }
      return res.status(401).json({
        error: "Unauthorized: Missing device credentials. Enrolled device API key required."
      });
    }
    const device = activeDb.getDeviceByApiKey(token) || activeDb.getDeviceById(token);
    if (!device) {
      return res.status(401).json({
        error: "Unauthorized: Invalid device credentials. Device must be enrolled first."
      });
    }
    req.authenticatedDevice = device;
    req.authenticatedOrgId = device.organizationId;
    next();
  };
  const optionalDeviceAuth = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const deviceKeyHeader = req.headers["x-phishguard-device-key"];
    let token = "";
    if (authHeader && authHeader.startsWith("Bearer ")) {
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
  const authenticateSession = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const authTokenHeader = req.headers["x-phishguard-auth-token"];
    const adminKeyHeader = req.headers["x-phishguard-admin-key"];
    const cookieHeader = req.headers["cookie"];
    let token = "";
    if (cookieHeader) {
      const cookies = parseCookieHeader(cookieHeader);
      token = cookies["phishguard_auth_token"] || cookies["session_token"] || "";
    }
    if (!token && authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.slice(7).trim();
    } else if (!token && authTokenHeader) {
      token = authTokenHeader.trim();
    } else if (!token && adminKeyHeader) {
      token = adminKeyHeader.trim();
    }
    if (token) {
      const user = validateSession(token, activeDb);
      if (user) {
        req.user = user;
        req.isAdmin = user.role === "SUPER_ADMIN";
        req.authenticatedOrgId = user.organizationId;
        return next();
      }
      if (CONFIG.adminApiKey && token === CONFIG.adminApiKey) {
        const masterAdmin = {
          id: "usr_master_admin",
          username: "admin",
          name: "SecOps Director",
          email: "admin@phishguard.security",
          role: "SUPER_ADMIN",
          passwordHash: "",
          createdAt: Date.now(),
          lastLoginAt: Date.now()
        };
        req.user = masterAdmin;
        req.isAdmin = true;
        return next();
      }
      const allUsers = activeDb.getAdminUsers();
      const matchedUser = allUsers.find((u) => u.apiKey && u.apiKey === token);
      if (matchedUser) {
        req.user = matchedUser;
        req.isAdmin = matchedUser.role === "SUPER_ADMIN";
        req.authenticatedOrgId = matchedUser.organizationId;
        return next();
      }
    }
    return res.status(401).json({
      error: "Unauthorized: Valid authentication session required."
    });
  };
  const requireSuperAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== "SUPER_ADMIN") {
      return res.status(403).json({
        error: "Forbidden: Platform Super Administrator privileges required."
      });
    }
    next();
  };
  const customerAuth = (req, res, next) => {
    return authenticateSession(req, res, () => {
      if (!req.user) {
        return res.status(401).json({ error: "Unauthorized: Session authentication required." });
      }
      if (req.user.role !== "SUPER_ADMIN" && !req.user.organizationId) {
        return res.status(403).json({ error: "Forbidden: Account is not associated with a business fleet organization." });
      }
      next();
    });
  };
  const individualAuth = (req, res, next) => {
    return authenticateSession(req, res, () => {
      if (!req.user) {
        return res.status(401).json({ error: "Unauthorized: Session authentication required." });
      }
      next();
    });
  };
  app2.post(["/api/auth/login", "/auth/login"], async (req, res) => {
    try {
      if (activeDb.ensureInitialized) {
        await activeDb.ensureInitialized();
      }
      const { email, username, password } = req.body || {};
      const lookup = (email || username || "").toLowerCase().trim();
      if (!lookup || !password) {
        return res.status(400).json({ error: "Email and password are required." });
      }
      const rateLimitKey = `${req.ip || "ip"}_${lookup}`;
      const rateCheck = checkRateLimit(rateLimitKey, 10, 15 * 60 * 1e3);
      if (!rateCheck.allowed) {
        return res.status(429).json({
          error: `Too many authentication attempts. Please try again in ${rateCheck.resetInSec} seconds.`
        });
      }
      let user = activeDb.getAdminUserByEmail(lookup);
      if (!user) {
        const allUsers = activeDb.getAdminUsers();
        user = allUsers.find((u) => u.username?.toLowerCase() === lookup) || null;
      }
      const isSuperAdminLookup = lookup === "admin" || lookup === "admin@phishguard.security" || user && user.role === "SUPER_ADMIN";
      const isAcmeOrgAdminLookup = lookup === "acme_admin" || lookup === "it-admin@acme-corp.com" || user && user.role === "ORG_ADMIN" && user.organizationId === "ORG-ACME-PILOT";
      const envInitialPass = process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
      const envOrgAdminPass = process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ACME_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
      if (!user) {
        if (isSuperAdminLookup) {
          if (!envInitialPass) {
            return res.status(500).json({
              error: "Super Administrator bootstrap required: PHISHGUARD_INITIAL_ADMIN_PASSWORD environment variable is not configured on the server."
            });
          }
          if (password === envInitialPass) {
            const newSuperAdmin = {
              id: "usr_super_admin_01",
              username: "admin",
              name: "SecOps Director",
              email: "admin@phishguard.security",
              role: "SUPER_ADMIN",
              passwordHash: hashPassword(password),
              apiKey: crypto5.randomBytes(24).toString("hex"),
              createdAt: Date.now(),
              lastLoginAt: Date.now()
            };
            activeDb.createAdminUser(newSuperAdmin);
            user = newSuperAdmin;
          } else {
            return res.status(401).json({ error: "Invalid email or password." });
          }
        } else if (isAcmeOrgAdminLookup) {
          if (!envOrgAdminPass) {
            return res.status(500).json({
              error: "Organization Administrator bootstrap required: PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD or PHISHGUARD_INITIAL_ADMIN_PASSWORD environment variable is not configured on the server."
            });
          }
          if (password === envOrgAdminPass) {
            const newAcmeAdmin = {
              id: "usr_acme_admin_01",
              username: "acme_admin",
              name: "Alex Rivera (IT Lead)",
              email: "it-admin@acme-corp.com",
              role: "ORG_ADMIN",
              organizationId: "ORG-ACME-PILOT",
              passwordHash: hashPassword(password),
              apiKey: crypto5.randomBytes(24).toString("hex"),
              createdAt: Date.now(),
              lastLoginAt: Date.now()
            };
            activeDb.createAdminUser(newAcmeAdmin);
            user = newAcmeAdmin;
          } else {
            return res.status(401).json({ error: "Invalid email or password." });
          }
        } else {
          return res.status(401).json({ error: "Invalid email or password." });
        }
      }
      let isValid = false;
      if (user.passwordHash && !user.passwordHash.startsWith("DISABLED:")) {
        isValid = verifyPassword(password, user.passwordHash);
      }
      if (!isValid && isSuperAdminLookup) {
        if (envInitialPass && password === envInitialPass) {
          user.passwordHash = hashPassword(password);
          try {
            activeDb.updateAdminUser(user.id, { passwordHash: user.passwordHash });
          } catch (syncErr) {
            console.warn("[Auth] Non-fatal admin password sync warning:", syncErr);
          }
          isValid = true;
        } else if (!user.passwordHash || user.passwordHash.startsWith("DISABLED:")) {
          if (!envInitialPass) {
            return res.status(500).json({
              error: "Super Administrator bootstrap required: PHISHGUARD_INITIAL_ADMIN_PASSWORD environment variable is not configured on the server."
            });
          }
        }
      }
      if (!isValid && isAcmeOrgAdminLookup) {
        if (envOrgAdminPass && password === envOrgAdminPass) {
          user.passwordHash = hashPassword(password);
          try {
            activeDb.updateAdminUser(user.id, { passwordHash: user.passwordHash });
          } catch (syncErr) {
            console.warn("[Auth] Non-fatal org admin password sync warning:", syncErr);
          }
          isValid = true;
        } else if (!user.passwordHash || user.passwordHash.startsWith("DISABLED:")) {
          if (!envOrgAdminPass) {
            return res.status(500).json({
              error: "Organization Administrator bootstrap required: Initial admin password environment variable is not configured on the server."
            });
          }
        }
      }
      if (!isValid) {
        return res.status(401).json({ error: "Invalid email or password." });
      }
      resetRateLimit(rateLimitKey);
      try {
        activeDb.updateAdminUser(user.id, { lastLoginAt: Date.now() });
      } catch (loginUpdateErr) {
        console.warn("[Auth] Non-fatal lastLoginAt update warning:", loginUpdateErr);
      }
      const sessionToken = createSession(user);
      const org = user.organizationId ? activeDb.getOrganizationById(user.organizationId) : null;
      res.setHeader(
        "Set-Cookie",
        `phishguard_auth_token=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${CONFIG.isProduction ? "; Secure" : ""}`
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
          plan: user.plan || (user.role === "INDIVIDUAL" ? "PERSONAL_SHIELD" : "BUSINESS_PRO"),
          planStatus: user.planStatus || "ACTIVE",
          billingInterval: user.billingInterval || "ANNUAL"
        }
      });
    } catch (err) {
      console.error("[Auth Service] Login error:", err?.message || err);
      return res.status(500).json({ error: "Authentication service error", message: "An internal authentication error occurred." });
    }
  });
  app2.post("/api/auth/signup", (req, res) => {
    try {
      const { email, password, name, accountType, organizationName, plan } = req.body;
      const cleanEmail = (email || "").toLowerCase().trim();
      if (!cleanEmail || !password || cleanEmail.indexOf("@") === -1) {
        return res.status(400).json({ error: "A valid email address and password are required." });
      }
      if (password.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters long." });
      }
      const existing = activeDb.getAdminUserByEmail(cleanEmail);
      if (existing) {
        return res.status(409).json({ error: "An account with this email address already exists." });
      }
      const displayName = name?.trim() || cleanEmail.split("@")[0];
      const username = cleanEmail.split("@")[0].replace(/[^a-zA-Z0-9_]/g, "") || `user_${crypto5.randomBytes(3).toString("hex")}`;
      const passwordHash = hashPassword(password);
      let createdUser;
      if (accountType === "BUSINESS") {
        const orgName = organizationName?.trim() || `${displayName}'s Organization`;
        const newOrg = activeDb.createOrganization({
          name: orgName,
          enforcementMode: "BLOCK",
          telemetryEnabled: true
        }, displayName);
        createdUser = activeDb.createAdminUser({
          email: cleanEmail,
          username,
          name: displayName,
          role: "ORG_ADMIN",
          organizationId: newOrg.organizationId,
          passwordHash,
          plan: "BUSINESS_PRO",
          planStatus: "ACTIVE",
          billingInterval: "ANNUAL"
        }, displayName);
      } else {
        createdUser = activeDb.createAdminUser({
          email: cleanEmail,
          username,
          name: displayName,
          role: "INDIVIDUAL",
          passwordHash,
          plan: plan || "PERSONAL_SHIELD",
          planStatus: "ACTIVE",
          billingInterval: "ANNUAL",
          devicesLimit: 5
        }, displayName);
      }
      const sessionToken = createSession(createdUser);
      const org = createdUser.organizationId ? activeDb.getOrganizationById(createdUser.organizationId) : null;
      res.setHeader(
        "Set-Cookie",
        `phishguard_auth_token=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${CONFIG.isProduction ? "; Secure" : ""}`
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
    } catch (err) {
      res.status(500).json({ error: "Failed to create account", message: err?.message });
    }
  });
  app2.post("/api/auth/logout", (req, res) => {
    const authHeader = req.headers["authorization"];
    const authTokenHeader = req.headers["x-phishguard-auth-token"];
    const cookieHeader = req.headers["cookie"];
    let token = "";
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.slice(7).trim();
    } else if (authTokenHeader) {
      token = authTokenHeader.trim();
    } else if (cookieHeader) {
      const cookies = parseCookieHeader(cookieHeader);
      token = cookies["phishguard_auth_token"] || cookies["session_token"] || "";
    }
    if (token) {
      invalidateSession(token);
    }
    res.setHeader(
      "Set-Cookie",
      "phishguard_auth_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    );
    res.json({ success: true, message: "Signed out successfully" });
  });
  app2.post("/api/auth/forgot-password", (req, res) => {
    res.json({
      success: true,
      message: "If an account exists with this email address, password recovery instructions have been dispatched."
    });
  });
  app2.get("/api/auth/me", authenticateSession, (req, res) => {
    const user = req.user;
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
        plan: user.plan || (user.role === "INDIVIDUAL" ? "PERSONAL_SHIELD" : "BUSINESS_PRO"),
        planStatus: user.planStatus || "ACTIVE",
        billingInterval: user.billingInterval || "ANNUAL"
      },
      organization: org
    });
  });
  app2.post("/api/auth/customer-login", (req, res) => {
    return app2._router.handle({ ...req, url: "/api/auth/login" }, res);
  });
  app2.get("/api/health", (req, res) => {
    const isSupabase = !!(process.env.SUPABASE_URL && (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY));
    const overview = activeDb.getOverviewStats();
    res.json({
      status: "ok",
      service: "PhishGuard Central Enterprise Security Platform",
      version: "1.0.0",
      environment: CONFIG.isProduction ? "production" : "development",
      runtime: process.env.VERCEL ? "Vercel Serverless" : "Node.js Cloud",
      database: {
        type: isSupabase ? "Supabase PostgreSQL" : "Local Persistence",
        status: "ONLINE"
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
  app2.get("/api/version", (req, res) => {
    res.json({
      latestVersion: "1.0.0",
      minSupportedVersion: "1.0.0",
      downloadUrl: "/downloads/phishguard-extension-v1.0.0.zip",
      releaseNotes: "PhishGuard Multi-Tenant Architecture & Enterprise Platform."
    });
  });
  app2.get("/api/config", optionalDeviceAuth, (req, res) => {
    const orgId = req.authenticatedOrgId || req.headers["x-phishguard-org"] || req.query.orgId || "ORG-ACME-PILOT";
    const org = activeDb.getOrganizationById(orgId) || activeDb.getOrganizations()[0];
    res.json({
      organizationId: org?.organizationId || orgId,
      organizationName: org?.name || "Acme Corporation",
      enforcementMode: org?.enforcementMode || "BLOCK",
      telemetryEnabled: org?.telemetryEnabled ?? true,
      minExtensionVersion: org?.minExtensionVersion || "1.0.0",
      retentionDays: org?.retentionDays || 90,
      backendUrl: org?.backendUrl || CONFIG.apiBaseUrl
    });
  });
  const handleEnrollment = (req, res) => {
    try {
      const {
        enrollmentToken,
        token,
        installationId,
        extensionVersion = "1.0.0",
        browser = "Chrome MV3",
        os = "Unknown OS",
        platform = "Desktop",
        deviceName
      } = req.body;
      const effectiveToken = enrollmentToken || token;
      if (!effectiveToken) {
        return res.status(400).json({ error: "Missing required field: enrollmentToken" });
      }
      if (!installationId) {
        return res.status(400).json({ error: "Missing required field: installationId" });
      }
      const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "127.0.0.1";
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
        return res.status(401).json({ error: result.error || "Device enrollment rejected" });
      }
      const org = activeDb.getOrganizationById(result.device.organizationId);
      res.status(201).json({
        success: true,
        deviceId: result.device.deviceId,
        installationId: result.device.installationId,
        organizationId: result.device.organizationId,
        organizationName: org?.name || "Organization",
        deviceApiKey: result.device.deviceApiKey,
        enforcementMode: org?.enforcementMode || "BLOCK",
        minExtensionVersion: org?.minExtensionVersion || "1.0.0",
        backendUrl: org?.backendUrl || CONFIG.apiBaseUrl
      });
    } catch (err) {
      console.error("[API /api/devices/enroll] Error:", err);
      res.status(500).json({ error: "Device enrollment failed", message: err?.message });
    }
  };
  app2.post("/api/devices/enroll", handleEnrollment);
  app2.post("/api/organizations/enroll", handleEnrollment);
  app2.post("/api/enrollment", handleEnrollment);
  const handleHeartbeat = (req, res) => {
    try {
      const authHeader = req.headers["authorization"];
      const deviceKeyHeader = req.headers["x-phishguard-device-key"];
      const token = (authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : deviceKeyHeader) || req.body?.deviceApiKey;
      let device = null;
      if (token) {
        device = activeDb.getDeviceByApiKey(token) || activeDb.getDeviceById(token);
      }
      const {
        deviceId = device?.deviceId,
        installationId = device?.installationId || req.body.installationId,
        extensionVersion = "1.0.0",
        browser = device?.browser || "Chrome MV3",
        os = device?.os || "Unknown OS",
        organizationId = device?.organizationId
      } = req.body;
      if (!deviceId && !installationId) {
        return res.status(400).json({ error: "Missing device identity in heartbeat request" });
      }
      const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "127.0.0.1";
      const result = activeDb.recordHeartbeat({
        deviceId: deviceId || device?.deviceId || "DEV-ANON",
        installationId: installationId || device?.installationId || "inst_anon",
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
    } catch (err) {
      res.status(500).json({ error: "Heartbeat processing failed", message: err?.message });
    }
  };
  app2.post("/api/devices/heartbeat", handleHeartbeat);
  app2.post("/api/device/heartbeat", handleHeartbeat);
  app2.post("/api/heartbeat", handleHeartbeat);
  app2.post("/api/events", optionalDeviceAuth, (req, res) => {
    try {
      const { events, event } = req.body;
      const authenticatedOrg = req.authenticatedOrgId;
      const authenticatedDevice = req.authenticatedDevice;
      const processEvent = (rawEvt) => {
        const orgId = authenticatedOrg || (rawEvt.deviceId ? activeDb.getDeviceById(rawEvt.deviceId)?.organizationId : null) || req.headers["x-phishguard-org"] || "ORG-ACME-PILOT";
        if (rawEvt.deviceId) {
          const matchedDev = activeDb.getDeviceById(rawEvt.deviceId);
          if (matchedDev && matchedDev.organizationId !== orgId && authenticatedOrg && authenticatedOrg !== matchedDev.organizationId) {
            throw new Error(`Device ${rawEvt.deviceId} does not belong to organization ${orgId}`);
          }
        }
        return {
          ...rawEvt,
          organizationId: orgId,
          deviceId: authenticatedDevice?.deviceId || rawEvt.deviceId || "DEV-ANON",
          installationId: authenticatedDevice?.installationId || rawEvt.installationId || "inst_anon"
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
        const targetEvent = event || req.body;
        const processed = processEvent(targetEvent);
        const result = activeDb.ingestSecurityEvent(processed);
        return res.json({
          success: result.success,
          isDuplicate: result.isDuplicate,
          eventId: processed.eventId
        });
      } else {
        return res.status(400).json({ error: "Missing required event or events array in request body" });
      }
    } catch (err) {
      console.error("[API /api/events POST] Error:", err);
      return res.status(400).json({ error: "Event ingestion failed", message: err?.message });
    }
  });
  app2.get(["/api/events", "/api/admin/events"], authenticateSession, (req, res) => {
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
      let targetOrgId = typeof organizationId === "string" ? organizationId : void 0;
      if (req.user && req.user.role !== "SUPER_ADMIN") {
        targetOrgId = req.user.organizationId;
      }
      const result = activeDb.getSecurityEvents({
        search: typeof search === "string" ? search : void 0,
        riskLevel: typeof riskLevel === "string" ? riskLevel : void 0,
        action: typeof action === "string" ? action : void 0,
        threatCategory: typeof threatCategory === "string" ? threatCategory : void 0,
        deviceId: typeof deviceId === "string" ? deviceId : void 0,
        organizationId: targetOrgId,
        sortBy: sortBy === "highest_risk" ? "highest_risk" : "newest",
        page: page ? parseInt(page, 10) : 1,
        pageSize: pageSize ? parseInt(pageSize, 10) : 50
      });
      res.json({
        events: result.events,
        total: result.total,
        page: page ? parseInt(page, 10) : 1,
        pageSize: pageSize ? parseInt(pageSize, 10) : 50
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to retrieve security events" });
    }
  });
  app2.get(["/api/events/:id", "/api/admin/events/:id"], authenticateSession, (req, res) => {
    const orgId = req.user?.role === "SUPER_ADMIN" ? typeof req.query.orgId === "string" ? req.query.orgId : void 0 : req.user?.organizationId;
    const event = activeDb.getEventById(req.params.id, orgId);
    if (!event) {
      return res.status(404).json({ error: "Security event not found" });
    }
    res.json({ event });
  });
  app2.get(["/api/devices", "/api/admin/devices"], authenticateSession, (req, res) => {
    try {
      let targetOrgId = typeof req.query.orgId === "string" ? req.query.orgId : void 0;
      if (req.user && req.user.role !== "SUPER_ADMIN") {
        targetOrgId = req.user.organizationId;
      }
      const devices = activeDb.getDevices(targetOrgId);
      res.json({ devices, total: devices.length });
    } catch (err) {
      res.status(500).json({ error: "Failed to retrieve enrolled devices" });
    }
  });
  app2.get(["/api/devices/:id", "/api/admin/devices/:id"], authenticateSession, (req, res) => {
    let targetOrgId = typeof req.query.orgId === "string" ? req.query.orgId : void 0;
    if (req.user && req.user.role !== "SUPER_ADMIN") {
      targetOrgId = req.user.organizationId;
    }
    const device = activeDb.getDeviceById(req.params.id, targetOrgId);
    if (!device) {
      return res.status(404).json({ error: "Device not found" });
    }
    const events = activeDb.getEventsByDevice(device.deviceId, targetOrgId);
    res.json({ device, events });
  });
  app2.post(["/api/devices/:id/revoke", "/api/admin/devices/:id/revoke"], authenticateSession, (req, res) => {
    try {
      const orgId = req.user?.role === "SUPER_ADMIN" ? void 0 : req.user?.organizationId;
      const ok = activeDb.revokeDevice(req.params.id, orgId, req.user?.name || req.user?.email || "Admin Console");
      if (!ok) {
        return res.status(404).json({ error: "Device not found or not authorized to revoke" });
      }
      res.json({ success: true, message: "Device revoked successfully" });
    } catch (err) {
      res.status(500).json({ error: "Failed to revoke device" });
    }
  });
  app2.get(["/api/overview", "/api/admin/overview"], authenticateSession, (req, res) => {
    try {
      let targetOrgId = typeof req.query.orgId === "string" ? req.query.orgId : void 0;
      if (req.user && req.user.role !== "SUPER_ADMIN") {
        targetOrgId = req.user.organizationId;
      }
      const overview = activeDb.getOverviewStats(targetOrgId);
      res.json(overview);
    } catch (err) {
      res.status(500).json({ error: "Failed to retrieve overview statistics" });
    }
  });
  app2.get("/api/reports/export-csv", authenticateSession, (req, res) => {
    try {
      let targetOrgId = typeof req.query.orgId === "string" ? req.query.orgId : "ORG-ACME-PILOT";
      if (req.user && req.user.role !== "SUPER_ADMIN") {
        targetOrgId = req.user.organizationId || targetOrgId;
      }
      const csv = activeDb.generateCsvExport(targetOrgId);
      res.header("Content-Type", "text/csv");
      res.attachment(`phishguard-security-events-${targetOrgId}-${(/* @__PURE__ */ new Date()).toISOString().slice(0, 10)}.csv`);
      return res.send(csv);
    } catch (err) {
      res.status(500).json({ error: "CSV export failed" });
    }
  });
  app2.get(["/api/organizations", "/api/admin/organizations"], authenticateSession, requireSuperAdmin, (req, res) => {
    res.json({ organizations: activeDb.getOrganizations() });
  });
  app2.get(["/api/organizations/:id", "/api/admin/organizations/:id"], authenticateSession, (req, res) => {
    if (req.user?.role !== "SUPER_ADMIN" && req.user?.organizationId !== req.params.id) {
      return res.status(403).json({ error: "Forbidden: Cannot access another organization." });
    }
    const org = activeDb.getOrganizationById(req.params.id);
    if (!org) return res.status(404).json({ error: "Organization not found" });
    res.json({ organization: org });
  });
  app2.post(["/api/organizations", "/api/admin/organizations"], authenticateSession, requireSuperAdmin, (req, res) => {
    try {
      const org = activeDb.createOrganization(req.body, req.user?.name || "Super Admin");
      res.status(201).json({ success: true, organization: org });
    } catch (err) {
      res.status(500).json({ error: "Failed to create organization" });
    }
  });
  app2.patch(["/api/organizations/:id", "/api/admin/organizations/:id"], authenticateSession, (req, res) => {
    try {
      if (req.user?.role !== "SUPER_ADMIN" && req.user?.organizationId !== req.params.id) {
        return res.status(403).json({ error: "Forbidden: Cannot update another organization." });
      }
      const updated = activeDb.updateOrganization(req.params.id, req.body, req.user?.name || "Admin Console");
      if (!updated) {
        return res.status(404).json({ error: "Organization not found" });
      }
      res.json({ success: true, organization: updated });
    } catch (err) {
      res.status(500).json({ error: "Failed to update organization" });
    }
  });
  app2.post("/api/admin/organizations/:id/suspend", authenticateSession, requireSuperAdmin, (req, res) => {
    try {
      const updated = activeDb.updateOrganization(req.params.id, { status: "SUSPENDED" }, req.user?.name || "Super Admin");
      if (!updated) return res.status(404).json({ error: "Organization not found" });
      res.json({ success: true, organization: updated });
    } catch (err) {
      res.status(500).json({ error: "Failed to suspend organization" });
    }
  });
  app2.post("/api/admin/organizations/:id/reactivate", authenticateSession, requireSuperAdmin, (req, res) => {
    try {
      const updated = activeDb.updateOrganization(req.params.id, { status: "ACTIVE" }, req.user?.name || "Super Admin");
      if (!updated) return res.status(404).json({ error: "Organization not found" });
      res.json({ success: true, organization: updated });
    } catch (err) {
      res.status(500).json({ error: "Failed to reactivate organization" });
    }
  });
  app2.delete("/api/admin/organizations/:id", authenticateSession, requireSuperAdmin, (req, res) => {
    try {
      const ok = activeDb.deleteOrganization ? activeDb.deleteOrganization(req.params.id, req.user?.name || "Super Admin") : false;
      if (!ok) return res.status(404).json({ error: "Organization not found" });
      res.json({ success: true, message: "Organization deleted successfully" });
    } catch (err) {
      res.status(500).json({ error: "Failed to delete organization" });
    }
  });
  app2.get("/api/organizations/:id/tokens", authenticateSession, (req, res) => {
    if (req.user?.role !== "SUPER_ADMIN" && req.user?.organizationId !== req.params.id) {
      return res.status(403).json({ error: "Forbidden: Cannot access another organization's tokens." });
    }
    const tokens = activeDb.getEnrollmentTokens(req.params.id);
    res.json({ tokens });
  });
  app2.post("/api/organizations/:id/tokens", authenticateSession, (req, res) => {
    try {
      if (req.user?.role !== "SUPER_ADMIN" && req.user?.organizationId !== req.params.id) {
        return res.status(403).json({ error: "Forbidden: Cannot create tokens for another organization." });
      }
      const { label, expiresInDays, maxUses } = req.body;
      const token = activeDb.createEnrollmentToken({
        organizationId: req.params.id,
        label,
        expiresInDays,
        maxUses,
        actor: req.user?.name || "Admin Console"
      });
      res.status(201).json({ success: true, token });
    } catch (err) {
      res.status(500).json({ error: "Failed to create enrollment token", message: err?.message });
    }
  });
  app2.post("/api/tokens/:id/revoke", authenticateSession, (req, res) => {
    try {
      const token = activeDb.getEnrollmentTokenById(req.params.id);
      if (!token) return res.status(404).json({ error: "Token not found" });
      if (req.user?.role !== "SUPER_ADMIN" && req.user?.organizationId !== token.organizationId) {
        return res.status(403).json({ error: "Forbidden: Cannot revoke token belonging to another organization." });
      }
      const ok = activeDb.revokeEnrollmentToken(req.params.id, req.user?.name || "Admin Console");
      res.json({ success: ok, message: "Enrollment token revoked successfully" });
    } catch (err) {
      res.status(500).json({ error: "Failed to revoke token" });
    }
  });
  app2.get(["/api/audit", "/api/admin/audit"], authenticateSession, (req, res) => {
    const orgId = req.user?.role === "SUPER_ADMIN" ? typeof req.query.orgId === "string" ? req.query.orgId : void 0 : req.user?.organizationId;
    const logs = activeDb.getAuditLogs(orgId);
    res.json({ logs, total: logs.length });
  });
  app2.get("/api/admin/users", authenticateSession, requireSuperAdmin, (req, res) => {
    const orgId = typeof req.query.orgId === "string" ? req.query.orgId : void 0;
    const users = activeDb.getAdminUsers(orgId).map((u) => ({
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
  app2.post("/api/admin/users", authenticateSession, requireSuperAdmin, (req, res) => {
    try {
      const { email, username, name, role, organizationId, password } = req.body;
      if (!email) return res.status(400).json({ error: "Email is required" });
      const existing = activeDb.getAdminUserByEmail(email);
      if (existing) return res.status(409).json({ error: "User with this email already exists" });
      const chosenPassword = password || crypto5.randomBytes(12).toString("hex");
      const passwordHash = hashPassword(chosenPassword);
      const newUser = activeDb.createAdminUser({
        email,
        username: username || email.split("@")[0],
        name: name || email,
        role: role || "ORG_ADMIN",
        organizationId: role === "SUPER_ADMIN" ? void 0 : organizationId,
        passwordHash
      }, req.user?.name || "Super Admin");
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
    } catch (err) {
      res.status(500).json({ error: "Failed to create user", message: err?.message });
    }
  });
  app2.get("/api/customer/overview", customerAuth, (req, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === "SUPER_ADMIN" ? req.query.orgId || "ORG-ACME-PILOT" : "");
      const org = activeDb.getOrganizationById(orgId);
      if (!org) return res.status(404).json({ error: "Organization not found" });
      const stats = activeDb.getOverviewStats(orgId);
      res.json({
        organization: org,
        stats
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to load customer overview" });
    }
  });
  app2.get("/api/customer/devices", customerAuth, (req, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === "SUPER_ADMIN" ? req.query.orgId || "ORG-ACME-PILOT" : "");
      const devices = activeDb.getDevices(orgId);
      res.json({ devices, total: devices.length });
    } catch (err) {
      res.status(500).json({ error: "Failed to load customer devices" });
    }
  });
  app2.post("/api/customer/devices/:id/revoke", customerAuth, (req, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === "SUPER_ADMIN" ? void 0 : "");
      const ok = activeDb.revokeDevice(req.params.id, orgId, req.user?.name || "Customer Admin");
      if (!ok) {
        return res.status(404).json({ error: "Device not found or not authorized to revoke" });
      }
      res.json({ success: true, message: "Device revoked from your fleet" });
    } catch (err) {
      res.status(500).json({ error: "Failed to revoke customer device" });
    }
  });
  app2.get("/api/customer/events", customerAuth, (req, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === "SUPER_ADMIN" ? req.query.orgId || "ORG-ACME-PILOT" : "");
      const { search, riskLevel, action, threatCategory, deviceId, sortBy, page, pageSize } = req.query;
      const result = activeDb.getSecurityEvents({
        search: typeof search === "string" ? search : void 0,
        riskLevel: typeof riskLevel === "string" ? riskLevel : void 0,
        action: typeof action === "string" ? action : void 0,
        threatCategory: typeof threatCategory === "string" ? threatCategory : void 0,
        deviceId: typeof deviceId === "string" ? deviceId : void 0,
        organizationId: orgId,
        sortBy: sortBy === "highest_risk" ? "highest_risk" : "newest",
        page: page ? parseInt(page, 10) : 1,
        pageSize: pageSize ? parseInt(pageSize, 10) : 50
      });
      res.json({
        events: result.events,
        total: result.total,
        page: page ? parseInt(page, 10) : 1,
        pageSize: pageSize ? parseInt(pageSize, 10) : 50
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to load customer events" });
    }
  });
  app2.get("/api/customer/tokens", customerAuth, (req, res) => {
    const orgId = req.user?.organizationId || (req.user?.role === "SUPER_ADMIN" ? req.query.orgId || "ORG-ACME-PILOT" : "");
    const tokens = activeDb.getEnrollmentTokens(orgId);
    res.json({ tokens });
  });
  app2.post("/api/customer/tokens", customerAuth, (req, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === "SUPER_ADMIN" ? req.body.organizationId || "ORG-ACME-PILOT" : "");
      const { label, expiresInDays, maxUses } = req.body;
      const token = activeDb.createEnrollmentToken({
        organizationId: orgId,
        label: label || "Enterprise Deployment Token",
        expiresInDays,
        maxUses,
        actor: req.user?.name || "Customer Admin"
      });
      res.status(201).json({ success: true, token });
    } catch (err) {
      res.status(500).json({ error: "Failed to create enrollment token" });
    }
  });
  app2.post("/api/customer/tokens/:id/revoke", customerAuth, (req, res) => {
    try {
      const token = activeDb.getEnrollmentTokenById(req.params.id);
      if (!token) return res.status(404).json({ error: "Token not found" });
      const orgId = req.user?.organizationId;
      if (req.user?.role !== "SUPER_ADMIN" && token.organizationId !== orgId) {
        return res.status(403).json({ error: "Forbidden: Cannot revoke token belonging to another organization" });
      }
      const ok = activeDb.revokeEnrollmentToken(req.params.id, req.user?.name || "Customer Admin");
      res.json({ success: ok, message: "Enrollment token revoked" });
    } catch (err) {
      res.status(500).json({ error: "Failed to revoke token" });
    }
  });
  app2.patch("/api/customer/settings", customerAuth, (req, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === "SUPER_ADMIN" ? req.body.organizationId || "ORG-ACME-PILOT" : "");
      const { enforcementMode, telemetryEnabled, minExtensionVersion } = req.body;
      const updated = activeDb.updateOrganization(orgId, {
        enforcementMode,
        telemetryEnabled,
        minExtensionVersion
      }, req.user?.name || "Customer Admin");
      res.json({ success: true, organization: updated });
    } catch (err) {
      res.status(500).json({ error: "Failed to update customer settings" });
    }
  });
  app2.get("/api/customer/export-csv", customerAuth, (req, res) => {
    try {
      const orgId = req.user?.organizationId || (req.user?.role === "SUPER_ADMIN" ? req.query.orgId || "ORG-ACME-PILOT" : "");
      const csv = activeDb.generateCsvExport(orgId);
      res.header("Content-Type", "text/csv");
      res.attachment(`phishguard-security-events-${orgId}-${(/* @__PURE__ */ new Date()).toISOString().slice(0, 10)}.csv`);
      return res.send(csv);
    } catch (err) {
      res.status(500).json({ error: "Customer CSV export failed" });
    }
  });
  app2.get("/api/individual/overview", individualAuth, (req, res) => {
    try {
      const user = req.user;
      const personalOrgId = user.organizationId || `INDIVIDUAL-${user.id}`;
      const devices = activeDb.getDevices(personalOrgId);
      const events = activeDb.getSecurityEvents({ organizationId: personalOrgId, pageSize: 20 });
      res.json({
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          plan: user.plan || "PERSONAL_SHIELD",
          planStatus: user.planStatus || "ACTIVE",
          billingInterval: user.billingInterval || "ANNUAL",
          devicesLimit: user.devicesLimit || 5
        },
        stats: {
          activeShield: true,
          protectedDevices: devices.length || 1,
          maxDevices: user.devicesLimit || 5,
          blockedThreatsCount: events.total || 0,
          lastActive: user.lastLoginAt || Date.now(),
          threatLevel: "SECURE"
        }
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to load individual overview" });
    }
  });
  app2.get("/api/individual/devices", individualAuth, (req, res) => {
    try {
      const user = req.user;
      const personalOrgId = user.organizationId || `INDIVIDUAL-${user.id}`;
      let devices = activeDb.getDevices(personalOrgId);
      if (devices.length === 0) {
        devices = [{
          id: `dev_${user.id.slice(0, 8)}_primary`,
          installationId: `inst_${user.id.slice(0, 8)}_primary`,
          deviceId: `dev_${user.id.slice(0, 8)}_primary`,
          organizationId: personalOrgId,
          deviceName: `${user.name}'s Primary Browser`,
          browser: "Chrome 128 / macOS",
          os: "macOS",
          extensionVersion: "1.0.0",
          firstSeen: user.createdAt,
          lastSeen: Date.now(),
          status: "ONLINE",
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
    } catch (err) {
      res.status(500).json({ error: "Failed to load devices" });
    }
  });
  app2.post("/api/individual/enroll-token", individualAuth, (req, res) => {
    try {
      const user = req.user;
      const personalOrgId = user.organizationId || `INDIVIDUAL-${user.id}`;
      const token = activeDb.createEnrollmentToken({
        organizationId: personalOrgId,
        label: `${user.name} Personal Device Token`,
        expiresInDays: 365,
        maxUses: user.devicesLimit || 5,
        actor: user.name
      });
      res.json({ success: true, token });
    } catch (err) {
      res.status(500).json({ error: "Failed to generate personal enrollment token" });
    }
  });
  app2.get("/api/individual/events", individualAuth, (req, res) => {
    try {
      const user = req.user;
      const personalOrgId = user.organizationId || `INDIVIDUAL-${user.id}`;
      const result = activeDb.getSecurityEvents({
        organizationId: personalOrgId,
        pageSize: 50
      });
      res.json({
        events: result.events,
        total: result.total
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to load personal events" });
    }
  });
  app2.patch("/api/individual/profile", individualAuth, (req, res) => {
    try {
      const user = req.user;
      const { name, password } = req.body;
      const updates = {};
      if (name && typeof name === "string") updates.name = name.trim();
      if (password && typeof password === "string" && password.length >= 8) {
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
    } catch (err) {
      res.status(500).json({ error: "Failed to update profile" });
    }
  });
  app2.use((req, res, next) => {
    const p = req.path || req.url || "";
    if (p.startsWith("/api") || p.startsWith("/auth")) {
      if (!res.headersSent) {
        return res.status(404).json({
          error: "Route not found",
          method: req.method,
          path: req.originalUrl || req.url
        });
      }
    }
    next();
  });
  app2.use((err, req, res, next) => {
    console.error("[PhishGuard Server] Uncaught route error:", err?.message || err);
    if (res.headersSent) {
      return next(err);
    }
    res.status(err?.status || 500).json({
      error: "An internal server error occurred.",
      message: err?.message || "Internal Server Error"
    });
  });
  return app2;
}

// src/server/api.ts
var app = createExpressApp();
var api_default = app;
export {
  api_default as default
};
//# sourceMappingURL=index.js.map
