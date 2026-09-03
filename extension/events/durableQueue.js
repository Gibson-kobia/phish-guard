import {
  computeEndpointStatusModel
} from "../types";
const MAX_QUEUE_SIZE = 500;
const BATCH_SYNC_SIZE = 25;
const DEFAULT_BACKEND_URL = typeof process !== "undefined" && process.env?.PHISHGUARD_API_BASE_URL ? process.env.PHISHGUARD_API_BASE_URL : "http://localhost:3000";
class DurableTelemetryQueue {
  constructor(options) {
    this.queue = [];
    this.syncedEventIds = /* @__PURE__ */ new Set();
    this.isSyncing = false;
    this.backendUrl = DEFAULT_BACKEND_URL;
    this.organizationId = "";
    this.organizationName = "";
    this.enrollmentToken = "";
    this.deviceApiKey = "";
    this.installationId = "";
    this.deviceId = "";
    this.extensionVersion = "1.0.0";
    this.telemetryEnabled = true;
    this.localProtectionActive = true;
    this.isEnrolled = false;
    this.isEnrolling = false;
    this.isRevoked = false;
    this.enrollmentFailed = false;
    this.enrollmentFailureReason = null;
    this.syncErrorReason = null;
    this.telemetryFailureReason = null;
    this.deviceManagementState = "UNKNOWN";
    this.lastHeartbeatTime = 0;
    this.lastSyncTime = 0;
    this.failedSyncAttempts = 0;
    this.isOnline = true;
    this.maxQueueSize = MAX_QUEUE_SIZE;
    this.initIdentifiers();
    if (options) {
      if (options.backendUrl) this.backendUrl = options.backendUrl;
      if (options.organizationId) {
        this.organizationId = options.organizationId;
        this.isEnrolled = true;
        this.deviceManagementState = "ACTIVE";
      }
      if (options.organizationName) this.organizationName = options.organizationName;
      if (options.enrollmentToken) this.enrollmentToken = options.enrollmentToken;
      if (options.deviceApiKey) {
        this.deviceApiKey = options.deviceApiKey;
        this.isEnrolled = true;
        this.deviceManagementState = "ACTIVE";
      }
      if (typeof options.telemetryEnabled === "boolean") this.telemetryEnabled = options.telemetryEnabled;
      if (typeof options.localProtectionActive === "boolean") this.localProtectionActive = options.localProtectionActive;
      if (options.extensionVersion) this.extensionVersion = options.extensionVersion;
      if (options.deviceId) this.deviceId = options.deviceId;
      if (options.installationId) this.installationId = options.installationId;
      if (options.fetchProvider) this.customFetch = options.fetchProvider;
      if (options.storageProvider) this.customStorage = options.storageProvider;
      if (options.maxQueueSize) this.maxQueueSize = options.maxQueueSize;
    }
  }
  initIdentifiers() {
    let storedInstallId = null;
    let storedDeviceId = null;
    let storedOrgId = null;
    let storedOrgName = null;
    let storedBackend = null;
    let storedApiKey = null;
    if (typeof localStorage !== "undefined") {
      try {
        storedInstallId = localStorage.getItem("phishguard_installation_id");
        storedDeviceId = localStorage.getItem("phishguard_device_id");
        storedOrgId = localStorage.getItem("phishguard_org_id");
        storedOrgName = localStorage.getItem("phishguard_org_name");
        storedBackend = localStorage.getItem("phishguard_backend_url");
        storedApiKey = localStorage.getItem("phishguard_device_api_key");
      } catch {
      }
    }
    this.installationId = storedInstallId || `inst_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    this.deviceId = storedDeviceId || `DEV-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
    if (storedBackend) this.backendUrl = storedBackend;
    if (storedOrgId) this.organizationId = storedOrgId;
    if (storedOrgName) this.organizationName = storedOrgName;
    if (storedApiKey) {
      this.deviceApiKey = storedApiKey;
      this.isEnrolled = true;
    }
    if (typeof localStorage !== "undefined") {
      try {
        localStorage.setItem("phishguard_installation_id", this.installationId);
        localStorage.setItem("phishguard_device_id", this.deviceId);
      } catch {
      }
    }
  }
  /**
   * Initializes enterprise storage configuration (reads Chrome Managed Policy or local storage)
   */
  async loadManagedPolicy() {
    try {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.managed) {
        const managed = await chrome.storage.managed.get(["PhishGuardApiBaseUrl", "EnrollmentToken", "OrganizationName", "EnforcementMode"]).catch(() => null);
        if (managed) {
          if (managed.PhishGuardApiBaseUrl) this.backendUrl = managed.PhishGuardApiBaseUrl;
          if (managed.EnrollmentToken) this.enrollmentToken = managed.EnrollmentToken;
          if (managed.OrganizationName) this.organizationName = managed.OrganizationName;
        }
      }
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        const local = await chrome.storage.local.get([
          "phishguard_installation_id",
          "phishguard_device_id",
          "phishguard_org_id",
          "phishguard_org_name",
          "phishguard_device_api_key",
          "phishguard_backend_url",
          "phishguard_enrollment_token",
          "phishguard_local_active"
        ]).catch(() => null);
        if (local) {
          if (local.phishguard_installation_id) this.installationId = local.phishguard_installation_id;
          if (local.phishguard_device_id) this.deviceId = local.phishguard_device_id;
          if (local.phishguard_org_id) this.organizationId = local.phishguard_org_id;
          if (local.phishguard_org_name) this.organizationName = local.phishguard_org_name;
          if (local.phishguard_enrollment_token) this.enrollmentToken = local.phishguard_enrollment_token;
          if (typeof local.phishguard_local_active === "boolean") this.localProtectionActive = local.phishguard_local_active;
          if (local.phishguard_device_api_key) {
            this.deviceApiKey = local.phishguard_device_api_key;
            this.isEnrolled = true;
          }
          if (local.phishguard_backend_url) this.backendUrl = local.phishguard_backend_url;
        }
      }
    } catch {
    }
  }
  setConfig(config) {
    if (config.backendUrl) this.backendUrl = config.backendUrl;
    if (config.organizationId) {
      this.organizationId = config.organizationId;
      this.isEnrolled = true;
    }
    if (config.organizationName) this.organizationName = config.organizationName;
    if (config.enrollmentToken) this.enrollmentToken = config.enrollmentToken;
    if (config.deviceApiKey) {
      this.deviceApiKey = config.deviceApiKey;
      this.isEnrolled = true;
    }
    if (typeof config.telemetryEnabled === "boolean") this.telemetryEnabled = config.telemetryEnabled;
    if (typeof config.localProtectionActive === "boolean") this.localProtectionActive = config.localProtectionActive;
    if (config.extensionVersion) this.extensionVersion = config.extensionVersion;
    if (config.deviceId) this.deviceId = config.deviceId;
    if (config.installationId) this.installationId = config.installationId;
  }
  setLocalProtectionActive(active) {
    this.localProtectionActive = active;
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ phishguard_local_active: active }).catch(() => {
      });
    }
  }
  /**
   * Computes the authoritative endpoint status model distinguishing:
   * 1. Local Protection State (LOCAL_PROTECTION_ACTIVE vs PAUSED)
   * 2. Cloud Enrollment State (NOT_ENROLLED, ENROLLING, ENROLLED, ENROLLMENT_FAILED, ENROLLMENT_REVOKED)
   * 3. Cloud Sync State (SYNCED, SYNCING, CLOUD_OFFLINE, SYNC_ERROR)
   * 4. Device Management State (ACTIVE, SUSPENDED, REVOKED, UNKNOWN)
   * 5. Security Telemetry State (TELEMETRY_PENDING, TELEMETRY_SYNCED, TELEMETRY_QUEUED, TELEMETRY_FAILED)
   * 6. Cloud Availability (ONLINE, OFFLINE, DEGRADED)
   */
  getStatusModel() {
    return computeEndpointStatusModel({
      localProtectionActive: this.localProtectionActive,
      isEnrolled: this.isEnrolled && !!this.organizationId,
      isEnrolling: this.isEnrolling,
      isOnline: this.isOnline,
      isRevoked: this.isRevoked,
      enrollmentFailed: this.enrollmentFailed,
      enrollmentFailureReason: this.enrollmentFailureReason,
      syncErrorReason: this.syncErrorReason,
      telemetryFailureReason: this.telemetryFailureReason,
      deviceManagementState: this.deviceManagementState,
      organizationId: this.organizationId,
      organizationName: this.organizationName,
      deviceId: this.deviceId,
      lastSyncTime: this.lastSyncTime,
      lastHeartbeatTime: this.lastHeartbeatTime,
      queueSize: this.queue.length
    });
  }
  getIdentifiers() {
    return {
      installationId: this.installationId,
      deviceId: this.deviceId,
      organizationId: this.organizationId,
      organizationName: this.organizationName,
      enrollmentToken: this.enrollmentToken,
      deviceApiKey: this.deviceApiKey ? `${this.deviceApiKey.slice(0, 10)}...` : "",
      isEnrolled: this.isEnrolled,
      isRevoked: this.isRevoked,
      backendUrl: this.backendUrl,
      extensionVersion: this.extensionVersion,
      telemetryEnabled: this.telemetryEnabled,
      localProtectionActive: this.localProtectionActive,
      isOnline: this.isOnline,
      queueSize: this.queue.length,
      lastSyncTime: this.lastSyncTime,
      statusModel: this.getStatusModel()
    };
  }
  /**
   * Device Enrollment Flow:
   * Contacts backend with enrollment token to establish device identity & obtain secret API key.
   */
  async enrollDevice(tokenOverride, backendOverride) {
    const token = tokenOverride || this.enrollmentToken;
    if (!token) {
      this.enrollmentFailed = true;
      this.enrollmentFailureReason = "INVALID_TOKEN";
      return { success: false, error: "Missing enrollment token", statusModel: this.getStatusModel() };
    }
    if (backendOverride) this.backendUrl = backendOverride;
    const fetchImpl = this.customFetch || (typeof fetch !== "undefined" ? fetch : void 0);
    if (!fetchImpl) {
      this.enrollmentFailed = true;
      this.enrollmentFailureReason = "API_UNAVAILABLE";
      return { success: false, error: "Fetch API unavailable", statusModel: this.getStatusModel() };
    }
    this.isEnrolling = true;
    this.enrollmentFailed = false;
    this.enrollmentFailureReason = null;
    this.isRevoked = false;
    try {
      const res = await fetchImpl(`${this.backendUrl}/api/devices/enroll`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enrollmentToken: token,
          installationId: this.installationId,
          extensionVersion: this.extensionVersion,
          browser: typeof navigator !== "undefined" ? navigator.userAgent : "Chrome MV3",
          os: typeof navigator !== "undefined" ? navigator.platform : "Unknown OS"
        })
      });
      this.isEnrolling = false;
      if (!res.ok) {
        const errData = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
        const errMsg = errData.error || `HTTP ${res.status}`;
        this.enrollmentFailed = true;
        if (errMsg.toLowerCase().includes("revoked")) {
          this.enrollmentFailureReason = "REVOKED_TOKEN";
        } else if (errMsg.toLowerCase().includes("expired")) {
          this.enrollmentFailureReason = "EXPIRED_TOKEN";
        } else if (errMsg.toLowerCase().includes("invalid")) {
          this.enrollmentFailureReason = "INVALID_TOKEN";
        } else {
          this.enrollmentFailureReason = "SERVER_VALIDATION_FAILURE";
        }
        return { success: false, error: errMsg, statusModel: this.getStatusModel() };
      }
      const data = await res.json();
      if (data.success && data.deviceApiKey) {
        this.deviceId = data.deviceId;
        this.organizationId = data.organizationId;
        this.organizationName = data.organizationName || data.organizationId;
        this.deviceApiKey = data.deviceApiKey;
        this.enrollmentToken = token;
        this.isEnrolled = true;
        this.isOnline = true;
        this.isRevoked = false;
        this.enrollmentFailed = false;
        this.enrollmentFailureReason = null;
        this.deviceManagementState = "ACTIVE";
        this.lastSyncTime = Date.now();
        if (typeof localStorage !== "undefined") {
          try {
            localStorage.setItem("phishguard_device_id", this.deviceId);
            localStorage.setItem("phishguard_org_id", this.organizationId);
            localStorage.setItem("phishguard_org_name", this.organizationName);
            localStorage.setItem("phishguard_device_api_key", this.deviceApiKey);
            localStorage.setItem("phishguard_enrollment_token", this.enrollmentToken);
          } catch {
          }
        }
        if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
          await chrome.storage.local.set({
            phishguard_device_id: this.deviceId,
            phishguard_org_id: this.organizationId,
            phishguard_org_name: this.organizationName,
            phishguard_device_api_key: this.deviceApiKey,
            phishguard_enrollment_token: this.enrollmentToken
          }).catch(() => {
          });
        }
        return { success: true, statusModel: this.getStatusModel() };
      }
      this.enrollmentFailed = true;
      this.enrollmentFailureReason = "SERVER_VALIDATION_FAILURE";
      return { success: false, error: data.error || "Invalid server response", statusModel: this.getStatusModel() };
    } catch (err) {
      this.isEnrolling = false;
      this.isOnline = false;
      this.enrollmentFailed = true;
      this.enrollmentFailureReason = "NETWORK_ERROR";
      return { success: false, error: err?.message || "Network failure during enrollment", statusModel: this.getStatusModel() };
    }
  }
  /**
   * Resets device back to Individual / Personal standalone mode (NOT_ENROLLED).
   */
  async unenroll() {
    this.isEnrolled = false;
    this.isEnrolling = false;
    this.isRevoked = false;
    this.enrollmentFailed = false;
    this.enrollmentFailureReason = null;
    this.deviceManagementState = "UNKNOWN";
    this.organizationId = "";
    this.organizationName = "";
    this.deviceApiKey = "";
    this.enrollmentToken = "";
    this.queue = [];
    if (typeof localStorage !== "undefined") {
      try {
        localStorage.removeItem("phishguard_org_id");
        localStorage.removeItem("phishguard_org_name");
        localStorage.removeItem("phishguard_device_api_key");
        localStorage.removeItem("phishguard_enrollment_token");
      } catch {
      }
    }
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      await chrome.storage.local.remove([
        "phishguard_org_id",
        "phishguard_org_name",
        "phishguard_device_api_key",
        "phishguard_enrollment_token"
      ]).catch(() => {
      });
    }
    return { success: true, statusModel: this.getStatusModel() };
  }
  /**
   * Enqueues a canonical security event.
   * If the queue exceeds MAX_QUEUE_SIZE, the oldest events are dropped to prevent memory leaks.
   */
  enqueue(event) {
    if (!event || !event.eventId) return;
    if (this.syncedEventIds.has(event.eventId) || this.queue.some((e) => e.eventId === event.eventId)) {
      return;
    }
    event.installationId = this.installationId;
    event.deviceId = this.deviceId;
    event.organizationId = this.organizationId;
    event.extensionVersion = this.extensionVersion;
    this.queue.push(event);
    if (this.queue.length > this.maxQueueSize) {
      this.queue.splice(0, this.queue.length - this.maxQueueSize);
    }
    if (this.telemetryEnabled) {
      this.flushQueueAsync().catch(() => {
      });
    }
  }
  getQueueLength() {
    return this.queue.length;
  }
  getQueueSize() {
    return this.queue.length;
  }
  getPendingEvents() {
    return [...this.queue];
  }
  /**
   * Flushes up to BATCH_SYNC_SIZE events to the central backend.
   * Uses device credentials for authenticated ingestion.
   */
  async flushQueue() {
    if (!this.telemetryEnabled || this.queue.length === 0 || this.isSyncing) {
      return { synced: 0, remaining: this.queue.length };
    }
    this.isSyncing = true;
    const batch = this.queue.slice(0, BATCH_SYNC_SIZE);
    const fetchImpl = this.customFetch || (typeof fetch !== "undefined" ? fetch : void 0);
    if (!fetchImpl) {
      this.isSyncing = false;
      return { synced: 0, remaining: this.queue.length, error: "Fetch API unavailable" };
    }
    try {
      const authHeader = this.deviceApiKey ? `Bearer ${this.deviceApiKey}` : `Bearer ${this.enrollmentToken}`;
      const response = await fetchImpl(`${this.backendUrl}/api/events`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": authHeader,
          "X-PhishGuard-Device-Key": this.deviceApiKey || "",
          "X-PhishGuard-Device": this.deviceId,
          "X-PhishGuard-Org": this.organizationId,
          "X-Extension-Version": this.extensionVersion
        },
        body: JSON.stringify({
          organizationId: this.organizationId,
          deviceId: this.deviceId,
          installationId: this.installationId,
          events: batch
        })
      });
      if (response.ok) {
        const syncedIds = new Set(batch.map((e) => e.eventId));
        this.queue = this.queue.filter((e) => !syncedIds.has(e.eventId));
        for (const id of syncedIds) {
          this.syncedEventIds.add(id);
          if (this.syncedEventIds.size > 2e3) {
            const first = this.syncedEventIds.values().next().value;
            if (first) this.syncedEventIds.delete(first);
          }
        }
        this.lastSyncTime = Date.now();
        this.failedSyncAttempts = 0;
        this.isOnline = true;
        this.syncErrorReason = null;
        this.telemetryFailureReason = null;
        this.isSyncing = false;
        return { synced: batch.length, remaining: this.queue.length };
      } else if (response.status === 401) {
        this.failedSyncAttempts++;
        this.isRevoked = true;
        this.isEnrolled = false;
        this.deviceManagementState = "REVOKED";
        this.syncErrorReason = "DEVICE_REVOKED";
        this.telemetryFailureReason = "AUTHENTICATION_FAILURE";
        this.isSyncing = false;
        return { synced: 0, remaining: this.queue.length, error: "Device enrollment has been revoked by administrator" };
      } else {
        this.failedSyncAttempts++;
        this.isOnline = false;
        this.syncErrorReason = "API_ERROR";
        this.telemetryFailureReason = "API_REJECTED_EVENT";
        this.isSyncing = false;
        return { synced: 0, remaining: this.queue.length, error: `HTTP ${response.status}` };
      }
    } catch (err) {
      this.failedSyncAttempts++;
      this.isOnline = false;
      this.syncErrorReason = "NETWORK_FAILURE";
      this.telemetryFailureReason = "NETWORK_UNAVAILABLE";
      this.isSyncing = false;
      return { synced: 0, remaining: this.queue.length, error: err?.message || "Network error" };
    }
  }
  async flushQueueAsync() {
    try {
      await this.flushQueue();
    } catch {
    }
  }
  /**
   * Dispatches periodic heartbeat to authenticate endpoint and sync health.
   */
  async sendHeartbeat() {
    try {
      const payload = {
        installationId: this.installationId,
        deviceId: this.deviceId,
        organizationId: this.organizationId,
        extensionVersion: this.extensionVersion,
        browser: typeof navigator !== "undefined" ? navigator.userAgent : "Chrome MV3",
        os: typeof navigator !== "undefined" ? navigator.platform : "Unknown",
        queueSize: this.queue.length
      };
      const fetchImpl = this.customFetch || (typeof fetch !== "undefined" ? fetch : void 0);
      if (!fetchImpl) {
        return { success: false };
      }
      const authHeader = this.deviceApiKey ? `Bearer ${this.deviceApiKey}` : `Bearer ${this.enrollmentToken}`;
      const res = await fetchImpl(`${this.backendUrl}/api/devices/heartbeat`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": authHeader,
          "X-PhishGuard-Device-Key": this.deviceApiKey || "",
          "X-PhishGuard-Device": this.deviceId,
          "X-PhishGuard-Org": this.organizationId
        },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        const data = await res.json().catch(() => null);
        this.lastHeartbeatTime = Date.now();
        this.isOnline = true;
        this.syncErrorReason = null;
        return { success: true, config: data };
      } else if (res.status === 401) {
        this.isRevoked = true;
        this.isEnrolled = false;
        this.deviceManagementState = "REVOKED";
        this.syncErrorReason = "DEVICE_REVOKED";
        return { success: false };
      } else {
        this.isOnline = false;
        this.syncErrorReason = "API_ERROR";
        return { success: false };
      }
    } catch {
      this.isOnline = false;
      this.syncErrorReason = "NETWORK_FAILURE";
      return { success: false };
    }
  }
  clearQueue() {
    this.queue = [];
  }
}
const globalTelemetryQueue = new DurableTelemetryQueue();
export {
  BATCH_SYNC_SIZE,
  DEFAULT_BACKEND_URL,
  DurableTelemetryQueue,
  MAX_QUEUE_SIZE,
  globalTelemetryQueue
};
