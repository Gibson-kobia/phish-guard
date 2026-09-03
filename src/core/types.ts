/**
 * PhishGuard Core Types & Signal Definitions
 * 
 * Canonical Single Source of Truth for:
 * 1. Chrome Extension Background Worker & Runtime
 * 2. In-browser Security Evaluation Playground / Developer Console
 * 3. Automated Security Test Runner
 */

export type SeverityLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ThreatSeverity = SeverityLevel;

// 5 Risk Tiers for consumer clarity
export type Verdict = 'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'HIGH_RISK' | 'DANGEROUS';

export type SignalCategory = 
  | 'URL_STRUCTURE'
  | 'TYPOSQUATTING'
  | 'DOM_SECURITY'
  | 'REPUTATION'
  | 'REDIRECT_CHAIN'
  | 'REDIRECT'
  | 'SOCIAL_ENGINEERING'
  | 'DOWNLOAD_SECURITY'
  | 'NETWORK_REQUEST'
  | 'PROTOCOL';

export interface DetectionSignal {
  id: string;
  category: SignalCategory;
  type: string;
  severity: ThreatSeverity;
  weight: number; // 0 - 100 base score contribution
  title: string;
  description: string;
  evidence?: Record<string, any>;
  confidence: number; // 0.0 to 1.0
}

export interface ProtectedBrand {
  id: string;
  name: string;
  canonicalDomains: string[];
  keywords: string[];
  category: 'FINANCIAL' | 'TECH' | 'SOCIAL' | 'CRYPTO' | 'ECOMMERCE' | 'PRODUCTIVITY' | 'OTHER';
}

export interface FormAnalysisMetadata {
  hasPasswordInput: boolean;
  hasCreditCardInput: boolean;
  hasSsnInput: boolean;
  hasEmailOrUserInput: boolean;
  has2FAInput: boolean;
  formsCount: number;
  suspiciousForms: Array<{
    action: string;
    method: string;
    isCrossOrigin: boolean;
    isInsecureHttp: boolean;
    hasPasswordField: boolean;
    inputCount: number;
    hiddenInputsCount: number;
  }>;
  hasHiddenCredentialFields: boolean;
  hasExternalScriptSources?: string[];
  pageTitle?: string;
}

export interface SocialEngineeringMetadata {
  hasUrgencyLanguage: boolean;
  hasAccountSuspensionNotice: boolean;
  hasCredentialVerificationPrompt: boolean;
  hasFakeTechSupportLanguage: boolean;
  hasPaymentUrgency: boolean;
  hasPrizeOrRewardClaim: boolean;
  detectedPhrases: string[];
  visibleHeadingsSample: string[];
}

export interface UrlFeatures {
  protocol: string;
  hostname: string;
  path: string;
  query: string;
  port: string;
  isIpAddress: boolean;
  isPunycode: boolean;
  decodedPunycode?: string;
  subdomainCount: number;
  domainParts: string[];
  tld: string;
  hasUserinfo: boolean;
  hasSuspiciousPort: boolean;
  hasHighRiskTld: boolean;
  suspiciousKeywords: string[];
  length: number;
  entropy: number;
  hyphenCount: number;
  dotCount: number;
}

export interface RedirectHop {
  url: string;
  timestamp: number;
  statusCode?: number;
}

export interface RedirectAnalysisData {
  initialUrl: string;
  finalUrl: string;
  hops: RedirectHop[];
  hopCount: number;
  hasUrlShortener?: boolean;
  hasShortener?: boolean;
  hasCrossDomainRedirect?: boolean;
  lastUpdated?: number;
}

export type RedirectMetadata = RedirectAnalysisData;

export interface DownloadSecurityContext {
  downloadId: number;
  url: string;
  filename: string;
  fileExtension: string;
  originUrl: string;
  originRiskScore: number;
  originVerdict: Verdict;
  isDangerousOrigin: boolean;
  isExecutable: boolean;
  timestamp: number;
}

export interface SecurityTimelineEvent {
  id: string;
  timestamp: number;
  timeString?: string;
  type: 
    | 'NAVIGATION'
    | 'DOMAIN_EVAL'
    | 'FORM_SECURITY'
    | 'REDIRECT_CHAIN'
    | 'SOCIAL_ENGINEERING'
    | 'DOWNLOAD_CONTEXT'
    | 'RISK_CALC'
    | 'ACTION';
  title: string;
  description: string;
  severity?: ThreatSeverity;
}

export interface SecurityEvidenceItem {
  id: string;
  category: SignalCategory;
  severity: ThreatSeverity;
  weight: number;
  summary: string;
  explanation: string;
}

export interface SecurityAnalysisResult {
  url: string;
  domain: string;
  timestamp: number;
  score: number; // 0 - 100
  severity: ThreatSeverity;
  verdict: Verdict;
  signals: DetectionSignal[];
  evidenceItems: SecurityEvidenceItem[];
  timeline: SecurityTimelineEvent[];
  reasons: string[];
  targetBrand?: ProtectedBrand;
  scanDurationMs: number;
  features?: {
    url?: UrlFeatures;
    form?: FormAnalysisMetadata | null;
    social?: SocialEngineeringMetadata | null;
    redirect?: RedirectAnalysisData | null;
    download?: DownloadSecurityContext | null;
    reputation?: {
      isAllowlisted: boolean;
      isBlocklisted: boolean;
      matchedDomain?: string;
    };
  };
  // Backwards compatibility alias properties
  urlFeatures?: UrlFeatures;
  formFeatures?: FormAnalysisMetadata | null;
  redirectFeatures?: RedirectAnalysisData | null;
  analysisTimeMs?: number;
}

export type AnalysisResult = SecurityAnalysisResult;

export interface ExtensionSettings {
  protectionEnabled: boolean;
  detectionSensitivity: 'CONSERVATIVE' | 'BALANCED' | 'AGGRESSIVE';
  warningThreshold: number; // e.g. 70
  blockThreshold: number; // e.g. 90
  enableUrlAnalysis: boolean;
  enableTyposquatting: boolean;
  enableDomAnalysis: boolean;
  enableSocialEngineering: boolean;
  enableRedirectAnalysis: boolean;
  enableDownloadContext: boolean;
  enableReputationLayer: boolean;
  enableNotifications: boolean;
  protectedBrands: ProtectedBrand[];
  allowlist: string[];
  blocklist: string[];
  developerMode: boolean;
  scanHistoryLimit: number;
}

export interface ScanHistoryItem {
  id: string;
  timestamp: number;
  url: string;
  domain: string;
  score: number;
  severity: ThreatSeverity;
  verdict: Verdict;
  topSignal: string;
  reasons: string[];
  userAction?: 'VISITED' | 'BLOCKED' | 'ALLOWED' | 'DISMISSED';
}

export interface SecurityTestCase {
  id: string;
  name: string;
  description: string;
  category: 
    | 'SAFE_BASELINE' 
    | 'HOMOGLYPH' 
    | 'COMBOSQUAT' 
    | 'RAW_IP' 
    | 'SUBDOMAINS' 
    | 'CREDENTIAL_HARVEST' 
    | 'REDIRECT' 
    | 'SOCIAL_ENGINEERING'
    | 'DOWNLOAD_CONTEXT';
  url: string;
  mockForm?: FormAnalysisMetadata | null;
  mockSocial?: SocialEngineeringMetadata | null;
  mockRedirect?: RedirectAnalysisData | null;
  mockDownload?: DownloadSecurityContext | null;
  expectedVerdict: Verdict;
  expectedMinScore: number;
  expectedMaxScore: number;
  expectedSignals: string[];
}

export interface TestSuiteResult {
  totalTests: number;
  passedTests: number;
  failedTests: number;
  durationMs: number;
  results: Array<{
    testCase: SecurityTestCase;
    passed: boolean;
    actualResult: SecurityAnalysisResult;
    failureReason?: string;
  }>;
}

export type TestRunResult = TestSuiteResult;

// ============================================================================
// THREAT INTELLIGENCE & SECURITY TELEMETRY EVENT LOGGING MODELS
// ============================================================================

export type ThreatIntelStatus = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN' | 'LOOKUP_FAILED';

export interface ThreatIntelProviderResult {
  provider: 'URLHAUS' | 'VIRUSTOTAL' | 'PHISHTANK' | 'SAFE_BROWSING' | 'OPENPHISH';
  status: ThreatIntelStatus;
  isFlagged: boolean;
  scoreContribution: number;
  details: string;
  queryLatencyMs: number;
  lastUpdated?: string;
  metadata?: Record<string, unknown>;
}

export interface ThreatIntelReport {
  overallVerdict: ThreatIntelStatus;
  maxScoreContribution: number;
  providersCount: number;
  flaggedCount: number;
  results: ThreatIntelProviderResult[];
  cached: boolean;
  queriedAt: number;
}

export type SecurityActionTaken =
  | 'SILENT_MONITORING'
  | 'IN_PAGE_BANNER'
  | 'BLOCKING_MODAL'
  | 'FORM_SUBMISSION_INTERCEPTED'
  | 'DOWNLOAD_INTERCEPTED'
  | 'USER_PROCEEDED_OVERRIDE'
  | 'ALLOWLISTED_BYPASS';

export interface InfrastructureSignals {
  isIpAddress: boolean;
  isPunycode: boolean;
  isFreeHosting: boolean;
  freeHostingProvider: string | null;
  hasSuspiciousPort: boolean;
  hasHighRiskTld: boolean;
  subdomainDepth: number;
  entropyScore: number;
  length: number;
  autonomousSystemOrHosting?: string;
}

export interface FormRiskIndicators {
  formsCount: number;
  hasPasswordInput: boolean;
  hasCreditCardInput: boolean;
  hasSsnInput: boolean;
  has2FAInput: boolean;
  hasHiddenCredentialFields: boolean;
  suspiciousFormActions: Array<{
    actionHost: string;
    isCrossOrigin: boolean;
    isInsecureHttp: boolean;
    hasPasswordField: boolean;
    method: string;
  }>;
}

export interface CrossOriginBehavior {
  hasCrossOriginPost: boolean;
  hasCrossOriginCredentialTarget: boolean;
  observedDestinations: string[];
}

export interface RedirectInformation {
  hopCount: number;
  hasShortener: boolean;
  hasCrossDomainRedirect: boolean;
  hops: Array<{
    url: string;
    hostname: string;
    statusCode?: number;
  }>;
}

export interface BrandCandidateInfo {
  name: string;
  confidence: number;
  isImpersonated: boolean;
  canonicalDomains: string[];
  evidence: string[];
}

/**
 * Privacy-Preserving Security Telemetry Log Record
 * Strictly captures metadata, never secrets, passwords, cookies, or payloads.
 */
export interface SecurityTelemetryRecord {
  id: string; // e.g. "tel_1740612345_a8f9"
  analysisId: string;
  timestamp: number;
  timeIso: string;
  url: string; // Sanitized URL (tokens and auth fragments stripped)
  domain: string;
  tld: string;
  pageRiskScore: number; // 0 - 100
  verdict: Verdict;
  severity: ThreatSeverity;
  confidence: number; // 0.0 - 1.0
  extensionVersion: string;
  
  detectedSignals: DetectionSignal[];
  brandCandidates: BrandCandidateInfo[];
  infrastructureSignals: InfrastructureSignals;
  threatIntelligence: ThreatIntelReport;
  formRiskIndicators: FormRiskIndicators;
  crossOriginBehavior: CrossOriginBehavior;
  redirectInformation: RedirectInformation;
  
  actionTaken: SecurityActionTaken;
  wasWarningDisplayed: boolean;
  wasDangerousFormBlocked: boolean;
  wasDownloadBlocked?: boolean;
  
  incidentId?: string; // Associated Security Incident if escalated
  targetBrandName?: string;
  reasons: string[];
}

export type IncidentStatus = 'ACTIVE' | 'INVESTIGATING' | 'MITIGATED' | 'FALSE_POSITIVE' | 'RESOLVED';
export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ThreatCategory = 
  | 'BRAND_IMPERSONATION'
  | 'CREDENTIAL_HARVESTING'
  | 'PAYMENT_FRAUD'
  | '2FA_INTERCEPTION'
  | 'SCAREWARE_TECH_SUPPORT'
  | 'MALWARE_DROPPER'
  | 'TYPOSQUAT_CAMPAIGN'
  | 'REDIRECT_SMUGGLING';

export interface MitreTechnique {
  id: string; // e.g. "T1566.002"
  name: string; // e.g. "Spearphishing Link"
  tactic: string; // e.g. "Initial Access"
  url?: string;
}

export interface AnalystNote {
  id: string;
  author: string;
  timestamp: number;
  text: string;
}

export interface IndicatorOfCompromise {
  type: 'DOMAIN' | 'URL' | 'IP' | 'SHA256' | 'BRAND_TERM';
  value: string;
  description: string;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
}

/**
 * Security Incident Model for Security Operations & Triage
 */
export interface SecurityIncident {
  incidentId: string; // e.g. "INC-2026-0841"
  title: string;
  threatCategory: ThreatCategory;
  severity: IncidentSeverity;
  status: IncidentStatus;
  riskScore: number;
  affectedDomain: string;
  targetBrand?: string;
  
  createdAt: number;
  updatedAt: number;
  
  mitreTechniques: MitreTechnique[];
  iocs: IndicatorOfCompromise[];
  
  telemetryLogIds: string[];
  firstSeenLog?: SecurityTelemetryRecord;
  
  analystNotes: AnalystNote[];
  recommendedMitigations: string[];
  
  assignedAnalyst?: string;
  resolvedAt?: number;
}

// ============================================================================
// CANONICAL PILOT-READY ENTERPRISE SECURITY EVENT MODEL
// ============================================================================

export type CanonicalEventType =
  | 'NAVIGATION_BLOCKED'
  | 'FORM_INTERCEPTED'
  | 'DOWNLOAD_INTERCEPTED'
  | 'WARNING_DISPLAYED'
  | 'SUSPICIOUS_OBSERVED'
  | 'USER_OVERRIDE'
  | 'SAFE_VISIT';

export type EnterpriseAction =
  | 'BLOCKED'
  | 'WARNED'
  | 'INTERCEPTED'
  | 'ALLOWED'
  | 'USER_OVERRIDE'
  | 'ALLOWLISTED';

export type EnterpriseRiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';

export interface CanonicalSecurityEventSignal {
  id: string;
  category: string;
  type: string;
  severity: string;
  weight: number;
  title: string;
  description: string;
  confidence: number;
}

/**
 * Canonical Security Event suitable for SIEM, centralized telemetry, and fleet auditing.
 * Strict privacy guarantee: Contains zero passwords, form inputs, keystrokes, cookies, or secrets.
 */
export interface CanonicalSecurityEvent {
  eventId: string; // Unique deterministic/UUID e.g. "evt_1740612345_a8f9"
  timestamp: number; // Epoch ms
  tabId: number;
  deviceId: string; // Stable anonymized device identifier e.g. "DEV-023-WIN"
  installationId: string; // Stable installation UUID
  organizationId: string; // Company organization identifier e.g. "ORG-ACME-CORP"
  extensionVersion: string; // e.g. "1.0.0"
  browserVersion?: string; // e.g. "Chrome 128.0 (MV3)"
  os?: string; // e.g. "macOS", "Windows 11", "Linux"
  eventType: CanonicalEventType;
  url: string; // Sanitized URL (tokens & sensitive params stripped)
  hostname: string; // e.g. "vintedmarket.netlify.app"
  riskScore: number; // 0 - 100
  riskLevel: EnterpriseRiskLevel;
  action: EnterpriseAction;
  detectionReasons: string[];
  signals: CanonicalSecurityEventSignal[];
  brand?: string | null;
  threatCategory: ThreatCategory | 'OTHER';
  navigationBlocked: boolean;
  userOverride: boolean;
  source: 'CLIENT_EXTENSION';
  createdAt: string; // ISO string
}

export type EnforcementMode = 'BLOCK' | 'WARN' | 'MONITOR';

export type OrganizationStatus = 'ACTIVE' | 'SUSPENDED' | 'PILOT';

export interface Organization {
  organizationId: string;
  name: string;
  status?: OrganizationStatus;
  enrollmentToken?: string; // Legacy / primary active token
  enforcementMode: EnforcementMode;
  telemetryEnabled: boolean;
  retentionDays: number;
  minExtensionVersion: string;
  backendUrl?: string;
  createdAt: number;
  updatedAt: number;
}

export type DeviceHealthStatus = 'ONLINE' | 'OFFLINE' | 'UPDATE_REQUIRED' | 'NEEDS_ATTENTION';

export interface EnrolledDevice {
  id?: string;
  installationId: string;
  deviceId: string;
  organizationId: string;
  deviceApiKey?: string;
  deviceName?: string;
  extensionVersion: string;
  browser: string;
  platform?: string;
  os: string;
  firstSeen: number;
  lastSeen: number;
  status: DeviceHealthStatus;
  eventsCount: number;
  blockedCount: number;
  warningsCount: number;
  lastIp?: string;
}

export interface EnrollmentToken {
  id: string;
  organizationId: string;
  token: string;
  tokenHash: string;
  label: string;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  createdAt: number;
  expiresAt: number | null;
  maxUses: number | null;
  useCount: number;
  revokedAt: number | null;
  revokedBy: string | null;
}

export interface DeviceEnrollmentRequest {
  enrollmentToken: string;
  installationId: string;
  extensionVersion: string;
  browser: string;
  os: string;
  platform?: string;
  deviceName?: string;
}

export interface DeviceEnrollmentResponse {
  success: boolean;
  deviceId: string;
  installationId: string;
  organizationId: string;
  organizationName: string;
  deviceApiKey: string;
  enforcementMode: EnforcementMode;
  minExtensionVersion: string;
  backendUrl: string;
  error?: string;
}

export interface DeviceHeartbeatPayload {
  installationId: string;
  deviceId: string;
  organizationId?: string;
  extensionVersion: string;
  browser?: string;
  os?: string;
  enforcementMode?: string;
  queueSize?: number;
}

export interface AuditLogEntry {
  id: string;
  organizationId: string;
  timestamp: number;
  actor: string;
  action: string;
  target: string;
  details: string;
}

// ============================================================================
// ============================================================================
// ARCHITECTURAL STATE MODEL (6-AXIS EXPLICIT STATE SYSTEM)
// ============================================================================

/**
 * 1. Local Protection State
 * Local detection engine running on-device in the browser extension.
 * Operates independently of cloud reachability or organization enrollment.
 */
export type LocalProtectionState =
  | 'LOCAL_PROTECTION_ACTIVE'
  | 'LOCAL_PROTECTION_PAUSED';

/**
 * 2. Cloud Enrollment State
 * Association of the browser/device with an organization's central control plane.
 */
export type CloudEnrollmentState =
  | 'NOT_ENROLLED'
  | 'ENROLLING'
  | 'ENROLLED'
  | 'ENROLLMENT_FAILED'
  | 'ENROLLMENT_REVOKED';

/**
 * 3. Cloud Synchronization / Heartbeat State
 * Communication health between enrolled endpoint and production API.
 */
export type CloudSyncState =
  | 'SYNCING'
  | 'SYNCED'
  | 'CLOUD_OFFLINE'
  | 'SYNC_ERROR'
  | 'NOT_APPLICABLE';

/**
 * 4. Device Management State
 * Authoritative lifecycle status assigned by the backend / administrator.
 */
export type DeviceManagementState =
  | 'ACTIVE'
  | 'SUSPENDED'
  | 'REVOKED'
  | 'UNKNOWN';

/**
 * 5. Security Telemetry State
 * Status of local event queuing and transmission to cloud storage.
 */
export type SecurityTelemetryState =
  | 'TELEMETRY_PENDING'
  | 'TELEMETRY_SYNCED'
  | 'TELEMETRY_QUEUED'
  | 'TELEMETRY_FAILED'
  | 'NONE';

/**
 * 6. Cloud / API Availability
 * Reachability and operational health of central servers.
 */
export type CloudApiAvailability =
  | 'ONLINE'
  | 'OFFLINE'
  | 'DEGRADED';

/**
 * Safe Diagnosable Reasons (No secrets or credentials exposed)
 */
export type EnrollmentFailureReason =
  | 'INVALID_TOKEN'
  | 'EXPIRED_TOKEN'
  | 'REVOKED_TOKEN'
  | 'MAX_USES_REACHED'
  | 'API_UNAVAILABLE'
  | 'SERVER_VALIDATION_FAILURE'
  | 'NETWORK_ERROR';

export type SyncErrorReason =
  | 'NETWORK_FAILURE'
  | 'AUTHENTICATION_FAILURE'
  | 'DEVICE_REVOKED'
  | 'API_ERROR'
  | 'SERVER_ERROR';

export type TelemetryFailureReason =
  | 'NETWORK_UNAVAILABLE'
  | 'API_REJECTED_EVENT'
  | 'AUTHENTICATION_FAILURE'
  | 'INVALID_DEVICE'
  | 'SERVER_DATABASE_FAILURE';

export type EndpointState =
  | 'LOCAL_PROTECTION_ACTIVE' // Browser detection is running locally
  | 'NOT_ENROLLED'            // No business cloud association (Individual mode)
  | 'ENROLLING'               // Enrollment request in progress
  | 'ENROLLED'                // Device registered to organization
  | 'SYNCED'                  // Heartbeat / cloud communication working normally
  | 'CLOUD_OFFLINE'           // Local protection continues, cloud unavailable
  | 'ENROLLMENT_FAILED'       // Enrollment rejected
  | 'ENROLLMENT_REVOKED';     // Revoked by organization admin

export interface EndpointStatusModel {
  // 6 Explicit State Axes
  localProtection: LocalProtectionState;
  cloudEnrollment: CloudEnrollmentState;
  cloudSync: CloudSyncState;
  deviceManagement: DeviceManagementState;
  telemetryState: SecurityTelemetryState;
  cloudAvailability: CloudApiAvailability;

  // Convenience and identifiers
  localProtectionActive: boolean;
  state: EndpointState;
  organizationId?: string | null;
  organizationName?: string | null;
  deviceId?: string | null;
  lastSyncTimestamp?: number | null;
  lastHeartbeatTimestamp?: number | null;
  queueSize: number;

  // Safe diagnostics
  enrollmentFailureReason?: EnrollmentFailureReason | string | null;
  syncErrorReason?: SyncErrorReason | string | null;
  telemetryFailureReason?: TelemetryFailureReason | string | null;

  // Clear UI Presentation
  headline: string;
  subline: string;
  badgeLabel: string;
  badgeVariant: 'safe' | 'managed' | 'warning' | 'neutral' | 'offline' | 'danger';
}

export function formatTimeAgo(timestamp?: number | null): string {
  if (!timestamp || timestamp <= 0) return 'never';
  const diffSec = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (diffSec < 5) return 'just now';
  if (diffSec < 60) return `${diffSec} seconds ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}

export function computeEndpointStatusModel(params: {
  localProtectionActive?: boolean;
  isEnrolled?: boolean;
  isEnrolling?: boolean;
  isOnline?: boolean;
  isRevoked?: boolean;
  enrollmentFailed?: boolean;
  enrollmentFailureReason?: string | null;
  syncErrorReason?: string | null;
  telemetryFailureReason?: string | null;
  deviceManagementState?: DeviceManagementState;
  organizationId?: string | null;
  organizationName?: string | null;
  deviceId?: string | null;
  lastSyncTime?: number | null;
  lastHeartbeatTime?: number | null;
  queueSize?: number;
}): EndpointStatusModel {
  const localActive = params.localProtectionActive !== false;
  const isEnrolled = !!params.isEnrolled && !!params.organizationId && !params.isRevoked;
  const isEnrolling = !!params.isEnrolling;
  const isOnline = params.isOnline !== false;
  const queueSize = params.queueSize || 0;
  const orgName = params.organizationName || (params.organizationId === 'ORG-ACME-PILOT' ? 'Acme Corporation' : params.organizationId) || 'Organization';

  // 1. Local Protection Axis
  const localProtection: LocalProtectionState = localActive ? 'LOCAL_PROTECTION_ACTIVE' : 'LOCAL_PROTECTION_PAUSED';

  // 2. Cloud Enrollment Axis
  let cloudEnrollment: CloudEnrollmentState = 'NOT_ENROLLED';
  if (params.isRevoked) {
    cloudEnrollment = 'ENROLLMENT_REVOKED';
  } else if (params.enrollmentFailed) {
    cloudEnrollment = 'ENROLLMENT_FAILED';
  } else if (isEnrolling) {
    cloudEnrollment = 'ENROLLING';
  } else if (isEnrolled) {
    cloudEnrollment = 'ENROLLED';
  }

  // 3. Cloud Synchronization Axis
  let cloudSync: CloudSyncState = 'CLOUD_OFFLINE';
  if (!isEnrolled) {
    cloudSync = 'NOT_APPLICABLE';
  } else if (!isOnline) {
    cloudSync = 'CLOUD_OFFLINE';
  } else if (isEnrolling) {
    cloudSync = 'SYNCING';
  } else if (params.syncErrorReason) {
    cloudSync = 'SYNC_ERROR';
  } else {
    cloudSync = 'SYNCED';
  }

  // 4. Device Management Axis (Authoritative from backend)
  const deviceManagement: DeviceManagementState = params.deviceManagementState || (params.isRevoked ? 'REVOKED' : isEnrolled ? 'ACTIVE' : 'UNKNOWN');

  // 5. Security Telemetry Axis
  let telemetryState: SecurityTelemetryState = 'TELEMETRY_SYNCED';
  if (queueSize > 0) {
    telemetryState = isOnline ? 'TELEMETRY_PENDING' : 'TELEMETRY_QUEUED';
  } else if (params.telemetryFailureReason) {
    telemetryState = 'TELEMETRY_FAILED';
  }

  // 6. Cloud Availability Axis
  const cloudAvailability: CloudApiAvailability = isOnline ? 'ONLINE' : 'OFFLINE';

  // Compute Presentation Strings
  let state: EndpointState = 'NOT_ENROLLED';
  let headline = 'Protected locally';
  let subline = 'PhishGuard is actively checking websites in this browser.';
  let badgeLabel = 'Local Protection Active';
  let badgeVariant: EndpointStatusModel['badgeVariant'] = 'safe';

  if (!localActive) {
    state = 'NOT_ENROLLED';
    headline = 'Protection Paused';
    subline = 'Real-time browser security checks are temporarily disabled.';
    badgeLabel = 'Paused';
    badgeVariant = 'warning';
  } else if (params.isRevoked) {
    state = 'ENROLLMENT_REVOKED';
    headline = 'Protected locally';
    subline = 'Organization enrollment has ended. Local protection continues.';
    badgeLabel = 'Revoked';
    badgeVariant = 'danger';
  } else if (params.enrollmentFailed) {
    state = 'ENROLLMENT_FAILED';
    headline = 'Enrollment failed';
    subline = params.enrollmentFailureReason ? `Reason: ${params.enrollmentFailureReason}. Local protection active.` : 'Could not complete fleet registration. Local protection remains active.';
    badgeLabel = 'Enrollment Failed';
    badgeVariant = 'warning';
  } else if (isEnrolling) {
    state = 'ENROLLING';
    headline = 'Connecting to Fleet...';
    subline = 'Registering device credentials with cloud policy server.';
    badgeLabel = 'Enrolling';
    badgeVariant = 'neutral';
  } else if (isEnrolled) {
    if (isOnline) {
      state = 'SYNCED';
      headline = 'Protected & managed';
      const syncText = params.lastSyncTime ? `Last sync ${formatTimeAgo(params.lastSyncTime)}` : 'Connected';
      subline = `Connected to ${orgName} · ${syncText}`;
      badgeLabel = 'Managed';
      badgeVariant = 'managed';
    } else {
      state = 'CLOUD_OFFLINE';
      headline = 'Protected (cloud offline)';
      subline = `Local detection remains active · Central cloud sync unreachable${queueSize > 0 ? ` (${queueSize} buffered telemetry events will retry)` : ''}`;
      badgeLabel = 'Cloud Offline';
      badgeVariant = 'offline';
    }
  } else {
    // Standalone Individual User / Not Enrolled
    state = 'NOT_ENROLLED';
    headline = 'Protected locally';
    subline = 'PhishGuard is actively checking websites in this browser using local detection.';
    badgeLabel = 'Local';
    badgeVariant = 'safe';
  }

  return {
    localProtection,
    cloudEnrollment,
    cloudSync,
    deviceManagement,
    telemetryState,
    cloudAvailability,
    localProtectionActive: localActive,
    state,
    organizationId: isEnrolled ? params.organizationId : null,
    organizationName: isEnrolled ? orgName : null,
    deviceId: isEnrolled ? params.deviceId : null,
    lastSyncTimestamp: params.lastSyncTime || null,
    lastHeartbeatTimestamp: params.lastHeartbeatTime || null,
    queueSize,
    enrollmentFailureReason: params.enrollmentFailureReason || null,
    syncErrorReason: params.syncErrorReason || null,
    telemetryFailureReason: params.telemetryFailureReason || null,
    headline,
    subline,
    badgeLabel,
    badgeVariant
  };
}

