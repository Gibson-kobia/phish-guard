function formatTimeAgo(timestamp) {
  if (!timestamp || timestamp <= 0) return "never";
  const diffSec = Math.max(0, Math.floor((Date.now() - timestamp) / 1e3));
  if (diffSec < 5) return "just now";
  if (diffSec < 60) return `${diffSec} seconds ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}
function computeEndpointStatusModel(params) {
  const localActive = params.localProtectionActive !== false;
  const isEnrolled = !!params.isEnrolled && !!params.organizationId && !params.isRevoked;
  const isEnrolling = !!params.isEnrolling;
  const isOnline = params.isOnline !== false;
  const queueSize = params.queueSize || 0;
  const orgName = params.organizationName || (params.organizationId === "ORG-ACME-PILOT" ? "Acme Corporation" : params.organizationId) || "Organization";
  const localProtection = localActive ? "LOCAL_PROTECTION_ACTIVE" : "LOCAL_PROTECTION_PAUSED";
  let cloudEnrollment = "NOT_ENROLLED";
  if (params.isRevoked) {
    cloudEnrollment = "ENROLLMENT_REVOKED";
  } else if (params.enrollmentFailed) {
    cloudEnrollment = "ENROLLMENT_FAILED";
  } else if (isEnrolling) {
    cloudEnrollment = "ENROLLING";
  } else if (isEnrolled) {
    cloudEnrollment = "ENROLLED";
  }
  let cloudSync = "CLOUD_OFFLINE";
  if (!isEnrolled) {
    cloudSync = "NOT_APPLICABLE";
  } else if (!isOnline) {
    cloudSync = "CLOUD_OFFLINE";
  } else if (isEnrolling) {
    cloudSync = "SYNCING";
  } else if (params.syncErrorReason) {
    cloudSync = "SYNC_ERROR";
  } else {
    cloudSync = "SYNCED";
  }
  const deviceManagement = params.deviceManagementState || (params.isRevoked ? "REVOKED" : isEnrolled ? "ACTIVE" : "UNKNOWN");
  let telemetryState = "TELEMETRY_SYNCED";
  if (queueSize > 0) {
    telemetryState = isOnline ? "TELEMETRY_PENDING" : "TELEMETRY_QUEUED";
  } else if (params.telemetryFailureReason) {
    telemetryState = "TELEMETRY_FAILED";
  }
  const cloudAvailability = isOnline ? "ONLINE" : "OFFLINE";
  let state = "NOT_ENROLLED";
  let headline = "Protected locally";
  let subline = "PhishGuard is actively checking websites in this browser.";
  let badgeLabel = "Local Protection Active";
  let badgeVariant = "safe";
  if (!localActive) {
    state = "NOT_ENROLLED";
    headline = "Protection Paused";
    subline = "Real-time browser security checks are temporarily disabled.";
    badgeLabel = "Paused";
    badgeVariant = "warning";
  } else if (params.isRevoked) {
    state = "ENROLLMENT_REVOKED";
    headline = "Protected locally";
    subline = "Organization enrollment has ended. Local protection continues.";
    badgeLabel = "Revoked";
    badgeVariant = "danger";
  } else if (params.enrollmentFailed) {
    state = "ENROLLMENT_FAILED";
    headline = "Enrollment failed";
    subline = params.enrollmentFailureReason ? `Reason: ${params.enrollmentFailureReason}. Local protection active.` : "Could not complete fleet registration. Local protection remains active.";
    badgeLabel = "Enrollment Failed";
    badgeVariant = "warning";
  } else if (isEnrolling) {
    state = "ENROLLING";
    headline = "Connecting to Fleet...";
    subline = "Registering device credentials with cloud policy server.";
    badgeLabel = "Enrolling";
    badgeVariant = "neutral";
  } else if (isEnrolled) {
    if (isOnline) {
      state = "SYNCED";
      headline = "Protected & managed";
      const syncText = params.lastSyncTime ? `Last sync ${formatTimeAgo(params.lastSyncTime)}` : "Connected";
      subline = `Connected to ${orgName} \xB7 ${syncText}`;
      badgeLabel = "Managed";
      badgeVariant = "managed";
    } else {
      state = "CLOUD_OFFLINE";
      headline = "Protected (cloud offline)";
      subline = `Local detection remains active \xB7 Central cloud sync unreachable${queueSize > 0 ? ` (${queueSize} buffered telemetry events will retry)` : ""}`;
      badgeLabel = "Cloud Offline";
      badgeVariant = "offline";
    }
  } else {
    state = "NOT_ENROLLED";
    headline = "Protected locally";
    subline = "PhishGuard is actively checking websites in this browser using local detection.";
    badgeLabel = "Local";
    badgeVariant = "safe";
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
export {
  computeEndpointStatusModel,
  formatTimeAgo
};
