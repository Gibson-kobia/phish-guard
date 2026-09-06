import { analyzePageSecurity } from '../engine/riskScoring.js';
import { DEFAULT_SETTINGS } from '../config/rules.js';
import { globalEventStore } from '../events/eventStore.js';
import { createNetworkSecurityEvent } from '../events/networkEvents.js';
import { createPageBrandingEvent } from '../events/pageEvents.js';
import { createFormSecurityEvent } from '../events/formEvents.js';
import { createNavigationSecurityEvent } from '../events/navigationEvents.js';
import { createDownloadSecurityEvent } from '../events/downloadEvents.js';
import { correlateSecurityEvents } from '../events/eventCorrelator.js';
import { buildCanonicalSecurityEvent } from '../events/canonicalEvent.js';
import { globalTelemetryQueue } from '../events/durableQueue.js';

// In-memory cache with MV3 chrome.storage.session integration
const tabScanResults = new Map();
const tabRedirectHistory = new Map();
const tabDownloadContexts = new Map();
const tabDomMetadata = new Map();
const tabWarningInFlight = new Map(); // tabId -> { targetUrl, warningUrl, timestamp }
const dismissedWarnings = new Set(); // Temporarily bypassed domains in current session

// Periodic heartbeat alarm for MV3 service worker
try {
  if (chrome.alarms) {
    chrome.alarms.create('phishguard_heartbeat', { periodInMinutes: 1 });
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === 'phishguard_heartbeat') {
        globalTelemetryQueue.sendHeartbeat().catch(() => {});
        globalTelemetryQueue.flushQueueAsync().catch(() => {});
      }
    });
  }
} catch {}

/**
 * Initialize Default Storage Configuration on Install
 */
chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get(['settings', 'history']);
  if (!existing.settings) {
    await chrome.storage.local.set({
      settings: DEFAULT_SETTINGS,
      history: []
    });
  }
});

/**
 * Helper to retrieve current settings
 */
async function getSettings() {
  const data = await chrome.storage.local.get('settings');
  return { ...DEFAULT_SETTINGS, ...(data.settings || {}) };
}

/**
 * Session storage helpers to survive MV3 Service Worker dormancy
 */
async function getSessionData(key) {
  try {
    if (chrome.storage && chrome.storage.session) {
      const data = await chrome.storage.session.get(key);
      return data[key];
    }
  } catch {
    // storage.session unavailable, fall back to memory
  }
  return null;
}

async function setSessionData(key, value) {
  try {
    if (chrome.storage && chrome.storage.session) {
      await chrome.storage.session.set({ [key]: value });
    }
  } catch {
    // ignore
  }
}

/**
 * Update Extension Badge based on 5-Tier Security Verdict
 * SAFE (0-19), LOW_RISK (20-39), SUSPICIOUS (40-59), HIGH_RISK (60-79), DANGEROUS (80-100)
 */
function updateBadge(tabId, verdict, score) {
  if (!tabId || tabId <= 0) return;

  let badgeText = '';
  let badgeColor = '#10B981'; // Green

  if (verdict === 'DANGEROUS') {
    badgeText = '!';
    badgeColor = '#DC2626'; // Deep Red
  } else if (verdict === 'HIGH_RISK') {
    badgeText = `${score}`;
    badgeColor = '#EF4444'; // Red
  } else if (verdict === 'SUSPICIOUS') {
    badgeText = `${score}`;
    badgeColor = '#F59E0B'; // Amber
  } else if (verdict === 'LOW_RISK') {
    badgeText = '';
    badgeColor = '#3B82F6'; // Blue
  } else {
    // SAFE: Quiet by default
    badgeText = '';
    badgeColor = '#10B981'; // Green
  }

  try {
    const textPromise = chrome.action.setBadgeText({ tabId, text: badgeText });
    if (textPromise && typeof textPromise.catch === 'function') {
      textPromise.catch(() => {});
    }
    const colorPromise = chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
    if (colorPromise && typeof colorPromise.catch === 'function') {
      colorPromise.catch(() => {});
    }
  } catch {
    // Tab may have closed
  }
}

/**
 * Safely navigates a tab to the PhishGuard warning interstitial.
 * 
 * Protects against Chrome MV3 asynchronous navigation race conditions:
 * 1. Idempotency: Deduplicates concurrent navigation attempts for the same tab & destination.
 * 2. Tab Lifecycle: Checks tab presence and prevents navigating tabs that are already at the warning page.
 * 3. Deliberate Promise Handling: Gracefully absorbs and classifies expected navigation cancellation errors
 *    ("Navigation rejected.", "Tabs cannot be edited", "No tab with id") without unhandled promise rejections.
 */
async function safelyNavigateTabToWarning(tabId, warningUrl, targetUrl) {
  if (!tabId || tabId <= 0) return;

  const now = Date.now();
  const existingInFlight = tabWarningInFlight.get(tabId);
  if (existingInFlight && existingInFlight.targetUrl === targetUrl && (now - existingInFlight.timestamp < 3500)) {
    return; // Active navigation already in flight for this destination
  }

  tabWarningInFlight.set(tabId, { targetUrl, warningUrl, timestamp: now });

  try {
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    if (!tab) {
      tabWarningInFlight.delete(tabId);
      return;
    }

    // Prevent navigation loops if tab is already displaying warning page
    if (tab.url && tab.url.startsWith(chrome.runtime.getURL('warning/warning.html'))) {
      return;
    }

    await chrome.tabs.update(tabId, { url: warningUrl });
  } catch (err) {
    const errMsg = err && err.message ? err.message : String(err);
    const isExpected = 
      errMsg.includes('Navigation rejected') || 
      errMsg.includes('Tabs cannot be edited') || 
      errMsg.includes('No tab with id') || 
      errMsg.includes('Cannot navigate to');

    if (!isExpected) {
      console.warn(`[PhishGuard] Non-fatal tab navigation warning for tab ${tabId}:`, errMsg);
    }
  } finally {
    // Release in-flight lock after brief window to allow subsequent legitimate user navigations
    setTimeout(() => {
      const current = tabWarningInFlight.get(tabId);
      if (current && current.timestamp === now) {
        tabWarningInFlight.delete(tabId);
      }
    }, 3500);
  }
}

/**
 * Main Analysis Coordinator for a given Tab URL
 */
async function performTabScan(tabId, url, formMetadata = null, socialMeta = null) {
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:') || url.startsWith('edge://')) {
    return null;
  }

  const settings = await getSettings();
  const redirectData = tabRedirectHistory.get(tabId) || {
    initialUrl: url,
    finalUrl: url,
    hops: [{ url, timestamp: Date.now() }],
    hopCount: 1
  };

  const downloadContext = tabDownloadContexts.get(tabId) || null;

  if (formMetadata) {
    tabDomMetadata.set(tabId, { formMetadata, socialMeta });
  } else if (tabDomMetadata.has(tabId)) {
    const cached = tabDomMetadata.get(tabId);
    formMetadata = cached.formMetadata;
    socialMeta = cached.socialMeta;
  }

  // 1. Evaluate Core Rules Analysis
  const analysis = analyzePageSecurity(
    url,
    formMetadata,
    redirectData,
    settings,
    socialMeta,
    downloadContext
  );

  // 2. Correlate Real-Time Behavioral Events from EventStore
  const tabEvents = globalEventStore.getTabEvents(tabId);
  const correlated = correlateSecurityEvents({
    tabId,
    url,
    domain: analysis.domain,
    events: tabEvents
  });

  // If compound event correlation identified higher severity threats, merge signals
  if (correlated && correlated.score > analysis.score) {
    analysis.score = Math.min(100, Math.max(analysis.score, correlated.score));
    analysis.verdict = correlated.verdict;
    analysis.severity = correlated.severity;
    
    // Add compound signals to analysis
    const incomingSignals = correlated.signals || correlated.evidence || [];
    for (const sig of incomingSignals) {
      if (!analysis.signals.some(s => s.type === sig.type)) {
        analysis.signals.push(sig);
      }
    }
  }

  tabScanResults.set(tabId, analysis);
  await setSessionData(`tab_${tabId}`, analysis);

  // Update extension badge
  updateBadge(tabId, analysis.verdict, analysis.score);

  // Save to local scan history (privacy-safe: domain, score, timestamp, top signals only)
  await recordScanHistory(analysis);

  // Enqueue canonical security event for enterprise fleet reporting
  try {
    const canonicalEvt = buildCanonicalSecurityEvent({
      tabId,
      url,
      analysis,
      action: analysis.score >= settings.blockThreshold ? 'BLOCKED' : analysis.score >= settings.warningThreshold ? 'WARNED' : 'ALLOWED'
    });
    globalTelemetryQueue.enqueue(canonicalEvt);
  } catch {}

  // Send legacy structured privacy-safe telemetry event to VPS Backend
  dispatchTelemetryToVPS(url, analysis, formMetadata, redirectData, settings).then(serverVerdict => {
    if (serverVerdict && serverVerdict.incidentId) {
      analysis.incidentId = serverVerdict.incidentId;
      if (serverVerdict.score > analysis.score) {
        analysis.score = serverVerdict.score;
        analysis.verdict = serverVerdict.verdict;
        analysis.severity = serverVerdict.severity;
        updateBadge(tabId, analysis.verdict, analysis.score);
      }
    }
  }).catch(() => {
    // Non-blocking offline fallback
  });

  // Check if warning interstitial is required
  const sessionDismissed = await getSessionData('dismissed_domains') || [];
  const isDismissed = dismissedWarnings.has(analysis.domain) || sessionDismissed.includes(analysis.domain.toLowerCase());
  if (analysis.score >= settings.warningThreshold && !isDismissed && settings.protectionEnabled) {
    const warningUrl = chrome.runtime.getURL(
      `warning/warning.html?url=${encodeURIComponent(url)}&score=${analysis.score}&verdict=${analysis.verdict}&domain=${encodeURIComponent(analysis.domain)}`
    );

    // Notify active content script to display non-destructive in-page banner
    chrome.tabs.sendMessage(tabId, {
      type: 'PHISHGUARD_SHOW_BANNER',
      analysis
    }).catch(() => {
      // Content script may not be initialized yet
    });

    // If score meets or exceeds blockThreshold, navigate to warning interstitial
    if (analysis.score >= settings.blockThreshold) {
      await safelyNavigateTabToWarning(tabId, warningUrl, url);
    }
  }

  return analysis;
}

/**
 * STEP 2: Dispatches structured, privacy-preserving observation event to PhishGuard VPS API
 * 
 * STRICT PRIVACY CONTRACT:
 * - NO passwords
 * - NO credit card numbers
 * - NO cookies or tokens
 * - NO raw form input values
 * - NO typed request bodies
 */
async function dispatchTelemetryToVPS(url, analysis, formMetadata, redirectData, settings) {
  try {
    const endpoint = settings.telemetryEndpoint || '/api/telemetry';
    
    const payload = {
      event_type: 'page_analysis',
      url: url,
      domain: analysis.domain,
      title: formMetadata?.pageTitle || '',
      forms: {
        password: !!formMetadata?.hasPasswordInput,
        payment: !!formMetadata?.hasCreditCardInput,
        otp: !!formMetadata?.has2FAInput,
        ssn: !!formMetadata?.hasSsnInput
      },
      cross_origin_forms: (formMetadata?.suspiciousForms || []).map(f => ({
        action: f.action,
        method: f.method,
        is_cross_origin: f.isCrossOrigin,
        has_password: f.hasPasswordField
      })),
      redirects: (redirectData?.hops || []).map(h => h.url),
      detected_brands: analysis.targetBrand ? [analysis.targetBrand.name] : [],
      timestamp: new Date().toISOString()
    };

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-PhishGuard-Agent': 'MV3-Extension',
        'X-Extension-Version': '1.0.0'
      },
      body: JSON.stringify(payload)
    });

    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    // Graceful offline failover
  }
  return null;
}

/**
 * Record non-sensitive metadata in local scan history
 */
async function recordScanHistory(analysis) {
  try {
    const data = await chrome.storage.local.get(['history', 'settings']);
    const history = data.history || [];
    const limit = data.settings?.scanHistoryLimit || 100;

    const topSignal = analysis.signals.length > 0 ? analysis.signals[0].title : 'No risks detected';

    const newItem = {
      id: `${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: analysis.timestamp,
      url: analysis.url,
      domain: analysis.domain,
      score: analysis.score,
      severity: analysis.severity,
      verdict: analysis.verdict,
      topSignal,
      reasons: analysis.reasons.slice(0, 2)
    };

    // Filter duplicates of same domain within recent window
    const updated = [newItem, ...history.filter(h => h.domain !== analysis.domain)].slice(0, limit);
    await chrome.storage.local.set({ history: updated });
  } catch (err) {
    console.error('[PhishGuard] Failed to update scan history:', err);
  }
}

/**
 * Real-Time Network Request Observation via Chrome WebRequest API
 * Privacy-first: Records ONLY method, URL target domain, and initiator origin.
 * NEVER captures request headers, bodies, cookies, or credentials.
 */
if (chrome.webRequest && chrome.webRequest.onBeforeRequest) {
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      if (details.tabId <= 0) return; // Background or internal browser request

      const targetUrl = details.url;
      const method = details.method || 'GET';
      const initiator = details.initiator || '';

      if (!targetUrl || targetUrl.startsWith('chrome-extension://') || targetUrl.startsWith('data:')) {
        return;
      }

      try {
        let pageUrl = initiator;
        const currentResult = tabScanResults.get(details.tabId);
        if (currentResult && currentResult.url) {
          pageUrl = currentResult.url;
        }

        if (pageUrl) {
          const networkEvent = createNetworkSecurityEvent(details.tabId, pageUrl, targetUrl, method, details.type);
          if (networkEvent) {
            globalEventStore.addEvent(networkEvent);

            // If a cross-origin POST happens on a page with credential inputs, re-evaluate tab scan
            if (networkEvent.isCrossOrigin && method === 'POST') {
              const domMeta = tabDomMetadata.get(details.tabId);
              if (domMeta?.formMetadata?.hasPasswordInput || domMeta?.formMetadata?.has2FAInput) {
                performTabScan(details.tabId, pageUrl);
              }
            }
          }
        }
      } catch {
        // Safe failover
      }
    },
    { urls: ['<all_urls>'] }
  );
}

/**
 * Navigation & Redirect Tracking via Chrome WebNavigation API
 */
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return; // Top-level frame only

  const tabId = details.tabId;
  const existingInFlight = tabWarningInFlight.get(tabId);
  // If tab is navigating to a different destination, clear previous in-flight warning lock
  if (existingInFlight && existingInFlight.targetUrl !== details.url) {
    tabWarningInFlight.delete(tabId);
  }

  const existingHistory = tabRedirectHistory.get(tabId);
  if (!existingHistory) {
    tabRedirectHistory.set(tabId, {
      initialUrl: details.url,
      finalUrl: details.url,
      hops: [{ url: details.url, timestamp: Date.now() }],
      hopCount: 1,
      lastUpdated: Date.now()
    });
  }
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  
  const tabId = details.tabId;
  const isRedirect = details.transitionQualifiers && (
    details.transitionQualifiers.includes('server_redirect') ||
    details.transitionQualifiers.includes('client_redirect')
  );

  let history = tabRedirectHistory.get(tabId);
  if (isRedirect && history) {
    history.hops.push({ url: details.url, timestamp: Date.now() });
    history.hopCount = history.hops.length;
    history.finalUrl = details.url;
    history.lastUpdated = Date.now();
  } else {
    // Fresh user navigation
    history = {
      initialUrl: details.url,
      finalUrl: details.url,
      hops: [{ url: details.url, timestamp: Date.now() }],
      hopCount: 1,
      lastUpdated: Date.now()
    };
    tabRedirectHistory.set(tabId, history);
    globalEventStore.clearTab(tabId);
  }

  const navEvent = createNavigationSecurityEvent(
    { tabId, url: details.url },
    history.hops.map(h => h.url)
  );
  if (navEvent) {
    globalEventStore.addEvent(navEvent);
  }

  performTabScan(details.tabId, details.url).catch(() => {});
});

/**
 * Download Security Context Monitoring (Chrome Downloads API)
 */
if (chrome.downloads && chrome.downloads.onCreated) {
  chrome.downloads.onCreated.addListener(async (downloadItem) => {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true }).catch(() => []);
      const activeTab = tabs && tabs.length > 0 ? tabs[0] : null;
      if (activeTab && activeTab.id) {
        const currentAnalysis = tabScanResults.get(activeTab.id);
        const originRiskScore = currentAnalysis ? currentAnalysis.score : 0;
        const originVerdict = currentAnalysis ? currentAnalysis.verdict : 'SAFE';

        const filename = downloadItem.filename || downloadItem.url.split('/').pop() || 'download';
        const fileExtension = filename.includes('.') ? filename.split('.').pop() : '';

        const downloadContext = {
          downloadId: downloadItem.id,
          url: downloadItem.url,
          filename,
          fileExtension,
          originUrl: activeTab.url || downloadItem.referrer || '',
          originRiskScore,
          originVerdict,
          isDangerousOrigin: originRiskScore >= 60,
          isExecutable: ['exe', 'msi', 'scr', 'bat', 'iso', 'apk', 'vbs', 'ps1'].includes(fileExtension.toLowerCase()),
          timestamp: Date.now()
        };

        tabDownloadContexts.set(activeTab.id, downloadContext);

        const dlEvent = createDownloadSecurityEvent({
          tabId: activeTab.id,
          downloadId: downloadItem.id || 0,
          url: downloadItem.url,
          filename,
          originUrl: activeTab.url || downloadItem.referrer || '',
          originRiskScore
        });
        if (dlEvent) {
          globalEventStore.addEvent(dlEvent);
        }

        // If download initiated from high risk origin, re-evaluate tab score and badge
        if (downloadContext.isDangerousOrigin && currentAnalysis) {
          performTabScan(activeTab.id, activeTab.url, currentAnalysis.features?.form, currentAnalysis.features?.social).catch(() => {});
        }
      }
    } catch {
      // Ignore if tab query fails
    }
  });
}

/**
 * Tab Activation & Removal Listeners
 */
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const result = tabScanResults.get(activeInfo.tabId);
  if (result) {
    updateBadge(activeInfo.tabId, result.verdict, result.score);
  } else {
    try {
      const tab = await chrome.tabs.get(activeInfo.tabId).catch(() => null);
      if (tab && tab.url) {
        await performTabScan(tab.id, tab.url);
      }
    } catch {
      // Tab may be closed or restricted
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabScanResults.delete(tabId);
  tabRedirectHistory.delete(tabId);
  tabDownloadContexts.delete(tabId);
  tabDomMetadata.delete(tabId);
  tabWarningInFlight.delete(tabId);
  globalEventStore.clearTab(tabId);
});

// Initialize Managed Policy & Device state on service worker startup
globalTelemetryQueue.loadManagedPolicy().then(() => {
  const identifiers = globalTelemetryQueue.getIdentifiers();
  if (identifiers.isEnrolled) {
    globalTelemetryQueue.sendHeartbeat().catch(() => {});
    globalTelemetryQueue.flushQueueAsync().catch(() => {});
  }
}).catch(() => {});

/**
 * Message Dispatcher for Content Scripts and Extension Popups
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // 1. Status Model Request for Popups & Settings
  if (message.type === 'PHISHGUARD_GET_STATUS_MODEL') {
    sendResponse({
      statusModel: globalTelemetryQueue.getStatusModel(),
      identifiers: globalTelemetryQueue.getIdentifiers()
    });
    return false;
  }

  // 2. Full Device & Fleet Info
  if (message.type === 'PHISHGUARD_GET_DEVICE_INFO') {
    const ids = globalTelemetryQueue.getIdentifiers();
    sendResponse({
      deviceId: ids.deviceId,
      organizationId: ids.organizationId,
      organizationName: ids.organizationName,
      enrolled: ids.isEnrolled,
      isOnline: ids.isOnline,
      queueSize: ids.queueSize,
      lastSyncTime: ids.lastSyncTime,
      statusModel: globalTelemetryQueue.getStatusModel()
    });
    return false;
  }

  // 3. Enterprise Enrollment Execution
  if (message.type === 'PHISHGUARD_ENROLL_DEVICE' || message.type === 'PHISHGUARD_SYNC_NOW') {
    (async () => {
      if (message.backendUrl) {
        globalTelemetryQueue.setConfig({ backendUrl: message.backendUrl });
      }
      const token = message.enrollmentToken || message.token;
      let enrollResult = { success: true };
      if (token) {
        enrollResult = await globalTelemetryQueue.enrollDevice(token, message.backendUrl);
      }
      
      await globalTelemetryQueue.sendHeartbeat().catch(() => {});
      await globalTelemetryQueue.flushQueueAsync().catch(() => {});

      const status = globalTelemetryQueue.getStatusModel();
      const ids = globalTelemetryQueue.getIdentifiers();
      sendResponse({
        success: enrollResult.success !== false,
        error: enrollResult.error,
        deviceId: ids.deviceId,
        statusModel: status
      });
    })();
    return true; // async response
  }

  // 4. Disconnect from Enterprise Fleet (Return to Individual Mode)
  if (message.type === 'PHISHGUARD_DISCONNECT_FLEET') {
    (async () => {
      const result = await globalTelemetryQueue.unenroll();
      sendResponse(result);
    })();
    return true; // async response
  }

  // 5. Content Script Reports DOM Form & Social Engineering Metadata
  if (message.type === 'PHISHGUARD_DOM_METADATA') {
    const tabId = sender.tab?.id;
    const url = sender.tab?.url || message.url;
    if (tabId && url) {
      // Record Form Security Event
      if (message.formMetadata) {
        const formEvent = createFormSecurityEvent(tabId, url, message.formMetadata);
        if (formEvent) globalEventStore.addEvent(formEvent);
      }

      // Record Page Branding Event
      const pageTitle = message.formMetadata?.pageTitle || '';
      const visibleHeadings = message.socialMeta?.visibleHeadingsSample || [];
      const brandEvent = createPageBrandingEvent(tabId, url, pageTitle, visibleHeadings);
      if (brandEvent) globalEventStore.addEvent(brandEvent);

      performTabScan(tabId, url, message.formMetadata, message.socialMeta)
        .then(res => {
          sendResponse({ success: true, result: res });
        })
        .catch(() => {
          sendResponse({ success: false, result: null });
        });
      return true; // async response
    }
  }

  // 6. Popup Requests Current Tab Analysis
  if (message.type === 'GET_CURRENT_ANALYSIS') {
    const tabId = message.tabId;
    const inMemoryResult = tabScanResults.get(tabId);
    if (inMemoryResult) {
      sendResponse({ result: inMemoryResult });
      return false;
    }

    // Check storage session or scan active tab directly
    (async () => {
      const sessionResult = await getSessionData(`tab_${tabId}`);
      if (sessionResult) {
        tabScanResults.set(tabId, sessionResult);
        sendResponse({ result: sessionResult });
        return;
      }

      try {
        const tab = await chrome.tabs.get(tabId).catch(() => null);
        if (tab && tab.url) {
          const freshScan = await performTabScan(tab.id, tab.url);
          sendResponse({ result: freshScan });
          return;
        }
      } catch {
        // Tab may have closed
      }

      sendResponse({ result: null });
    })();

    return true; // async response
  }

  // 7. User proceeds through warning interstitial (bypasses warning for domain)
  if (message.type === 'DISMISS_WARNING_FOR_DOMAIN') {
    if (message.domain) {
      const cleanDomain = message.domain.toLowerCase();
      dismissedWarnings.add(cleanDomain);
      (async () => {
        const currentList = await getSessionData('dismissed_domains') || [];
        if (!currentList.includes(cleanDomain)) {
          await setSessionData('dismissed_domains', [...currentList, cleanDomain]);
        }
        sendResponse({ success: true });
      })();
      return true;
    }
    sendResponse({ success: false });
    return false;
  }

  // 8. Force Rescan requested from UI
  if (message.type === 'FORCE_RESCAN') {
    if (message.tabId && message.url) {
      performTabScan(message.tabId, message.url)
        .then(res => {
          sendResponse({ success: true, result: res });
        })
        .catch(() => {
          sendResponse({ success: false, result: null });
        });
      return true;
    }
  }
});
