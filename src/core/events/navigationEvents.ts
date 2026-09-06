/**
 * PhishGuard Navigation & Redirect Event Analyzer
 */

import { NavigationSecurityEvent, ThreatSeverity } from './eventTypes';
import { KNOWN_URL_SHORTENERS } from '../config/brands';

export interface RawNavigationHop {
  tabId: number;
  url: string;
  previousUrl?: string;
  statusCode?: number;
  transitionType?: string;
}

export function createNavigationSecurityEvent(
  hop: RawNavigationHop | number | string | null | undefined,
  hopsList: string[] = []
): NavigationSecurityEvent | null {
  let tabId = 0;
  let targetUrl = '';

  if (typeof hop === 'number') {
    tabId = hop;
  } else if (hop && typeof hop === 'object') {
    tabId = typeof hop.tabId === 'number' ? hop.tabId : 0;
    targetUrl = typeof hop.url === 'string' ? hop.url.trim() : '';
  } else if (typeof hop === 'string') {
    targetUrl = hop.trim();
  }

  const cleanHopsList = Array.isArray(hopsList)
    ? hopsList.filter((h): h is string => typeof h === 'string' && h.trim().length > 0)
    : [];

  // Fallback to hopsList if targetUrl was not provided in the hop object or hop was passed as tabId number
  if (!targetUrl && cleanHopsList.length > 0) {
    targetUrl = cleanHopsList[cleanHopsList.length - 1];
  }

  // If no URL is available at all, return null to prevent creating false/misleading events
  if (!targetUrl) {
    return null;
  }

  if (cleanHopsList.length === 0 && targetUrl) {
    cleanHopsList.push(targetUrl);
  }

  let hostname = '';
  let origin = '';
  let isInternalScheme = false;

  try {
    const isStandardScheme = /^https?:\/\//i.test(targetUrl) || /^\/\//.test(targetUrl);
    const urlToParse = isStandardScheme
      ? (targetUrl.startsWith('//') ? 'https:' + targetUrl : targetUrl)
      : (targetUrl.includes('://') ? targetUrl : 'https://' + targetUrl);

    const parsed = new URL(urlToParse);
    hostname = (parsed.hostname || '').toLowerCase();
    origin = parsed.origin && parsed.origin !== 'null' ? parsed.origin : (parsed.protocol || targetUrl);

    if (['chrome:', 'chrome-extension:', 'edge:', 'about:', 'devtools:', 'brave:', 'opera:'].includes(parsed.protocol)) {
      isInternalScheme = true;
      if (!hostname) {
        hostname = parsed.pathname.replace(/^\/+/, '').split('/')[0] || parsed.protocol.replace(':', '');
      }
    }
  } catch {
    hostname = (typeof targetUrl === 'string' ? targetUrl : '').toLowerCase();
    origin = targetUrl;
  }

  const hasShortener = cleanHopsList.some(h => {
    try {
      if (typeof h !== 'string' || !h) return false;
      const u = new URL(h.startsWith('http') ? h : 'https://' + h);
      const hHost = (u.hostname || '').toLowerCase();
      return KNOWN_URL_SHORTENERS.some(s => hHost.endsWith(s.toLowerCase()));
    } catch {
      return false;
    }
  });

  const hopCount = cleanHopsList.length;
  let severity: ThreatSeverity = 'SAFE';
  let title = 'Navigation Hop';
  let description = `Navigated to ${hostname || targetUrl}.`;

  if (isInternalScheme) {
    severity = 'SAFE';
    title = 'Internal Browser Navigation';
    description = `Navigated to internal browser resource (${targetUrl}).`;
  } else if (hopCount >= 3 && hasShortener) {
    severity = 'HIGH';
    title = 'Multi-Hop Redirect Trampoline via URL Shortener';
    description = `Navigation passed through ${hopCount} redirect hops including intermediary URL shorteners.`;
  } else if (hopCount >= 3) {
    severity = 'MEDIUM';
    title = 'Multi-Hop Redirect Chain';
    description = `Navigation traversed ${hopCount} redirect hops.`;
  } else if (hasShortener) {
    severity = 'LOW';
    title = 'URL Shortener Redirection';
    description = `Link resolved through an intermediary URL shortening service.`;
  }

  return {
    id: `nav_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: Date.now(),
    tabId,
    pageUrl: targetUrl,
    pageOrigin: origin,
    type: hopCount > 1 ? 'REDIRECT_HOP_OBSERVED' : 'NAVIGATION_COMMITTED',
    severity,
    title,
    description,
    initialUrl: cleanHopsList[0] || targetUrl,
    redirectHopCount: hopCount,
    hasUrlShortener: hasShortener,
    hopDomains: cleanHopsList.map(h => {
      try {
        const u = new URL(h.startsWith('http') ? h : 'https://' + h);
        return (u.hostname || h).toLowerCase();
      } catch {
        return typeof h === 'string' ? h.toLowerCase() : '';
      }
    }),
    evidence: {
      hopCount,
      hasShortener,
      hopsList: cleanHopsList
    }
  };
}
