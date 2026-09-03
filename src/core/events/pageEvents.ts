/**
 * PhishGuard Page & Branding Event Analyzer
 * 
 * Constructs structured page branding and domain hierarchy events for both
 * known protected brands and arbitrary inferred brand candidates.
 */

import { PageBrandingEvent, ThreatSeverity } from './eventTypes';
import { inferBrandIdentity, evaluateBrandDomainMismatch, extractRegisteredDomain } from '../engine/brandIdentity';

export interface PageMetadataInput {
  tabId: number;
  url: string;
  title?: string;
  headings?: string[];
  metaTokens?: string[];
}

export function createPageBrandingEvent(
  inputOrTabId: PageMetadataInput | number | null | undefined,
  urlArg?: string,
  titleArg?: string,
  headingsArg?: string[],
  metaTokensArg?: string[]
): PageBrandingEvent | null {
  let tabId = 0;
  let url = '';
  let title = '';
  let headings: string[] = [];
  let metaTokens: string[] = [];

  if (typeof inputOrTabId === 'number') {
    tabId = inputOrTabId;
    url = typeof urlArg === 'string' ? urlArg : '';
    title = typeof titleArg === 'string' ? titleArg : '';
    headings = Array.isArray(headingsArg) ? headingsArg : [];
    metaTokens = Array.isArray(metaTokensArg) ? metaTokensArg : [];
  } else if (inputOrTabId && typeof inputOrTabId === 'object') {
    tabId = typeof inputOrTabId.tabId === 'number' ? inputOrTabId.tabId : 0;
    url = typeof inputOrTabId.url === 'string' ? inputOrTabId.url : '';
    title = typeof inputOrTabId.title === 'string' ? inputOrTabId.title : '';
    headings = Array.isArray(inputOrTabId.headings) ? inputOrTabId.headings : [];
    metaTokens = Array.isArray(inputOrTabId.metaTokens) ? inputOrTabId.metaTokens : [];
  }

  if (!url || tabId <= 0) {
    return null;
  }

  let hostname = '';
  let origin = '';

  try {
    const parsed = new URL(url.startsWith('http') ? url : 'https://' + url);
    hostname = parsed.hostname.toLowerCase();
    origin = parsed.origin;
  } catch {
    hostname = url.toLowerCase();
    origin = url;
  }

  const registeredDomain = extractRegisteredDomain(hostname);
  const visibleTokens = [...headings, ...metaTokens];
  
  const candidate = inferBrandIdentity(hostname, title, visibleTokens);
  if (!candidate) {
    return null;
  }

  const mismatchEval = evaluateBrandDomainMismatch(hostname, candidate);
  if (!mismatchEval) {
    return null;
  }

  const isFreeHosting = mismatchEval.isFreeHostingAbuse;
  const isOfficial = mismatchEval.isOfficial;

  let severity: ThreatSeverity = 'SAFE';
  let eventType: PageBrandingEvent['type'] = 'BRAND_IDENTITY_DETECTED';
  let eventTitle = `Verified ${candidate.candidateName} Domain`;
  let description = `Official authentic service for ${candidate.candidateName}.`;

  if (!isOfficial) {
    if (isFreeHosting) {
      severity = 'CRITICAL';
      eventType = 'FREE_HOSTING_DETECTED';
      eventTitle = `${candidate.candidateName} Impersonation on Free Hosting`;
      description = `Website displays ${candidate.candidateName} branding on third-party cloud platform (${mismatchEval.freeHostingProvider}) rather than official ${candidate.canonicalDomains[0]}.`;
    } else {
      severity = 'HIGH';
      eventType = 'DOMAIN_MISMATCH_DETECTED';
      eventTitle = `Brand Domain Mismatch (${candidate.candidateName})`;
      description = `Website claims to represent ${candidate.candidateName}, but hostname (${hostname}) does not match official domain (${candidate.canonicalDomains[0]}).`;
    }
  }

  return {
    id: `brand_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: Date.now(),
    tabId,
    pageUrl: url,
    pageOrigin: origin,
    type: eventType,
    severity,
    title: eventTitle,
    description,
    claimedBrandName: candidate.candidateName,
    canonicalDomains: candidate.canonicalDomains,
    currentHostname: hostname,
    currentRegisteredDomain: registeredDomain,
    isFreeHostingProvider: isFreeHosting,
    freeHostingProviderName: mismatchEval.freeHostingProvider,
    isOfficialDomain: isOfficial,
    brandTokensFound: candidate.evidence,
    pageTitle: title,
    evidence: {
      candidateName: candidate.candidateName,
      canonicalDomains: candidate.canonicalDomains,
      hostname,
      registeredDomain,
      isOfficial,
      isFreeHosting,
      freeHostingProvider: mismatchEval.freeHostingProvider,
      confidence: candidate.confidence,
      evidenceList: candidate.evidence
    }
  };
}
