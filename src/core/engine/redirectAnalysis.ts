import { DetectionSignal, RedirectAnalysisData } from '../types';
import { KNOWN_URL_SHORTENERS } from '../config/brands';

/**
 * Analyzes navigation redirect chains and URL shorteners
 */
export function analyzeRedirectChain(redirectData?: RedirectAnalysisData | null): DetectionSignal[] {
  const signals: DetectionSignal[] = [];
  if (!redirectData || !redirectData.hops || redirectData.hops.length <= 1) {
    return signals;
  }

  const hopCount = redirectData.hopCount || redirectData.hops.length;
  
  // 1. Long Redirect Chain (>= 3 hops)
  if (hopCount >= 3) {
    signals.push({
      id: 'SIGNAL_LONG_REDIRECT_CHAIN',
      category: 'REDIRECT_CHAIN',
      type: 'MULTI_HOP_REDIRECT_CHAIN',
      severity: hopCount >= 4 ? 'HIGH' : 'MEDIUM',
      weight: hopCount >= 4 ? 30 : 22,
      title: `Multi-Hop Navigation Redirect Chain (${hopCount} hops)`,
      description: `Navigation underwent ${hopCount} consecutive redirects before reaching the target. Threat actors use complex redirect trampolines to evade web scanners and referral headers.`,
      confidence: 0.88,
      evidence: {
        hopCount,
        hops: redirectData.hops.map(h => h.url)
      }
    });
  }

  // 2. URL Shortener Used as Gateway
  let initialHost = '';
  try {
    const parsed = new URL(redirectData.initialUrl);
    initialHost = parsed.hostname.toLowerCase();
  } catch {
    initialHost = redirectData.initialUrl;
  }

  const isShortener = KNOWN_URL_SHORTENERS.some(s => initialHost === s || initialHost.endsWith('.' + s));
  if (isShortener) {
    signals.push({
      id: 'SIGNAL_SHORTENER_REDIRECT',
      category: 'REDIRECT_CHAIN',
      type: 'URL_SHORTENER_INTERMEDIARY',
      severity: 'LOW',
      weight: 12,
      title: `URL Shortener Intermediary (${initialHost})`,
      description: `Traffic routed through a public URL shortening service (${initialHost}) which masks the destination domain.`,
      confidence: 0.85,
      evidence: {
        shortenerDomain: initialHost,
        destinationUrl: redirectData.finalUrl
      }
    });
  }

  return signals;
}
