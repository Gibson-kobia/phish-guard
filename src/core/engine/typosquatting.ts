import { DetectionSignal, ProtectedBrand } from '../types';
import { HOMOGLYPH_MAP } from '../config/rules';
import { DEFAULT_PROTECTED_BRANDS } from '../config/brands';

/**
 * Normalizes visual homoglyphs and alphanumeric substitutions
 */
export function normalizeVisualSubstitutions(text: string): string {
  let normalized = '';
  let i = 0;
  while (i < text.length) {
    if (i + 1 < text.length) {
      const twoChar = text.substring(i, i + 2);
      if (HOMOGLYPH_MAP[twoChar]) {
        normalized += HOMOGLYPH_MAP[twoChar];
        i += 2;
        continue;
      }
    }

    const singleChar = text[i];
    normalized += HOMOGLYPH_MAP[singleChar] || singleChar;
    i++;
  }
  return normalized;
}

/**
 * Calculates Damerau-Levenshtein edit distance (handles insertions, deletions, substitutions, and adjacent transpositions)
 */
export function damerauLevenshteinDistance(source: string, target: string): number {
  const srcLen = source.length;
  const tgtLen = target.length;
  
  if (srcLen === 0) return tgtLen;
  if (tgtLen === 0) return srcLen;

  const matrix: number[][] = [];
  for (let i = 0; i <= srcLen; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= tgtLen; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= srcLen; i++) {
    for (let j = 1; j <= tgtLen; j++) {
      const cost = source[i - 1] === target[j - 1] ? 0 : 1;

      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,        // deletion
        matrix[i][j - 1] + 1,        // insertion
        matrix[i - 1][j - 1] + cost  // substitution
      );

      // Transposition check
      if (
        i > 1 &&
        j > 1 &&
        source[i - 1] === target[j - 2] &&
        source[i - 2] === target[j - 1]
      ) {
        matrix[i][j] = Math.min(matrix[i][j], matrix[i - 2][j - 2] + cost);
      }
    }
  }

  return matrix[srcLen][tgtLen];
}

/**
 * Analyzes a domain for typosquatting, visual homoglyphs, combosquatting, and brand impersonation
 */
export function analyzeTyposquatting(
  hostname: string,
  customBrands?: ProtectedBrand[]
): {
  signals: DetectionSignal[];
  targetBrand?: ProtectedBrand;
  isLegitimateBrand: boolean;
} {
  const signals: DetectionSignal[] = [];
  const brands = customBrands && customBrands.length > 0 ? customBrands : DEFAULT_PROTECTED_BRANDS;
  const cleanHost = hostname.toLowerCase();

  // Extract core domain segments (excluding common ccTLDs)
  const hostParts = cleanHost.split('.').filter(Boolean);
  if (hostParts.length === 0) {
    return { signals, isLegitimateBrand: false };
  }

  // 1. Check if domain is an official canonical domain for any protected brand
  for (const brand of brands) {
    for (const canonical of brand.canonicalDomains) {
      if (cleanHost === canonical || cleanHost.endsWith('.' + canonical)) {
        return {
          signals: [],
          targetBrand: brand,
          isLegitimateBrand: true
        };
      }
    }
  }

  let matchedBrand: ProtectedBrand | undefined;

  // 2. Evaluate each hostname segment (excluding TLD)
  const candidateSegments = hostParts.slice(0, -1);
  const normalizedCandidateSegments = candidateSegments.map(s => normalizeVisualSubstitutions(s));

  for (const brand of brands) {
    const brandName = brand.id.toLowerCase();
    const brandDisplay = brand.name;

    for (let sIdx = 0; sIdx < candidateSegments.length; sIdx++) {
      const rawSegment = candidateSegments[sIdx];
      const normSegment = normalizedCandidateSegments[sIdx];

      // A. Visual Homoglyph Substitution Attack (e.g. paypa1, micros0ft, g00gle)
      if (normSegment === brandName && rawSegment !== brandName) {
        matchedBrand = brand;
        signals.push({
          id: `SIGNAL_HOMOGLYPH_${brand.id.toUpperCase()}`,
          category: 'TYPOSQUATTING',
          type: 'HOMOGLYPH_SUBSTITUTION',
          severity: 'CRITICAL',
          weight: 65,
          title: `Visual Homoglyph Impersonation (${brandDisplay})`,
          description: `Segment "${rawSegment}" visually mimics protected brand "${brandDisplay}" using character substitution (normalized: "${normSegment}").`,
          confidence: 0.98,
          evidence: {
            brand: brandDisplay,
            spoofedSegment: rawSegment,
            normalized: normSegment
          }
        });
        break;
      }

      // Also check sub-word homoglyphs with hyphens (e.g. paypa1-update)
      const subTokens = rawSegment.split(/[-_]/);
      for (const token of subTokens) {
        const normToken = normalizeVisualSubstitutions(token);
        if (normToken === brandName && token !== brandName) {
          matchedBrand = brand;
          signals.push({
            id: `SIGNAL_HOMOGLYPH_TOKEN_${brand.id.toUpperCase()}`,
            category: 'TYPOSQUATTING',
            type: 'HOMOGLYPH_SUBSTITUTION',
            severity: 'CRITICAL',
            weight: 60,
            title: `Visual Homoglyph Token Impersonation (${brandDisplay})`,
            description: `Token "${token}" within domain mimics protected brand "${brandDisplay}".`,
            confidence: 0.95,
            evidence: {
              brand: brandDisplay,
              spoofedToken: token,
              normalized: normToken
            }
          });
          break;
        }
      }

      // B. Combosquatting (Unauthorized Brand Name Embedding)
      // e.g. paypal-security-verification.com, google-login-portal.net
      if (rawSegment.includes(brandName) && rawSegment !== brandName) {
        matchedBrand = brand;
        signals.push({
          id: `SIGNAL_EMBEDDED_BRAND_${brand.id.toUpperCase()}`,
          category: 'TYPOSQUATTING',
          type: 'BRAND_COMBOSQUATTING',
          severity: 'HIGH',
          weight: 48,
          title: `Unauthorized Brand Combosquatting (${brandDisplay})`,
          description: `Domain contains the brand name "${brandName}" embedded inside an unregistered host segment ("${rawSegment}"). Official services host on canonical root domains.`,
          confidence: 0.92,
          evidence: {
            brand: brandDisplay,
            embeddedInSegment: rawSegment
          }
        });
        break;
      }

      // C. Damerau-Levenshtein Typosquatting (Edit Distance = 1 or 2)
      // e.g. paypl.com (deletion), paypaal.com (insertion), paypla.com (transposition)
      if (rawSegment.length >= 4 && brandName.length >= 4) {
        const dist = damerauLevenshteinDistance(rawSegment, brandName);
        
        if (dist === 1) {
          matchedBrand = brand;
          signals.push({
            id: `SIGNAL_TYPOSQUAT_D1_${brand.id.toUpperCase()}`,
            category: 'TYPOSQUATTING',
            type: 'TYPOSQUAT_DISTANCE_1',
            severity: 'HIGH',
            weight: 52,
            title: `High-Confidence Typosquat (${brandDisplay})`,
            description: `Domain segment "${rawSegment}" is only 1 edit away from official brand "${brandName}". This closely matches common user keyboard slips.`,
            confidence: 0.94,
            evidence: {
              brand: brandDisplay,
              segment: rawSegment,
              editDistance: 1
            }
          });
          break;
        } else if (dist === 2 && rawSegment.length >= 6) {
          matchedBrand = brand;
          signals.push({
            id: `SIGNAL_TYPOSQUAT_D2_${brand.id.toUpperCase()}`,
            category: 'TYPOSQUATTING',
            type: 'TYPOSQUAT_DISTANCE_2',
            severity: 'MEDIUM',
            weight: 35,
            title: `Potential Typosquat Variant (${brandDisplay})`,
            description: `Domain segment "${rawSegment}" is 2 edits away from brand "${brandName}".`,
            confidence: 0.80,
            evidence: {
              brand: brandDisplay,
              segment: rawSegment,
              editDistance: 2
            }
          });
          break;
        }
      }
    }
  }

  return {
    signals,
    targetBrand: matchedBrand,
    isLegitimateBrand: false
  };
}
