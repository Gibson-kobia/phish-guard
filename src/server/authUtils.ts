/**
 * PhishGuard Security & Authentication Utilities
 * 
 * Implements password-specific hashing using Node.js crypto.scryptSync with 16-byte random salts,
 * timing-safe password verification, cryptographically secure token generation, and rate limiting.
 */

import crypto from 'crypto';

export interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const loginAttempts = new Map<string, RateLimitEntry>();

/**
 * Hash a password using scrypt with a unique 16-byte cryptographically secure salt.
 * Output format: scrypt:<hex_salt>:<hex_hash>
 */
export function hashPassword(password: string): string {
  if (!password || typeof password !== 'string') {
    throw new Error('Password must be a non-empty string');
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt:${salt}:${derivedKey.toString('hex')}`;
}

/**
 * Verify a plaintext password against a stored hash using timing-safe comparison.
 * Supports scrypt (standard) and legacy SHA-256 with migration compatibility.
 */
export function verifyPassword(password: string, storedHash: string): boolean {
  if (!password || !storedHash) return false;

  try {
    if (storedHash.startsWith('scrypt:')) {
      const parts = storedHash.split(':');
      if (parts.length !== 3) return false;
      const salt = parts[1];
      const originalHash = parts[2];
      const derivedKey = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
      const derivedKeyHex = derivedKey.toString('hex');

      if (derivedKeyHex.length !== originalHash.length) return false;
      return crypto.timingSafeEqual(Buffer.from(derivedKeyHex, 'hex'), Buffer.from(originalHash, 'hex'));
    }

    // Legacy SHA-256 fallback
    const sha256 = crypto.createHash('sha256').update(password).digest('hex');
    if (storedHash.length === sha256.length) {
      return crypto.timingSafeEqual(Buffer.from(sha256, 'hex'), Buffer.from(storedHash, 'hex'));
    }
  } catch (err) {
    return false;
  }

  return false;
}

/**
 * Generate a cryptographically secure random session token.
 */
export function generateSecureToken(prefix = 'pg_sess_'): string {
  return `${prefix}${crypto.randomBytes(32).toString('hex')}`;
}

/**
 * Simple in-memory rate limiter for authentication endpoints.
 * Limits attempts per identifier (IP + username) within a window.
 */
export function checkRateLimit(key: string, maxAttempts = 10, windowMs = 15 * 60 * 1000): { allowed: boolean; remaining: number; resetInSec: number } {
  const now = Date.now();
  const entry = loginAttempts.get(key);

  if (!entry || now > entry.resetAt) {
    loginAttempts.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: maxAttempts - 1, resetInSec: Math.ceil(windowMs / 1000) };
  }

  entry.count += 1;
  const remaining = Math.max(0, maxAttempts - entry.count);
  const resetInSec = Math.ceil((entry.resetAt - now) / 1000);

  if (entry.count > maxAttempts) {
    return { allowed: false, remaining: 0, resetInSec };
  }

  return { allowed: true, remaining, resetInSec };
}

/**
 * Clear rate limit for a key on successful login.
 */
export function resetRateLimit(key: string): void {
  loginAttempts.delete(key);
}
