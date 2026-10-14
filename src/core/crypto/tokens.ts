import crypto from 'node:crypto';

/**
 * Production Cryptographic Token & ID Utility
 * Replaces all unsafe Math.random() usage with OS-level Cryptographically Secure PRNG (CSPRNG).
 */
export class TokenService {
  /**
   * Generates a cryptographically secure UUID v4.
   */
  static generateId(): string {
    return crypto.randomUUID();
  }

  /**
   * Generates a secure API key with a prefix and high entropy.
   * Format: sk_live_<48 hex chars> (192 bits of entropy)
   */
  static generateApiKey(prefix: string = 'sk_live'): string {
    const buffer = crypto.randomBytes(24);
    return `${prefix}_${buffer.toString('hex')}`;
  }

  /**
   * Generates a secure random hex string of specified byte length.
   */
  static generateRandomHex(bytes: number = 32): string {
    return crypto.randomBytes(bytes).toString('hex');
  }

  /**
   * Calculates Shannon entropy in bits for a given string.
   */
  static calculateEntropyBits(value: string): number {
    if (!value || value.length === 0) return 0;

    let poolSize = 0;
    if (/[a-z]/.test(value)) poolSize += 26;
    if (/[A-Z]/.test(value)) poolSize += 26;
    if (/[0-9]/.test(value)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(value)) poolSize += 33;

    if (poolSize === 0) return 0;
    return Math.round(value.length * (Math.log(poolSize) / Math.log(2)));
  }
}
