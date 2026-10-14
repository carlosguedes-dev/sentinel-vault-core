import crypto from 'node:crypto';

/**
 * Production Password & Secret Hashing Service
 * Uses scrypt (memory-hard key derivation function) with individual CSPRNG salts
 * and timing-safe comparisons to defend against rainbow tables, brute force, and side-channel timing attacks.
 */
export class HasherService {
  private static readonly SALT_LENGTH = 16;
  private static readonly KEY_LENGTH = 64;
  private static readonly SCRYPT_OPTIONS: crypto.ScryptOptions = {
    N: 16384, // CPU/memory cost
    r: 8,     // Block size
    p: 1,     // Parallelization parameter
  };

  /**
   * Hashes a plaintext secret/password using scrypt with a unique random salt.
   * Returns formatted string: "salt:derivedKey" (hex encoded).
   */
  static async hash(plaintext: string): Promise<string> {
    if (!plaintext || typeof plaintext !== 'string') {
      throw new Error('Plaintext value is required for hashing');
    }

    const salt = crypto.randomBytes(this.SALT_LENGTH);
    const derivedKey = crypto.scryptSync(
      plaintext,
      salt,
      this.KEY_LENGTH,
      this.SCRYPT_OPTIONS
    );

    return `${salt.toString('hex')}:${derivedKey.toString('hex')}`;
  }

  /**
   * Verifies a plaintext against a stored hash using constant-time comparison.
   * Defends completely against timing attacks.
   */
  static async verify(plaintext: string, storedHash: string): Promise<boolean> {
    if (!plaintext || !storedHash || !storedHash.includes(':')) {
      return false;
    }

    try {
      const [saltHex, keyHex] = storedHash.split(':');
      if (!saltHex || !keyHex) return false;

      const salt = Buffer.from(saltHex, 'hex');
      const expectedKey = Buffer.from(keyHex, 'hex');

      const derivedKey = crypto.scryptSync(
        plaintext,
        salt,
        expectedKey.length,
        this.SCRYPT_OPTIONS
      );

      // Constant-time buffer comparison to prevent timing leaks
      return crypto.timingSafeEqual(derivedKey, expectedKey);
    } catch {
      return false;
    }
  }

  /**
   * Compares two strings in constant time.
   */
  static constantTimeCompare(a: string, b: string): boolean {
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');

    if (bufA.length !== bufB.length) {
      return false;
    }

    return crypto.timingSafeEqual(bufA, bufB);
  }
}
