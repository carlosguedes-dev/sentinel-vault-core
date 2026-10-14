import crypto from 'node:crypto';
import { env } from '../../config/env.js';

export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  authTag: string;
  version: number;
}

/**
 * Production Authenticated Cipher Service
 * Uses AES-256-GCM (Galois/Counter Mode) authenticated encryption.
 * Any modification of ciphertext or authTag causes an immediate authentication exception.
 */
export class CipherService {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly IV_LENGTH = 12; // 96 bits recommended for GCM
  private static readonly AUTH_TAG_LENGTH = 16; // 128 bits auth tag
  private static readonly VERSION = 1;

  private static getMasterKey(): Buffer {
    return Buffer.from(env.MASTER_ENCRYPTION_KEY, 'hex');
  }

  /**
   * Encrypts plaintext data into an authenticated AES-256-GCM payload.
   */
  static encrypt(plaintext: string, additionalData?: string): EncryptedPayload {
    if (!plaintext) {
      throw new Error('Plaintext data is required for encryption');
    }

    const key = this.getMasterKey();
    const iv = crypto.randomBytes(this.IV_LENGTH);

    const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv, {
      authTagLength: this.AUTH_TAG_LENGTH,
    });

    if (additionalData) {
      cipher.setAAD(Buffer.from(additionalData, 'utf8'));
    }

    let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
    ciphertext += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return {
      ciphertext,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      version: this.VERSION,
    };
  }

  /**
   * Decrypts an authenticated AES-256-GCM payload.
   * Throws if tampered with or corrupted.
   */
  static decrypt(payload: EncryptedPayload, additionalData?: string): string {
    if (!payload.ciphertext || !payload.iv || !payload.authTag) {
      throw new Error('Malformed encrypted payload structure');
    }

    const key = this.getMasterKey();
    const iv = Buffer.from(payload.iv, 'hex');
    const authTag = Buffer.from(payload.authTag, 'hex');

    const decipher = crypto.createDecipheriv(this.ALGORITHM, key, iv, {
      authTagLength: this.AUTH_TAG_LENGTH,
    });

    decipher.setAuthTag(authTag);

    if (additionalData) {
      decipher.setAAD(Buffer.from(additionalData, 'utf8'));
    }

    let decrypted = decipher.update(payload.ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}
