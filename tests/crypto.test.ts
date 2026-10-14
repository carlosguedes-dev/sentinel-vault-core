import { test, describe } from 'node:test';
import assert from 'node:assert';
import { CipherService } from '../src/core/crypto/cipher.js';
import { TokenService } from '../src/core/crypto/tokens.js';

describe('🛡️ Cryptographic Engine Tests (AEAD AES-256-GCM)', () => {
  test('Should encrypt and decrypt plaintext accurately', () => {
    const original = 'super_secret_stripe_live_key_999!';
    const context = 'STRIPE_KEY';

    const payload = CipherService.encrypt(original, context);

    assert.ok(payload.ciphertext, 'Ciphertext should not be empty');
    assert.strictEqual(payload.iv.length, 24, 'IV should be 12 bytes (24 hex chars)');
    assert.strictEqual(payload.authTag.length, 32, 'AuthTag should be 16 bytes (32 hex chars)');

    const decrypted = CipherService.decrypt(payload, context);
    assert.strictEqual(decrypted, original, 'Decrypted value must match original plaintext');
  });

  test('Should reject decryption if ciphertext is tampered with (AuthTag validation)', () => {
    const original = 'database_password_admin_2026';
    const payload = CipherService.encrypt(original);

    // Tamper with first character of ciphertext
    const tamperedCiphertext =
      (payload.ciphertext[0] === 'a' ? 'b' : 'a') + payload.ciphertext.slice(1);
    const tamperedPayload = { ...payload, ciphertext: tamperedCiphertext };

    assert.throws(
      () => {
        CipherService.decrypt(tamperedPayload);
      },
      /Unsupported state or unable to authenticate data/,
      'Tampered ciphertext must cause AEAD decryption failure'
    );
  });

  test('Should generate cryptographically unique IDs and API keys', () => {
    const id1 = TokenService.generateId();
    const id2 = TokenService.generateId();
    assert.notStrictEqual(id1, id2, 'UUIDs must be unique');

    const key1 = TokenService.generateApiKey('sk_live');
    const key2 = TokenService.generateApiKey('sk_live');
    assert.notStrictEqual(key1, key2, 'API keys must be unique');
    assert.ok(key1.startsWith('sk_live_'), 'API key must contain requested prefix');
  });

  test('Should calculate entropy accurately', () => {
    const weak = '123456';
    const strong = 'K8#mQ2$pL9@zX1!vB7';

    const entropyWeak = TokenService.calculateEntropyBits(weak);
    const entropyStrong = TokenService.calculateEntropyBits(strong);

    assert.ok(entropyStrong > entropyWeak, 'Strong password must have higher entropy');
    assert.ok(entropyStrong > 80, 'High entropy string must exceed 80 bits');
  });
});
