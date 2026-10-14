import { test, describe } from 'node:test';
import assert from 'node:assert';
import { HasherService } from '../src/core/crypto/hasher.js';

describe('🔑 Authentication & Hashing Engine Tests (scrypt + timingSafeEqual)', () => {
  test('Should hash passwords with unique salts', async () => {
    const password = 'SentinelMasterPassword#2026';
    const hash1 = await HasherService.hash(password);
    const hash2 = await HasherService.hash(password);

    assert.notStrictEqual(hash1, hash2, 'Identical passwords must produce distinct salted hashes');

    const isValid1 = await HasherService.verify(password, hash1);
    const isValid2 = await HasherService.verify(password, hash2);

    assert.strictEqual(isValid1, true, 'Hash 1 must verify against original password');
    assert.strictEqual(isValid2, true, 'Hash 2 must verify against original password');
  });

  test('Should reject invalid passwords with timing safe comparison', async () => {
    const password = 'CorrectPassword#123';
    const wrongPassword = 'WrongPassword#123';

    const hash = await HasherService.hash(password);
    const isValid = await HasherService.verify(wrongPassword, hash);

    assert.strictEqual(isValid, false, 'Invalid password must be rejected');
  });

  test('Should compare strings in constant time', () => {
    const str1 = 'secure_secret_token_alpha';
    const str2 = 'secure_secret_token_alpha';
    const str3 = 'secure_secret_token_beta!';

    assert.strictEqual(HasherService.constantTimeCompare(str1, str2), true);
    assert.strictEqual(HasherService.constantTimeCompare(str1, str3), false);
  });
});
