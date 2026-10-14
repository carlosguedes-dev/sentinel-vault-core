import { test, describe } from 'node:test';
import assert from 'node:assert';
import { createRateLimiter } from '../src/infrastructure/middleware/rate-limiter.js';
import { RateLimitError } from '../src/core/errors/app-error.js';

describe('⚡ Rate Limiter Shield Tests', () => {
  test('Should allow requests within quota and throw RateLimitError when exceeded', () => {
    const limiter = createRateLimiter({
      windowMs: 5000,
      maxRequests: 3,
    });

    const mockReq = {
      headers: {},
      socket: { remoteAddress: '192.168.1.100' },
    } as any;

    const mockRes = {
      setHeader: (_name: string, _val: any) => {},
    } as any;

    let calls = 0;
    const next = () => {
      calls += 1;
    };

    // First 3 requests must succeed
    limiter(mockReq, mockRes, next);
    limiter(mockReq, mockRes, next);
    limiter(mockReq, mockRes, next);
    assert.strictEqual(calls, 3, 'First 3 requests must pass');

    // 4th request must throw RateLimitError
    assert.throws(
      () => {
        limiter(mockReq, mockRes, next);
      },
      (err: any) => err instanceof RateLimitError,
      'Exceeding quota must throw RateLimitError'
    );
  });
});
