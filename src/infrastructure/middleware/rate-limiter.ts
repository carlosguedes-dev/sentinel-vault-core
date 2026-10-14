import { Request, Response, NextFunction } from 'express';
import { RateLimitError } from '../../core/errors/app-error.js';

interface RateLimitRecord {
  count: number;
  resetTime: number;
}

/**
 * In-memory sliding window Rate Limiter
 * Defends against brute-force attacks and denial of service.
 */
export function createRateLimiter(options: {
  windowMs: number;
  maxRequests: number;
  message?: string;
}) {
  const store = new Map<string, RateLimitRecord>();

  // Cleanup expired buckets every minute to prevent memory leaks
  setInterval(() => {
    const now = Date.now();
    for (const [key, record] of store.entries()) {
      if (now > record.resetTime) {
        store.delete(key);
      }
    }
  }, 60000).unref();

  return (req: Request, _res: Response, next: NextFunction) => {
    // Determine client identifier (IP or forwarded IP)
    const ip =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      req.socket.remoteAddress ||
      'unknown';

    const now = Date.now();
    const existing = store.get(ip);

    if (!existing || now > existing.resetTime) {
      store.set(ip, {
        count: 1,
        resetTime: now + options.windowMs,
      });
      return next();
    }

    if (existing.count >= options.maxRequests) {
      const retryAfter = Math.ceil((existing.resetTime - now) / 1000);
      _res.setHeader('Retry-After', retryAfter);
      throw new RateLimitError(
        options.message || `Rate limit exceeded. Try again in ${retryAfter} seconds.`
      );
    }

    existing.count += 1;
    next();
  };
}
