import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller.js';
import { AuthMiddleware } from '../../infrastructure/middleware/auth.middleware.js';
import { createRateLimiter } from '../../infrastructure/middleware/rate-limiter.js';
import { env } from '../../config/env.js';

export const authRouter = Router();

// Dedicated strict rate limiter for login attempts (defends against brute-force)
const loginLimiter = createRateLimiter({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  maxRequests: env.AUTH_RATE_LIMIT_MAX_REQUESTS,
  message: 'Too many authentication attempts. IP temporarily throttled.',
});

authRouter.post('/login', loginLimiter, AuthController.login);
authRouter.get('/me', AuthMiddleware.authenticate, AuthController.me);
authRouter.post(
  '/generate-api-key',
  AuthMiddleware.authenticate,
  AuthMiddleware.requireRole('ADMIN'),
  AuthController.generateApiKey
);
