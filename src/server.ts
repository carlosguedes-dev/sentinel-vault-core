import express, { Express } from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { configureSecurityMiddleware } from './infrastructure/middleware/security.js';
import { createRateLimiter } from './infrastructure/middleware/rate-limiter.js';
import { errorHandler } from './infrastructure/middleware/error.middleware.js';
import { apiRouter } from './presentation/routes/api.router.js';
import { env } from './config/env.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createApp(): Express {
  const app = express();

  // 1. Trust proxy if behind reverse proxy
  app.set('trust proxy', 1);

  // 2. Security Headers & CORS Protection
  configureSecurityMiddleware(app);

  // 3. Body Parser with Strict Payload Limits (Prevents memory exhaustion)
  app.use(express.json({ limit: '512kb' }));
  app.use(express.urlencoded({ extended: false, limit: '512kb' }));

  // 4. Global API Rate Limiter
  const globalLimiter = createRateLimiter({
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    maxRequests: env.RATE_LIMIT_MAX_REQUESTS,
    message: 'Global API rate limit reached. Please throttle requests.',
  });
  app.use('/api', globalLimiter);

  // 5. Mount API Routes
  app.use('/api/v1', apiRouter);

  // 6. Serve Cyberpunk HUD Telemetry Dashboard
  let publicDir = path.join(__dirname, 'presentation', 'views', 'public');
  if (!fs.existsSync(publicDir)) {
    publicDir = path.join(__dirname, '..', 'src', 'presentation', 'views', 'public');
  }
  app.use(express.static(publicDir));

  // 7. Fallback to HUD Dashboard for SPA routing
  app.get('/', (_req, res) => {
    res.sendFile(path.join(publicDir, 'index.html'));
  });

  // 8. Centralized Error Handler (Always last)
  app.use(errorHandler);

  return app;
}
