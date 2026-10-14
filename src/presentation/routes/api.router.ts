import { Router } from 'express';
import { authRouter } from './auth.routes.js';
import { vaultRouter } from './vault.routes.js';
import { HealthController } from '../controllers/health.controller.js';

export const apiRouter = Router();

// Health & Telemetry (Public)
apiRouter.get('/health', HealthController.getHealth);

// Sub-routers
apiRouter.use('/auth', authRouter);
apiRouter.use('/vault', vaultRouter);
