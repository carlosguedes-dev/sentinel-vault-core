import { Router } from 'express';
import { VaultController } from '../controllers/vault.controller.js';
import { AuthMiddleware } from '../../infrastructure/middleware/auth.middleware.js';

export const vaultRouter = Router();

// All vault routes require authentication
vaultRouter.use(AuthMiddleware.authenticate);

// List metadata of secrets (OPERATOR, ADMIN, AUDITOR)
vaultRouter.get('/secrets', VaultController.listSecrets);

// Create new encrypted secret (OPERATOR, ADMIN)
vaultRouter.post(
  '/secrets',
  AuthMiddleware.requireRole('ADMIN', 'OPERATOR'),
  VaultController.createSecret
);

// Decrypt and view plaintext secret (ADMIN only or OPERATOR with audited access)
vaultRouter.get(
  '/secrets/:id/decrypt',
  AuthMiddleware.requireRole('ADMIN', 'OPERATOR'),
  VaultController.getSecretValue
);

// Delete secret (ADMIN only)
vaultRouter.delete(
  '/secrets/:id',
  AuthMiddleware.requireRole('ADMIN'),
  VaultController.deleteSecret
);
