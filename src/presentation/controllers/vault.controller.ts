import { Request, Response } from 'express';
import { z } from 'zod';
import { vaultRepository } from '../../infrastructure/database/memory-vault.repo.js';
import { CipherService } from '../../core/crypto/cipher.js';
import { TokenService } from '../../core/crypto/tokens.js';
import { NotFoundError, ValidationError } from '../../core/errors/app-error.js';
import { SecretItem } from '../../domain/models/secret.model.js';

const createSecretSchema = z.object({
  keyName: z
    .string()
    .min(2)
    .max(100)
    .regex(/^[A-Z0-9_-]+$/i, 'keyName must contain only alphanumeric characters, underscores, and dashes'),
  plaintextValue: z.string().min(1).max(65536, 'Secret value must not exceed 64KB'),
  description: z.string().max(500).default(''),
  environment: z.enum(['development', 'staging', 'production']).default('development'),
  tags: z.array(z.string().max(30)).max(10).default([]),
  expiresAt: z.string().datetime().optional(),
});

export class VaultController {
  static async createSecret(req: Request, res: Response): Promise<void> {
    const input = createSecretSchema.parse(req.body);

    // Check duplicate key in same environment
    const existing = await vaultRepository.findSecretByKey(input.keyName, input.environment);
    if (existing) {
      throw new ValidationError(
        `Secret with keyName '${input.keyName}' already exists in '${input.environment}' environment`
      );
    }

    // Encrypt payload with AES-256-GCM using authenticated keyName
    const payload = CipherService.encrypt(input.plaintextValue, input.keyName);

    const entropyBits = TokenService.calculateEntropyBits(input.plaintextValue);

    const secret: SecretItem = {
      id: TokenService.generateId(),
      keyName: input.keyName.toUpperCase(),
      description: input.description,
      payload,
      environment: input.environment,
      tags: input.tags,
      createdBy: req.user?.username || 'anonymous',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      expiresAt: input.expiresAt,
      accessCount: 0,
    };

    await vaultRepository.saveSecret(secret);

    res.status(201).json({
      success: true,
      message: 'Secret encrypted with AES-256-GCM and stored securely in vault.',
      secret: {
        id: secret.id,
        keyName: secret.keyName,
        environment: secret.environment,
        description: secret.description,
        tags: secret.tags,
        entropyBits,
        createdAt: secret.createdAt,
      },
    });
  }

  static async listSecrets(req: Request, res: Response): Promise<void> {
    const envFilter = req.query.environment as string | undefined;
    const secrets = await vaultRepository.listSecrets(envFilter);

    // Return metadata ONLY (never leak ciphertext or keys in list)
    const sanitized = secrets.map((s) => ({
      id: s.id,
      keyName: s.keyName,
      description: s.description,
      environment: s.environment,
      tags: s.tags,
      createdBy: s.createdBy,
      createdAt: s.createdAt,
      accessCount: s.accessCount,
      lastAccessedAt: s.lastAccessedAt,
      isExpired: s.expiresAt ? new Date(s.expiresAt) < new Date() : false,
    }));

    res.json({
      success: true,
      count: sanitized.length,
      secrets: sanitized,
    });
  }

  static async getSecretValue(req: Request, res: Response): Promise<void> {
    const id = req.params.id as string;
    const secret = await vaultRepository.findSecretById(id);

    if (!secret) {
      throw new NotFoundError('Secret');
    }

    if (secret.expiresAt && new Date(secret.expiresAt) < new Date()) {
      throw new ValidationError('Secret has expired and cannot be retrieved.');
    }

    // Decrypt AES-256-GCM payload with authenticated tag verification
    const decryptedValue = CipherService.decrypt(secret.payload, secret.keyName);

    // Record audit access
    await vaultRepository.recordAccess(secret.id);

    res.json({
      success: true,
      keyName: secret.keyName,
      environment: secret.environment,
      plaintextValue: decryptedValue,
      decryptedAt: new Date().toISOString(),
      accessedBy: req.user?.username,
    });
  }

  static async deleteSecret(req: Request, res: Response): Promise<void> {
    const id = req.params.id as string;
    const secret = await vaultRepository.findSecretById(id);

    if (!secret) {
      throw new NotFoundError('Secret');
    }

    await vaultRepository.deleteSecret(id);

    res.json({
      success: true,
      message: `Secret '${secret.keyName}' successfully purged from the vault.`,
    });
  }
}
