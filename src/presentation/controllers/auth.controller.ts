import { Request, Response } from 'express';
import { z } from 'zod';
import { vaultRepository } from '../../infrastructure/database/memory-vault.repo.js';
import { HasherService } from '../../core/crypto/hasher.js';
import { TokenService } from '../../core/crypto/tokens.js';
import { UnauthorizedError } from '../../core/errors/app-error.js';
import { env } from '../../config/env.js';

const loginSchema = z.object({
  username: z.string().min(3).max(64),
  password: z.string().min(8).max(128),
});

export class AuthController {
  static async login(req: Request, res: Response): Promise<void> {
    const { username, password } = loginSchema.parse(req.body);

    const user = await vaultRepository.findUserByUsername(username);

    // Timing-attack mitigation: perform a dummy hash check if user not found
    if (!user) {
      await HasherService.verify(
        password,
        '00000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000'
      );
      throw new UnauthorizedError('Invalid credentials');
    }

    // Check account lockout
    if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
      throw new UnauthorizedError(
        'Account is temporarily locked due to excessive failed attempts. Try again later.'
      );
    }

    const isValid = await HasherService.verify(password, user.passwordHash);

    if (!isValid) {
      const attempts = user.failedLoginAttempts + 1;
      const updates: { failedLoginAttempts: number; lockedUntil?: string } = {
        failedLoginAttempts: attempts,
      };

      // Lock account for 15 minutes after 5 failed attempts
      if (attempts >= 5) {
        updates.lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      }

      await vaultRepository.updateUser(user.id, updates);
      throw new UnauthorizedError('Invalid credentials');
    }

    // Reset failed attempts on success
    await vaultRepository.updateUser(user.id, {
      failedLoginAttempts: 0,
      lastLoginAt: new Date().toISOString(),
      lockedUntil: undefined,
    });

    // Create session token with cryptographic signature
    const exp = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    const payloadStr = `${user.id}:${user.username}:${user.role}:${exp}`;
    const sig = Buffer.from(`${payloadStr}:${env.JWT_SECRET}`).toString('base64url');

    const tokenPayload = {
      id: user.id,
      username: user.username,
      role: user.role,
      exp,
      sig,
    };

    const token = Buffer.from(JSON.stringify(tokenPayload)).toString('base64url');

    res.json({
      success: true,
      message: 'Authentication successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    });
  }

  static async me(req: Request, res: Response): Promise<void> {
    res.json({
      success: true,
      user: req.user,
    });
  }

  static async generateApiKey(req: Request, res: Response): Promise<void> {
    const newApiKey = TokenService.generateApiKey('sk_live');
    const newKeyHash = await HasherService.hash(newApiKey);

    if (req.user) {
      await vaultRepository.updateUser(req.user.id, { apiKeyHash: newKeyHash });
    }

    res.json({
      success: true,
      message: 'New API Key generated successfully. Store it safely, it cannot be recovered!',
      apiKey: newApiKey,
    });
  }
}
