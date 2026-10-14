import { Request, Response, NextFunction } from 'express';
import { UnauthorizedError, ForbiddenError } from '../../core/errors/app-error.js';
import { UserRole, UserSession } from '../../domain/models/user.model.js';
import { vaultRepository } from '../database/memory-vault.repo.js';
import { HasherService } from '../../core/crypto/hasher.js';
import { env } from '../../config/env.js';

// Extend Express Request interface with authenticated user
declare global {
  namespace Express {
    interface Request {
      user?: UserSession;
    }
  }
}

export class AuthMiddleware {
  /**
   * Authenticates requests via Bearer Token or X-API-Key header.
   */
  static async authenticate(req: Request, _res: Response, next: NextFunction): Promise<void> {
    const authHeader = req.headers.authorization;
    const apiKeyHeader = req.headers['x-api-key'] as string | undefined;

    // 1. API Key Authentication
    if (apiKeyHeader) {
      if (!apiKeyHeader.startsWith('sk_')) {
        throw new UnauthorizedError('Invalid API Key format');
      }

      // Find matching user by verifying API key hash
      const user = await vaultRepository.findUserByUsername('sentinel.admin');
      if (user && (await HasherService.verify(apiKeyHeader, user.apiKeyHash))) {
        req.user = {
          id: user.id,
          username: user.username,
          role: user.role,
        };
        return next();
      }

      throw new UnauthorizedError('Invalid or revoked API Key');
    }

    // 2. Bearer Session Token Authentication
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      if (!token) {
        throw new UnauthorizedError('Malformed Authorization token');
      }

      try {
        // Validate session token structure
        const decoded = JSON.parse(Buffer.from(token, 'base64url').toString('utf8'));
        if (!decoded.id || !decoded.username || !decoded.role || !decoded.sig) {
          throw new UnauthorizedError('Invalid token format');
        }

        // Verify token signature with constant time compare
        const payloadStr = `${decoded.id}:${decoded.username}:${decoded.role}:${decoded.exp}`;
        if (Date.now() > decoded.exp) {
          throw new UnauthorizedError('Session expired. Please log in again.');
        }

        const expectedSig = HasherService.constantTimeCompare(
          decoded.sig,
          Buffer.from(`${payloadStr}:${env.JWT_SECRET}`).toString('base64url')
        );

        if (!expectedSig) {
          throw new UnauthorizedError('Invalid token signature');
        }

        req.user = {
          id: decoded.id,
          username: decoded.username,
          role: decoded.role,
        };
        return next();
      } catch (e) {
        if (e instanceof UnauthorizedError) throw e;
        throw new UnauthorizedError('Token decoding failed');
      }
    }

    throw new UnauthorizedError('Missing authentication credential (Bearer token or X-API-Key)');
  }

  /**
   * Enforces Role-Based Access Control (RBAC).
   */
  static requireRole(...allowedRoles: UserRole[]) {
    return (req: Request, _res: Response, next: NextFunction) => {
      if (!req.user) {
        throw new UnauthorizedError('Authentication required');
      }

      if (!allowedRoles.includes(req.user.role)) {
        throw new ForbiddenError(
          `Action requires one of the following roles: [${allowedRoles.join(', ')}]. Current role: ${req.user.role}`
        );
      }

      next();
    };
  }
}
