import { Request, Response } from 'express';
import os from 'node:os';
import { env } from '../../config/env.js';

export class HealthController {
  static getHealth(_req: Request, res: Response): void {
    const memory = process.memoryUsage();

    res.json({
      status: 'HEALTHY',
      service: 'sentinel-vault-core',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor(process.uptime()),
      telemetry: {
        environment: env.NODE_ENV,
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        cpuCount: os.cpus().length,
        memoryUsageMB: {
          heapUsed: Math.round(memory.heapUsed / 1024 / 1024),
          heapTotal: Math.round(memory.heapTotal / 1024 / 1024),
          rss: Math.round(memory.rss / 1024 / 1024),
        },
      },
      securityEngine: {
        cipherAlgorithm: 'AES-256-GCM',
        keyDerivation: 'scrypt',
        csprngStatus: 'ACTIVE',
        rateLimiterStatus: 'ACTIVE',
        strictCsp: 'ENABLED',
        timingSafeEqual: 'ENABLED',
      },
    });
  }
}
