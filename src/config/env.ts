import dotenv from 'dotenv';
import { z } from 'zod';

// Load environment variables from .env file
dotenv.config();

const envSchema = z.object({
  PORT: z.coerce.number().default(4000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  MASTER_ENCRYPTION_KEY: z
    .string()
    .length(64, 'MASTER_ENCRYPTION_KEY must be exactly 64 hexadecimal characters (32 bytes for AES-256-GCM)')
    .regex(/^[0-9a-fA-F]+$/, 'MASTER_ENCRYPTION_KEY must be a valid hex string')
    .refine(
      (val) => !val.includes('your_64_character') && !val.includes('00000000'),
      'Cannot use placeholder or insecure MASTER_ENCRYPTION_KEY in configuration'
    ),
  JWT_SECRET: z
    .string()
    .min(32, 'JWT_SECRET must be at least 32 characters long for high cryptographic entropy')
    .refine(
      (val) => !val.toLowerCase().includes('change-in-production') && !val.includes('your_super_secure'),
      'Insecure default JWT_SECRET detected. Application refuses to start with default fallback secret.'
    ),
  ALLOWED_ORIGINS: z
    .string()
    .default('http://localhost:4000,http://127.0.0.1:4000')
    .transform((val) => val.split(',').map((o) => o.trim())),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().default(60000),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().default(100),
  AUTH_RATE_LIMIT_MAX_REQUESTS: z.coerce.number().default(10),
});

const parseEnv = () => {
  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    console.error('\n🛑 [FATAL CONFIGURATION ERROR] Environment validation failed:');
    result.error.issues.forEach((issue) => {
      console.error(`  ✖ [${issue.path.join('.')}] ${issue.message}`);
    });
    console.error('\nPlease update your .env file according to .env.example.\n');
    process.exit(1);
  }

  return result.data;
};

export const env = parseEnv();
