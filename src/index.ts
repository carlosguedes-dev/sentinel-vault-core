import { createApp } from './server.js';
import { env } from './config/env.js';

const app = createApp();

const server = app.listen(env.PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   🛡️  SENTINEL VAULT CORE // PRODUCTION SECURITY ENGINE        ║
║   Zero-Trust Cryptographic Secret Manager & HUD Telemetry      ║
║   Architected for: carlosguedes-dev                            ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
  ⚡ Status: ONLINE & HARDENED
  🌐 Server URL: http://localhost:${env.PORT}
  📡 API Base:   http://localhost:${env.PORT}/api/v1
  📊 HUD UI:     http://localhost:${env.PORT}
  🔒 Encryption: AES-256-GCM (Authenticated AEAD)
  🔑 KDF/Hasher: scrypt (with unique CSPRNG salts)
  🛡️ CSP & CORS: Strict Whitelist (No unsafe-eval)
  ⚙️ Environment: ${env.NODE_ENV.toUpperCase()}
`);
});

// Graceful Shutdown Handler
const shutdown = (signal: string) => {
  console.log(`\n🛑 [${signal}] Initiating graceful shutdown...`);
  server.close(() => {
    console.log('✅ Server connections closed. Process terminating safely.');
    process.exit(0);
  });

  // Force shutdown after 10 seconds timeout
  setTimeout(() => {
    console.error('⚠️ Could not close connections in time, forcefully shutting down.');
    process.exit(1);
  }, 10000).unref();
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  console.error('💥 Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('💥 Unhandled Rejection:', reason);
});
