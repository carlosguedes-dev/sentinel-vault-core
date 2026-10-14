import { IVaultRepository } from '../../domain/repositories/vault.repo.js';
import { SecretItem } from '../../domain/models/secret.model.js';
import { User } from '../../domain/models/user.model.js';
import { HasherService } from '../../core/crypto/hasher.js';
import { TokenService } from '../../core/crypto/tokens.js';

/**
 * High-performance, isolated Vault Repository implementation.
 * Encapsulates state in a secure in-memory store.
 */
export class MemoryVaultRepository implements IVaultRepository {
  private secrets = new Map<string, SecretItem>();
  private users = new Map<string, User>();
  private initialized = false;

  constructor() {
    this.bootstrapAdmin();
  }

  private async bootstrapAdmin(): Promise<void> {
    if (this.initialized) return;

    // Creates an initial admin user with secure scrypt hash
    const adminId = TokenService.generateId();
    const initialPassword = 'SentinelAdmin#2026';
    const passwordHash = await HasherService.hash(initialPassword);

    const initialApiKey = TokenService.generateApiKey('sk_admin');
    const apiKeyHash = await HasherService.hash(initialApiKey);

    const admin: User = {
      id: adminId,
      username: 'sentinel.admin',
      passwordHash,
      role: 'ADMIN',
      apiKeyHash,
      createdAt: new Date().toISOString(),
      failedLoginAttempts: 0,
    };

    this.users.set(admin.id, admin);
    this.initialized = true;

    // Log initialization credentials for local setup (displayed only once safely)
    if (process.env.NODE_ENV !== 'test') {
      console.log('🛡️ [SENTINEL BOOTSTRAP] Initial Admin Created:');
      console.log(`   Username: ${admin.username}`);
      console.log(`   Initial Password: ${initialPassword}`);
      console.log(`   Admin API Key: ${initialApiKey}`);
      console.log('   (Please rotate admin password on initial login)\n');
    }
  }

  async saveSecret(secret: SecretItem): Promise<SecretItem> {
    this.secrets.set(secret.id, { ...secret });
    return secret;
  }

  async findSecretById(id: string): Promise<SecretItem | null> {
    const item = this.secrets.get(id);
    return item ? { ...item } : null;
  }

  async findSecretByKey(keyName: string, environment?: string): Promise<SecretItem | null> {
    for (const secret of this.secrets.values()) {
      if (secret.keyName.toLowerCase() === keyName.toLowerCase()) {
        if (!environment || secret.environment === environment) {
          return { ...secret };
        }
      }
    }
    return null;
  }

  async listSecrets(environment?: string): Promise<SecretItem[]> {
    const list: SecretItem[] = [];
    for (const secret of this.secrets.values()) {
      if (!environment || secret.environment === environment) {
        list.push({ ...secret });
      }
    }
    return list.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async deleteSecret(id: string): Promise<boolean> {
    return this.secrets.delete(id);
  }

  async recordAccess(id: string): Promise<void> {
    const item = this.secrets.get(id);
    if (item) {
      item.accessCount += 1;
      item.lastAccessedAt = new Date().toISOString();
      this.secrets.set(id, item);
    }
  }

  async findUserByUsername(username: string): Promise<User | null> {
    for (const user of this.users.values()) {
      if (user.username.toLowerCase() === username.toLowerCase()) {
        return { ...user };
      }
    }
    return null;
  }

  async findUserById(id: string): Promise<User | null> {
    const user = this.users.get(id);
    return user ? { ...user } : null;
  }

  async saveUser(user: User): Promise<User> {
    this.users.set(user.id, { ...user });
    return user;
  }

  async updateUser(id: string, updates: Partial<User>): Promise<void> {
    const user = this.users.get(id);
    if (user) {
      this.users.set(id, { ...user, ...updates });
    }
  }
}

// Global Singleton Repository
export const vaultRepository = new MemoryVaultRepository();
