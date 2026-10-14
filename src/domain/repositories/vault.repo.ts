import { SecretItem } from '../models/secret.model.js';
import { User } from '../models/user.model.js';

export interface IVaultRepository {
  // Secret operations
  saveSecret(secret: SecretItem): Promise<SecretItem>;
  findSecretById(id: string): Promise<SecretItem | null>;
  findSecretByKey(keyName: string, environment?: string): Promise<SecretItem | null>;
  listSecrets(environment?: string): Promise<SecretItem[]>;
  deleteSecret(id: string): Promise<boolean>;
  recordAccess(id: string): Promise<void>;

  // User & Auth operations
  findUserByUsername(username: string): Promise<User | null>;
  findUserById(id: string): Promise<User | null>;
  saveUser(user: User): Promise<User>;
  updateUser(id: string, updates: Partial<User>): Promise<void>;
}
