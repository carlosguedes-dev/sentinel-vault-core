import { EncryptedPayload } from '../../core/crypto/cipher.js';

export interface SecretItem {
  id: string;
  keyName: string;
  description: string;
  payload: EncryptedPayload;
  environment: 'development' | 'staging' | 'production';
  tags: string[];
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  expiresAt?: string;
  accessCount: number;
  lastAccessedAt?: string;
}

export interface CreateSecretDTO {
  keyName: string;
  plaintextValue: string;
  description?: string;
  environment?: 'development' | 'staging' | 'production';
  tags?: string[];
  expiresAt?: string;
}

export interface SecretMetadataDTO {
  id: string;
  keyName: string;
  description: string;
  environment: string;
  tags: string[];
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  accessCount: number;
  lastAccessedAt?: string;
}
