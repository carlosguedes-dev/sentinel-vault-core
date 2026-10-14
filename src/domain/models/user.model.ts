export type UserRole = 'ADMIN' | 'OPERATOR' | 'AUDITOR';

export interface User {
  id: string;
  username: string;
  passwordHash: string;
  role: UserRole;
  apiKeyHash: string;
  createdAt: string;
  lastLoginAt?: string;
  failedLoginAttempts: number;
  lockedUntil?: string;
}

export interface UserSession {
  id: string;
  username: string;
  role: UserRole;
}
