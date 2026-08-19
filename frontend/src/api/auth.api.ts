import { apiClient } from './client.ts';

export interface UserPayload {
  id: string;
  email: string;
  publicKey: string;
  encryptedPrivateKey: string;
  keyIv: string;
  // Post-Quantum fields
  pqcPublicKey?: string | null;
  encryptedPqcPrivKey?: string | null;
  pqcKeyIv?: string | null;
  dsaPublicKey?: string | null;
  encryptedDsaPrivKey?: string | null;
  dsaKeyIv?: string | null;
}

export interface AuthResponse {
  token: string;
  user: UserPayload;
}

export const authApi = {
  async getSalt(email: string): Promise<string> {
    const res = await apiClient.post<{ salt: string }>('/auth/salt', { email });
    return res.data.salt;
  },

  async register(data: {
    email: string;
    authHash: string;
    salt: string;
    publicKey: string;
    encryptedPrivateKey: string;
    keyIv: string;
    pqcPublicKey?: string;
    encryptedPqcPrivKey?: string;
    pqcKeyIv?: string;
    dsaPublicKey?: string;
    encryptedDsaPrivKey?: string;
    dsaKeyIv?: string;
  }): Promise<AuthResponse> {
    const res = await apiClient.post<AuthResponse>('/auth/register', data);
    return res.data;
  },

  async login(data: { email: string; authHash: string }): Promise<AuthResponse> {
    const res = await apiClient.post<AuthResponse>('/auth/login', data);
    return res.data;
  },
};
