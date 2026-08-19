import { apiClient } from './client.ts';

export interface PublicKeyInfo {
  email: string;
  publicKey: string;
  pqcPublicKey?: string | null;
  dsaPublicKey?: string | null;
}

export const keysApi = {
  async getPublicKey(email: string): Promise<PublicKeyInfo> {
    const res = await apiClient.get<PublicKeyInfo>(`/keys/${encodeURIComponent(email)}`);
    return res.data;
  },

  async upgradePqc(data: {
    pqcPublicKey: string;
    encryptedPqcPrivKey: string;
    pqcKeyIv: string;
    dsaPublicKey: string;
    encryptedDsaPrivKey: string;
    dsaKeyIv: string;
  }): Promise<{ message: string; pqcPublicKey: string; dsaPublicKey: string }> {
    const res = await apiClient.post<{ message: string; pqcPublicKey: string; dsaPublicKey: string }>(
      '/keys/upgrade-pqc',
      data
    );
    return res.data;
  },

  async updatePrivateKey(data: {
    encryptedPrivateKey: string;
    keyIv: string;
    encryptedPqcPrivKey?: string;
    pqcKeyIv?: string;
    encryptedDsaPrivKey?: string;
    dsaKeyIv?: string;
  }): Promise<void> {
    await apiClient.put('/keys/private', data);
  },
};
