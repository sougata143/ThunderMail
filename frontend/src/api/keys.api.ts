import { apiClient } from './client.ts';

export const keysApi = {
  async getPublicKey(email: string): Promise<{ email: string; publicKey: string }> {
    const res = await apiClient.get<{ email: string; publicKey: string }>(`/keys/${encodeURIComponent(email)}`);
    return res.data;
  },

  async updatePrivateKey(data: { encryptedPrivateKey: string; keyIv: string }): Promise<void> {
    await apiClient.put('/keys/private', data);
  },
};
