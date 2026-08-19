import { apiClient } from './client.ts';
import type { EncryptedMessagePayload } from '../crypto/messageCipher.ts';

export interface EnvelopeSummary {
  id: string;
  senderEmail: string;
  recipientEmail: string;
  folder: 'INBOX' | 'SENT' | 'DRAFTS' | 'TRASH' | 'SPAM';
  encryptedSubject: string;
  subjectIv: string;
  encryptedSessionKey: string;
  senderSessionKey: string;
  isRead: boolean;
  isE2ee: boolean;
  isPqc: boolean;
  authStatus: 'PASS' | 'PARTIAL' | 'FAIL' | 'NONE';
  signatureStatus: 'VERIFIED' | 'FAILED' | 'UNSIGNED';
  createdAt: string;
}

export interface FolderResponse {
  messages: EnvelopeSummary[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export interface FullMessageRecord extends EnvelopeSummary {
  encryptedBody: string;
  bodyIv: string;
  encryptedAttachmentsMetadata?: string | null;
  authDetails?: string | null;
  classicCiphertext?: string | null;
  pqcCiphertext?: string | null;
  senderClassicCt?: string | null;
  senderPqcCt?: string | null;
  senderSignature?: string | null;
}

export const mailApi = {
  async getFolder(folderName: string, page = 1, limit = 20): Promise<FolderResponse> {
    const res = await apiClient.get<FolderResponse>(`/mail/folder/${folderName}`, {
      params: { page, limit },
    });
    return res.data;
  },

  async getMail(id: string): Promise<FullMessageRecord> {
    const res = await apiClient.get<FullMessageRecord>(`/mail/${id}`);
    return res.data;
  },

  async sendMail(payload: EncryptedMessagePayload): Promise<{ messageId: string }> {
    const res = await apiClient.post<{ messageId: string }>('/mail/send', payload);
    return res.data;
  },

  async patchStatus(id: string, updates: { isRead?: boolean; folder?: string }): Promise<void> {
    await apiClient.patch(`/mail/${id}/status`, updates);
  },

  async deleteMail(id: string): Promise<void> {
    await apiClient.delete(`/mail/${id}`);
  },
};
