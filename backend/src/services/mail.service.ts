import { AuthStatus, Folder, SignatureStatus } from '@prisma/client';
import { prisma } from '../server.js';

interface StoreMessageParams {
  senderEmail: string;
  recipientEmail: string;
  encryptedSessionKey: string;
  senderSessionKey: string;
  encryptedSubject: string;
  encryptedBody: string;
  subjectIv: string;
  bodyIv: string;
  encryptedAttachments?: string;
  isE2ee: boolean;
  folder?: keyof typeof Folder;
  authStatus?: AuthStatus;
  authDetails?: string | null;
  // Hybrid PQC and Signature parameters
  isPqc?: boolean;
  classicCiphertext?: string | null;
  pqcCiphertext?: string | null;
  senderClassicCt?: string | null;
  senderPqcCt?: string | null;
  senderSignature?: string | null;
  signatureStatus?: SignatureStatus;
}

export const mailService = {
  /**
   * Store an encrypted message in the database.
   * The server never sees plaintext — it stores ciphertext blobs only.
   */
  async storeInternalMessage(params: StoreMessageParams) {
    return prisma.mailboxMessage.create({
      data: {
        senderEmail: params.senderEmail,
        recipientEmail: params.recipientEmail,
        folder: (params.folder as Folder) ?? Folder.INBOX,
        encryptedSessionKey: params.encryptedSessionKey,
        senderSessionKey: params.senderSessionKey,
        encryptedSubject: params.encryptedSubject,
        encryptedBody: params.encryptedBody,
        subjectIv: params.subjectIv,
        bodyIv: params.bodyIv,
        encryptedAttachmentsMetadata: params.encryptedAttachments ?? null,
        isE2ee: params.isE2ee,
        isPqc: params.isPqc ?? false,
        classicCiphertext: params.classicCiphertext ?? null,
        pqcCiphertext: params.pqcCiphertext ?? null,
        senderClassicCt: params.senderClassicCt ?? null,
        senderPqcCt: params.senderPqcCt ?? null,
        senderSignature: params.senderSignature ?? null,
        signatureStatus: params.signatureStatus ?? SignatureStatus.UNSIGNED,
        isRead: false,
        authStatus: params.authStatus ?? AuthStatus.NONE,
        authDetails: params.authDetails ?? null,
      },
    });
  },

  /**
   * Get unread message count for a user (for badge indicator).
   */
  async getUnreadCount(email: string): Promise<number> {
    return prisma.mailboxMessage.count({
      where: {
        recipientEmail: email,
        folder: Folder.INBOX,
        isRead: false,
      },
    });
  },
};
