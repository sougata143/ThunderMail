import { Folder } from '@prisma/client';
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
        isRead: false,
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
