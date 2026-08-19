import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { prisma } from '../server.js';
import { authenticate } from '../middleware/auth.middleware.js';

export async function userRoutes(app: FastifyInstance) {
  app.addHook('preHandler', authenticate);

  /**
   * GET /api/user/me
   * Returns user profile info and storage stats.
   */
  app.get('/me', async (request: FastifyRequest, reply: FastifyReply) => {
    const { email } = request.user;

    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        publicKey: true,
        encryptedPrivateKey: true,
        keyIv: true,
        createdAt: true,
        _count: {
          select: {
            receivedMessages: true,
            sentMessages: true,
          },
        },
      },
    });

    if (!user) {
      return reply.status(404).send({ error: 'User not found.' });
    }

    // Rough storage estimate based on encrypted blob sizes
    const allMessages = await prisma.mailboxMessage.findMany({
      where: {
        OR: [{ recipientEmail: email }, { senderEmail: email }],
      },
      select: {
        encryptedBody: true,
        encryptedSubject: true,
        encryptedAttachmentsMetadata: true,
      },
    });

    const storageBytesUsed = allMessages.reduce((acc, msg) => {
      return (
        acc +
        msg.encryptedBody.length +
        msg.encryptedSubject.length +
        (msg.encryptedAttachmentsMetadata?.length ?? 0)
      );
    }, 0);

    return {
      id: user.id,
      email: user.email,
      publicKey: user.publicKey,
      encryptedPrivateKey: user.encryptedPrivateKey,
      keyIv: user.keyIv,
      createdAt: user.createdAt,
      stats: {
        totalReceived: user._count.receivedMessages,
        totalSent: user._count.sentMessages,
        storageBytesUsed,
        storageQuotaBytes: 1073741824, // 1 GB quota
      },
    };
  });
}
