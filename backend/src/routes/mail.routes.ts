import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { Folder } from '@prisma/client';
import { prisma } from '../server.js';
import { authenticate } from '../middleware/auth.middleware.js';
import { mailService } from '../services/mail.service.js';
import { smtpRelayService } from '../services/smtpRelay.service.js';

// ─── Schemas ─────────────────────────────────────────────────────
// For internal E2EE sends: require real session keys
const e2eeMailSchema = z.object({
  recipientEmail: z.string().email(),
  encryptedSessionKey: z.string().min(32),
  senderSessionKey: z.string().min(32),
  encryptedSubject: z.string(),
  encryptedBody: z.string(),
  subjectIv: z.string(),
  bodyIv: z.string(),
  encryptedAttachments: z.string().optional(),
  isE2ee: z.literal(true).default(true),
  plaintextSubject: z.string().optional(),
  plaintextBody: z.string().optional(),
});

// For external relay sends: session keys are placeholder sentinels
const relayMailSchema = z.object({
  recipientEmail: z.string().email(),
  encryptedSessionKey: z.string().default('RELAY_NO_KEY'),
  senderSessionKey: z.string().default('RELAY_NO_KEY'),
  encryptedSubject: z.string(),
  encryptedBody: z.string(),
  subjectIv: z.string().default('RELAY_IV'),
  bodyIv: z.string().default('RELAY_IV'),
  encryptedAttachments: z.string().optional(),
  isE2ee: z.literal(false),
  plaintextSubject: z.string().min(1),
  plaintextBody: z.string().min(1),
});

const sendMailSchema = z.discriminatedUnion('isE2ee', [e2eeMailSchema, relayMailSchema]);


const patchStatusSchema = z.object({
  isRead: z.boolean().optional(),
  folder: z.nativeEnum(Folder).optional(),
});

const folderParam = z.enum(['INBOX', 'SENT', 'DRAFTS', 'TRASH', 'SPAM']);

// ─── Routes ──────────────────────────────────────────────────────
export async function mailRoutes(app: FastifyInstance) {
  // All mail routes require authentication
  app.addHook('preHandler', authenticate);

  /**
   * GET /api/mail/folder/:folderName
   * Returns paginated encrypted mail envelopes for the current user.
   * Encrypted blobs are returned as-is — client decrypts them.
   */
  app.get(
    '/folder/:folderName',
    async (
      request: FastifyRequest<{
        Params: { folderName: string };
        Querystring: { page?: string; limit?: string };
      }>,
      reply: FastifyReply,
    ) => {
      const folder = folderParam.safeParse(request.params.folderName.toUpperCase());
      if (!folder.success) {
        return reply.status(400).send({ error: 'Invalid folder name.' });
      }

      const page = Math.max(1, Number.parseInt(request.query.page ?? '1', 10));
      const limit = Math.min(50, Math.max(1, Number.parseInt(request.query.limit ?? '20', 10)));
      const skip = (page - 1) * limit;

      const { email } = request.user;

      // INBOX, DRAFTS, TRASH, SPAM → filter by recipientEmail
      // SENT → filter by senderEmail
      const whereClause =
        folder.data === 'SENT'
          ? { senderEmail: email, folder: folder.data }
          : { recipientEmail: email, folder: folder.data };

      const [messages, total] = await Promise.all([
        prisma.mailboxMessage.findMany({
          where: whereClause,
          orderBy: { createdAt: 'desc' },
          skip,
          take: limit,
          select: {
            id: true,
            senderEmail: true,
            recipientEmail: true,
            folder: true,
            encryptedSubject: true,
            subjectIv: true,
            encryptedSessionKey: true,
            senderSessionKey: true,
            isRead: true,
            isE2ee: true,
            createdAt: true,
          },
        }),
        prisma.mailboxMessage.count({ where: whereClause }),
      ]);

      return {
        messages,
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit),
        },
      };
    },
  );

  /**
   * GET /api/mail/:id
   * Returns the full encrypted message blob for decryption.
   */
  app.get(
    '/:id',
    async (
      request: FastifyRequest<{ Params: { id: string } }>,
      reply: FastifyReply,
    ) => {
      const { email } = request.user;
      const message = await prisma.mailboxMessage.findFirst({
        where: {
          id: request.params.id,
          OR: [{ recipientEmail: email }, { senderEmail: email }],
        },
      });

      if (!message) {
        return reply.status(404).send({ error: 'Message not found.' });
      }

      return message;
    },
  );

  /**
   * POST /api/mail/send
   * Stores the encrypted message for the recipient.
   * For E2EE: stores ciphertext blobs only.
   * For external: triggers SMTP relay with plaintext.
   */
  app.post('/send', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = sendMailSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({
        error: 'Validation failed.',
        details: body.error.flatten().fieldErrors,
      });
    }

    const { email: senderEmail } = request.user;
    const data = body.data;

    // Check if recipient exists on this server
    const recipient = await prisma.user.findUnique({
      where: { email: data.recipientEmail },
      select: { publicKey: true, email: true },
    });

    let inboxMessage = null;

    if (recipient) {
      // ── Internal E2EE message ──
      inboxMessage = await mailService.storeInternalMessage({
        senderEmail,
        recipientEmail: data.recipientEmail,
        encryptedSessionKey: data.encryptedSessionKey,
        senderSessionKey: data.senderSessionKey,
        encryptedSubject: data.encryptedSubject,
        encryptedBody: data.encryptedBody,
        subjectIv: data.subjectIv,
        bodyIv: data.bodyIv,
        encryptedAttachments: data.encryptedAttachments,
        isE2ee: true,
      });
    } else {
      // ── External SMTP relay ──
      if (!data.plaintextSubject || !data.plaintextBody) {
        return reply.status(422).send({
          error: 'Plaintext subject and body required for external recipients.',
        });
      }

      await smtpRelayService.sendExternal({
        from: senderEmail,
        to: data.recipientEmail,
        subject: data.plaintextSubject,
        body: data.plaintextBody,
      });
    }

    // Store a SENT copy for the sender only for internal E2EE messages.
    // For external relay we skip DB storage to avoid persisting plaintext sentinel values.
    if (recipient) {
      await mailService.storeInternalMessage({
        senderEmail,
        recipientEmail: senderEmail,
        encryptedSessionKey: data.senderSessionKey,
        senderSessionKey: data.senderSessionKey,
        encryptedSubject: data.encryptedSubject,
        encryptedBody: data.encryptedBody,
        subjectIv: data.subjectIv,
        bodyIv: data.bodyIv,
        encryptedAttachments: data.encryptedAttachments,
        isE2ee: true,
        folder: 'SENT',
      });
    }

    return reply.status(201).send({
      message: 'Message sent successfully.',
      messageId: inboxMessage?.id,
    });
  });

  /**
   * PATCH /api/mail/:id/status
   * Mark as read or move to a folder.
   */
  app.patch(
    '/:id/status',
    async (
      request: FastifyRequest<{ Params: { id: string } }>,
      reply: FastifyReply,
    ) => {
      const body = patchStatusSchema.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({ error: 'Invalid status update.' });
      }

      const { email } = request.user;
      const message = await prisma.mailboxMessage.findFirst({
        where: {
          id: request.params.id,
          OR: [{ recipientEmail: email }, { senderEmail: email }],
        },
      });

      if (!message) {
        return reply.status(404).send({ error: 'Message not found.' });
      }

      const updated = await prisma.mailboxMessage.update({
        where: { id: request.params.id },
        data: {
          ...(body.data.isRead !== undefined ? { isRead: body.data.isRead } : {}),
          ...(body.data.folder !== undefined ? { folder: body.data.folder } : {}),
        },
      });

      return { message: 'Status updated.', data: updated };
    },
  );

  /**
   * DELETE /api/mail/:id
   * Permanently delete a message.
   */
  app.delete(
    '/:id',
    async (
      request: FastifyRequest<{ Params: { id: string } }>,
      reply: FastifyReply,
    ) => {
      const { email } = request.user;
      const message = await prisma.mailboxMessage.findFirst({
        where: {
          id: request.params.id,
          OR: [{ recipientEmail: email }, { senderEmail: email }],
        },
      });

      if (!message) {
        return reply.status(404).send({ error: 'Message not found.' });
      }

      await prisma.mailboxMessage.delete({ where: { id: request.params.id } });
      return reply.status(200).send({ message: 'Message deleted.' });
    },
  );
}
