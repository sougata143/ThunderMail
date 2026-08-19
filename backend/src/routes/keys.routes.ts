import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { prisma } from '../server.js';
import { authenticate } from '../middleware/auth.middleware.js';

const updatePrivateKeySchema = z.object({
  encryptedPrivateKey: z.string().min(32),
  keyIv: z.string().min(16),
});

export async function keysRoutes(app: FastifyInstance) {
  /**
   * GET /api/keys/:email
   * Returns the RSA public key for any email address.
   * Used by composer to encrypt session key for recipient.
   * Public key is — by definition — not secret.
   */
  app.get(
    '/:email',
    async (request: FastifyRequest<{ Params: { email: string } }>, reply: FastifyReply) => {
      const { email } = request.params;

      if (!email || !email.includes('@')) {
        return reply.status(400).send({ error: 'Invalid email address.' });
      }

      const user = await prisma.user.findUnique({
        where: { email },
        select: { publicKey: true, email: true },
      });

      if (!user) {
        return reply.status(404).send({ error: 'User not found on this server.' });
      }

      return { email: user.email, publicKey: user.publicKey };
    },
  );

  /**
   * PUT /api/keys/private
   * Key rotation: update the encrypted private key blob.
   * Client re-encrypts private key with new UMK after password change.
   */
  app.put(
    '/private',
    { preHandler: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = updatePrivateKeySchema.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({
          error: 'Validation failed.',
          details: body.error.flatten().fieldErrors,
        });
      }

      const { email } = request.user;

      await prisma.user.update({
        where: { email },
        data: {
          encryptedPrivateKey: body.data.encryptedPrivateKey,
          keyIv: body.data.keyIv,
        },
      });

      return { message: 'Private key updated successfully.' };
    },
  );
}
