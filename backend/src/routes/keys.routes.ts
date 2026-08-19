import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { prisma } from '../server.js';
import { authenticate } from '../middleware/auth.middleware.js';

const updatePrivateKeySchema = z.object({
  encryptedPrivateKey: z.string().min(32),
  keyIv: z.string().min(16),
  encryptedPqcPrivKey: z.string().optional(),
  pqcKeyIv: z.string().optional(),
  encryptedDsaPrivKey: z.string().optional(),
  dsaKeyIv: z.string().optional(),
});

const upgradePqcSchema = z.object({
  pqcPublicKey: z.string().min(32),
  encryptedPqcPrivKey: z.string().min(32),
  pqcKeyIv: z.string().min(16),
  dsaPublicKey: z.string().min(32),
  encryptedDsaPrivKey: z.string().min(32),
  dsaKeyIv: z.string().min(16),
});

export async function keysRoutes(app: FastifyInstance) {
  /**
   * GET /api/keys/:email
   * Returns the RSA and PQC public keys for any email address.
   * Used by composer to perform Hybrid KEM encapsulation for recipient.
   * Public keys are — by definition — not secret.
   */
  app.get(
    '/:email',
    async (request: FastifyRequest<{ Params: { email: string } }>, reply: FastifyReply) => {
      const { email } = request.params;

      if (!email?.includes('@')) {
        return reply.status(400).send({ error: 'Invalid email address.' });
      }

      const user = await prisma.user.findUnique({
        where: { email },
        select: {
          publicKey: true,
          pqcPublicKey: true,
          dsaPublicKey: true,
          email: true,
        },
      });

      if (!user) {
        return reply.status(404).send({ error: 'User not found on this server.' });
      }

      return {
        email: user.email,
        publicKey: user.publicKey,
        pqcPublicKey: user.pqcPublicKey,
        dsaPublicKey: user.dsaPublicKey,
      };
    },
  );

  /**
   * POST /api/keys/upgrade-pqc
   * Lazy PQC Key Upgrade:
   * Called by the client when an existing pre-PQC user logs in,
   * securely attaching newly generated ML-KEM-768 and ML-DSA-65 key material.
   */
  app.post(
    '/upgrade-pqc',
    { preHandler: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = upgradePqcSchema.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({
          error: 'Validation failed.',
          details: body.error.flatten().fieldErrors,
        });
      }

      const { email } = request.user;
      const updated = await prisma.user.update({
        where: { email },
        data: {
          pqcPublicKey: body.data.pqcPublicKey,
          encryptedPqcPrivKey: body.data.encryptedPqcPrivKey,
          pqcKeyIv: body.data.pqcKeyIv,
          dsaPublicKey: body.data.dsaPublicKey,
          encryptedDsaPrivKey: body.data.encryptedDsaPrivKey,
          dsaKeyIv: body.data.dsaKeyIv,
        },
      });

      return {
        message: 'Post-Quantum keys provisioned successfully.',
        pqcPublicKey: updated.pqcPublicKey,
        dsaPublicKey: updated.dsaPublicKey,
      };
    },
  );

  /**
   * PUT /api/keys/private
   * Key rotation: update the encrypted private key blobs.
   * Client re-encrypts private keys with new UMK after password change.
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
          ...(body.data.encryptedPqcPrivKey ? { encryptedPqcPrivKey: body.data.encryptedPqcPrivKey } : {}),
          ...(body.data.pqcKeyIv ? { pqcKeyIv: body.data.pqcKeyIv } : {}),
          ...(body.data.encryptedDsaPrivKey ? { encryptedDsaPrivKey: body.data.encryptedDsaPrivKey } : {}),
          ...(body.data.dsaKeyIv ? { dsaKeyIv: body.data.dsaKeyIv } : {}),
        },
      });

      return { message: 'Private keys updated successfully.' };
    },
  );
}
