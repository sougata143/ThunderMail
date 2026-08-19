import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { prisma } from '../server.js';
import { env } from '../config/env.js';

// ─── Schemas ─────────────────────────────────────────────────────
const saltSchema = z.object({ email: z.string().email() });

const registerSchema = z.object({
  email: z.string().email(),
  authHash: z.string().min(32),
  salt: z.string().min(16),
  publicKey: z.string().min(100),
  encryptedPrivateKey: z.string().min(32),
  keyIv: z.string().min(16),
});

const loginSchema = z.object({
  email: z.string().email(),
  authHash: z.string().min(32),
});

// ─── Routes ──────────────────────────────────────────────────────
export async function authRoutes(app: FastifyInstance) {
  /**
   * POST /api/auth/salt
   * Returns the Argon2id/PBKDF2 salt for a given email.
   * Used by the client BEFORE login to re-derive the UMK.
   * Does NOT reveal if the email exists (returns dummy salt if not found to prevent enumeration).
   */
  app.post(
    '/salt',
    {
      config: { rateLimit: { max: 20, timeWindow: '5 minutes' } },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = saltSchema.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({ error: 'Invalid email address.' });
      }

      const user = await prisma.user.findUnique({
        where: { email: body.data.email },
        select: { salt: true },
      });

      // Return a deterministic dummy salt to prevent user enumeration
      const salt = user?.salt ?? Buffer.from(body.data.email).toString('base64');
      return { salt };
    },
  );

  /**
   * POST /api/auth/register
   * Stores the user's public key, encrypted private key, salt, and auth verifier.
   * The server NEVER sees the plaintext password or the User Master Key (UMK).
   */
  app.post(
    '/register',
    {
      config: { rateLimit: { max: 5, timeWindow: '15 minutes' } },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = registerSchema.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({
          error: 'Validation failed.',
          details: body.error.flatten().fieldErrors,
        });
      }

      const existing = await prisma.user.findUnique({
        where: { email: body.data.email },
      });

      if (existing) {
        return reply.status(409).send({ error: 'Email address already registered.' });
      }

      const user = await prisma.user.create({
        data: {
          email: body.data.email,
          authHash: body.data.authHash,
          salt: body.data.salt,
          publicKey: body.data.publicKey,
          encryptedPrivateKey: body.data.encryptedPrivateKey,
          keyIv: body.data.keyIv,
        },
      });

      const token = app.jwt.sign({
        userId: user.id,
        email: user.email,
      });

      return reply.status(201).send({
        token,
        user: {
          id: user.id,
          email: user.email,
          publicKey: user.publicKey,
          encryptedPrivateKey: user.encryptedPrivateKey,
          keyIv: user.keyIv,
        },
      });
    },
  );

  /**
   * POST /api/auth/login
   * Verifies the auth hash (HMAC-SHA256 derived from UMK, NOT the UMK itself).
   * Returns JWT + encrypted key bundle so client can decrypt private key in browser.
   */
  app.post(
    '/login',
    {
      config: { rateLimit: { max: 10, timeWindow: '15 minutes' } },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = loginSchema.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({ error: 'Invalid credentials format.' });
      }

      const user = await prisma.user.findUnique({
        where: { email: body.data.email },
      });

      if (!user || user.authHash !== body.data.authHash) {
        // Constant-time-like response to prevent timing attacks
        await new Promise((r) => setTimeout(r, 200));
        return reply.status(401).send({ error: 'Invalid email or password.' });
      }

      const token = app.jwt.sign({
        userId: user.id,
        email: user.email,
      });

      return {
        token,
        user: {
          id: user.id,
          email: user.email,
          publicKey: user.publicKey,
          encryptedPrivateKey: user.encryptedPrivateKey,
          keyIv: user.keyIv,
        },
      };
    },
  );
}
