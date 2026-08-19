import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { prisma } from '../server.js';

// ─── Schemas ─────────────────────────────────────────────────────
const saltSchema = z.object({
  email: z.string().email().transform((e) => e.trim().toLowerCase()),
});

const registerSchema = z.object({
  email: z.string().email().transform((e) => e.trim().toLowerCase()),
  authHash: z.string().min(32),
  salt: z.string().min(16),
  // Classical RSA-4096 Key Material
  publicKey: z.string().min(100),
  encryptedPrivateKey: z.string().min(32),
  keyIv: z.string().min(16),
  // Post-Quantum ML-KEM-768 & ML-DSA-65 Key Material (optional during transition)
  pqcPublicKey: z.string().optional(),
  encryptedPqcPrivKey: z.string().optional(),
  pqcKeyIv: z.string().optional(),
  dsaPublicKey: z.string().optional(),
  encryptedDsaPrivKey: z.string().optional(),
  dsaKeyIv: z.string().optional(),
});

const loginSchema = z.object({
  email: z.string().email().transform((e) => e.trim().toLowerCase()),
  authHash: z.string().min(32),
});

// ─── Routes ──────────────────────────────────────────────────────
export async function authRoutes(app: FastifyInstance) {
  /**
   * POST /api/auth/salt
   * Returns the PBKDF2 salt for a given email (normalized to lowercase).
   * Does NOT reveal if the email exists (returns deterministic dummy salt if not found).
   */
  app.post(
    '/salt',
    {
      config: { rateLimit: { max: 100, timeWindow: '5 minutes' } },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = saltSchema.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({ error: 'Invalid email address.' });
      }

      const email = body.data.email;
      const user = await prisma.user.findUnique({
        where: { email },
        select: { salt: true },
      });

      // Return real salt if user exists; otherwise deterministic dummy salt
      const salt = user?.salt ?? Buffer.from(`thundermail_salt_${email}`).toString('base64').padEnd(44, '=');
      return { salt };
    },
  );

  /**
   * POST /api/auth/register
   * Stores the user's public keys, encrypted private keys, salt, and auth verifier.
   * The server NEVER sees the plaintext password or the User Master Key (UMK).
   */
  app.post(
    '/register',
    {
      config: { rateLimit: { max: 20, timeWindow: '15 minutes' } },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = registerSchema.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({
          error: 'Validation failed.',
          details: body.error.flatten().fieldErrors,
        });
      }

      const {
        email,
        authHash,
        salt,
        publicKey,
        encryptedPrivateKey,
        keyIv,
        pqcPublicKey,
        encryptedPqcPrivKey,
        pqcKeyIv,
        dsaPublicKey,
        encryptedDsaPrivKey,
        dsaKeyIv,
      } = body.data;

      const existing = await prisma.user.findUnique({
        where: { email },
      });

      if (existing) {
        return reply.status(409).send({ error: 'Email address already registered.' });
      }

      const user = await prisma.user.create({
        data: {
          email,
          authHash,
          salt,
          publicKey,
          encryptedPrivateKey,
          keyIv,
          pqcPublicKey: pqcPublicKey ?? null,
          encryptedPqcPrivKey: encryptedPqcPrivKey ?? null,
          pqcKeyIv: pqcKeyIv ?? null,
          dsaPublicKey: dsaPublicKey ?? null,
          encryptedDsaPrivKey: encryptedDsaPrivKey ?? null,
          dsaKeyIv: dsaKeyIv ?? null,
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
          pqcPublicKey: user.pqcPublicKey,
          encryptedPqcPrivKey: user.encryptedPqcPrivKey,
          pqcKeyIv: user.pqcKeyIv,
          dsaPublicKey: user.dsaPublicKey,
          encryptedDsaPrivKey: user.encryptedDsaPrivKey,
          dsaKeyIv: user.dsaKeyIv,
        },
      });
    },
  );

  /**
   * POST /api/auth/login
   * Verifies the auth hash (HMAC-SHA256 derived from UMK).
   * Returns JWT + user encrypted key bundle so client can decrypt private keys in browser.
   */
  app.post(
    '/login',
    {
      config: { rateLimit: { max: 50, timeWindow: '15 minutes' } },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = loginSchema.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({ error: 'Invalid credentials format.' });
      }

      const { email, authHash } = body.data;

      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user || user.authHash !== authHash) {
        await new Promise((r) => setTimeout(r, 100));
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
          pqcPublicKey: user.pqcPublicKey,
          encryptedPqcPrivKey: user.encryptedPqcPrivKey,
          pqcKeyIv: user.pqcKeyIv,
          dsaPublicKey: user.dsaPublicKey,
          encryptedDsaPrivKey: user.encryptedDsaPrivKey,
          dsaKeyIv: user.dsaKeyIv,
        },
      };
    },
  );
}
