import Fastify from 'fastify';
import cors from '@fastify/cors';
import jwt from '@fastify/jwt';
import rateLimit from '@fastify/rate-limit';
import { env } from './config/env.js';
import { authRoutes } from './routes/auth.routes.js';
import { keysRoutes } from './routes/keys.routes.js';
import { mailRoutes } from './routes/mail.routes.js';
import { inboundRoutes } from './routes/inbound.routes.js';
import { userRoutes } from './routes/user.routes.js';
import { PrismaClient } from '@prisma/client';

export const prisma = new PrismaClient({
  log: env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
});

export const buildApp = async () => {
  const app = Fastify({
    logger: {
      level: env.NODE_ENV === 'production' ? 'warn' : 'info',
      transport:
        env.NODE_ENV === 'development'
          ? { target: 'pino-pretty', options: { colorize: true } }
          : undefined,
    },
  });

  // ─── Plugins ─────────────────────────────────────────────────────
  await app.register(cors, {
    origin: env.CORS_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  });

  await app.register(jwt, {
    secret: env.JWT_SECRET,
    sign: { expiresIn: env.JWT_EXPIRES_IN },
  });

  await app.register(rateLimit, {
    global: true,
    max: 200,
    timeWindow: '1 minute',
    errorResponseBuilder: () => ({
      statusCode: 429,
      error: 'Too Many Requests',
      message: 'Rate limit exceeded. Please try again later.',
    }),
  });

  // ─── Routes ──────────────────────────────────────────────────────
  await app.register(authRoutes, { prefix: '/api/auth' });
  await app.register(keysRoutes, { prefix: '/api/keys' });
  await app.register(mailRoutes, { prefix: '/api/mail' });
  await app.register(inboundRoutes, { prefix: '/api/mail/inbound' });
  await app.register(userRoutes, { prefix: '/api/user' });

  // ─── Health check ─────────────────────────────────────────────
  app.get('/api/health', async () => ({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'thundermail-backend',
  }));

  // ─── Shutdown hooks ───────────────────────────────────────────
  app.addHook('onClose', async () => {
    await prisma.$disconnect();
  });

  return app;
};

// ─── Start with top-level await ──────────────────────────────────
if (env.NODE_ENV !== 'test') {
  try {
    const app = await buildApp();
    await app.listen({ port: env.PORT, host: '0.0.0.0' });
    console.log(`🚀 ThunderMail backend running on port ${env.PORT}`);
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

