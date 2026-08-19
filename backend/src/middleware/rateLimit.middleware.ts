import type { FastifyInstance } from 'fastify';

/**
 * Rate limit configuration for auth routes (stricter limits).
 * Applied to /api/auth/* to prevent brute-force attacks.
 */
export const authRateLimitConfig = {
  max: 10,
  timeWindow: '15 minutes',
  errorResponseBuilder: () => ({
    statusCode: 429,
    error: 'Too Many Requests',
    message: 'Too many auth attempts. Please wait 15 minutes.',
  }),
};

/**
 * Register tighter rate limits on auth routes.
 */
export async function registerAuthRateLimit(app: FastifyInstance) {
  await app.register(
    async (authApp) => {
      authApp.addHook('onRequest', async (request, reply) => {
        const rateLimit = authApp.rateLimit;
        if (rateLimit) {
          await rateLimit({
            max: authRateLimitConfig.max,
            timeWindow: authRateLimitConfig.timeWindow,
          } as Parameters<typeof rateLimit>[0]);
        }
      });
    },
    { prefix: '/api/auth' },
  );
}
