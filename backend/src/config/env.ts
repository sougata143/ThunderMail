import { z } from 'zod';

const envSchema = z.object({
  DATABASE_URL: z.string().url().default(process.env.DATABASE_URL || 'postgresql://thundermail:change_me_strong_password_here@localhost:5433/thundermail'),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters').default(process.env.JWT_SECRET || 'test_jwt_secret_must_be_at_least_32_characters_long_12345'),
  JWT_EXPIRES_IN: z.string().default('7d'),
  APP_DOMAIN: z.string().default(process.env.APP_DOMAIN || 'thundermail.sougatatech.com'),
  SMTP_HOST: z.string().default(''),
  SMTP_PORT: z.coerce.number().default(587),
  SMTP_USER: z.string().default(''),
  SMTP_PASS: z.string().default(''),
  SMTP_FROM: z.string().email().default(process.env.SMTP_FROM || 'noreply@thundermail.sougatatech.com'),
  DOMAIN: z.string().default(process.env.DOMAIN || 'thundermail.sougatatech.com'),
  CORS_ORIGIN: z.string().default('http://localhost:5173'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(3001),
  // Inbound email auth
  INBOUND_PROVIDER: z.enum(['webhook', 'smtp']).default('webhook'),
  INBOUND_WEBHOOK_SECRET: z.string().optional(),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('❌ Invalid environment variables:');
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const env = parsed.data;
process.env.DATABASE_URL = env.DATABASE_URL;
process.env.JWT_SECRET = env.JWT_SECRET;
export type Env = typeof env;
