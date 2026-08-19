# ─── Build stage ───────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app

RUN apk add --no-cache openssl libc6-compat

# Install dependencies with --ignore-scripts to prevent arbitrary script execution
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts

# Explicit allowlist of source and configuration files
COPY tsconfig.json ./
COPY prisma ./prisma/
COPY src ./src/

# Use pinned local Prisma CLI binary from package-lock.json to generate Prisma Client
RUN ./node_modules/.bin/prisma generate
RUN npm run build

# ─── Runner stage ───────────────────────────────────────────────
FROM node:20-alpine AS runner
WORKDIR /app

RUN apk add --no-cache openssl libc6-compat

ENV NODE_ENV=production

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --ignore-scripts

# Copy built artifacts and Prisma engine from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder /app/node_modules/@prisma ./node_modules/@prisma
COPY --from=builder /app/node_modules/prisma ./node_modules/prisma
COPY --from=builder /app/node_modules/.bin ./node_modules/.bin
COPY prisma ./prisma/

# Set non-root ownership and switch to unprivileged node user
RUN chown -R node:node /app
USER node

# Push database schema on startup and launch server
CMD ["sh", "-c", "./node_modules/.bin/prisma db push --skip-generate && node dist/server.js"]

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD wget -qO- http://localhost:3001/api/health || exit 1
