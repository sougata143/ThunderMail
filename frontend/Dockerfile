# ─── Build stage ───────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app

# Install dependencies with --ignore-scripts to prevent arbitrary script execution
COPY package.json package-lock.json ./
RUN npm ci --legacy-peer-deps --ignore-scripts

# Explicit allowlist of source and config files (replaces insecure glob `COPY . ./`)
COPY index.html vite.config.ts tsconfig.json tailwind.config.ts postcss.config.js ./
COPY src ./src/

RUN npm run build

# ─── Runner stage (Nginx non-root) ─────────────────────────────
FROM nginx:alpine AS runner

# Create required pid, cache, and log paths with non-root ownership
RUN touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid /var/cache/nginx /var/log/nginx /etc/nginx/conf.d

# Copy static web assets as root-owned read-only (unprivileged nginx cannot modify them)
COPY --from=builder --chown=root:root /app/dist /usr/share/nginx/html

# Set permissions and generate nginx configuration in a single chained layer
RUN chmod -R 755 /usr/share/nginx/html && \
    printf 'server {\n\
    listen 8080;\n\
    server_name localhost;\n\
\n\
    location / {\n\
        root /usr/share/nginx/html;\n\
        index index.html index.htm;\n\
        try_files $uri $uri/ /index.html;\n\
    }\n\
\n\
    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {\n\
        root /usr/share/nginx/html;\n\
        expires 1y;\n\
        add_header Cache-Control "public, immutable";\n\
    }\n\
}\n' > /etc/nginx/conf.d/default.conf

# Switch to unprivileged non-root user
USER nginx

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
