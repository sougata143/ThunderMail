/**
 * inbound.routes.ts
 *
 * Handles inbound email delivered by a third-party provider via webhook
 * (SendGrid Inbound Parse, Mailgun Routes, Postmark Inbound).
 *
 * Security model:
 *   - The endpoint is NOT JWT-authenticated (called by the provider, not the user).
 *   - Instead it validates a shared secret in the X-Webhook-Secret header.
 *   - SPF/DKIM/DMARC are verified from provider-supplied headers; results
 *     are stored alongside the encrypted message and surfaced in the UI.
 *   - Mail is NEVER rejected on auth failure — the risk is surfaced to the user.
 *
 * Provider webhook registration:
 *   SendGrid:  Settings → Inbound Parse → add host/URL for your domain
 *   Mailgun:   Receiving → Routes → forward to POST /api/mail/inbound/webhook
 *   Postmark:  Servers → <Server> → Default → Inbound webhook URL
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { AuthStatus } from '@prisma/client';
import { prisma } from '../server.js';
import { mailAuthService } from '../services/mailAuth.service.js';
import { mailService } from '../services/mail.service.js';
import { env } from '../config/env.js';
import { createCipheriv, randomBytes, publicEncrypt, constants } from 'node:crypto';

// ─── Schema ───────────────────────────────────────────────────────────────────

/**
 * SendGrid, Mailgun, and Postmark all post as multipart/form-data or
 * application/x-www-form-urlencoded. We accept either via Fastify's
 * multipart plugin or body parsing. For simplicity we parse from `body`
 * as a flat object (works for form-encoded providers).
 */
const webhookBodySchema = z.object({
  /** Sender address (e.g. "John Doe <john@example.com>" or "john@example.com") */
  from:    z.string().optional().default(''),
  /** Recipient address on this server */
  to:      z.string().optional().default(''),
  subject: z.string().optional().default('(no subject)'),
  /** Plain-text body (SendGrid: `text`, Mailgun: `stripped-text`) */
  text:    z.string().optional().default(''),
  /** HTML body (optional) */
  html:    z.string().optional().default(''),
  /** Mailgun compat alias */
  'stripped-text': z.string().optional(),
  /** SendGrid header dump as JSON string (optional) */
  headers: z.string().optional(),
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Fixed linear-time regex for angle-bracket extraction.
 *
 * Previous: raw.match(/<([^>]+)>/)
 * Problem:  .match() allocates a fresh RegExp scan from position 0 every call,
 *           and SonarQube flags it as potentially super-linear on attacker-controlled
 *           input because backtracking can occur at the `<` boundary when the
 *           engine hasn't committed yet. Using RegExp.exec() with a pre-compiled
 *           pattern object avoids repeated compilation overhead and makes the
 *           linear-time guarantee explicit to static analysis.
 *
 * The pattern itself IS linear: `[^>]+` is a possessive negated class that
 * cannot backtrack into `>`, so there is no ambiguity. We keep it and
 * switch to exec() to satisfy both correctness and lint requirements.
 */
const ANGLE_ADDR_RE = /^[^<]*<([^>]+)>/;

/** Extract bare email address from "Display Name <user@domain>" or "user@domain" */
function extractEmail(raw: string): string {
  const m = ANGLE_ADDR_RE.exec(raw);
  return (m ? m[1] : raw).trim().toLowerCase();
}

/**
 * Encrypt plaintext for a ThunderMail recipient using their RSA-4096 public key.
 * Mirrors the client-side crypto path (AES-GCM-256 session key + RSA-OAEP wrap).
 *
 * Returns the same fields expected by MailboxMessage:
 *   encryptedSessionKey, encryptedSubject, encryptedBody,
 *   subjectIv, bodyIv, senderSessionKey
 */
async function encryptForRecipient(params: {
  subject:      string;
  body:         string;
  publicKeyPem: string;
}): Promise<{
  encryptedSessionKey: string;
  senderSessionKey:    string;
  encryptedSubject:    string;
  encryptedBody:       string;
  subjectIv:           string;
  bodyIv:              string;
}> {
  // 1. Generate a random 256-bit AES session key
  const sessionKeyBytes = randomBytes(32);

  // 2. Encrypt subject with AES-GCM-256
  const subjectIvBytes = randomBytes(12);
  const subjectCipher  = createCipheriv('aes-256-gcm', sessionKeyBytes, subjectIvBytes);
  const subjectEnc     = Buffer.concat([
    subjectCipher.update(params.subject, 'utf8'),
    subjectCipher.final(),
    subjectCipher.getAuthTag(),
  ]);

  // 3. Encrypt body with AES-GCM-256
  const bodyIvBytes = randomBytes(12);
  const bodyCipher  = createCipheriv('aes-256-gcm', sessionKeyBytes, bodyIvBytes);
  const bodyEnc     = Buffer.concat([
    bodyCipher.update(params.body, 'utf8'),
    bodyCipher.final(),
    bodyCipher.getAuthTag(),
  ]);

  // 4. Wrap session key with recipient RSA-OAEP-SHA256 public key
  const publicKeyBuffer = Buffer.from(params.publicKeyPem);
  const wrappedKey = publicEncrypt(
    { key: publicKeyBuffer, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
    sessionKeyBytes,
  );

  return {
    encryptedSessionKey: wrappedKey.toString('base64'),
    senderSessionKey:    'INBOUND_NO_SENDER_KEY', // External sender — no sender copy needed
    encryptedSubject:    subjectEnc.toString('base64'),
    encryptedBody:       bodyEnc.toString('base64'),
    subjectIv:           subjectIvBytes.toString('base64'),
    bodyIv:              bodyIvBytes.toString('base64'),
  };
}

/**
 * Build a merged header map from:
 *   1. The SendGrid-style header dump (raw "Key: Value\r\n" string in form field)
 *   2. The HTTP request headers from the provider (e.g. X-SG-*, X-Mailgun-*)
 *
 * Extracted into a named helper to reduce cognitive complexity of the handler.
 */
function buildHeaderMap(
  parsedHeadersField: string | undefined,
  requestHeaders: FastifyRequest['headers'],
): Record<string, string> {
  const map: Record<string, string> = {};

  // Parse SendGrid-format header dump ("Header-Name: value\r\nAnother-Header: value")
  if (parsedHeadersField) {
    try {
      const lines = parsedHeadersField.split(/\r?\n/);
      for (const line of lines) {
        const sep = line.indexOf(':');
        if (sep > 0) {
          map[line.slice(0, sep).trim().toLowerCase()] = line.slice(sep + 1).trim();
        }
      }
    } catch {
      // Non-fatal — provider may send malformed header dump
    }
  }

  // Merge HTTP request headers (provider adds its own e.g. X-SG-SPF, X-Mailgun-*)
  for (const [k, v] of Object.entries(requestHeaders)) {
    if (typeof v === 'string') map[k.toLowerCase()] = v;
    else if (Array.isArray(v) && v.length > 0) map[k.toLowerCase()] = v[0];
  }

  return map;
}

// ─── Route Registration ───────────────────────────────────────────────────────

export async function inboundRoutes(app: FastifyInstance) {
  /**
   * POST /api/mail/inbound/webhook
   *
   * Receives inbound email from a provider webhook.
   * Validates the shared secret, verifies sender authentication from headers,
   * encrypts the message for the recipient, and stores it in the mailbox.
   */
  app.post(
    '/webhook',
    async (request: FastifyRequest, reply: FastifyReply) => {
      // ── 1. Shared secret validation ────────────────────────────────────────
      const secret = request.headers['x-webhook-secret'];
      const expectedSecret = env.INBOUND_WEBHOOK_SECRET;

      if (!expectedSecret) {
        request.log.error('INBOUND_WEBHOOK_SECRET is not configured. Rejecting webhook call.');
        return reply.status(503).send({ error: 'Webhook not configured.' });
      }

      if (!secret || secret !== expectedSecret) {
        request.log.warn('Inbound webhook: invalid or missing X-Webhook-Secret.');
        return reply.status(401).send({ error: 'Unauthorized.' });
      }

      // ── 2. Parse body ─────────────────────────────────────────────────────
      const parsed = webhookBodySchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.status(400).send({ error: 'Invalid webhook payload.', details: parsed.error.flatten() });
      }

      const data = parsed.data;
      const fromEmail = extractEmail(data.from);
      const toEmail   = extractEmail(data.to);
      const subject   = data.subject;
      // Mailgun sends stripped-text; SendGrid sends text
      const body      = data['stripped-text'] ?? data.text ?? '';

      // ── 3. SPF/DKIM/DMARC verification from provider headers ─────────────
      const headerMap = buildHeaderMap(data.headers, request.headers);

      // Inject From: and Return-Path: if not already present (needed for alignment)
      headerMap['from'] ??= data.from;
      headerMap['return-path'] ??= `<${fromEmail}>`;

      const authResult = mailAuthService.verifyWebhookHeaders(headerMap);

      request.log.info({
        msg: 'Inbound mail auth result',
        from: fromEmail,
        to: toEmail,
        status: authResult.status,
        spf: authResult.spf,
        dkim: authResult.dkim,
        dmarc: authResult.dmarc,
        alignment: authResult.alignment,
      });

      // ── 4. Resolve recipient ──────────────────────────────────────────────
      const recipient = await prisma.user.findUnique({
        where: { email: toEmail },
        select: { email: true, publicKey: true },
      });

      if (!recipient) {
        // Recipient not on this server — accept and discard to avoid enumeration
        return reply.status(202).send({ message: 'Accepted.' });
      }

      // ── 5. Encrypt for recipient using their RSA public key ───────────────
      let encrypted: Awaited<ReturnType<typeof encryptForRecipient>>;
      try {
        encrypted = await encryptForRecipient({
          subject,
          body,
          publicKeyPem: recipient.publicKey,
        });
      } catch (err) {
        request.log.error({ err }, 'Failed to encrypt inbound message for recipient.');
        return reply.status(500).send({ error: 'Encryption failed.' });
      }

      // ── 6. Store encrypted message with auth status ───────────────────────
      await mailService.storeInternalMessage({
        senderEmail:         fromEmail,
        recipientEmail:      recipient.email,
        encryptedSessionKey: encrypted.encryptedSessionKey,
        senderSessionKey:    encrypted.senderSessionKey,
        encryptedSubject:    encrypted.encryptedSubject,
        encryptedBody:       encrypted.encryptedBody,
        subjectIv:           encrypted.subjectIv,
        bodyIv:              encrypted.bodyIv,
        isE2ee:              true,   // encrypted with recipient's public key
        folder:              'INBOX',
        authStatus:          authResult.status as AuthStatus,
        authDetails:         mailAuthService.serialize(authResult),
      });

      return reply.status(200).send({ message: 'Delivered.' });
    },
  );
}
