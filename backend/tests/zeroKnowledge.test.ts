import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../src/server.js';
import { prisma } from '../src/server.js';
import type { FastifyInstance } from 'fastify';

/**
 * Zero-Knowledge Test Suite
 *
 * Verifies the core security invariant of ThunderMail:
 * NO plaintext message content is stored in the database.
 *
 * After registering users and sending messages, we inspect raw DB rows
 * to confirm only ciphertext blobs exist.
 */
describe('Zero-Knowledge Invariants', () => {
  let app: FastifyInstance;
  let aliceToken: string;
  let bobToken: string;

  const alice = {
    email: 'alice@test.thundermail.local',
    authHash: 'a'.repeat(64),
    salt: Buffer.from('alice-salt-32bytes').toString('base64'),
    publicKey: 'mock-alice-public-key-' + 'x'.repeat(200),
    encryptedPrivateKey: 'enc-alice-private-' + 'x'.repeat(100),
    keyIv: Buffer.from('alice-iv-16bytes').toString('base64'),
  };

  const bob = {
    email: 'bob@test.thundermail.local',
    authHash: 'b'.repeat(64),
    salt: Buffer.from('bob-salt-32bytes!!').toString('base64'),
    publicKey: 'mock-bob-public-key-' + 'x'.repeat(200),
    encryptedPrivateKey: 'enc-bob-private-' + 'x'.repeat(100),
    keyIv: Buffer.from('bob-iv-16bytes!!').toString('base64'),
  };

  beforeAll(async () => {
    app = await buildApp();
    // Clean up test users
    await prisma.mailboxMessage.deleteMany({
      where: {
        OR: [
          { senderEmail: alice.email },
          { recipientEmail: alice.email },
          { senderEmail: bob.email },
          { recipientEmail: bob.email },
        ],
      },
    });
    await prisma.user.deleteMany({
      where: { email: { in: [alice.email, bob.email] } },
    });
  });

  afterAll(async () => {
    // Clean up
    await prisma.mailboxMessage.deleteMany({
      where: {
        OR: [
          { senderEmail: alice.email },
          { recipientEmail: alice.email },
          { senderEmail: bob.email },
          { recipientEmail: bob.email },
        ],
      },
    });
    await prisma.user.deleteMany({
      where: { email: { in: [alice.email, bob.email] } },
    });
    await app.close();
  });

  it('should register Alice without storing plaintext password', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: alice,
    });

    expect(res.statusCode).toBe(201);
    aliceToken = JSON.parse(res.body).token;

    // Inspect the DB row directly
    const dbUser = await prisma.user.findUnique({ where: { email: alice.email } });
    expect(dbUser).toBeTruthy();

    // Auth hash must NOT be a plaintext password
    expect(dbUser!.authHash).not.toContain('password');
    expect(dbUser!.authHash).not.toContain('secret');

    // Must store the encrypted private key (not plaintext)
    expect(dbUser!.encryptedPrivateKey).toBe(alice.encryptedPrivateKey);

    // Must store the public key (public by design)
    expect(dbUser!.publicKey).toBe(alice.publicKey);
  });

  it('should register Bob', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: bob,
    });

    expect(res.statusCode).toBe(201);
    bobToken = JSON.parse(res.body).token;
  });

  it('should send E2EE message and store ONLY ciphertext in the database', async () => {
    const PLAINTEXT_SUBJECT = 'TOP SECRET: Meeting at midnight';
    const PLAINTEXT_BODY = 'Bring the documents to the usual location.';

    const ENCRYPTED_SUBJECT = 'CIPHERTEXT_SUBJECT_BLOB_' + Buffer.from(PLAINTEXT_SUBJECT).toString('base64');
    const ENCRYPTED_BODY = 'CIPHERTEXT_BODY_BLOB_' + Buffer.from(PLAINTEXT_BODY).toString('base64');

    const res = await app.inject({
      method: 'POST',
      url: '/api/mail/send',
      headers: { authorization: `Bearer ${aliceToken}` },
      payload: {
        recipientEmail: bob.email,
        encryptedSessionKey: 'RSA_OAEP_WRAPPED_SESSION_KEY_' + 'x'.repeat(64),
        senderSessionKey: 'RSA_OAEP_SENDER_SESSION_KEY_' + 'x'.repeat(64),
        encryptedSubject: ENCRYPTED_SUBJECT,
        encryptedBody: ENCRYPTED_BODY,
        subjectIv: Buffer.from('subject-iv-12b').toString('base64'),
        bodyIv: Buffer.from('body-iv-12byte').toString('base64'),
        isE2ee: true,
      },
    });

    expect(res.statusCode).toBe(201);

    // ── CORE ZERO-KNOWLEDGE ASSERTION ──────────────────────────────
    // Inspect the database directly — must NOT contain plaintext
    const messages = await prisma.mailboxMessage.findMany({
      where: { recipientEmail: bob.email },
    });

    expect(messages.length).toBeGreaterThan(0);

    for (const msg of messages) {
      // The plaintext subject must NEVER appear in the DB
      expect(msg.encryptedSubject).not.toContain(PLAINTEXT_SUBJECT);
      expect(msg.encryptedBody).not.toContain(PLAINTEXT_BODY);

      // Ciphertext blobs must be present
      expect(msg.encryptedSubject.length).toBeGreaterThan(0);
      expect(msg.encryptedBody.length).toBeGreaterThan(0);
      expect(msg.encryptedSessionKey.length).toBeGreaterThan(0);
    }
  });

  it('should return encrypted blobs from the API (no plaintext in response)', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/mail/folder/INBOX',
      headers: { authorization: `Bearer ${bobToken}` },
    });

    expect(res.statusCode).toBe(200);
    const { messages } = JSON.parse(res.body);
    expect(messages.length).toBeGreaterThan(0);

    for (const msg of messages) {
      // API response must not contain any plaintext message content
      const rawJson = JSON.stringify(msg);
      expect(rawJson).not.toContain('TOP SECRET');
      expect(rawJson).not.toContain('midnight');
      expect(rawJson).not.toContain('documents');
    }
  });

  it('should not expose private key in any API response', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/user/me',
      headers: { authorization: `Bearer ${aliceToken}` },
    });

    expect(res.statusCode).toBe(200);
    const user = JSON.parse(res.body);

    // Encrypted private key blob is returned (needed for client decryption)
    // but it must be the ENCRYPTED version, not plaintext
    expect(user.encryptedPrivateKey).toBe(alice.encryptedPrivateKey);
    expect(user.encryptedPrivateKey).not.toContain('private_key_plaintext');
  });
});
