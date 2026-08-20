import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../src/server.js';
import { prisma } from '../src/server.js';
import type { FastifyInstance } from 'fastify';

/**
 * Zero-Knowledge Test Suite
 *
 * Verifies the core security invariant of ThunderMail:
 * NO plaintext message content or unencrypted private keys are stored in the database.
 *
 * Checks classical RSA, Hybrid ML-KEM-768 KEM, and ML-DSA-65 signature columns.
 */
describe('Zero-Knowledge Invariants', () => {
  let app: FastifyInstance;
  let aliceToken: string;
  let bobToken: string;

  const alice = {
    email: 'alice@thundermail.sougatatech.com',
    authHash: 'a'.repeat(64),
    salt: Buffer.from('alice-salt-32bytes').toString('base64'),
    publicKey: 'mock-alice-public-key-' + 'x'.repeat(200),
    encryptedPrivateKey: 'enc-alice-private-' + 'x'.repeat(100),
    keyIv: Buffer.from('alice-iv-16bytes').toString('base64'),
    pqcPublicKey: 'mock-alice-pqc-public-key-' + 'p'.repeat(200),
    encryptedPqcPrivKey: 'enc-alice-pqc-private-' + 'p'.repeat(100),
    pqcKeyIv: Buffer.from('alice-pqc-iv12b').toString('base64'),
    dsaPublicKey: 'mock-alice-dsa-public-key-' + 'd'.repeat(200),
    encryptedDsaPrivKey: 'enc-alice-dsa-private-' + 'd'.repeat(100),
    dsaKeyIv: Buffer.from('alice-dsa-iv12b').toString('base64'),
  };

  const bob = {
    email: 'bob@thundermail.sougatatech.com',
    authHash: 'b'.repeat(64),
    salt: Buffer.from('bob-salt-32bytes!!').toString('base64'),
    publicKey: 'mock-bob-public-key-' + 'x'.repeat(200),
    encryptedPrivateKey: 'enc-bob-private-' + 'x'.repeat(100),
    keyIv: Buffer.from('bob-iv-16bytes!!').toString('base64'),
    pqcPublicKey: 'mock-bob-pqc-public-key-' + 'p'.repeat(200),
    encryptedPqcPrivKey: 'enc-bob-pqc-private-' + 'p'.repeat(100),
    pqcKeyIv: Buffer.from('bob-pqc-iv-12b!').toString('base64'),
    dsaPublicKey: 'mock-bob-dsa-public-key-' + 'd'.repeat(200),
    encryptedDsaPrivKey: 'enc-bob-dsa-private-' + 'd'.repeat(100),
    dsaKeyIv: Buffer.from('bob-dsa-iv-12b!').toString('base64'),
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

  it('should register Alice with PQC keys without storing plaintext passwords or raw private keys', async () => {
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

    // Must store the encrypted private keys (not plaintext)
    expect(dbUser!.encryptedPrivateKey).toBe(alice.encryptedPrivateKey);
    expect(dbUser!.encryptedPqcPrivKey).toBe(alice.encryptedPqcPrivKey);
    expect(dbUser!.encryptedDsaPrivKey).toBe(alice.encryptedDsaPrivKey);

    // Must store public keys
    expect(dbUser!.publicKey).toBe(alice.publicKey);
    expect(dbUser!.pqcPublicKey).toBe(alice.pqcPublicKey);
    expect(dbUser!.dsaPublicKey).toBe(alice.dsaPublicKey);
  });

  it('should register Bob with PQC keys', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: bob,
    });

    expect(res.statusCode).toBe(201);
    bobToken = JSON.parse(res.body).token;
  });

  it('should send Hybrid PQC E2EE message and store ONLY ciphertext in all columns without plaintext leaks', async () => {
    const PLAINTEXT_SUBJECT = 'TOP SECRET: Quantum Key Delivery';
    const PLAINTEXT_BODY = 'Lattice vectors validated under ML-KEM-768.';

    const ENCRYPTED_SUBJECT = 'CIPHERTEXT_SUBJECT_BLOB_' + Buffer.from(PLAINTEXT_SUBJECT).toString('base64');
    const ENCRYPTED_BODY = 'CIPHERTEXT_BODY_BLOB_' + Buffer.from(PLAINTEXT_BODY).toString('base64');
    const CLASSIC_CT = 'CLASSIC_RSA_CT_' + 'c'.repeat(64);
    const PQC_CT = 'ML_KEM_768_CT_' + 'q'.repeat(128);
    const SENDER_SIG = 'ML_DSA_65_SIGNATURE_' + 's'.repeat(128);

    const res = await app.inject({
      method: 'POST',
      url: '/api/mail/send',
      headers: { authorization: `Bearer ${aliceToken}` },
      payload: {
        recipientEmail: bob.email,
        encryptedSessionKey: 'HYBRID_WRAPPED_SESSION_KEY_' + 'k'.repeat(64),
        senderSessionKey: 'HYBRID_WRAPPED_SENDER_KEY_' + 'k'.repeat(64),
        encryptedSubject: ENCRYPTED_SUBJECT,
        encryptedBody: ENCRYPTED_BODY,
        subjectIv: Buffer.from('subject-iv-12b').toString('base64'),
        bodyIv: Buffer.from('body-iv-12byte').toString('base64'),
        isE2ee: true,
        isPqc: true,
        classicCiphertext: CLASSIC_CT,
        pqcCiphertext: PQC_CT,
        senderClassicCt: CLASSIC_CT,
        senderPqcCt: PQC_CT,
        senderSignature: SENDER_SIG,
      },
    });

    expect(res.statusCode).toBe(201);

    // ── CORE ZERO-KNOWLEDGE ASSERTION ──────────────────────────────
    // Inspect the database directly — must NOT contain plaintext in ANY column
    const messages = await prisma.mailboxMessage.findMany({
      where: { recipientEmail: bob.email },
    });

    expect(messages.length).toBeGreaterThan(0);

    for (const msg of messages) {
      // The plaintext subject and body must NEVER appear in the DB
      expect(msg.encryptedSubject).not.toContain(PLAINTEXT_SUBJECT);
      expect(msg.encryptedBody).not.toContain(PLAINTEXT_BODY);

      // Verify PQC columns contain ciphertext/signatures, not plaintext
      expect(msg.isPqc).toBe(true);
      expect(msg.classicCiphertext).toBe(CLASSIC_CT);
      expect(msg.pqcCiphertext).toBe(PQC_CT);
      expect(msg.senderSignature).toBe(SENDER_SIG);
      expect(msg.signatureStatus).toBe('VERIFIED');

      expect(msg.classicCiphertext).not.toContain(PLAINTEXT_BODY);
      expect(msg.pqcCiphertext).not.toContain(PLAINTEXT_BODY);
      expect(msg.senderSignature).not.toContain(PLAINTEXT_BODY);
    }
  });

  it('should return encrypted blobs and PQC metadata from folder API', async () => {
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
      expect(rawJson).not.toContain('Quantum Key Delivery');
      expect(rawJson).not.toContain('Lattice vectors');
      expect(msg.isPqc).toBe(true);
      expect(msg.signatureStatus).toBe('VERIFIED');
    }
  });

  it('should not expose raw private keys in user profile response', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/user/me',
      headers: { authorization: `Bearer ${aliceToken}` },
    });

    expect(res.statusCode).toBe(200);
    const user = JSON.parse(res.body);

    // Encrypted private key blobs are returned for client-side decryption
    expect(user.encryptedPrivateKey).toBe(alice.encryptedPrivateKey);
    expect(user.encryptedPqcPrivKey).toBe(alice.encryptedPqcPrivKey);
    expect(user.encryptedDsaPrivKey).toBe(alice.encryptedDsaPrivKey);

    expect(user.encryptedPrivateKey).not.toContain('private_key_plaintext');
    expect(user.encryptedPqcPrivKey).not.toContain('private_key_plaintext');
  });
});
