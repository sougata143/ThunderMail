import { describe, it, expect } from 'vitest';
import {
  generateSalt,
  deriveUMK,
  deriveUMKRawBits,
  deriveAuthHash,
} from '../keyDerivation.ts';
import {
  encryptPrivateKey,
  decryptPrivateKey,
} from '../keyManagement.ts';
import {
  encryptMailMessage,
  decryptMailMessage,
} from '../messageCipher.ts';

describe('ThunderMail Client-Side Cryptographic Protocol', () => {
  it('should derive consistent AuthHash and UMK from password and salt', async () => {
    const password = 'CorrectHorseBatteryStaple123!';
    const salt = generateSalt();

    const umk1 = await deriveUMK(password, salt);
    const umk2 = await deriveUMK(password, salt);
    expect(umk1).toBeDefined();
    expect(umk2).toBeDefined();

    const raw1 = await deriveUMKRawBits(password, salt);
    const raw2 = await deriveUMKRawBits(password, salt);
    const authHash1 = await deriveAuthHash(raw1);
    const authHash2 = await deriveAuthHash(raw2);

    expect(authHash1).toBe(authHash2);
    expect(authHash1.length).toBe(64); // HMAC-SHA256 hex string length
  });

  it('should encrypt and decrypt private key with UMK', async () => {
    const password = 'MasterPassword2026';
    const salt = generateSalt();
    const umk = await deriveUMK(password, salt);

    // Generate RSA key pair (2048 in test for speed, 4096 in production)
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );

    const { encryptedPrivateKey, keyIv } = await encryptPrivateKey(keyPair.privateKey, umk);
    expect(encryptedPrivateKey).toBeDefined();
    expect(keyIv).toBeDefined();

    // Decrypt back into CryptoKey
    const decryptedPrivKey = await decryptPrivateKey(encryptedPrivateKey, keyIv, umk);
    expect(decryptedPrivKey).toBeDefined();
    expect(decryptedPrivKey.algorithm.name).toBe('RSA-OAEP');
  });

  it('should perform full E2EE message encryption and decryption roundtrip', async () => {
    // Generate Alice and Bob keys
    const aliceKeys = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );

    const bobKeys = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );

    const PLAINTEXT_SUBJECT = 'Project Blue Sky: Confidential';
    const PLAINTEXT_BODY = 'The launch schedule has been finalized for Q3.';

    // Alice encrypts for Bob
    const payload = await encryptMailMessage({
      recipientEmail: 'bob@thundermail.local',
      subject: PLAINTEXT_SUBJECT,
      body: PLAINTEXT_BODY,
      recipientPublicKey: bobKeys.publicKey,
      senderPublicKey: aliceKeys.publicKey,
    });

    // Verify ciphertext does not leak plaintext
    expect(payload.encryptedSubject).not.toContain(PLAINTEXT_SUBJECT);
    expect(payload.encryptedBody).not.toContain(PLAINTEXT_BODY);

    // Bob decrypts with Bob's private key
    const bobDecrypted = await decryptMailMessage({
      encryptedSessionKey: payload.encryptedSessionKey,
      encryptedSubject: payload.encryptedSubject,
      encryptedBody: payload.encryptedBody,
      subjectIv: payload.subjectIv,
      bodyIv: payload.bodyIv,
      privateKey: bobKeys.privateKey,
    });

    expect(bobDecrypted.subject).toBe(PLAINTEXT_SUBJECT);
    expect(bobDecrypted.body).toBe(PLAINTEXT_BODY);

    // Alice decrypts her Sent copy with Alice's private key and senderSessionKey
    const aliceDecrypted = await decryptMailMessage({
      encryptedSessionKey: payload.senderSessionKey,
      encryptedSubject: payload.encryptedSubject,
      encryptedBody: payload.encryptedBody,
      subjectIv: payload.subjectIv,
      bodyIv: payload.bodyIv,
      privateKey: aliceKeys.privateKey,
    });

    expect(aliceDecrypted.subject).toBe(PLAINTEXT_SUBJECT);
    expect(aliceDecrypted.body).toBe(PLAINTEXT_BODY);
  });
});
