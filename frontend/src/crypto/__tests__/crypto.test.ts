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
  generateFullHybridKeyBundle,
  decryptRawKeyBytes,
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
    expect(authHash1).toHaveLength(64); // HMAC-SHA256 hex string length
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

  it('should generate, encrypt, and decrypt full hybrid PQC key bundle (RSA + ML-KEM + ML-DSA)', async () => {
    const password = 'QuantumProofPassword2026!';
    const salt = generateSalt();
    const umk = await deriveUMK(password, salt);

    const bundle = await generateFullHybridKeyBundle(umk);

    expect(bundle.publicKeyPem).toBeDefined();
    expect(bundle.pqcPublicKey).toBeDefined();
    expect(bundle.dsaPublicKey).toBeDefined();

    // Decrypt raw PQC and DSA private keys
    const decryptedPqcPriv = await decryptRawKeyBytes(
      bundle.encryptedPqcPrivKey!,
      bundle.pqcKeyIv!,
      umk
    );
    const decryptedDsaPriv = await decryptRawKeyBytes(
      bundle.encryptedDsaPrivKey!,
      bundle.dsaKeyIv!,
      umk
    );

    expect(decryptedPqcPriv).toEqual(bundle.rawPqcPrivateKey);
    expect(decryptedDsaPriv).toEqual(bundle.rawDsaPrivateKey);
  });

  it('should perform full Hybrid Post-Quantum E2EE message encryption, decryption, and ML-DSA signature verification', async () => {
    const salt = generateSalt();
    const aliceUmk = await deriveUMK('AlicePassword123!', salt);
    const bobUmk = await deriveUMK('BobPassword123!', salt);

    const aliceBundle = await generateFullHybridKeyBundle(aliceUmk);
    const bobBundle = await generateFullHybridKeyBundle(bobUmk);

    const PLAINTEXT_SUBJECT = 'Post-Quantum Defense Plan';
    const PLAINTEXT_BODY = 'Lattice-based cryptography is active. Message secured against quantum adversaries.';

    // Alice encrypts for Bob using both Classical RSA + ML-KEM-768, and signs with ML-DSA-65
    const payload = await encryptMailMessage({
      recipientEmail: 'bob@thundermail.local',
      subject: PLAINTEXT_SUBJECT,
      body: PLAINTEXT_BODY,
      recipientPublicKey: (await crypto.subtle.importKey(
        'spki',
        Uint8Array.from(atob(bobBundle.publicKeyPem), c => c.charCodeAt(0)),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['encrypt']
      )),
      senderPublicKey: (await crypto.subtle.importKey(
        'spki',
        Uint8Array.from(atob(aliceBundle.publicKeyPem), c => c.charCodeAt(0)),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['encrypt']
      )),
      recipientPqcPublicKey: Uint8Array.from(atob(bobBundle.pqcPublicKey!), c => c.charCodeAt(0)),
      senderPqcPublicKey: Uint8Array.from(atob(aliceBundle.pqcPublicKey!), c => c.charCodeAt(0)),
      senderDsaPrivateKey: aliceBundle.rawDsaPrivateKey,
    });

    expect(payload.isPqc).toBe(true);
    expect(payload.classicCiphertext).toBeDefined();
    expect(payload.pqcCiphertext).toBeDefined();
    expect(payload.senderSignature).toBeDefined();

    // Verify plaintext is not leaked
    expect(payload.encryptedSubject).not.toContain(PLAINTEXT_SUBJECT);
    expect(payload.encryptedBody).not.toContain(PLAINTEXT_BODY);

    // Bob decrypts with Bob's private keys and verifies Alice's signature
    const bobDecrypted = await decryptMailMessage({
      encryptedSessionKey: payload.encryptedSessionKey,
      encryptedSubject: payload.encryptedSubject,
      encryptedBody: payload.encryptedBody,
      subjectIv: payload.subjectIv,
      bodyIv: payload.bodyIv,
      privateKey: aliceBundle.rawPrivateKey ? bobBundle.rawPrivateKey! : null as any,
      isPqc: payload.isPqc,
      classicCiphertext: payload.classicCiphertext,
      pqcCiphertext: payload.pqcCiphertext,
      rawPqcPrivateKey: bobBundle.rawPqcPrivateKey,
      senderSignature: payload.senderSignature,
      senderDsaPublicKey: Uint8Array.from(atob(aliceBundle.dsaPublicKey!), c => c.charCodeAt(0)),
    });

    expect(bobDecrypted.subject).toBe(PLAINTEXT_SUBJECT);
    expect(bobDecrypted.body).toBe(PLAINTEXT_BODY);
    expect(bobDecrypted.isPqc).toBe(true);
    expect(bobDecrypted.signatureStatus).toBe('VERIFIED');

    // Tampered payload fails ML-DSA signature check
    const tamperedDecrypted = await decryptMailMessage({
      encryptedSessionKey: payload.encryptedSessionKey,
      encryptedSubject: payload.encryptedSubject,
      encryptedBody: 'TamperedBodyCiphertext==' + payload.encryptedBody.slice(24),
      subjectIv: payload.subjectIv,
      bodyIv: payload.bodyIv,
      privateKey: bobBundle.rawPrivateKey!,
      isPqc: payload.isPqc,
      classicCiphertext: payload.classicCiphertext,
      pqcCiphertext: payload.pqcCiphertext,
      rawPqcPrivateKey: bobBundle.rawPqcPrivateKey,
      senderSignature: payload.senderSignature,
      senderDsaPublicKey: Uint8Array.from(atob(aliceBundle.dsaPublicKey!), c => c.charCodeAt(0)),
    }).catch(() => null);

    // If decryption fails due to bad auth tag or signature verification fails:
    expect(tamperedDecrypted?.signatureStatus).not.toBe('VERIFIED');
  });
});
