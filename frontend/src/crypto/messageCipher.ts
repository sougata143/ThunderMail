/**
 * ThunderMail Message Cipher
 * Hybrid Post-Quantum Cryptography Implementation:
 * - One-time symmetric session key: AES-GCM-256 (encrypts subject, body, attachments)
 * - Classical KEM: RSA-OAEP-4096 ephemeral shared secret
 * - Post-Quantum KEM: ML-KEM-768 (FIPS 203) encapsulation
 * - Combined KEK: HKDF-SHA384(ss_classic || ss_pqc, salt = ct_classic || ct_pqc, info = "ThunderMail-Hybrid-v1-KEK")
 * - Key Wrapping: AES-GCM-256(KEK, SessionKey)
 * - Post-Quantum Digital Signature: ML-DSA-65 (FIPS 204) signing payload hash
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { base64ToBuffer, bufferToBase64 } from './keyDerivation.ts';

export interface EncryptedMessagePayload {
  recipientEmail: string;
  encryptedSessionKey: string;
  senderSessionKey: string;
  encryptedSubject: string;
  encryptedBody: string;
  subjectIv: string;
  bodyIv: string;
  encryptedAttachments?: string;
  isE2ee: boolean;

  // Hybrid Post-Quantum Fields
  isPqc: boolean;
  classicCiphertext?: string;
  pqcCiphertext?: string;
  senderClassicCt?: string;
  senderPqcCt?: string;
  senderSignature?: string;

  // Plaintext fields for external relay
  plaintextSubject?: string;
  plaintextBody?: string;
}

export interface DecryptedMessageContent {
  subject: string;
  body: string;
  attachmentsMetadata?: unknown;
  isPqc: boolean;
  signatureStatus: 'VERIFIED' | 'FAILED' | 'UNSIGNED';
}

/**
 * Derives a 256-bit AES-GCM Key Encryption Key (KEK) from classical and PQC shared secrets.
 */
async function deriveHybridKEK(params: {
  classicSharedSecret: Uint8Array;
  pqcSharedSecret: Uint8Array;
  classicCiphertext: Uint8Array;
  pqcCiphertext: Uint8Array;
}): Promise<CryptoKey> {
  // Combine shared secrets: ss_classic || ss_pqc (64 bytes IKM)
  const ikm = new Uint8Array(params.classicSharedSecret.length + params.pqcSharedSecret.length);
  ikm.set(params.classicSharedSecret, 0);
  ikm.set(params.pqcSharedSecret, params.classicSharedSecret.length);

  // Salt = ct_classic || ct_pqc
  const salt = new Uint8Array(params.classicCiphertext.length + params.pqcCiphertext.length);
  salt.set(params.classicCiphertext, 0);
  salt.set(params.pqcCiphertext, params.classicCiphertext.length);

  const enc = new TextEncoder();
  const info = enc.encode('ThunderMail-Hybrid-v1-KEK');

  const baseKey = await crypto.subtle.importKey(
    'raw',
    ikm,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-384',
      salt,
      info,
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Compute SHA-384 digest of all ciphertext components for ML-DSA-65 signing.
 */
async function computePayloadDigest(params: {
  encryptedSubject: string;
  encryptedBody: string;
  subjectIv: string;
  bodyIv: string;
  encryptedSessionKey: string;
  classicCiphertext?: string;
  pqcCiphertext?: string;
}): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const payloadString = [
    params.encryptedSubject,
    params.encryptedBody,
    params.subjectIv,
    params.bodyIv,
    params.encryptedSessionKey,
    params.classicCiphertext ?? '',
    params.pqcCiphertext ?? '',
  ].join('|');

  const digestBuffer = await crypto.subtle.digest('SHA-384', enc.encode(payloadString));
  return new Uint8Array(digestBuffer);
}

/**
 * Encrypt an email message for E2EE delivery with Hybrid Post-Quantum Protection.
 */
export async function encryptMailMessage(params: {
  recipientEmail: string;
  subject: string;
  body: string;
  recipientPublicKey: CryptoKey;
  senderPublicKey: CryptoKey;
  recipientPqcPublicKey?: Uint8Array | null;
  senderPqcPublicKey?: Uint8Array | null;
  senderDsaPrivateKey?: Uint8Array | null;
  attachmentsMetadata?: unknown;
}): Promise<EncryptedMessagePayload> {
  const enc = new TextEncoder();

  // 1. Generate random one-time symmetric session key (AES-GCM-256)
  const sessionKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const rawSessionKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', sessionKey));

  // 2. Encrypt subject
  const subjectIv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedSubjectBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: subjectIv },
    sessionKey,
    enc.encode(params.subject)
  );

  // 3. Encrypt body
  const bodyIv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedBodyBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: bodyIv },
    sessionKey,
    enc.encode(params.body)
  );

  // Optional: encrypt attachments metadata
  let encryptedAttachments: string | undefined;
  if (params.attachmentsMetadata) {
    const metaIv = crypto.getRandomValues(new Uint8Array(12));
    const encMeta = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: metaIv },
      sessionKey,
      enc.encode(JSON.stringify(params.attachmentsMetadata))
    );
    encryptedAttachments = JSON.stringify({
      data: bufferToBase64(encMeta),
      iv: bufferToBase64(metaIv),
    });
  }

  // 4. Session Key Wrapping (Hybrid PQC vs Classical RSA Fallback)
  let encryptedSessionKey: string;
  let senderSessionKey: string;
  let classicCiphertext: string | undefined;
  let pqcCiphertext: string | undefined;
  let senderClassicCt: string | undefined;
  let senderPqcCt: string | undefined;
  const isPqc = !!(params.recipientPqcPublicKey && params.senderPqcPublicKey);

  if (isPqc && params.recipientPqcPublicKey && params.senderPqcPublicKey) {
    // ─── Recipient Hybrid KEK ───
    // A. Classical RSA KEM: generate random 32-byte secret and encrypt with RSA-OAEP
    const recipientClassicSs = crypto.getRandomValues(new Uint8Array(32));
    const recipientClassicCtBuffer = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      params.recipientPublicKey,
      recipientClassicSs
    );
    const recipientClassicCt = new Uint8Array(recipientClassicCtBuffer);

    // B. Post-Quantum ML-KEM-768 encapsulation
    const recipientPqc = ml_kem768.encapsulate(params.recipientPqcPublicKey);

    // C. Combine into Recipient KEK
    const recipientKek = await deriveHybridKEK({
      classicSharedSecret: recipientClassicSs,
      pqcSharedSecret: recipientPqc.sharedSecret,
      classicCiphertext: recipientClassicCt,
      pqcCiphertext: recipientPqc.cipherText,
    });

    // D. Wrap SessionKey under Recipient KEK (AES-GCM with 12-byte IV)
    const recipientWrapIv = crypto.getRandomValues(new Uint8Array(12));
    const recipientWrappedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: recipientWrapIv },
      recipientKek,
      rawSessionKeyBytes
    );
    // Bundle wrapped session key with its IV: IV(12) + Ciphertext
    const recipientCombinedWrap = new Uint8Array(recipientWrapIv.length + recipientWrappedBuffer.byteLength);
    recipientCombinedWrap.set(recipientWrapIv, 0);
    recipientCombinedWrap.set(new Uint8Array(recipientWrappedBuffer), recipientWrapIv.length);

    encryptedSessionKey = bufferToBase64(recipientCombinedWrap);
    classicCiphertext = bufferToBase64(recipientClassicCt);
    pqcCiphertext = bufferToBase64(recipientPqc.cipherText);

    // ─── Sender Hybrid KEK (for Sent folder) ───
    const senderClassicSs = crypto.getRandomValues(new Uint8Array(32));
    const senderClassicCtBuffer = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      params.senderPublicKey,
      senderClassicSs
    );
    const senderClassicCtBytes = new Uint8Array(senderClassicCtBuffer);

    const senderPqc = ml_kem768.encapsulate(params.senderPqcPublicKey);

    const senderKek = await deriveHybridKEK({
      classicSharedSecret: senderClassicSs,
      pqcSharedSecret: senderPqc.sharedSecret,
      classicCiphertext: senderClassicCtBytes,
      pqcCiphertext: senderPqc.cipherText,
    });

    const senderWrapIv = crypto.getRandomValues(new Uint8Array(12));
    const senderWrappedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: senderWrapIv },
      senderKek,
      rawSessionKeyBytes
    );
    const senderCombinedWrap = new Uint8Array(senderWrapIv.length + senderWrappedBuffer.byteLength);
    senderCombinedWrap.set(senderWrapIv, 0);
    senderCombinedWrap.set(new Uint8Array(senderWrappedBuffer), senderWrapIv.length);

    senderSessionKey = bufferToBase64(senderCombinedWrap);
    senderClassicCt = bufferToBase64(senderClassicCtBytes);
    senderPqcCt = bufferToBase64(senderPqc.cipherText);
  } else {
    // ─── Classical Legacy RSA-OAEP Fallback ───
    const wrappedRecipientKey = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      params.recipientPublicKey,
      rawSessionKeyBytes
    );
    const wrappedSenderKey = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      params.senderPublicKey,
      rawSessionKeyBytes
    );
    encryptedSessionKey = bufferToBase64(wrappedRecipientKey);
    senderSessionKey = bufferToBase64(wrappedSenderKey);
  }

  // 5. Post-Quantum Sender Digital Signature (ML-DSA-65)
  let senderSignature: string | undefined;
  if (params.senderDsaPrivateKey) {
    const payloadDigest = await computePayloadDigest({
      encryptedSubject: bufferToBase64(encryptedSubjectBuffer),
      encryptedBody: bufferToBase64(encryptedBodyBuffer),
      subjectIv: bufferToBase64(subjectIv),
      bodyIv: bufferToBase64(bodyIv),
      encryptedSessionKey,
      classicCiphertext,
      pqcCiphertext,
    });
    const sigBytes = ml_dsa65.sign(payloadDigest, params.senderDsaPrivateKey);
    senderSignature = bufferToBase64(sigBytes);
  }

  return {
    recipientEmail: params.recipientEmail,
    encryptedSessionKey,
    senderSessionKey,
    encryptedSubject: bufferToBase64(encryptedSubjectBuffer),
    encryptedBody: bufferToBase64(encryptedBodyBuffer),
    subjectIv: bufferToBase64(subjectIv),
    bodyIv: bufferToBase64(bodyIv),
    encryptedAttachments,
    isE2ee: true,
    isPqc,
    classicCiphertext,
    pqcCiphertext,
    senderClassicCt,
    senderPqcCt,
    senderSignature,
  };
}

/**
 * Decrypt an email message and verify sender post-quantum digital signature.
 */
export async function decryptMailMessage(params: {
  encryptedSessionKey: string;
  encryptedSubject: string;
  encryptedBody: string;
  subjectIv: string;
  bodyIv: string;
  encryptedAttachmentsMetadata?: string | null;
  privateKey: CryptoKey;
  // Hybrid PQC Parameters
  isPqc?: boolean;
  classicCiphertext?: string | null;
  pqcCiphertext?: string | null;
  rawPqcPrivateKey?: Uint8Array | null;
  // Signature Verification Parameters
  senderSignature?: string | null;
  senderDsaPublicKey?: Uint8Array | null;
}): Promise<DecryptedMessageContent> {
  const dec = new TextDecoder();
  let sessionKeyBytes: Uint8Array;

  // 1. Unwrap Symmetric Session Key
  if (
    params.isPqc &&
    params.classicCiphertext &&
    params.pqcCiphertext &&
    params.rawPqcPrivateKey
  ) {
    // ─── Hybrid Decapsulation ───
    // A. Classical RSA Decapsulation
    const classicCtBytes = base64ToBuffer(params.classicCiphertext);
    const classicSsBuffer = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      params.privateKey,
      classicCtBytes as BufferSource
    );
    const classicSs = new Uint8Array(classicSsBuffer);

    // B. ML-KEM-768 Decapsulation
    const pqcCtBytes = base64ToBuffer(params.pqcCiphertext);
    const pqcSs = ml_kem768.decapsulate(pqcCtBytes, params.rawPqcPrivateKey);

    // C. Derive KEK
    const kek = await deriveHybridKEK({
      classicSharedSecret: classicSs,
      pqcSharedSecret: pqcSs,
      classicCiphertext: classicCtBytes,
      pqcCiphertext: pqcCtBytes,
    });

    // D. Unwrap Session Key (first 12 bytes are IV)
    const wrappedBlob = base64ToBuffer(params.encryptedSessionKey);
    const wrapIv = wrappedBlob.slice(0, 12);
    const wrapCiphertext = wrappedBlob.slice(12);

    const unwrappedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: wrapIv },
      kek,
      wrapCiphertext as BufferSource
    );
    sessionKeyBytes = new Uint8Array(unwrappedBuffer);
  } else {
    // ─── Legacy Classical RSA Unwrap ───
    const wrappedKeyBytes = base64ToBuffer(params.encryptedSessionKey);
    const rawSessionKeyBuffer = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      params.privateKey,
      wrappedKeyBytes as BufferSource
    );
    sessionKeyBytes = new Uint8Array(rawSessionKeyBuffer);
  }

  // Import unwrapped session key
  // Copy into a plain ArrayBuffer-backed Uint8Array so SubtleCrypto's
  // strict BufferSource overload is satisfied (noble/post-quantum may
  // return Uint8Array<ArrayBufferLike> which includes SharedArrayBuffer).
  const sessionKeyBuf = new Uint8Array(sessionKeyBytes.buffer instanceof ArrayBuffer
    ? sessionKeyBytes.buffer
    : sessionKeyBytes.slice(0).buffer
  );
  const sessionKey = await crypto.subtle.importKey(
    'raw',
    sessionKeyBuf,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  // 2. Decrypt subject
  const subjectIv = base64ToBuffer(params.subjectIv);
  const encryptedSubjectBytes = base64ToBuffer(params.encryptedSubject);
  const decryptedSubjectBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: subjectIv as BufferSource },
    sessionKey,
    encryptedSubjectBytes as BufferSource
  );
  const subject = dec.decode(decryptedSubjectBuffer);

  // 3. Decrypt body
  const bodyIv = base64ToBuffer(params.bodyIv);
  const encryptedBodyBytes = base64ToBuffer(params.encryptedBody);
  const decryptedBodyBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bodyIv as BufferSource },
    sessionKey,
    encryptedBodyBytes as BufferSource
  );
  const body = dec.decode(decryptedBodyBuffer);

  // 4. Verify Post-Quantum Digital Signature (ML-DSA-65)
  let signatureStatus: 'VERIFIED' | 'FAILED' | 'UNSIGNED' = 'UNSIGNED';
  if (params.senderSignature && params.senderDsaPublicKey) {
    try {
      const payloadDigest = await computePayloadDigest({
        encryptedSubject: params.encryptedSubject,
        encryptedBody: params.encryptedBody,
        subjectIv: params.subjectIv,
        bodyIv: params.bodyIv,
        encryptedSessionKey: params.encryptedSessionKey,
        classicCiphertext: params.classicCiphertext ?? undefined,
        pqcCiphertext: params.pqcCiphertext ?? undefined,
      });
      const sigBytes = base64ToBuffer(params.senderSignature);
      const isValid = ml_dsa65.verify(sigBytes, payloadDigest, params.senderDsaPublicKey);
      signatureStatus = isValid ? 'VERIFIED' : 'FAILED';
    } catch {
      signatureStatus = 'FAILED';
    }
  }

  return {
    subject,
    body,
    isPqc: !!params.isPqc,
    signatureStatus,
  };
}
