/**
 * ThunderMail Message Cipher
 * Conforms to INITIAL_SETUP.md specification §3.C:
 * - One-time symmetric session key: AES-GCM-256
 * - Encrypt subject and body with SessionKey
 * - Encrypt SessionKey with Recipient's PublicKey (RSA-OAEP) -> EncryptedSessionKey
 * - Encrypt SessionKey with Sender's PublicKey (RSA-OAEP) -> SenderSessionKey
 */

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
  plaintextSubject?: string;
  plaintextBody?: string;
}

export interface DecryptedMessageContent {
  subject: string;
  body: string;
  attachmentsMetadata?: unknown;
}

/**
 * Encrypt an email message for E2EE delivery.
 */
export async function encryptMailMessage(params: {
  recipientEmail: string;
  subject: string;
  body: string;
  recipientPublicKey: CryptoKey;
  senderPublicKey: CryptoKey;
  attachmentsMetadata?: unknown;
}): Promise<EncryptedMessagePayload> {
  const enc = new TextEncoder();

  // 1. Generate random one-time symmetric session key (AES-GCM-256)
  const sessionKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

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

  // 4. Wrap SessionKey with recipient's RSA-OAEP public key
  const rawSessionKey = await crypto.subtle.exportKey('raw', sessionKey);
  const wrappedRecipientKey = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    params.recipientPublicKey,
    rawSessionKey
  );

  // 5. Wrap SessionKey with sender's RSA-OAEP public key (for Sent folder)
  const wrappedSenderKey = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    params.senderPublicKey,
    rawSessionKey
  );

  return {
    recipientEmail: params.recipientEmail,
    encryptedSessionKey: bufferToBase64(wrappedRecipientKey),
    senderSessionKey: bufferToBase64(wrappedSenderKey),
    encryptedSubject: bufferToBase64(encryptedSubjectBuffer),
    encryptedBody: bufferToBase64(encryptedBodyBuffer),
    subjectIv: bufferToBase64(subjectIv),
    bodyIv: bufferToBase64(bodyIv),
    encryptedAttachments,
    isE2ee: true,
  };
}

/**
 * Decrypt an email message using the user's RSA-OAEP private key.
 */
export async function decryptMailMessage(params: {
  encryptedSessionKey: string;
  encryptedSubject: string;
  encryptedBody: string;
  subjectIv: string;
  bodyIv: string;
  encryptedAttachmentsMetadata?: string | null;
  privateKey: CryptoKey;
}): Promise<DecryptedMessageContent> {
  const dec = new TextDecoder();

  // 1. Unwrap the symmetric session key with user's RSA private key
  const wrappedKeyBytes = base64ToBuffer(params.encryptedSessionKey);
  const rawSessionKeyBuffer = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    params.privateKey,
    wrappedKeyBytes as BufferSource
  );

  const sessionKey = await crypto.subtle.importKey(
    'raw',
    rawSessionKeyBuffer,
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

  return {
    subject,
    body,
  };
}
