import { webcrypto } from 'node:crypto';

/**
 * Server-side crypto service.
 * Used ONLY for inbound external mail processing:
 *   - Receives plaintext from external SMTP
 *   - Encrypts immediately with recipient's RSA public key
 *   - Discards plaintext from memory
 *
 * NOTE: The server does NOT perform any decryption. Ever.
 */
export const cryptoService = {
  /**
   * Encrypt an inbound external email's body with the recipient's RSA-OAEP public key.
   * Returns base64-encoded ciphertext of the AES session key encrypted by RSA-OAEP.
   */
  async encryptForRecipient(
    plaintext: string,
    recipientPublicKeyBase64: string,
  ): Promise<{
    encryptedBody: string;
    encryptedSubject: string;
    encryptedSessionKey: string;
    bodyIv: string;
    subjectIv: string;
  }> {
    // Import the recipient's RSA-OAEP public key
    const publicKeyBuffer = Buffer.from(recipientPublicKeyBase64, 'base64');
    const rsaPublicKey = await webcrypto.subtle.importKey(
      'spki',
      publicKeyBuffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['wrapKey'],
    );

    // Generate a random AES-GCM session key
    const sessionKey = await webcrypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    // Encrypt the body
    const bodyIvBytes = webcrypto.getRandomValues(new Uint8Array(12));
    const encryptedBodyBytes = await webcrypto.subtle.encrypt(
      { name: 'AES-GCM', iv: bodyIvBytes },
      sessionKey,
      Buffer.from(plaintext, 'utf-8'),
    );

    // Encrypt a placeholder subject
    const subjectIvBytes = webcrypto.getRandomValues(new Uint8Array(12));
    const encryptedSubjectBytes = await webcrypto.subtle.encrypt(
      { name: 'AES-GCM', iv: subjectIvBytes },
      sessionKey,
      Buffer.from('[External Message]', 'utf-8'),
    );

    // Wrap the session key with recipient's RSA public key
    const wrappedSessionKey = await webcrypto.subtle.wrapKey(
      'raw',
      sessionKey,
      rsaPublicKey,
      { name: 'RSA-OAEP' },
    );

    return {
      encryptedBody: Buffer.from(encryptedBodyBytes).toString('base64'),
      encryptedSubject: Buffer.from(encryptedSubjectBytes).toString('base64'),
      encryptedSessionKey: Buffer.from(wrappedSessionKey).toString('base64'),
      bodyIv: Buffer.from(bodyIvBytes).toString('base64'),
      subjectIv: Buffer.from(subjectIvBytes).toString('base64'),
    };
  },
};
