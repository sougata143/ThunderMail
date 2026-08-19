/**
 * ThunderMail Client-Side Key Management
 * Conforms to INITIAL_SETUP.md specification §3.A & §3.B:
 * - Asymmetric Keypair: RSA-OAEP-4096 (SHA-256)
 * - Private Key Encryption: AES-GCM-256(UMK, RawPrivateKey, IV)
 */

import { base64ToBuffer, bufferToBase64 } from './keyDerivation.ts';

export interface KeyPairBundle {
  publicKeyPem: string;
  encryptedPrivateKey: string;
  keyIv: string;
  rawPrivateKey?: CryptoKey;
}

/**
 * Generate a new RSA-OAEP-4096 key pair in browser.
 */
export async function generateRSAKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: 'SHA-256',
    },
    true, // extractable for local encryption/export
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}

/**
 * Export RSA public key to base64 SPKI format
 */
export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  const spki = await crypto.subtle.exportKey('spki', publicKey);
  return bufferToBase64(spki);
}

/**
 * Import RSA public key from base64 SPKI format
 */
export async function importPublicKey(spkiBase64: string): Promise<CryptoKey> {
  const buffer = base64ToBuffer(spkiBase64);
  return crypto.subtle.importKey(
    'spki',
    buffer as BufferSource,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'wrapKey']
  );
}

/**
 * Encrypt the raw private key with the User Master Key (UMK) via AES-GCM-256.
 */
export async function encryptPrivateKey(
  privateKey: CryptoKey,
  umk: CryptoKey
): Promise<{ encryptedPrivateKey: string; keyIv: string }> {
  // Export private key to PKCS#8 format
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encryptedBytes = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    umk,
    pkcs8
  );

  return {
    encryptedPrivateKey: bufferToBase64(encryptedBytes),
    keyIv: bufferToBase64(iv),
  };
}

/**
 * Decrypt the encrypted private key using the User Master Key (UMK) in memory.
 */
export async function decryptPrivateKey(
  encryptedPrivateKeyBase64: string,
  keyIvBase64: string,
  umk: CryptoKey
): Promise<CryptoKey> {
  const encryptedBytes = base64ToBuffer(encryptedPrivateKeyBase64);
  const iv = base64ToBuffer(keyIvBase64);

  const decryptedPkcs8 = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource,
    },
    umk,
    encryptedBytes as BufferSource
  );

  return crypto.subtle.importKey(
    'pkcs8',
    decryptedPkcs8,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    true,
    ['decrypt', 'unwrapKey']
  );
}
