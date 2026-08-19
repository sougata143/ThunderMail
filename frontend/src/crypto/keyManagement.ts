/**
 * ThunderMail Client-Side Key Management
 * Hybrid Post-Quantum Cryptography Architecture:
 * - Classical Asymmetric Keypair: RSA-OAEP-4096 (SHA-256)
 * - Post-Quantum KEM: ML-KEM-768 (FIPS 203)
 * - Post-Quantum Signature: ML-DSA-65 (FIPS 204)
 * - All Private Key Material Encrypted at Rest: AES-GCM-256(UMK, RawPrivateKey, IV)
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { base64ToBuffer, bufferToBase64 } from './keyDerivation.ts';

// Re-export so callers can use a single import path
export { base64ToBuffer, bufferToBase64 };

export interface KeyPairBundle {
  // Classical RSA-OAEP-4096
  publicKeyPem: string;
  encryptedPrivateKey: string;
  keyIv: string;
  rawPrivateKey?: CryptoKey;

  // Post-Quantum ML-KEM-768 (FIPS 203)
  pqcPublicKey?: string;
  encryptedPqcPrivKey?: string;
  pqcKeyIv?: string;
  rawPqcPrivateKey?: Uint8Array;

  // Post-Quantum ML-DSA-65 (FIPS 204)
  dsaPublicKey?: string;
  encryptedDsaPrivKey?: string;
  dsaKeyIv?: string;
  rawDsaPrivateKey?: Uint8Array;
}

// ─── Classical RSA-OAEP-4096 ─────────────────────────────────────────────────

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
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}

export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  const spki = await crypto.subtle.exportKey('spki', publicKey);
  return bufferToBase64(spki);
}

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

export async function encryptPrivateKey(
  privateKey: CryptoKey,
  umk: CryptoKey
): Promise<{ encryptedPrivateKey: string; keyIv: string }> {
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
  return encryptRawKeyBytes(new Uint8Array(pkcs8), umk);
}

export async function decryptPrivateKey(
  encryptedPrivateKeyBase64: string,
  keyIvBase64: string,
  umk: CryptoKey
): Promise<CryptoKey> {
  const decryptedBytes = await decryptRawKeyBytes(encryptedPrivateKeyBase64, keyIvBase64, umk);
  return crypto.subtle.importKey(
    'pkcs8',
    decryptedBytes as BufferSource,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    true,
    ['decrypt', 'unwrapKey']
  );
}

// ─── Post-Quantum ML-KEM-768 (FIPS 203) ──────────────────────────────────────

export function generateMLKEMKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const keys = ml_kem768.keygen();
  return { publicKey: keys.publicKey, secretKey: keys.secretKey };
}

// ─── Post-Quantum ML-DSA-65 (FIPS 204) ───────────────────────────────────────

export function generateMLDSAKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const keys = ml_dsa65.keygen();
  return { publicKey: keys.publicKey, secretKey: keys.secretKey };
}

// ─── Generic Raw Bytes Encryption / Decryption under UMK ─────────────────────

export async function encryptRawKeyBytes(
  rawBytes: Uint8Array,
  umk: CryptoKey
): Promise<{ encryptedPrivateKey: string; keyIv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedBytes = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    umk,
    rawBytes as BufferSource
  );

  return {
    encryptedPrivateKey: bufferToBase64(encryptedBytes),
    keyIv: bufferToBase64(iv),
  };
}

export async function decryptRawKeyBytes(
  encryptedBase64: string,
  keyIvBase64: string,
  umk: CryptoKey
): Promise<Uint8Array> {
  const encryptedBytes = base64ToBuffer(encryptedBase64);
  const iv = base64ToBuffer(keyIvBase64);

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource,
    },
    umk,
    encryptedBytes as BufferSource
  );

  return new Uint8Array(decryptedBuffer);
}

// ─── Full Hybrid Keypair Bundle Generation ───────────────────────────────────

export async function generateFullHybridKeyBundle(umk: CryptoKey): Promise<KeyPairBundle> {
  // 1. Generate Classical RSA-4096
  const rsaPair = await generateRSAKeyPair();
  const publicKeyPem = await exportPublicKey(rsaPair.publicKey);
  const rsaEnc = await encryptPrivateKey(rsaPair.privateKey, umk);

  // 2. Generate ML-KEM-768
  const mlkemPair = generateMLKEMKeyPair();
  const pqcPublicKey = bufferToBase64(mlkemPair.publicKey);
  const pqcEnc = await encryptRawKeyBytes(mlkemPair.secretKey, umk);

  // 3. Generate ML-DSA-65
  const mldsaPair = generateMLDSAKeyPair();
  const dsaPublicKey = bufferToBase64(mldsaPair.publicKey);
  const dsaEnc = await encryptRawKeyBytes(mldsaPair.secretKey, umk);

  return {
    publicKeyPem,
    encryptedPrivateKey: rsaEnc.encryptedPrivateKey,
    keyIv: rsaEnc.keyIv,
    rawPrivateKey: rsaPair.privateKey,

    pqcPublicKey,
    encryptedPqcPrivKey: pqcEnc.encryptedPrivateKey,
    pqcKeyIv: pqcEnc.keyIv,
    rawPqcPrivateKey: mlkemPair.secretKey,

    dsaPublicKey,
    encryptedDsaPrivKey: dsaEnc.encryptedPrivateKey,
    dsaKeyIv: dsaEnc.keyIv,
    rawDsaPrivateKey: mldsaPair.secretKey,
  };
}
