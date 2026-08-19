/**
 * ThunderMail Client-Side Key Derivation
 * Conforms to INITIAL_SETUP.md specification §3.A:
 * - UMK = PBKDF2(password, salt, 100000, 256, 'SHA-256')
 * - AuthHash = HMAC-SHA256(UMK, "auth-verification-token")
 */

/**
 * Generate a cryptographically secure random 32-byte salt, returned as base64.
 */
export function generateSalt(): string {
  const saltBytes = crypto.getRandomValues(new Uint8Array(32));
  return bufferToBase64(saltBytes);
}

/**
 * Convert base64 string to Uint8Array buffer
 */
export function base64ToBuffer(base64: string): Uint8Array {
  const binaryString = window.atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.codePointAt(i) ?? 0;
  }
  return bytes;
}

/**
 * Convert buffer to base64 string
 */
export function bufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCodePoint(bytes[i]);
  }
  return window.btoa(binary);
}

/**
 * Convert ArrayBuffer to Hex string
 */
export function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Derives the User Master Key (UMK) using PBKDF2-SHA256 (100,000 iterations).
 * The UMK is an AES-GCM-256 CryptoKey used to encrypt the user's private key.
 */
export async function deriveUMK(password: string, saltBase64: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const saltBytes = base64ToBuffer(saltBase64);

  // Import raw password as key material
  const passwordKeyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey', 'deriveBits']
  );

  // Derive AES-GCM-256 key for private key encryption
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes as BufferSource,
      iterations: 100000,
      hash: 'SHA-256',
    },
    passwordKeyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Derives raw UMK bytes for HMAC-based AuthHash derivation.
 */
export async function deriveUMKRawBits(password: string, saltBase64: string): Promise<ArrayBuffer> {
  const enc = new TextEncoder();
  const saltBytes = base64ToBuffer(saltBase64);

  const passwordKeyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  return crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes as BufferSource,
      iterations: 100000,
      hash: 'SHA-256',
    },
    passwordKeyMaterial,
    256
  );
}

/**
 * Derives AuthHash = HMAC-SHA256(UMK, "auth-verification-token").
 * Sent to the server for authentication — server cannot infer UMK or password.
 */
export async function deriveAuthHash(rawUmkBits: ArrayBuffer): Promise<string> {
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    rawUmkBits,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const enc = new TextEncoder();
  const signature = await crypto.subtle.sign(
    'HMAC',
    hmacKey,
    enc.encode('auth-verification-token')
  );

  return bufferToHex(signature);
}
