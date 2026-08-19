import React, { createContext, useContext, useState, useCallback, type ReactNode } from 'react';
import {
  generateRSAKeyPair,
  exportPublicKey,
  importPublicKey,
  encryptPrivateKey,
  decryptPrivateKey,
} from '../crypto/keyManagement.ts';
import {
  deriveUMK,
  deriveUMKRawBits,
  deriveAuthHash,
  generateSalt,
} from '../crypto/keyDerivation.ts';
import {
  encryptMailMessage,
  decryptMailMessage,
  type EncryptedMessagePayload,
  type DecryptedMessageContent,
} from '../crypto/messageCipher.ts';
import { keystore } from '../crypto/storage.ts';

interface CryptoContextType {
  privateKey: CryptoKey | null;
  publicKeyPem: string | null;
  publicKey: CryptoKey | null;
  isUnlocked: boolean;
  initializeNewAccount: (password: string, email: string) => Promise<{
    salt: string;
    authHash: string;
    publicKeyPem: string;
    encryptedPrivateKey: string;
    keyIv: string;
  }>;
  unlockAccount: (params: {
    password: string;
    email: string;
    salt: string;
    encryptedPrivateKey: string;
    keyIv: string;
    publicKeyPem: string;
  }) => Promise<{ authHash: string }>;
  encryptMessage: (params: {
    recipientEmail: string;
    subject: string;
    body: string;
    recipientPublicKeyPem: string;
  }) => Promise<EncryptedMessagePayload>;
  decryptMessage: (params: {
    encryptedSessionKey: string;
    encryptedSubject: string;
    encryptedBody: string;
    subjectIv: string;
    bodyIv: string;
    encryptedAttachmentsMetadata?: string | null;
  }) => Promise<DecryptedMessageContent>;
  lockSession: () => void;
}

const CryptoContext = createContext<CryptoContextType | null>(null);

export const CryptoProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [privateKey, setPrivateKey] = useState<CryptoKey | null>(null);
  const [publicKeyPem, setPublicKeyPem] = useState<string | null>(null);
  const [publicKey, setPublicKey] = useState<CryptoKey | null>(null);

  const lockSession = useCallback(() => {
    setPrivateKey(null);
    setPublicKeyPem(null);
    setPublicKey(null);
  }, []);

  /**
   * Initializes a brand new account keypair during registration.
   */
  const initializeNewAccount = useCallback(async (password: string, email: string) => {
    // 1. Generate salt
    const salt = generateSalt();

    // 2. Derive UMK (CryptoKey) and AuthHash
    const umk = await deriveUMK(password, salt);
    const rawUmkBits = await deriveUMKRawBits(password, salt);
    const authHash = await deriveAuthHash(rawUmkBits);

    // 3. Generate RSA-OAEP-4096 Key Pair
    const keyPair = await generateRSAKeyPair();

    // 4. Encrypt private key with UMK
    const { encryptedPrivateKey, keyIv } = await encryptPrivateKey(keyPair.privateKey, umk);

    // 5. Export public key to base64 PEM/SPKI
    const pubPem = await exportPublicKey(keyPair.publicKey);

    // Keep active keys in memory
    setPrivateKey(keyPair.privateKey);
    setPublicKey(keyPair.publicKey);
    setPublicKeyPem(pubPem);

    // Cache encrypted bundle in IndexedDB
    await keystore.saveKeyBundle({
      email,
      salt,
      publicKeyPem: pubPem,
      encryptedPrivateKey,
      keyIv,
      lastUpdated: Date.now(),
    });

    return {
      salt,
      authHash,
      publicKeyPem: pubPem,
      encryptedPrivateKey,
      keyIv,
    };
  }, []);

  /**
   * Unlocks an existing account during login: derives UMK and decrypts the private key.
   */
  const unlockAccount = useCallback(async (params: {
    password: string;
    email: string;
    salt: string;
    encryptedPrivateKey: string;
    keyIv: string;
    publicKeyPem: string;
  }) => {
    // 1. Derive UMK & AuthHash
    const umk = await deriveUMK(params.password, params.salt);
    const rawUmkBits = await deriveUMKRawBits(params.password, params.salt);
    const authHash = await deriveAuthHash(rawUmkBits);

    // 2. Decrypt private key into memory
    const decryptedPrivKey = await decryptPrivateKey(
      params.encryptedPrivateKey,
      params.keyIv,
      umk
    );

    // 3. Import public key
    const importedPubKey = await importPublicKey(params.publicKeyPem);

    setPrivateKey(decryptedPrivKey);
    setPublicKey(importedPubKey);
    setPublicKeyPem(params.publicKeyPem);

    // Cache encrypted bundle in IndexedDB
    await keystore.saveKeyBundle({
      email: params.email,
      salt: params.salt,
      publicKeyPem: params.publicKeyPem,
      encryptedPrivateKey: params.encryptedPrivateKey,
      keyIv: params.keyIv,
      lastUpdated: Date.now(),
    });

    return { authHash };
  }, []);

  /**
   * Encrypts an outgoing message using recipient's and sender's public keys.
   */
  const encryptMessage = useCallback(async (params: {
    recipientEmail: string;
    subject: string;
    body: string;
    recipientPublicKeyPem: string;
  }) => {
    if (!publicKey) {
      throw new Error('Sender public key not loaded');
    }
    const recipientPubKey = await importPublicKey(params.recipientPublicKeyPem);

    return encryptMailMessage({
      recipientEmail: params.recipientEmail,
      subject: params.subject,
      body: params.body,
      recipientPublicKey: recipientPubKey,
      senderPublicKey: publicKey,
    });
  }, [publicKey]);

  /**
   * Decrypts an incoming message using user's in-memory private key.
   */
  const decryptMessage = useCallback(async (params: {
    encryptedSessionKey: string;
    encryptedSubject: string;
    encryptedBody: string;
    subjectIv: string;
    bodyIv: string;
    encryptedAttachmentsMetadata?: string | null;
  }) => {
    if (!privateKey) {
      throw new Error('Private key not unlocked in session');
    }
    return decryptMailMessage({
      ...params,
      privateKey,
    });
  }, [privateKey]);

  const contextValue = React.useMemo(
    () => ({
      privateKey,
      publicKeyPem,
      publicKey,
      isUnlocked: !!privateKey,
      initializeNewAccount,
      unlockAccount,
      encryptMessage,
      decryptMessage,
      lockSession,
    }),
    [
      privateKey,
      publicKeyPem,
      publicKey,
      initializeNewAccount,
      unlockAccount,
      encryptMessage,
      decryptMessage,
      lockSession,
    ]
  );

  return (
    <CryptoContext.Provider value={contextValue}>
      {children}
    </CryptoContext.Provider>
  );
};

export const useCrypto = (): CryptoContextType => {
  const context = useContext(CryptoContext);
  if (!context) {
    throw new Error('useCrypto must be used within a CryptoProvider');
  }
  return context;
};
