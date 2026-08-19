import React, { createContext, useContext, useState, useCallback, type ReactNode } from 'react';
import {
  importPublicKey,
  decryptPrivateKey,
  generateFullHybridKeyBundle,
  decryptRawKeyBytes,
  generateMLKEMKeyPair,
  generateMLDSAKeyPair,
  encryptRawKeyBytes,
  bufferToBase64,
  base64ToBuffer,
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
import { keysApi } from '../api/keys.api.ts';

interface CryptoContextType {
  privateKey: CryptoKey | null;
  publicKeyPem: string | null;
  publicKey: CryptoKey | null;
  pqcPublicKey: string | null;
  dsaPublicKey: string | null;
  rawPqcPrivateKey: Uint8Array | null;
  rawDsaPrivateKey: Uint8Array | null;
  isUnlocked: boolean;
  initializeNewAccount: (password: string, email: string) => Promise<{
    salt: string;
    authHash: string;
    publicKeyPem: string;
    encryptedPrivateKey: string;
    keyIv: string;
    pqcPublicKey: string;
    encryptedPqcPrivKey: string;
    pqcKeyIv: string;
    dsaPublicKey: string;
    encryptedDsaPrivKey: string;
    dsaKeyIv: string;
  }>;
  unlockAccount: (params: {
    password: string;
    email: string;
    salt: string;
    encryptedPrivateKey: string;
    keyIv: string;
    publicKeyPem: string;
    pqcPublicKey?: string | null;
    encryptedPqcPrivKey?: string | null;
    pqcKeyIv?: string | null;
    dsaPublicKey?: string | null;
    encryptedDsaPrivKey?: string | null;
    dsaKeyIv?: string | null;
  }) => Promise<{ authHash: string }>;
  encryptMessage: (params: {
    recipientEmail: string;
    subject: string;
    body: string;
    recipientPublicKeyPem: string;
    recipientPqcPublicKey?: string | null;
  }) => Promise<EncryptedMessagePayload>;
  decryptMessage: (params: {
    encryptedSessionKey: string;
    encryptedSubject: string;
    encryptedBody: string;
    subjectIv: string;
    bodyIv: string;
    encryptedAttachmentsMetadata?: string | null;
    isPqc?: boolean;
    classicCiphertext?: string | null;
    pqcCiphertext?: string | null;
    senderSignature?: string | null;
    senderDsaPublicKey?: string | null;
  }) => Promise<DecryptedMessageContent>;
  lockSession: () => void;
}

const CryptoContext = createContext<CryptoContextType | null>(null);

export const CryptoProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [privateKey, setPrivateKey] = useState<CryptoKey | null>(null);
  const [publicKeyPem, setPublicKeyPem] = useState<string | null>(null);
  const [publicKey, setPublicKey] = useState<CryptoKey | null>(null);
  const [pqcPublicKey, setPqcPublicKey] = useState<string | null>(null);
  const [dsaPublicKey, setDsaPublicKey] = useState<string | null>(null);
  const [rawPqcPrivateKey, setRawPqcPrivateKey] = useState<Uint8Array | null>(null);
  const [rawDsaPrivateKey, setRawDsaPrivateKey] = useState<Uint8Array | null>(null);

  const lockSession = useCallback(() => {
    setPrivateKey(null);
    setPublicKeyPem(null);
    setPublicKey(null);
    setPqcPublicKey(null);
    setDsaPublicKey(null);
    setRawPqcPrivateKey(null);
    setRawDsaPrivateKey(null);
  }, []);

  /**
   * Initializes a brand new account hybrid key bundle (RSA + ML-KEM + ML-DSA) during registration.
   */
  const initializeNewAccount = useCallback(async (password: string, email: string) => {
    // 1. Generate salt
    const salt = generateSalt();

    // 2. Derive UMK (CryptoKey) and AuthHash
    const umk = await deriveUMK(password, salt);
    const rawUmkBits = await deriveUMKRawBits(password, salt);
    const authHash = await deriveAuthHash(rawUmkBits);

    // 3. Generate full hybrid key bundle
    const bundle = await generateFullHybridKeyBundle(umk);

    const importedPubKey = await importPublicKey(bundle.publicKeyPem);

    // Keep active keys in memory
    setPrivateKey(bundle.rawPrivateKey ?? null);
    setPublicKey(importedPubKey);
    setPublicKeyPem(bundle.publicKeyPem);
    setPqcPublicKey(bundle.pqcPublicKey ?? null);
    setDsaPublicKey(bundle.dsaPublicKey ?? null);
    setRawPqcPrivateKey(bundle.rawPqcPrivateKey ?? null);
    setRawDsaPrivateKey(bundle.rawDsaPrivateKey ?? null);

    // Cache encrypted bundle in IndexedDB
    await keystore.saveKeyBundle({
      email,
      salt,
      publicKeyPem: bundle.publicKeyPem,
      encryptedPrivateKey: bundle.encryptedPrivateKey,
      keyIv: bundle.keyIv,
      lastUpdated: Date.now(),
    });

    return {
      salt,
      authHash,
      publicKeyPem: bundle.publicKeyPem,
      encryptedPrivateKey: bundle.encryptedPrivateKey,
      keyIv: bundle.keyIv,
      pqcPublicKey: bundle.pqcPublicKey!,
      encryptedPqcPrivKey: bundle.encryptedPqcPrivKey!,
      pqcKeyIv: bundle.pqcKeyIv!,
      dsaPublicKey: bundle.dsaPublicKey!,
      encryptedDsaPrivKey: bundle.encryptedDsaPrivKey!,
      dsaKeyIv: bundle.dsaKeyIv!,
    };
  }, []);

  /**
   * Unlocks an existing account during login: derives UMK and decrypts the private keys.
   * If the account lacks PQC keys (registered before PQC upgrade), lazily provisions them.
   */
  const unlockAccount = useCallback(async (params: {
    password: string;
    email: string;
    salt: string;
    encryptedPrivateKey: string;
    keyIv: string;
    publicKeyPem: string;
    pqcPublicKey?: string | null;
    encryptedPqcPrivKey?: string | null;
    pqcKeyIv?: string | null;
    dsaPublicKey?: string | null;
    encryptedDsaPrivKey?: string | null;
    dsaKeyIv?: string | null;
  }) => {
    // 1. Derive UMK & AuthHash
    const umk = await deriveUMK(params.password, params.salt);
    const rawUmkBits = await deriveUMKRawBits(params.password, params.salt);
    const authHash = await deriveAuthHash(rawUmkBits);

    // 2. Decrypt classical private key into memory
    const decryptedPrivKey = await decryptPrivateKey(
      params.encryptedPrivateKey,
      params.keyIv,
      umk
    );

    // 3. Import classical public key
    const importedPubKey = await importPublicKey(params.publicKeyPem);

    setPrivateKey(decryptedPrivKey);
    setPublicKey(importedPubKey);
    setPublicKeyPem(params.publicKeyPem);

    let activePqcPub = params.pqcPublicKey ?? null;
    let activeDsaPub = params.dsaPublicKey ?? null;
    let activeRawPqcPriv: Uint8Array | null = null;
    let activeRawDsaPriv: Uint8Array | null = null;

    // 4. Decrypt PQC and DSA private keys, or lazily generate them if missing
    if (params.encryptedPqcPrivKey && params.pqcKeyIv && params.encryptedDsaPrivKey && params.dsaKeyIv) {
      activeRawPqcPriv = await decryptRawKeyBytes(params.encryptedPqcPrivKey, params.pqcKeyIv, umk);
      activeRawDsaPriv = await decryptRawKeyBytes(params.encryptedDsaPrivKey, params.dsaKeyIv, umk);
    } else {
      // Lazy upgrade for legacy account
      const mlkemPair = generateMLKEMKeyPair();
      const mldsaPair = generateMLDSAKeyPair();

      const pqcEnc = await encryptRawKeyBytes(mlkemPair.secretKey, umk);
      const dsaEnc = await encryptRawKeyBytes(mldsaPair.secretKey, umk);

      activePqcPub = bufferToBase64(mlkemPair.publicKey);
      activeDsaPub = bufferToBase64(mldsaPair.publicKey);
      activeRawPqcPriv = mlkemPair.secretKey;
      activeRawDsaPriv = mldsaPair.secretKey;

      // Persist upgraded PQC keys on server in background
      try {
        await keysApi.upgradePqc({
          pqcPublicKey: activePqcPub!,
          encryptedPqcPrivKey: pqcEnc.encryptedPrivateKey,
          pqcKeyIv: pqcEnc.keyIv,
          dsaPublicKey: activeDsaPub!,
          encryptedDsaPrivKey: dsaEnc.encryptedPrivateKey,
          dsaKeyIv: dsaEnc.keyIv,
        });
      } catch (err) {
        console.warn('Could not complete lazy PQC key upgrade on server:', err);
      }
    }

    setPqcPublicKey(activePqcPub);
    setDsaPublicKey(activeDsaPub);
    setRawPqcPrivateKey(activeRawPqcPriv);
    setRawDsaPrivateKey(activeRawDsaPriv);

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
   * Encrypts an outgoing message using recipient's and sender's hybrid public keys.
   */
  const encryptMessage = useCallback(async (params: {
    recipientEmail: string;
    subject: string;
    body: string;
    recipientPublicKeyPem: string;
    recipientPqcPublicKey?: string | null;
  }) => {
    if (!publicKey) {
      throw new Error('Sender public key not loaded');
    }
    const recipientPubKey = await importPublicKey(params.recipientPublicKeyPem);

    const recipientPqcBytes = params.recipientPqcPublicKey
      ? base64ToBuffer(params.recipientPqcPublicKey)
      : null;
    const senderPqcBytes = pqcPublicKey
      ? base64ToBuffer(pqcPublicKey)
      : null;

    return encryptMailMessage({
      recipientEmail: params.recipientEmail,
      subject: params.subject,
      body: params.body,
      recipientPublicKey: recipientPubKey,
      senderPublicKey: publicKey,
      recipientPqcPublicKey: recipientPqcBytes,
      senderPqcPublicKey: senderPqcBytes,
      senderDsaPrivateKey: rawDsaPrivateKey,
    });
  }, [publicKey, pqcPublicKey, rawDsaPrivateKey]);

  /**
   * Decrypts an incoming message using user's in-memory hybrid private keys.
   */
  const decryptMessage = useCallback(async (params: {
    encryptedSessionKey: string;
    encryptedSubject: string;
    encryptedBody: string;
    subjectIv: string;
    bodyIv: string;
    encryptedAttachmentsMetadata?: string | null;
    isPqc?: boolean;
    classicCiphertext?: string | null;
    pqcCiphertext?: string | null;
    senderSignature?: string | null;
    senderDsaPublicKey?: string | null;
  }) => {
    if (!privateKey) {
      throw new Error('Private key not unlocked in session');
    }
    const senderDsaBytes = params.senderDsaPublicKey
      ? base64ToBuffer(params.senderDsaPublicKey)
      : null;

    return decryptMailMessage({
      ...params,
      privateKey,
      rawPqcPrivateKey,
      senderDsaPublicKey: senderDsaBytes,
    });
  }, [privateKey, rawPqcPrivateKey]);

  const contextValue = React.useMemo(
    () => ({
      privateKey,
      publicKeyPem,
      publicKey,
      pqcPublicKey,
      dsaPublicKey,
      rawPqcPrivateKey,
      rawDsaPrivateKey,
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
      pqcPublicKey,
      dsaPublicKey,
      rawPqcPrivateKey,
      rawDsaPrivateKey,
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
