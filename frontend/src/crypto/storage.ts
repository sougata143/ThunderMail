/**
 * ThunderMail Client-Side IndexedDB Storage
 * Stores encrypted key bundles as local cache.
 * Note: Decrypted plaintext private keys are NEVER written to IndexedDB or localStorage.
 */

import { openDB, type IDBPDatabase } from 'idb';

const DB_NAME = 'thundermail_keystore';
const DB_VERSION = 1;
const STORE_KEY_BUNDLES = 'key_bundles';
const STORE_DRAFTS = 'drafts';

interface KeyBundleRecord {
  email: string;
  salt: string;
  publicKeyPem: string;
  encryptedPrivateKey: string;
  keyIv: string;
  lastUpdated: number;
}

async function getDB(): Promise<IDBPDatabase> {
  return openDB(DB_NAME, DB_VERSION, {
    upgrade(db) {
      if (!db.objectStoreNames.contains(STORE_KEY_BUNDLES)) {
        db.createObjectStore(STORE_KEY_BUNDLES, { keyPath: 'email' });
      }
      if (!db.objectStoreNames.contains(STORE_DRAFTS)) {
        db.createObjectStore(STORE_DRAFTS, { keyPath: 'id' });
      }
    },
  });
}

export const keystore = {
  async saveKeyBundle(record: KeyBundleRecord): Promise<void> {
    const db = await getDB();
    await db.put(STORE_KEY_BUNDLES, record);
  },

  async getKeyBundle(email: string): Promise<KeyBundleRecord | undefined> {
    const db = await getDB();
    return db.get(STORE_KEY_BUNDLES, email);
  },

  async clearKeyBundle(email: string): Promise<void> {
    const db = await getDB();
    await db.delete(STORE_KEY_BUNDLES, email);
  },

  async clearAll(): Promise<void> {
    const db = await getDB();
    await db.clear(STORE_KEY_BUNDLES);
    await db.clear(STORE_DRAFTS);
  },
};

/**
 * 24-word recovery phrase generator (BIP-39 style wordlist simulation)
 */
const WORDLIST = [
  'thunder', 'shield', 'cipher', 'quantum', 'vault', 'matrix', 'crystal', 'vector',
  'vertex', 'nebula', 'solace', 'shadow', 'aurora', 'zenith', 'pulse', 'orbit',
  'beacon', 'summit', 'horizon', 'prism', 'vortex', 'falcon', 'titan', 'glacier',
  'amber', 'cobalt', 'obsidian', 'cascade', 'dynamo', 'echo', 'flare', 'genesis',
  'haven', 'iron', 'jupiter', 'kinetic', 'lunar', 'mystic', 'nexus', 'omega',
  'phoenix', 'quasar', 'radiant', 'stellar', 'tactical', 'uranium', 'valiant', 'warden'
];

export function generateRecoveryPhrase(): string[] {
  const randomIndices = new Uint8Array(24);
  crypto.getRandomValues(randomIndices);
  return Array.from(randomIndices).map((n) => WORDLIST[n % WORDLIST.length]);
}
