import { useState, useEffect, useCallback } from 'react';
import { authApi, type UserPayload } from '../api/auth.api.ts';
import { useCrypto } from './useCrypto.tsx';
import { keystore } from '../crypto/storage.ts';
import { deriveUMKRawBits, deriveAuthHash } from '../crypto/keyDerivation.ts';

export function useAuth() {
  const { initializeNewAccount, unlockAccount, lockSession, isUnlocked } = useCrypto();
  const [user, setUser] = useState<UserPayload | null>(() => {
    const saved = localStorage.getItem('tm_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Listen for 401 unauthorized events
  useEffect(() => {
    const handleUnauthorized = () => {
      setUser(null);
      lockSession();
    };
    window.addEventListener('auth:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('auth:unauthorized', handleUnauthorized);
  }, [lockSession]);

  /**
   * Register a new user with client-side Zero-Knowledge crypto generation.
   */
  const register = useCallback(
    async (email: string, pass: string) => {
      setLoading(true);
      setError(null);
      try {
        // 1. Generate keys client-side
        const keyBundle = await initializeNewAccount(pass, email);

        // 2. Submit only the public key, encrypted private key, salt, and authHash
        const res = await authApi.register({
          email,
          authHash: keyBundle.authHash,
          salt: keyBundle.salt,
          publicKey: keyBundle.publicKeyPem,
          encryptedPrivateKey: keyBundle.encryptedPrivateKey,
          keyIv: keyBundle.keyIv,
        });

        localStorage.setItem('tm_jwt', res.token);
        localStorage.setItem('tm_user', JSON.stringify(res.user));
        setUser(res.user);
        return { success: true, user: res.user };
      } catch (err: unknown) {
        const message =
          (err as { response?: { data?: { error?: string } } })?.response?.data?.error ||
          (err as Error).message ||
          'Registration failed';
        setError(message);
        return { success: false, error: message };
      } finally {
        setLoading(false);
      }
    },
    [initializeNewAccount]
  );

  /**
   * Login: fetch salt -> derive authHash & UMK -> unlock private key in memory -> authenticate.
   */
  const login = useCallback(
    async (email: string, pass: string) => {
      setLoading(true);
      setError(null);
      try {
        // 1. Fetch salt for email (anti-enumeration returns dummy if not found)
        const salt = await authApi.getSalt(email);

        // 2. Derive UMK & AuthHash, decrypt private key if cached or wait for login response
        // First check IndexedDB cache
        const cachedBundle = await keystore.getKeyBundle(email);

        if (cachedBundle) {
          const { authHash } = await unlockAccount({
            password: pass,
            email,
            salt: cachedBundle.salt,
            encryptedPrivateKey: cachedBundle.encryptedPrivateKey,
            keyIv: cachedBundle.keyIv,
            publicKeyPem: cachedBundle.publicKeyPem,
          });

          const res = await authApi.login({ email, authHash });
          localStorage.setItem('tm_jwt', res.token);
          localStorage.setItem('tm_user', JSON.stringify(res.user));
          setUser(res.user);
          return { success: true, user: res.user };
        } else {
          // If no local cache, derive AuthHash using the salt from server
          const rawUmk = await deriveUMKRawBits(pass, salt);
          const authHash = await deriveAuthHash(rawUmk);

          const res = await authApi.login({ email, authHash });

          // Unlock private key with the response bundle
          await unlockAccount({
            password: pass,
            email,
            salt,
            encryptedPrivateKey: res.user.encryptedPrivateKey,
            keyIv: res.user.keyIv,
            publicKeyPem: res.user.publicKey,
          });

          localStorage.setItem('tm_jwt', res.token);
          localStorage.setItem('tm_user', JSON.stringify(res.user));
          setUser(res.user);
          return { success: true, user: res.user };
        }
      } catch (err: unknown) {
        const message =
          (err as { response?: { data?: { error?: string } } })?.response?.data?.error ||
          (err as Error).message ||
          'Authentication failed';
        setError(message);
        return { success: false, error: message };
      } finally {
        setLoading(false);
      }
    },
    [unlockAccount]
  );

  /**
   * Logout: purge JWT, user data, and wipe private key from memory.
   */
  const logout = useCallback(() => {
    localStorage.removeItem('tm_jwt');
    localStorage.removeItem('tm_user');
    setUser(null);
    lockSession();
  }, [lockSession]);

  return {
    user,
    isAuthenticated: !!user && isUnlocked,
    isKeyUnlocked: isUnlocked,
    loading,
    error,
    register,
    login,
    logout,
  };
}
