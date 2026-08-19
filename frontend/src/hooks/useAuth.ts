import { useState, useEffect, useCallback } from 'react';
import { authApi, type UserPayload } from '../api/auth.api.ts';
import { useCrypto } from './useCrypto.tsx';
import { deriveUMKRawBits, deriveAuthHash } from '../crypto/keyDerivation.ts';

export function useAuth() {
  const { initializeNewAccount, unlockAccount, lockSession, isUnlocked } = useCrypto();
  const [user, setUser] = useState<UserPayload | null>(() => {
    try {
      const saved = localStorage.getItem('tm_user');
      return saved ? (JSON.parse(saved) as UserPayload) : null;
    } catch {
      return null;
    }
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
      const normalizedEmail = email.trim().toLowerCase();
      try {
        // 1. Generate keys client-side
        const keyBundle = await initializeNewAccount(pass, normalizedEmail);

        // 2. Submit only the public key, encrypted private key, salt, and authHash
        const res = await authApi.register({
          email: normalizedEmail,
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
   * Login: fetch salt -> derive authHash & UMK -> authenticate -> unlock private key in RAM.
   */
  const login = useCallback(
    async (email: string, pass: string) => {
      setLoading(true);
      setError(null);
      const normalizedEmail = email.trim().toLowerCase();
      try {
        // 1. Fetch salt for email from server
        const salt = await authApi.getSalt(normalizedEmail);

        // 2. Derive UMK bits and AuthHash using the salt
        const rawUmk = await deriveUMKRawBits(pass, salt);
        const authHash = await deriveAuthHash(rawUmk);

        // 3. Authenticate with server using AuthHash
        const res = await authApi.login({ email: normalizedEmail, authHash });

        // 4. On successful login, unlock the private key into RAM using the user's encrypted key bundle
        await unlockAccount({
          password: pass,
          email: normalizedEmail,
          salt,
          encryptedPrivateKey: res.user.encryptedPrivateKey,
          keyIv: res.user.keyIv,
          publicKeyPem: res.user.publicKey,
        });

        localStorage.setItem('tm_jwt', res.token);
        localStorage.setItem('tm_user', JSON.stringify(res.user));
        setUser(res.user);
        return { success: true, user: res.user };
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

  // isAuthenticated: user data present in state + a JWT exists in storage.
  // We do NOT gate on isUnlocked here to avoid a React setState race condition:
  // unlockAccount() calls setPrivateKey() which is async; by the time AppContent
  // re-renders, privateKey may not yet be reflected in isUnlocked even though the
  // key IS loaded in memory. The mailbox itself can still read privateKey fine.
  const hasJwt = !!localStorage.getItem('tm_jwt');

  return {
    user,
    isAuthenticated: !!user && hasJwt,
    isKeyUnlocked: isUnlocked,
    loading,
    error,
    register,
    login,
    logout,
  };
}
