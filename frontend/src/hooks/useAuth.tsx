import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from 'react';
import { authApi, type UserPayload } from '../api/auth.api.ts';
import { useCrypto } from './useCrypto.tsx';
import { deriveUMKRawBits, deriveAuthHash } from '../crypto/keyDerivation.ts';

// ─── Types ───────────────────────────────────────────────────────
export interface AuthContextType {
  user: UserPayload | null;
  isAuthenticated: boolean;
  isKeyUnlocked: boolean;
  loading: boolean;
  error: string | null;
  register: (email: string, pass: string) => Promise<{ success: boolean; error?: string; user?: UserPayload }>;
  login: (email: string, pass: string) => Promise<{ success: boolean; error?: string; user?: UserPayload }>;
  logout: () => void;
}

// ─── Context ─────────────────────────────────────────────────────
const AuthContext = createContext<AuthContextType | null>(null);

// ─── Provider ────────────────────────────────────────────────────
export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
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

  // Listen for 401 unauthorized events from axios interceptors
  useEffect(() => {
    const handleUnauthorized = () => {
      localStorage.removeItem('tm_jwt');
      localStorage.removeItem('tm_user');
      setUser(null);
      lockSession();
    };
    window.addEventListener('auth:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('auth:unauthorized', handleUnauthorized);
  }, [lockSession]);

  /**
   * Register: generate hybrid keys client-side, submit public verifier & encrypted bundle.
   */
  const register = useCallback(
    async (email: string, pass: string) => {
      setLoading(true);
      setError(null);
      const normalizedEmail = email.trim().toLowerCase();
      try {
        const keyBundle = await initializeNewAccount(pass, normalizedEmail);
        const res = await authApi.register({
          email: normalizedEmail,
          authHash: keyBundle.authHash,
          salt: keyBundle.salt,
          publicKey: keyBundle.publicKeyPem,
          encryptedPrivateKey: keyBundle.encryptedPrivateKey,
          keyIv: keyBundle.keyIv,
          pqcPublicKey: keyBundle.pqcPublicKey,
          encryptedPqcPrivKey: keyBundle.encryptedPqcPrivKey,
          pqcKeyIv: keyBundle.pqcKeyIv,
          dsaPublicKey: keyBundle.dsaPublicKey,
          encryptedDsaPrivKey: keyBundle.encryptedDsaPrivKey,
          dsaKeyIv: keyBundle.dsaKeyIv,
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
    [initializeNewAccount],
  );

  /**
   * Login: fetch salt → derive UMK/AuthHash → authenticate → unlock private keys in RAM.
   */
  const login = useCallback(
    async (email: string, pass: string) => {
      setLoading(true);
      setError(null);
      const normalizedEmail = email.trim().toLowerCase();
      try {
        // 1. Fetch server-side salt
        const salt = await authApi.getSalt(normalizedEmail);

        // 2. Derive AuthHash client-side
        const rawUmk = await deriveUMKRawBits(pass, salt);
        const authHash = await deriveAuthHash(rawUmk);

        // 3. Authenticate — server returns JWT + encrypted key bundle (including PQC if provisioned)
        const res = await authApi.login({ email: normalizedEmail, authHash });

        // 4. Decrypt private keys into browser RAM using UMK (lazily upgrading if PQC missing)
        await unlockAccount({
          password: pass,
          email: normalizedEmail,
          salt,
          encryptedPrivateKey: res.user.encryptedPrivateKey,
          keyIv: res.user.keyIv,
          publicKeyPem: res.user.publicKey,
          pqcPublicKey: res.user.pqcPublicKey,
          encryptedPqcPrivKey: res.user.encryptedPqcPrivKey,
          pqcKeyIv: res.user.pqcKeyIv,
          dsaPublicKey: res.user.dsaPublicKey,
          encryptedDsaPrivKey: res.user.encryptedDsaPrivKey,
          dsaKeyIv: res.user.dsaKeyIv,
        });

        // 5. Persist JWT + user metadata (no secrets)
        localStorage.setItem('tm_jwt', res.token);
        localStorage.setItem('tm_user', JSON.stringify(res.user));

        // 6. Update shared context state → triggers AppContent re-render → redirect ✅
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
    [unlockAccount],
  );

  /**
   * Logout: wipe JWT, user metadata, and private keys from memory.
   */
  const logout = useCallback(() => {
    localStorage.removeItem('tm_jwt');
    localStorage.removeItem('tm_user');
    setUser(null);
    lockSession();
  }, [lockSession]);

  const contextValue = React.useMemo(
    () => ({
      user,
      isAuthenticated: !!user,
      isKeyUnlocked: isUnlocked,
      loading,
      error,
      register,
      login,
      logout,
    }),
    [user, isUnlocked, loading, error, register, login, logout]
  );

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};

// ─── Hook ────────────────────────────────────────────────────────
export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
