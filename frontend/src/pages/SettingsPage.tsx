import React from 'react';
import { Shield, Lock, Key, Cpu } from 'lucide-react';
import { useAuth } from '../hooks/useAuth.ts';
import { useCrypto } from '../hooks/useCrypto.tsx';

export const SettingsPage: React.FC = () => {
  const { user } = useAuth();
  const { publicKeyPem } = useCrypto();

  return (
    <div className="max-w-4xl mx-auto p-8 space-y-8 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
          <Shield className="w-6 h-6 text-violet-400" />
          Security & Cryptographic Settings
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Review your zero-knowledge encryption parameters and active cryptographic keys.
        </p>
      </div>

      {/* Account Info */}
      <div className="glass-panel p-6 rounded-2xl border border-white/10 space-y-4">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <Key className="w-5 h-5 text-violet-400" />
          Account Credentials
        </h2>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-slate-400 block text-xs">Email Address:</span>
            <span className="text-slate-200 font-semibold">{user?.email}</span>
          </div>
          <div>
            <span className="text-slate-400 block text-xs">Account ID (UUID):</span>
            <span className="text-slate-200 font-mono text-xs">{user?.id}</span>
          </div>
        </div>
      </div>

      {/* Crypto Protocols */}
      <div className="glass-panel p-6 rounded-2xl border border-white/10 space-y-4">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <Cpu className="w-5 h-5 text-violet-400" />
          Cryptographic Specifications
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          <div className="bg-thunder-900 p-3.5 rounded-xl border border-white/5 space-y-1">
            <span className="text-violet-400 font-semibold block">Asymmetric Scheme</span>
            <span className="text-slate-300">RSA-OAEP-4096 (SHA-256)</span>
          </div>
          <div className="bg-thunder-900 p-3.5 rounded-xl border border-white/5 space-y-1">
            <span className="text-violet-400 font-semibold block">Symmetric Cipher</span>
            <span className="text-slate-300">AES-GCM-256 (Random 96-bit IV)</span>
          </div>
          <div className="bg-thunder-900 p-3.5 rounded-xl border border-white/5 space-y-1">
            <span className="text-violet-400 font-semibold block">Key Derivation (UMK)</span>
            <span className="text-slate-300">PBKDF2-SHA256 (100,000 iter)</span>
          </div>
          <div className="bg-thunder-900 p-3.5 rounded-xl border border-white/5 space-y-1">
            <span className="text-violet-400 font-semibold block">Authentication Token</span>
            <span className="text-slate-300">HMAC-SHA256(UMK, "auth...")</span>
          </div>
        </div>
      </div>

      {/* Public Key Display */}
      <div className="glass-panel p-6 rounded-2xl border border-white/10 space-y-3">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <Lock className="w-5 h-5 text-emerald-400" />
          Public Key (SPKI Format)
        </h2>
        <p className="text-xs text-slate-400">
          This public key is stored on the server to allow other users to encrypt emails for you.
        </p>
        <div className="bg-thunder-950 p-4 rounded-xl font-mono text-[11px] text-violet-300 break-all max-h-36 overflow-y-auto border border-white/5">
          {publicKeyPem || 'No key loaded in session'}
        </div>
      </div>
    </div>
  );
};
