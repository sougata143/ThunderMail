import React, { useState } from 'react';
import { Shield, Lock, Key, ArrowRight, UserPlus, LogIn, Sparkles } from 'lucide-react';
import { Button } from '../components/ui/Button.tsx';
import { Input } from '../components/ui/Input.tsx';
import { RecoveryPhraseModal } from '../components/crypto/RecoveryPhraseModal.tsx';
import { generateRecoveryPhrase } from '../crypto/storage.ts';
import { useAuth } from '../hooks/useAuth.ts';

export const AuthPage: React.FC = () => {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [cryptoStatus, setCryptoStatus] = useState<string | null>(null);

  // Recovery phrase state
  const [recoveryWords, setRecoveryWords] = useState<string[]>([]);
  const [showRecoveryModal, setShowRecoveryModal] = useState(false);

  const { login, register, loading, error } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;

    if (isRegister) {
      if (password !== confirmPassword) {
        alert('Passwords do not match');
        return;
      }
      if (password.length < 8) {
        alert('Password must be at least 8 characters');
        return;
      }

      setCryptoStatus('Deriving UMK with PBKDF2 (100k iter) & Generating RSA-4096 Keypair...');
      const words = generateRecoveryPhrase();
      setRecoveryWords(words);

      const res = await register(email, password);
      setCryptoStatus(null);

      if (res.success) {
        setShowRecoveryModal(true);
      }
    } else {
      setCryptoStatus('Deriving AuthHash & decrypting private key in RAM...');
      await login(email, password);
      setCryptoStatus(null);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 bg-gradient-to-br from-thunder-950 via-thunder-900 to-[#120826] relative overflow-hidden">
      {/* Background ambient lighting */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-violet-600/15 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-indigo-600/15 rounded-full blur-3xl pointer-events-none" />

      {/* Main card */}
      <div className="w-full max-w-md glass-panel rounded-3xl p-8 border border-white/10 shadow-2xl relative z-10 animate-fade-in">
        {/* Brand header */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-violet-700 via-violet-600 to-indigo-500 flex items-center justify-center mb-4 shadow-glow">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            ThunderMail
            <span className="text-[11px] bg-violet-500/20 text-violet-300 font-mono px-2 py-0.5 rounded border border-violet-500/30">
              Zero-Knowledge
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1.5 max-w-xs">
            End-to-End Encrypted Webmail with client-side RSA-4096 and AES-GCM-256
          </p>
        </div>

        {/* Tab switcher */}
        <div className="flex rounded-xl bg-thunder-950 p-1 mb-6 border border-white/5">
          <button
            type="button"
            onClick={() => setIsRegister(false)}
            className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-xs font-semibold transition-all ${
              !isRegister
                ? 'bg-violet-600 text-white shadow-glow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <LogIn className="w-3.5 h-3.5" />
            Sign In
          </button>
          <button
            type="button"
            onClick={() => setIsRegister(true)}
            className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-xs font-semibold transition-all ${
              isRegister
                ? 'bg-violet-600 text-white shadow-glow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <UserPlus className="w-3.5 h-3.5" />
            Create Account
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <Input
              label="ThunderMail Address"
              type="email"
              placeholder="user@thundermail.local"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              leftIcon={<Key className="w-4 h-4" />}
            />
          </div>

          <div>
            <Input
              label="Master Password"
              type="password"
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              leftIcon={<Lock className="w-4 h-4" />}
            />
          </div>

          {isRegister && (
            <div className="animate-slide-up">
              <Input
                label="Confirm Master Password"
                type="password"
                placeholder="••••••••••••"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                leftIcon={<Lock className="w-4 h-4" />}
              />
            </div>
          )}

          {error && (
            <div className="bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs p-3 rounded-xl animate-fade-in">
              {error}
            </div>
          )}

          {cryptoStatus && (
            <div className="bg-violet-500/10 border border-violet-500/30 text-violet-300 text-xs p-3 rounded-xl flex items-center gap-2 animate-fade-in font-mono text-[11px]">
              <Sparkles className="w-4 h-4 shrink-0 text-violet-400 animate-spin" />
              <span>{cryptoStatus}</span>
            </div>
          )}

          <Button
            type="submit"
            className="w-full py-2.5 mt-2 shadow-glow"
            isLoading={loading}
            rightIcon={<ArrowRight className="w-4 h-4" />}
          >
            {isRegister ? 'Generate Keys & Register' : 'Unlock Encrypted Mailbox'}
          </Button>
        </form>

        {/* Security badge footer */}
        <div className="mt-8 pt-6 border-t border-white/10 flex items-center justify-between text-[11px] text-slate-500">
          <span>WebCrypto SubtleCrypto</span>
          <span>Argon2 / PBKDF2</span>
          <span>Zero-Knowledge</span>
        </div>
      </div>

      {/* Recovery Phrase Modal */}
      <RecoveryPhraseModal
        isOpen={showRecoveryModal}
        onClose={() => setShowRecoveryModal(false)}
        words={recoveryWords}
      />
    </div>
  );
};
