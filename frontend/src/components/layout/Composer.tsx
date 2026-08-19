import React, { useState, useEffect } from 'react';
import { Send, X } from 'lucide-react';
import { Button } from '../ui/Button.tsx';
import { Input } from '../ui/Input.tsx';
import { KeyBadge } from '../ui/KeyBadge.tsx';
import { keysApi } from '../../api/keys.api.ts';
import { useMailbox } from '../../hooks/useMailbox.ts';

interface ComposerProps {
  isOpen: boolean;
  onClose: () => void;
  initialTo?: string;
  initialSubject?: string;
}

export const Composer: React.FC<ComposerProps> = ({
  isOpen,
  onClose,
  initialTo = '',
  initialSubject = '',
}) => {
  const { sendEmail, isSending } = useMailbox();
  const [to, setTo] = useState(initialTo);
  const [subject, setSubject] = useState(initialSubject);
  const [body, setBody] = useState('');
  const [hasPublicKey, setHasPublicKey] = useState<boolean | null>(null);
  const [isCheckingKey, setIsCheckingKey] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  useEffect(() => {
    setTo(initialTo);
    setSubject(initialSubject);
  }, [initialTo, initialSubject]);

  // Check if recipient has a registered public key for E2EE with optional chaining
  useEffect(() => {
    if (!to?.includes('@')) {
      setHasPublicKey(null);
      return;
    }

    const timer = setTimeout(async () => {
      setIsCheckingKey(true);
      try {
        await keysApi.getPublicKey(to);
        setHasPublicKey(true);
      } catch {
        setHasPublicKey(false);
      } finally {
        setIsCheckingKey(false);
      }
    }, 400);

    return () => clearTimeout(timer);
  }, [to]);

  if (!isOpen) return null;

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!to || !subject) return;

    setStatusMessage('Encrypting message with AES-256-GCM + RSA-4096...');
    try {
      await sendEmail({
        recipientEmail: to,
        subject,
        body,
      });
      setStatusMessage(null);
      setTo('');
      setSubject('');
      setBody('');
      onClose();
    } catch (err: unknown) {
      const errorMsg =
        (err as { response?: { data?: { error?: string } } })?.response?.data?.error ||
        (err as Error).message ||
        'Failed to encrypt and send message';
      setStatusMessage(`Error: ${errorMsg}`);
    }
  };

  return (
    <div className="fixed bottom-0 right-8 z-50 w-full max-w-2xl glass-panel rounded-t-2xl shadow-2xl border border-white/10 text-slate-100 animate-slide-up flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/10 bg-thunder-900/60 rounded-t-2xl">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-sm text-white">New Encrypted Message</span>
          {hasPublicKey !== null && !isCheckingKey && (
            <KeyBadge isE2ee={hasPublicKey} publicKeyFound={hasPublicKey} />
          )}
        </div>
        <button
          type="button"
          onClick={onClose}
          className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
          aria-label="Close Composer"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Form */}
      <form onSubmit={handleSend} className="p-5 space-y-3.5 flex-1 flex flex-col">
        {/* Recipient */}
        <div>
          <Input
            placeholder="Recipient email (e.g. alice@thundermail.local)"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            required
            type="email"
            rightIcon={
              isCheckingKey ? (
                <span className="text-[10px] text-slate-500 animate-pulse">Checking key...</span>
              ) : undefined
            }
          />
        </div>

        {/* Subject */}
        <div>
          <Input
            placeholder="Subject"
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            required
          />
        </div>

        {/* Body */}
        <div className="flex-1 min-h-[160px]">
          <textarea
            placeholder="Write your zero-knowledge encrypted message here..."
            value={body}
            onChange={(e) => setBody(e.target.value)}
            className="w-full h-full min-h-[180px] glass-input rounded-xl p-3.5 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none resize-none font-sans"
            required
          />
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-2 border-t border-white/10">
          <div className="text-xs text-slate-400 font-mono">
            {statusMessage || (
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                {' Browser WebCrypto API Ready'}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" type="button" onClick={onClose}>
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              type="submit"
              isLoading={isSending}
              leftIcon={<Send className="w-3.5 h-3.5" />}
            >
              Encrypt & Send
            </Button>
          </div>
        </div>
      </form>
    </div>
  );
};
