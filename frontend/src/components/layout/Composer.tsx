import React, { useState, useEffect } from 'react';
import { Send, X, ShieldCheck, Globe } from 'lucide-react';
import { Button } from '../ui/Button.tsx';
import { Input } from '../ui/Input.tsx';
import { keysApi } from '../../api/keys.api.ts';
import { useMailbox } from '../../hooks/useMailbox.ts';
import { APP_DOMAIN } from '../../config/app.ts';

interface ComposerProps {
  initialTo?: string;
  initialSubject?: string;
  isOpen: boolean;
  onClose: () => void;
}

export const Composer: React.FC<ComposerProps> = ({
  initialTo = '',
  initialSubject = '',
  isOpen,
  onClose,
}) => {
  const [to, setTo] = useState(initialTo);
  const [subject, setSubject] = useState(initialSubject);
  const [body, setBody] = useState('');
  const [isCheckingKey, setIsCheckingKey] = useState(false);
  const [isE2eeRecipient, setIsE2eeRecipient] = useState<boolean | null>(null);

  const { sendEmail, isSending } = useMailbox();

  useEffect(() => {
    setTo(initialTo);
    setSubject(initialSubject);
  }, [initialTo, initialSubject]);

  useEffect(() => {
    if (!to || !to.includes('@')) {
      setIsE2eeRecipient(null);
      return;
    }

    const timer = setTimeout(async () => {
      setIsCheckingKey(true);
      try {
        const keyInfo = await keysApi.getPublicKey(to.trim());
        setIsE2eeRecipient(!!keyInfo.publicKey);
      } catch {
        setIsE2eeRecipient(false);
      } finally {
        setIsCheckingKey(false);
      }
    }, 400);

    return () => clearTimeout(timer);
  }, [to]);

  if (!isOpen) return null;

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!to || isSending) return;

    try {
      await sendEmail({
        recipientEmail: to.trim().toLowerCase(),
        subject: subject.trim(),
        body: body.trim(),
      });
      onClose();
    } catch (err: unknown) {
      alert(`Send failed: ${(err as Error).message}`);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-2xl glass-panel rounded-2xl border border-white/10 shadow-2xl flex flex-col max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-white/10 flex items-center justify-between bg-thunder-950/60">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-white">New Secure Message</h3>
            {isE2eeRecipient === true && (
              <span className="flex items-center gap-1 text-[11px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded-full font-medium">
                <ShieldCheck className="w-3 h-3" />
                E2EE Active
              </span>
            )}
            {isE2eeRecipient === false && (
              <span className="flex items-center gap-1 text-[11px] bg-amber-500/10 text-amber-400 border border-amber-500/20 px-2 py-0.5 rounded-full font-medium">
                <Globe className="w-3 h-3" />
                Standard TLS Relay
              </span>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSend} className="p-5 space-y-3.5 flex-1 flex flex-col">
          {/* Recipient */}
          <div>
            <Input
              placeholder={`Recipient email (e.g. alice@${APP_DOMAIN})`}
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
            <div className="text-xs text-slate-400 font-mono flex items-center gap-1.5 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <span>Browser WebCrypto API Ready</span>
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
    </div>
  );
};
