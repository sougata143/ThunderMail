import React, { useState } from 'react';
import { ShieldAlert, Copy, Check, Key } from 'lucide-react';
import { Modal } from '../ui/Modal.tsx';
import { Button } from '../ui/Button.tsx';

interface RecoveryPhraseModalProps {
  isOpen: boolean;
  onClose: () => void;
  words: string[];
}

export const RecoveryPhraseModal: React.FC<RecoveryPhraseModalProps> = ({
  isOpen,
  onClose,
  words,
}) => {
  const [copied, setCopied] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(words.join(' '));
    setCopied(true);
    setTimeout(() => setCopied(false), 3000);
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={() => {
        if (confirmed) onClose();
      }}
      title="Zero-Knowledge Recovery Phrase"
      maxWidth="lg"
    >
      <div className="space-y-4">
        <div className="bg-amber-500/10 border border-amber-500/20 text-amber-300 p-4 rounded-xl flex items-start gap-3 text-xs leading-relaxed">
          <ShieldAlert className="w-5 h-5 shrink-0 text-amber-400 mt-0.5" />
          <div>
            <strong className="font-semibold block mb-1">
              Store these 24 words in a secure, offline location.
            </strong>
            <p className="mt-1">
              Because ThunderMail is zero-knowledge, the server cannot reset your password or recover
              your emails if you lose your credentials.
            </p>
          </div>
        </div>

        {/* 24 Words Grid with stable unique key based on position and word */}
        <div className="grid grid-cols-3 sm:grid-cols-4 gap-2 bg-thunder-950 p-4 rounded-xl border border-white/10 font-mono text-xs max-h-60 overflow-y-auto">
          {words.map((word, idx) => (
            <div
              key={`${idx + 1}-${word}`}
              className="bg-white/5 px-2.5 py-1.5 rounded flex items-center justify-between text-slate-300 border border-white/5"
            >
              <span className="text-slate-500 text-[10px] select-none">{idx + 1}.</span>
              <span className="font-medium text-slate-200">{word}</span>
            </div>
          ))}
        </div>

        {/* Action Controls */}
        <div className="flex items-center justify-between pt-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={handleCopy}
            leftIcon={copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
          >
            {copied ? 'Copied to Clipboard' : 'Copy All Words'}
          </Button>

          <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300 select-none">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
              className="rounded bg-thunder-900 border-white/20 text-violet-600 focus:ring-violet-500 w-4 h-4"
            />
            <span>I have safely saved my recovery phrase</span>
          </label>
        </div>

        <div className="pt-2">
          <Button
            variant="primary"
            className="w-full"
            disabled={!confirmed}
            onClick={onClose}
            leftIcon={<Key className="w-4 h-4" />}
          >
            Continue to Secure Mailbox
          </Button>
        </div>
      </div>
    </Modal>
  );
};
