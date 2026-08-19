import React from 'react';
import { Lock, ShieldCheck, ShieldAlert } from 'lucide-react';

interface KeyBadgeProps {
  isE2ee: boolean;
  publicKeyFound?: boolean;
  size?: 'sm' | 'md';
}

export const KeyBadge: React.FC<KeyBadgeProps> = ({
  isE2ee,
  publicKeyFound = true,
  size = 'sm',
}) => {
  if (isE2ee && publicKeyFound) {
    return (
      <div
        className={`inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium ${
          size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm'
        }`}
        title="End-to-End Encrypted: RSA-OAEP-4096 + AES-GCM-256"
      >
        <Lock className={size === 'sm' ? 'w-3 h-3' : 'w-4 h-4'} />
        <span>E2EE Active</span>
      </div>
    );
  }

  if (publicKeyFound) {
    return (
      <div
        className={`inline-flex items-center gap-1.5 rounded-full bg-violet-500/10 text-violet-300 border border-violet-500/20 font-medium ${
          size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm'
        }`}
      >
        <ShieldCheck className={size === 'sm' ? 'w-3 h-3' : 'w-4 h-4'} />
        <span>Key Verified</span>
      </div>
    );
  }

  return (
    <div
      className={`inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 font-medium ${
        size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm'
      }`}
      title="External recipient: Standard TLS Relay (No Zero-Knowledge E2EE)"
    >
      <ShieldAlert className={size === 'sm' ? 'w-3 h-3' : 'w-4 h-4'} />
      <span>Standard TLS Relay</span>
    </div>
  );
};
