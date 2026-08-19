import React, { useState } from 'react';
import { Download, ShieldCheck, Copy, Check } from 'lucide-react';
import { Modal } from '../ui/Modal.tsx';
import { Button } from '../ui/Button.tsx';
import { useCrypto } from '../../hooks/useCrypto.ts';

interface KeyExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  userEmail: string;
}

export const KeyExportModal: React.FC<KeyExportModalProps> = ({
  isOpen,
  onClose,
  userEmail,
}) => {
  const { publicKeyPem } = useCrypto();
  const [copied, setCopied] = useState(false);

  const handleCopyPublic = () => {
    if (publicKeyPem) {
      navigator.clipboard.writeText(publicKeyPem);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownloadBackup = () => {
    const backupData = {
      email: userEmail,
      publicKeyPem,
      exportTimestamp: new Date().toISOString(),
      algorithm: 'RSA-OAEP-4096 / AES-GCM-256 / PBKDF2-SHA256',
      service: 'ThunderMail Zero-Knowledge E2EE',
    };

    const blob = new Blob([JSON.stringify(backupData, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `thundermail-key-backup-${userEmail.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Security & Cryptographic Keys" maxWidth="lg">
      <div className="space-y-4">
        <div className="bg-thunder-900/80 p-4 rounded-xl border border-white/10 space-y-2">
          <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold">
            <ShieldCheck className="w-4 h-4" />
            <span>Active Asymmetric Key: RSA-OAEP-4096</span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Your private key is loaded exclusively in browser RAM and is never sent unencrypted to
            any server. Below is your public key used by others to send you E2EE mail.
          </p>
        </div>

        {/* Public Key Display with associated label */}
        <div className="space-y-1.5">
          <label htmlFor="spki-public-key" className="text-xs font-medium text-slate-300">
            Public Key (SPKI Base64 Format):
          </label>
          <div
            id="spki-public-key"
            aria-label="Public Key Base64 Display"
            className="bg-thunder-950 p-3 rounded-lg border border-white/10 font-mono text-[11px] text-violet-300 break-all max-h-32 overflow-y-auto"
          >
            {publicKeyPem || 'Key not loaded'}
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-3 pt-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={handleCopyPublic}
            className="flex-1"
            leftIcon={copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
          >
            {copied ? 'Copied' : 'Copy Public Key'}
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={handleDownloadBackup}
            className="flex-1"
            leftIcon={<Download className="w-4 h-4" />}
          >
            Download Key Backup
          </Button>
        </div>
      </div>
    </Modal>
  );
};
