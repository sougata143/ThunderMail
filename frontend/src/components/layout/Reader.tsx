import React, { useState } from 'react';
import {
  Lock,
  Trash2,
  Code,
  Reply,
  ShieldCheck,
  CheckCircle,
  Archive,
  Cpu,
  CheckCheck,
  AlertTriangle,
} from 'lucide-react';
import { Button } from '../ui/Button.tsx';
import { Spinner } from '../ui/Spinner.tsx';
import { AuthBadge } from '../ui/AuthBadge.tsx';
import { useMailbox } from '../../hooks/useMailbox.ts';

interface ReaderProps {
  messageId: string | null;
  folderName: string;
  onReply: (to: string, subject: string) => void;
  onDelete: (id: string) => void;
}

export const Reader: React.FC<ReaderProps> = ({
  messageId,
  folderName,
  onReply,
  onDelete,
}) => {
  const { useMessageDetail, patchStatus } = useMailbox(folderName);
  const { data: message, isLoading, isError } = useMessageDetail(messageId);
  const [showRawCiphertext, setShowRawCiphertext] = useState(false);

  if (!messageId) {
    return (
      <div className="flex-1 h-full flex flex-col items-center justify-center text-slate-500 p-8 text-center">
        <div className="w-16 h-16 rounded-2xl bg-white/5 flex items-center justify-center mb-4 border border-white/5">
          <Lock className="w-8 h-8 opacity-40 text-violet-400" />
        </div>
        <h3 className="text-base font-medium text-slate-300">No message selected</h3>
        <p className="text-xs text-slate-500 max-w-sm mt-1">
          Select an encrypted envelope from the list to decrypt and view its contents in-memory.
        </p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex-1 h-full flex items-center justify-center">
        <Spinner size="lg" label="Decrypting in client memory (Hybrid ML-KEM-768 + RSA-4096 + AES-GCM-256)..." />
      </div>
    );
  }

  if (isError || !message) {
    return (
      <div className="flex-1 h-full flex flex-col items-center justify-center text-rose-400 p-8 text-center">
        <p className="text-sm font-medium">Decryption or Fetch Failed</p>
        <p className="text-xs text-slate-500 mt-1">
          Unable to unwrap session key with the active private key.
        </p>
      </div>
    );
  }

  const handleMarkUnread = async () => {
    await patchStatus({ id: message.id, isRead: false });
  };

  const handleMoveTrash = async () => {
    await patchStatus({ id: message.id, folder: 'TRASH' });
    onDelete(message.id);
  };

  return (
    <div className="flex-1 h-full flex flex-col overflow-y-auto bg-thunder-950/40">
      {/* Top Action Toolbar */}
      <div className="glass-panel border-b border-white/10 px-6 py-3 flex items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => onReply(message.senderEmail, message.decryptedSubject || '')}
            leftIcon={<Reply className="w-3.5 h-3.5" />}
          >
            Reply
          </Button>

          <Button
            variant="ghost"
            size="sm"
            onClick={handleMarkUnread}
            leftIcon={<CheckCircle className="w-3.5 h-3.5" />}
          >
            Mark Unread
          </Button>

          <Button
            variant="ghost"
            size="sm"
            onClick={handleMoveTrash}
            leftIcon={<Archive className="w-3.5 h-3.5" />}
          >
            Move to Trash
          </Button>

          <Button
            variant="danger"
            size="sm"
            onClick={() => onDelete(message.id)}
            leftIcon={<Trash2 className="w-3.5 h-3.5" />}
          >
            Delete
          </Button>
        </div>

        {/* Raw Ciphertext toggle for transparency */}
        <Button
          variant={showRawCiphertext ? 'primary' : 'secondary'}
          size="sm"
          onClick={() => setShowRawCiphertext(!showRawCiphertext)}
          leftIcon={<Code className="w-3.5 h-3.5" />}
        >
          {showRawCiphertext ? 'View Plaintext' : 'Raw Ciphertext'}
        </Button>
      </div>

      {/* Message Header */}
      <div className="p-6 border-b border-white/10 space-y-4">
        <div className="flex items-start justify-between gap-4">
          <h2 className="text-xl font-bold tracking-tight text-white">
            {message.decryptedSubject}
          </h2>
          <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
            {/* E2EE Mode Badge */}
            {message.isE2ee ? (
              <span className="inline-flex items-center gap-1.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-3 py-1 rounded-full text-xs font-semibold">
                <ShieldCheck className="w-4 h-4" />
                Zero-Knowledge E2EE
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 bg-amber-500/10 text-amber-400 border border-amber-500/20 px-3 py-1 rounded-full text-xs font-medium">
                Standard TLS Relay
              </span>
            )}

            {/* Hybrid Post-Quantum Badge */}
            {message.isPqc && (
              <span className="inline-flex items-center gap-1.5 bg-indigo-500/10 text-indigo-300 border border-indigo-500/30 px-3 py-1 rounded-full text-xs font-semibold shadow-sm">
                <Cpu className="w-3.5 h-3.5 text-indigo-400" />
                Hybrid PQC (ML-KEM-768)
              </span>
            )}

            {/* ML-DSA-65 Digital Signature Verification Badge */}
            {message.signatureStatus === 'VERIFIED' && (
              <span className="inline-flex items-center gap-1.5 bg-violet-500/10 text-violet-300 border border-violet-500/30 px-3 py-1 rounded-full text-xs font-semibold">
                <CheckCheck className="w-3.5 h-3.5 text-violet-400" />
                ML-DSA-65 Signed
              </span>
            )}
            {message.signatureStatus === 'FAILED' && (
              <span className="inline-flex items-center gap-1.5 bg-rose-500/10 text-rose-300 border border-rose-500/30 px-3 py-1 rounded-full text-xs font-semibold">
                <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                Signature Verification Failed
              </span>
            )}

            {/* Inbound Sender Authenticity (SPF/DKIM/DMARC) Badge */}
            <AuthBadge
              status={message.authStatus ?? 'NONE'}
              detailsJson={message.authDetails}
              isInternal={message.isE2ee && !message.authDetails}
            />
          </div>
        </div>

        <div className="flex items-center justify-between text-xs text-slate-400">
          <div className="space-y-1">
            <p>
              <strong className="text-slate-300">From:</strong> {message.senderEmail}
            </p>
            <p>
              <strong className="text-slate-300">To:</strong> {message.recipientEmail}
            </p>
          </div>
          <div className="text-right font-mono text-[11px] text-slate-500">
            {new Date(message.createdAt).toLocaleString()}
          </div>
        </div>
      </div>

      {/* Message Body Content */}
      <div className="p-6 flex-1">
        {showRawCiphertext ? (
          /* Raw Ciphertext Inspection View */
          <div className="space-y-4 font-mono text-xs animate-fade-in">
            <div className="bg-amber-500/10 text-amber-300 border border-amber-500/20 rounded-lg p-3">
              ⚠️ <strong>Zero-Knowledge Transparency Mode:</strong> This is the exact raw encrypted
              blob stored on the backend database. The server never sees the decrypted plaintext.
            </div>

            <div className="space-y-2">
              <label htmlFor="raw-encrypted-session-key" className="text-slate-400 font-semibold block">
                {message.isPqc ? 'Hybrid Wrapped Session Key (AES-GCM-256 with Hybrid KEK):' : 'RSA-OAEP Encrypted Session Key (Base64):'}
              </label>
              <div
                id="raw-encrypted-session-key"
                className="bg-thunder-900 rounded-lg p-3 text-violet-300 break-all border border-white/10 max-h-24 overflow-y-auto"
              >
                {message.encryptedSessionKey}
              </div>
            </div>

            {message.isPqc && (
              <>
                <div className="space-y-2">
                  <label htmlFor="raw-classic-ciphertext" className="text-slate-400 font-semibold block">
                    Classical RSA-OAEP KEM Ciphertext (Base64):
                  </label>
                  <div
                    id="raw-classic-ciphertext"
                    className="bg-thunder-900 rounded-lg p-3 text-blue-300 break-all border border-white/10 max-h-24 overflow-y-auto"
                  >
                    {message.classicCiphertext}
                  </div>
                </div>

                <div className="space-y-2">
                  <label htmlFor="raw-pqc-ciphertext" className="text-slate-400 font-semibold block">
                    Post-Quantum ML-KEM-768 Ciphertext (Base64, 1088 bytes):
                  </label>
                  <div
                    id="raw-pqc-ciphertext"
                    className="bg-thunder-900 rounded-lg p-3 text-indigo-300 break-all border border-white/10 max-h-24 overflow-y-auto"
                  >
                    {message.pqcCiphertext}
                  </div>
                </div>
              </>
            )}

            {message.senderSignature && (
              <div className="space-y-2">
                <label htmlFor="raw-sender-signature" className="text-slate-400 font-semibold block">
                  Post-Quantum ML-DSA-65 Sender Signature (Base64, 3309 bytes):
                </label>
                <div
                  id="raw-sender-signature"
                  className="bg-thunder-900 rounded-lg p-3 text-emerald-300 break-all border border-white/10 max-h-24 overflow-y-auto"
                >
                  {message.senderSignature}
                </div>
              </div>
            )}

            <div className="space-y-2">
              <label htmlFor="raw-encrypted-subject" className="text-slate-400 font-semibold block">
                AES-GCM Encrypted Subject (Base64):
              </label>
              <div
                id="raw-encrypted-subject"
                className="bg-thunder-900 rounded-lg p-3 text-slate-300 break-all border border-white/10"
              >
                {message.encryptedSubject}
              </div>
            </div>

            <div className="space-y-2">
              <label htmlFor="raw-encrypted-body" className="text-slate-400 font-semibold block">
                AES-GCM Encrypted Body (Base64):
              </label>
              <div
                id="raw-encrypted-body"
                className="bg-thunder-900 rounded-lg p-3 text-slate-300 break-all border border-white/10 max-h-48 overflow-y-auto"
              >
                {message.encryptedBody}
              </div>
            </div>
          </div>
        ) : (
          /* Plaintext Render View */
          <div className="prose prose-invert max-w-none text-slate-200 text-sm leading-relaxed whitespace-pre-wrap animate-fade-in">
            {message.decryptedBody}
          </div>
        )}
      </div>
    </div>
  );
};
